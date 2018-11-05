package servingcert

import (
	crand "crypto/rand"
	"fmt"
	"time"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/core/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"bytes"

	"github.com/openshift/library-go/pkg/crypto"
)

// ServiceServingCertController is responsible for synchronizing Service objects stored
// in the system with actual running replica sets and pods.
type CARotationController struct {
	configMapClient kcoreclient.ConfigMapsGetter
	secretClient    kcoreclient.SecretsGetter

	// Services that need to be checked
	queue      workqueue.RateLimitingInterface
	maxRetries int

	configMapLister    listers.ConfigMapLister
	configMapHasSynced cache.InformerSynced

	secretLister    listers.SecretLister
	secretHasSynced cache.InformerSynced

	ca        *crypto.CA
	dnsSuffix string

	// syncHandler does the work. It's factored out for unit testing
	syncHandler func(serviceKey string) error
}

// NewCARotationController creates a new CARotationController.
func NewCARotationController(configMaps informers.ConfigMapInformer, secrets informers.SecretInformer, configMapClient kcoreclient.ConfigMapsGetter, secretClient kcoreclient.SecretsGetter, ca *crypto.CA, dnsSuffix string, resyncInterval time.Duration) *CARotationController {
	rc := &CARotationController{
		secretClient:    secretClient,
		configMapClient: configMapClient,

		queue:      workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		maxRetries: 10,

		ca:        ca,
		dnsSuffix: dnsSuffix,
	}

	secrets.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: rc.addSecret,
		},
		resyncInterval,
	)
	rc.secretHasSynced = secrets.Informer().GetController().HasSynced
	rc.secretLister = secrets.Lister()

	rc.configMapHasSynced = configMaps.Informer().GetController().HasSynced
	rc.configMapLister = configMaps.Lister()

	rc.syncHandler = rc.syncCAs

	return rc
}

// Run begins watching and syncing.
func (rc *CARotationController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer rc.queue.ShutDown()

	if !cache.WaitForCacheSync(stopCh, rc.configMapHasSynced, rc.secretHasSynced) {
		return
	}

	glog.V(5).Infof("Starting workers")
	for i := 0; i < workers; i++ {
		go wait.Until(rc.worker, time.Second, stopCh)
	}
	<-stopCh
	glog.V(1).Infof("Shutting down")
}

func (rc *CARotationController) addSecret(obj interface{}) {
	secret, ok := obj.(*v1.Secret)
	if !ok {
		return
	}

	// Look for a specific secret to use as the new CA.
	if secret.Namespace != "openshift-service-cert-signer" || secret.Name != "replacement-service-signer-ca" {
		return
	}

	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		glog.Errorf("Couldn't get key for object %+v: %v", obj, err)
		return
	}

	rc.queue.Add(key)
}

// worker runs a worker thread that just dequeues items, processes them, and marks them done.
// It enforces that the syncHandler is never invoked concurrently with the same key.
func (rc *CARotationController) worker() {
	for {
		if !rc.work() {
			return
		}
	}
}

// work returns true if the worker thread should continue
func (rc *CARotationController) work() bool {
	key, quit := rc.queue.Get()
	if quit {
		return false
	}
	defer rc.queue.Done(key)

	if err := rc.syncHandler(key.(string)); err == nil {
		// this means the request was successfully handled.  We should "forget" the item so that any retry
		// later on is reset
		rc.queue.Forget(key)

	} else {
		// if we had an error it means that we didn't handle it, which means that we want to requeue the work
		utilruntime.HandleError(fmt.Errorf("error syncing service, it will be retried: %v", err))
		rc.queue.AddRateLimited(key)
	}

	return true
}

// syncService will sync the service with the given key.
// This function is not meant to be invoked concurrently with the same key.
func (rc *CARotationController) syncCAs(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	newCASecret, err := rc.secretLister.Secrets(namespace).Get(name)
	if kapierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	sharedCABundleConfigMap, err := rc.configMapLister.ConfigMaps("openshift-service-cert-signer").Get("signing-cabundle")
	if err != nil {
		return err
	}
	caBundleConfigMap := sharedCABundleConfigMap.DeepCopy()

	sharedOldCASecret, err := rc.secretLister.Secrets("openshift-service-cert-signer").Get("service-serving-cert-signer-signing-key")
	if err != nil {
		return err
	}
	oldCASecret := sharedOldCASecret.DeepCopy()

	if hasSameCert(oldCASecret, newCASecret) {
		return nil
	}

	// create cross-signed interims
	bundle, signedByOld, err := createInterimCAs(oldCASecret, newCASecret)
	if err != nil {
		return err
	}

	// Update signing secret with the new CA and the generated intermediate to distribute with service certs.
	oldCASecret.Data["tls.crt"] = newCASecret.Data["tls.crt"]
	oldCASecret.Data["tls.key"] = newCASecret.Data["tls.key"]
	oldCASecret.Data["intermediate.crt"] = signedByOld
	_, err = rc.secretClient.Secrets("openshift-service-cert-signer").Update(oldCASecret)
	if err != nil {
		return err
	}

	// Update CA bundle
	caBundleConfigMap.Data["cabundle.crt"] = string(bundle)
	_, err = rc.configMapClient.ConfigMaps("openshift-service-cert-signer").Update(caBundleConfigMap)
	if err != nil {
		return err
	}

	// trigger regeneration
	return err
}

func hasSameCert(s1, s2 *v1.Secret) bool {
	cert1, key1, err := getCertSecretData(s1)
	if err != nil {
		return false
	}
	cert2, key2, err := getCertSecretData(s2)
	if err != nil {
		return false
	}
	return bytes.Equal(cert1, cert2) && bytes.Equal(key1, key2)
}

func getCertSecretData(secret *v1.Secret) ([]byte, []byte, error) {
	cert, ok := secret.Data["tls.crt"]
	if !ok || len(cert) == 0 {
		return nil, nil, fmt.Errorf("secret %s does not contain cert data", secret.Name)
	}
	key, ok := secret.Data["tls.key"]
	if !ok || len(key) == 0 {
		return nil, nil, fmt.Errorf("secret %s does not contain key data", secret.Name)
	}
	return cert, key, nil
}

// Returns full bundle, signed-by-old intermdiate, nil
func createInterimCAs(oldCASecret, newCASecret *v1.Secret) ([]byte, []byte, error) {
	oldCACertPem, oldCAKeyPem, err := getCertSecretData(oldCASecret)
	if err != nil {
		return nil, nil, err
	}
	newCACertPem, newCAKeyPem, err := getCertSecretData(newCASecret)
	if err != nil {
		return nil, nil, err
	}

	oldCACert, err := parsePemCert(oldCACertPem)
	if err != nil {
		return nil, nil, err
	}
	oldCAKey, err := parsePemKey(oldCAKeyPem)
	if err != nil {
		return nil, nil, err
	}

	newCACert, err := parsePemCert(newCACertPem)
	if err != nil {
		return nil, nil, err
	}
	newCAKey, err := parsePemKey(newCAKeyPem)
	if err != nil {
		return nil, nil, err
	}

	// The first interim CA comprises of the old CA's public key, private key, and subject. It's self-issued but not
	// self-signed as it's signed by the new CA key. This creates a trust bridge between refreshed clients and
	// unrefreshed servers.
	signedByNew, err := x509.CreateCertificate(crand.Reader, oldCACert, oldCACert, oldCACert.PublicKey, newCAKey)
	if err != nil {
		return nil, nil, err
	}

	// The second interim CA comprises of the new CA's public key, private key, and subject. It's self-issued but not
	// self-signed as it's signed by the old CA key. This creates a trust bridge between the unrefreshed clients and
	// refreshed servers, as long as refreshed servers serve with a bundle containing this CA and the serving cert.
	signedByOld, err := x509.CreateCertificate(crand.Reader, newCACert, newCACert, newCACert.PublicKey, oldCAKey)
	if err != nil {
		return nil, nil, err
	}

	// Assemble bundle.
	signedByNewPem, err := encodeASN1Cert(signedByNew)
	if err != nil {
		return nil, nil, err
	}

	signedByOldPem, err := encodeASN1Cert(signedByOld)
	if err != nil {
		return nil, nil, err
	}

	bundle := make([]byte, 0)
	bundle = append(bundle, oldCACertPem...)
	bundle = append(bundle, signedByNewPem...)
	bundle = append(bundle, signedByOldPem...)
	bundle = append(bundle, newCACertPem...)
	return bundle, signedByOldPem, nil
}

func encodeASN1Cert(certDer []byte) ([]byte, error) {
	b := bytes.Buffer{}
	err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func parsePemCert(certPem []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, fmt.Errorf("error parsing certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePemKey(keyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("error parsing key pem")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
