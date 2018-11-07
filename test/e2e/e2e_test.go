package e2e

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	cryptohelpers "github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-serving-cert-signer/pkg/controller/servingcert"
)

const (
	serviceCAOperatorNamespace   = "openshift-core-operators"
	serviceCAControllerNamespace = "openshift-service-cert-signer"
	serviceCAOperatorPodPrefix   = "openshift-service-cert-signer-operator"
	apiInjectorPodPrefix         = "apiservice-cabundle-injector"
	configMapInjectorPodPrefix   = "configmap-cabundle-injector"
	caControllerPodPrefix        = "service-serving-cert-signer"
)

func hasPodWithPrefixName(client *kubernetes.Clientset, name, namespace string) bool {
	if client == nil || len(name) == 0 || len(namespace) == 0 {
		return false
	}
	pods, err := client.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		return false
	}
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.GetName(), name) {
			return true
		}
	}
	return false
}

func createTestNamespace(client *kubernetes.Clientset, namespaceName string) (*v1.Namespace, error) {
	ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	})
	return ns, err
}

// on success returns serviceName, secretName, nil
func createServingCertAnnotatedService(client *kubernetes.Clientset, secretName, serviceName, namespace string) error {
	_, err := client.CoreV1().Services(namespace).Create(&v1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Annotations: map[string]string{
				servingcert.ServingCertSecretAnnotation: secretName,
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name: "tests",
					Port: 8443,
				},
			},
		},
	})
	return err
}

func createCABundleConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	_, err := client.CoreV1().ConfigMaps(namespace).Create(&v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
			Annotations: map[string]string{
				"service.alpha.openshift.io/inject-cabundle": "true",
			},
		},
	})
	return err
}

//func getTLSCredsFromSecret(client *kubernetes.Clientset, secretName, namespace, certDataKey, keyDataKey string) ([]byte, []byte, error) {
//	secret, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
//	if err != nil {
//		return nil, nil, err
//	}
//	certData, ok := secret.Data[certDataKey]
//	if !ok {
//		return nil, nil, fmt.Errorf("secret %s does not have data key %s", secret.Name, certDataKey)
//	}
//	if len(certData) == 0 {
//		return nil, nil, fmt.Errorf("secret %s does not contain cert data", secret.Name)
//	}
//	keyData, ok := secret.Data[keyDataKey]
//	if !ok {
//		return nil, nil, fmt.Errorf("secret %s does not have data key %s", secret.Name, keyDataKey)
//	}
//	if len(keyData) == 0 {
//		return nil, nil, fmt.Errorf("secret %s does not contain key data", secret.Name)
//	}
//	return certData, keyData, nil
//}

func pollForServiceServingSecret(client *kubernetes.Clientset, secretName, namespace string) (*v1.Secret, error) {
	var secret *v1.Secret
	pollErr := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
		if err != nil && kapierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret = s
		return true, nil
	})
	return secret, pollErr
}
func pollForNewCert(client *kubernetes.Clientset, ns, secretName string, certPem, keyPem []byte) ([]byte, []byte, error) {
	var returnCertPem []byte
	var returnKeyPem []byte
	pollErr := wait.PollImmediate(time.Second, 50*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(ns).Get(secretName, metav1.GetOptions{})
		if err != nil && kapierrors.IsNotFound(err) {
			return false, nil
		}

		if err != nil {
			return false, err
		}

		c, k := s.Data["tls.crt"], s.Data["tls.key"]
		if len(c) == 0 || len(k) == 0 {
			return false, nil
		}

		if bytes.Equal(c, certPem) && bytes.Equal(k, keyPem) {
			return false, nil
		}

		returnCertPem = c
		returnKeyPem = k
		return true, nil
	})
	return returnCertPem, returnKeyPem, pollErr
}

func pollForNewCABundleData(client *kubernetes.Clientset, ns, configMapName string, bundle []byte) ([]byte, error) {
	var returnBundle []byte
	pollErr := wait.PollImmediate(time.Second, 50*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(ns).Get(configMapName, metav1.GetOptions{})
		if err != nil && kapierrors.IsNotFound(err) {
			return false, nil
		}

		if err != nil {
			return false, err
		}

		data := cm.Data["cabundle.crt"]
		if len(data) == 0 {
			return false, nil
		}
		dataBytes := []byte(data)

		if bytes.Equal(dataBytes, bundle) {
			return false, nil
		}

		returnBundle = dataBytes
		return true, nil
	})
	return returnBundle, pollErr
}

func pollForBundleConfigMapData(client *kubernetes.Clientset, configMapName, namespace string) ([]byte, error) {
	var returnData []byte
	pollErr := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
		if err != nil && kapierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		data, ok := cm.Data["cabundle.crt"]
		if !ok || len(data) == 0 {
			return false, err
		}
		returnData = []byte(data)
		return true, nil
	})
	return returnData, pollErr
}

func cleanupServiceSignerTestObjects(client *kubernetes.Clientset, secretName, serviceName, namespace string) {
	client.CoreV1().Secrets(namespace).Delete(secretName, &metav1.DeleteOptions{})
	client.CoreV1().Services(namespace).Delete(serviceName, &metav1.DeleteOptions{})
	client.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
}

func TestE2E(t *testing.T) {
	// use /tmp/admin.conf (placed by ci-operator) or KUBECONFIG env
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	// load client
	client, err := clientcmd.LoadFromFile(confPath)
	if err != nil {
		t.Fatalf("error loading config: %v", err)
	}
	adminConfig, err := clientcmd.NewDefaultClientConfig(*client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("error loading admin config: %v", err)
	}
	adminClient, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error getting admin client: %v", err)
	}

	// the service-serving-cert-operator and controllers should be running as a stock OpenShift component. our first test is to
	// verify that all of the components are running.
	if !hasPodWithPrefixName(adminClient, serviceCAOperatorPodPrefix, serviceCAOperatorNamespace) {
		t.Fatalf("%s not running in %s namespace", serviceCAOperatorPodPrefix, serviceCAOperatorNamespace)
	}
	if !hasPodWithPrefixName(adminClient, apiInjectorPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", apiInjectorPodPrefix, serviceCAControllerNamespace)
	}
	if !hasPodWithPrefixName(adminClient, configMapInjectorPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", configMapInjectorPodPrefix, serviceCAControllerNamespace)
	}
	if !hasPodWithPrefixName(adminClient, caControllerPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", caControllerPodPrefix, serviceCAControllerNamespace)
	}

	// test the main feature. annotate service -> created secret
	t.Run("serving-cert-annotation", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		_, err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
	})

	t.Run("rotate CA", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		servingSecret, err := pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}

		err = createCABundleConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating cabundle configmap")
		}

		// get configmap bundle , bundle A
		bundle, err := pollForBundleConfigMapData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching cabundle configmap")
		}

		// get serving cert and key from secret -> server cert X and server key X
		servingCertPem := servingSecret.Data["tls.crt"]
		servingKeyPem := servingSecret.Data["tls.crt"]

		// replace service signer cert with one about to expire
		err = replaceServiceCA(adminClient)
		if err != nil {
			t.Fatalf("error replacing service CA")
		}

		// fetch new configmap bundle until its different from bundle A. This is bundle B, bundle rotation has happened
		newConfigMapBundleData, err := pollForNewCABundleData(adminClient, ns.Name, testConfigMapName, bundle)
		if err != nil {
			t.Fatalf("error polling for new ca bundle data")
		}
		fmt.Println("original bundle:")
		fmt.Println(string(bundle))
		fmt.Println("replaced bundle:")
		fmt.Println(string(newConfigMapBundleData))

		// fetch new signer cert until it's different from cert x, this is cert y -> server rotation has happened
		// ensure it has bundle
		newServingCertPem, newServingKeyPem, err := pollForNewCert(adminClient, ns.Name, testSecretName, servingCertPem, servingKeyPem)
		if err != nil {
			t.Fatalf("error polling for new signer cert")
		}

		fmt.Println("original server cert:")
		fmt.Println(servingCertPem)
		fmt.Println("original serving key:")
		fmt.Println(string(servingKeyPem))

		fmt.Println("replaced serving cert:")
		fmt.Println(string(newServingCertPem))
		fmt.Println("replaced serving key:")
		fmt.Println(string(newServingKeyPem))

		//// ensure it has 4 certs
		//err := verifyCABundleData(newConfigMapBundleData)
		//if err != nil {
		//	t.Fatalf("error verifying bundle data")
		//}
		//
		//// tests are:
		//// serve cert X and client A
		//err = testServiceServingCertAndBundle(servingCertPem, servingKeyPem, bundle)
		//if err != nil {
		//	t.Fatalf("error verifying old serving cert with old bundle")
		//}
		//// serve cert y + intermediate with client A
		//err = testServiceServingCertAndBundle(newServingCertPem, newServingKeyPem, bundle)
		//if err != nil {
		//	t.Fatalf("error verifying new serving certs with old bundle")
		//}
		//// serve cert X and client bundle B
		//err = testServiceServingCertAndBundle(servingCertPem, servingKeyPem, newConfigMapBundleData)
		//if err != nil {
		//	t.Fatalf("error verifying old serving cert with new bundle")
		//}
		//// serve cert y + intermediate with client bundle B
		//err = testServiceServingCertAndBundle(newServingCertPem, newServingKeyPem, newConfigMapBundleData)
		//if err != nil {
		//	t.Fatalf("error verifying new serving cert with new bundle")
		//}

	})
	// TODO: additional tests
	// - configmap CA bundle injection
	// - API service CA bundle injection
	// - regenerate serving cert
}

/*
func getSigningSubject(client *kubernetes.Clientset) (pkix.Name, error) {
	currentCASecret, err := client.CoreV1().Secrets("openshift-service-cert-signer").Get("service-serving-cert-signer-signing-key", metav1.GetOptions{})
	if err != nil {
		return pkix.Name{}, err
	}
	caPem, ok := currentCASecret.Data["tls.crt"]
	if !ok {
		return pkix.Name{}, fmt.Errorf("no tls.crt data in service-serving-cert-signer-signing-key secret")
	}
	dataBlock, _ := pem.Decode(caPem)
	caCert, err := x509.ParseCertificate(dataBlock.Bytes)
	if err != nil {
		return pkix.Name{}, err
	}
	return caCert.Subject, nil
}

func CreateCrossSignedInterimCAs(client *kubernetes.Clientset, currentCASecretName, currentCASecretNamespace, newCASecretName, newCASecretNamespace string) ([]byte, []byte, error) {
	curCACertDer, curCAKeyDer, err := getTLSCredsFromSecret(client, currentCASecretName, currentCASecretNamespace, "tls.crt", "tls.key")
	if err != nil {
		return nil, nil, err
	}
	newCACertDer, newCAKeyDer, err := getTLSCredsFromSecret(client, newCASecretName, newCASecretNamespace, "tls.crt", "tls.key")
	if err != nil {
		return nil, nil, err
	}

	curCABlock, _ := pem.Decode(curCACertDer)
	curCACert, err := x509.ParseCertificate(curCABlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	curCAKeyBlock, _ := pem.Decode(curCAKeyDer)
	curCAKey, err := x509.ParsePKCS1PrivateKey(curCAKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	newCABlock, _ := pem.Decode(newCACertDer)
	newCACert, err := x509.ParseCertificate(newCABlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	newCAKeyBlock, _ := pem.Decode(newCAKeyDer)
	newCAKey, err := x509.ParsePKCS1PrivateKey(newCAKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// The first cross-signed intermediate has the current CA's public and private key and subject, signed by the new CA key
	// XXX change auth key ID to new CA auth key
	firstCrossSigned, err := x509.CreateCertificate(crand.Reader, curCACert, curCACert, curCACert.PublicKey, newCAKey)
	if err != nil {
		return nil, nil, err
	}

	firstCrossSignedCert, err := x509.ParseCertificates(firstCrossSigned)
	if err != nil {
		return nil, nil, err
	}
	if len(firstCrossSignedCert) != 1 {
		return nil, nil, fmt.Errorf("Expected one certificate")
	}

	firstCrossSignedCApem, err := encodeCertificates(firstCrossSignedCert...)
	if err != nil {
		return nil, nil, err
	}

	// XXX
	curCAPem, err := encodeCertificates(curCACert)
	if err != nil {
		return nil, nil, err
	}
	newCAPem, err := encodeCertificates(newCACert)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("current CA PEM\n")
	fmt.Printf("%s\n", curCAPem)
	ioutil.WriteFile("/tmp/current.crt", curCAPem, 0644)
	fmt.Printf("new CA PEM\n")
	fmt.Printf("%s\n", newCAPem)
	ioutil.WriteFile("/tmp/new.crt", newCAPem, 0644)
	fmt.Printf("first cross signed PEM\n")
	fmt.Printf("%s\n", firstCrossSignedCApem)
	ioutil.WriteFile("/tmp/first.crt", firstCrossSignedCApem, 0644)

	// The second cross-signed intermediate has the new CA's public and private key and subject, signed by the old CA key
	secondCrossSigned, err := x509.CreateCertificate(crand.Reader, newCACert, newCACert, newCACert.PublicKey, curCAKey)
	if err != nil {
		return nil, nil, err
	}

	secondCrossSignedCert, err := x509.ParseCertificates(secondCrossSigned)
	if err != nil {
		return nil, nil, err
	}
	if len(secondCrossSignedCert) != 1 {
		return nil, nil, fmt.Errorf("Expected one certificate")
	}

	secondCrossSignedCApem, err := encodeCertificates(secondCrossSignedCert...)
	if err != nil {
		return nil, nil, err
	}

	// XXX
	fmt.Printf("second cross signed PEM\n")
	fmt.Printf("%s\n", secondCrossSignedCApem)
	ioutil.WriteFile("/tmp/second.crt", secondCrossSignedCApem, 0644)

	return firstCrossSignedCApem, secondCrossSignedCApem, nil
}
*/
func replaceServiceCA(adminClient *kubernetes.Clientset) error {
	currentCA, err := adminClient.CoreV1().Secrets(serviceCAControllerNamespace).Get("service-serving-cert-signer-signing-key", metav1.GetOptions{})
	if err != nil {
		return err
	}

	certs, err := cryptohelpers.CertsFromPEM(currentCA.Data["tls.crt"])
	if err != nil {
		return err
	}
	cert := certs[0]

	replacementCATemplate := &x509.Certificate{
		Subject:               cert.Subject,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now().Add(-1 * time.Second),
		NotAfter:              time.Now().Add(2 * time.Minute),
		SerialNumber:          big.NewInt(1),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	replacementCAPublicKey, replacementCAPrivateKey, err := cryptohelpers.NewKeyPair()
	if err != nil {
		return err
	}

	replacementDer, err := x509.CreateCertificate(crand.Reader, replacementCATemplate, replacementCATemplate, replacementCAPublicKey, replacementCAPrivateKey)
	if err != nil {
		return err
	}

	replacementCert, err := x509.ParseCertificates(replacementDer)
	if err != nil {
		return err
	}
	if len(replacementCert) != 1 {
		return fmt.Errorf("Expected one certificate")
	}

	caPem, err := encodeCertificates(replacementCert...)
	if err != nil {
		return err
	}

	caKey, err := encodeKey(replacementCAPrivateKey)
	if err != nil {
		return err
	}

	currentCA.Data["tls.crt"] = caPem
	currentCA.Data["tls.key"] = caKey

	_, err = adminClient.CoreV1().Secrets(currentCA.Namespace).Update(currentCA)
	return err
}

func encodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}

func encodeKey(key crypto.PrivateKey) ([]byte, error) {
	b := bytes.Buffer{}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return []byte{}, err
		}
		if err := pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
			return b.Bytes(), err
		}
	case *rsa.PrivateKey:
		if err := pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
			return []byte{}, err
		}
	default:
		return []byte{}, errors.New("Unrecognized key type")

	}
	return b.Bytes(), nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var characters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

// used for random suffix
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = characters[rand.Intn(len(characters))]
	}
	return string(b)
}
