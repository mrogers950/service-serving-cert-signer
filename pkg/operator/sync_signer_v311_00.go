package operator

import (
	"bytes"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"crypto/x509/pkix"
	"math/big"

	operatorsv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	scsv1alpha1 "github.com/openshift/api/servicecertsigner/v1alpha1"
	cryptohelpers "github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/service-serving-cert-signer/pkg/operator/v310_00_assets"

	"crypto/ecdsa"
	"errors"
)

// syncSigningController_v311_00_to_latest takes care of synchronizing (not upgrading) the thing we're managing.
// most of the time the sync method will be good for a large span of minor versions
func syncSigningController_v311_00_to_latest(c ServiceCertSignerOperator, operatorConfig *scsv1alpha1.ServiceCertSignerOperatorConfig, previousAvailability *operatorsv1alpha1.VersionAvailability) (operatorsv1alpha1.VersionAvailability, []error) {
	versionAvailability := operatorsv1alpha1.VersionAvailability{
		Version: operatorConfig.Spec.Version,
	}

	errors := []error{}
	var err error

	requiredNamespace := resourceread.ReadNamespaceV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/ns.yaml"))
	_, _, err = resourceapply.ApplyNamespace(c.corev1Client, requiredNamespace)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "ns", err))
	}

	requiredClusterRole := resourceread.ReadClusterRoleV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/clusterrole.yaml"))
	_, _, err = resourceapply.ApplyClusterRole(c.rbacv1Client, requiredClusterRole)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "svc", err))
	}

	requiredClusterRoleBinding := resourceread.ReadClusterRoleBindingV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/clusterrolebinding.yaml"))
	_, _, err = resourceapply.ApplyClusterRoleBinding(c.rbacv1Client, requiredClusterRoleBinding)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "svc", err))
	}

	requiredService := resourceread.ReadServiceV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/svc.yaml"))
	_, _, err = resourceapply.ApplyService(c.corev1Client, requiredService)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "svc", err))
	}

	requiredSA := resourceread.ReadServiceAccountV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/sa.yaml"))
	_, saModified, err := resourceapply.ApplyServiceAccount(c.corev1Client, requiredSA)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "sa", err))
	}

	// TODO create a new configmap whenever the data value changes
	_, configMapModified, err := manageSigningConfigMap_v311_00_to_latest(c.corev1Client, operatorConfig)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "configmap", err))
	}

	_, signingSecretModified, err := manageSigningSecret_v311_00_to_latest(c.corev1Client)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "signing-key", err))
	}

	forceDeployment := operatorConfig.ObjectMeta.Generation != operatorConfig.Status.ObservedGeneration
	if saModified { // SA modification can cause new tokens
		forceDeployment = true
	}
	if signingSecretModified {
		forceDeployment = true
	}
	if configMapModified {
		forceDeployment = true
	}

	// our configmaps and secrets are in order, now it is time to create the DS
	// TODO check basic preconditions here
	actualDeployment, _, err := manageSignerDeployment_v311_00_to_latest(c.appsv1Client, operatorConfig, previousAvailability, forceDeployment)
	if err != nil {
		errors = append(errors, fmt.Errorf("%q: %v", "deployment", err))
	}

	return resourcemerge.ApplyDeploymentGenerationAvailability(versionAvailability, actualDeployment, errors...), errors
}

func manageSigningConfigMap_v311_00_to_latest(client coreclientv1.ConfigMapsGetter, operatorConfig *scsv1alpha1.ServiceCertSignerOperatorConfig) (*corev1.ConfigMap, bool, error) {
	configMap := resourceread.ReadConfigMapV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/cm.yaml"))
	defaultConfig := v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/defaultconfig.yaml")
	requiredConfigMap, _, err := resourcemerge.MergeConfigMap(configMap, "controller-config.yaml", nil, defaultConfig, operatorConfig.Spec.ServiceServingCertSignerConfig.Raw)
	if err != nil {
		return nil, false, err
	}
	return resourceapply.ApplyConfigMap(client, requiredConfigMap)
}

// TODO manage rotation in addition to initial creation
func manageSigningSecret_v311_00_to_latest(client coreclientv1.SecretsGetter) (*corev1.Secret, bool, error) {
	secret := resourceread.ReadSecretV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/signing-secret.yaml"))
	existing, err := client.Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		// Check the existing CA expiration to see if we need to do key rotation.
		currentCACertPem, currentCAKeyPem, err := getCertSecretData(existing)
		if err != nil {
			return nil, false, err
		}
		currentCACert, err := parsePemCert(currentCACertPem)
		if err != nil {
			return nil, false, err
		}
		currentCAKey, err := parsePemKey(currentCAKeyPem)
		if err != nil {
			return nil, false, err
		}

		now := time.Now()
		tilExpire := currentCACert.NotAfter.Sub(now)

		halfExpiration := now.Add(time.Duration(tilExpire.Nanoseconds()/2) * time.Nanosecond)
		if !now.After(halfExpiration) {
			// Still time left.
			return existing, false, nil
		}

		// Half of the CA expiration time has elapsed, go ahead and rotate.
		// Create the new CA
		newCACert, newCAKey, newCACertPem, newCAKeyPem, err := createServiceSigner(currentCACert.Subject, 356)
		if err != nil {
			return nil, false, err
		}
		// The first interim CA comprises of the old CA's public key, private key, and subject. It's self-issued but not
		// self-signed as it's signed by the new CA key. This creates a trust bridge between refreshed clients and
		// unrefreshed servers.
		signedByNew, err := x509.CreateCertificate(crand.Reader, currentCACert, currentCACert, currentCACert.PublicKey, newCAKey)
		if err != nil {
			return nil, false, err
		}

		// The second interim CA comprises of the new CA's public key, private key, and subject. It's self-issued but not
		// self-signed as it's signed by the old CA key. This creates a trust bridge between the unrefreshed clients and
		// refreshed servers, as long as refreshed servers serve with a bundle containing this CA and the serving cert.
		signedByOld, err := x509.CreateCertificate(crand.Reader, newCACert, newCACert, newCACert.PublicKey, currentCAKey)
		if err != nil {
			return nil, false, err
		}

		// Assemble bundle.
		signedByNewPem, err := encodeASN1Cert(signedByNew)
		if err != nil {
			return nil, false, err
		}

		signedByOldPem, err := encodeASN1Cert(signedByOld)
		if err != nil {
			return nil, false, err
		}

		bundle := make([]byte, 0)
		bundle = append(bundle, currentCACertPem...)
		bundle = append(bundle, signedByNewPem...)
		bundle = append(bundle, signedByOldPem...)
		bundle = append(bundle, newCACertPem...)

		secret.Data["tls.crt"] = newCACertPem
		secret.Data["tls.key"] = newCAKeyPem
		secret.Data["intermediate.crt"] = signedByOldPem
		secret.Data["cabundle.crt"] = bundle

		return resourceapply.ApplySecret(client, secret)
	}

	ca, err := cryptohelpers.MakeCAConfig(serviceServingCertSignerName(), 10)
	if err != nil {
		return existing, false, err
	}

	certBytes := &bytes.Buffer{}
	keyBytes := &bytes.Buffer{}
	if err := ca.WriteCertConfig(certBytes, keyBytes); err != nil {
		return existing, false, err
	}

	secret.Data["tls.crt"] = certBytes.Bytes()
	secret.Data["tls.key"] = keyBytes.Bytes()

	return resourceapply.ApplySecret(client, secret)
}

func encodeASN1Cert(certDer []byte) ([]byte, error) {
	b := bytes.Buffer{}
	err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func createServiceSigner(caSubject pkix.Name, days int) (*x509.Certificate, crypto.PrivateKey, []byte, []byte, error) {
	// XXX set subjectKeyId
	replacementCATemplate := &x509.Certificate{
		Subject: caSubject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    time.Now().Add(-1 * time.Second),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		SerialNumber: big.NewInt(1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	replacementCAPublicKey, replacementCAPrivateKey, err := cryptohelpers.NewKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	replacementDer, err := x509.CreateCertificate(crand.Reader, replacementCATemplate, replacementCATemplate, replacementCAPublicKey, replacementCAPrivateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	replacementCert, err := x509.ParseCertificates(replacementDer)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(replacementCert) != 1 {
		return nil, nil, nil, nil, fmt.Errorf("Expected one certificate")
	}

	caPem, err := encodeCertificates(replacementCert...)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	caKey, err := encodeKey(replacementCAPrivateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return replacementCert[0], replacementCAPrivateKey, caPem, caKey, nil
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

func getCertSecretData(secret *corev1.Secret) ([]byte, []byte, error) {
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

func manageSignerDeployment_v311_00_to_latest(client appsclientv1.DeploymentsGetter, options *scsv1alpha1.ServiceCertSignerOperatorConfig, previousAvailability *operatorsv1alpha1.VersionAvailability, forceDeployment bool) (*appsv1.Deployment, bool, error) {
	required := resourceread.ReadDeploymentV1OrDie(v310_00_assets.MustAsset("v3.10.0/service-serving-cert-signer-controller/deployment.yaml"))
	required.Spec.Template.Spec.Containers[0].Image = options.Spec.ImagePullSpec
	required.Spec.Template.Spec.Containers[0].Args = append(required.Spec.Template.Spec.Containers[0].Args, fmt.Sprintf("-v=%d", options.Spec.Logging.Level))

	return resourceapply.ApplyDeployment(client, required, resourcemerge.ExpectedDeploymentGeneration(required, previousAvailability), forceDeployment)
}

func serviceServingCertSignerName() string {
	return fmt.Sprintf("%s@%d", "openshift-service-serving-signer", time.Now().Unix())
}
