package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// GenerateSelfSignedCert generates a self-signed certificate and key
// and saves them to the specified paths
func GenerateSelfSignedCert(certPath, keyPath string) error {
	// Create directory if it doesn't exist
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return errors.Wrap(err, "failed to create certificate directory")
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.Wrap(err, "failed to generate private key")
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"WG Access Server"},
			CommonName:   "WG Access Server Self-Signed Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return errors.Wrap(err, "failed to create certificate")
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Write certificate to file
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return errors.Wrap(err, "failed to write certificate file")
	}

	// Write private key to file
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return errors.Wrap(err, "failed to write private key file")
	}

	logrus.Infof("Generated self-signed certificate: %s", certPath)
	logrus.Infof("Generated private key: %s", keyPath)

	return nil
}

// LoadTLSCert loads a TLS certificate from the specified paths
// If the certificate doesn't exist, it generates a self-signed one
func LoadTLSCert(certPath, keyPath string) (*tls.Config, error) {
	// Check if certificate and key exist
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	// If either file doesn't exist, generate a self-signed certificate
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		logrus.Info("Certificate or key not found, generating self-signed certificate")
		if err := GenerateSelfSignedCert(certPath, keyPath); err != nil {
			return nil, err
		}
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load TLS certificate")
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:  tls.VersionTLS12,
	}

	return tlsConfig, nil
}

// GetDefaultCertPaths returns the default paths for the certificate and key
func GetDefaultCertPaths() (string, string) {
	// Use the current directory as the default location
	certPath := "wg-access-server.crt"
	keyPath := "wg-access-server.key"
	return certPath, keyPath
} 
