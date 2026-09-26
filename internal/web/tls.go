package web

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
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CertHosts returns the names and addresses a generated certificate should be
// valid for: localhost, every address currently configured on this machine -
// which covers the LAN address people actually type as well as the server's
// own VPN address - and the configured external host.
func CertHosts(externalHost string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}

	if host := hostFromExternalHost(externalHost); host != "" {
		hosts = append(hosts, host)
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logrus.Warn(errors.Wrap(err, "failed to list interface addresses for the self-signed certificate"))
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		// Link-local addresses are not how anyone reaches the web UI and
		// would only bloat the certificate.
		if ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		hosts = append(hosts, ipnet.IP.String())
	}

	return deduplicate(hosts)
}

// hostFromExternalHost reduces the configured external host to a bare host
// name or address: it may carry a scheme, a port and a path
// (e.g. "https://vpn.example.com:8443/").
func hostFromExternalHost(externalHost string) string {
	host := strings.TrimSpace(externalHost)
	if host == "" {
		return ""
	}
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}
	// a bare IPv6 address may still be bracketed
	return strings.Trim(host, "[]")
}

func deduplicate(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

// GenerateSelfSignedCert generates a self-signed certificate and key valid
// for the given hosts (names and IP addresses) and saves them to the
// specified paths
func GenerateSelfSignedCert(certPath, keyPath string, hosts []string) error {
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

	// A certificate is identified by issuer and serial number, so a serial
	// hardcoded to 1 makes the certificates of two installations look like the
	// same one to a trust store that has both.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return errors.Wrap(err, "failed to generate a certificate serial number")
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"WG Access Server"},
			CommonName:   "WG Access Server Self-Signed Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	logrus.Infof("Generating a self-signed certificate for: %s", strings.Join(hosts, ", "))

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
// If the certificate doesn't exist, it generates a self-signed one valid for
// the given hosts
func LoadTLSCert(certPath, keyPath string, hosts []string) (*tls.Config, error) {
	// Check if certificate and key exist
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	// If either file doesn't exist, generate a self-signed certificate
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		logrus.Info("Certificate or key not found, generating self-signed certificate")
		if err := GenerateSelfSignedCert(certPath, keyPath, hosts); err != nil {
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
		MinVersion:   tls.VersionTLS12,
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
