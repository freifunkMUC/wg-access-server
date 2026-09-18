package services

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func generate(t *testing.T, hosts []string) (*x509.Certificate, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "wg-access-server.crt")
	keyPath := filepath.Join(dir, "wg-access-server.key")

	if err := GenerateSelfSignedCert(certPath, keyPath, hosts); err != nil {
		t.Fatal(err)
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("certificate file does not contain a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPath, keyPath
}

func TestGenerateSelfSignedCertCoversItsHosts(t *testing.T) {
	cert, _, keyPath := generate(t, []string{"localhost", "vpn.example.com", "127.0.0.1", "192.0.2.10", "2001:db8::1"})

	for _, name := range []string{"localhost", "vpn.example.com"} {
		if !slices.Contains(cert.DNSNames, name) {
			t.Errorf("certificate has DNS names %q, want it to contain %q", cert.DNSNames, name)
		}
	}
	for _, addr := range []string{"127.0.0.1", "192.0.2.10", "2001:db8::1"} {
		ip := net.ParseIP(addr)
		if !slices.ContainsFunc(cert.IPAddresses, func(got net.IP) bool { return got.Equal(ip) }) {
			t.Errorf("certificate has IPs %v, want it to contain %s", cert.IPAddresses, addr)
		}
	}

	// The browser has to accept the address people type, so verifying against
	// a LAN address must succeed.
	if err := cert.VerifyHostname("192.0.2.10"); err != nil {
		t.Errorf("certificate is not valid for the LAN address: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("private key has mode %o, want 600", mode)
	}
}

// A serial number hardcoded to 1 makes the certificates of two installations
// collide in a trust store that holds both.
func TestGenerateSelfSignedCertUsesRandomSerials(t *testing.T) {
	first, _, _ := generate(t, []string{"localhost"})
	second, _, _ := generate(t, []string{"localhost"})

	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Errorf("both certificates use serial number %s", first.SerialNumber)
	}
}

// An existing certificate must be kept - regenerating it on every start would
// hand out a new identity each time.
func TestLoadTLSCertKeepsAnExistingCertificate(t *testing.T) {
	cert, certPath, keyPath := generate(t, []string{"localhost"})

	if _, err := LoadTLSCert(certPath, keyPath, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	reloaded, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("the existing certificate was replaced")
	}
}

func TestLoadTLSCertGeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "sub", "wg-access-server.crt")
	keyPath := filepath.Join(dir, "sub", "wg-access-server.key")

	config, err := LoadTLSCert(certPath, keyPath, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(config.Certificates))
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was not written: %v", path, err)
		}
	}
}

func TestHostFromExternalHost(t *testing.T) {
	tests := []struct {
		externalHost string
		want         string
	}{
		{externalHost: "", want: ""},
		{externalHost: "vpn.example.com", want: "vpn.example.com"},
		{externalHost: "https://vpn.example.com", want: "vpn.example.com"},
		{externalHost: "https://vpn.example.com:8443", want: "vpn.example.com"},
		{externalHost: "https://vpn.example.com:8443/", want: "vpn.example.com"},
		{externalHost: "  https://vpn.example.com/ui  ", want: "vpn.example.com"},
		{externalHost: "192.0.2.10", want: "192.0.2.10"},
		{externalHost: "192.0.2.10:8443", want: "192.0.2.10"},
		{externalHost: "2001:db8::1", want: "2001:db8::1"},
		{externalHost: "[2001:db8::1]:8443", want: "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.externalHost, func(t *testing.T) {
			if got := hostFromExternalHost(tt.externalHost); got != tt.want {
				t.Errorf("hostFromExternalHost(%q) = %q, want %q", tt.externalHost, got, tt.want)
			}
		})
	}
}

func TestCertHosts(t *testing.T) {
	hosts := CertHosts("https://vpn.example.com:8443")

	for _, want := range []string{"localhost", "127.0.0.1", "::1", "vpn.example.com"} {
		if !slices.Contains(hosts, want) {
			t.Errorf("CertHosts() = %q, want it to contain %q", hosts, want)
		}
	}

	seen := map[string]bool{}
	for _, host := range hosts {
		if seen[host] {
			t.Errorf("CertHosts() = %q, contains %q twice", hosts, host)
		}
		seen[host] = true
	}

	// The addresses of this machine are what makes reaching the UI over the
	// LAN or the VPN address work without a warning.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot list interface addresses: %v", err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		if !slices.Contains(hosts, ipnet.IP.String()) {
			t.Errorf("CertHosts() = %q, want it to contain the local address %q", hosts, ipnet.IP)
		}
	}
}
