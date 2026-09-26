package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveWith(t *testing.T, request *http.Request) http.Header {
	t.Helper()
	recorder := httptest.NewRecorder()
	SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(recorder, request)
	return recorder.Result().Header
}

func TestSecurityHeaders(t *testing.T) {
	header := serveWith(t, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for name, value := range want {
		if got := header.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}

	policy := header.Get("Content-Security-Policy")
	for _, directive := range []string{
		"default-src 'self'",
		"script-src 'self'",
		// MUI generates styles at runtime and the login pages carry a <style>
		"style-src 'self' 'unsafe-inline'",
		// the QR code is rendered into a data: URI
		"img-src 'self' data:",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, directive) {
			t.Errorf("Content-Security-Policy %q is missing %q", policy, directive)
		}
	}
}

// HSTS belongs on a TLS response only: a browser ignores it on plain HTTP,
// and the web UI may be served over HTTP on purpose.
func TestStrictTransportSecurityOnlyOverTLS(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := serveWith(t, plain).Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q on a plain HTTP request, want none", got)
	}

	secure := httptest.NewRequest(http.MethodGet, "/", nil)
	secure.TLS = &tls.ConnectionState{}
	if got := serveWith(t, secure).Get("Strict-Transport-Security"); got == "" {
		t.Error("no Strict-Transport-Security on a TLS request")
	}
}
