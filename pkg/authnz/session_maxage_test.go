package authnz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
)

func TestSessionMaxAge(t *testing.T) {
	tests := []struct {
		name    string
		config  *authconfig.SessionStoreConfig
		want    int
		wantErr bool
	}{
		{name: "no session store configured", want: int(DefaultSessionMaxAge.Seconds())},
		{name: "empty value keeps the default", config: &authconfig.SessionStoreConfig{}, want: int(DefaultSessionMaxAge.Seconds())},
		{name: "hours", config: &authconfig.SessionStoreConfig{MaxAge: "24h"}, want: 86400},
		{name: "minutes", config: &authconfig.SessionStoreConfig{MaxAge: "90m"}, want: 5400},
		{name: "not a duration", config: &authconfig.SessionStoreConfig{MaxAge: "forever"}, wantErr: true},
		// a zero or negative MaxAge means something entirely different to
		// gorilla/sessions (session cookie / delete), so refuse it
		{name: "zero", config: &authconfig.SessionStoreConfig{MaxAge: "0s"}, wantErr: true},
		{name: "negative", config: &authconfig.SessionStoreConfig{MaxAge: "-1h"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sessionMaxAge(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("sessionMaxAge(%+v) = %d, want an error", tt.config, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("sessionMaxAge(%+v) returned %v", tt.config, err)
			}
			if got != tt.want {
				t.Errorf("sessionMaxAge(%+v) = %d, want %d", tt.config, got, tt.want)
			}
		})
	}
}

// The configured lifetime has to reach the cookie, not just the store.
func TestSessionCookieUsesTheConfiguredMaxAge(t *testing.T) {
	m := newBasicAuthMiddlewareWithSessionStore(t, "admin", "s3cret",
		&authconfig.SessionStoreConfig{MaxAge: "2h"})

	req := httptest.NewRequest("POST", "/signin/0", nil)
	req.SetBasicAuth("admin", "s3cret")
	rr := httptest.NewRecorder()
	m.Middleware(http.NotFoundHandler()).ServeHTTP(rr, req)

	if cookie := findSessionCookie(t, rr); cookie.MaxAge != 7200 {
		t.Errorf("session cookie Max-Age = %d, want 7200", cookie.MaxAge)
	}
}

// A bad value must stop the server rather than silently falling back.
func TestNewRefusesABadMaxAge(t *testing.T) {
	_, err := New(authconfig.AuthConfig{
		SessionStore: &authconfig.SessionStoreConfig{MaxAge: "yesterday"},
	}, nil)
	if err == nil {
		t.Fatal("New accepted a session lifetime that is not a duration")
	}
}
