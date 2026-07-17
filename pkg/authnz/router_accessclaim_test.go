package authnz

import (
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// appConfig builds a minimal AppConfig for exercising ClaimsMiddleware.
func appConfig(auth authconfig.AuthConfig) *config.AppConfig {
	return &config.AppConfig{
		AdminUsername: "admin",
		Auth:          auth,
	}
}

// expectNotAuthorized asserts that err is a *LoginError with code NotAuthorized.
func expectNotAuthorized(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a NotAuthorized error, got nil")
	}
	lerr, ok := err.(*LoginError)
	if !ok {
		t.Fatalf("expected *LoginError, got %T: %v", err, err)
	}
	if lerr.code != NotAuthorized {
		t.Fatalf("expected error code NotAuthorized (%d), got %d", NotAuthorized, lerr.code)
	}
}

func TestClaimsMiddlewareMultipleOIDCAccessClaim(t *testing.T) {
	auth := authconfig.AuthConfig{
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {
				OIDC: &authconfig.OIDCConfig{
					Name:        "corp",
					AccessClaim: "vpn-access",
				},
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth))

	t.Run("missing access claim is rejected", func(t *testing.T) {
		user := &authsession.Identity{Provider: "corp", Subject: "alice"}
		expectNotAuthorized(t, mw(user))
	})

	t.Run("access claim with wrong value is rejected", func(t *testing.T) {
		user := &authsession.Identity{Provider: "corp", Subject: "alice"}
		user.Claims.Add("vpn-access", "false")
		expectNotAuthorized(t, mw(user))
	})

	t.Run("access claim present is allowed", func(t *testing.T) {
		user := &authsession.Identity{Provider: "corp", Subject: "alice"}
		user.Claims.Add("vpn-access", "true")
		if err := mw(user); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

// The provider name defaults to the map key when OIDC.Name is left empty
// (mirroring AuthConfig.Providers), so the accessClaim must still be enforced.
func TestClaimsMiddlewareMultipleOIDCAccessClaimMapKeyFallback(t *testing.T) {
	auth := authconfig.AuthConfig{
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {
				OIDC: &authconfig.OIDCConfig{
					// Name intentionally empty; falls back to map key "corp"
					AccessClaim: "vpn-access",
				},
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth))

	user := &authsession.Identity{Provider: "corp", Subject: "alice"}
	expectNotAuthorized(t, mw(user))

	user = &authsession.Identity{Provider: "corp", Subject: "alice"}
	user.Claims.Add("vpn-access", "true")
	if err := mw(user); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// An explicitly set OIDC.Name takes precedence over the map key: a user
// carrying the map key as provider name must not match that provider.
func TestClaimsMiddlewareMultipleOIDCExplicitNameWinsOverMapKey(t *testing.T) {
	auth := authconfig.AuthConfig{
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {
				OIDC: &authconfig.OIDCConfig{
					Name:        "sso",
					AccessClaim: "vpn-access",
				},
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth))

	// provider "sso" is checked...
	user := &authsession.Identity{Provider: "sso", Subject: "alice"}
	expectNotAuthorized(t, mw(user))

	// ...but the map key "corp" no longer identifies this provider
	user = &authsession.Identity{Provider: "corp", Subject: "alice"}
	if err := mw(user); err != nil {
		t.Fatalf("expected nil error for non-matching provider name, got %v", err)
	}
}

// Regression: the legacy top-level auth.oidc accessClaim must still be enforced.
func TestClaimsMiddlewareLegacyOIDCAccessClaim(t *testing.T) {
	auth := authconfig.AuthConfig{
		ProviderConfig: authconfig.ProviderConfig{
			OIDC: &authconfig.OIDCConfig{
				Name:        "legacy-oidc",
				AccessClaim: "vpn-access",
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth))

	user := &authsession.Identity{Provider: "legacy-oidc", Subject: "alice"}
	expectNotAuthorized(t, mw(user))

	user = &authsession.Identity{Provider: "legacy-oidc", Subject: "alice"}
	user.Claims.Add("vpn-access", "true")
	if err := mw(user); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestClaimsMiddlewareNoAccessClaimConfigured(t *testing.T) {
	auth := authconfig.AuthConfig{
		ProviderConfig: authconfig.ProviderConfig{
			Basic: &authconfig.BasicAuthConfig{Users: []string{}},
		},
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {
				OIDC: &authconfig.OIDCConfig{
					Name: "corp",
					// no AccessClaim configured
				},
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth))

	t.Run("basic auth provider without OIDC config is allowed", func(t *testing.T) {
		user := &authsession.Identity{Provider: authconfig.BasicAuthProvider, Subject: "bob"}
		if err := mw(user); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("OIDC provider without accessClaim is allowed", func(t *testing.T) {
		user := &authsession.Identity{Provider: "corp", Subject: "alice"}
		if err := mw(user); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

func TestClaimsMiddlewareNilUserNotAuthenticated(t *testing.T) {
	mw := ClaimsMiddleware(appConfig(authconfig.AuthConfig{}))
	err := mw(nil)
	if err == nil {
		t.Fatal("expected an error for nil user, got nil")
	}
	lerr, ok := err.(*LoginError)
	if !ok {
		t.Fatalf("expected *LoginError, got %T: %v", err, err)
	}
	if lerr.code != NotAuthenticated {
		t.Fatalf("expected error code NotAuthenticated (%d), got %d", NotAuthenticated, lerr.code)
	}
}

// Admin elevation behavior must be untouched: only basic/simple auth users
// matching AdminUsername become admin; OIDC users never do implicitly.
func TestClaimsMiddlewareAdminElevationUntouched(t *testing.T) {
	auth := authconfig.AuthConfig{
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {
				OIDC: &authconfig.OIDCConfig{Name: "corp"},
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth))

	t.Run("basic auth admin user becomes admin", func(t *testing.T) {
		user := &authsession.Identity{Provider: authconfig.BasicAuthProvider, Subject: "admin"}
		if err := mw(user); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if !user.Claims.IsAdmin() {
			t.Error("expected basic auth admin user to be elevated to admin")
		}
	})

	t.Run("OIDC user named like admin is not elevated", func(t *testing.T) {
		user := &authsession.Identity{Provider: "corp", Subject: "admin"}
		if err := mw(user); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if user.Claims.IsAdmin() {
			t.Error("OIDC user must not be elevated to admin by username")
		}
	})
}
