package authnz

import (
	"errors"
	"testing"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// testEntry stands in for the hash of a configured user; nothing here checks
// a password.
const testEntry = "not-checked"

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
	mw := ClaimsMiddleware(appConfig(auth), nil)

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
	mw := ClaimsMiddleware(appConfig(auth), nil)

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
	mw := ClaimsMiddleware(appConfig(auth), nil)

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
	mw := ClaimsMiddleware(appConfig(auth), nil)

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
			Basic: &authconfig.BasicAuthConfig{Users: []string{"bob:" + testEntry}},
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
	mw := ClaimsMiddleware(appConfig(auth), nil)

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
	mw := ClaimsMiddleware(appConfig(authconfig.AuthConfig{}), nil)
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
		ProviderConfig: authconfig.ProviderConfig{
			Basic: &authconfig.BasicAuthConfig{Users: []string{"admin:" + testEntry}},
		},
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {
				OIDC: &authconfig.OIDCConfig{Name: "corp"},
			},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth), nil)

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

// A session or an API token made before an admin revoked somebody's access
// still carries its claims; the check has to ask on every request.
func TestClaimsMiddlewareRefusesARevokedUser(t *testing.T) {
	revoked := map[string]bool{"alice": true}
	mw := ClaimsMiddleware(appConfig(authconfig.AuthConfig{}), func(subject string) (bool, error) {
		return revoked[subject], nil
	})

	expectNotAuthorized(t, mw(&authsession.Identity{Provider: "corp", Subject: "alice"}))
	if err := mw(&authsession.Identity{Provider: "corp", Subject: "bob"}); err != nil {
		t.Errorf("somebody else was refused: %v", err)
	}

	delete(revoked, "alice")
	if err := mw(&authsession.Identity{Provider: "corp", Subject: "alice"}); err != nil {
		t.Errorf("alice was refused after getting access back: %v", err)
	}
}

// Not knowing whether the access was revoked must not let the request through.
func TestClaimsMiddlewareFailsClosedWithoutTheUsers(t *testing.T) {
	mw := ClaimsMiddleware(appConfig(authconfig.AuthConfig{}), func(string) (bool, error) {
		return false, errors.New("connection refused")
	})
	if err := mw(&authsession.Identity{Provider: "corp", Subject: "alice"}); err == nil {
		t.Error("the request went through without knowing whether alice was revoked")
	}
}

// A session and an API token keep the identity from sign-in. For the built-in
// providers the configuration is the only thing that says who may come in, so
// a user who was taken out of it must be refused on the requests that follow,
// not when the session ends 30 days later.
func TestClaimsMiddlewareRefusesAUserRemovedFromTheConfiguration(t *testing.T) {
	for _, provider := range []string{authconfig.SimpleAuthProvider, authconfig.BasicAuthProvider} {
		t.Run(provider, func(t *testing.T) {
			auth := authconfig.AuthConfig{
				Multiple: map[string]*authconfig.ProviderConfig{
					// the other built-in provider's list counts as well
					"a": {Simple: &authconfig.SimpleAuthConfig{Users: []string{"alice:" + testEntry}}},
					"b": {Basic: &authconfig.BasicAuthConfig{Users: []string{"carol:" + testEntry}}},
				},
			}
			mw := ClaimsMiddleware(appConfig(auth), nil)

			for _, listed := range []string{"alice", "carol"} {
				if err := mw(&authsession.Identity{Provider: provider, Subject: listed}); err != nil {
					t.Errorf("%s is in the configuration and was refused: %v", listed, err)
				}
			}
			expectNotAuthorized(t, mw(&authsession.Identity{Provider: provider, Subject: "bob"}))
		})
	}
}

// ... and the configuration says nothing about the people who come in through
// an identity provider.
func TestClaimsMiddlewareLeavesIdentityProviderUsersAlone(t *testing.T) {
	auth := authconfig.AuthConfig{
		ProviderConfig: authconfig.ProviderConfig{
			Simple: &authconfig.SimpleAuthConfig{Users: []string{"alice:" + testEntry}},
		},
		Multiple: map[string]*authconfig.ProviderConfig{
			"corp": {OIDC: &authconfig.OIDCConfig{Name: "corp"}},
		},
	}
	mw := ClaimsMiddleware(appConfig(auth), nil)
	if err := mw(&authsession.Identity{Provider: "corp", Subject: "bob"}); err != nil {
		t.Errorf("an OIDC user was refused for not being in simple.users: %v", err)
	}
}
