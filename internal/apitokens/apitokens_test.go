package apitokens

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func alice() *authsession.Identity {
	return &authsession.Identity{Provider: "oidc", Subject: "alice", Name: "Alice", Email: "alice@example.org"}
}

func newManager(t *testing.T, claims authsession.ClaimsMiddleware) (*Manager, *storage.InMemoryStorage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	return New(s, claims), s
}

func TestCreateAndAuthenticate(t *testing.T) {
	m, s := newManager(t, nil)

	secret, token, err := m.Create(alice(), "  backup script ", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, Prefix) {
		t.Errorf("secret %q does not start with %q", secret, Prefix)
	}
	if token.Name != "backup script" {
		t.Errorf("name = %q, want it trimmed", token.Name)
	}

	// the secret itself is nowhere in the storage
	stored, _ := s.ListTokens("")
	for _, st := range stored {
		if strings.Contains(st.Hash+st.Identity+st.ID+st.Name, strings.TrimPrefix(secret, Prefix)) {
			t.Fatal("the secret is stored")
		}
	}

	identity, used, err := m.Authenticate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "alice" || identity.Email != "alice@example.org" || identity.Provider != "oidc" {
		t.Errorf("identity = %+v, want alice's", identity)
	}
	if used.ID != token.ID {
		t.Errorf("authenticated with token %s, want %s", used.ID, token.ID)
	}

	second, _, err := m.Create(alice(), "another", nil)
	if err != nil {
		t.Fatal(err)
	}
	if second == secret {
		t.Error("two tokens got the same secret")
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	m, _ := newManager(t, nil)
	past := time.Now().Add(-time.Minute)

	for name, create := range map[string]func() error{
		"empty name":    func() error { _, _, err := m.Create(alice(), "   ", nil); return err },
		"long name":     func() error { _, _, err := m.Create(alice(), strings.Repeat("x", 101), nil); return err },
		"expiry passed": func() error { _, _, err := m.Create(alice(), "old", &past); return err },
	} {
		var validation *ValidationError
		if err := create(); !errors.As(err, &validation) {
			t.Errorf("%s: err = %v, want a ValidationError", name, err)
		}
	}
}

func TestAuthenticateRefuses(t *testing.T) {
	m, _ := newManager(t, nil)
	expires := time.Now().Add(time.Hour)
	secret, token, err := m.Create(alice(), "script", &expires)
	if err != nil {
		t.Fatal(err)
	}

	for name, candidate := range map[string]string{
		"unknown":        Prefix + "not-a-token",
		"without prefix": strings.TrimPrefix(secret, Prefix),
		"empty":          "",
	} {
		if _, _, err := m.Authenticate(candidate); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}

	m.now = func() time.Time { return expires }
	if _, _, err := m.Authenticate(secret); !errors.Is(err, ErrExpired) {
		t.Errorf("at the expiry: err = %v, want ErrExpired", err)
	}
	m.now = time.Now

	if _, err := m.Delete(alice(), token.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Authenticate(secret); !errors.Is(err, ErrInvalid) {
		t.Errorf("revoked: err = %v, want ErrInvalid", err)
	}
}

// For basic auth the admin claim comes from the configuration, so a token
// must not preserve it: it is admin exactly as long as its owner is the
// configured admin.
func TestConfiguredAdminIsNotFrozenIntoTheToken(t *testing.T) {
	adminUsername := "root"
	claims := func(user *authsession.Identity) error {
		if user.Provider == authconfig.BasicAuthProvider && user.Subject == adminUsername {
			user.Claims.MakeAdmin()
		}
		return nil
	}
	m, _ := newManager(t, claims)

	root := &authsession.Identity{Provider: authconfig.BasicAuthProvider, Subject: "root"}
	root.Claims.MakeAdmin() // as the session middleware leaves it
	secret, _, err := m.Create(root, "ops", nil)
	if err != nil {
		t.Fatal(err)
	}

	identity, _, err := m.Authenticate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Claims.IsAdmin() {
		t.Error("the configured admin's token is not admin")
	}

	adminUsername = "somebody-else"
	identity, _, err = m.Authenticate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Claims.IsAdmin() {
		t.Error("the token stayed admin after its owner stopped being the configured admin")
	}
}

// Claims from an identity provider are kept, like a session keeps them.
func TestProviderClaimsAreKept(t *testing.T) {
	m, _ := newManager(t, nil)
	owner := alice()
	owner.Claims.MakeAdmin()
	owner.Claims.Add("group", "ops")

	secret, _, err := m.Create(owner, "ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := m.Authenticate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Claims.IsAdmin() || !identity.Claims.Has("group", "ops") {
		t.Errorf("claims = %+v, want the provider's", identity.Claims)
	}
}

func TestOwnerWithoutAccessIsForbidden(t *testing.T) {
	allowed := true
	m, _ := newManager(t, func(*authsession.Identity) error {
		if !allowed {
			return errors.New("User has no access")
		}
		return nil
	})
	secret, _, err := m.Create(alice(), "script", nil)
	if err != nil {
		t.Fatal(err)
	}

	allowed = false
	var forbidden *ForbiddenError
	if _, _, err := m.Authenticate(secret); !errors.As(err, &forbidden) {
		t.Errorf("err = %v, want a ForbiddenError", err)
	}
}

func TestLastUseIsRecordedAtMostOncePerInterval(t *testing.T) {
	m, s := newManager(t, nil)
	now := time.Now()
	m.now = func() time.Time { return now }
	secret, token, err := m.Create(alice(), "poller", nil)
	if err != nil {
		t.Fatal(err)
	}

	lastUse := func() time.Time {
		stored, _ := s.GetToken(token.ID)
		if stored.LastUsedAt == nil {
			return time.Time{}
		}
		return *stored.LastUsedAt
	}

	first := now
	if _, _, err := m.Authenticate(secret); err != nil {
		t.Fatal(err)
	}
	if !lastUse().Equal(first) {
		t.Fatalf("last use = %v, want %v", lastUse(), first)
	}

	now = first.Add(touchInterval / 2)
	_, _, _ = m.Authenticate(secret)
	if !lastUse().Equal(first) {
		t.Errorf("last use was written again within the interval: %v", lastUse())
	}

	now = first.Add(touchInterval)
	_, _, _ = m.Authenticate(secret)
	if !lastUse().Equal(now) {
		t.Errorf("last use = %v, want %v", lastUse(), now)
	}
}

func TestDeleteIsLimitedToOwnerAndAdmins(t *testing.T) {
	m, _ := newManager(t, nil)
	_, token, err := m.Create(alice(), "script", nil)
	if err != nil {
		t.Fatal(err)
	}

	mallory := &authsession.Identity{Provider: "oidc", Subject: "mallory"}
	if _, err := m.Delete(mallory, token.ID); !errors.Is(err, storage.ErrTokenNotFound) {
		t.Errorf("another user: err = %v, want ErrTokenNotFound", err)
	}

	admin := &authsession.Identity{Provider: "oidc", Subject: "admin"}
	admin.Claims.MakeAdmin()
	if _, err := m.Delete(admin, token.ID); err != nil {
		t.Errorf("an admin could not revoke the token: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	m, _ := newManager(t, nil)
	secret, token, err := m.Create(alice(), "script", nil)
	if err != nil {
		t.Fatal(err)
	}

	var seen *authsession.Identity
	var seenToken string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = authsession.CurrentUser(r.Context())
		seenToken = authsession.APIToken(r.Context())
	})

	// a browser session of somebody else, as the session middleware leaves it
	withSession := func(r *http.Request) *http.Request {
		return r.WithContext(authsession.SetIdentityCtx(r.Context(), &authsession.AuthSession{
			Identity: &authsession.Identity{Subject: "bob"},
		}))
	}

	serve := func(manager *Manager, path, authorization string) *httptest.ResponseRecorder {
		seen, seenToken = nil, ""
		r := withSession(httptest.NewRequest(http.MethodPost, path, nil))
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		Middleware(manager)(next).ServeHTTP(w, r)
		return w
	}

	t.Run("a valid token acts as its owner", func(t *testing.T) {
		w := serve(m, "/api/proto.Devices/ListDevices", "Bearer "+secret)
		if w.Code != http.StatusOK || seen == nil || seen.Subject != "alice" {
			t.Fatalf("status %d, identity %+v: want alice", w.Code, seen)
		}
		if seenToken != token.ID {
			t.Errorf("token = %q, want %q", seenToken, token.ID)
		}
	})

	t.Run("the scheme is case insensitive", func(t *testing.T) {
		if serve(m, "/api/x", "bearer "+secret); seen == nil || seen.Subject != "alice" {
			t.Errorf("identity %+v, want alice", seen)
		}
	})

	t.Run("an invalid token is refused, not passed on", func(t *testing.T) {
		w := serve(m, "/api/x", "Bearer "+Prefix+"nope")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", w.Code)
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Error("no WWW-Authenticate header")
		}
		if seen != nil {
			t.Error("the request reached the handler")
		}
	})

	t.Run("disabled tokens are refused", func(t *testing.T) {
		if w := serve(nil, "/api/x", "Bearer "+secret); w.Code != http.StatusUnauthorized || seen != nil {
			t.Errorf("status %d, reached handler %v", w.Code, seen != nil)
		}
	})

	t.Run("the web UI does not accept tokens", func(t *testing.T) {
		serve(m, "/", "Bearer "+secret)
		if seen == nil || seen.Subject != "bob" || seenToken != "" {
			t.Errorf("identity %+v, token %q: want bob's session untouched", seen, seenToken)
		}
	})

	t.Run("without a token the session is used", func(t *testing.T) {
		serve(m, "/api/x", "")
		if seen == nil || seen.Subject != "bob" {
			t.Errorf("identity %+v, want bob", seen)
		}
	})

	t.Run("basic credentials are not a token", func(t *testing.T) {
		serve(m, "/api/x", "Basic YWRtaW46aHVudGVyMg==")
		if seen == nil || seen.Subject != "bob" {
			t.Errorf("identity %+v, want bob", seen)
		}
	})

	t.Run("an owner without access is forbidden", func(t *testing.T) {
		denying, _ := newManager(t, func(*authsession.Identity) error { return errors.New("no access") })
		denied, _, err := denying.Create(alice(), "script", nil)
		if err != nil {
			t.Fatal(err)
		}
		if w := serve(denying, "/api/x", "Bearer "+denied); w.Code != http.StatusForbidden || seen != nil {
			t.Errorf("status %d, reached handler %v", w.Code, seen != nil)
		}
	})
}

func TestMaxLifetimeRefusesTokensBeyondTheCap(t *testing.T) {
	const day = 24 * time.Hour
	within, at, beyond, far := time.Now().Add(time.Hour), time.Now().Add(day), time.Now().Add(2*day), time.Now().Add(10*365*day)

	capped := New(storage.NewMemoryStorage(), nil, WithMaxLifetime(day))
	for name, expiresAt := range map[string]*time.Time{"never": nil, "beyond the cap": &beyond, "far beyond": &far} {
		_, _, err := capped.Create(alice(), name, expiresAt)
		var validation *ValidationError
		if !errors.As(err, &validation) {
			t.Errorf("%s: err = %v, want a ValidationError", name, err)
		} else if !strings.Contains(err.Error(), "limits API tokens to 24h0m0s") {
			t.Errorf("%s: the message %q does not say what the limit is", name, err)
		}
	}
	for name, expiresAt := range map[string]*time.Time{"within the cap": &within, "at the cap": &at} {
		if _, _, err := capped.Create(alice(), name, expiresAt); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// the minute given for the browser's clock is accepted, but the token
	// says the expiry that applies, as the list does
	slack := time.Now().Add(day + 30*time.Second)
	_, token, err := capped.Create(alice(), "a little past the cap", &slack)
	if err != nil {
		t.Fatalf("a little past the cap: %v", err)
	}
	if limit := token.CreatedAt.Add(day); token.ExpiresAt == nil || token.ExpiresAt.After(limit) {
		t.Errorf("the token says it expires at %v, after the cap at %v", token.ExpiresAt, limit)
	}

	// without a cap nothing changes: no expiry, or one far away, is fine
	for _, m := range []*Manager{New(storage.NewMemoryStorage(), nil), New(storage.NewMemoryStorage(), nil, WithMaxLifetime(0))} {
		for name, expiresAt := range map[string]*time.Time{"never": nil, "far": &far} {
			if _, _, err := m.Create(alice(), name, expiresAt); err != nil {
				t.Errorf("no cap, %s: %v", name, err)
			}
		}
	}
}

// Setting the cap has to reach the tokens that exist: they are refused once
// created_at + cap has passed, whatever expiry they carry. Every backend that
// keeps tokens, since the check works on what the storage returns.
func TestMaxLifetimeAppliesToExistingTokens(t *testing.T) {
	const cap = 24 * time.Hour
	backends := map[string]string{
		"memory":   "memory://",
		"sqlite3":  "sqlite3://" + filepath.Join(t.TempDir(), "tokens.db"),
		"postgres": os.Getenv("WG_TEST_POSTGRES_URI"),
		"mysql":    os.Getenv("WG_TEST_MYSQL_URI"),
	}
	for name, uri := range backends {
		if uri == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, err := storage.NewStorage(uri)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Open(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			owner := alice()
			owner.Subject = "cap-owner-" + name
			t.Cleanup(func() { _, _ = s.DeleteTokensForOwner(owner.Subject) })

			// made before the cap existed: one that never expires, one that
			// expires in a year, one that expires within the cap
			created := time.Now().Truncate(time.Second)
			before := New(s, nil)
			before.now = func() time.Time { return created }
			year, soon := created.Add(365*cap), created.Add(time.Hour)
			never, _, err := before.Create(owner, "never", nil)
			if err != nil {
				t.Fatal(err)
			}
			yearly, _, err := before.Create(owner, "yearly", &year)
			if err != nil {
				t.Fatal(err)
			}
			short, _, err := before.Create(owner, "short", &soon)
			if err != nil {
				t.Fatal(err)
			}

			at := func(when time.Time) func() time.Time { return func() time.Time { return when } }

			// no cap: both work long after
			if _, _, err := before.Authenticate(never); err != nil {
				t.Errorf("without a cap, a token that never expires: %v", err)
			}

			capped := New(s, nil, WithMaxLifetime(cap))
			capped.now = at(created.Add(cap - time.Minute))
			for name, secret := range map[string]string{"never": never, "yearly": yearly} {
				if _, _, err := capped.Authenticate(secret); err != nil {
					t.Errorf("%s, just before created_at + cap: %v", name, err)
				}
			}
			capped.now = at(created.Add(cap + time.Minute))
			for name, secret := range map[string]string{"never": never, "yearly": yearly, "short": short} {
				if _, _, err := capped.Authenticate(secret); !errors.Is(err, ErrExpired) {
					t.Errorf("%s, after created_at + cap: err = %v, want ErrExpired", name, err)
				}
			}
			// the same tokens work without the cap, apart from the one that
			// expired by itself
			before.now = at(created.Add(cap + time.Minute))
			for name, secret := range map[string]string{"never": never, "yearly": yearly} {
				if _, _, err := before.Authenticate(secret); err != nil {
					t.Errorf("%s without the cap, a day later: %v", name, err)
				}
			}

			// listings show the expiry that applies
			capped.now = time.Now
			listed, err := capped.List(owner.Subject)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 3 {
				t.Fatalf("%d tokens listed, want 3", len(listed))
			}
			for _, token := range listed {
				want := token.CreatedAt.Add(cap)
				if token.Name == "short" {
					want = token.CreatedAt.Add(time.Hour)
				}
				if token.ExpiresAt == nil || !token.ExpiresAt.Equal(want) {
					t.Errorf("%s: listed expiry %v, want %v", token.Name, token.ExpiresAt, want)
				}
			}
			plain, err := New(s, nil).List(owner.Subject)
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range plain {
				if token.Name == "never" && token.ExpiresAt != nil {
					t.Errorf("without a cap, the listed expiry of a token that never expires is %v", token.ExpiresAt)
				}
			}
		})
	}
}
