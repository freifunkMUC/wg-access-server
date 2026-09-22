package authnz

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/traces"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authtemplates"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authutil"
)

type loginErrorCode int

const (
	NotAuthenticated loginErrorCode = 1
	NotAuthorized    loginErrorCode = 2
)

type LoginError struct {
	msg  string
	code loginErrorCode
}

func (err *LoginError) Error() string {
	return fmt.Sprintf("%d: %s", err.code, err.msg)
}

type AuthMiddleware struct {
	config           authconfig.AuthConfig
	claimsMiddleware authsession.ClaimsMiddleware
	router           *mux.Router
	runtime          *authruntime.ProviderRuntime
}

func New(config authconfig.AuthConfig, claimsMiddleware authsession.ClaimsMiddleware) (*AuthMiddleware, error) {
	router := mux.NewRouter()
	var storeSecret []byte
	if config.SessionStore == nil || config.SessionStore.Secret == "" {
		storeSecret = []byte(authutil.RandomString(32))
	} else {
		var err error
		storeSecret, err = hex.DecodeString(config.SessionStore.Secret)
		if err != nil {
			return nil, err
		}
		if len(storeSecret) != 32 {
			return nil, errors.New("Session store secret must be 32 bytes long")
		}
	}
	maxAge, err := sessionMaxAge(config.SessionStore)
	if err != nil {
		return nil, err
	}

	store := sessions.NewCookieStore(storeSecret)
	store.Options = &sessions.Options{
		Path: "/",
		// how long a session stays valid, 30 days unless configured
		// (ClearSession relies on mutating MaxAge to -1 to delete the cookie)
		MaxAge: maxAge,
		// prevent JavaScript from reading the session cookie (XSS hardening)
		HttpOnly: true,
		// only opt-in: the web UI is also served over plain HTTP on `port`,
		// where a Secure cookie would silently break login
		Secure: config.SessionStore != nil && config.SessionStore.Secure,
		// Lax still sends the cookie on top-level GET navigations, so the
		// OIDC redirect callback keeps working while cross-site subrequests
		// no longer carry the session cookie (CSRF hardening)
		SameSite: http.SameSiteLaxMode,
	}
	runtime := authruntime.NewProviderRuntime(store)
	providers := config.Providers()
	runtime.SetProviderCount(len(providers))

	for _, p := range providers {
		if p.RegisterRoutes != nil {
			err := p.RegisterRoutes(router, runtime)
			if err != nil {
				return nil, err
			}
		}
	}

	router.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("signout") != "1" && !config.DesiresSignInPage() && len(providers) == 1 {
			// we only have one provider, so jump directly to that
			providers[0].Invoke(w, r, runtime)
			return
		}
		w.WriteHeader(http.StatusOK)
		banner, _ := runtime.GetBanner(w, r)
		err := authtemplates.RenderLoginPage(w, authtemplates.LoginPage{
			Title:     "Sign in",
			Providers: providers,
			Banner:    banner,
		})
		if err != nil {
			logrus.Error(errors.Wrap(err, "failed to render the login page"))
		}
	})

	router.HandleFunc("/signin/{index}", func(w http.ResponseWriter, r *http.Request) {
		index, err := strconv.Atoi(mux.Vars(r)["index"])
		if err != nil || index < 0 || len(providers) <= index {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Unknown provider")
			return
		}
		provider := providers[index]
		provider.Invoke(w, r, runtime)
	})

	router.HandleFunc("/signout", func(w http.ResponseWriter, r *http.Request) {
		_ = runtime.ClearSession(w, r)
		runtime.Restart(w, r)
	})

	return &AuthMiddleware{
		config,
		claimsMiddleware,
		router,
		runtime,
	}, nil
}

// DefaultSessionMaxAge is how long a session stays valid unless the operator
// configures something else. It is also how long it takes for access revoked
// at the identity provider to take effect, because the claims of a session
// are not re-checked after the login.
const DefaultSessionMaxAge = 30 * 24 * time.Hour

// sessionMaxAge reads the configured session lifetime in seconds.
func sessionMaxAge(config *authconfig.SessionStoreConfig) (int, error) {
	if config == nil || config.MaxAge == "" {
		return int(DefaultSessionMaxAge.Seconds()), nil
	}

	maxAge, err := time.ParseDuration(config.MaxAge)
	if err != nil {
		return 0, errors.Wrapf(err, "auth.sessionStore.maxAge is not a duration such as \"24h\": %q", config.MaxAge)
	}
	if maxAge <= 0 {
		return 0, errors.Errorf("auth.sessionStore.maxAge must be positive, got %q", config.MaxAge)
	}

	logrus.Infof("Web sessions expire after %s", maxAge)
	return int(maxAge.Seconds()), nil
}

func NewMiddleware(config authconfig.AuthConfig, claimsMiddleware authsession.ClaimsMiddleware) (mux.MiddlewareFunc, error) {
	authMiddleware, err := New(config, claimsMiddleware)
	if err != nil {
		return nil, err
	}
	return authMiddleware.Middleware, nil
}

func ClaimsMiddleware(conf *config.AppConfig) authsession.ClaimsMiddleware {
	return func(user *authsession.Identity) error {
		if user == nil {
			return &LoginError{
				msg:  "User is not logged in",
				code: NotAuthenticated,
			}
		}
		// restrict privilege elevation by username to basic and simple auth users only
		if (user.Provider == authconfig.BasicAuthProvider || user.Provider == authconfig.SimpleAuthProvider) && user.Subject == conf.AdminUsername {
			user.Claims.MakeAdmin()
		}
		// allow access to users only when access claim is present for OIDC
		if oidc := findOIDCProvider(&conf.Auth, user.Provider); oidc != nil && oidc.AccessClaim != "" {
			if !user.Claims.Has(oidc.AccessClaim, "true") {
				return &LoginError{
					msg:  "User has no access",
					code: NotAuthorized,
				}
			}
		}

		return nil
	}
}

// findOIDCProvider returns the OIDC provider config with the given name,
// looking at both the legacy top-level OIDC provider and the ones
// configured under auth.multiple.
func findOIDCProvider(auth *authconfig.AuthConfig, name string) *authconfig.OIDCConfig {
	if auth.OIDC != nil && auth.OIDC.Name == name {
		return auth.OIDC
	}
	for providerName, providerConfig := range auth.Multiple {
		if providerConfig.OIDC == nil {
			continue
		}
		// the name defaults to the map key if not set explicitly (see AuthConfig.Providers)
		if providerConfig.OIDC.Name == name || (providerConfig.OIDC.Name == "" && providerName == name) {
			return providerConfig.OIDC
		}
	}
	return nil
}

func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if the request is for an auth
		// related page i.e. /signin
		// to be handled by our own router
		if ok := m.router.Match(r, &mux.RouteMatch{}); ok {
			m.router.ServeHTTP(w, r)
			return
		}

		// otherwise we apply the standard middleware
		// functionality i.e. annotate the request context
		// with the request user (identity)
		if s, err := m.runtime.GetSession(r); err == nil {
			if s.Identity == nil {
				// Can happen due to an aborted or failed login at the OIDC provider
				// Redirect the user to the signin page, so they can redo the login
				http.Redirect(w, r, "/signin", http.StatusSeeOther)
				return
			}
			if m.claimsMiddleware != nil {
				if err := m.claimsMiddleware(s.Identity); err != nil {
					traces.Logger(r.Context()).Error(errors.Wrap(err, "authnz middleware failure"))
					if lerr, ok := err.(*LoginError); ok {
						switch lerr.code {
						case NotAuthorized:
							// The user is signed in, their account just may
							// not use this server. Sending them back to the
							// sign-in page would look like the login failed,
							// so tell them what happened instead.
							notAuthorized(w)
						default:
							// A redirect needs a 3xx status: with anything
							// else the browser ignores the Location header
							// and shows an empty page.
							http.Redirect(w, r, "/signin", http.StatusSeeOther)
						}
						return
					}
					http.Redirect(w, r, "/signin", http.StatusSeeOther)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(authsession.SetIdentityCtx(r.Context(), s)))
		} else {
			// GetSession() errors e.g. after the server restarted, because old session cookies are no longer trusted
			// The RequireAuthentication() middleware will be next in line and prompt the user to log in
			next.ServeHTTP(w, r)
		}
	})
}

// notAuthorized tells a signed in user that their account has no access. It
// deliberately does not redirect: the session is valid, so the sign-in page
// has nothing to offer them except signing in as somebody else.
func notAuthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, "Your account is not allowed to access this server.\n\n"+
		"To sign in with a different account, go to /signout\n")
}

func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authsession.Authenticated(r.Context()) {
			next.ServeHTTP(w, r)
		} else {
			http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
		}
	})
}
