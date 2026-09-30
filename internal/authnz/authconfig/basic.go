package authconfig

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authutil"
)

const BasicAuthProvider = "basic"

type BasicAuthConfig struct {
	// Users is a list of htpasswd encoded username:password pairs
	// supports BCrypt, Sha, Ssha, Md5
	// example: "htpasswd -nB <username>"
	// copy the result into your user's array
	Users []string `yaml:"users"`
}

func (c *BasicAuthConfig) Provider() *authruntime.Provider {
	// One throttle per provider, created once: Providers() is called when the
	// auth middleware is built and the result is kept for the process.
	throttle := newLoginThrottle()
	return &authruntime.Provider{
		Type: BasicAuthProvider,
		Name: BasicAuthProvider,
		Invoke: func(w http.ResponseWriter, r *http.Request, runtime *authruntime.ProviderRuntime) {
			basicAuthLogin(c, runtime, throttle)(w, r)
		},
	}
}

func basicAuthLogin(c *BasicAuthConfig, runtime *authruntime.ProviderRuntime, throttle *loginThrottle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// accept standard basic auth challenges
		u, p, isBasic := r.BasicAuth()

		if !isBasic {
			// we'll handle form submissions and direct
			// browser challenges
			u = r.FormValue("username")
			p = r.FormValue("password")
		}

		// A request without any credentials is the browser asking for the
		// challenge, not a failed attempt.
		attempted := u != ""
		if attempted {
			throttle.wait(u)
		}
		// Every way out of a right password returns, so reaching past this
		// block means the credentials were not right.
		if ok := checkCreds(c.Users, u, p, runtime); ok {
			throttle.recordSuccess(u)
			err := runtime.SetSession(w, r, &authsession.AuthSession{
				Identity: &authsession.Identity{
					Provider: BasicAuthProvider,
					Subject:  u,
					Name:     u,
					Email:    "", // basic auth has no email
				},
			})
			if err == nil {
				runtime.Done(w, r)
				return
			}
			// As in simple auth: the password was right, so this is not a
			// credentials problem and saying so would send people looking
			// for the wrong thing.
			logrus.Error(fmt.Errorf("failed to start the session after the password: %w", err))
			http.Error(w, "Could not sign in", http.StatusInternalServerError)
			return
		}

		if attempted {
			throttle.recordFailure(u)
			logrus.Warnf("Failed login attempt for user '%s' (basic auth, remote address: %s)", u, r.RemoteAddr)
		}

		if !isBasic {
			runtime.ShowBanner(w, r, authsession.Banner{
				Text:   "Invalid username or password",
				Intent: "danger",
			})
		} else {
			// challenge browser
			w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintln(w, "Unauthorized")
		}
	}
}

// dummyHash is what an unknown user is checked against, so that a wrong
// username costs the same bcrypt round as a wrong password does. Without it
// the response time tells an attacker which accounts exist. It is generated
// from a random password, so nothing can ever match it - and the result is
// discarded anyway.
var dummyHash = func() string {
	hash, err := bcrypt.GenerateFromPassword([]byte(authutil.RandomString(32)), bcrypt.DefaultCost)
	if err != nil {
		logrus.Error(fmt.Errorf("failed to prepare the login timing hash: %w", err))
		return ""
	}
	return string(hash)
}()

// checkCreds says whether the password is right for a user the configuration
// lists. The configuration decides who may sign in at all; a password the user
// set for themselves decides what their password is - unless an admin has
// changed the configured entry since, in which case theirs wins and the stored
// one is ignored. Without that an admin could hand out a password and never
// take it back.
func checkCreds(users []string, username string, password string, stored *ProviderRuntime) bool {
	for _, user := range users {
		if u, configured, ok := parsehtpassword(user); ok {
			if u != username {
				continue
			}
			if hash, from := passwordOf(stored, username); hash != "" && from == configured {
				return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
			}
			return checkhtpasswd(configured, password)
		}
	}

	// no such user: spend the same time a real password check would
	checkhtpasswd(dummyHash, password)
	return false
}

// ProviderRuntime is named here rather than imported into every caller.
type ProviderRuntime = authruntime.ProviderRuntime

func passwordOf(runtime *ProviderRuntime, subject string) (string, string) {
	if runtime == nil {
		return "", ""
	}
	return runtime.Password(subject)
}

// PasswordMatches says whether a password matches a configured entry, in
// whichever htpasswd format it is written. It is how the sign-in checks a
// password, and the one place that decides it.
func PasswordMatches(entry string, password string) bool {
	return checkhtpasswd(entry, password)
}

// parsehtpassword splits an "username:hash" entry. An entry without a colon
// is not a credential at all, so it is rejected rather than indexed into.
func parsehtpassword(user string) (string, string, bool) {
	username, hash, ok := strings.Cut(user, ":")
	if !ok || username == "" || hash == "" {
		logrus.Warnf("ignoring malformed user entry %q: expected the htpasswd format 'username:hash'", user)
		return "", "", false
	}
	return username, hash, true
}

func checkhtpasswd(required string, given string) bool {
	if encoded, err := htpasswd.AcceptBcrypt(required); encoded != nil && err == nil {
		return encoded.MatchesPassword(given)
	}
	if encoded, err := htpasswd.AcceptSha(required); encoded != nil && err == nil {
		return encoded.MatchesPassword(given)
	}
	if encoded, err := htpasswd.AcceptSsha(required); encoded != nil && err == nil {
		return encoded.MatchesPassword(given)
	}
	if encoded, err := htpasswd.AcceptMd5(required); encoded != nil && err == nil {
		return encoded.MatchesPassword(given)
	}
	return false
}
