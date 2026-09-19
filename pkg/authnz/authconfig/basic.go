package authconfig

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"

	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
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
		credentialsOK := false

		if ok := checkCreds(c.Users, u, p); ok {
			credentialsOK = true
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
		}

		if attempted && !credentialsOK {
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

func checkCreds(users []string, username string, password string) bool {
	for _, user := range users {
		if u, p, ok := parsehtpassword(user); ok {
			if u == username {
				return checkhtpasswd(p, password)
			}
		}
	}
	return false
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
