package authconfig

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authruntime"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authtemplates"
)

const SimpleAuthProvider = "simple"

// SimpleAuthConfig is an alternative to BasicAuthConfig where the login happens through a login page and a POST request.
type SimpleAuthConfig struct {
	// Users is a list of htpasswd encoded username:password pairs
	// supports BCrypt, Sha, Ssha, Md5
	// example: "htpasswd -nB <username>"
	// copy the result into your user's array
	Users []string `yaml:"users"`
}

const postURL = "/signin/simpleauth"

func (c *SimpleAuthConfig) Provider() *authruntime.Provider {
	// One throttle per provider, created once: Providers() is called when the
	// auth middleware is built and the result is kept for the process.
	throttle := newLoginThrottle()
	return &authruntime.Provider{
		Type: SimpleAuthProvider,
		Name: SimpleAuthProvider,
		// The flow is as follows: /signin page -> navigation to /signin/{index}
		// -> Invoke / simpleAuthLogin() renders login form -> POST to postURL / simpleAuthPostEndpoint()
		// -> redirect to /
		Invoke: func(w http.ResponseWriter, r *http.Request, runtime *authruntime.ProviderRuntime) {
			simpleAuthLogin(runtime)(w, r)
		},
		RegisterRoutes: func(router *mux.Router, runtime *authruntime.ProviderRuntime) error {
			router.HandleFunc(postURL, simpleAuthPostEndpoint(c, runtime, throttle))
			return nil
		},
	}
}

func simpleAuthLogin(runtime *authruntime.ProviderRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A login page with a username and a password field
		w.WriteHeader(http.StatusOK)
		err := authtemplates.RenderSimpleAuthPage(w, authtemplates.SimpleAuthPage{
			PostURL:        postURL,
			OtherProviders: runtime.HasOtherProviders(),
		})
		if err != nil {
			logrus.Error(fmt.Errorf("failed to render simple auth login page: %w", err))
			return
		}
	}
}

func simpleAuthPostEndpoint(c *SimpleAuthConfig, runtime *authruntime.ProviderRuntime, throttle *loginThrottle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Could not parse form", http.StatusBadRequest)
			return
		}
		// The second step: a password that was already right, waiting for
		// the code. The browser carries which account that was, signed by
		// the session store - it is not a login, nothing reads an identity
		// out of it.
		if code := r.PostForm.Get("code"); code != "" {
			finishWithCode(w, r, runtime, throttle, code)
			return
		}

		u := r.PostForm.Get("username")
		p := r.PostForm.Get("password")

		// An empty form is not an attempt at a password.
		attempted := u != "" && p != ""
		if attempted {
			throttle.wait(u)
		}
		credentialsOK := false

		if attempted && checkCreds(c.Users, u, p, runtime) {
			credentialsOK = true
			throttle.recordSuccess(u)

			// A right password is the whole login only for somebody without
			// a second factor. For everybody else it is half of one.
			if runtime.TwoFactorRequired(u) {
				askForCode(w, r, runtime, u)
				return
			}

			err = runtime.SetSession(w, r, sessionFor(u))
			if err == nil {
				runtime.Done(w, r)
				return
			}
		}

		if attempted && !credentialsOK {
			throttle.recordFailure(u)
			logrus.Warnf("Failed login attempt for user '%s' (simple auth, remote address: %s)", u, r.RemoteAddr)
		}

		w.WriteHeader(http.StatusForbidden)
		err = authtemplates.RenderSimpleAuthPage(w, authtemplates.SimpleAuthPage{
			PostURL:        postURL,
			ErrorMessage:   "Invalid username or password",
			OtherProviders: runtime.HasOtherProviders(),
		})
		if err != nil {
			logrus.Error(fmt.Errorf("failed to render simple auth login page: %w", err))
			return
		}
	}
}

// pendingFor is how long the code page is good for. Long enough to find the
// phone, short enough that a browser left open on it is not a way in later.
const pendingFor = 5 * time.Minute

func sessionFor(username string) *authsession.AuthSession {
	return &authsession.AuthSession{
		Identity: &authsession.Identity{
			Provider: SimpleAuthProvider,
			Subject:  username,
			Name:     username,
			Email:    "", // simple auth has no email
		},
	}
}

// askForCode remembers whose password was right and asks for their code.
func askForCode(w http.ResponseWriter, r *http.Request, runtime *ProviderRuntime, username string) {
	err := runtime.SetSession(w, r, &authsession.AuthSession{
		Pending: &authsession.PendingLogin{
			Subject:  username,
			Provider: SimpleAuthProvider,
			Until:    time.Now().Add(pendingFor),
		},
	})
	if err != nil {
		logrus.Error(fmt.Errorf("failed to remember the pending login: %w", err))
		http.Error(w, "Could not start the sign-in", http.StatusInternalServerError)
		return
	}

	renderCodePage(w, runtime, "")
}

// finishWithCode is the second step: the code, for the account whose password
// was right a moment ago.
func finishWithCode(w http.ResponseWriter, r *http.Request, runtime *ProviderRuntime, throttle *loginThrottle, code string) {
	session, err := runtime.GetSession(r)
	if err != nil || session == nil || !session.Pending.Valid(time.Now()) ||
		session.Pending.Provider != SimpleAuthProvider {
		// No password step, or one that has expired: back to the start
		// rather than a code field that can never work.
		runtime.Restart(w, r)
		return
	}

	username := session.Pending.Subject
	throttle.wait(username)

	if !runtime.CheckTwoFactor(username, code) {
		throttle.recordFailure(username)
		logrus.Warnf("Failed two-factor attempt for user '%s' (simple auth, remote address: %s)", username, r.RemoteAddr)
		w.WriteHeader(http.StatusForbidden)
		renderCodePage(w, runtime, "That code is not right")
		return
	}

	throttle.recordSuccess(username)
	if err := runtime.SetSession(w, r, sessionFor(username)); err != nil {
		logrus.Error(fmt.Errorf("failed to start the session after the second factor: %w", err))
		http.Error(w, "Could not sign in", http.StatusInternalServerError)
		return
	}
	runtime.Done(w, r)
}

func renderCodePage(w http.ResponseWriter, runtime *ProviderRuntime, errorMessage string) {
	err := authtemplates.RenderSimpleAuthPage(w, authtemplates.SimpleAuthPage{
		PostURL:        postURL,
		AskForCode:     true,
		ErrorMessage:   errorMessage,
		OtherProviders: runtime.HasOtherProviders(),
	})
	if err != nil {
		logrus.Error(fmt.Errorf("failed to render the two-factor page: %w", err))
	}
}
