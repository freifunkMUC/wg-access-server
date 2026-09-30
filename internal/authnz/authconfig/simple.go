package authconfig

import (
	"fmt"
	"io"
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

const (
	postURL = "/signin/simpleauth"
	// passkeyURL is where the browser asks what to sign, for the account
	// whose password was right a moment ago.
	passkeyURL = "/signin/simpleauth/passkey"
	// passkeyScriptURL serves the script that does the asking.
	passkeyScriptURL = "/signin/simpleauth/passkey.js"
)

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
			router.HandleFunc(passkeyURL, passkeyOptionsEndpoint(runtime))
			router.HandleFunc(passkeyScriptURL, passkeyScriptEndpoint())
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
		// the code or the passkey. The browser carries which account that
		// was, signed by the session store - it is not a login, nothing
		// reads an identity out of it.
		if answer := r.PostForm.Get("passkey"); answer != "" {
			finishWithPasskey(w, r, runtime, throttle, []byte(answer))
			return
		}
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

	renderCodePage(w, runtime, username, "")
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
		renderCodePage(w, runtime, username, "That code is not right")
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

func renderCodePage(w http.ResponseWriter, runtime *ProviderRuntime, username string, errorMessage string) {
	err := authtemplates.RenderSimpleAuthPage(w, authtemplates.SimpleAuthPage{
		PostURL:          postURL,
		AskForCode:       true,
		OfferPasskey:     runtime.HasPasskey(username),
		PasskeyURL:       passkeyURL,
		PasskeyScriptURL: passkeyScriptURL,
		HasCodes:         runtime.TwoFactorCodes(username),
		ErrorMessage:     errorMessage,
		OtherProviders:   runtime.HasOtherProviders(),
	})
	if err != nil {
		logrus.Error(fmt.Errorf("failed to render the two-factor page: %w", err))
	}
}

// passkeyScriptEndpoint serves the sign-in page's passkey script. It says
// nothing about anybody, so it needs no session.
func passkeyScriptEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		if _, err := io.WriteString(w, authtemplates.PasskeyScript); err != nil {
			logrus.Warn(fmt.Errorf("failed to write the passkey script: %w", err))
		}
	}
}

// passkeyOptionsEndpoint hands the browser what to sign. It says nothing to
// anybody without a password step behind them.
func passkeyOptionsEndpoint(runtime *authruntime.ProviderRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := runtime.GetSession(r)
		if err != nil || session == nil || !session.Pending.Valid(time.Now()) ||
			session.Pending.Provider != SimpleAuthProvider {
			http.Error(w, "No sign-in is in progress", http.StatusForbidden)
			return
		}

		options, err := runtime.BeginPasskeyLogin(r, session.Pending.Subject)
		if err != nil {
			logrus.Warn(fmt.Errorf("failed to start the passkey sign-in: %w", err))
			http.Error(w, "The passkey sign-in could not be started", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write(options); err != nil {
			logrus.Warn(fmt.Errorf("failed to write the passkey options: %w", err))
		}
	}
}

// finishWithPasskey is the second step answered with a passkey.
func finishWithPasskey(w http.ResponseWriter, r *http.Request, runtime *ProviderRuntime, throttle *loginThrottle, answer []byte) {
	session, err := runtime.GetSession(r)
	if err != nil || session == nil || !session.Pending.Valid(time.Now()) ||
		session.Pending.Provider != SimpleAuthProvider {
		runtime.Restart(w, r)
		return
	}

	username := session.Pending.Subject
	throttle.wait(username)

	if err := runtime.FinishPasskeyLogin(r, username, answer); err != nil {
		throttle.recordFailure(username)
		logrus.Warnf("Failed passkey attempt for user '%s' (simple auth, remote address: %s): %v",
			username, r.RemoteAddr, err)
		w.WriteHeader(http.StatusForbidden)
		renderCodePage(w, runtime, username, "That passkey was not accepted")
		return
	}

	throttle.recordSuccess(username)
	if err := runtime.SetSession(w, r, sessionFor(username)); err != nil {
		logrus.Error(fmt.Errorf("failed to start the session after the passkey: %w", err))
		http.Error(w, "Could not sign in", http.StatusInternalServerError)
		return
	}
	runtime.Done(w, r)
}
