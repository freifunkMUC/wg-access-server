package authsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

type AuthSession struct {
	// State holds the OAuth2 state value used for CSRF protection
	State *string
	// Nonce holds the OpenID Connect nonce used to bind an ID token to the login session
	Nonce *string
	// ID names the session the identity belongs to. It is what the cookie
	// carries once somebody has signed in; the identity itself is kept by the
	// server, so that a session can be ended.
	ID string
	// Identity is who signed in. It is read from the session store on every
	// request and is never written to the cookie.
	Identity *Identity `json:"-"`
	// APIToken is the id of the API token a request authenticated with,
	// empty for a browser session. It is never part of the session cookie.
	APIToken string `json:"-"`
}

// Sessions is where the identity of a browser session is kept while the
// cookie carries no more than its id.
type Sessions interface {
	// Create starts a session for the identity and returns the id for the
	// cookie.
	Create(identity *Identity, r *http.Request) (string, error)
	// Identity returns who a session belongs to, or an error when it does not
	// exist, expired or was ended.
	Identity(id string) (*Identity, error)
	// End stops a session by the id from the cookie.
	End(id string) error
}

type Banner struct {
	Text   string
	Intent string
}

type authSessionKey string

var sessionKey authSessionKey = "auth-session"

func GetSession(store sessions.Store, browserSessions Sessions, r *http.Request) (*AuthSession, error) {
	session, _ := store.Get(r, string(sessionKey))
	data, ok := session.Values[string(sessionKey)].([]byte)
	if !ok {
		return nil, errors.New("session not authenticated")
	}

	s := &AuthSession{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("failed to parse session: %w", err)
	}

	// A cookie without an id is a login in progress - it carries the state
	// and the nonce of the flow, and nobody has signed in yet.
	if s.ID != "" {
		identity, err := browserSessions.Identity(s.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to read the session: %w", err)
		}
		s.Identity = identity
	}
	return s, nil
}

func SetSession(store sessions.Store, browserSessions Sessions, r *http.Request, w http.ResponseWriter, s *AuthSession) error {
	// Somebody signed in: the identity goes to the server, the cookie gets
	// the id of the session it now belongs to.
	if s.Identity != nil && s.ID == "" {
		id, err := browserSessions.Create(s.Identity, r)
		if err != nil {
			return fmt.Errorf("failed to start the session: %w", err)
		}
		s.ID = id
	}

	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	session, _ := store.Get(r, string(sessionKey))
	session.Values[string(sessionKey)] = data
	if err := session.Save(r, w); err != nil {
		return err
	}

	if s.Identity != nil {
		logrus.Infof("Creating web session with provider '%s' for user '%s' (remote address: %s)", s.Identity.Provider, s.Identity.Name, r.RemoteAddr)
	}

	return nil
}

func AddFlash(store sessions.Store, r *http.Request, w http.ResponseWriter, key string, value string) {
	session, err := store.Get(r, string(sessionKey))
	if err != nil {
		logrus.Warn(fmt.Errorf("failed to get session for flash message: %w", err))
		return
	}
	session.AddFlash(value, key)
	if err := session.Save(r, w); err != nil {
		logrus.Warn(fmt.Errorf("failed to save flash message: %w", err))
	}
}

func GetFlash(store sessions.Store, r *http.Request, w http.ResponseWriter, key string) (string, bool) {
	session, err := store.Get(r, string(sessionKey))
	if err != nil {
		return "", false
	}
	results := session.Flashes(key)
	if len(results) >= 1 {
		if v, ok := results[0].(string); ok {
			if err := session.Save(r, w); err != nil {
				logrus.Warn(fmt.Errorf("failed to save session after getting flash: %w", err))
			}
			return v, true
		}
	}
	return "", false
}

func ClearSession(store sessions.Store, browserSessions Sessions, r *http.Request, w http.ResponseWriter) error {
	// End the session before the cookie goes: a cookie that is gone can no
	// longer say which session to end.
	if current, err := GetSession(store, browserSessions, r); err == nil && current.ID != "" {
		if err := browserSessions.End(current.ID); err != nil {
			logrus.Error(fmt.Errorf("failed to end the session: %w", err))
		}
	}

	session, _ := store.Get(r, string(sessionKey))
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		logrus.Error(err)
		return err
	}
	return nil
}

func SetIdentityCtx(parent context.Context, session *AuthSession) context.Context {
	return context.WithValue(parent, sessionKey, session)
}

// CurrentSessionID returns the id of the browser session a request came with.
// It is empty for a request that carried an API token, and it is the secret
// from the cookie - never hand it out.
func CurrentSessionID(ctx context.Context) string {
	if session, ok := ctx.Value(sessionKey).(*AuthSession); ok {
		return session.ID
	}
	return ""
}

func CurrentUser(ctx context.Context) (*Identity, error) {
	if session, ok := ctx.Value(sessionKey).(*AuthSession); ok {
		if session.Identity != nil {
			return session.Identity, nil
		}
	}
	return nil, errors.New("Unauthenticated")
}

// APIToken returns the id of the API token the request authenticated with, or
// "" for a browser session.
func APIToken(ctx context.Context) string {
	if session, ok := ctx.Value(sessionKey).(*AuthSession); ok {
		return session.APIToken
	}
	return ""
}

func Authenticated(ctx context.Context) bool {
	_, err := CurrentUser(ctx)
	return err == nil
}
