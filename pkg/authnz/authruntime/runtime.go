package authruntime

import (
	"encoding/json"
	"net/http"

	"github.com/freifunkMUC/wg-access-server/internal/traces"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
	"github.com/pkg/errors"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type Provider struct {
	Type           string
	Name           string
	Invoke         func(http.ResponseWriter, *http.Request, *ProviderRuntime)
	RegisterRoutes func(*mux.Router, *ProviderRuntime) error
	Branding       ProviderBranding
}

type ProviderBranding struct {
	Background string `yaml:"background"`
	Color      string `yaml:"color"`
	Icon       string `yaml:"icon"`
}

type ProviderRuntime struct {
	store sessions.Store
	// checkLogin may refuse a sign-in the provider accepted, before it
	// becomes a session.
	checkLogin func(*authsession.Identity) error
}

func NewProviderRuntime(store sessions.Store) *ProviderRuntime {
	return &ProviderRuntime{store: store}
}

// OnLoginCheck registers what decides whether a sign-in a provider accepted
// may become a session. Every provider ends up in SetSession, so it is the
// one place that sees all of them. An error that is a *RefusedError is the
// sign-in being refused; anything else is the check failing, and refuses it
// as well.
func (p *ProviderRuntime) OnLoginCheck(check func(*authsession.Identity) error) {
	p.checkLogin = check
}

// RefusedError is a sign-in the provider accepted and the server does not.
// Reason is for the person signing in, Detail for the log: what the person is
// told must not hand out more than they already know.
type RefusedError struct {
	Reason string
	Detail string
}

func (e *RefusedError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Reason
}

func (p *ProviderRuntime) SetSession(w http.ResponseWriter, r *http.Request, s *authsession.AuthSession) error {
	// A session without an identity is a provider keeping state in the middle
	// of its flow - the OIDC nonce, for instance. Nobody signed in yet.
	if s.Identity != nil && p.checkLogin != nil {
		if err := p.checkLogin(s.Identity); err != nil {
			return err
		}
	}
	return authsession.SetSession(p.store, r, w, s)
}

func (p *ProviderRuntime) GetSession(r *http.Request) (*authsession.AuthSession, error) {
	return authsession.GetSession(p.store, r)
}

func (p *ProviderRuntime) ClearSession(w http.ResponseWriter, r *http.Request) error {
	return authsession.ClearSession(p.store, r, w)
}

func (p *ProviderRuntime) Restart(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/signin?signout=1", http.StatusTemporaryRedirect)
}

func (p *ProviderRuntime) Done(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (p *ProviderRuntime) ShowBanner(w http.ResponseWriter, r *http.Request, banner authsession.Banner) {
	data, err := json.Marshal(banner)
	if err != nil {
		traces.Logger(r.Context()).Error(errors.Wrap(err, "failed to serialize banner message"))
		return
	}
	authsession.AddFlash(p.store, r, w, "banner", string(data))
	http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
}

func (p *ProviderRuntime) GetBanner(w http.ResponseWriter, r *http.Request) (*authsession.Banner, bool) {
	if v, found := authsession.GetFlash(p.store, r, w, "banner"); found {
		banner := &authsession.Banner{}
		if err := json.Unmarshal([]byte(v), banner); err == nil {
			return banner, true
		}
	}
	return nil, false
}
