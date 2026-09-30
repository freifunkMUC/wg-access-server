package authruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/traces"

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

// Passwords is where a password somebody set for themselves is looked up.
// Only the built-in providers have one; for everybody else the password
// belongs to their identity provider.
type Passwords interface {
	// UserPassword returns the stored bcrypt hash and the configured entry
	// that was in effect when it was set. Both empty means the user has set
	// no password of their own - which is the normal case.
	UserPassword(subject string) (hash string, from string)
}

// TwoFactor is the second factor of the built-in sign-in. Nil when nothing
// keeps one, which is a server where a right password is the whole login.
type TwoFactor interface {
	// Enabled says whether this person is asked for a second factor at all.
	Enabled(subject string) bool
	// CodesEnabled says whether an authenticator app is one of them, so that
	// a code field is only shown to somebody who can fill it in.
	CodesEnabled(subject string) bool
	// Check says whether a code is theirs - from their app, or one of their
	// recovery codes, which it uses up.
	Check(subject string, code string) bool
}

// Passkeys is the other second factor: a credential the browser holds, bound
// to this site. Nil when nothing keeps one.
type Passkeys interface {
	// Has says whether this person can sign in with a passkey.
	Has(subject string) bool
	// BeginLogin returns the options the browser needs, as JSON.
	BeginLogin(r *http.Request, subject string) (json.RawMessage, error)
	// FinishLogin says whether the browser's answer proves a passkey of
	// this person.
	FinishLogin(r *http.Request, subject string, answer []byte) error
}

type ProviderRuntime struct {
	store sessions.Store
	// browserSessions keeps who signed in; the cookie carries only an id.
	browserSessions authsession.Sessions
	// otherProviders is whether a user can sign in some other way, too.
	otherProviders bool
	// recordLogin is told who signed in, once a provider has established it.
	recordLogin func(*authsession.Identity)
	// passwords is where a user's own password is looked up, nil when
	// nothing stores one.
	passwords Passwords
	// twoFactor is the second factor, nil when nothing keeps one.
	twoFactor TwoFactor
	// passkeys are the other second factor, nil for the same reason.
	passkeys Passkeys
}

func NewProviderRuntime(store sessions.Store, browserSessions authsession.Sessions) *ProviderRuntime {
	return &ProviderRuntime{store: store, browserSessions: browserSessions}
}

// UsePasswords registers where a password somebody set for themselves is
// looked up.
func (p *ProviderRuntime) UsePasswords(passwords Passwords) {
	p.passwords = passwords
}

// Password returns the stored password of a user and the configured entry it
// was set against. Without a store, nobody has one.
func (p *ProviderRuntime) Password(subject string) (hash string, from string) {
	if p.passwords == nil {
		return "", ""
	}
	return p.passwords.UserPassword(subject)
}

// UseTwoFactor registers where the second factor is kept.
func (p *ProviderRuntime) UseTwoFactor(twoFactor TwoFactor) {
	p.twoFactor = twoFactor
}

// TwoFactorRequired says whether this person has to give a code as well.
func (p *ProviderRuntime) TwoFactorRequired(subject string) bool {
	return p.twoFactor != nil && p.twoFactor.Enabled(subject)
}

// TwoFactorCodes says whether this person has an authenticator app set up.
func (p *ProviderRuntime) TwoFactorCodes(subject string) bool {
	return p.twoFactor != nil && p.twoFactor.CodesEnabled(subject)
}

// CheckTwoFactor says whether the code is theirs.
func (p *ProviderRuntime) CheckTwoFactor(subject string, code string) bool {
	return p.twoFactor != nil && p.twoFactor.Check(subject, code)
}

// UsePasskeys registers where the passkeys are kept.
func (p *ProviderRuntime) UsePasskeys(passkeys Passkeys) {
	p.passkeys = passkeys
}

// HasPasskey says whether this person can sign in with one.
func (p *ProviderRuntime) HasPasskey(subject string) bool {
	return p.passkeys != nil && p.passkeys.Has(subject)
}

// BeginPasskeyLogin returns what the browser needs to answer with a passkey.
func (p *ProviderRuntime) BeginPasskeyLogin(r *http.Request, subject string) (json.RawMessage, error) {
	if p.passkeys == nil {
		return nil, errors.New("this server keeps no passkeys")
	}
	return p.passkeys.BeginLogin(r, subject)
}

// FinishPasskeyLogin says whether the answer proves a passkey of this person.
func (p *ProviderRuntime) FinishPasskeyLogin(r *http.Request, subject string, answer []byte) error {
	if p.passkeys == nil {
		return errors.New("this server keeps no passkeys")
	}
	return p.passkeys.FinishLogin(r, subject, answer)
}

// OnLogin registers what to do when somebody signed in. Every provider ends
// up here, so it is the one place that sees all of them.
func (p *ProviderRuntime) OnLogin(record func(*authsession.Identity)) {
	p.recordLogin = record
}

// SetProviderCount tells the providers how many there are, so a provider's
// own login page knows whether to offer a way back to the others.
func (p *ProviderRuntime) SetProviderCount(count int) {
	p.otherProviders = count > 1
}

// HasOtherProviders reports whether a user can sign in some other way, too.
func (p *ProviderRuntime) HasOtherProviders() bool {
	return p.otherProviders
}

func (p *ProviderRuntime) SetSession(w http.ResponseWriter, r *http.Request, s *authsession.AuthSession) error {
	if err := authsession.SetSession(p.store, p.browserSessions, r, w, s); err != nil {
		return err
	}

	// A session without an identity is a provider keeping state in the middle
	// of its flow - the OIDC nonce, for instance. Nobody signed in yet.
	if s.Identity != nil && p.recordLogin != nil {
		p.recordLogin(s.Identity)
	}
	return nil
}

func (p *ProviderRuntime) GetSession(r *http.Request) (*authsession.AuthSession, error) {
	return authsession.GetSession(p.store, p.browserSessions, r)
}

func (p *ProviderRuntime) ClearSession(w http.ResponseWriter, r *http.Request) error {
	return authsession.ClearSession(p.store, p.browserSessions, r, w)
}

// Restart sends the browser back to the sign-in page. 303, so that it gets
// there with a GET whatever method brought it here.
func (p *ProviderRuntime) Restart(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/signin?signout=1", http.StatusSeeOther)
}

// Done sends a signed in browser on to the web UI. 303, not 307: after the
// POST of a sign-in form, 307 would make the browser POST the form to "/"
// once more.
func (p *ProviderRuntime) Done(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *ProviderRuntime) ShowBanner(w http.ResponseWriter, r *http.Request, banner authsession.Banner) {
	data, err := json.Marshal(banner)
	if err != nil {
		traces.Logger(r.Context()).Error(fmt.Errorf("failed to serialize banner message: %w", err))
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
