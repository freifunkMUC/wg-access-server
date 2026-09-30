package users

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

var (
	// ErrNoPasskey is a credential nobody registered, or one of somebody
	// else. The two are not told apart.
	ErrNoPasskey = errors.New("no such passkey")
	// ErrNoChallenge is the second half of a registration or a sign-in
	// arriving without the first, or long after it.
	ErrNoChallenge = errors.New("this passkey exchange has expired: start again")
	// ErrPasskeyExists is registering a credential id that is already
	// registered - to this person or to anybody else.
	ErrPasskeyExists = errors.New("this passkey is already registered")
)

// challengeFor is how long the browser has to answer. A person reaching for a
// security key in a drawer needs longer than a phone in a pocket.
const challengeFor = 5 * time.Minute

// maxPasskeyName is what fits in the column, and in a line of the list.
const maxPasskeyName = 64

// Passkeys are WebAuthn credentials used as a second factor: after the
// password, the browser proves it holds a key that this server registered.
//
// Unlike a code from an app, a passkey is bound to the site it was made for -
// a page pretending to be this one cannot ask for it, and a person cannot read
// it out to somebody on the phone. That is the reason for having it.
type Passkeys struct {
	storage storage.Storage
	// relyingParty says which site this is, as far as a browser is
	// concerned. It is what binds a credential to this server.
	relyingParty func(r *http.Request) (id string, origin string)
	now          func() time.Time
}

func NewPasskeys(s storage.Storage, relyingParty func(*http.Request) (string, string)) *Passkeys {
	return &Passkeys{storage: s, relyingParty: relyingParty, now: time.Now}
}

// List returns somebody's passkeys, newest first.
func (p *Passkeys) List(subject string) ([]*storage.Passkey, error) {
	return p.storage.ListPasskeys(subject)
}

// Has says whether this person can sign in with a passkey at all.
func (p *Passkeys) Has(subject string) bool {
	passkeys, err := p.storage.ListPasskeys(subject)
	return err == nil && len(passkeys) > 0
}

// Delete removes one passkey of a person.
func (p *Passkeys) Delete(subject string, id string) error {
	if err := p.storage.DeletePasskey(subject, id); err != nil {
		if errors.Is(err, storage.ErrPasskeyNotFound) {
			return ErrNoPasskey
		}
		return fmt.Errorf("failed to delete the passkey: %w", err)
	}
	return nil
}

// BeginRegistration returns the options the browser needs to make a
// credential, and remembers the challenge until the answer comes back.
func (p *Passkeys) BeginRegistration(r *http.Request, subject string) (json.RawMessage, error) {
	user, err := p.user(subject)
	if err != nil {
		return nil, err
	}

	auth, err := p.webauthn(r)
	if err != nil {
		return nil, err
	}

	// A credential that is already registered must not be offered again: the
	// browser then says so instead of quietly replacing it.
	options, session, err := auth.BeginRegistration(user,
		webauthn.WithExclusions(user.credentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// Any authenticator: a phone, a laptop, a key on a keyring.
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start the passkey registration: %w", err)
	}

	if err := p.keepChallenge(subject, session); err != nil {
		return nil, err
	}

	return json.Marshal(options)
}

// FinishRegistration stores what the browser made, under a name the person
// can tell it by.
func (p *Passkeys) FinishRegistration(r *http.Request, subject string, name string, answer []byte) (*storage.Passkey, error) {
	user, err := p.user(subject)
	if err != nil {
		return nil, err
	}

	session, err := p.takeChallenge(subject, user.stored)
	if err != nil {
		return nil, err
	}

	auth, err := p.webauthn(r)
	if err != nil {
		return nil, err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(answer)
	if err != nil {
		return nil, fmt.Errorf("the browser's answer could not be read: %w", err)
	}

	credential, err := auth.CreateCredential(user, *session, parsed)
	if err != nil {
		return nil, fmt.Errorf("the passkey was not accepted: %w", err)
	}

	data, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to store the passkey: %w", err)
	}

	passkey := &storage.Passkey{
		ID:        base64.RawURLEncoding.EncodeToString(credential.ID),
		Owner:     subject,
		Name:      passkeyName(name),
		Data:      data,
		CreatedAt: p.now().UTC(),
	}
	if err := p.storage.AddPasskey(passkey); err != nil {
		if errors.Is(err, storage.ErrPasskeyExists) {
			// An authenticator picks its own credential id, so this is a
			// credential id that was asked for. It belongs to whoever
			// registered it first, and this registration does not get it.
			return nil, ErrPasskeyExists
		}
		return nil, fmt.Errorf("failed to store the passkey: %w", err)
	}

	return passkey, nil
}

// BeginLogin returns the options for signing in with a passkey, for the
// person whose password was right a moment ago.
func (p *Passkeys) BeginLogin(r *http.Request, subject string) (json.RawMessage, error) {
	user, err := p.user(subject)
	if err != nil {
		return nil, err
	}
	if len(user.WebAuthnCredentials()) == 0 {
		return nil, ErrNoPasskey
	}

	auth, err := p.webauthn(r)
	if err != nil {
		return nil, err
	}

	options, session, err := auth.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("failed to start the passkey sign-in: %w", err)
	}

	if err := p.keepChallenge(subject, session); err != nil {
		return nil, err
	}

	return json.Marshal(options)
}

// FinishLogin says whether the browser proved it holds a passkey of this
// person, and records that the passkey was used.
func (p *Passkeys) FinishLogin(r *http.Request, subject string, answer []byte) error {
	user, err := p.user(subject)
	if err != nil {
		return err
	}

	session, err := p.takeChallenge(subject, user.stored)
	if err != nil {
		return err
	}

	auth, err := p.webauthn(r)
	if err != nil {
		return err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(answer)
	if err != nil {
		return fmt.Errorf("the browser's answer could not be read: %w", err)
	}

	credential, err := auth.ValidateLogin(user, *session, parsed)
	if err != nil {
		return fmt.Errorf("the passkey was not accepted: %w", err)
	}

	// The sign count and the backup state travel with the credential, so it
	// is written back: a cloned authenticator is spotted by the count going
	// backwards, which the library checks against what is stored.
	stored, err := p.storage.GetPasskey(base64.RawURLEncoding.EncodeToString(credential.ID))
	if err != nil {
		// It was accepted, so it exists; not being able to write the use back
		// is not a reason to refuse the sign-in.
		return nil
	}
	if data, err := json.Marshal(credential); err == nil {
		stored.Data = data
	}
	used := p.now().UTC()
	stored.LastUsedAt = &used
	if err := p.storage.UpdatePasskey(stored); err != nil {
		return nil //nolint:nilerr // the sign-in was fine; the bookkeeping was not
	}

	return nil
}

// webauthn builds the library's view of this server for one request.
func (p *Passkeys) webauthn(r *http.Request) (*webauthn.WebAuthn, error) {
	id, origin := p.relyingParty(r)
	if id == "" {
		return nil, errors.New("passkeys need to know which host this server is: set vpn.externalHost")
	}

	auth, err := webauthn.New(&webauthn.Config{
		RPID:          id,
		RPDisplayName: "wg-access-server",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to prepare the passkey exchange: %w", err)
	}
	return auth, nil
}

func (p *Passkeys) keepChallenge(subject string, session *webauthn.SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to keep the passkey challenge: %w", err)
	}
	until := p.now().Add(challengeFor).UTC()
	if err := p.storage.SetWebauthnChallenge(subject, string(data), &until); err != nil {
		return fmt.Errorf("failed to keep the passkey challenge: %w", err)
	}
	return nil
}

// takeChallenge reads the challenge and clears it, so that an answer counts
// once and an abandoned exchange does not wait around.
func (p *Passkeys) takeChallenge(subject string, user *storage.User) (*webauthn.SessionData, error) {
	if user.WebauthnChallenge == "" || user.WebauthnChallengeUntil == nil ||
		p.now().After(*user.WebauthnChallengeUntil) {
		return nil, ErrNoChallenge
	}

	session := &webauthn.SessionData{}
	if err := json.Unmarshal([]byte(user.WebauthnChallenge), session); err != nil {
		return nil, ErrNoChallenge
	}

	if err := p.storage.SetWebauthnChallenge(subject, "", nil); err != nil {
		return nil, fmt.Errorf("failed to clear the passkey challenge: %w", err)
	}

	return session, nil
}

func (p *Passkeys) user(subject string) (*passkeyUser, error) {
	stored, err := p.storage.GetUser(subject)
	if err != nil || stored == nil {
		return nil, ErrNoPasswordHere
	}
	passkeys, err := p.storage.ListPasskeys(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to read the passkeys: %w", err)
	}
	return &passkeyUser{stored: stored, passkeys: passkeys}, nil
}

func passkeyName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > maxPasskeyName {
		name = name[:maxPasskeyName]
	}
	return name
}

// RelyingPartyFromHost builds the relying party from a configured host, or
// from the request when none is configured. The configured one is what a
// deployment behind a reverse proxy wants: the Host header is whatever
// reached the server, and a passkey must be bound to the name people type.
func RelyingPartyFromHost(configured string, httpsOnly bool) func(*http.Request) (string, string) {
	return func(r *http.Request) (string, string) {
		host := configured
		if host == "" && r != nil {
			host = r.Host
		}
		if host == "" {
			return "", ""
		}

		// The relying party id is a domain, without a port; the origin is the
		// site the browser is on, with one.
		id := host
		if name, _, err := net.SplitHostPort(host); err == nil {
			id = name
		}

		scheme := "https"
		if !httpsOnly && r != nil && r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}

		origin := url.URL{Scheme: scheme, Host: hostWithPort(host, r)}
		return id, origin.String()
	}
}

// hostWithPort keeps the port the browser used, which the origin needs and
// the configured host often lacks.
func hostWithPort(configured string, r *http.Request) string {
	if _, _, err := net.SplitHostPort(configured); err == nil {
		return configured
	}
	if r != nil {
		if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" {
			return net.JoinHostPort(configured, port)
		}
	}
	return configured
}

// passkeyUser is what the WebAuthn library asks about a person.
type passkeyUser struct {
	stored   *storage.User
	passkeys []*storage.Passkey
}

// WebAuthnID is the user handle. It has to be stable and must not be the
// username - a name can be given to somebody else later, and a credential
// would follow it. The hash of the subject is stable and says nothing.
func (u *passkeyUser) WebAuthnID() []byte {
	sum := sha256.Sum256([]byte("wg-access-server:" + u.stored.Subject))
	return sum[:]
}

func (u *passkeyUser) WebAuthnName() string {
	return u.stored.Subject
}

func (u *passkeyUser) WebAuthnDisplayName() string {
	if u.stored.Name != "" {
		return u.stored.Name
	}
	return u.stored.Subject
}

func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	credentials := []webauthn.Credential{}
	for _, passkey := range u.passkeys {
		credential := webauthn.Credential{}
		if err := json.Unmarshal(passkey.Data, &credential); err != nil {
			// A row nothing can read is not a credential anybody can use.
			continue
		}
		credentials = append(credentials, credential)
	}
	return credentials
}

func (u *passkeyUser) credentialDescriptors() []protocol.CredentialDescriptor {
	descriptors := []protocol.CredentialDescriptor{}
	for _, credential := range u.WebAuthnCredentials() {
		descriptors = append(descriptors, credential.Descriptor())
	}
	return descriptors
}
