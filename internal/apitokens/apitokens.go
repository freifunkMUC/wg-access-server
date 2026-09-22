// Package apitokens lets scripts use the API on behalf of a user, with a
// token instead of a browser session.
//
// A token acts as the identity its owner had when creating it - the same
// snapshot a web session keeps from the login. The claims middleware runs on
// every request with a token just as it does for a session, so rules derived
// from the configuration (who is admin for basic auth, the OIDC access claim)
// are checked against the current configuration, not the one at creation.
package apitokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authconfig"
	"github.com/freifunkMUC/wg-access-server/pkg/authnz/authsession"
)

// Prefix starts every token, so that a token pasted somewhere it does not
// belong is recognisable - by people and by secret scanners.
const Prefix = "wgas_"

// maxNameLength matches the size of the name column.
const maxNameLength = 100

// touchInterval limits how often the last use of a token is written: a
// script polling the API must not turn every read into a write.
const touchInterval = time.Minute

var (
	// ErrInvalid is returned for a token that does not exist, was revoked or
	// is malformed. They are deliberately not told apart.
	ErrInvalid = errors.New("invalid api token")
	ErrExpired = errors.New("api token has expired")
)

// ForbiddenError is returned for a valid token whose owner may no longer use
// the server, e.g. because the OIDC access claim is now required.
type ForbiddenError struct {
	cause error
}

func (e *ForbiddenError) Error() string {
	return "the owner of this api token has no access: " + e.cause.Error()
}

// ValidationError is a problem with what the user asked for.
type ValidationError struct {
	msg string
}

func (e *ValidationError) Error() string {
	return e.msg
}

type Manager struct {
	storage storage.TokenStorage
	claims  authsession.ClaimsMiddleware
	now     func() time.Time
}

func New(s storage.TokenStorage, claims authsession.ClaimsMiddleware) *Manager {
	return &Manager{storage: s, claims: claims, now: time.Now}
}

// Create issues a token for owner and returns its secret, which is not
// stored anywhere and cannot be shown again.
func (m *Manager) Create(owner *authsession.Identity, name string, expiresAt *time.Time) (string, *storage.APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, &ValidationError{"a token needs a name"}
	}
	if utf8.RuneCountInString(name) > maxNameLength {
		return "", nil, &ValidationError{"the name of a token can be at most 100 characters long"}
	}
	now := m.now()
	if expiresAt != nil && !expiresAt.After(now) {
		return "", nil, &ValidationError{"the expiry date of a token must be in the future"}
	}

	identity, err := json.Marshal(snapshot(owner))
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to encode the identity")
	}

	id, err := randomString(8, hex.EncodeToString)
	if err != nil {
		return "", nil, err
	}
	secret, err := randomString(32, base64.RawURLEncoding.EncodeToString)
	if err != nil {
		return "", nil, err
	}
	secret = Prefix + secret

	token := &storage.APIToken{
		ID:        id,
		Owner:     owner.Subject,
		Name:      name,
		Hash:      hash(secret),
		Identity:  string(identity),
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	if err := m.storage.SaveToken(token); err != nil {
		return "", nil, err
	}
	return secret, token, nil
}

// snapshot is the identity a token acts as. The admin claim that basic and
// simple auth users get from the configuration is left out: the claims
// middleware adds it again on every request for as long as the user is the
// configured admin, and no longer than that.
func snapshot(owner *authsession.Identity) *authsession.Identity {
	copied := *owner
	copied.Claims = nil
	for _, claim := range owner.Claims {
		derived := owner.Provider == authconfig.BasicAuthProvider || owner.Provider == authconfig.SimpleAuthProvider
		if derived && claim.Name == authsession.AdminClaim {
			continue
		}
		copied.Claims = append(copied.Claims, claim)
	}
	return &copied
}

// Authenticate returns the identity a request with this secret acts as.
func (m *Manager) Authenticate(secret string) (*authsession.Identity, *storage.APIToken, error) {
	if !strings.HasPrefix(secret, Prefix) {
		return nil, nil, ErrInvalid
	}

	token, err := m.storage.GetTokenByHash(hash(secret))
	if errors.Is(err, storage.ErrTokenNotFound) {
		return nil, nil, ErrInvalid
	}
	if err != nil {
		return nil, nil, err
	}

	now := m.now()
	if token.Expired(now) {
		return nil, nil, ErrExpired
	}

	identity := &authsession.Identity{}
	if err := json.Unmarshal([]byte(token.Identity), identity); err != nil {
		return nil, nil, errors.Wrapf(err, "failed to decode the identity of api token %s", token.ID)
	}
	if m.claims != nil {
		if err := m.claims(identity); err != nil {
			return nil, nil, &ForbiddenError{err}
		}
	}

	if token.LastUsedAt == nil || now.Sub(*token.LastUsedAt) >= touchInterval {
		if err := m.storage.TouchToken(token.ID, now); err != nil {
			// not a reason to refuse the request
			logrus.Warn(err)
		}
	}

	return identity, token, nil
}

// List returns the tokens of one owner, or every token for "".
func (m *Manager) List(owner string) ([]*storage.APIToken, error) {
	return m.storage.ListTokens(owner)
}

// Delete revokes a token. Users can revoke their own tokens, admins any. For
// anybody else a token that exists is reported as missing, so that ids cannot
// be probed.
func (m *Manager) Delete(user *authsession.Identity, id string) (*storage.APIToken, error) {
	token, err := m.storage.GetToken(id)
	if err != nil {
		return nil, err
	}
	if token.Owner != user.Subject && !user.Claims.IsAdmin() {
		return nil, storage.ErrTokenNotFound
	}
	if err := m.storage.DeleteToken(id); err != nil {
		return nil, err
	}
	return token, nil
}

// DeleteForOwner revokes every token of one user.
func (m *Manager) DeleteForOwner(owner string) error {
	return m.storage.DeleteTokensForOwner(owner)
}

func hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomString(bytes int, encode func([]byte) string) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Wrap(err, "failed to generate a random token")
	}
	return encode(buf), nil
}
