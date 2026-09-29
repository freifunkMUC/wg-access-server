// Package websessions keeps the browser sessions of the web UI.
//
// The cookie carries nothing but an id; who signed in is kept here. That is
// what makes a session something the server can end: signing out, deleting a
// user or taking their access away stops every request that names it, on
// every replica, because a session is read from the storage rather than
// unpacked from the cookie.
package websessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// touchInterval limits how often the last use of a session is written: a web
// UI polling the API must not turn every read into a write.
const touchInterval = time.Minute

// cleanupInterval is how often sessions that nobody can use any more are
// removed. A var so the tests can shorten it.
var cleanupInterval = time.Hour

// maxUserAgentLength matches the size of the column. What a browser sends is
// not bounded, and it is only ever shown back to the person it came from.
const maxUserAgentLength = 255

// ErrInvalid is returned for a session that does not exist, was ended or has
// expired. They are deliberately not told apart.
var ErrInvalid = errors.New("invalid session")

type Manager struct {
	storage storage.SessionStorage
	// maxAge is how long a new session lasts, the same span the cookie gets.
	maxAge time.Duration
	now    func() time.Time
}

func New(s storage.SessionStorage, maxAge time.Duration) *Manager {
	return &Manager{storage: s, maxAge: maxAge, now: time.Now}
}

// Create starts a session for the identity and returns the id the cookie
// carries. The id is not stored, only its hash: whoever reads the database
// learns which sessions exist, not how to use them.
func (m *Manager) Create(identity *authsession.Identity, r *http.Request) (string, error) {
	if identity == nil {
		return "", errors.New("a session needs an identity")
	}

	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("failed to encode the identity: %w", err)
	}

	secret, err := newID()
	if err != nil {
		return "", err
	}

	now := m.now()
	session := &storage.Session{
		ID:         uuid.NewString(),
		Owner:      identity.Subject,
		Hash:       hash(secret),
		Identity:   string(encoded),
		UserAgent:  userAgent(r),
		RemoteAddr: remoteAddr(r),
		CreatedAt:  now,
		ExpiresAt:  now.Add(m.maxAge),
		LastSeenAt: now,
	}
	if err := m.storage.SaveSession(session); err != nil {
		return "", err
	}

	return secret, nil
}

// Identity returns who the session belongs to, and records that it was used.
// An id that names no session, one that expired, and a malformed one are all
// ErrInvalid: a browser cannot tell them apart, and neither should whoever
// tries ids.
func (m *Manager) Identity(id string) (*authsession.Identity, error) {
	if id == "" {
		return nil, ErrInvalid
	}

	session, err := m.storage.GetSessionByHash(hash(id))
	if errors.Is(err, storage.ErrSessionNotFound) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}

	now := m.now()
	if session.Expired(now) {
		return nil, ErrInvalid
	}

	identity := &authsession.Identity{}
	if err := json.Unmarshal([]byte(session.Identity), identity); err != nil {
		return nil, fmt.Errorf("failed to decode the identity of session %s: %w", session.ID, err)
	}

	if now.Sub(session.LastSeenAt) >= touchInterval {
		if err := m.storage.TouchSession(session.ID, now); err != nil {
			// not a reason to refuse the request
			logrus.Warn(err)
		}
	}

	return identity, nil
}

// End stops a session, by the id the cookie carries. An id that names none is
// not an error: signing out twice is a thing browsers do.
func (m *Manager) End(id string) error {
	if id == "" {
		return nil
	}
	session, err := m.storage.GetSessionByHash(hash(id))
	if errors.Is(err, storage.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return m.storage.DeleteSession(session.ID)
}

// List returns the sessions of one user, newest first.
func (m *Manager) List(owner string) ([]*storage.Session, error) {
	return m.storage.ListSessions(owner)
}

// EndAllForOwner signs somebody out everywhere.
func (m *Manager) EndAllForOwner(owner string) error {
	return m.storage.DeleteSessionsForOwner(owner)
}

// StartCleanup removes the sessions nobody can use any more, until the
// context is cancelled. They would keep working for nobody, but a table that
// only grows is its own problem.
func (m *Manager) StartCleanup(ctx context.Context) {
	go m.cleanupLoop(ctx)
}

func (m *Manager) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		if removed, err := m.storage.DeleteExpiredSessions(m.now()); err != nil {
			logrus.Warn(fmt.Errorf("failed to remove expired sessions: %w", err))
		} else if removed > 0 {
			logrus.Debugf("removed %d expired session(s)", removed)
		}

		select {
		case <-ctx.Done():
			logrus.Debug("stopping the session cleanup")
			return
		case <-ticker.C:
		}
	}
}

// newID is the value the cookie carries: 32 bytes of randomness, which is
// what stands between a stranger and somebody else's session.
func newID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate a session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func userAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	agent := r.UserAgent()
	if len(agent) > maxUserAgentLength {
		agent = agent[:maxUserAgentLength]
	}
	return agent
}

func remoteAddr(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
