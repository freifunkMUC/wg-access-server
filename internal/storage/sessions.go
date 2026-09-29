package storage

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
)

// ErrSessionNotFound is returned for a browser session that does not exist -
// or no longer does, because it expired or was signed out.
var ErrSessionNotFound = errors.New("session not found")

// Session is a browser session. The identity it was created with is kept
// here rather than in the cookie, so that signing somebody out, deleting them
// or taking their access away ends it at once - on every replica, since there
// is nothing to notify.
//
// Only the hash of the id in the cookie is stored: whoever reads the database
// learns which sessions exist, not how to use them.
type Session struct {
	ID    string `gorm:"type:varchar(32);primaryKey"`
	Owner string `gorm:"type:varchar(100);index:idx_sessions_owner"`
	// Hash is the SHA-256 of the id in the cookie, hex encoded. A session is
	// looked up by it on every request.
	Hash string `gorm:"type:varchar(64);uniqueIndex:uix_sessions_hash"`
	// Identity is who signed in, as JSON. A request with this session acts as
	// that identity.
	Identity string `gorm:"type:text"`
	// UserAgent and RemoteAddr are what the browser said and where it came
	// from, so that somebody can tell their own sessions apart.
	UserAgent  string `gorm:"type:varchar(255)"`
	RemoteAddr string `gorm:"type:varchar(64)"`
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

func (Session) TableName() string {
	return "sessions"
}

// Expired reports whether the session may no longer be used at the given time.
func (s *Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

// SessionStorage keeps the browser sessions. They are read on every request
// that carries one, so a session that was ended stops working everywhere at
// once.
type SessionStorage interface {
	SaveSession(session *Session) error
	GetSessionByHash(hash string) (*Session, error)
	// ListSessions returns the sessions of one owner, newest first.
	ListSessions(owner string) ([]*Session, error)
	// TouchSession records that a session was used.
	TouchSession(id string, at time.Time) error
	DeleteSession(id string) error
	// DeleteSessionsForOwner ends every session of one user.
	DeleteSessionsForOwner(owner string) error
	// DeleteExpiredSessions removes what nobody can use any more.
	DeleteExpiredSessions(now time.Time) (int, error)
}

func (s *InMemoryStorage) SaveSession(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, stored := range s.sessions {
		if stored.Hash == session.Hash && stored.ID != session.ID {
			return errors.New("a session with this hash already exists")
		}
	}
	stored := *session
	s.sessions[session.ID] = &stored
	return nil
}

func (s *InMemoryStorage) GetSessionByHash(hash string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if session.Hash == hash {
			found := *session
			return &found, nil
		}
	}
	return nil, ErrSessionNotFound
}

func (s *InMemoryStorage) ListSessions(owner string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sessions := []*Session{}
	for _, session := range s.sessions {
		if session.Owner == owner {
			found := *session
			sessions = append(sessions, &found)
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].CreatedAt.After(sessions[j].CreatedAt) })
	return sessions, nil
}

func (s *InMemoryStorage) TouchSession(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	session.LastSeenAt = at
	return nil
}

func (s *InMemoryStorage) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *InMemoryStorage) DeleteSessionsForOwner(owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.Owner == owner {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *InMemoryStorage) DeleteExpiredSessions(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, session := range s.sessions {
		if session.Expired(now) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}

func (s *SQLStorage) SaveSession(session *Session) error {
	if err := s.db.Create(session).Error; err != nil {
		return fmt.Errorf("failed to write session: %w", err)
	}
	return nil
}

func (s *SQLStorage) GetSessionByHash(hash string) (*Session, error) {
	session := &Session{}
	if err := s.db.Where("hash = ?", hash).First(session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to read session: %w", err)
	}
	return session, nil
}

func (s *SQLStorage) ListSessions(owner string) ([]*Session, error) {
	sessions := []*Session{}
	if err := s.db.Where("owner = ?", owner).Order("created_at desc").Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("failed to read sessions: %w", err)
	}
	return sessions, nil
}

func (s *SQLStorage) TouchSession(id string, at time.Time) error {
	q := s.db.Model(&Session{}).Where("id = ?", id).UpdateColumn("last_seen_at", at)
	if q.Error != nil {
		return fmt.Errorf("failed to record the use of a session: %w", q.Error)
	}
	if q.RowsAffected == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (s *SQLStorage) DeleteSession(id string) error {
	if err := s.db.Where("id = ?", id).Delete(&Session{}).Error; err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func (s *SQLStorage) DeleteSessionsForOwner(owner string) error {
	if err := s.db.Where("owner = ?", owner).Delete(&Session{}).Error; err != nil {
		return fmt.Errorf("failed to delete the sessions of the user: %w", err)
	}
	return nil
}

func (s *SQLStorage) DeleteExpiredSessions(now time.Time) (int, error) {
	q := s.db.Where("expires_at <= ?", now).Delete(&Session{})
	if q.Error != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", q.Error)
	}
	return int(q.RowsAffected), nil
}
