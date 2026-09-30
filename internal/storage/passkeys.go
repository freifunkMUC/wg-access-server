package storage

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// ErrPasskeyNotFound is a credential id nobody has.
var ErrPasskeyNotFound = errors.New("passkey not found")

// Passkey is one credential somebody registered: a security key, a phone, a
// laptop's own authenticator. A person can have several, which is the point -
// one to carry and one in a drawer.
//
// The credential itself is kept as the library wrote it, in Data, rather than
// spread over columns: it is the library's structure, it grows between
// versions, and nothing here needs to look inside it. The columns beside it
// are what the person is shown and what the storage sorts by.
type Passkey struct {
	// ID is the credential id the authenticator gave, base64url encoded.
	ID string `gorm:"type:varchar(255);primaryKey"`
	// Owner is whose it is.
	Owner string `gorm:"type:varchar(100);index"`
	// Name is what the person called it, so they can tell one from another.
	Name string
	// Data is the credential as the WebAuthn library serializes it.
	Data       []byte
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// PasskeyStorage keeps the credentials and the challenge of a registration or
// a sign-in that is in flight.
type PasskeyStorage interface {
	// SavePasskey stores a new credential, or the same one again with a
	// changed sign count after a sign-in.
	SavePasskey(passkey *Passkey) error
	// ListPasskeys returns the credentials of one user, newest first.
	ListPasskeys(owner string) ([]*Passkey, error)
	// GetPasskey returns one credential by its id.
	GetPasskey(id string) (*Passkey, error)
	// DeletePasskey removes one credential of a user. Somebody else's is
	// reported as missing rather than refused.
	DeletePasskey(owner string, id string) error
	// SetWebauthnChallenge keeps what a registration or a sign-in needs
	// between its two halves. An empty value clears it.
	SetWebauthnChallenge(subject string, data string, until *time.Time) error
}

func (s *InMemoryStorage) SavePasskey(passkey *Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := *passkey
	s.passkeys[passkey.ID] = &stored
	return nil
}

func (s *InMemoryStorage) ListPasskeys(owner string) ([]*Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	found := []*Passkey{}
	for _, passkey := range s.passkeys {
		if passkey.Owner == owner {
			copied := *passkey
			found = append(found, &copied)
		}
	}
	sortPasskeys(found)
	return found, nil
}

func (s *InMemoryStorage) GetPasskey(id string) (*Passkey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	passkey, ok := s.passkeys[id]
	if !ok {
		return nil, ErrPasskeyNotFound
	}
	copied := *passkey
	return &copied, nil
}

func (s *InMemoryStorage) DeletePasskey(owner string, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	passkey, ok := s.passkeys[id]
	if !ok || passkey.Owner != owner {
		return ErrPasskeyNotFound
	}
	delete(s.passkeys, id)
	return nil
}

func (s *InMemoryStorage) SetWebauthnChallenge(subject string, data string, until *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[subject]
	if !ok {
		return fmt.Errorf("user '%s' does not exist", subject)
	}
	changed := *user
	changed.WebauthnChallenge = data
	changed.WebauthnChallengeUntil = until
	s.users[subject] = &changed
	return nil
}

func (s *SQLStorage) SavePasskey(passkey *Passkey) error {
	if err := s.db.Save(passkey).Error; err != nil {
		return fmt.Errorf("failed to write the passkey: %w", err)
	}
	return nil
}

func (s *SQLStorage) ListPasskeys(owner string) ([]*Passkey, error) {
	var passkeys []*Passkey
	if err := s.db.Where("owner = ?", owner).Find(&passkeys).Error; err != nil {
		return nil, fmt.Errorf("failed to list the passkeys: %w", err)
	}
	sortPasskeys(passkeys)
	return passkeys, nil
}

func (s *SQLStorage) GetPasskey(id string) (*Passkey, error) {
	passkey := &Passkey{}
	if err := s.db.Where("id = ?", id).First(passkey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPasskeyNotFound
		}
		return nil, fmt.Errorf("failed to read the passkey: %w", err)
	}
	return passkey, nil
}

func (s *SQLStorage) DeletePasskey(owner string, id string) error {
	q := s.db.Where("owner = ? AND id = ?", owner, id).Delete(&Passkey{})
	if q.Error != nil {
		return fmt.Errorf("failed to delete the passkey: %w", q.Error)
	}
	if q.RowsAffected == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

func (s *SQLStorage) SetWebauthnChallenge(subject string, data string, until *time.Time) error {
	q := s.db.Model(&User{}).
		Where("subject = ?", subject).
		UpdateColumns(map[string]interface{}{"webauthn_challenge": data, "webauthn_challenge_until": until})
	if q.Error != nil {
		return fmt.Errorf("failed to write the webauthn challenge: %w", q.Error)
	}
	if q.RowsAffected == 0 {
		return fmt.Errorf("user '%s' does not exist", subject)
	}
	return nil
}

// sortPasskeys puts the newest first, as the UI lists them.
func sortPasskeys(passkeys []*Passkey) {
	for i := 1; i < len(passkeys); i++ {
		for j := i; j > 0 && passkeys[j].CreatedAt.After(passkeys[j-1].CreatedAt); j-- {
			passkeys[j], passkeys[j-1] = passkeys[j-1], passkeys[j]
		}
	}
}
