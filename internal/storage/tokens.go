package storage

import (
	"sort"
	"time"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

// ErrTokenNotFound is returned for an API token that does not exist - or no
// longer does, because it was revoked.
var ErrTokenNotFound = errors.New("api token not found")

// APIToken lets a script use the API on behalf of a user. Only the hash of
// the secret is stored: whoever reads the database learns which tokens exist,
// not how to use them.
type APIToken struct {
	ID    string `gorm:"type:varchar(32);primaryKey"`
	Owner string `gorm:"type:varchar(100);index:idx_api_tokens_owner"`
	Name  string `gorm:"type:varchar(100)"`
	// Hash is the SHA-256 of the secret, hex encoded. A token is looked up
	// by it on every request.
	Hash string `gorm:"type:varchar(64);uniqueIndex:uix_api_tokens_hash"`
	// Identity is the identity of the owner at the time the token was
	// created, as JSON. A request with the token acts as that identity.
	Identity   string `gorm:"type:text"`
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

func (APIToken) TableName() string {
	return "api_tokens"
}

// Expired reports whether the token may no longer be used at the given time.
func (t *APIToken) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

// TokenStorage keeps the API tokens. Tokens are read from the storage on
// every request that carries one, so a revoked token stops working on every
// server replica at once - there is nothing to notify.
type TokenStorage interface {
	SaveToken(token *APIToken) error
	// ListTokens returns the tokens of one owner, or every token for "".
	ListTokens(owner string) ([]*APIToken, error)
	GetToken(id string) (*APIToken, error)
	GetTokenByHash(hash string) (*APIToken, error)
	// TouchToken records that a token was used.
	TouchToken(id string, at time.Time) error
	DeleteToken(id string) error
	// DeleteTokensForOwner revokes every token of one user.
	DeleteTokensForOwner(owner string) error
}

func (s *InMemoryStorage) SaveToken(token *APIToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, stored := range s.tokens {
		if stored.Hash == token.Hash && stored.ID != token.ID {
			return errors.New("an api token with this hash already exists")
		}
	}
	stored := *token
	s.tokens[token.ID] = &stored
	return nil
}

func (s *InMemoryStorage) ListTokens(owner string) ([]*APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := []*APIToken{}
	for _, token := range s.tokens {
		if owner == "" || token.Owner == owner {
			copied := *token
			tokens = append(tokens, &copied)
		}
	}
	// oldest first, like the SQL backends
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].CreatedAt.Before(tokens[j].CreatedAt) })
	return tokens, nil
}

func (s *InMemoryStorage) GetToken(id string) (*APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if token, ok := s.tokens[id]; ok {
		copied := *token
		return &copied, nil
	}
	return nil, ErrTokenNotFound
}

func (s *InMemoryStorage) GetTokenByHash(hash string) (*APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.tokens {
		if token.Hash == hash {
			copied := *token
			return &copied, nil
		}
	}
	return nil, ErrTokenNotFound
}

func (s *InMemoryStorage) TouchToken(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token, ok := s.tokens[id]; ok {
		token.LastUsedAt = &at
	}
	return nil
}

func (s *InMemoryStorage) DeleteToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[id]; !ok {
		return ErrTokenNotFound
	}
	delete(s.tokens, id)
	return nil
}

func (s *InMemoryStorage) DeleteTokensForOwner(owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, token := range s.tokens {
		if token.Owner == owner {
			delete(s.tokens, id)
		}
	}
	return nil
}

func (s *SQLStorage) SaveToken(token *APIToken) error {
	if err := s.db.Create(token).Error; err != nil {
		return errors.Wrap(err, "failed to write api token")
	}
	return nil
}

func (s *SQLStorage) ListTokens(owner string) ([]*APIToken, error) {
	tokens := []*APIToken{}
	query := s.db
	if owner != "" {
		query = query.Where("owner = ?", owner)
	}
	if err := query.Order("created_at").Find(&tokens).Error; err != nil {
		return nil, errors.Wrap(err, "failed to read api tokens")
	}
	return tokens, nil
}

func (s *SQLStorage) GetToken(id string) (*APIToken, error) {
	return s.firstToken("id = ?", id)
}

func (s *SQLStorage) GetTokenByHash(hash string) (*APIToken, error) {
	return s.firstToken("hash = ?", hash)
}

func (s *SQLStorage) firstToken(query string, value string) (*APIToken, error) {
	token := &APIToken{}
	err := s.db.Where(query, value).First(token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to read api token")
	}
	return token, nil
}

func (s *SQLStorage) TouchToken(id string, at time.Time) error {
	if err := s.db.Model(&APIToken{}).Where("id = ?", id).UpdateColumn("last_used_at", at).Error; err != nil {
		return errors.Wrap(err, "failed to record the use of an api token")
	}
	return nil
}

func (s *SQLStorage) DeleteToken(id string) error {
	q := s.db.Where("id = ?", id).Delete(&APIToken{})
	if q.Error != nil {
		return errors.Wrap(q.Error, "failed to delete api token")
	}
	if q.RowsAffected == 0 {
		return ErrTokenNotFound
	}
	return nil
}

func (s *SQLStorage) DeleteTokensForOwner(owner string) error {
	if err := s.db.Where("owner = ?", owner).Delete(&APIToken{}).Error; err != nil {
		return errors.Wrap(err, "failed to delete the api tokens of the user")
	}
	return nil
}
