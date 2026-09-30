// Package users keeps what a person can change about their own account. For
// now that is the password of the built-in sign-in; with an identity provider
// there is nothing here to change.
package users

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

var (
	// ErrWrongPassword is the current password not being the current
	// password. It is not told apart from anything else to the caller beyond
	// what the API says.
	ErrWrongPassword = errors.New("wrong password")
	// ErrNoPasswordHere is an account whose password this server does not
	// keep: one from an identity provider, or a user the configuration does
	// not list.
	ErrNoPasswordHere = errors.New("no password is kept here for this account")
)

// Configured returns the configured entry for a user - the htpasswd hash an
// admin wrote in the config file - and whether they are listed at all.
type Configured func(subject string) (entry string, listed bool)

// Matches says whether a password matches a configured entry, in whichever of
// the htpasswd formats it is written.
type Matches func(entry string, password string) bool

// Passwords changes the password somebody set for themselves. The
// configuration stays the list of who may sign in: a password is only ever
// stored for a user it lists, and it is stored together with the entry that
// was in effect, so that an admin changing the config file takes it back.
type Passwords struct {
	storage    storage.UserStorage
	configured Configured
	matches    Matches
}

func NewPasswords(s storage.UserStorage, configured Configured, matches Matches) *Passwords {
	return &Passwords{storage: s, configured: configured, matches: matches}
}

// Verify says whether this is the password of that user, by the same rule the
// sign-in uses. It is how an action guards itself against somebody who walked
// up to a browser that is already signed in.
func (p *Passwords) Verify(subject string, password string) error {
	entry, listed := p.configured(subject)
	if !listed {
		return ErrNoPasswordHere
	}

	stored, from := p.stored(subject)
	ok := false
	if stored != "" && from == entry {
		ok = bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	} else {
		ok = p.matches(entry, password)
	}
	if !ok {
		return ErrWrongPassword
	}
	return nil
}

// Change replaces the password of one user, after checking the one they have.
func (p *Passwords) Change(subject string, current string, next string) error {
	entry, listed := p.configured(subject)
	if !listed {
		return ErrNoPasswordHere
	}

	// The same rule the sign-in uses: their own password counts while the
	// configured entry it was set against is still the one in the config.
	if err := p.Verify(subject, current); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash the new password: %w", err)
	}

	if err := p.storage.SetUserPassword(subject, string(hash), entry); err != nil {
		return fmt.Errorf("failed to store the new password: %w", err)
	}
	return nil
}

func (p *Passwords) stored(subject string) (string, string) {
	user, err := p.storage.GetUser(subject)
	if err != nil || user == nil {
		// Nobody has signed in as them, or the storage cannot say. Either way
		// the configured entry is what counts, which is what a user without a
		// password of their own has.
		return "", ""
	}
	return user.PasswordHash, user.PasswordFrom
}
