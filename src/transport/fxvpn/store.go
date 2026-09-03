// Account store (accounts.json, design Part I §5 / II.2.1): the identity
// level is the same as WARP/wg/opera stores — JSON on disk 0600 written
// atomically (tmp + fsync + rename), corrupt files quarantined *.corrupt.
//
// REDACTION CONTRACT (red line 2): passwords and refresh tokens never reach
// logs. Account.String()/Redacted() render presence flags only; tests pin
// this so a future fmt.Errorf("%v", account) cannot regress it.
package fxvpn

import (
	"encoding/json"
	"errors"
	"fmt"
)

const accountsFormatVersion = 1

// Account is one FxA identity of the pool.
type Account struct {
	Email        string `json:"email"`
	Label        string `json:"label,omitempty"`
	Password     string `json:"password,omitempty"`      // needed only for (re)login
	RefreshToken string `json:"refresh_token,omitempty"` // long-lived; preferred working secret
}

// Validate enforces the L0 onboarding invariant: an account must be usable
// — either a refresh token (resume path) or a password (login path).
func (a *Account) Validate() error {
	if a == nil || a.Email == "" {
		return fmt.Errorf("%w: empty email", ErrAccountInvalid)
	}
	if a.RefreshToken == "" && a.Password == "" {
		return fmt.Errorf("%w: %s has neither refresh_token nor password", ErrAccountInvalid, a.Email)
	}
	return nil
}

// Redacted renders the account for logs: no secrets, only shape.
func (a *Account) Redacted() string {
	if a == nil {
		return "<nil>"
	}
	email := a.Email
	if i := indexByte(email, '@'); i >= 0 && i+1 < len(email) {
		email = email[:1] + "***@" + email[i+1:]
	}
	flags := "["
	if a.Password != "" {
		flags += "pw,"
	}
	if a.RefreshToken != "" {
		flags += "rt,"
	}
	flags += "]"
	return email + flags + " label=" + quoteOrDash(a.Label)
}

func (a *Account) String() string { return a.Redacted() }

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func quoteOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// AccountsFile is the persisted schema.
type AccountsFile struct {
	Version  int       `json:"version"`
	Accounts []Account `json:"accounts"`
}

// AccountStore persists AccountsFile at Path.
type AccountStore struct {
	Path string
}

// NewAccountStore builds a store handle (no I/O).
func NewAccountStore(path string) *AccountStore { return &AccountStore{Path: path} }

// Load reads the store. Missing -> ErrStoreAbsent (clean first-provision).
// Corrupt -> quarantined *.corrupt + ErrStoreCorrupt (class
// fxvpn-account-store-corrupt); callers treat that as "reprovision allowed".
func (s *AccountStore) Load() (*AccountsFile, error) {
	blob, err := readStoreFile(s.Path)
	if err != nil {
		return nil, err // ErrStoreAbsent passthrough
	}
	var f AccountsFile
	if jerr := json.Unmarshal(blob, &f); jerr != nil || f.Version != accountsFormatVersion {
		if qerr := quarantinePath(s.Path); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrStoreCorrupt, jerr, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrStoreCorrupt, jerr)
	}
	for i := range f.Accounts {
		if verr := f.Accounts[i].Validate(); verr != nil {
			if qerr := quarantinePath(s.Path); qerr != nil {
				return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrStoreCorrupt, verr, qerr)
			}
			return nil, fmt.Errorf("%w: %v", ErrStoreCorrupt, verr)
		}
	}
	return &f, nil
}

// Save writes the file atomically with format stamping.
func (s *AccountStore) Save(f *AccountsFile) error {
	if f == nil {
		return errors.New("fxvpn: nil accounts file")
	}
	f.Version = accountsFormatVersion
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return saveAtomic(s.Path, blob)
}
