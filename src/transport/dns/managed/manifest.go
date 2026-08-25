// Package managed implements the B4X-supervised dnscrypt-proxy backend
// (addendum Part VII). The backend is an optional pinned transport provider;
// B4X owns policy, selection, canary, promotion and rollback. Runtime
// download of arbitrary binaries is prohibited (§42).
package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// PinnedCommit is the owner-approved dnscrypt-proxy commit (addendum G.2).
const PinnedCommit = "c3ba78fac8a37fd05c1a4faba77300a9dc03a9dd"
const PinnedLicense = "ISC"

// BinaryManifest is the supply-chain record for one managed binary
// (addendum §13/§42).
type BinaryManifest struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	License     string `json:"license"`
	GOOS        string `json:"goos"`
	GOARCH      string `json:"goarch"`
	SHA256      string `json:"sha256"`
	BuildRecord string `json:"build_record"` // reproducible/pinned build reference
}

// ErrUnverifiedBinary is returned whenever a binary fails manifest checks;
// the supervisor refuses to start it (zero-tolerance gate
// dns_unverified_backend_binary_total).
var ErrUnverifiedBinary = errors.New("managed backend binary failed verification")

// Validate checks the manifest itself.
func (m BinaryManifest) Validate() error {
	if m.Commit != PinnedCommit {
		return fmt.Errorf("%w: commit %q is not pinned %q", ErrUnverifiedBinary, m.Commit, PinnedCommit)
	}
	if m.License != PinnedLicense {
		return fmt.Errorf("%w: license %q mismatch", ErrUnverifiedBinary, m.License)
	}
	if m.GOOS != runtime.GOOS || m.GOARCH != runtime.GOARCH {
		return fmt.Errorf("%w: platform %s/%s != %s/%s", ErrUnverifiedBinary, m.GOOS, m.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if len(m.SHA256) != 64 {
		return fmt.Errorf("%w: sha256 missing", ErrUnverifiedBinary)
	}
	if m.BuildRecord == "" {
		return fmt.Errorf("%w: build record missing", ErrUnverifiedBinary)
	}
	return nil
}

// HashFile computes the SHA-256 of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyBinary checks a binary path against the manifest.
func VerifyBinary(path string, m BinaryManifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	sum, err := HashFile(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnverifiedBinary, err)
	}
	if sum != m.SHA256 {
		return fmt.Errorf("%w: sha256 mismatch", ErrUnverifiedBinary)
	}
	return nil
}
