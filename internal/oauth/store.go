package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ClientID identifies an OAuth client: either an https URL (a Client ID
// Metadata Document) or an ID issued by dynamic client registration.
type ClientID string

// GrantID identifies one user authorization of one client.
type GrantID string

// tokenHash is the hex SHA-256 of a token. Tokens are 256-bit random
// values, so a fast hash is enough; only hashes are stored.
type tokenHash string

func hashToken(tok string) tokenHash {
	h := sha256.Sum256([]byte(tok))
	return tokenHash(hex.EncodeToString(h[:]))
}

// newSecret returns prefix followed by 256 random bits. The prefix makes
// leaked tokens easy to recognize (and to add to secret scanners).
func newSecret(prefix string) string {
	b := make([]byte, 32)
	rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// registeredClient is a client created by dynamic client registration.
type registeredClient struct {
	ID           ClientID  `json:"id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

// grant is a user's authorization of a client. It holds the current
// refresh token (hashed) and the previous one, so reuse of a rotated-out
// token can be detected and the grant revoked.
type grant struct {
	ID               GrantID   `json:"id"`
	ClientID         ClientID  `json:"client_id"`
	ClientName       string    `json:"client_name"`
	RedirectHost     string    `json:"redirect_host"`
	Email            string    `json:"email"`
	Scopes           []string  `json:"scopes"`
	CreatedAt        time.Time `json:"created_at"`
	RefreshedAt      time.Time `json:"refreshed_at"`
	RefreshHash      tokenHash `json:"refresh_hash"`
	PrevRefreshHash  tokenHash `json:"prev_refresh_hash,omitempty"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

// state is everything that must survive a restart. Access tokens and
// authorization codes are deliberately memory-only: after a restart
// clients get a 401 and use their refresh token.
type state struct {
	Version int                            `json:"version"`
	Clients map[ClientID]*registeredClient `json:"clients"`
	Grants  map[GrantID]*grant             `json:"grants"`
}

const stateVersion = 1

func emptyState() *state {
	return &state{
		Version: stateVersion,
		Clients: map[ClientID]*registeredClient{},
		Grants:  map[GrantID]*grant{},
	}
}

func loadState(path string) (*state, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return emptyState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	st := emptyState()
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("state %s: unsupported version %d", path, st.Version)
	}
	if st.Clients == nil {
		st.Clients = map[ClientID]*registeredClient{}
	}
	if st.Grants == nil {
		st.Grants = map[GrantID]*grant{}
	}
	return st, nil
}

// saveState writes st atomically: temp file, fsync, rename, fsync dir.
// A crash leaves either the old state or the new one, never a torn file.
func saveState(path string, st *state) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state dir: %w", err)
	}
	defer func() { _ = d.Close() }() // read-only handle
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync state dir: %w", err)
	}
	return nil
}
