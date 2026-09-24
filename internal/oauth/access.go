package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// Access tokens are self-contained and MACed with a key persisted in the
// state file, so they survive restarts without a disk write per token.
// They are not bearer-only, though: each names its grant and the grant's
// access generation, and Verify looks the grant up. Deleting a grant
// revokes its tokens at once, bumping the generation (on refresh) retires
// the previous access token, and anything stored on the grant (scopes,
// future per-grant policy) applies live rather than being frozen into
// tokens.
//
// Format: "exm_at_" + b64url(payload) + "." + b64url(HMAC-SHA256(key, payload)),
// payload = version(1) | exp unix(8) | generation(8) | grant ID.

const (
	accessPrefix     = "exm_at_"
	accessVersion    = 1
	accessKeySize    = 32
	accessHeaderSize = 1 + 8 + 8
)

var errBadAccessToken = errors.New("malformed or forged access token")

type accessClaims struct {
	grant   GrantID
	gen     uint64
	expires time.Time
}

func signAccess(key []byte, c accessClaims) string {
	p := make([]byte, 0, accessHeaderSize+len(c.grant))
	p = append(p, accessVersion)
	p = binary.BigEndian.AppendUint64(p, uint64(c.expires.Unix())) //nolint:gosec // G115: post-1970 timestamps
	p = binary.BigEndian.AppendUint64(p, c.gen)
	p = append(p, c.grant...)
	enc := base64.RawURLEncoding
	return accessPrefix + enc.EncodeToString(p) + "." + enc.EncodeToString(accessMAC(key, p))
}

// parseAccess checks the MAC and decodes the claims. Expiry and grant
// state are the caller's to check.
func parseAccess(key []byte, tok string) (accessClaims, error) {
	body, ok := strings.CutPrefix(tok, accessPrefix)
	if !ok {
		return accessClaims{}, errBadAccessToken
	}
	p64, m64, ok := strings.Cut(body, ".")
	if !ok {
		return accessClaims{}, errBadAccessToken
	}
	enc := base64.RawURLEncoding
	p, err1 := enc.DecodeString(p64)
	mac, err2 := enc.DecodeString(m64)
	if err1 != nil || err2 != nil || !hmac.Equal(mac, accessMAC(key, p)) {
		return accessClaims{}, errBadAccessToken
	}
	if len(p) <= accessHeaderSize || p[0] != accessVersion {
		return accessClaims{}, errBadAccessToken
	}
	return accessClaims{
		expires: time.Unix(int64(binary.BigEndian.Uint64(p[1:9])), 0), //nolint:gosec // G115: we signed it
		gen:     binary.BigEndian.Uint64(p[9:17]),
		grant:   GrantID(p[accessHeaderSize:]),
	}, nil
}

func accessMAC(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return m.Sum(nil)
}
