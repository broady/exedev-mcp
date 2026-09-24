package exe

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// APINamespace is the SSHSIG namespace for exe.dev API tokens.
const APINamespace = "v0@exe.dev"

// DefaultCmds returns the lobby commands a minted token may run: VM
// lifecycle, inspection, sharing (for share_vm), and ssh into any VM. Billing, team, key
// and integration management are deliberately excluded.
func DefaultCmds() []string {
	return []string{
		"help", "ls", "new", "rm", "restart", "rename", "tag", "comment", "stat", "whoami",
		"ssh", "share show", "share port", "share set-public", "share set-private",
		"share add", "share remove", "share add-link", "share remove-link", "share receive-email",
	}
}

// Permissions is the signed token payload. See
// https://exe.dev/docs/https-api#granular-permissions.
type Permissions struct {
	Exp  int64    `json:"exp,omitempty"`
	Nbf  int64    `json:"nbf,omitempty"`
	Cmds []string `json:"cmds,omitempty"`
}

// MintToken signs perms with signer, producing an exe0 token. It does what
// `ssh-keygen -Y sign -n v0@exe.dev` does, so it works with keys that only
// live in an agent (1Password, Secretive, hardware keys).
func MintToken(signer ssh.Signer, perms Permissions) (string, error) {
	// encoding/json output is compact with no duplicate keys, which the API
	// requires: the payload must be byte-identical to what was signed.
	payload, err := json.Marshal(perms)
	if err != nil {
		return "", fmt.Errorf("marshal permissions: %w", err)
	}
	sig, err := SignSSHSIG(signer, APINamespace, payload)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return "exe0." + enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// SignSSHSIG returns the binary SSHSIG blob (the armored body of
// `ssh-keygen -Y sign`) for message, using SHA-512.
// Format: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
func SignSSHSIG(signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	const hashAlg = "sha512"
	h := sha512.Sum512(message)

	var signed []byte
	signed = append(signed, "SSHSIG"...)
	signed = appendString(signed, []byte(namespace))
	signed = appendString(signed, nil) // reserved
	signed = appendString(signed, []byte(hashAlg))
	signed = appendString(signed, h[:])

	sig, err := sign(signer, signed)
	if err != nil {
		return nil, fmt.Errorf("sshsig: sign: %w", err)
	}

	var blob []byte
	blob = append(blob, "SSHSIG"...)
	blob = binary.BigEndian.AppendUint32(blob, 1) // version
	blob = appendString(blob, signer.PublicKey().Marshal())
	blob = appendString(blob, []byte(namespace))
	blob = appendString(blob, nil) // reserved
	blob = appendString(blob, []byte(hashAlg))
	blob = appendString(blob, ssh.Marshal(sig))
	return blob, nil
}

// sign uses rsa-sha2-512 for RSA keys; SSHSIG forbids SHA-1 ssh-rsa.
func sign(signer ssh.Signer, data []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("RSA signer does not support rsa-sha2-512")
		}
		return as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	}
	return signer.Sign(rand.Reader, data)
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // G115: inputs are keys, signatures and short strings
	return append(b, s...)
}

// AgentDialer opens a connection to an SSH agent.
type AgentDialer func(ctx context.Context) (agent.ExtendedAgent, io.Closer, error)

// AgentMinter is a TokenSource that mints short-lived tokens by signing
// with a key held in an SSH agent. Nothing secret touches disk, and a
// leaked token expires on its own.
type AgentMinter struct {
	dial AgentDialer
	key  ssh.PublicKey
	cmds []string
	ttl  time.Duration
	now  func() time.Time

	mu     sync.Mutex
	cached string
	exp    time.Time
}

// NewAgentMinter returns a minter that signs with key, which must be in the
// agent and registered with exe.dev (`ssh exe.dev ssh-key list`).
func NewAgentMinter(dial AgentDialer, key ssh.PublicKey, cmds []string, ttl time.Duration) *AgentMinter {
	return &AgentMinter{dial: dial, key: key, cmds: slices.Clone(cmds), ttl: ttl, now: time.Now}
}

// Token implements TokenSource. It reuses a token until it is within a
// fifth of its lifetime of expiring.
func (m *AgentMinter) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.cached != "" && now.Before(m.exp.Add(-m.ttl/5)) {
		return m.cached, nil
	}
	exp := now.Add(m.ttl)
	tok, err := m.mint(ctx, Permissions{Exp: exp.Unix(), Cmds: m.cmds})
	if err != nil {
		return "", err
	}
	m.cached, m.exp = tok, exp
	return tok, nil
}

// mint dials the agent per call: mints are rare, and agents (1Password in
// particular) restart independently of us.
func (m *AgentMinter) mint(ctx context.Context, perms Permissions) (string, error) {
	ag, closer, err := m.dial(ctx)
	if err != nil {
		return "", fmt.Errorf("ssh agent: %w", err)
	}
	defer func() { _ = closer.Close() }() // agent connection; nothing to flush
	signer, err := agentSigner(ag, m.key)
	if err != nil {
		return "", err
	}
	return MintToken(signer, perms)
}

func agentSigner(ag agent.ExtendedAgent, key ssh.PublicKey) (ssh.Signer, error) {
	signers, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("ssh agent: list keys: %w", err)
	}
	want := key.Marshal()
	for _, s := range signers {
		if string(s.PublicKey().Marshal()) == string(want) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("ssh agent: key %s not found", ssh.FingerprintSHA256(key))
}

// KeyPrefs narrows which agent keys FindAgentKey considers, mirroring how
// ssh picks identities.
type KeyPrefs struct {
	// Pin, if set, selects the key with this SHA256 fingerprint or comment,
	// without probing.
	Pin string
	// Prefer lists keys to try first, in order (ssh's IdentityFile).
	Prefer []ssh.PublicKey
	// Only restricts probing to Prefer (ssh's IdentitiesOnly).
	Only bool
}

// FindAgentKey picks the agent key to mint tokens with. Unless pinned, it
// probes candidates against the API with a whoami-only token and the first
// that exe.dev accepts wins. Probing signs with each candidate, which may
// prompt (1Password, Secretive) and reveals the key to exe.dev, so preferred
// keys go first.
func FindAgentKey(ctx context.Context, dial AgentDialer, endpoint string, prefs KeyPrefs) (ssh.PublicKey, error) {
	ag, closer, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("ssh agent: %w", err)
	}
	defer func() { _ = closer.Close() }() // agent connection; nothing to flush
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("ssh agent: list keys: %w", err)
	}
	if prefs.Pin != "" {
		for _, k := range keys {
			if k.Comment == prefs.Pin || ssh.FingerprintSHA256(k) == prefs.Pin {
				return k, nil
			}
		}
		return nil, fmt.Errorf("ssh agent: no key matches %q", prefs.Pin)
	}
	candidates := orderKeys(keys, prefs.Prefer, prefs.Only)
	if len(candidates) == 0 {
		if prefs.Only {
			return nil, errors.New("ssh agent: none of the IdentityFile keys for exe.dev are in the agent (IdentitiesOnly is set)")
		}
		return nil, errors.New("ssh agent: no keys")
	}
	var errs []error
	for _, k := range candidates {
		signer, err := agentSigner(ag, k)
		if err != nil {
			return nil, err
		}
		tok, err := MintToken(signer, Permissions{Exp: time.Now().Add(time.Minute).Unix(), Cmds: []string{"whoami"}})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ssh.FingerprintSHA256(k), err))
			continue
		}
		c, err := New(Config{Endpoint: endpoint, Tokens: StaticToken(tok)})
		if err != nil {
			return nil, err
		}
		_, err = c.Lobby(ctx, "whoami")
		if err == nil {
			return k, nil
		}
		if apiErr, ok := errors.AsType[*APIError](err); !ok || apiErr.Status != 401 {
			return nil, err // network trouble, not a wrong key
		}
		errs = append(errs, fmt.Errorf("%s (%s): not registered with exe.dev", ssh.FingerprintSHA256(k), k.Comment))
	}
	return nil, fmt.Errorf("no agent key is accepted by exe.dev: %w", errors.Join(errs...))
}

// orderKeys returns the agent keys in prefer order, followed (unless only)
// by the remaining agent keys in agent order.
func orderKeys(keys []*agent.Key, prefer []ssh.PublicKey, only bool) []*agent.Key {
	out := make([]*agent.Key, 0, len(keys))
	used := make(map[string]bool, len(keys))
	for _, p := range prefer {
		want := string(p.Marshal())
		for _, k := range keys {
			if !used[want] && string(k.Marshal()) == want {
				used[want] = true
				out = append(out, k)
			}
		}
	}
	if only {
		return out
	}
	for _, k := range keys {
		if !used[string(k.Marshal())] {
			out = append(out, k)
		}
	}
	return out
}
