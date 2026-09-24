package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseSSHConfig(t *testing.T) {
	dir := t.TempDir()
	pub := func(name string) ssh.PublicKey {
		k, _, _ := ed25519.GenerateKey(rand.Reader)
		sk, err := ssh.NewPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), ssh.MarshalAuthorizedKey(sk), 0o600); err != nil {
			t.Fatal(err)
		}
		return sk
	}
	onDisk := pub("id_ed25519.pub") // private key path; ssh reads the .pub beside it
	agentOnly := pub("exe.dev.pub") // IdentityFile names the .pub (1Password)

	cfg := parseSSHConfig([]byte("user cbro\n" +
		"identitiesonly yes\n" +
		"identityagent SSH_AUTH_SOCK\n" +
		"identityfile " + filepath.Join(dir, "id_rsa") + "\n" + // absent default
		"identityfile " + filepath.Join(dir, "exe.dev.pub") + "\n" +
		"identityfile " + filepath.Join(dir, "id_ed25519") + "\n"))

	if !cfg.identitiesOnly {
		t.Error("identitiesOnly = false, want true")
	}
	if cfg.identityAgent != "" {
		t.Errorf("identityAgent = %q, want empty for SSH_AUTH_SOCK", cfg.identityAgent)
	}
	got := cfg.identities()
	want := []ssh.PublicKey{agentOnly, onDisk}
	if len(got) != len(want) {
		t.Fatalf("identities: got %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if ssh.FingerprintSHA256(got[i]) != ssh.FingerprintSHA256(want[i]) {
			t.Errorf("identities[%d] = %s, want %s", i, ssh.FingerprintSHA256(got[i]), ssh.FingerprintSHA256(want[i]))
		}
	}

	if a := parseSSHConfig([]byte("identityagent /run/agent.sock\n")).identityAgent; a != "/run/agent.sock" {
		t.Errorf("identityAgent = %q", a)
	}
}
