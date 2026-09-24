package exe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestParseVMName(t *testing.T) {
	for in, want := range map[string]VMName{
		"foo":            "foo",
		"Foo-1":          "foo-1",
		"bar.exe.xyz":    "bar",
		" spaced ":       "spaced",
		"":               "",
		"-leading":       "",
		"has_underscore": "",
		"a;rm -rf /":     "",
	} {
		got, err := ParseVMName(in)
		if want == "" {
			if err == nil {
				t.Errorf("ParseVMName(%q) = %q, want error", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("ParseVMName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	bash := requireBash(t)
	for _, s := range []string{"", "plain", "a b", "it's", `"$HOME"`, "`id`", "a\nb", `back\slash`, "'", "--flag=x y"} {
		out, err := exec.Command(bash, "-c", `printf %s `+Quote(s)).Output()
		if err != nil {
			t.Fatalf("bash: %v", err)
		}
		if string(out) != s {
			t.Errorf("Quote(%q) round-tripped to %q", s, out)
		}
	}
}

func TestScriptCommand(t *testing.T) {
	bash := requireBash(t)
	script := "cd /tmp && echo \"it's $((1+1))\" | tr a-z A-Z\nprintf '%s\\n' `echo bt` \"a  b\"\necho err >&2\nexit 7"
	cmd := ScriptCommand(script, ScriptOptions{TimeoutSeconds: 10})
	if strings.Contains(cmd, "'") {
		t.Fatalf("command contains a single quote: %s", cmd)
	}
	out, err := exec.Command(bash, "-c", cmd).CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("exit = %v, want 7; output %s", err, out)
	}
	for _, want := range []string{"IT'S 2", "bt\na  b\n", "err"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestScriptCommandTimeout(t *testing.T) {
	bash := requireBash(t)
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("timeout(1) not installed")
	}
	start := time.Now()
	err := exec.Command(bash, "-c", ScriptCommand("sleep 30", ScriptOptions{TimeoutSeconds: 1})).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 124 {
		t.Fatalf("err = %v, want exit 124", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestSignSSHSIGVerifiesWithSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	signer := newTestSigner(t)
	msg := []byte(`{"exp":1922918400}`)
	blob, err := SignSSHSIG(signer, APINamespace, msg)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sigPath := filepath.Join(dir, "sig")
	armored := "-----BEGIN SSH SIGNATURE-----\n" + wrap(base64.StdEncoding.EncodeToString(blob), 70) + "-----END SSH SIGNATURE-----\n"
	if err := os.WriteFile(sigPath, []byte(armored), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(keygen, "-Y", "check-novalidate", "-n", APINamespace, "-s", sigPath)
	cmd.Stdin = bytes.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected signature: %v\n%s", err, out)
	}
}

func TestMintTokenFormat(t *testing.T) {
	signer := newTestSigner(t)
	tok, err := MintToken(signer, Permissions{Exp: 1922918400, Cmds: []string{"ls", "ssh-key list"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "exe0" {
		t.Fatalf("token %q: want exe0.<payload>.<sig>", tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload), `{"exp":1922918400,"cmds":["ls","ssh-key list"]}`; got != want {
		t.Errorf("payload = %s, want %s", got, want)
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		t.Errorf("signature not base64url: %v", err)
	}
}

func TestAgentMinterCachesAndRefreshes(t *testing.T) {
	keyring, key := newTestAgent(t)
	dials := 0
	dial := func(context.Context) (agent.ExtendedAgent, io.Closer, error) {
		dials++
		return keyring, io.NopCloser(nil), nil
	}
	now := time.Unix(1_900_000_000, 0)
	m := NewAgentMinter(dial, key, []string{"ls"}, time.Hour)
	m.now = func() time.Time { return now }

	t1, err := m.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Minute)
	t2, _ := m.Token(t.Context())
	if t1 != t2 || dials != 1 {
		t.Errorf("token re-minted early (dials=%d)", dials)
	}
	now = now.Add(20 * time.Minute) // within the last fifth of the hour
	t3, _ := m.Token(t.Context())
	if t3 == t1 || dials != 2 {
		t.Errorf("token not refreshed near expiry (dials=%d)", dials)
	}
}

func TestFindAgentKey(t *testing.T) {
	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	keys := make([]ssh.PublicKey, 0, 2)
	for _, comment := range []string{"other", "exe"} {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: comment}); err != nil {
			t.Fatal(err)
		}
		pub, _ := ssh.NewPublicKey(priv.Public())
		keys = append(keys, pub)
	}
	registered := keys[1]
	// Fake exe.dev that accepts only tokens signed by the registered key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sig, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[2])
		if !bytes.Contains(sig, registered.Marshal()) {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid token"}`)
			return
		}
		io.WriteString(w, `{"email":"a@b.c"}`)
	}))
	defer srv.Close()
	dial := func(context.Context) (agent.ExtendedAgent, io.Closer, error) { return keyring, io.NopCloser(nil), nil }

	got, err := FindAgentKey(t.Context(), dial, srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), registered.Marshal()) {
		t.Errorf("picked %s, want the registered key", ssh.FingerprintSHA256(got))
	}
	got, err = FindAgentKey(t.Context(), dial, srv.URL, "other")
	if err != nil || !bytes.Equal(got.Marshal(), keys[0].Marshal()) {
		t.Errorf("pin by comment: got %v, %v", got, err)
	}
	if _, err := FindAgentKey(t.Context(), dial, srv.URL, "nope"); err == nil {
		t.Error("pin with no match: want error")
	}
}

func TestClientExec(t *testing.T) {
	var gotBody, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotAuth = string(b), r.Header.Get("Authorization")
		w.Header().Set("Trailer", "X-Exe-Exit")
		io.WriteString(w, strings.Repeat("a", 100)+"MIDDLE"+strings.Repeat("z", 100))
		w.Header().Set("X-Exe-Exit", "3")
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Tokens: StaticToken("tok")})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Exec(t.Context(), "myvm", "echo hi", 50)
	if err != nil {
		t.Fatal(err)
	}
	if gotBody != "ssh myvm 'echo hi'" || gotAuth != "Bearer tok" {
		t.Errorf("request body %q auth %q", gotBody, gotAuth)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit = %d, want 3", res.ExitCode)
	}
	if res.Omitted != 156 {
		t.Errorf("omitted = %d, want 156", res.Omitted)
	}
	want := strings.Repeat("a", 25) + "\n[... 156 bytes omitted ...]\n" + strings.Repeat("z", 25)
	if string(res.Output) != want {
		t.Errorf("output = %q, want %q", res.Output, want)
	}

	if _, err := c.Exec(t.Context(), "myvm", "echo 'x'", 50); err == nil {
		t.Error("single quote in command: want error")
	}
}

func TestClientExecMissingTrailer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "partial")
	}))
	defer srv.Close()
	c, _ := New(Config{Endpoint: srv.URL})
	if _, err := c.Exec(t.Context(), "vm", "true", 100); err == nil {
		t.Fatal("want error when exit status is missing")
	}
}

func TestClientLobbyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch string(b) {
		case "ls":
			io.WriteString(w, `{"vms":[]}`)
		case "rm":
			w.WriteHeader(422)
			io.WriteString(w, `{"error":"missing VM name"}`)
		case "html":
			io.WriteString(w, `<html>`)
		}
	}))
	defer srv.Close()
	c, _ := New(Config{Endpoint: srv.URL})

	out, err := c.Lobby(t.Context(), "ls")
	if err != nil || string(out) != `{"vms":[]}` {
		t.Errorf("ls = %s, %v", out, err)
	}
	_, err = c.Lobby(t.Context(), "rm")
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok || apiErr.Status != 422 || apiErr.Message != "missing VM name" {
		t.Errorf("rm err = %v", err)
	}
	if _, err := c.Lobby(t.Context(), "html"); err == nil {
		t.Error("non-JSON response: want error")
	}
	if _, err := c.Lobby(t.Context(), strings.Repeat("x", maxBody+1)); err == nil {
		t.Error("oversized command: want error")
	}
}

func TestHeadTailSmallWrites(t *testing.T) {
	h := newHeadTail(10)
	for i := range 100 {
		h.Write([]byte{byte('0' + i%10)})
	}
	b, omitted := h.Bytes()
	if omitted != 90 || !strings.HasPrefix(string(b), "01234") || !strings.HasSuffix(string(b), "56789") {
		t.Errorf("got %q omitted %d", b, omitted)
	}
	h = newHeadTail(10)
	h.Write([]byte("short"))
	if b, omitted := h.Bytes(); string(b) != "short" || omitted != 0 {
		t.Errorf("got %q omitted %d", b, omitted)
	}
}

func requireBash(t *testing.T) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	return bash
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestAgent(t *testing.T) (agent.ExtendedAgent, ssh.PublicKey) {
	t.Helper()
	keyring := agent.NewKeyring().(agent.ExtendedAgent)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(priv.Public())
	return keyring, pub
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s + "\n"
}
