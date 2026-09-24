package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/broady/exedev-mcp/internal/exe"
	"github.com/broady/exedev-mcp/internal/tools"
)

// mintedTokenTTL bounds the damage of a leaked minted token.
const mintedTokenTTL = time.Hour

type stdioCmd struct {
	Token    string   `help:"exe.dev API token (from 'ssh exe.dev ssh-key generate-api-key'). If unset, tokens are minted with your SSH agent." env:"EXE_TOKEN"`
	SSHAgent string   `help:"SSH agent socket. Defaults to SSH_AUTH_SOCK, then the IdentityAgent ssh uses for exe.dev." env:"EXE_SSH_AUTH_SOCK" name:"ssh-agent"`
	Key      string   `help:"Agent key to sign with, by SHA256 fingerprint or comment. Defaults to the first key exe.dev accepts, trying the IdentityFile keys ssh uses for exe.dev first." env:"EXE_SSH_KEY"`
	Cmds     []string `help:"Lobby commands minted tokens may run." env:"EXE_TOKEN_CMDS"`
	Endpoint string   `help:"exe.dev API endpoint." default:"${endpoint}" env:"EXE_ENDPOINT"`
}

func (c *stdioCmd) Run(a *app) error {
	tokens, err := c.tokenSource(a)
	if err != nil {
		return err
	}
	client, err := exe.New(exe.Config{Endpoint: c.Endpoint, Tokens: tokens})
	if err != nil {
		return err
	}
	a.log.Info("serving MCP on stdio")
	if err := tools.NewServer(client, version(), tools.Options{}).Run(a.ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("stdio server: %w", err)
	}
	return nil
}

func (c *stdioCmd) tokenSource(a *app) (exe.TokenSource, error) {
	if c.Token != "" {
		return exe.StaticToken(c.Token), nil
	}
	cfg := readSSHConfig(a.ctx)
	sock, err := c.agentSocket(cfg)
	if err != nil {
		return nil, err
	}
	dial := func(ctx context.Context) (agent.ExtendedAgent, io.Closer, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "unix", sock)
		if err != nil {
			return nil, nil, err
		}
		return agent.NewClient(conn), conn, nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, time.Minute)
	defer cancel()
	prefs := exe.KeyPrefs{Pin: c.Key, Prefer: cfg.identities(), Only: cfg.identitiesOnly}
	key, err := exe.FindAgentKey(ctx, dial, c.Endpoint, prefs)
	if err != nil {
		return nil, fmt.Errorf("%w\nSet EXE_TOKEN, or add an agent key to exe.dev: ssh-add -L | ssh exe.dev ssh-key add", err)
	}
	if c.Key == "" {
		a.log.Info("found the exe.dev key by probing the agent; set EXE_SSH_KEY=<key> to skip probing", "key", keyFingerprint(key))
	}
	cmds := c.Cmds
	if len(cmds) == 0 {
		cmds = exe.DefaultCmds()
	}
	a.log.Info("minting exe.dev tokens with ssh agent", "socket", sock, "key", keyFingerprint(key), "ttl", mintedTokenTTL)
	return exe.NewAgentMinter(dial, key, cmds, mintedTokenTTL), nil
}

// sshConfig is what ssh would use to reach exe.dev, from `ssh -G exe.dev`.
type sshConfig struct {
	identityAgent  string
	identityFiles  []string
	identitiesOnly bool
}

// readSSHConfig asks ssh how it would connect to exe.dev. Failure is not
// fatal: it only loses the config's hints, so it returns the zero config.
func readSSHConfig(ctx context.Context) sshConfig {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", "-G", "exe.dev").Output()
	if err != nil {
		return sshConfig{}
	}
	return parseSSHConfig(out)
}

func parseSSHConfig(out []byte) sshConfig {
	var cfg sshConfig
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		switch k {
		case "identityagent":
			if v != "none" && v != "SSH_AUTH_SOCK" {
				cfg.identityAgent = expandHome(v)
			}
		case "identityfile":
			cfg.identityFiles = append(cfg.identityFiles, expandHome(v))
		case "identitiesonly":
			cfg.identitiesOnly = v == "yes"
		}
	}
	return cfg
}

// identities returns the public keys of the configured IdentityFiles that
// exist. ssh -G lists the defaults (~/.ssh/id_ed25519...) even when absent.
// An IdentityFile may name the .pub itself, which is how agent-only keys
// (1Password) are selected.
func (c sshConfig) identities() []ssh.PublicKey {
	var keys []ssh.PublicKey
	for _, f := range c.identityFiles {
		if !strings.HasSuffix(f, ".pub") {
			f += ".pub"
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// agentSocket finds the SSH agent. GUI apps like Claude Desktop often start
// without SSH_AUTH_SOCK, so fall back to what ssh itself would use for
// exe.dev, which picks up agents configured only in ~/.ssh/config
// (1Password, Secretive).
func (c *stdioCmd) agentSocket(cfg sshConfig) (string, error) {
	if c.SSHAgent != "" {
		return expandHome(c.SSHAgent), nil
	}
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		return s, nil
	}
	if cfg.identityAgent != "" {
		return cfg.identityAgent, nil
	}
	return "", errors.New("no SSH agent found: set SSH_AUTH_SOCK or --ssh-agent, or use EXE_TOKEN")
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}
