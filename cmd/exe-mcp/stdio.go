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
	"golang.org/x/crypto/ssh/agent"

	"github.com/broady/exedev-mcp/internal/exe"
	"github.com/broady/exedev-mcp/internal/tools"
)

// mintedTokenTTL bounds the damage of a leaked minted token.
const mintedTokenTTL = time.Hour

type stdioCmd struct {
	Token    string   `help:"exe.dev API token (from 'ssh exe.dev ssh-key generate-api-key'). If unset, tokens are minted with your SSH agent." env:"EXE_TOKEN"`
	SSHAgent string   `help:"SSH agent socket. Defaults to SSH_AUTH_SOCK, then the IdentityAgent ssh uses for exe.dev." env:"EXE_SSH_AUTH_SOCK" name:"ssh-agent"`
	Key      string   `help:"Agent key to sign with, by SHA256 fingerprint or comment. Defaults to the first key exe.dev accepts." env:"EXE_SSH_KEY"`
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
	sock, err := c.agentSocket(a.ctx)
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
	key, err := exe.FindAgentKey(ctx, dial, c.Endpoint, c.Key)
	if err != nil {
		return nil, fmt.Errorf("%w\nSet EXE_TOKEN, or add an agent key to exe.dev: ssh-add -L | ssh exe.dev ssh-key add", err)
	}
	cmds := c.Cmds
	if len(cmds) == 0 {
		cmds = exe.DefaultCmds()
	}
	a.log.Info("minting exe.dev tokens with ssh agent", "socket", sock, "key", keyFingerprint(key), "ttl", mintedTokenTTL)
	return exe.NewAgentMinter(dial, key, cmds, mintedTokenTTL), nil
}

// agentSocket finds the SSH agent. GUI apps like Claude Desktop often start
// without SSH_AUTH_SOCK, so fall back to what ssh itself would use for
// exe.dev, which picks up agents configured only in ~/.ssh/config
// (1Password, Secretive).
func (c *stdioCmd) agentSocket(ctx context.Context) (string, error) {
	if c.SSHAgent != "" {
		return expandHome(c.SSHAgent), nil
	}
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		return s, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", "-G", "exe.dev").Output()
	if err != nil {
		return "", fmt.Errorf("no SSH agent: SSH_AUTH_SOCK is unset and 'ssh -G exe.dev' failed: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "identityagent "); ok && v != "none" && v != "SSH_AUTH_SOCK" {
			return expandHome(v), nil
		}
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
