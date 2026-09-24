package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/broady/exedev-mcp/internal/exe"
	"github.com/broady/exedev-mcp/internal/oauth"
	"github.com/broady/exedev-mcp/internal/tools"
)

const (
	reflectionURL = "https://reflection.int.exe.xyz"
	// maxMCPBody bounds a single MCP request; write_file content is the
	// largest legitimate payload (2MiB), JSON-escaped.
	maxMCPBody = 8 << 20
	// shutdownTimeout lets in-flight tool calls finish. Commands keep
	// running on the VM regardless, so there is no point waiting longer.
	shutdownTimeout = 30 * time.Second
)

type serveCmd struct {
	Addr      string   `help:"Listen address. exe.dev proxies https://VM.exe.xyz to port 8000." default:":8000" env:"EXE_MCP_ADDR"`
	PublicURL string   `help:"Public origin, e.g. https://myvm.exe.xyz. Defaults to this VM's URL." env:"EXE_MCP_PUBLIC_URL" name:"public-url"`
	Owner     []string `help:"exe.dev account emails allowed to connect. Defaults to this VM's owner." env:"EXE_MCP_OWNER"`
	ExecURL   string   `help:"exe.dev API endpoint. Use an HTTP proxy integration that injects the API token, so the token never touches this VM." default:"https://exe-api.int.exe.xyz/exec" env:"EXE_MCP_EXEC_URL" name:"exec-url"`
	State     string   `help:"OAuth state file (registered clients and grants)." env:"EXE_MCP_STATE" type:"path"`
}

func (c *serveCmd) Run(a *app) error {
	if err := c.discover(a.ctx); err != nil {
		return err
	}
	if c.State == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("find state dir (set --state): %w", err)
		}
		c.State = filepath.Join(dir, "exe-mcp", "oauth.json")
	}
	authz, err := oauth.New(oauth.Config{
		Issuer:    c.PublicURL,
		Owners:    c.Owner,
		StatePath: c.State,
		Logger:    a.log,
	})
	if err != nil {
		return err
	}
	client, err := exe.New(exe.Config{Endpoint: c.ExecURL})
	if err != nil {
		return err
	}
	mcpServer := tools.NewServer(client, version())

	mux := http.NewServeMux()
	authz.Register(mux)
	requireToken := auth.RequireBearerToken(authz.Verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: authz.ResourceMetadataURL(),
		Scopes:              []string{oauth.Scope},
	})
	mux.Handle("/mcp", requireToken(http.MaxBytesHandler(newMCPHandler(mcpServer, a.log), maxMCPBody)))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "exe.dev MCP server.\n\nAdd %s as a custom connector in Claude.\nManage connected applications at %s/oauth/grants\n", authz.Resource(), c.PublicURL)
	})

	srv := &http.Server{
		Addr:              c.Addr,
		Handler:           logRequests(a, mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		// Tool calls stream results for up to the 10 minute command limit.
		WriteTimeout:   15 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(a.ctx, "tcp", c.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	a.log.Info("serving MCP", "addr", ln.Addr().String(), "resource", authz.Resource(), "owners", c.Owner, "exec_url", c.ExecURL, "state", c.State)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }() // owner: this function; waited on below
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-a.ctx.Done():
	}
	a.log.Info("shutting down", "timeout", shutdownTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		a.log.Warn("graceful shutdown timed out; closing", "err", err)
		_ = srv.Close()
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func newMCPHandler(s *mcp.Server, log *slog.Logger) http.Handler {
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{
			// Stateless: nothing to lose on restart, no session table to bound.
			Stateless: true,
			Logger:    log,
			// The exe.dev proxy connects over loopback with the public Host,
			// which the SDK's automatic DNS rebinding check rejects. Rebinding
			// is moot here: every request needs a bearer token, and there is no
			// ambient credential for a rebinding page to ride on.
			DisableLocalhostProtection: true,
		},
	)
}

// discover fills the public URL and owner from the exe.dev Reflection
// integration, which every VM has by default.
func (c *serveCmd) discover(ctx context.Context) error {
	if c.PublicURL != "" && len(c.Owner) > 0 {
		return nil
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	get := func(path string, v any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reflectionURL+path, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
	}
	if c.PublicURL == "" {
		var info struct {
			Name string `json:"name"`
		}
		if err := get("/", &info); err != nil || info.Name == "" {
			return fmt.Errorf("discover VM name via Reflection integration (or set --public-url): %v", err)
		}
		c.PublicURL = "https://" + info.Name + ".exe.xyz"
	}
	if len(c.Owner) == 0 {
		var info struct {
			Email string `json:"email"`
		}
		if err := get("/email", &info); err != nil || info.Email == "" {
			return fmt.Errorf("discover owner via Reflection integration (or set --owner): %v", err)
		}
		c.Owner = []string{info.Email}
	}
	return nil
}

// logRequests logs one line per request. Query strings are omitted: on
// OAuth endpoints they carry codes and state.
func logRequests(a *app, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		a.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach Flush for SSE streaming.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func keyFingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }
