// Package exe is a client for the exe.dev HTTPS API.
//
// The API is the exe.dev SSH lobby shoved into a POST body: every call is
// POST /exec with the command line as the body. Lobby commands return JSON.
// "ssh <vm> <cmd>" streams the VM command's combined stdout and stderr and
// reports the exit status in the X-Exe-Exit trailer.
package exe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is the public exe.dev HTTPS API endpoint.
const DefaultEndpoint = "https://exe.dev/exec"

const (
	// maxBody is the server's documented request body limit.
	maxBody = 64 << 10
	// maxLobbyResponse bounds lobby JSON responses. `ls` for an account with
	// hundreds of VMs is well under this.
	maxLobbyResponse = 8 << 20
)

// TokenSource supplies bearer tokens for the API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a TokenSource for a fixed token, e.g. from
// `ssh exe.dev ssh-key generate-api-key`.
type StaticToken string

// Token implements TokenSource.
func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

// Config configures a Client.
type Config struct {
	// Endpoint is the /exec URL. Defaults to DefaultEndpoint. On an exe.dev VM
	// this can be an HTTP proxy integration (https://NAME.int.exe.xyz/exec)
	// that injects the token at the network edge.
	Endpoint string
	// Tokens supplies the bearer token. Nil sends no Authorization header,
	// which is right when Endpoint is an integration that injects it.
	Tokens TokenSource
	// HTTPClient overrides the HTTP client. It must not set Client.Timeout:
	// VM commands stream for as long as they run, so deadlines come from the
	// request context.
	HTTPClient *http.Client
}

// Client calls the exe.dev HTTPS API. It is safe for concurrent use.
type Client struct {
	endpoint string
	tokens   TokenSource
	http     *http.Client
}

// New returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	if !strings.HasPrefix(cfg.Endpoint, "https://") && !strings.HasPrefix(cfg.Endpoint, "http://") {
		return nil, fmt.Errorf("exe: endpoint %q is not an http(s) URL", cfg.Endpoint)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = newHTTPClient()
	}
	return &Client{endpoint: cfg.Endpoint, tokens: cfg.Tokens, http: hc}, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			// Lobby commands are cut off server-side at 30s; VM commands send
			// headers immediately and then stream.
			ResponseHeaderTimeout: 45 * time.Second,
		},
	}
}

// APIError is a non-success response from the API.
type APIError struct {
	Status  int    // HTTP status code
	Message string // server-provided error message
}

func (e *APIError) Error() string {
	return fmt.Sprintf("exe.dev: %s (HTTP %d)", e.Message, e.Status)
}

// Lobby runs a lobby command (e.g. "ls", "new --name=foo") and returns its
// JSON output.
func (c *Client) Lobby(ctx context.Context, command string) (json.RawMessage, error) {
	resp, err := c.post(ctx, command)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLobbyResponse+1))
	if err != nil {
		return nil, fmt.Errorf("exe.dev: read response: %w", err)
	}
	if len(body) > maxLobbyResponse {
		return nil, fmt.Errorf("exe.dev: response exceeds %d bytes", maxLobbyResponse)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("exe.dev: response is not JSON: %.200q", body)
	}
	return body, nil
}

// Result is the outcome of a VM command.
type Result struct {
	// Output is the command's combined stdout and stderr. If the output
	// exceeded the limit, it holds the head and tail with a marker between.
	Output []byte
	// Omitted is the number of output bytes dropped from the middle.
	Omitted int64
	// ExitCode is the command's exit status.
	ExitCode int
}

// Exec runs shellCmd on vm via `ssh`. shellCmd is interpreted by the VM
// user's login shell and must not contain single quotes; see ScriptCommand
// for arbitrary scripts. At most maxOutput bytes of output are retained.
//
// Cancelling ctx abandons the request but does not stop the remote command:
// exe.dev keeps it running. Enforce deadlines on the VM (e.g. timeout(1)).
func (c *Client) Exec(ctx context.Context, vm VMName, shellCmd string, maxOutput int) (Result, error) {
	if strings.Contains(shellCmd, "'") {
		return Result{}, errors.New("exe: shell command must not contain single quotes")
	}
	resp, err := c.post(ctx, "ssh "+string(vm)+" '"+shellCmd+"'")
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	out := newHeadTail(maxOutput)
	if _, err := io.Copy(out, resp.Body); err != nil {
		return Result{}, fmt.Errorf("exe.dev: read output: %w", err)
	}
	// Trailers are only populated once the body is fully read.
	exit := resp.Trailer.Get("X-Exe-Exit")
	if exit == "" {
		return Result{}, errors.New("exe.dev: output ended without an exit status")
	}
	code, err := strconv.Atoi(exit)
	if err != nil {
		return Result{}, fmt.Errorf("exe.dev: bad exit status %q", exit)
	}
	b, omitted := out.Bytes()
	return Result{Output: b, Omitted: omitted, ExitCode: code}, nil
}

func (c *Client) post(ctx context.Context, command string) (*http.Response, error) {
	if len(command) > maxBody {
		return nil, fmt.Errorf("exe: command is %d bytes; the API limit is %d", len(command), maxBody)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(command))
	if err != nil {
		return nil, fmt.Errorf("exe: build request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	if c.tokens != nil {
		tok, err := c.tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("exe: get token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exe.dev: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, readAPIError(resp)
	}
	return resp, nil
}

func readAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return &APIError{Status: resp.StatusCode, Message: msg}
}

// headTail is an io.Writer that keeps the first and last limit/2 bytes.
// Build logs put the interesting part at the end; the head shows how it
// started.
type headTail struct {
	head, tail []byte
	half       int
	total      int64
}

func newHeadTail(limit int) *headTail {
	return &headTail{half: max(limit/2, 1)}
}

func (h *headTail) Write(p []byte) (int, error) {
	n := len(p)
	h.total += int64(n)
	if room := h.half - len(h.head); room > 0 {
		k := min(room, len(p))
		h.head = append(h.head, p[:k]...)
		p = p[k:]
	}
	if len(p) == 0 {
		return n, nil
	}
	h.tail = append(h.tail, p...)
	if over := len(h.tail) - h.half; over > 0 {
		// Compact rather than reslice so the buffer doesn't grow unboundedly.
		h.tail = append(h.tail[:0], h.tail[over:]...)
	}
	return n, nil
}

// Bytes returns the retained output and the number of bytes omitted.
func (h *headTail) Bytes() ([]byte, int64) {
	omitted := h.total - int64(len(h.head)+len(h.tail))
	out := make([]byte, 0, len(h.head)+len(h.tail)+64)
	out = append(out, h.head...)
	if omitted > 0 {
		out = fmt.Appendf(out, "\n[... %d bytes omitted ...]\n", omitted)
	}
	return append(out, h.tail...), omitted
}
