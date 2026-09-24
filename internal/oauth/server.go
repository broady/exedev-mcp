// Package oauth is a small OAuth 2.1 authorization server for an MCP
// server hosted on an exe.dev VM.
//
// It follows the MCP authorization spec (2026-07-28): protected resource
// metadata (RFC 9728), authorization server metadata (RFC 8414), Client ID
// Metadata Documents with dynamic client registration (RFC 7591) as a
// fallback, PKCE S256, resource indicators (RFC 8707), the iss response
// parameter (RFC 9207), and refresh token rotation.
//
// It stores no passwords. The exe.dev HTTPS proxy authenticates the user and
// sets X-ExeDev-Email; the proxy strips that header from client requests,
// so it can be trusted. The server must therefore only be reachable through
// the exe.dev proxy.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/broady/exedev-mcp/internal/access"
)

// Scope is the single scope this server issues: full access to the owner's
// exe.dev VMs through the tools.
const Scope = "exe"

// Token lifetimes. Access tokens are short so revocation bites quickly even
// though they live in memory; refresh tokens rotate on every use and expire
// after this long unused.
const (
	accessTokenTTL   = time.Hour
	refreshTokenTTL  = 30 * 24 * time.Hour
	codeTTL          = time.Minute
	consentTTL       = 10 * time.Minute
	maxPending       = 64
	maxCodes         = 64
	maxGrants        = 100
	maxFormBody      = 16 << 10
	identityHeader   = "X-ExeDev-Email"
	loginPath        = "/__exe.dev/login"
	defaultTrustHost = "claude.ai"
)

// Config configures a Server.
type Config struct {
	// Issuer is the server's public origin, e.g. https://myvm.exe.xyz.
	Issuer string
	// Owners are the exe.dev account emails allowed to authorize clients.
	Owners []string
	// StatePath is where registered clients and grants are persisted.
	StatePath string
	// TrustedClientHosts are client_id hosts whose metadata documents are
	// shown as verified on the consent page. Defaults to claude.ai.
	TrustedClientHosts []string
	// Account, if set, reports the exe.dev account the server acts as. The
	// dashboard shows it, so a broken or mismatched API integration is
	// visible at a glance.
	Account func(ctx context.Context) (email string, err error)
	// VMs lists the account's VMs, for choosing what a connection may use.
	// If nil or failing, the consent page offers full access only.
	VMs func(ctx context.Context) ([]access.VM, error)
	// HostVM is the VM the server runs on. It is not offered to limited
	// connections: it holds the API integration, so commands there have
	// full access (tools.Options.HostVM enforces this).
	HostVM string
	Logger *slog.Logger
}

// Server is the authorization server and token verifier.
type Server struct {
	issuer       string
	resource     string
	owners       []string
	statePath    string
	trustedHosts []string
	account      func(context.Context) (string, error)
	listVMs      func(context.Context) ([]access.VM, error)
	hostVM       string
	log          *slog.Logger
	fetcher      *http.Client
	now          func() time.Time
	cop          *http.CrossOriginProtection

	mu       sync.Mutex
	st       *state
	pending  map[string]*pendingAuthorization
	codes    map[tokenHash]*authorizationCode
	metadata map[ClientID]cachedMetadata
}

type pendingAuthorization struct {
	client        client
	redirectURI   string
	state         string
	codeChallenge string
	scopes        []string
	email         string
	expires       time.Time
	// choices are the VMs and tags offered on the consent page.
	choices  []access.VM
	vmsError string
}

type authorizationCode struct {
	clientID      ClientID
	clientName    string
	redirectURI   string
	codeChallenge string
	scopes        []string
	access        access.Policy
	email         string
	expires       time.Time
}

// New returns a Server, loading persisted state.
func New(cfg Config) (*Server, error) {
	iss, err := url.Parse(cfg.Issuer)
	if err != nil || iss.Scheme != "https" || iss.Host == "" || (iss.Path != "" && iss.Path != "/") || iss.RawQuery != "" {
		return nil, fmt.Errorf("oauth: issuer %q must be an https origin", cfg.Issuer)
	}
	if len(cfg.Owners) == 0 {
		return nil, errors.New("oauth: at least one owner email is required")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("oauth: state path is required")
	}
	st, err := loadState(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	trusted := cfg.TrustedClientHosts
	if trusted == nil {
		trusted = []string{defaultTrustHost}
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	s := &Server{
		issuer:       issuer,
		resource:     issuer + "/mcp",
		owners:       lowerAll(cfg.Owners),
		statePath:    cfg.StatePath,
		trustedHosts: lowerAll(trusted),
		account:      cfg.Account,
		listVMs:      cfg.VMs,
		hostVM:       cfg.HostVM,
		log:          logger,
		fetcher:      newMetadataFetcher(),
		now:          time.Now,
		cop:          http.NewCrossOriginProtection(),
		st:           st,
		pending:      map[string]*pendingAuthorization{},
		codes:        map[tokenHash]*authorizationCode{},
		metadata:     map[ClientID]cachedMetadata{},
	}
	if len(st.AccessKey) != accessKeySize {
		st.AccessKey = make([]byte, accessKeySize)
		rand.Read(st.AccessKey)
		if err := s.saveLocked(); err != nil {
			return nil, fmt.Errorf("oauth: %w", err)
		}
	}
	return s, nil
}

func lowerAll(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Resource is the MCP server URL tokens are issued for.
func (s *Server) Resource() string { return s.resource }

// ResourceMetadataURL is the protected resource metadata document URL, for
// WWW-Authenticate challenges.
func (s *Server) ResourceMetadataURL() string {
	return s.issuer + "/.well-known/oauth-protected-resource/mcp"
}

// Register adds the authorization server's endpoints to mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authServerMetadata)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.Handle("POST /oauth/authorize", s.cop.Handler(http.HandlerFunc(s.consent)))
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/register", s.registerClient)
	mux.HandleFunc("OPTIONS /oauth/{endpoint}", preflight)
	mux.HandleFunc("OPTIONS /.well-known/{doc...}", preflight)
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.Handle("POST /oauth/grants/revoke", s.cop.Handler(http.HandlerFunc(s.revoke)))
}

// accessKey holds the grant's access.Policy in auth.TokenInfo.Extra.
const accessKey = "exe-mcp/access"

// PolicyOf returns the access policy that Verify attached to info. It
// fails closed: no token, or a token from another verifier, allows nothing.
func PolicyOf(info *auth.TokenInfo) (access.Policy, error) {
	if info != nil {
		if p, ok := info.Extra[accessKey].(access.Policy); ok {
			return p, nil
		}
	}
	return access.Policy{}, errors.New("no access policy for this request")
}

// Verify is an auth.TokenVerifier for the MCP endpoint.
func (s *Server) Verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := parseAccess(s.st.AccessKey, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	if !s.now().Before(c.expires) {
		return nil, fmt.Errorf("%w: expired token", auth.ErrInvalidToken)
	}
	g, ok := s.st.Grants[c.grant]
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: grant revoked", auth.ErrInvalidToken)
	case c.gen != g.AccessGen:
		return nil, fmt.Errorf("%w: superseded by a refresh", auth.ErrInvalidToken)
	case !slices.Contains(s.owners, g.Email):
		return nil, fmt.Errorf("%w: %s is no longer an owner", auth.ErrInvalidToken, g.Email)
	}
	if now := s.now(); now.Sub(g.UsedAt) >= usedResolution {
		g.UsedAt = now
		// Failing to record use must not fail the request; saveLocked logs.
		_ = s.saveLocked()
	}
	return &auth.TokenInfo{
		Scopes: slices.Clone(g.Scopes), Expiration: c.expires, UserID: g.Email,
		Extra: map[string]any{accessKey: g.Access.Clone()},
	}, nil
}

// identity returns the authenticated owner's email, or writes a response
// (login redirect or 403) and returns false.
func (s *Server) identity(w http.ResponseWriter, r *http.Request, loginReturn string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(identityHeader)))
	if email == "" {
		if loginReturn == "" {
			s.page(w, http.StatusUnauthorized, errorPage("Sign in required", "Sign in to exe.dev and try again."))
			return "", false
		}
		http.Redirect(w, r, loginPath+"?redirect="+url.QueryEscape(loginReturn), http.StatusFound)
		return "", false
	}
	if !slices.Contains(s.owners, email) {
		s.log.Warn("oauth: non-owner denied", "email", email, "path", r.URL.Path)
		s.page(w, http.StatusForbidden, errorPage("Not allowed",
			fmt.Sprintf("You are signed in to exe.dev as %s, which is not allowed to use this server.", email)))
		return "", false
	}
	return email, true
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"scopes_supported":         []string{Scope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "exe.dev",
	})
}

func (s *Server) authServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.issuer + "/oauth/authorize",
		"token_endpoint":                                 s.issuer + "/oauth/token",
		"registration_endpoint":                          s.issuer + "/oauth/register",
		"scopes_supported":                               []string{Scope},
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	})
}

// matchesResource reports whether an RFC 8707 resource parameter names this
// server. Clients vary in whether they send the MCP endpoint or the origin.
func (s *Server) matchesResource(res string) bool {
	res = strings.TrimSuffix(res, "/")
	return res == s.resource || res == s.issuer
}

// usedResolution bounds how often Verify writes the state file to record
// a grant's last use: at most once per grant per interval.
const usedResolution = time.Minute

// saveLocked persists state. s.mu must be held.
func (s *Server) saveLocked() error {
	if err := saveState(s.statePath, s.st); err != nil {
		s.log.Error("oauth: save state", "err", err)
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// preflight answers CORS preflights for the endpoints browser-based MCP
// clients call directly. None of them use cookies.
func preflight(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}
