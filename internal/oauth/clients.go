package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	maxRedirectURIs     = 10
	maxClientNameLen    = 100
	maxClientMetadata   = 64 << 10
	clientMetadataTTL   = 10 * time.Minute
	maxCachedMetadata   = 32
	maxRegisteredClient = 200
)

var (
	errInvalidRedirect = errors.New("invalid redirect_uri")
	errTooManyClients  = errors.New("too many registered clients")
)

// client is a resolved OAuth client, from either source.
type client struct {
	ID           ClientID
	Name         string
	RedirectURIs []string
	// Metadata is true for Client ID Metadata Document clients, whose
	// identity is anchored in the client_id URL's host.
	Metadata bool
	// Trusted is true when the client_id host is on the trusted list.
	Trusted bool
}

// Host returns the client_id URL's host for metadata-document clients.
func (c client) Host() string {
	if !c.Metadata {
		return ""
	}
	u, err := url.Parse(string(c.ID))
	if err != nil {
		return ""
	}
	return u.Host
}

type cachedMetadata struct {
	client  client
	expires time.Time
}

// resolveClient finds a client by ID. URL-shaped IDs are fetched as Client
// ID Metadata Documents. Callers must only do this for authenticated
// owners: fetching is a server-side request to a caller-chosen URL.
func (s *Server) resolveClient(ctx context.Context, id ClientID) (client, error) {
	if strings.HasPrefix(string(id), "https://") {
		return s.metadataClient(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rc, ok := s.st.Clients[id]
	if !ok {
		return client{}, fmt.Errorf("unknown client_id %q", id)
	}
	return client{ID: rc.ID, Name: rc.Name, RedirectURIs: slices.Clone(rc.RedirectURIs)}, nil
}

func (s *Server) metadataClient(ctx context.Context, id ClientID) (client, error) {
	now := s.now()
	s.mu.Lock()
	if c, ok := s.metadata[id]; ok && now.Before(c.expires) {
		s.mu.Unlock()
		return c.client, nil
	}
	s.mu.Unlock()

	c, err := s.fetchMetadata(ctx, id)
	if err != nil {
		return client{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.metadata {
		if !now.Before(v.expires) {
			delete(s.metadata, k)
		}
	}
	if len(s.metadata) >= maxCachedMetadata {
		clear(s.metadata)
	}
	s.metadata[id] = cachedMetadata{client: c, expires: now.Add(clientMetadataTTL)}
	return c, nil
}

// fetchMetadata fetches and validates a Client ID Metadata Document.
// https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
func (s *Server) fetchMetadata(ctx context.Context, id ClientID) (client, error) {
	u, err := url.Parse(string(id))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return client{}, fmt.Errorf("client_id %q is not a valid metadata document URL", id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, string(id), nil)
	if err != nil {
		return client{}, fmt.Errorf("client metadata: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	// The URL is attacker-chosen by design (CIMD); fetcher refuses
	// non-public addresses at dial time.
	resp, err := s.fetcher.Do(req)
	if err != nil {
		return client{}, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return client{}, fmt.Errorf("fetch client metadata: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxClientMetadata+1))
	if err != nil {
		return client{}, fmt.Errorf("read client metadata: %w", err)
	}
	if len(body) > maxClientMetadata {
		return client{}, errors.New("client metadata document too large")
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return client{}, fmt.Errorf("parse client metadata: %w", err)
	}
	if doc.ClientID != string(id) {
		return client{}, fmt.Errorf("client metadata client_id %q does not match its URL", doc.ClientID)
	}
	if doc.AuthMethod != "" && doc.AuthMethod != "none" {
		return client{}, fmt.Errorf("client metadata: token_endpoint_auth_method %q unsupported; only public clients (none) are supported", doc.AuthMethod)
	}
	if err := validateRedirectURIs(doc.RedirectURIs); err != nil {
		return client{}, fmt.Errorf("client metadata: %w", err)
	}
	name := cleanName(doc.ClientName)
	if name == "" {
		name = u.Host
	}
	return client{
		ID:           id,
		Name:         name,
		RedirectURIs: doc.RedirectURIs,
		Metadata:     true,
		Trusted:      slices.Contains(s.trustedHosts, strings.ToLower(u.Host)),
	}, nil
}

// register creates a client via dynamic client registration (RFC 7591).
// The endpoint is unauthenticated, so the client table is bounded: when
// full, the oldest client without a grant is evicted.
func (s *Server) register(name string, redirectURIs []string) (*registeredClient, error) {
	if err := validateRedirectURIs(redirectURIs); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidRedirect, err)
	}
	rc := &registeredClient{
		ID:           ClientID(newSecret("exm_client_")),
		Name:         cleanName(name),
		RedirectURIs: slices.Clone(redirectURIs),
		CreatedAt:    s.now(),
	}
	if rc.Name == "" {
		rc.Name = "Unnamed client"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.Clients) >= maxRegisteredClient && !s.evictUnusedClientLocked() {
		return nil, errTooManyClients
	}
	s.st.Clients[rc.ID] = rc
	if err := s.saveLocked(); err != nil {
		delete(s.st.Clients, rc.ID)
		return nil, err
	}
	return rc, nil
}

func (s *Server) evictUnusedClientLocked() bool {
	used := map[ClientID]bool{}
	for _, g := range s.st.Grants {
		used[g.ClientID] = true
	}
	var oldest *registeredClient
	for _, c := range s.st.Clients {
		if !used[c.ID] && (oldest == nil || c.CreatedAt.Before(oldest.CreatedAt)) {
			oldest = c
		}
	}
	if oldest == nil {
		return false
	}
	delete(s.st.Clients, oldest.ID)
	return true
}

func validateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return errors.New("redirect_uris is required")
	}
	if len(uris) > maxRedirectURIs {
		return fmt.Errorf("at most %d redirect_uris are allowed", maxRedirectURIs)
	}
	for _, u := range uris {
		if err := validateRedirectURI(u); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI allows https, http on loopback (RFC 8252 7.3), and
// private-use schemes for native apps (RFC 8252 7.1). RFC 8252 asks for
// reverse-domain schemes, but real clients use cursor:// and vscode://.
func validateRedirectURI(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("redirect_uri %q is not an absolute URI", s)
	}
	if u.Fragment != "" {
		return fmt.Errorf("redirect_uri %q must not have a fragment", s)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("redirect_uri %q has no host", s)
		}
	case "http":
		if !isLoopback(u) {
			return fmt.Errorf("redirect_uri %q: http is only allowed for loopback", s)
		}
	case "javascript", "data", "file", "vbscript", "blob", "about":
		return fmt.Errorf("redirect_uri %q: scheme not allowed", s)
	}
	return nil
}

// isNativeRedirect reports whether a redirect URI delivers the code to an
// app on the user's device (loopback or private-use scheme). Any local
// process can claim these, so the consent page warns about them.
func isNativeRedirect(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (isLoopback(u) || !strings.EqualFold(u.Scheme, "https"))
}

func isLoopback(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// matchRedirectURI reports whether got is one of the registered URIs.
// Matching is exact, except that loopback URIs ignore the port: native
// clients like Claude Code listen on an ephemeral port (RFC 8252 7.3).
func matchRedirectURI(registered []string, got string) bool {
	if slices.Contains(registered, got) {
		return true
	}
	g, err := url.Parse(got)
	if err != nil || !isLoopback(g) {
		return false
	}
	for _, r := range registered {
		ru, err := url.Parse(r)
		if err == nil && isLoopback(ru) && ru.Hostname() == g.Hostname() && ru.Path == g.Path && ru.RawQuery == g.RawQuery {
			return true
		}
	}
	return false
}

// redirectHost is the part of a redirect URI a user can recognize.
func redirectHost(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.Host != "" {
		return u.Hostname()
	}
	return u.Scheme + ":"
}

func cleanName(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxClientNameLen {
		s = string(r[:maxClientNameLen])
	}
	return s
}

// newMetadataFetcher returns an HTTP client for fetching client metadata
// documents that refuses to connect to non-public addresses. On exe.dev
// that matters beyond the usual SSRF concerns: integrations live at
// 169.254.169.254 and inject credentials into requests.
func newMetadataFetcher() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		// Control runs after DNS resolution, on the address actually dialed,
		// so DNS rebinding can't sneak past it.
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !isPublicAddr(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil, // a proxy would dial on our behalf, bypassing Control
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed for client metadata")
		},
	}
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 can reach IPv4 private space
}

func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
