package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	testIssuer = "https://vm.exe.xyz"
	owner      = "owner@example.com"
	claudeCB   = "https://claude.ai/api/mcp/auth_callback"
)

type harness struct {
	t         *testing.T
	s         *Server
	srv       *httptest.Server
	statePath string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessAt(t, filepath.Join(t.TempDir(), "state.json"))
}

func newHarnessAt(t *testing.T, statePath string) *harness {
	t.Helper()
	s, err := New(Config{Issuer: testIssuer, Owners: []string{"Owner@Example.com"}, StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{t: t, s: s, srv: srv, statePath: statePath}
}

// do sends a request as the exe.dev proxy would forward it: with the
// signed-in user's email, if any. Redirects are not followed.
func (h *harness) do(method, path, email string, body io.Reader, header http.Header) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, body)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if email != "" {
		req.Header.Set(identityHeader, email)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (h *harness) register(redirect string) ClientID {
	h.t.Helper()
	resp := h.do("POST", "/oauth/register", "", strings.NewReader(`{"client_name":"Claude","redirect_uris":["`+redirect+`"],"token_endpoint_auth_method":"client_secret_post"}`), nil)
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("register: %d %s", resp.StatusCode, readAll(resp))
	}
	var out struct {
		ClientID   ClientID `json:"client_id"`
		AuthMethod string   `json:"token_endpoint_auth_method"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.AuthMethod != "none" {
		h.t.Errorf("auth method = %q, want none", out.AuthMethod)
	}
	return out.ClientID
}

type authzParams struct {
	clientID  ClientID
	redirect  string
	challenge string
	extra     url.Values
}

func (h *harness) authorizeURL(p authzParams) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {string(p.clientID)},
		"redirect_uri":          {p.redirect},
		"code_challenge":        {p.challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"exe offline_access"},
		"resource":              {testIssuer + "/mcp"},
	}
	for k, v := range p.extra {
		q[k] = v
	}
	return "/oauth/authorize?" + q.Encode()
}

var requestIDRE = regexp.MustCompile(`name="request_id" value="([^"]+)"`)

// approve walks the consent page and returns the redirect location.
func (h *harness) approve(p authzParams, action string) *url.URL {
	h.t.Helper()
	resp := h.do("GET", h.authorizeURL(p), owner, nil, nil)
	page := readAll(resp)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("authorize: %d %s", resp.StatusCode, page)
	}
	m := requestIDRE.FindStringSubmatch(page)
	if m == nil {
		h.t.Fatalf("no request_id in consent page:\n%s", page)
	}
	form := url.Values{"request_id": {m[1]}, "action": {action}}
	resp = h.do("POST", "/oauth/authorize", owner, strings.NewReader(form.Encode()), http.Header{
		"Content-Type":   {"application/x-www-form-urlencoded"},
		"Sec-Fetch-Site": {"same-origin"},
	})
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("consent: %d %s", resp.StatusCode, readAll(resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	return loc
}

func (h *harness) tokenReq(form url.Values) (int, map[string]any) {
	h.t.Helper()
	resp := h.do("POST", "/oauth/token", "", strings.NewReader(form.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 43) + newSecret("")[:10]
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func readAll(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func TestMetadata(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		var prm map[string]any
		json.NewDecoder(h.do("GET", path, "", nil, nil).Body).Decode(&prm)
		if prm["resource"] != testIssuer+"/mcp" || prm["authorization_servers"].([]any)[0] != testIssuer {
			t.Errorf("%s = %v", path, prm)
		}
	}
	var asm map[string]any
	json.NewDecoder(h.do("GET", "/.well-known/oauth-authorization-server", "", nil, nil).Body).Decode(&asm)
	// Claude only uses CIMD when both of these are advertised.
	if asm["client_id_metadata_document_supported"] != true {
		t.Error("client_id_metadata_document_supported not advertised")
	}
	if m := asm["token_endpoint_auth_methods_supported"].([]any); len(m) != 1 || m[0] != "none" {
		t.Errorf("token_endpoint_auth_methods_supported = %v", m)
	}
	if m := asm["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v", m)
	}
	if asm["issuer"] != testIssuer || asm["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("metadata = %v", asm)
	}
}

func TestFullFlowWithRefreshRotation(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	verifier, challenge := pkce()
	loc := h.approve(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}, "approve")

	q := loc.Query()
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != claudeCB {
		t.Fatalf("redirected to %s", got)
	}
	if q.Get("state") != "xyz" || q.Get("iss") != testIssuer || q.Get("code") == "" {
		t.Fatalf("redirect params = %v", q)
	}

	status, tok := h.tokenReq(url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {claudeCB},
		"client_id": {string(id)}, "code_verifier": {verifier}, "resource": {testIssuer + "/mcp"},
	})
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	at1, rt1 := str(tok, "access_token"), str(tok, "refresh_token")
	if !strings.HasPrefix(at1, "exm_at_") || !strings.HasPrefix(rt1, "exm_rt_") || tok["token_type"] != "Bearer" || tok["scope"] != "exe" {
		t.Fatalf("token response = %v", tok)
	}
	info, err := h.s.Verify(t.Context(), at1, nil)
	if err != nil || info.UserID != owner || info.Scopes[0] != Scope {
		t.Fatalf("Verify = %+v, %v", info, err)
	}

	// Code reuse fails.
	if status, out := h.tokenReq(url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {claudeCB},
		"client_id": {string(id)}, "code_verifier": {verifier},
	}); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("code reuse: %d %v", status, out)
	}

	// Refresh rotates both tokens and invalidates the old access token.
	status, tok = h.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {string(id)}})
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, tok)
	}
	at2, rt2 := str(tok, "access_token"), str(tok, "refresh_token")
	if rt2 == rt1 || at2 == at1 {
		t.Fatal("tokens not rotated")
	}
	if _, err := h.s.Verify(t.Context(), at1, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("old access token still valid: %v", err)
	}
	if _, err := h.s.Verify(t.Context(), at2, nil); err != nil {
		t.Errorf("new access token: %v", err)
	}

	// Replaying the rotated-out refresh token revokes the whole grant.
	if status, out := h.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}}); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("refresh reuse: %d %v", status, out)
	}
	if _, err := h.s.Verify(t.Context(), at2, nil); err == nil {
		t.Error("access token survived grant revocation")
	}
	if status, _ := h.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt2}}); status != 400 {
		t.Error("current refresh token survived grant revocation")
	}
}

func TestTokenExchangeChecks(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	other := h.register(claudeCB)

	for name, tc := range map[string]struct {
		mutate  func(url.Values)
		wantErr string
	}{
		"wrong verifier":     {func(v url.Values) { v.Set("code_verifier", strings.Repeat("x", 43)) }, "invalid_grant"},
		"wrong redirect":     {func(v url.Values) { v.Set("redirect_uri", "https://claude.ai/other") }, "invalid_grant"},
		"wrong client":       {func(v url.Values) { v.Set("client_id", string(other)) }, "invalid_grant"},
		"wrong resource":     {func(v url.Values) { v.Set("resource", "https://evil.example/mcp") }, "invalid_target"},
		"client secret":      {func(v url.Values) { v.Set("client_secret", "s") }, "invalid_client"},
		"missing verifier":   {func(v url.Values) { v.Del("code_verifier") }, "invalid_request"},
		"bad grant type":     {func(v url.Values) { v.Set("grant_type", "password") }, "unsupported_grant_type"},
		"short verifier len": {func(v url.Values) { v.Set("code_verifier", "short") }, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			verifier, challenge := pkce()
			code := h.approve(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}, "approve").Query().Get("code")
			form := url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {claudeCB},
				"client_id": {string(id)}, "code_verifier": {verifier},
			}
			tc.mutate(form)
			if _, out := h.tokenReq(form); out["error"] != tc.wantErr {
				t.Errorf("error = %v, want %s", out, tc.wantErr)
			}
		})
	}

	// A failed exchange burns the code (a guessed verifier gets one try).
	verifier, challenge := pkce()
	code := h.approve(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}, "approve").Query().Get("code")
	base := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {claudeCB}, "client_id": {string(id)}}
	bad := url.Values{"code_verifier": {strings.Repeat("x", 43)}}
	for k, v := range base {
		bad[k] = v
	}
	h.tokenReq(bad)
	base.Set("code_verifier", verifier)
	if status, _ := h.tokenReq(base); status != 400 {
		t.Error("code usable after a failed exchange")
	}
}

func TestAuthorizeRequiresLogin(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	_, challenge := pkce()
	path := h.authorizeURL(authzParams{clientID: id, redirect: claudeCB, challenge: challenge})
	resp := h.do("GET", path, "", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Path != "/__exe.dev/login" || loc.Query().Get("redirect") != path {
		t.Errorf("login redirect = %s", loc)
	}
}

func TestAuthorizeRejectsNonOwner(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	_, challenge := pkce()
	resp := h.do("GET", h.authorizeURL(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}), "mallory@example.com", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
}

func TestAuthorizeInvalidClientOrRedirectIsNotRedirected(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	_, challenge := pkce()
	for name, p := range map[string]authzParams{
		"unknown client":        {clientID: "nope", redirect: claudeCB, challenge: challenge},
		"unregistered redirect": {clientID: id, redirect: "https://evil.example/cb", challenge: challenge},
		"missing redirect":      {clientID: id, redirect: "", challenge: challenge},
	} {
		resp := h.do("GET", h.authorizeURL(p), owner, nil, nil)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestAuthorizeErrorsRedirectWithIss(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	_, challenge := pkce()
	for name, tc := range map[string]struct {
		extra url.Values
		want  string
	}{
		"plain pkce":    {url.Values{"code_challenge_method": {"plain"}}, "invalid_request"},
		"no pkce":       {url.Values{"code_challenge": {""}}, "invalid_request"},
		"token flow":    {url.Values{"response_type": {"token"}}, "unsupported_response_type"},
		"foreign audit": {url.Values{"resource": {"https://other.exe.xyz/mcp"}}, "invalid_target"},
	} {
		resp := h.do("GET", h.authorizeURL(authzParams{clientID: id, redirect: claudeCB, challenge: challenge, extra: tc.extra}), owner, nil, nil)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if q := loc.Query(); resp.StatusCode != http.StatusFound || q.Get("error") != tc.want || q.Get("iss") != testIssuer || q.Get("state") != "xyz" {
			t.Errorf("%s: %d %s", name, resp.StatusCode, loc)
		}
	}
}

func TestConsentDenyAndCSRF(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	_, challenge := pkce()
	loc := h.approve(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}, "deny")
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Errorf("deny redirect = %s", loc)
	}

	// A cross-site form post (CSRF) is rejected even with a valid request ID.
	page := readAll(h.do("GET", h.authorizeURL(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}), owner, nil, nil))
	rid := requestIDRE.FindStringSubmatch(page)[1]
	form := url.Values{"request_id": {rid}, "action": {"approve"}}
	resp := h.do("POST", "/oauth/authorize", owner, strings.NewReader(form.Encode()), http.Header{
		"Content-Type":   {"application/x-www-form-urlencoded"},
		"Sec-Fetch-Site": {"cross-site"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site consent: status %d", resp.StatusCode)
	}
	// The request can't be approved by a different user either.
	resp = h.do("POST", "/oauth/authorize", "mallory@example.com", strings.NewReader(form.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-owner consent: status %d", resp.StatusCode)
	}
}

func TestConsentPageEscapesClientName(t *testing.T) {
	h := newHarness(t)
	resp := h.do("POST", "/oauth/register", "", strings.NewReader(`{"client_name":"<script>alert(1)</script>","redirect_uris":["`+claudeCB+`"]}`), nil)
	var out struct {
		ClientID ClientID `json:"client_id"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	_, challenge := pkce()
	resp = h.do("GET", h.authorizeURL(authzParams{clientID: out.ClientID, redirect: claudeCB, challenge: challenge}), owner, nil, nil)
	page := readAll(resp)
	if strings.Contains(page, "<script>") || !strings.Contains(page, "not verified") {
		t.Error("client name not escaped or unverified warning missing")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("consent page can be framed")
	}
}

func TestClientIDMetadataDocument(t *testing.T) {
	h := newHarness(t)
	var docBody string
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, docBody)
	}))
	defer doc.Close()
	h.s.fetcher = doc.Client()
	clientID := ClientID(doc.URL + "/client.json")
	host := strings.TrimPrefix(doc.URL, "https://")
	h.s.trustedHosts = []string{strings.ToLower(host)}

	// Claude Code declares a portless loopback redirect and listens on an
	// ephemeral port.
	docBody = `{"client_id":"` + string(clientID) + `","client_name":"Claude Code","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"token_endpoint_auth_method":"none"}`
	verifier, challenge := pkce()
	redirect := "http://localhost:53712/callback"
	resp := h.do("GET", h.authorizeURL(authzParams{clientID: clientID, redirect: redirect, challenge: challenge}), owner, nil, nil)
	page := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "verified") || !strings.Contains(page, "application on this computer") {
		t.Fatalf("consent: %d\n%s", resp.StatusCode, page)
	}
	code := h.approve(authzParams{clientID: clientID, redirect: redirect, challenge: challenge}, "approve").Query().Get("code")
	status, tok := h.tokenReq(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {string(clientID)}, "code_verifier": {verifier},
	})
	if status != 200 || str(tok, "access_token") == "" {
		t.Fatalf("token: %d %v", status, tok)
	}

	// Invalid documents are rejected (after the cache expires).
	for name, body := range map[string]string{
		"id mismatch":         `{"client_id":"https://evil.example/client.json","client_name":"x","redirect_uris":["https://a.example/cb"]}`,
		"confidential client": `{"client_id":"` + string(clientID) + `","redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"bad redirect":        `{"client_id":"` + string(clientID) + `","redirect_uris":["http://evil.example/cb"]}`,
		"no redirects":        `{"client_id":"` + string(clientID) + `"}`,
		"not json":            `<html>`,
	} {
		docBody = body
		h.s.mu.Lock()
		clear(h.s.metadata)
		h.s.mu.Unlock()
		resp := h.do("GET", h.authorizeURL(authzParams{clientID: clientID, redirect: "https://a.example/cb", challenge: challenge}), owner, nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	verifier, challenge := pkce()
	code := h.approve(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}, "approve").Query().Get("code")
	_, tok := h.tokenReq(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {claudeCB},
		"client_id": {string(id)}, "code_verifier": {verifier},
	})

	h2 := newHarnessAt(t, h.statePath)
	if _, err := h2.s.Verify(t.Context(), str(tok, "access_token"), nil); err == nil {
		t.Error("access tokens should not survive a restart")
	}
	status, out := h2.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {str(tok, "refresh_token")}, "client_id": {string(id)}})
	if status != 200 {
		t.Fatalf("refresh after restart: %d %v", status, out)
	}
	if _, err := h2.s.Verify(t.Context(), str(out, "access_token"), nil); err != nil {
		t.Error(err)
	}
}

func TestGrantsPageRevoke(t *testing.T) {
	h := newHarness(t)
	id := h.register(claudeCB)
	verifier, challenge := pkce()
	code := h.approve(authzParams{clientID: id, redirect: claudeCB, challenge: challenge}, "approve").Query().Get("code")
	_, tok := h.tokenReq(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {claudeCB},
		"client_id": {string(id)}, "code_verifier": {verifier},
	})

	page := readAll(h.do("GET", "/oauth/grants", owner, nil, nil))
	m := regexp.MustCompile(`name="grant_id" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil || !strings.Contains(page, "Claude") {
		t.Fatalf("grants page:\n%s", page)
	}
	resp := h.do("POST", "/oauth/grants/revoke", owner, strings.NewReader(url.Values{"grant_id": {m[1]}}.Encode()), http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}, "Sec-Fetch-Site": {"same-origin"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if _, err := h.s.Verify(t.Context(), str(tok, "access_token"), nil); err == nil {
		t.Error("access token valid after revoke")
	}
	if status, _ := h.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {str(tok, "refresh_token")}}); status != 400 {
		t.Error("refresh token valid after revoke")
	}
}

func TestRegisterValidation(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["http://evil.example/cb"]}`,
		`{"redirect_uris":["javascript:alert(1)"]}`,
		`{"redirect_uris":["https://a.example/cb#frag"]}`,
		`not json`,
	} {
		if resp := h.do("POST", "/oauth/register", "", strings.NewReader(body), nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, resp.StatusCode)
		}
	}
}

func TestRegisterIsBounded(t *testing.T) {
	h := newHarness(t)
	for range maxRegisteredClient + 20 {
		h.register(claudeCB)
	}
	h.s.mu.Lock()
	n := len(h.s.st.Clients)
	h.s.mu.Unlock()
	if n > maxRegisteredClient {
		t.Errorf("%d clients registered, max %d", n, maxRegisteredClient)
	}
}

func TestValidateRedirectURI(t *testing.T) {
	for uri, ok := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true,
		"http://localhost:1234/cb":                true,
		"http://127.0.0.1/cb":                     true,
		"http://[::1]:9/cb":                       true,
		"cursor://anysphere.cursor-retrieval/cb":  true,
		"com.example.app:/oauth":                  true,
		"http://example.com/cb":                   false,
		"http://localhost.evil.com/cb":            false,
		"javascript:alert(1)":                     false,
		"data:text/html,x":                        false,
		"myapp://cb":                              true,
		"/relative":                               false,
		"https://a.example/cb#x":                  false,
	} {
		if err := validateRedirectURI(uri); (err == nil) != ok {
			t.Errorf("validateRedirectURI(%q) = %v, want ok=%v", uri, err, ok)
		}
	}
}

func TestMatchRedirectURI(t *testing.T) {
	reg := []string{"http://localhost/callback", "https://claude.ai/cb"}
	for got, want := range map[string]bool{
		"http://localhost:5555/callback": true,
		"http://localhost/callback":      true,
		"http://localhost:5555/other":    false,
		"http://127.0.0.1:5555/callback": false,
		"https://claude.ai/cb":           true,
		"https://claude.ai:444/cb":       false,
		"https://claude.ai/cb?x=1":       false,
	} {
		if matchRedirectURI(reg, got) != want {
			t.Errorf("matchRedirectURI(%q) = %v", got, !want)
		}
	}
}

func TestIsPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":          true,
		"2606:4700::1111":  true,
		"127.0.0.1":        false,
		"169.254.169.254":  false, // exe.dev integrations and cloud metadata
		"10.1.2.3":         false,
		"192.168.1.1":      false,
		"100.100.1.1":      false,
		"::1":              false,
		"fe80::1":          false,
		"fd00::1":          false,
		"::ffff:127.0.0.1": false,
		"0.0.0.0":          false,
		"64:ff9b::a00:1":   false,
	} {
		if got := isPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublicAddr(%s) = %v", addr, got)
		}
	}
}

func TestMetadataFetcherRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := newMetadataFetcher().Get(srv.URL + "/client.json")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("fetch of loopback = %v, want refusal", err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	dir := t.TempDir()
	for _, cfg := range []Config{
		{Issuer: "http://vm.exe.xyz", Owners: []string{owner}, StatePath: dir + "/s"},
		{Issuer: "https://vm.exe.xyz/path", Owners: []string{owner}, StatePath: dir + "/s"},
		{Issuer: testIssuer, StatePath: dir + "/s"},
		{Issuer: testIssuer, Owners: []string{owner}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v): want error", cfg)
		}
	}
}
