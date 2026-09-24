package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
)

// tokenError is an RFC 6749 section 5.2 error response.
type tokenError struct {
	status int
	code   string
	desc   string
}

func (e *tokenError) Error() string { return e.code + ": " + e.desc }

func invalidRequest(desc string) *tokenError {
	return &tokenError{http.StatusBadRequest, "invalid_request", desc}
}

func invalidGrant(desc string) *tokenError {
	return &tokenError{http.StatusBadRequest, "invalid_grant", desc}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// token handles POST /oauth/token.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.tokenFail(w, invalidRequest("malformed form body"))
		return
	}
	f := r.PostForm
	clientID := ClientID(f.Get("client_id"))
	if user, pass, ok := r.BasicAuth(); ok {
		// Public clients only. Tolerate client_secret_basic with an empty
		// secret, which some libraries send for public clients.
		if pass != "" {
			s.tokenFail(w, &tokenError{http.StatusUnauthorized, "invalid_client", "only public clients are supported"})
			return
		}
		clientID = ClientID(user)
	}
	if f.Get("client_secret") != "" {
		s.tokenFail(w, &tokenError{http.StatusUnauthorized, "invalid_client", "only public clients are supported"})
		return
	}
	if res := f.Get("resource"); res != "" && !s.matchesResource(res) {
		s.tokenFail(w, &tokenError{http.StatusBadRequest, "invalid_target", "resource does not identify this server"})
		return
	}

	var (
		resp *tokenResponse
		err  error
	)
	switch f.Get("grant_type") {
	case "authorization_code":
		resp, err = s.exchangeCode(clientID, f.Get("code"), f.Get("redirect_uri"), f.Get("code_verifier"))
	case "refresh_token":
		resp, err = s.refresh(clientID, f.Get("refresh_token"), f.Get("scope"))
	case "":
		err = invalidRequest("grant_type is required")
	default:
		err = &tokenError{http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token"}
	}
	if err != nil {
		s.tokenFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) tokenFail(w http.ResponseWriter, err error) {
	te, ok := errors.AsType[*tokenError](err)
	if !ok {
		s.log.Error("oauth: token endpoint", "err", err)
		te = &tokenError{http.StatusInternalServerError, "server_error", "internal error"}
	}
	writeJSON(w, te.status, map[string]string{"error": te.code, "error_description": te.desc})
}

func (s *Server) exchangeCode(clientID ClientID, code, redirectURI, verifier string) (*tokenResponse, error) {
	if code == "" || verifier == "" || clientID == "" {
		return nil, invalidRequest("code, code_verifier and client_id are required")
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return nil, invalidRequest("malformed code_verifier")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(code)
	c, ok := s.codes[h]
	// Codes are single use: delete before any check can fail, so a failed
	// attempt (e.g. a wrong verifier) also burns the code.
	delete(s.codes, h)
	switch {
	case !ok || !s.now().Before(c.expires):
		return nil, invalidGrant("unknown or expired authorization code")
	case c.clientID != clientID:
		return nil, invalidGrant("code was issued to a different client")
	case c.redirectURI != redirectURI:
		return nil, invalidGrant("redirect_uri does not match the authorization request")
	case !verifyPKCE(verifier, c.codeChallenge):
		return nil, invalidGrant("code_verifier does not match code_challenge")
	}

	now := s.now()
	if len(s.st.Grants) >= maxGrants {
		s.evictOldestGrantLocked()
	}
	refresh := newSecret("exm_rt_")
	g := &grant{
		ID:               GrantID(newSecret("")),
		ClientID:         clientID,
		ClientName:       c.clientName,
		RedirectHost:     redirectHost(c.redirectURI),
		Email:            c.email,
		Scopes:           c.scopes,
		CreatedAt:        now,
		RefreshedAt:      now,
		RefreshHash:      hashToken(refresh),
		RefreshExpiresAt: now.Add(refreshTokenTTL),
	}
	s.st.Grants[g.ID] = g
	if err := s.saveLocked(); err != nil {
		delete(s.st.Grants, g.ID)
		return nil, err
	}
	s.log.Info("oauth: grant created", "grant", g.ID, "client_id", clientID, "client_name", g.ClientName, "email", g.Email)
	return s.issueAccessLocked(g, refresh), nil
}

func (s *Server) refresh(clientID ClientID, refresh, scope string) (*tokenResponse, error) {
	if refresh == "" {
		return nil, invalidRequest("refresh_token is required")
	}
	h := hashToken(refresh)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, g := range s.st.Grants {
		if g.PrevRefreshHash == h {
			// A rotated-out token was replayed: either the client or an
			// attacker holds a stolen copy. Revoke the whole grant
			// (OAuth 2.1 section 4.3.1).
			s.log.Warn("oauth: refresh token reuse; revoking grant", "grant", g.ID, "client_name", g.ClientName)
			if err := s.revokeGrantLocked(g.ID); err != nil {
				return nil, err
			}
			return nil, invalidGrant("refresh token was already used")
		}
		if g.RefreshHash != h {
			continue
		}
		switch {
		case !now.Before(g.RefreshExpiresAt):
			return nil, invalidGrant("refresh token expired")
		case !slices.Contains(s.owners, g.Email):
			return nil, invalidGrant("the authorizing user is no longer an owner of this server")
		case clientID != "" && clientID != g.ClientID:
			return nil, invalidGrant("refresh token was issued to a different client")
		}
		if scope != "" {
			for _, sc := range strings.Fields(scope) {
				if !slices.Contains(g.Scopes, sc) {
					return nil, &tokenError{http.StatusBadRequest, "invalid_scope", "scope exceeds the original grant"}
				}
			}
		}
		next := newSecret("exm_rt_")
		prev := *g
		g.PrevRefreshHash, g.RefreshHash = g.RefreshHash, hashToken(next)
		g.RefreshedAt, g.RefreshExpiresAt = now, now.Add(refreshTokenTTL)
		// The client replaces its access token on refresh; the old one goes.
		g.AccessGen++
		if err := s.saveLocked(); err != nil {
			*g = prev
			return nil, err
		}
		return s.issueAccessLocked(g, next), nil
	}
	return nil, invalidGrant("unknown refresh token")
}

// issueAccessLocked mints an access token for g. s.mu must be held.
func (s *Server) issueAccessLocked(g *grant, refresh string) *tokenResponse {
	tok := signAccess(s.st.AccessKey, accessClaims{grant: g.ID, gen: g.AccessGen, expires: s.now().Add(accessTokenTTL)})
	return &tokenResponse{
		AccessToken:  tok,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		RefreshToken: refresh,
		Scope:        strings.Join(g.Scopes, " "),
	}
}

func (s *Server) evictOldestGrantLocked() {
	var oldest *grant
	for _, g := range s.st.Grants {
		if oldest == nil || g.RefreshedAt.Before(oldest.RefreshedAt) {
			oldest = g
		}
	}
	if oldest != nil {
		delete(s.st.Grants, oldest.ID)
	}
}

func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// registerClient handles POST /oauth/register (RFC 7591). All clients are
// registered as public clients using PKCE, whatever auth method they ask
// for; RFC 7591 lets the server override requested metadata.
func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "malformed JSON"})
		return
	}
	rc, err := s.register(req.ClientName, req.RedirectURIs)
	switch {
	case errors.Is(err, errInvalidRedirect):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": err.Error()})
		return
	case errors.Is(err, errTooManyClients):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "internal error"})
		return
	}
	s.log.Info("oauth: client registered", "client_id", rc.ID, "client_name", rc.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  rc.ID,
		"client_id_issued_at":        rc.CreatedAt.Unix(),
		"client_name":                rc.Name,
		"redirect_uris":              rc.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}
