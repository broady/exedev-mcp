package oauth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// authorize handles GET /oauth/authorize: authenticate the owner, validate
// the request, and show the consent page.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	// Authenticate before anything else: resolving a metadata-document
	// client makes an outbound request, which strangers must not trigger.
	email, ok := s.identity(w, r, r.URL.RequestURI())
	if !ok {
		return
	}
	q := r.URL.Query()

	// Until client_id and redirect_uri are validated, errors are shown to
	// the user and never redirected (RFC 6749 4.1.2.1): an unvalidated
	// redirect_uri is an open redirector.
	clientID := ClientID(q.Get("client_id"))
	if clientID == "" {
		s.page(w, http.StatusBadRequest, errorPage("Invalid request", "The client_id parameter is missing."))
		return
	}
	c, err := s.resolveClient(r.Context(), clientID)
	if err != nil {
		s.log.Warn("oauth: resolve client", "client_id", clientID, "err", err)
		s.page(w, http.StatusBadRequest, errorPage("Unknown application", err.Error()))
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !matchRedirectURI(c.RedirectURIs, redirectURI) {
		s.page(w, http.StatusBadRequest, errorPage("Invalid redirect", "The redirect_uri is not registered for this application."))
		return
	}

	st := q.Get("state")
	fail := func(code, desc string) {
		// redirectURI was matched against the client's registered URIs above.
		http.Redirect(w, r, s.redirectWith(redirectURI, url.Values{"error": {code}, "error_description": {desc}, "state": {st}}), http.StatusFound) //nolint:gosec // G710
	}
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "response_type must be code")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	case len(q.Get("code_challenge")) < 43 || len(q.Get("code_challenge")) > 128:
		fail("invalid_request", "malformed code_challenge")
		return
	}
	if res := q.Get("resource"); res != "" && !s.matchesResource(res) {
		fail("invalid_target", "resource does not identify this server")
		return
	}
	// There is one scope. Unknown scopes (e.g. offline_access, which some
	// clients add to get refresh tokens) are dropped rather than rejected;
	// refresh tokens are always issued.
	scopes := []string{Scope}

	id := newSecret("")
	s.mu.Lock()
	now := s.now()
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
	full := len(s.pending) >= maxPending
	if !full {
		s.pending[id] = &pendingAuthorization{
			client: c, redirectURI: redirectURI, state: st, codeChallenge: q.Get("code_challenge"),
			scopes: scopes, email: email, expires: now.Add(consentTTL),
		}
	}
	s.mu.Unlock()
	if full {
		s.page(w, http.StatusServiceUnavailable, errorPage("Busy", "Too many pending authorization requests. Try again in a few minutes."))
		return
	}

	s.page(w, http.StatusOK, consentPage{
		RequestID:    id,
		ClientName:   c.Name,
		ClientHost:   c.Host(),
		Trusted:      c.Trusted,
		RedirectHost: redirectHost(redirectURI),
		Native:       isNativeRedirect(redirectURI),
		Email:        email,
		Server:       strings.TrimPrefix(s.issuer, "https://"),
	})
}

// consent handles the consent form POST. Cross-origin POSTs are rejected by
// http.CrossOriginProtection before this runs; the unguessable request ID
// ties the decision to a consent page this server rendered for this user.
func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	email, ok := s.identity(w, r, "")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, errorPage("Invalid request", "Malformed form."))
		return
	}
	id := r.PostForm.Get("request_id")
	s.mu.Lock()
	p, ok := s.pending[id]
	delete(s.pending, id)
	s.mu.Unlock()
	if !ok || !s.now().Before(p.expires) || p.email != email {
		s.page(w, http.StatusBadRequest, errorPage("Request expired", "This authorization request has expired. Start again from your application."))
		return
	}

	if r.PostForm.Get("action") != "approve" {
		s.log.Info("oauth: authorization denied", "client_id", p.client.ID, "email", email)
		http.Redirect(w, r, s.redirectWith(p.redirectURI, url.Values{"error": {"access_denied"}, "state": {p.state}}), http.StatusFound)
		return
	}

	code := newSecret("exm_code_")
	s.mu.Lock()
	now := s.now()
	for k, c := range s.codes {
		if !now.Before(c.expires) {
			delete(s.codes, k)
		}
	}
	full := len(s.codes) >= maxCodes
	if !full {
		s.codes[hashToken(code)] = &authorizationCode{
			clientID: p.client.ID, clientName: p.client.Name, redirectURI: p.redirectURI,
			codeChallenge: p.codeChallenge, scopes: p.scopes, email: email, expires: now.Add(codeTTL),
		}
	}
	s.mu.Unlock()
	if full {
		s.page(w, http.StatusServiceUnavailable, errorPage("Busy", "Too many pending authorizations. Try again in a minute."))
		return
	}
	s.log.Info("oauth: authorization approved", "client_id", p.client.ID, "client_name", p.client.Name, "email", email)
	http.Redirect(w, r, s.redirectWith(p.redirectURI, url.Values{"code": {code}, "state": {p.state}}), http.StatusFound)
}

// redirectWith adds params and iss (RFC 9207) to a validated redirect URI,
// preserving its existing query. Empty values are omitted.
func (s *Server) redirectWith(redirectURI string, params url.Values) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI // validated earlier; unreachable
	}
	q := u.Query()
	for k, vs := range params {
		if len(vs) > 0 && vs[0] != "" {
			q.Set(k, vs[0])
		}
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// grants lists the owner's grants with revoke buttons.
func (s *Server) grants(w http.ResponseWriter, r *http.Request) {
	email, ok := s.identity(w, r, r.URL.RequestURI())
	if !ok {
		return
	}
	s.mu.Lock()
	var list []grantRow
	for _, g := range s.st.Grants {
		if g.Email == email {
			list = append(list, grantRow{ID: string(g.ID), Client: g.ClientName, RedirectHost: g.RedirectHost, Created: g.CreatedAt, LastUsed: g.RefreshedAt})
		}
	}
	s.mu.Unlock()
	slices.SortFunc(list, func(a, b grantRow) int { return b.LastUsed.Compare(a.LastUsed) })
	s.page(w, http.StatusOK, grantsPage{Email: email, Grants: list})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	email, ok := s.identity(w, r, "")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.page(w, http.StatusBadRequest, errorPage("Invalid request", "Malformed form."))
		return
	}
	id := GrantID(r.PostForm.Get("grant_id"))
	s.mu.Lock()
	g, ok := s.st.Grants[id]
	var err error
	if ok && g.Email == email {
		err = s.revokeGrantLocked(id)
	}
	s.mu.Unlock()
	if err != nil {
		s.page(w, http.StatusInternalServerError, errorPage("Error", "Could not save the revocation."))
		return
	}
	if ok {
		s.log.Info("oauth: grant revoked by owner", "grant", id, "client_name", g.ClientName)
	}
	http.Redirect(w, r, "/oauth/grants", http.StatusSeeOther)
}

// revokeGrantLocked deletes a grant and its access tokens. s.mu must be held.
func (s *Server) revokeGrantLocked(id GrantID) error {
	delete(s.st.Grants, id)
	for k, at := range s.access {
		if at.grant == id {
			delete(s.access, k)
		}
	}
	return s.saveLocked()
}
