package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/broady/exedev-mcp/internal/access"
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
	choices, vmsErr := s.vmChoices(r.Context())

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
			choices: choices, vmsError: vmsErr,
		}
	}
	p := s.pending[id]
	s.mu.Unlock()
	if full {
		s.page(w, http.StatusServiceUnavailable, errorPage("Busy", "Too many pending authorization requests. Try again in a few minutes."))
		return
	}
	s.page(w, http.StatusOK, s.consentPage(id, p, defaultChoice(), ""))
}

// vmChoices lists the VMs a limited connection may be given, leaving out
// the host VM. On failure the consent page offers all VMs only.
func (s *Server) vmChoices(ctx context.Context) ([]access.VM, string) {
	if s.listVMs == nil {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(ctx, accountTimeout)
	defer cancel()
	vms, err := s.listVMs(ctx)
	if err != nil {
		s.log.Warn("oauth: list VMs for consent", "err", err)
		return nil, err.Error()
	}
	return slices.DeleteFunc(vms, func(v access.VM) bool { return v.Name == s.hostVM }), ""
}

// choice is a consent form submission.
type choice struct {
	scope  string // "all", "vms" or "tags"
	policy access.Policy
}

// defaultChoice is what the consent page starts with: everything.
func defaultChoice() choice { return choice{scope: "all", policy: access.Full()} }

// consentPage renders p. c and formErr carry a submission back to the
// user.
func (s *Server) consentPage(id string, p *pendingAuthorization, c choice, formErr string) consentPage {
	var tags []string
	for _, v := range p.choices {
		tags = append(tags, v.Tags...)
	}
	slices.Sort(tags)
	cp := consentPage{
		RequestID:    id,
		ClientName:   p.client.Name,
		ClientHost:   p.client.Host(),
		Trusted:      p.client.Trusted,
		RedirectHost: redirectHost(p.redirectURI),
		Native:       isNativeRedirect(p.redirectURI),
		Email:        p.email,
		Limitable:    s.limitable(p),
		Scope:        c.scope,
		HostVM:       s.hostVM,
		Error:        formErr,
	}
	for _, v := range p.choices {
		cp.VMs = append(cp.VMs, vmChoice{Name: v.Name, Tags: v.Tags, Checked: slices.Contains(c.policy.VMs, v.Name)})
	}
	for _, t := range slices.Compact(tags) {
		cp.Tags = append(cp.Tags, tagChoice{Name: t, Checked: slices.Contains(c.policy.Tags, t)})
	}
	for _, op := range access.Ops() {
		cp.Ops = append(cp.Ops, opChoice{Op: op, Label: opLabels[op], Checked: c.policy.Can(op)})
	}
	return cp
}

// limitable reports whether p can be limited to some VMs, which needs the
// VM list.
func (s *Server) limitable(p *pendingAuthorization) bool {
	return s.listVMs != nil && p.vmsError == ""
}

// parseChoice reads the consent form. Only the list matching the scope
// counts, and manage is dropped outside the all scope, since the page hides
// both.
func parseChoice(form url.Values) choice {
	c := choice{scope: form.Get("scope")}
	ops := make([]access.Op, 0, len(form["op"]))
	for _, op := range form["op"] {
		ops = append(ops, access.Op(op))
	}
	c.policy.Ops = access.NormalizeOps(ops)
	switch c.scope {
	case "vms":
		c.policy.VMs = form["vm"]
	case "tags":
		c.policy.Tags = form["tag"]
	default:
		c.scope = "all"
		c.policy.AllVMs = true
	}
	if !c.policy.AllVMs {
		c.policy.Ops = slices.DeleteFunc(c.policy.Ops, func(op access.Op) bool { return op == access.OpManage })
	}
	return c
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
	approve := r.PostForm.Get("action") == "approve"
	c := parseChoice(r.PostForm)
	policy := c.policy
	var policyErr error
	s.mu.Lock()
	p, ok := s.pending[id]
	valid := ok && s.now().Before(p.expires) && p.email == email
	if valid && approve {
		policyErr = s.checkPolicy(p, policy)
	}
	// A rejected choice keeps the request, so the user can fix it.
	if policyErr == nil {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if !valid {
		s.page(w, http.StatusBadRequest, errorPage("Request expired", "This authorization request has expired. Start again from your application."))
		return
	}
	if policyErr != nil {
		s.page(w, http.StatusBadRequest, s.consentPage(id, p, c, policyErr.Error()))
		return
	}

	if !approve {
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
			codeChallenge: p.codeChallenge, scopes: p.scopes, access: policy, email: email, expires: now.Add(codeTTL),
		}
	}
	s.mu.Unlock()
	if full {
		s.page(w, http.StatusServiceUnavailable, errorPage("Busy", "Too many pending authorizations. Try again in a minute."))
		return
	}
	s.log.Info("oauth: authorization approved", "client_id", p.client.ID, "client_name", p.client.Name, "email", email, "access", policy.String())
	http.Redirect(w, r, s.redirectWith(p.redirectURI, url.Values{"code": {code}, "state": {p.state}}), http.StatusFound)
}

// checkPolicy validates a consent choice against what the page offered.
func (s *Server) checkPolicy(p *pendingAuthorization, policy access.Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if policy.AllVMs {
		return nil
	}
	if !s.limitable(p) {
		return errors.New("VMs could not be listed, so only all VMs can be granted")
	}
	for _, v := range policy.VMs {
		if v == s.hostVM {
			return fmt.Errorf("%s runs this server and is only available with all VMs", v)
		}
	}
	return nil
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

// accountTimeout bounds the dashboard's exe.dev API check; the page
// renders without it rather than hang.
const accountTimeout = 5 * time.Second

// dashboard shows the owner how to connect, whether the exe.dev API
// integration works, and the connected applications.
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	email, ok := s.identity(w, r, r.URL.RequestURI())
	if !ok {
		return
	}
	d := dashboardPage{Email: email, Resource: s.resource}
	if s.account != nil {
		ctx, cancel := context.WithTimeout(r.Context(), accountTimeout)
		acct, err := s.account(ctx)
		cancel()
		d.Account, d.AccountChecked = acct, true
		if err != nil {
			s.log.Warn("dashboard: exe.dev account check", "err", err)
			d.AccountErr = err.Error()
		}
	}
	now := s.now()
	s.mu.Lock()
	for _, g := range s.st.Grants {
		if g.Email == email {
			d.Grants = append(d.Grants, grantRow{
				ID: string(g.ID), Client: g.ClientName, RedirectHost: g.RedirectHost, Access: g.Access.String(),
				Used: ago(now, g.UsedAt), sortKey: lastActive(g),
			})
		}
	}
	s.mu.Unlock()
	slices.SortFunc(d.Grants, func(a, b grantRow) int { return b.sortKey.Compare(a.sortKey) })
	s.page(w, http.StatusOK, d)
}

// lastActive orders the dashboard: most recently used, or created if never
// used.
func lastActive(g *grant) time.Time {
	if g.UsedAt.After(g.CreatedAt) {
		return g.UsedAt
	}
	return g.CreatedAt
}

// ago describes t relative to now, e.g. "5m ago".
func ago(now, t time.Time) string {
	switch d := now.Sub(t); {
	case t.IsZero():
		return "never used"
	case d < usedResolution:
		return "used just now"
	case d < time.Hour:
		return fmt.Sprintf("used %dm ago", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("used %dh ago", int(d/time.Hour))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("used %dd ago", int(d/(24*time.Hour)))
	default:
		return "used " + t.UTC().Format("Jan 2, 2006")
	}
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// revokeGrantLocked deletes a grant, which also invalidates its access
// tokens. s.mu must be held.
func (s *Server) revokeGrantLocked(id GrantID) error {
	delete(s.st.Grants, id)
	return s.saveLocked()
}
