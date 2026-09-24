package oauth

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/broady/exedev-mcp/internal/access"
)

type consentPage struct {
	RequestID    string
	ClientName   string
	ClientHost   string // metadata document host; empty for registered clients
	Trusted      bool
	RedirectHost string
	Native       bool // redirect goes to an app on this device
	Email        string

	// Limitable is set when VMs could be listed, so access can be limited
	// to some of them.
	Limitable bool
	Scope     string // "all", "vms" or "tags"
	VMs       []vmChoice
	Tags      []tagChoice
	HostVM    string
	Ops       []opChoice
	Error     string // why the last submission was rejected
}

type vmChoice struct {
	Name    string
	Tags    []string
	Checked bool
}

type tagChoice struct {
	Name    string
	Checked bool
}

type opChoice struct {
	Op      access.Op
	Label   string
	Checked bool
}

var opLabels = map[access.Op]string{
	access.OpRead:    "read files",
	access.OpWrite:   "write files",
	access.OpRun:     "run commands",
	access.OpRestart: "restart",
	access.OpManage:  "create & delete VMs",
}

type grantRow struct {
	ID           string
	Client       string
	RedirectHost string
	Access       string
	Used         string // e.g. "used 5m ago"
	sortKey      time.Time
}

type dashboardPage struct {
	Email          string
	Resource       string // MCP URL to add as a connector
	AccountChecked bool
	Account        string // exe.dev account the API integration acts as
	AccountErr     string
	Grants         []grantRow
}

// AccountMismatch reports an API integration holding someone else's token.
func (d dashboardPage) AccountMismatch() bool {
	return d.Account != "" && !strings.EqualFold(d.Account, d.Email)
}

type messagePage struct {
	Title   string
	Message string
}

func errorPage(title, msg string) messagePage { return messagePage{Title: title, Message: msg} }

var pages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.}} · exe.dev MCP</title>
<style>
:root {
  --bg:#f8fafc; --card:#fff; --fg:#334155; --strong:#0f172a; --muted:#64748b; --soft:#94a3b8; --line:#e2e8f0; --sunk:#f1f5f9;
  --accent:#0f172a; --accent-fg:#f8fafc; --ok:#15803d; --warn:#b45309; --warn-bg:#fffbeb; --warn-line:#fde68a;
}
@media (prefers-color-scheme: dark) { :root {
  --bg:#020617; --card:#0f172a; --fg:#cbd5e1; --strong:#f8fafc; --muted:#94a3b8; --soft:#64748b; --line:#1e293b; --sunk:#1e293b;
  --accent:#f8fafc; --accent-fg:#0f172a; --ok:#4ade80; --warn:#fbbf24; --warn-bg:#1c1403; --warn-line:#713f12;
} }
* { box-sizing:border-box }
body { margin:0; min-height:100vh; background:var(--bg); color:var(--fg); font:14px/1.6 ui-monospace,"JetBrains Mono","SF Mono",SFMono-Regular,Menlo,Consolas,monospace; }
main { max-width:30rem; margin:0 auto; padding:10vh 16px 32px; }
.brand { margin:0 0 12px; color:var(--muted); font-size:13px; } .brand b { color:var(--strong); }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:24px; }
.card + .card { margin-top:12px; }
h1 { margin:0; font-size:18px; line-height:1.4; font-weight:600; color:var(--strong); }
h2 { margin:0 0 12px; font-size:14px; font-weight:600; color:var(--strong); }
p { margin:6px 0 0; color:var(--muted); }
.sub { margin-top:2px; color:var(--muted); font-size:13px; }
.badge { display:inline-block; margin-left:6px; padding:0 6px; border:1px solid var(--line); border-radius:4px; font-size:12px; color:var(--muted); }
.badge.ok { color:var(--ok); border-color:currentColor; }
.warn { margin:16px 0 0; padding:8px 12px; border:1px solid var(--warn-line); background:var(--warn-bg); color:var(--warn); border-radius:6px; font-size:13px; }
.rows { margin:20px 0 0; border-top:1px solid var(--line); }
.row { display:grid; grid-template-columns:5.5rem 1fr; gap:12px; align-items:start; padding:12px 0; border-bottom:1px solid var(--line); }
.k { color:var(--muted); padding-top:3px; }
@media (max-width:480px) { .card { padding:20px 16px; } .row { grid-template-columns:1fr; gap:4px; } .k { padding-top:0; font-size:13px; } }
.v { min-width:0; overflow-wrap:anywhere; color:var(--strong); padding-top:3px; }
.seg { display:inline-flex; border:1px solid var(--line); border-radius:6px; overflow:hidden; }
.seg input, .chip input { position:absolute; opacity:0; pointer-events:none; }
.seg label { padding:2px 12px; cursor:pointer; color:var(--muted); }
.seg label + input + label { border-left:1px solid var(--line); }
.seg input:checked + label { background:var(--accent); color:var(--accent-fg); }
.seg input:focus-visible + label, .chip:has(input:focus-visible) { outline:2px solid var(--strong); outline-offset:-2px; }
.panel { display:none; margin-top:10px; }
form:has(#scope-vms:checked) .p-vms, form:has(#scope-tags:checked) .p-tags { display:block; }
form:not(:has(#scope-all:checked)) .op-manage { display:none; }
.list { display:flex; flex-direction:column; max-height:13rem; overflow:auto; border:1px solid var(--line); border-radius:6px; padding:4px 0; }
.list label { display:flex; align-items:center; gap:8px; padding:2px 10px; cursor:pointer; }
.list label:hover { background:var(--sunk); }
.list input { margin:0; accent-color:var(--accent); }
.row > * { min-width:0; }
.list .n { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.list .t { flex:1 1 0; min-width:0; color:var(--soft); font-size:12px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.list label.off { cursor:default; color:var(--soft); } .list label.off:hover { background:none; }
.chips { display:flex; flex-wrap:wrap; gap:6px; }
.chip { position:relative; padding:1px 10px; border:1px solid var(--line); border-radius:6px; cursor:pointer; color:var(--soft); }
.chip::before { content:"\2212  "; }
.chip:has(input:checked) { color:var(--strong); border-color:var(--strong); }
.chip:has(input:checked)::before { content:"+ "; }
.err { margin:0 0 16px; padding:8px 12px; border:1px solid var(--warn-line); background:var(--warn-bg); color:var(--warn); border-radius:6px; }
.actions { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:20px; }
button { font:inherit; padding:8px 14px; border-radius:6px; border:1px solid var(--line); background:var(--card); color:var(--strong); cursor:pointer; }
button:hover { border-color:var(--soft); }
button.primary { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
button.primary:hover { opacity:.85; }
button.small { padding:2px 10px; font-size:13px; }
button:focus-visible { outline:2px solid var(--strong); outline-offset:2px; }
code { display:block; margin:6px 0 0; padding:8px 10px; background:var(--sunk); border-radius:6px; color:var(--strong); overflow-wrap:anywhere; user-select:all; font:inherit; font-size:13px; }
.label { margin:14px 0 0; color:var(--muted); font-size:13px; } .label:first-of-type { margin-top:0; }
.status { margin-top:16px; font-size:13px; color:var(--muted); } .status b { color:var(--strong); font-weight:normal; }
.status .ok { color:var(--ok); } .status.bad { color:var(--warn); }
ul.grants { list-style:none; margin:0; padding:0; }
ul.grants li { display:flex; align-items:center; gap:12px; padding:10px 0; }
ul.grants li + li { border-top:1px solid var(--line); }
.grow { flex:1; min-width:0; } .grow b { display:block; font-weight:normal; color:var(--strong); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.grow small { color:var(--muted); font-size:12px; }
.empty { color:var(--soft); }
.foot { margin:12px 0 0; font-size:12px; color:var(--soft); }
</style></head><body><main>
<div class="brand"><b>exe.dev</b> mcp</div>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "consent"}}{{template "head" "Authorize"}}
<div class="card">
<h1>{{.ClientName}}</h1>
<div class="sub">wants access to your exe.dev account{{if .Trusted}}<span class="badge ok">verified</span>{{else}}<span class="badge">not verified</span>{{end}}</div>
{{if or (not .Trusted) .Native}}<div class="warn">{{if .Native}}Returns to an app on this computer. {{end}}Only allow if you started this.</div>{{end}}
<form method="post" action="/oauth/authorize">
<input type="hidden" name="request_id" value="{{.RequestID}}">
<div class="rows">
{{if .Error}}<div class="err" style="margin:12px 0 0">{{.Error}}</div>{{end}}
<div class="row"><span class="k">vms</span><div>
  {{if .Limitable}}<div class="seg" role="radiogroup">
    <input type="radio" name="scope" value="all" id="scope-all"{{if eq .Scope "all"}} checked{{end}}><label for="scope-all">all</label>
    <input type="radio" name="scope" value="vms" id="scope-vms"{{if eq .Scope "vms"}} checked{{end}}><label for="scope-vms">pick</label>
    {{if .Tags}}<input type="radio" name="scope" value="tags" id="scope-tags"{{if eq .Scope "tags"}} checked{{end}}><label for="scope-tags">by tag</label>{{end}}
  </div>
  <div class="panel p-vms"><div class="list">
    {{range .VMs}}<label><input type="checkbox" name="vm" value="{{.Name}}"{{if .Checked}} checked{{end}}><span class="n">{{.Name}}</span>{{if .Tags}}<span class="t">{{range $i, $t := .Tags}}{{if $i}} {{end}}#{{$t}}{{end}}</span>{{end}}</label>{{end}}
    {{if .HostVM}}<label class="off"><input type="checkbox" disabled><span class="n">{{.HostVM}}</span><span class="t">this server</span></label>{{end}}
  </div></div>
  {{if .Tags}}<div class="panel p-tags"><div class="list">
    {{range .Tags}}<label><input type="checkbox" name="tag" value="{{.Name}}"{{if .Checked}} checked{{end}}><span class="n">#{{.Name}}</span></label>{{end}}
  </div></div>{{end}}
  {{else}}<input type="hidden" name="scope" value="all" id="scope-all" checked><span class="v">all</span>{{end}}
</div></div>
<div class="row"><span class="k">allow</span><div class="chips">
  {{range .Ops}}<label class="chip op-{{.Op}}"><input type="checkbox" name="op" value="{{.Op}}"{{if .Checked}} checked{{end}}>{{.Label}}</label>{{end}}
</div></div>
<div class="row"><span class="k">account</span><span class="v">{{.Email}}</span></div>
<div class="row"><span class="k">returns to</span><span class="v">{{.RedirectHost}}</span></div>
</div>
<div class="actions"><button name="action" value="deny">Deny</button><button class="primary" name="action" value="approve">Allow</button></div>
</form>
</div>
{{template "foot"}}{{end}}

{{define "dashboard"}}{{template "head" "Dashboard"}}
<div class="card">
<p class="label">connector url</p>
<code>{{.Resource}}</code>
<p class="label">claude code</p>
<code>claude mcp add --transport http exe {{.Resource}}</code>
{{if .AccountChecked}}<div class="status{{if or .AccountErr .AccountMismatch}} bad{{end}}">
  {{- if .AccountErr}}exe.dev API unreachable: {{.AccountErr}}. Check the http-proxy integration.
  {{- else if .AccountMismatch}}exe.dev API acts as <b>{{.Account}}</b>, not you. The integration holds someone else's token.
  {{- else}}<span class="ok">&#10003;</span> exe.dev API connected as <b>{{.Account}}</b>{{end -}}
</div>{{end}}
</div>
<div class="card">
<h2>Connections</h2>
{{if .Grants}}<ul class="grants">
{{range .Grants}}<li>
  <div class="grow"><b>{{.Client}}</b><small>{{.Access}} · {{.RedirectHost}} · {{.Used}}</small></div>
  <form method="post" action="/oauth/grants/revoke"><input type="hidden" name="grant_id" value="{{.ID}}"><button class="small">revoke</button></form>
</li>
{{end}}</ul>{{else}}<p class="empty">none</p>{{end}}
</div>
<p class="foot">{{.Email}}</p>
{{template "foot"}}{{end}}

{{define "message"}}{{template "head" .Title}}
<div class="card"><h1>{{.Title}}</h1><p>{{.Message}}</p></div>
{{template "foot"}}{{end}}
`))

// page renders an HTML page with headers that stop it being framed
// (clickjacking the Allow button) or leaking the URL via Referer.
func (s *Server) page(w http.ResponseWriter, status int, data any) {
	var name string
	switch data.(type) {
	case consentPage:
		name = "consent"
	case dashboardPage:
		name = "dashboard"
	case messagePage:
		name = "message"
	default:
		panic("oauth: unknown page type") // programmer error
	}
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("oauth: render page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
