package oauth

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"time"
)

type consentPage struct {
	RequestID    string
	ClientName   string
	ClientHost   string // metadata document host; empty for registered clients
	Trusted      bool
	RedirectHost string
	Native       bool // redirect goes to an app on this device
	Email        string
	Server       string
}

type grantRow struct {
	ID           string
	Client       string
	RedirectHost string
	Created      time.Time
	LastUsed     time.Time
}

type grantsPage struct {
	Email  string
	Grants []grantRow
}

type messagePage struct {
	Title   string
	Message string
}

func errorPage(title, msg string) messagePage { return messagePage{Title: title, Message: msg} }

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"date": func(t time.Time) string { return t.UTC().Format("Jan 2") },
	"initial": func(name string) string {
		for _, r := range name {
			return strings.ToUpper(string(r))
		}
		return "?"
	},
}).Parse(`
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.}} · exe.dev MCP</title>
<style>
:root {
  --bg:#f5f5f4; --fg:#1c1917; --muted:#78716c; --soft:#a8a29e; --card:#fff; --line:#e7e5e4; --sunk:#fafaf9;
  --accent:#1c1917; --accent-fg:#fafaf9; --accent-hover:#44403c;
  --warn-bg:#fffbeb; --warn-line:#fde68a; --warn-fg:#92400e;
  --ok-bg:#f0fdf4; --ok-fg:#15803d; --no-bg:#f5f5f4; --no-fg:#57534e;
  --shadow:0 1px 2px rgb(28 25 23 / .04), 0 8px 24px -8px rgb(28 25 23 / .12);
}
@media (prefers-color-scheme: dark) { :root {
  --bg:#0c0a09; --fg:#f5f5f4; --muted:#a8a29e; --soft:#78716c; --card:#1c1917; --line:#292524; --sunk:#171412;
  --accent:#f5f5f4; --accent-fg:#1c1917; --accent-hover:#d6d3d1;
  --warn-bg:#2a1a05; --warn-line:#78350f; --warn-fg:#fcd34d;
  --ok-bg:#052e16; --ok-fg:#86efac; --no-bg:#292524; --no-fg:#d6d3d1;
  --shadow:none;
} }
* { box-sizing:border-box }
body { margin:0; min-height:100vh; background:var(--bg); color:var(--fg); font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; -webkit-font-smoothing:antialiased; }
main { max-width:26rem; margin:0 auto; padding:10vh 16px 32px; }
.brand { display:flex; align-items:center; gap:8px; margin:0 0 16px 4px; font-size:.8125rem; color:var(--muted); }
.brand b { color:var(--fg); font-weight:600; letter-spacing:-.01em; }
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:28px; box-shadow:var(--shadow); }
.app { display:flex; align-items:center; gap:14px; margin-bottom:20px; }
.avatar { flex:none; width:44px; height:44px; border-radius:12px; display:grid; place-items:center; background:var(--accent); color:var(--accent-fg); font-weight:600; font-size:1.125rem; }
.avatar.sm { width:32px; height:32px; border-radius:9px; font-size:.875rem; }
h1 { font-size:1.1875rem; line-height:1.35; letter-spacing:-.015em; margin:0; font-weight:600; }
.sub { display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-top:4px; font-size:.8125rem; color:var(--muted); }
.pill { display:inline-flex; align-items:center; gap:3px; padding:1px 7px 1px 5px; border-radius:99px; font-size:.75rem; font-weight:500; }
.pill.ok { background:var(--ok-bg); color:var(--ok-fg); } .pill.no { background:var(--no-bg); color:var(--no-fg); padding-left:7px; }
.pill svg { width:12px; height:12px; }
.label { margin:0 0 8px; font-size:.8125rem; color:var(--muted); }
ul.perms { list-style:none; margin:0 0 20px; padding:0; border:1px solid var(--line); border-radius:12px; }
ul.perms li { display:flex; align-items:center; gap:12px; padding:11px 14px; font-size:.9375rem; }
ul.perms li + li { border-top:1px solid var(--line); }
ul.perms svg { flex:none; width:18px; height:18px; color:var(--muted); }
dl { display:grid; grid-template-columns:auto 1fr; gap:6px 16px; margin:0; padding:12px 14px; background:var(--sunk); border-radius:10px; font-size:.8125rem; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; text-align:right; font-weight:500; }
.warn { display:flex; gap:10px; margin:16px 0 0; padding:10px 12px; border:1px solid var(--warn-line); background:var(--warn-bg); color:var(--warn-fg); border-radius:10px; font-size:.8125rem; }
.warn svg { flex:none; width:16px; height:16px; margin-top:2px; }
.actions { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:24px; }
button { font:inherit; font-weight:500; padding:10px 16px; border-radius:10px; border:1px solid var(--line); background:var(--card); color:var(--fg); cursor:pointer; transition:background .12s, border-color .12s; }
button:hover { background:var(--sunk); border-color:var(--soft); }
button.primary { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
button.primary:hover { background:var(--accent-hover); border-color:var(--accent-hover); }
button.small { padding:5px 12px; font-size:.8125rem; }
button:focus-visible { outline:2px solid var(--fg); outline-offset:2px; }
p { margin:8px 0 0; color:var(--muted); }
.foot { margin:16px 4px 0; font-size:.8125rem; color:var(--muted); text-align:center; }
.foot a { color:inherit; }
ul.grants { list-style:none; margin:16px 0 0; padding:0; }
ul.grants li { display:flex; align-items:center; gap:12px; padding:12px 0; }
ul.grants li + li { border-top:1px solid var(--line); }
.grow { flex:1; min-width:0; } .grow b { display:block; font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; } .grow small { color:var(--muted); font-size:.8125rem; }
.empty { margin:16px 0 0; padding:24px; text-align:center; border:1px dashed var(--line); border-radius:12px; color:var(--muted); font-size:.875rem; }
</style></head><body><main>
<div class="brand"><b>exe.dev</b> MCP</div>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "icon-check"}}<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 8.5 2.5 2.5L12 5.5"/></svg>{{end}}
{{define "icon-alert"}}<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 1.75 15 14H1z"/><path d="M8 6.5v3M8 11.75v.01"/></svg>{{end}}

{{define "consent"}}{{template "head" "Authorize"}}
<div class="card">
<div class="app">
  <div class="avatar" aria-hidden="true">{{initial .ClientName}}</div>
  <div>
    <h1>{{.ClientName}} wants access to your exe.dev account</h1>
    <div class="sub">{{if .ClientHost}}{{.ClientHost}}{{else}}self-registered{{end}}
    {{if .Trusted}}<span class="pill ok">{{template "icon-check"}}verified</span>{{else}}<span class="pill no">not verified</span>{{end}}</div>
  </div>
</div>
<p class="label">This will allow {{.ClientName}} to:</p>
<ul class="perms">
  <li><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.5" y="3.5" width="15" height="13" rx="2"/><path d="m6 8 2.5 2L6 12M10.5 12.5H14"/></svg>Run commands on your VMs</li>
  <li><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11.5 2.5H5.5a1.5 1.5 0 0 0-1.5 1.5v12a1.5 1.5 0 0 0 1.5 1.5h9a1.5 1.5 0 0 0 1.5-1.5V7z"/><path d="M11.5 2.5V7H16M7.5 11h5M7.5 14h3"/></svg>Read and write files</li>
  <li><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.5" y="3" width="15" height="6" rx="1.5"/><rect x="2.5" y="11" width="15" height="6" rx="1.5"/><path d="M6 6h.01M6 14h.01"/></svg>Create and delete VMs</li>
</ul>
<dl>
  <dt>Signed in as</dt><dd>{{.Email}}</dd>
  <dt>Returns to</dt><dd>{{.RedirectHost}}</dd>
  <dt>Server</dt><dd>{{.Server}}</dd>
</dl>
{{if or (not .Trusted) .Native}}<div class="warn">{{template "icon-alert"}}<span>
{{- if not .Trusted}}This application's identity is not verified. {{end}}
{{- if .Native}}Access is delivered to an application on this computer. {{end -}}
Only continue if you just started this connection yourself.</span></div>{{end}}
<form method="post" action="/oauth/authorize">
<input type="hidden" name="request_id" value="{{.RequestID}}">
<div class="actions"><button name="action" value="deny">Deny</button><button class="primary" name="action" value="approve">Allow</button></div>
</form>
</div>
<p class="foot">You can revoke access at any time in <a href="/oauth/grants">connected applications</a>.</p>
{{template "foot"}}{{end}}

{{define "grants"}}{{template "head" "Connected applications"}}
<div class="card">
<h1>Connected applications</h1>
<p>Signed in as {{.Email}}.</p>
{{if .Grants}}<ul class="grants">
{{range .Grants}}<li>
  <div class="avatar sm" aria-hidden="true">{{initial .Client}}</div>
  <div class="grow"><b>{{.Client}}</b><small>{{.RedirectHost}} · last used {{date .LastUsed}}</small></div>
  <form method="post" action="/oauth/grants/revoke"><input type="hidden" name="grant_id" value="{{.ID}}"><button class="small">Revoke</button></form>
</li>
{{end}}</ul>{{else}}<div class="empty">No applications are connected.</div>{{end}}
</div>
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
	case grantsPage:
		name = "grants"
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
