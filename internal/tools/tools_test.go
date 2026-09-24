package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/broady/exedev-mcp/internal/access"
	"github.com/broady/exedev-mcp/internal/exe"
)

// fakeExe emulates POST /exec. "ssh <vm> '<cmd>'" runs cmd with the local
// bash in a temp home directory, standing in for the VM; lobby commands are
// recorded and answered from a table.
type fakeExe struct {
	home string

	mu       sync.Mutex
	lobby    []string
	requests int
	maxBody  int
}

func newFakeExe(t *testing.T) (*fakeExe, *mcp.ClientSession) {
	t.Helper()
	return newFakeExeWith(t, Options{})
}

func newFakeExeWith(t *testing.T, opts Options) (*fakeExe, *mcp.ClientSession) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	f := &fakeExe{home: t.TempDir()}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := exe.New(exe.Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(c, "test", opts)
	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return f, cs
}

func (f *fakeExe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	body := string(b)
	f.mu.Lock()
	f.requests++
	f.maxBody = max(f.maxBody, len(body))
	f.mu.Unlock()

	if rest, ok := strings.CutPrefix(body, "ssh "); ok {
		vm, quoted, _ := strings.Cut(rest, " ")
		if vm != "testvm" {
			w.WriteHeader(422)
			fmt.Fprintf(w, `{"error":"VM %q not found"}`, vm)
			return
		}
		cmd := strings.TrimSuffix(strings.TrimPrefix(quoted, "'"), "'")
		c := exec.CommandContext(r.Context(), "bash", "-c", cmd)
		c.Dir = f.home
		c.Env = []string{"HOME=" + f.home, "PATH=" + os.Getenv("PATH")}
		w.Header().Set("Trailer", "X-Exe-Exit")
		c.Stdout, c.Stderr = w, w
		err := c.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		w.Header().Set("X-Exe-Exit", fmt.Sprint(code))
		return
	}

	f.mu.Lock()
	f.lobby = append(f.lobby, body)
	f.mu.Unlock()
	switch {
	case body == "ls":
		io.WriteString(w, `{"vms":[{"vm_name":"testvm","status":"running","https_url":"https://testvm.exe.xyz","ssh_dest":"testvm.exe.xyz","tags":["a"],"allocated_cpus":2},{"vm_name":"other","tags":["b"]},{"vm_name":"host","tags":["a"]}],"shared_vms":[{"vm_name":"theirs","status":"running","owner_email":"x@y.z"}]}`)
	case strings.HasPrefix(body, "new"), strings.HasPrefix(body, "rm "), strings.HasPrefix(body, "share "):
		io.WriteString(w, `{"ok":true}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"unknown command"}`)
	}
}

func (f *fakeExe) lastLobby() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lobby) == 0 {
		return ""
	}
	return f.lobby[len(f.lobby)-1]
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func TestListVMs(t *testing.T) {
	_, cs := newFakeExe(t)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_vms"})
	if err != nil || res.IsError {
		t.Fatalf("list_vms: %v %v", err, res)
	}
	var out listVMsOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.VMs) != 3 || out.VMs[0].Name != "testvm" || out.VMs[0].CPUs != 2 || out.VMs[0].URL != "https://testvm.exe.xyz" {
		t.Errorf("vms = %+v", out.VMs)
	}
	if len(out.Shared) != 1 || out.Shared[0].Owner != "x@y.z" {
		t.Errorf("shared = %+v", out.Shared)
	}
}

func TestCreateVMQuotesArgs(t *testing.T) {
	f, cs := newFakeExe(t)
	_, isErr := call(t, cs, "create_vm", map[string]any{
		"name": "new-vm", "cpus": 4, "tags": []string{"a", "b"}, "prompt": "build it's app; rm -rf /",
	})
	if isErr {
		t.Fatal("create_vm failed")
	}
	want := `new --name=new-vm --cpu=4 --tag=a,b '--prompt=build it'\''s app; rm -rf /'`
	if got := f.lastLobby(); got != want {
		t.Errorf("lobby command\n got %s\nwant %s", got, want)
	}
	if _, isErr := call(t, cs, "create_vm", map[string]any{"name": "Bad Name!"}); !isErr {
		t.Error("invalid name: want error")
	}
}

func TestExeCommand(t *testing.T) {
	f, cs := newFakeExe(t)
	out, isErr := call(t, cs, "exe_command", map[string]any{"command": "ssh exe.dev rm testvm"})
	if isErr || out != `{"ok":true}` || f.lastLobby() != "rm testvm" {
		t.Errorf("got %q (err=%v), lobby %q", out, isErr, f.lastLobby())
	}
	if out, isErr := call(t, cs, "exe_command", map[string]any{"command": "bogus"}); !isErr || !strings.Contains(out, "unknown command") {
		t.Errorf("unknown command: %q %v", out, isErr)
	}
	if call(t, cs, "exe_command", map[string]any{"command": "help share"}); f.lastLobby() != "help share" {
		t.Errorf("help share: lobby %q, want it passed through", f.lastLobby())
	}
	// Refused before reaching the lobby: commands other tools own, and any
	// spelling of a command name the lobby might lex differently.
	for _, cmd := range []string{
		"ssh testvm ls", "ssh", "share set-public testvm", "ssh exe.dev share add testvm a@b.c",
		"'share' set-public testvm", `sh""are set-public testvm`, `\share set-public testvm`, "SHARE set-public testvm", "--json share show testvm",
	} {
		f.mu.Lock()
		f.lobby = nil
		f.mu.Unlock()
		if _, isErr := call(t, cs, "exe_command", map[string]any{"command": cmd}); !isErr || f.lastLobby() != "" {
			t.Errorf("exe_command %q: want refused without a lobby call", cmd)
		}
	}
}

func TestRunCommand(t *testing.T) {
	f, cs := newFakeExe(t)
	os.Mkdir(filepath.Join(f.home, "sub dir"), 0o755)
	out, isErr := call(t, cs, "run_command", map[string]any{
		"vm": "testvm", "cwd": "sub dir", "command": "pwd\necho \"it's\" 'quoted' $((6*7)) >&2\nexit 3",
	})
	if isErr {
		t.Fatalf("run_command: %s", out)
	}
	for _, want := range []string{"/sub dir\n", "it's quoted 42\n", "[exit status 3]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
	out, _ = call(t, cs, "run_command", map[string]any{"vm": "testvm", "command": "sleep 5", "timeout_seconds": 1})
	if !strings.Contains(out, "timed out after 1s") {
		t.Errorf("timeout output: %q", out)
	}
	if out, isErr := call(t, cs, "run_command", map[string]any{"vm": "nope", "command": "true"}); !isErr || !strings.Contains(out, "not found") {
		t.Errorf("unknown VM: %q %v", out, isErr)
	}
	if _, isErr := call(t, cs, "run_command", map[string]any{"vm": "testvm", "command": "true", "timeout_seconds": 9999}); !isErr {
		t.Error("excessive timeout: want error")
	}
}

func TestWriteReadEditFile(t *testing.T) {
	f, cs := newFakeExe(t)
	path := "dir/-odd name's.txt"
	content := "line one\nline two\n"
	if out, isErr := call(t, cs, "write_file", map[string]any{"vm": "testvm", "path": path, "content": content}); isErr {
		t.Fatalf("write_file: %s", out)
	}
	got, _ := os.ReadFile(filepath.Join(f.home, path))
	if string(got) != content {
		t.Fatalf("file = %q", got)
	}

	out, isErr := call(t, cs, "read_file", map[string]any{"vm": "testvm", "path": path})
	if isErr || out != "     1\tline one\n     2\tline two\n" {
		t.Errorf("read_file = %q (err=%v)", out, isErr)
	}
	out, _ = call(t, cs, "read_file", map[string]any{"vm": "testvm", "path": path, "offset": 2, "limit": 1})
	if !strings.HasPrefix(out, "     2\tline two\n") {
		t.Errorf("read_file offset = %q", out)
	}
	if _, isErr := call(t, cs, "read_file", map[string]any{"vm": "testvm", "path": "missing"}); !isErr {
		t.Error("missing file: want error")
	}

	os.Chmod(filepath.Join(f.home, path), 0o751)
	if out, isErr := call(t, cs, "edit_file", map[string]any{"vm": "testvm", "path": path, "old_string": "two", "new_string": "2"}); isErr {
		t.Fatalf("edit_file: %s", out)
	}
	got, _ = os.ReadFile(filepath.Join(f.home, path))
	if string(got) != "line one\nline 2\n" {
		t.Errorf("after edit = %q", got)
	}
	if fi, _ := os.Stat(filepath.Join(f.home, path)); fi.Mode().Perm() != 0o751 {
		t.Errorf("mode = %v, want preserved 0751", fi.Mode().Perm())
	}
	if out, isErr := call(t, cs, "edit_file", map[string]any{"vm": "testvm", "path": path, "old_string": "line", "new_string": "L"}); !isErr || !strings.Contains(out, "2 times") {
		t.Errorf("ambiguous edit: %q %v", out, isErr)
	}
	if _, isErr := call(t, cs, "edit_file", map[string]any{"vm": "testvm", "path": path, "old_string": "line", "new_string": "L", "replace_all": true}); isErr {
		t.Error("replace_all failed")
	}
	got, _ = os.ReadFile(filepath.Join(f.home, path))
	if string(got) != "L one\nL 2\n" {
		t.Errorf("after replace_all = %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(f.home, "dir"))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestWriteFileLargeIsChunked(t *testing.T) {
	f, cs := newFakeExe(t)
	var b strings.Builder
	for i := range 20000 {
		fmt.Fprintf(&b, "line %d %s\n", i, strings.Repeat("x", i%50))
	}
	content := b.String() // ~800KiB: many chunks
	if out, isErr := call(t, cs, "write_file", map[string]any{"vm": "testvm", "path": "big.txt", "content": content}); isErr {
		t.Fatalf("write_file: %s", out)
	}
	got, _ := os.ReadFile(filepath.Join(f.home, "big.txt"))
	if string(got) != content {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(content))
	}
	if f.maxBody > 64<<10 {
		t.Errorf("request body %d exceeds the API's 64KiB limit", f.maxBody)
	}
	if f.requests < 10 {
		t.Errorf("only %d requests; expected chunking", f.requests)
	}
	if _, isErr := call(t, cs, "write_file", map[string]any{"vm": "testvm", "path": "empty", "content": ""}); isErr {
		t.Error("empty write failed")
	}
	if fi, err := os.Stat(filepath.Join(f.home, "empty")); err != nil || fi.Size() != 0 {
		t.Errorf("empty file: %v %v", fi, err)
	}
}

func fixedPolicy(p access.Policy) func(*mcp.CallToolRequest) (access.Policy, error) {
	return func(*mcp.CallToolRequest) (access.Policy, error) { return p, nil }
}

func listedVMs(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_vms"})
	if err != nil || res.IsError {
		t.Fatalf("list_vms: %v %v", err, res)
	}
	var out listVMsOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(out.VMs)+len(out.Shared))
	for _, v := range append(out.VMs, out.Shared...) {
		names = append(names, v.Name)
	}
	return names
}

func TestPolicyByName(t *testing.T) {
	_, cs := newFakeExeWith(t, Options{Policy: fixedPolicy(access.Policy{VMs: []string{"testvm"}, Ops: []access.Op{access.OpRead, access.OpRun, access.OpRestart}}), HostVM: "host"})
	if out, isErr := call(t, cs, "run_command", map[string]any{"vm": "testvm", "command": "echo hi"}); isErr || !strings.Contains(out, "hi") {
		t.Errorf("allowed VM: %q", out)
	}
	for tool, args := range map[string]map[string]any{
		"run_command": {"vm": "other", "command": "true"},
		"read_file":   {"vm": "other", "path": "x"},
		"restart_vm":  {"vm": "other"},
	} {
		out, isErr := call(t, cs, tool, args)
		if !isErr || !strings.Contains(out, "not allowed to use VM other") {
			t.Errorf("%s on other VM: %v %q", tool, isErr, out)
		}
	}
	if got := strings.Join(listedVMs(t, cs), ","); got != "testvm" {
		t.Errorf("list_vms = %s", got)
	}
	// Account-level tools are offered (Options.Ops is nil) but refuse.
	for tool, args := range map[string]map[string]any{
		"create_vm":   {},
		"delete_vm":   {"vm": "testvm"},
		"exe_command": {"command": "ls"},
	} {
		out, isErr := call(t, cs, tool, args)
		if !isErr || !strings.Contains(out, "not allowed to manage") {
			t.Errorf("%s: %v %q", tool, isErr, out)
		}
	}
}

func TestPolicyByTagExcludesHost(t *testing.T) {
	_, cs := newFakeExeWith(t, Options{Policy: fixedPolicy(access.Policy{Tags: []string{"a"}, Ops: []access.Op{access.OpRun}}), HostVM: "host"})
	if _, isErr := call(t, cs, "run_command", map[string]any{"vm": "testvm", "command": "true"}); isErr {
		t.Error("tagged VM refused")
	}
	// host carries tag a, but running commands there reaches the API
	// integration: only full access may.
	if out, isErr := call(t, cs, "run_command", map[string]any{"vm": "host", "command": "true"}); !isErr || !strings.Contains(out, "not allowed") {
		t.Errorf("host VM: %v %q", isErr, out)
	}
	if got := strings.Join(listedVMs(t, cs), ","); got != "testvm" {
		t.Errorf("list_vms = %s", got)
	}
}

func TestPolicyFailsClosed(t *testing.T) {
	_, cs := newFakeExeWith(t, Options{Policy: func(*mcp.CallToolRequest) (access.Policy, error) {
		return access.Policy{}, errors.New("no policy")
	}})
	if out, isErr := call(t, cs, "run_command", map[string]any{"vm": "testvm", "command": "true"}); !isErr || !strings.Contains(out, "no policy") {
		t.Errorf("run_command: %v %q", isErr, out)
	}
}

func TestReadOnly(t *testing.T) {
	f, cs := newFakeExeWith(t, Options{Policy: fixedPolicy(access.Policy{AllVMs: true, Ops: []access.Op{access.OpRead}})})
	if err := os.WriteFile(filepath.Join(f.home, "x"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, isErr := call(t, cs, "read_file", map[string]any{"vm": "testvm", "path": "x"}); isErr || !strings.Contains(out, "hello") {
		t.Errorf("read_file: %q", out)
	}
	for tool, args := range map[string]map[string]any{
		"run_command": {"vm": "testvm", "command": "touch y"},
		"write_file":  {"vm": "testvm", "path": "y", "content": "z"},
		"edit_file":   {"vm": "testvm", "path": "x", "old_string": "hello", "new_string": "bye"},
		"restart_vm":  {"vm": "testvm"},
		"delete_vm":   {"vm": "testvm"},
	} {
		if out, isErr := call(t, cs, tool, args); !isErr || !strings.Contains(out, "not allowed to") {
			t.Errorf("%s: %v %q", tool, isErr, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(f.home, "x")); string(b) != "hello\n" {
		t.Errorf("file changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(f.home, "y")); err == nil {
		t.Error("read-only connection created a file")
	}
}

func TestOpsSelectTools(t *testing.T) {
	for _, tc := range []struct {
		ops  []access.Op
		want string
	}{
		{nil, "create_vm,delete_vm,edit_file,exe_command,list_vms,read_file,restart_vm,run_command,share_vm,write_file"},
		{[]access.Op{access.OpShare}, "list_vms,share_vm"},
		{[]access.Op{access.OpExpose}, "list_vms,share_vm"},
		{[]access.Op{}, "list_vms"},
		{[]access.Op{access.OpRead}, "list_vms,read_file"},
		{[]access.Op{access.OpWrite, access.OpRun}, "edit_file,list_vms,run_command,write_file"},
	} {
		_, cs := newFakeExeWith(t, Options{Ops: tc.ops})
		res, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(res.Tools))
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		slices.Sort(names)
		if got := strings.Join(names, ","); got != tc.want {
			t.Errorf("ops %v: tools = %s, want %s", tc.ops, got, tc.want)
		}
	}
}

func TestFullAccessSeesHost(t *testing.T) {
	_, cs := newFakeExeWith(t, Options{Policy: fixedPolicy(access.Full()), HostVM: "host"})
	if got := strings.Join(listedVMs(t, cs), ","); got != "testvm,other,host,theirs" {
		t.Errorf("list_vms = %s", got)
	}
}

func TestShareVM(t *testing.T) {
	share := []access.Op{access.OpShare}
	expose := []access.Op{access.OpExpose}
	for _, tc := range []struct {
		name string
		ops  []access.Op
		args map[string]any
		want string // lobby command, or "" for refused
	}{
		{"show", share, map[string]any{"action": "show"}, "share show testvm"},
		{"add web", share, map[string]any{"action": "add", "who": "a@b.c", "message": "it's up"}, `share add testvm a@b.c '--message=it'\''s up'`},
		{"add team", share, map[string]any{"action": "add", "who": "team"}, "share add testvm team"},
		{"add shell needs expose", share, map[string]any{"action": "add", "who": "a@b.c", "shell": true}, ""},
		{"add shell", expose, map[string]any{"action": "add", "who": "a@b.c", "shell": true}, "share add testvm a@b.c --root"},
		{"remove shell", share, map[string]any{"action": "remove", "who": "a@b.c", "shell": true}, "share remove testvm a@b.c --root"},
		{"who is not a flag", expose, map[string]any{"action": "add", "who": "--root"}, ""},
		{"who is one word", expose, map[string]any{"action": "add", "who": "a@b.c --root"}, ""},
		{"who required", share, map[string]any{"action": "remove"}, ""},
		{"message only on add", share, map[string]any{"action": "remove", "who": "a@b.c", "message": "x"}, ""},
		{"set-private", share, map[string]any{"action": "set-private"}, "share set-private testvm"},
		{"set-public needs expose", share, map[string]any{"action": "set-public"}, ""},
		{"set-public", expose, map[string]any{"action": "set-public"}, "share set-public testvm"},
		{"add-link needs expose", share, map[string]any{"action": "add-link"}, ""},
		{"remove-link", share, map[string]any{"action": "remove-link", "link": "abc_123"}, "share remove-link testvm abc_123"},
		{"remove-link validates", share, map[string]any{"action": "remove-link", "link": "-x"}, ""},
		{"show port", share, map[string]any{"action": "port"}, "share port testvm"},
		{"set port needs expose", share, map[string]any{"action": "port", "port": 8080}, ""},
		{"set port", expose, map[string]any{"action": "port", "port": 8080}, "share port testvm 8080"},
		{"bad port", expose, map[string]any{"action": "port", "port": 70000}, ""},
		{"email on needs expose", share, map[string]any{"action": "receive-email", "enabled": true}, ""},
		{"email off", share, map[string]any{"action": "receive-email", "enabled": false}, "share receive-email testvm off"},
		{"email on", expose, map[string]any{"action": "receive-email", "enabled": true}, "share receive-email testvm on"},
		{"unknown action", expose, map[string]any{"action": "domain"}, ""},
		{"no share op", []access.Op{access.OpRun}, map[string]any{"action": "show"}, ""},
	} {
		f, cs := newFakeExeWith(t, Options{Policy: fixedPolicy(access.Policy{VMs: []string{"testvm"}, Ops: tc.ops})})
		tc.args["vm"] = "testvm"
		_, isErr := call(t, cs, "share_vm", tc.args)
		if got := f.lastLobby(); got != tc.want || isErr != (tc.want == "") {
			t.Errorf("%s: lobby %q (err=%v), want %q", tc.name, got, isErr, tc.want)
		}
	}
}

func TestShareVMHost(t *testing.T) {
	f, cs := newFakeExeWith(t, Options{Policy: fixedPolicy(access.Full()), HostVM: "host"})
	if _, isErr := call(t, cs, "share_vm", map[string]any{"vm": "host", "action": "set-private"}); !isErr || f.lastLobby() != "" {
		t.Errorf("set-private on host: err=%v, lobby %q", isErr, f.lastLobby())
	}
	if _, isErr := call(t, cs, "share_vm", map[string]any{"vm": "host", "action": "show"}); isErr || f.lastLobby() != "share show host" {
		t.Errorf("show on host: err=%v, lobby %q", isErr, f.lastLobby())
	}
	_, cs = newFakeExeWith(t, Options{Policy: fixedPolicy(access.Policy{Tags: []string{"a"}, Ops: []access.Op{access.OpShare}}), HostVM: "host"})
	if _, isErr := call(t, cs, "share_vm", map[string]any{"vm": "host", "action": "show"}); !isErr {
		t.Error("show on host by tag: want refused")
	}
}
