// Package tools exposes exe.dev VMs as MCP tools.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/broady/exedev-mcp/internal/access"
	"github.com/broady/exedev-mcp/internal/exe"
)

const instructions = `Tools for exe.dev: Linux VMs with persistent disks, reachable at https://<vm>.exe.xyz.

Start with list_vms. Use run_command for anything shell-shaped on a VM, and read_file / write_file / edit_file for files. Each run_command is a fresh non-interactive login shell in the home directory (/home/exedev on the default image); state other than the filesystem does not persist between calls. For work longer than 10 minutes, start it in the background (setsid nohup CMD > LOG 2>&1 &) and poll the log.

The default image (exeuntu) is Ubuntu with sudo, Docker, common toolchains, and the Shelley coding agent at https://<vm>.shelley.exe.xyz. A VM's web server on port 8000 is served at https://<vm>.exe.xyz (private to the owner unless shared).`

// Limits. The API caps request bodies at 64KiB and output is returned to a
// model, so everything is bounded.
const (
	lobbyTimeout      = 60 * time.Second
	defaultCmdTimeout = 120
	maxCmdTimeout     = 600
	maxCommandOutput  = 64 << 10
	maxReadOutput     = 256 << 10
	maxEditFileSize   = 2 << 20
	maxWriteFileSize  = 2 << 20
	writeChunkSize    = 24 << 10 // base64'd twice on the wire: ~43KiB
	defaultReadLimit  = 2000
	execTimeoutMargin = 30 * time.Second
)

// Options configure access control. The zero value gives every call full
// access, as in stdio mode where the user runs the server as themselves.
type Options struct {
	// Policy returns the access policy of the connection making a call,
	// checked on every call. Nil means full access.
	Policy func(*mcp.CallToolRequest) (access.Policy, error)
	// Ops selects which tools the server offers; nil offers all. Set it to
	// the connection's allowed operations so clients don't offer tools that
	// would always fail.
	Ops []access.Op
	// HostVM is the VM this server runs on. It holds the API integration,
	// so running commands there is equivalent to full access: policies
	// without AllVMs never allow it.
	HostVM string
}

// NewServer returns an MCP server exposing exe.dev through c.
func NewServer(c *exe.Client, version string, opts Options) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "exe.dev", Title: "exe.dev", Version: version}, &mcp.ServerOptions{
		Instructions: instructions,
	})
	t := &toolset{c: c, policy: opts.Policy, hostVM: opts.HostVM}
	offer := func(op access.Op) bool { return opts.Ops == nil || slices.Contains(opts.Ops, op) }

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_vms",
		Description: "List your exe.dev VMs and VMs shared with you.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
	}, t.listVMs)
	if offer(access.OpRead) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "read_file",
			Description: "Read a text file on a VM, with line numbers. Relative paths are relative to the home directory.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
		}, t.readFile)
	}
	if offer(access.OpWrite) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "write_file",
			Description: "Create or overwrite a file on a VM atomically, creating parent directories. Keeps the mode of an existing file.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(false)},
		}, t.writeFile)
		mcp.AddTool(s, &mcp.Tool{
			Name:        "edit_file",
			Description: "Replace exact text in a file on a VM. old_string must match exactly once unless replace_all is set.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(false)},
		}, t.editFile)
	}
	if offer(access.OpRun) {
		mcp.AddTool(s, &mcp.Tool{
			Name: "run_command",
			Description: "Run a bash command or script on a VM and return its combined stdout/stderr and exit status. " +
				"Runs as the VM's default user in a login shell with no stdin. Output over 64KiB keeps the head and tail.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(true)},
		}, t.runCommand)
	}
	if offer(access.OpRestart) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "restart_vm",
			Description: "Restart an exe.dev VM. Running processes are killed; the disk is kept.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(false)},
		}, t.restartVM)
	}
	if offer(access.OpShare) || offer(access.OpExpose) {
		mcp.AddTool(s, &mcp.Tool{
			Name: "share_vm",
			Description: "Show or change who can reach a VM. show lists its shares; add and remove share its web (https://<vm>.exe.xyz) with a user or team; " +
				"add with shell also grants SSH, terminal and Shelley; add-link creates a link anyone can use; set-public and set-private open or close the web to everyone; " +
				"port sets the proxied port; receive-email turns inbound email on or off.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(true)},
		}, t.shareVM)
	}
	if offer(access.OpManage) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "create_vm",
			Description: "Create a new exe.dev VM. It is ready in seconds. Optionally give an initial task to the Shelley coding agent on the new VM.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(false), OpenWorldHint: new(false)},
		}, t.createVM)
		mcp.AddTool(s, &mcp.Tool{
			Name:        "delete_vm",
			Description: "Permanently delete an exe.dev VM and its disk. This cannot be undone.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(false)},
		}, t.deleteVM)
		mcp.AddTool(s, &mcp.Tool{
			Name: "exe_command",
			Description: "Run any other exe.dev lobby command and return its JSON output, e.g. `tag myvm prod`, `resize myvm --disk=50GB`, `help new`. " +
				"Run `help` to list commands. Which commands are allowed depends on the API token. Use share_vm for sharing and run_command for ssh.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(false)},
		}, t.exeCommand)
	}
	return s
}

type toolset struct {
	c      *exe.Client
	policy func(*mcp.CallToolRequest) (access.Policy, error)
	hostVM string
}

// policyOf returns the calling connection's policy.
func (t *toolset) policyOf(req *mcp.CallToolRequest) (access.Policy, error) {
	if t.policy == nil {
		return access.Full(), nil
	}
	return t.policy(req)
}

// allows reports whether p covers vm, given its tags.
func (t *toolset) allows(p access.Policy, vm access.VM) bool {
	if p.AllVMs {
		return true
	}
	return vm.Name != t.hostVM && p.Allows(vm)
}

// authorize parses vm and checks the caller may do op on it. Tag-based
// policies look up the VM's current tags, so untagging a VM revokes
// access immediately.
func (t *toolset) authorize(ctx context.Context, req *mcp.CallToolRequest, op access.Op, vm string) (exe.VMName, error) {
	name, err := exe.ParseVMName(vm)
	if err != nil {
		return "", err
	}
	p, err := t.policyOf(req)
	if err != nil {
		return "", err
	}
	if !p.Can(op) {
		return "", fmt.Errorf("this connection is not allowed to %s (it allows %s)", op, p)
	}
	target := access.VM{Name: string(name)}
	if p.NeedsTags(target.Name) {
		vms, err := t.ls(ctx)
		if err != nil {
			return "", err
		}
		for _, v := range vms.all() {
			if v.Name == target.Name {
				target.Tags = v.Tags
			}
		}
	}
	if !t.allows(p, target) {
		return "", fmt.Errorf("this connection is not allowed to use VM %s (it allows %s)", name, p)
	}
	return name, nil
}

// lobby runs a lobby command with a bounded deadline.
func (t *toolset) lobby(ctx context.Context, command string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, lobbyTimeout)
	defer cancel()
	return t.c.Lobby(ctx, command)
}

// script runs a bash script on vm. The HTTP deadline trails the on-VM
// timeout so the VM reports the timeout rather than us abandoning it.
func (t *toolset) script(ctx context.Context, vm exe.VMName, script string, opts exe.ScriptOptions, maxOutput int) (exe.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutSeconds)*time.Second+execTimeoutMargin)
	defer cancel()
	return t.c.Exec(ctx, vm, exe.ScriptCommand(script, opts), maxOutput)
}

func textResult(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}}}
}

func jsonResult(raw json.RawMessage) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}
}

// --- list_vms

type listVMsInput struct{}

// VM is a trimmed view of a VM from `ls`.
type VM struct {
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Region      string   `json:"region,omitempty"`
	URL         string   `json:"url"`
	SSH         string   `json:"ssh,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Comment     string   `json:"comment,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	CPUs        int      `json:"cpus,omitempty"`
	MemoryBytes int64    `json:"memory_bytes,omitempty"`
	DiskBytes   int64    `json:"disk_bytes,omitempty"`
	ProxyPort   int      `json:"proxy_port,omitempty"`
	ProxyShare  string   `json:"proxy_share,omitempty"`
}

type listVMsOutput struct {
	VMs    []VM `json:"vms"`
	Shared []VM `json:"shared_with_me,omitempty"`
}

// lsOutput is the part of `ls` output the tools use.
type lsOutput struct {
	VMs    []VM
	Shared []VM
}

func (o lsOutput) all() []VM { return append(slices.Clip(o.VMs), o.Shared...) }

func (t *toolset) ls(ctx context.Context) (lsOutput, error) {
	raw, err := t.lobby(ctx, "ls")
	if err != nil {
		return lsOutput{}, err
	}
	type lsVM struct {
		Name        string   `json:"vm_name"`
		Status      string   `json:"status"`
		Region      string   `json:"region"`
		URL         string   `json:"https_url"`
		SSH         string   `json:"ssh_dest"`
		Tags        []string `json:"tags"`
		Comment     string   `json:"comment"`
		Owner       string   `json:"owner_email"`
		CPUs        int      `json:"allocated_cpus"`
		MemoryBytes int64    `json:"memory_capacity_bytes"`
		DiskBytes   int64    `json:"disk_capacity_bytes"`
		ProxyPort   int      `json:"proxy_port"`
		ProxyShare  string   `json:"proxy_share"`
	}
	var ls struct {
		VMs    []lsVM `json:"vms"`
		Shared []lsVM `json:"shared_vms"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return lsOutput{}, fmt.Errorf("parse ls output: %w", err)
	}
	conv := func(in []lsVM) []VM {
		out := make([]VM, 0, len(in))
		for _, v := range in {
			out = append(out, VM(v))
		}
		return out
	}
	return lsOutput{VMs: conv(ls.VMs), Shared: conv(ls.Shared)}, nil
}

func (t *toolset) listVMs(ctx context.Context, req *mcp.CallToolRequest, _ listVMsInput) (*mcp.CallToolResult, listVMsOutput, error) {
	p, err := t.policyOf(req)
	if err != nil {
		return nil, listVMsOutput{}, err
	}
	ls, err := t.ls(ctx)
	if err != nil {
		return nil, listVMsOutput{}, err
	}
	visible := func(vms []VM) []VM {
		return slices.DeleteFunc(vms, func(v VM) bool { return !t.allows(p, access.VM{Name: v.Name, Tags: v.Tags}) })
	}
	return nil, listVMsOutput{VMs: visible(ls.VMs), Shared: visible(ls.Shared)}, nil
}

// --- create_vm

type createVMInput struct {
	Name    string   `json:"name,omitempty" jsonschema:"VM name (lowercase letters, digits, hyphens); auto-generated if empty"`
	Image   string   `json:"image,omitempty" jsonschema:"container image; defaults to boldsoftware/exeuntu (Ubuntu with dev tools and Shelley)"`
	CPUs    int      `json:"cpus,omitempty" jsonschema:"number of CPUs (default 2)"`
	Memory  string   `json:"memory,omitempty" jsonschema:"memory, e.g. 8GB"`
	Disk    string   `json:"disk,omitempty" jsonschema:"disk size, e.g. 50GB"`
	Tags    []string `json:"tags,omitempty" jsonschema:"tags to add to the VM"`
	Comment string   `json:"comment,omitempty" jsonschema:"short note about the VM (max 200 bytes)"`
	Prompt  string   `json:"prompt,omitempty" jsonschema:"initial task for the Shelley coding agent on the new VM"`
}

func (t *toolset) createVM(ctx context.Context, req *mcp.CallToolRequest, in createVMInput) (*mcp.CallToolResult, any, error) {
	if err := t.requireManage(req); err != nil {
		return nil, nil, err
	}
	args := []string{"new"}
	if in.Name != "" {
		name, err := exe.ParseVMName(in.Name)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, "--name="+string(name))
	}
	add := func(flag, v string) {
		if v != "" {
			args = append(args, exe.Quote("--"+flag+"="+v))
		}
	}
	add("image", in.Image)
	if in.CPUs > 0 {
		add("cpu", fmt.Sprint(in.CPUs))
	}
	add("memory", in.Memory)
	add("disk", in.Disk)
	add("tag", strings.Join(in.Tags, ","))
	add("comment", in.Comment)
	add("prompt", in.Prompt)
	raw, err := t.lobby(ctx, strings.Join(args, " "))
	if err != nil {
		return nil, nil, err
	}
	return jsonResult(raw), nil, nil
}

// --- delete_vm, restart_vm

type vmInput struct {
	VM string `json:"vm" jsonschema:"VM name"`
}

func (t *toolset) deleteVM(ctx context.Context, req *mcp.CallToolRequest, in vmInput) (*mcp.CallToolResult, any, error) {
	if err := t.requireManage(req); err != nil {
		return nil, nil, err
	}
	return t.vmLobby(ctx, req, access.OpManage, "rm", in.VM)
}

func (t *toolset) restartVM(ctx context.Context, req *mcp.CallToolRequest, in vmInput) (*mcp.CallToolResult, any, error) {
	return t.vmLobby(ctx, req, access.OpRestart, "restart", in.VM)
}

func (t *toolset) vmLobby(ctx context.Context, req *mcp.CallToolRequest, op access.Op, cmd, vm string) (*mcp.CallToolResult, any, error) {
	name, err := t.authorize(ctx, req, op, vm)
	if err != nil {
		return nil, nil, err
	}
	raw, err := t.lobby(ctx, cmd+" "+string(name))
	if err != nil {
		return nil, nil, err
	}
	return jsonResult(raw), nil, nil
}

// --- exe_command

// lobbyCommandRE matches the command name at the start of a lobby command
// line. Commands owned by other tools are refused by name, which is only
// sound if every lexer agrees on that name, so the name must be a bare word:
// no quotes, escapes or uppercase that the lobby might read differently.
var lobbyCommandRE = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\s|$)`)

type exeCommandInput struct {
	Command string `json:"command" jsonschema:"lobby command line, as typed after 'ssh exe.dev'"`
}

func (t *toolset) exeCommand(ctx context.Context, req *mcp.CallToolRequest, in exeCommandInput) (*mcp.CallToolResult, any, error) {
	if err := t.requireManage(req); err != nil {
		return nil, nil, err
	}
	cmd := strings.TrimSpace(in.Command)
	cmd = strings.TrimSpace(strings.TrimPrefix(cmd, "ssh exe.dev "))
	if cmd == "" {
		return nil, nil, errors.New("command is required")
	}
	name := strings.TrimSpace(lobbyCommandRE.FindString(cmd))
	switch name {
	case "":
		return nil, nil, fmt.Errorf("command must start with a plain lowercase command name, got %q", cmd)
	case "ssh":
		return nil, nil, errors.New("use run_command to run commands on a VM")
	case "share":
		return nil, nil, errors.New("use share_vm to change sharing")
	}
	raw, err := t.lobby(ctx, cmd)
	if err != nil {
		return nil, nil, err
	}
	return jsonResult(raw), nil, nil
}

// requireManage guards the account-level tools that name no VM.
func (t *toolset) requireManage(req *mcp.CallToolRequest) error {
	p, err := t.policyOf(req)
	if err != nil {
		return err
	}
	if !p.AllVMs || !p.Can(access.OpManage) {
		return fmt.Errorf("this connection is not allowed to manage VMs (it allows %s)", p)
	}
	return nil
}
