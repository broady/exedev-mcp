package tools

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/broady/exedev-mcp/internal/exe"
)

// --- run_command

type runCommandInput struct {
	VM             string `json:"vm" jsonschema:"VM name"`
	Command        string `json:"command" jsonschema:"bash command or multi-line script"`
	Cwd            string `json:"cwd,omitempty" jsonschema:"working directory (default: home directory)"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"kill the command after this many seconds (default 120, max 600)"`
}

func (t *toolset) runCommand(ctx context.Context, _ *mcp.CallToolRequest, in runCommandInput) (*mcp.CallToolResult, any, error) {
	vm, err := exe.ParseVMName(in.VM)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return nil, nil, errors.New("command is required")
	}
	timeout := in.TimeoutSeconds
	switch {
	case timeout <= 0:
		timeout = defaultCmdTimeout
	case timeout > maxCmdTimeout:
		return nil, nil, fmt.Errorf("timeout_seconds must be at most %d; run longer jobs in the background", maxCmdTimeout)
	}
	script := in.Command
	if in.Cwd != "" {
		script = "cd -- " + exe.Quote(in.Cwd) + " || exit\n" + script
	}
	res, err := t.script(ctx, vm, script, exe.ScriptOptions{TimeoutSeconds: timeout, Login: true}, maxCommandOutput)
	if err != nil {
		return nil, nil, err
	}
	status := fmt.Sprintf("[exit status %d]", res.ExitCode)
	if res.ExitCode == 124 {
		status = fmt.Sprintf("[exit status 124: timed out after %ds]", timeout)
	}
	out := string(res.Output)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return textResult("%s%s", out, status), nil, nil
}

// --- read_file

type readFileInput struct {
	VM     string `json:"vm" jsonschema:"VM name"`
	Path   string `json:"path" jsonschema:"file path"`
	Offset int    `json:"offset,omitempty" jsonschema:"first line to read, 1-based (default 1)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of lines (default 2000)"`
}

func (t *toolset) readFile(ctx context.Context, _ *mcp.CallToolRequest, in readFileInput) (*mcp.CallToolResult, any, error) {
	vm, err := exe.ParseVMName(in.VM)
	if err != nil {
		return nil, nil, err
	}
	if in.Path == "" {
		return nil, nil, errors.New("path is required")
	}
	offset, limit := max(in.Offset, 1), in.Limit
	if limit <= 0 {
		limit = defaultReadLimit
	}
	// awk reads stdin so paths starting with "-" or containing "=" are safe.
	script := fmt.Sprintf(`f=%s
if [ ! -f "$f" ]; then echo "not a regular file: $f" >&2; exit 2; fi
awk -v o=%d -v l=%d '
NR >= o && NR < o+l { if (length($0) > 2000) $0 = substr($0, 1, 2000) "..."; printf "%%6d\t%%s\n", NR, $0 }
END {
	if (NR == 0) print "(empty file)"
	else if (NR >= o+l) printf "\n[showing lines %%d-%%d of %%d; use offset to read more]\n", o, o+l-1, NR
	else if (o > NR) printf "[offset %%d is past the end: file has %%d lines]\n", o, NR
}' < "$f"`, exe.Quote(in.Path), offset, limit)
	res, err := t.script(ctx, vm, script, exe.ScriptOptions{TimeoutSeconds: 30}, maxReadOutput)
	if err != nil {
		return nil, nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil, fmt.Errorf("read %s: %s", in.Path, strings.TrimSpace(string(res.Output)))
	}
	return textResult("%s", res.Output), nil, nil
}

// --- write_file

type writeFileInput struct {
	VM      string `json:"vm" jsonschema:"VM name"`
	Path    string `json:"path" jsonschema:"file path"`
	Content string `json:"content" jsonschema:"full file content"`
}

func (t *toolset) writeFile(ctx context.Context, _ *mcp.CallToolRequest, in writeFileInput) (*mcp.CallToolResult, any, error) {
	vm, err := exe.ParseVMName(in.VM)
	if err != nil {
		return nil, nil, err
	}
	if in.Path == "" {
		return nil, nil, errors.New("path is required")
	}
	if err := t.put(ctx, vm, in.Path, []byte(in.Content)); err != nil {
		return nil, nil, err
	}
	return textResult("wrote %d bytes to %s", len(in.Content), in.Path), nil, nil
}

// put writes data to path on vm. The API has no stdin and a 64KiB request
// limit, so data goes in base64 chunks appended to a temp file that is
// renamed into place at the end: readers never see a partial file.
func (t *toolset) put(ctx context.Context, vm exe.VMName, path string, data []byte) error {
	if len(data) > maxWriteFileSize {
		return fmt.Errorf("content is %d bytes; the limit is %d", len(data), maxWriteFileSize)
	}
	suffix := make([]byte, 6)
	rand.Read(suffix)
	tmp := fmt.Sprintf("%s.exe-mcp-%x.tmp", path, suffix)
	header := fmt.Sprintf("set -e\np=%s\nt=%s\n", exe.Quote(path), exe.Quote(tmp))

	for off := 0; off == 0 || off < len(data); off += writeChunkSize {
		chunk := data[off:min(off+writeChunkSize, len(data))]
		first, last := off == 0, off+writeChunkSize >= len(data)
		var b strings.Builder
		b.WriteString(header)
		redirect := ">>"
		if first {
			b.WriteString(`mkdir -p -- "$(dirname -- "$p")"` + "\n")
			redirect = ">"
		}
		fmt.Fprintf(&b, "printf %%s %s | base64 -d %s \"$t\"\n", exe.Quote(base64.StdEncoding.EncodeToString(chunk)), redirect)
		if last {
			b.WriteString(`if [ -e "$p" ]; then chmod --reference="$p" -- "$t" 2>/dev/null || true; fi` + "\n")
			b.WriteString(`mv -f -- "$t" "$p"` + "\n")
		}
		res, err := t.script(ctx, vm, b.String(), exe.ScriptOptions{TimeoutSeconds: 30}, 4<<10)
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("write %s: %s", path, strings.TrimSpace(string(res.Output)))
		}
		if err != nil {
			t.cleanup(vm, tmp) //nolint:contextcheck // cleanup must run even when ctx is cancelled
			return err
		}
	}
	return nil
}

// cleanup removes a temp file after a failed write. Best effort: it runs
// with a fresh context because ctx may be what failed.
func (t *toolset) cleanup(vm exe.VMName, tmp string) {
	ctx, cancel := context.WithTimeout(context.Background(), lobbyTimeout)
	defer cancel()
	_, _ = t.script(ctx, vm, "rm -f -- "+exe.Quote(tmp), exe.ScriptOptions{TimeoutSeconds: 10}, 1<<10)
}

// --- edit_file

type editFileInput struct {
	VM         string `json:"vm" jsonschema:"VM name"`
	Path       string `json:"path" jsonschema:"file path"`
	OldString  string `json:"old_string" jsonschema:"exact text to replace"`
	NewString  string `json:"new_string" jsonschema:"replacement text"`
	ReplaceAll bool   `json:"replace_all,omitempty" jsonschema:"replace every occurrence instead of requiring exactly one"`
}

func (t *toolset) editFile(ctx context.Context, _ *mcp.CallToolRequest, in editFileInput) (*mcp.CallToolResult, any, error) {
	vm, err := exe.ParseVMName(in.VM)
	if err != nil {
		return nil, nil, err
	}
	if in.Path == "" || in.OldString == "" {
		return nil, nil, errors.New("path and old_string are required")
	}
	if in.OldString == in.NewString {
		return nil, nil, errors.New("old_string and new_string are identical")
	}
	res, err := t.script(ctx, vm, "exec cat -- "+exe.Quote(in.Path), exe.ScriptOptions{TimeoutSeconds: 30}, maxEditFileSize+1)
	if err != nil {
		return nil, nil, err
	}
	if res.ExitCode != 0 {
		return nil, nil, fmt.Errorf("read %s: %s", in.Path, strings.TrimSpace(string(res.Output)))
	}
	if res.Omitted > 0 {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes; use run_command (sed, patch) instead", in.Path, maxEditFileSize)
	}
	content := string(res.Output)
	n := strings.Count(content, in.OldString)
	switch {
	case n == 0:
		return nil, nil, fmt.Errorf("old_string not found in %s", in.Path)
	case n > 1 && !in.ReplaceAll:
		return nil, nil, fmt.Errorf("old_string occurs %d times in %s; add surrounding context to make it unique, or set replace_all", n, in.Path)
	}
	if in.ReplaceAll {
		content = strings.ReplaceAll(content, in.OldString, in.NewString)
	} else {
		content = strings.Replace(content, in.OldString, in.NewString, 1)
	}
	if err := t.put(ctx, vm, in.Path, []byte(content)); err != nil {
		return nil, nil, err
	}
	return textResult("replaced %d occurrence(s) in %s", n, in.Path), nil, nil
}
