package tools

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/broady/exedev-mcp/internal/access"
	"github.com/broady/exedev-mcp/internal/exe"
)

// --- share_vm

type shareVMInput struct {
	VM      string `json:"vm" jsonschema:"VM name"`
	Action  string `json:"action" jsonschema:"one of show, add, remove, add-link, remove-link, set-public, set-private, port, receive-email"`
	Who     string `json:"who,omitempty" jsonschema:"email address or team name, for add and remove"`
	Shell   bool   `json:"shell,omitempty" jsonschema:"add: also grant shell (SSH, terminal, Shelley) access; remove: take away only shell access, keeping web"`
	Message string `json:"message,omitempty" jsonschema:"add: note to include in the invitation"`
	Link    string `json:"link,omitempty" jsonschema:"remove-link: the link's token, from show"`
	Port    int    `json:"port,omitempty" jsonschema:"port: the VM port to serve at https://<vm>.exe.xyz; omit to show the current one"`
	Enabled *bool  `json:"enabled,omitempty" jsonschema:"receive-email: true to turn inbound email on, false for off; omit to show the current setting"`
}

var (
	// Share targets and link tokens go on the lobby command line as
	// arguments; a leading "-" would be read as a flag.
	shareWhoRE  = regexp.MustCompile(`^[A-Za-z0-9._%+@][A-Za-z0-9._%+@-]{0,253}$`)
	shareLinkRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,255}$`)
)

func (t *toolset) shareVM(ctx context.Context, req *mcp.CallToolRequest, in shareVMInput) (*mcp.CallToolResult, any, error) {
	args, op, err := shareArgs(in)
	if err != nil {
		return nil, nil, err
	}
	name, err := t.authorize(ctx, req, op, in.VM)
	if err != nil {
		return nil, nil, err
	}
	// Anyone with shell on the host VM can use the API integration, and
	// the connector needs the host VM public: only look.
	if name == exe.VMName(t.hostVM) && in.Action != "show" {
		return nil, nil, fmt.Errorf("VM %s runs this server; change its sharing with ssh exe.dev", name)
	}
	cmd := strings.Join(append([]string{"share", in.Action, string(name)}, args...), " ")
	raw, err := t.lobby(ctx, cmd)
	if err != nil {
		return nil, nil, err
	}
	return jsonResult(raw), nil, nil
}

// shareArgs validates in and returns the arguments after "share <action>
// <vm>", and the operation the action needs. Actions that only narrow
// access or look need OpShare; those that widen it beyond a named web user
// need OpExpose.
func shareArgs(in shareVMInput) ([]string, access.Op, error) {
	switch in.Action {
	case "show", "set-private":
		return nil, access.OpShare, nil
	case "add", "remove":
		if !shareWhoRE.MatchString(in.Who) {
			return nil, "", fmt.Errorf("%s needs who: an email address or team name, got %q", in.Action, in.Who)
		}
		args := []string{in.Who}
		op := access.OpShare
		if in.Shell {
			args = append(args, "--root")
			if in.Action == "add" {
				op = access.OpExpose
			}
		}
		if in.Message != "" {
			if in.Action != "add" {
				return nil, "", errors.New("message is only for add")
			}
			args = append(args, exe.Quote("--message="+in.Message))
		}
		return args, op, nil
	case "add-link", "set-public":
		return nil, access.OpExpose, nil
	case "remove-link":
		if !shareLinkRE.MatchString(in.Link) {
			return nil, "", fmt.Errorf("remove-link needs link: a link token from show, got %q", in.Link)
		}
		return []string{in.Link}, access.OpShare, nil
	case "port":
		switch {
		case in.Port == 0:
			return nil, access.OpShare, nil
		case in.Port < 1 || in.Port > 65535:
			return nil, "", fmt.Errorf("invalid port %d", in.Port)
		}
		return []string{fmt.Sprint(in.Port)}, access.OpExpose, nil
	case "receive-email":
		switch {
		case in.Enabled == nil:
			return nil, access.OpShare, nil
		case *in.Enabled:
			return []string{"on"}, access.OpExpose, nil
		default:
			return []string{"off"}, access.OpShare, nil
		}
	default:
		return nil, "", fmt.Errorf("unknown action %q: use show, add, remove, add-link, remove-link, set-public, set-private, port or receive-email", in.Action)
	}
}
