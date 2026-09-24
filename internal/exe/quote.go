package exe

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// VMName is a validated exe.dev VM name.
type VMName string

var vmNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ParseVMName validates s as a VM name. It also accepts a VM hostname
// ("foo.exe.xyz"), which models often pass.
func ParseVMName(s string) (VMName, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".exe.xyz")
	if !vmNameRE.MatchString(s) {
		return "", fmt.Errorf("invalid VM name %q", s)
	}
	return VMName(s), nil
}

// Quote quotes s as a single POSIX shell word. The exe.dev lobby and the
// VM's shell both lex POSIX-style.
func Quote(s string) string {
	if s != "" && strings.IndexFunc(s, needsQuote) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func needsQuote(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	}
	return !strings.ContainsRune("-_./=:,@%+", r)
}

// ScriptOptions controls how ScriptCommand runs a script.
type ScriptOptions struct {
	// TimeoutSeconds kills the script after this many seconds (0 = none).
	TimeoutSeconds int
	// Login runs the script in a login shell, so PATH and friends match an
	// interactive session. Leave false when output must be exact (file
	// reads), since profile scripts may print.
	Login bool
}

// ScriptCommand returns a single-quote-free shell command that runs script
// with bash on the VM.
//
// The command crosses two shell lexers (the lobby's, then the VM's), each
// eating a layer of quoting. Base64 survives both untouched, so the script
// travels encoded and is decoded on the VM. stdin is /dev/null so a script
// can't block waiting for input the API can't provide.
func ScriptCommand(script string, opts ScriptOptions) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	flags := "-c"
	if opts.Login {
		flags = "-lc"
	}
	run := "bash " + flags + ` "$S"`
	if opts.TimeoutSeconds > 0 {
		// -k: SIGKILL if the script ignores SIGTERM.
		run = fmt.Sprintf("timeout -k 5 %d %s", opts.TimeoutSeconds, run)
	}
	return "S=$(printf %s " + b64 + " | base64 -d) && exec " + run + " </dev/null"
}
