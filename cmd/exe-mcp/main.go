// Command exe-mcp is an MCP server for exe.dev VMs.
//
// Run it locally over stdio (Claude Desktop, Claude Code), authenticating to
// exe.dev with short-lived tokens signed by your SSH agent:
//
//	exe-mcp stdio
//
// Or host it on an exe.dev VM for claude.ai, Claude Desktop and mobile
// connectors, with OAuth backed by exe.dev login:
//
//	exe-mcp serve
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/alecthomas/kong"

	"github.com/broady/exedev-mcp/internal/exe"
)

type cli struct {
	LogLevel slog.Level `help:"Log level (debug, info, warn, error)." default:"info" env:"EXE_MCP_LOG_LEVEL"`

	Stdio   stdioCmd   `cmd:"" help:"Serve MCP over stdio, authenticating to exe.dev as you."`
	Serve   serveCmd   `cmd:"" help:"Serve MCP over HTTP with OAuth, on an exe.dev VM."`
	Version versionCmd `cmd:"" help:"Print the version."`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "exe-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	var c cli
	kctx := kong.Parse(&c,
		kong.Name("exe-mcp"),
		kong.Description("MCP server for exe.dev VMs."),
		kong.UsageOnError(),
		kong.Vars{"endpoint": exe.DefaultEndpoint},
	)
	// stdout belongs to the MCP stdio transport; logs go to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: c.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return kctx.Run(&app{ctx: ctx, log: logger})
}

// app is shared by all commands.
type app struct {
	ctx context.Context // process lifetime: cancelled on SIGINT/SIGTERM
	log *slog.Logger
}

type versionCmd struct{}

func (versionCmd) Run() error {
	fmt.Println(version())
	return nil
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "devel"
}
