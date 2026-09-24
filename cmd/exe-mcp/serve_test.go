package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/broady/exedev-mcp/internal/access"
)

// The exe.dev proxy reaches the server over loopback with the VM's public
// Host header; that must not trip DNS rebinding protection.
func TestMCPHandlerAcceptsProxiedHost(t *testing.T) {
	srv := httptest.NewServer(newMCPHandler(func(*http.Request) *mcp.Server { return mcp.NewServer(&mcp.Implementation{Name: "t"}, nil) }, slog.New(slog.DiscardHandler)))
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "myvm.exe.xyz"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServerCacheFailsClosed(t *testing.T) {
	var built [][]access.Op
	c := &serverCache{build: func(ops []access.Op) *mcp.Server {
		built = append(built, ops)
		return mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	}}
	// A missing policy must not mean "no restriction", which is what nil
	// means to tools.Options.
	c.get(nil)
	if built[0] == nil || len(built[0]) != 0 {
		t.Errorf("nil ops built %#v, want empty non-nil", built[0])
	}
	if c.get([]access.Op{access.OpRun, access.OpRead}) != c.get([]access.Op{access.OpRead, access.OpRun}) {
		t.Error("equivalent op sets got different servers")
	}
	if len(built) != 2 {
		t.Errorf("built %d servers, want 2", len(built))
	}
}
