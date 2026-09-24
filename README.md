# exe-mcp

An MCP server for [exe.dev](https://exe.dev) VMs. Claude can list, create and
delete your VMs, run commands on them, and read, write and edit their files.

```
go install github.com/broady/exedev-mcp/cmd/exe-mcp@latest
```

There are two ways to run it:

- **Locally, over stdio**, for Claude Desktop, Claude Code, and other MCP
  clients on your machine. It authenticates as you with your SSH agent, the
  same key `ssh exe.dev` uses.
- **Hosted on an exe.dev VM**, as a remote connector for claude.ai, Claude
  Desktop and Claude mobile. OAuth is backed by exe.dev login, and the exe.dev
  API token never touches the VM.

## Local (stdio)

Claude Code:

```
claude mcp add exe -- exe-mcp stdio
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "exe": { "command": "/Users/you/go/bin/exe-mcp", "args": ["stdio"] }
  }
}
```

No token setup is needed. exe-mcp signs short-lived (1h) API tokens with a key
in your SSH agent. The tokens are limited to VM management commands; billing
and SSH key management are not allowed.

It picks the key the way `ssh exe.dev` does. It reads `ssh -G exe.dev` and
tries the agent keys matching `IdentityFile` first, then the other agent keys
unless `IdentitiesOnly yes` is set. It sends exe.dev a `whoami` token signed by
each candidate until one is accepted. Every try is a signature, which may prompt
(1Password, Secretive) and shows exe.dev that key, so pin the key to skip
probing. The log prints the fingerprint it found:

```
claude mcp add exe -e EXE_SSH_KEY=SHA256:... -- exe-mcp stdio
```

```json
"exe": {
  "command": "/Users/you/go/bin/exe-mcp",
  "args": ["stdio"],
  "env": { "EXE_SSH_KEY": "SHA256:..." }
}
```

GUI apps often start without `SSH_AUTH_SOCK`, so exe-mcp falls back to the
`IdentityAgent` that `ssh -G exe.dev` reports. That covers agents such as
1Password and Secretive that are configured only in `~/.ssh/config`.

| Flag | Env | Default |
|---|---|---|
| `--token` | `EXE_TOKEN` | mint with the SSH agent |
| `--ssh-agent` | `EXE_SSH_AUTH_SOCK` | `SSH_AUTH_SOCK`, then ssh's `IdentityAgent` |
| `--key` | `EXE_SSH_KEY` | probe `IdentityFile` keys, then the rest (match by `SHA256:` fingerprint or comment) |
| `--cmds` | `EXE_TOKEN_CMDS` | VM management commands |

## Hosted (remote connector)

```sh
VM=my-mcp

ssh exe.dev new --name=$VM

# An API token that lives in an exe.dev integration, not on the VM. The VM
# reaches the API through https://exe-api.int.exe.xyz, and the proxy adds
# the token.
ssh exe.dev ssh-key generate-api-key --label=$VM --exp=1y --json \
    --cmds=help,ls,new,rm,restart,rename,tag,comment,stat,whoami,ssh,share |
  jq -r .token |
  ssh exe.dev integrations add http-proxy --name exe-api \
    --target https://exe.dev --bearer=- --attach vm:$VM

task deploy VM=$VM

# Custom connectors can't log in through exe.dev's proxy, so the VM must be
# public. The server authenticates every request itself (see Security).
ssh exe.dev share set-public $VM
```

Next, add `https://my-mcp.exe.xyz/mcp` as a custom connector in claude.ai:
Settings, then Connectors, then Add custom connector. Leave the OAuth client
fields empty. When you connect, exe.dev asks you to sign in, and a consent
page then asks you to allow the client.

The connector also works in Claude Code:
`claude mcp add --transport http exe https://my-mcp.exe.xyz/mcp`.

The dashboard at `https://my-mcp.exe.xyz/` shows the connector URL, checks that the API integration works and which account it acts as, and lists connected applications with their access so you can revoke them.

### Access per connection

When you connect an application, the consent page asks which VMs and
operations it may use. By default it gets everything.

**VMs:** all of them, a list you pick, or any VM carrying one of the tags you
pick. A tag covers VMs tagged later, and untagging a VM cuts off access on the
next call.

**Operations:**

| Operation | Tools |
|---|---|
| read files | `read_file` |
| write files | `write_file`, `edit_file` |
| run commands | `run_command` |
| restart | `restart_vm` |
| create & delete VMs | `create_vm`, `delete_vm`, `exe_command`; all VMs only |

`list_vms` is always available and shows only the allowed VMs. A connection
sees only the tools it may use, and access is checked again on every call.
For example, read files on the `prod` tag gives a read-only view of
production. To change a connection's access, revoke it and connect again.

Note that run commands implies the rest on the same VM: a shell can read and
write files and reboot the machine. Leave it off for real read-only access.

The VM running the server is only available with all VMs. It holds the
API integration, so running commands there reaches the whole account. The
same is true of any other VM you attach the integration to.

`serve` reads its VM name and owner from the exe.dev Reflection integration.
Overrides go in `~/.config/exe-mcp/env` on the VM:

| Flag | Env | Default |
|---|---|---|
| `--addr` | `EXE_MCP_ADDR` | `:8000` |
| `--public-url` | `EXE_MCP_PUBLIC_URL` | `https://<vm>.exe.xyz` |
| `--owner` | `EXE_MCP_OWNER` | the VM owner's email; repeat the flag or comma-separate the env var to allow more |
| `--exec-url` | `EXE_MCP_EXEC_URL` | `https://exe-api.int.exe.xyz/exec` |
| `--state` | `EXE_MCP_STATE` | `~/.config/exe-mcp/oauth.json` |
| `--vm-name` | `EXE_MCP_VM_NAME` | this VM's name; only offered to full-access connections |

## Tools

| Tool | |
|---|---|
| `list_vms` | VMs you own and VMs shared with you |
| `create_vm` | Optional name, image, CPUs, memory, disk, tags, comment, and a first task for Shelley |
| `delete_vm`, `restart_vm` | |
| `exe_command` | Any other exe.dev lobby command the token allows |
| `run_command` | Runs in a bash login shell, with a timeout (default 2m, max 10m) and optional cwd. Output is capped at 64KB; beyond that the middle is dropped |
| `read_file` | Line-numbered, with offset and limit |
| `write_file` | Atomic (temp file, then rename); keeps the existing mode |
| `edit_file` | Exact string replacement that must match once, or pass `replace_all` |

## Security

- **Authorization server.** Implements the MCP authorization spec:
  - OAuth 2.1 with PKCE (S256 only);
  - protected resource metadata (RFC 9728) and authorization server metadata
    (RFC 8414);
  - client ID metadata documents, with dynamic client registration as a
    fallback;
  - resource indicators (RFC 8707) and `iss` in redirects (RFC 9207).
- **Tokens.** Access tokens last 1 hour. They are MACed with a key in the
  state file and checked against their grant on every request, so they
  survive restarts, yet revoking a grant or removing an owner cuts them off
  at once. Refresh tokens rotate on every use, and each refresh retires the
  previous access token. Reusing an old refresh token revokes the whole
  grant. Only refresh token hashes are stored.
- **Login.** exe.dev login identifies the user through the `X-ExeDev-Email`
  header, which the exe.dev proxy sets and strips from client requests. Only
  owners (`--owner`) can authorize. Anyone else gets 403, and a stranger
  can't make the server fetch a metadata document.
- **Consent page.** Protected against CSRF (`http.CrossOriginProtection`) and
  framing. It names the application and where the redirect goes, and it warns
  about unverified clients and native-app redirects.
- **Metadata fetches.** Fetches for metadata documents refuse private,
  loopback and link-local addresses at dial time.
- **The API token.** It stays in the integration. A compromised VM can use it
  through the proxy but can't take it anywhere else. Scope it with `--cmds`
  and `--exp`.

The MCP endpoint is stateless and access tokens survive restarts, so
connected clients don't notice a restart. Only an authorization in progress
(a consent page left open) has to start again.

## How commands run

`POST https://exe.dev/exec` takes one command line. That line is lexed twice:
once by the exe.dev lobby and once by the VM's shell. Scripts are therefore
sent base64-encoded:

```
ssh vm 'S=$(printf %s <base64> | base64 -d) && exec timeout -k 5 120 bash -lc "$S" </dev/null'
```

The timeout runs on the VM, because disconnecting the HTTP request doesn't
stop the remote command. Requests are limited to 64KB, so `write_file` sends
large files in chunks.

## Development

```
task check    # lint (golangci-lint, including format and vet) and go test -race
task build
```

The tool tests run against a fake `/exec` that executes commands with local
bash. The OAuth tests cover the full flow, CSRF, reuse detection, CIMD
fetching with a TLS test server, and persistence.
