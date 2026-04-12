# arista-ssh-mcp

MCP server for interacting with Arista switches over SSH. Exposes switch operations as tools for use with Claude Code and Claude Desktop.

## Tools

### `get_config`

Retrieves the running or startup configuration from an Arista switch.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `host` | string | yes | — | Hostname or IP address of the switch |
| `username` | string | yes | — | SSH username |
| `port` | int | no | 22 | SSH port |
| `config_type` | string | no | `running` | `running` or `startup` |

### `get_inventory`

Retrieves hardware inventory from an Arista switch as JSON (`show inventory | json`).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `host` | string | yes | — | Hostname or IP address of the switch |
| `username` | string | yes | — | SSH username |
| `port` | int | no | 22 | SSH port |

## Authentication

Authentication methods are tried in order:

1. **SSH agent** — if `SSH_AUTH_SOCK` is set, the agent is used automatically. No configuration needed.
2. **Password** — set via the `ARISTA_PASSWORD` environment variable (see below).

At least one method must be available at call time. Using an SSH agent is recommended; the password fallback is intended for environments where agent forwarding is unavailable.

### Password via environment variable

Set `ARISTA_PASSWORD` before starting the server:

```bash
export ARISTA_PASSWORD=mysecret
arista-ssh-mcp
```

The password is never passed through tool parameters or the MCP protocol — it is read once from the environment at call time and applies to all connections made by the server process.

## Building

Requires Go 1.26 or later.

```bash
go build -o arista-ssh-mcp .
```

## Integration

### Claude Code

Add a project-local `.mcp.json` at the root of your repository:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/absolute/path/to/arista-ssh-mcp"
    }
  }
}
```

If you need password authentication, use the `env` key:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/absolute/path/to/arista-ssh-mcp",
      "env": {
        "ARISTA_PASSWORD": "mysecret"
      }
    }
  }
}
```

Alternatively, register the server globally with the Claude Code CLI:

```bash
claude mcp add arista-ssh /absolute/path/to/arista-ssh-mcp
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/absolute/path/to/arista-ssh-mcp"
    }
  }
}
```

With password authentication:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/absolute/path/to/arista-ssh-mcp",
      "env": {
        "ARISTA_PASSWORD": "mysecret"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config.

## Logging

The server logs to stderr (never stdout, which is reserved for the MCP protocol). The log level is controlled by the `LOG_LEVEL` environment variable:

| Value | Description |
|---|---|
| `debug` | Connection details, command strings, byte counts |
| `info` | Default — tool calls, connect/disconnect, success/failure |
| `warn` | Warnings only |
| `error` | Errors only |

```bash
LOG_LEVEL=debug arista-ssh-mcp
```

## License

Apache License 2.0
