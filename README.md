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

## Default username

Set `ARISTA_USERNAME` to avoid specifying `username` in every tool call:

```bash
export ARISTA_USERNAME=admin
```

The `username` tool parameter takes precedence if provided.

## Authentication

Authentication methods are tried in order:

1. **SSH agent** — if `SSH_AUTH_SOCK` is set, the agent is used automatically. No configuration needed.
2. **Password** — set via the `ARISTA_PASSWORD` environment variable (see below).

At least one method must be available at call time.

> **Claude Desktop note:** Claude Desktop is a GUI application and does not inherit your shell environment, so `SSH_AUTH_SOCK` is not available to the MCP server process. Set it explicitly in the `env` block of the config (see the Claude Desktop section below). Claude Code runs in the terminal and inherits your shell environment, so no extra configuration is needed there.

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

To install the binary to `/usr/local/bin` after building (macOS and Linux):

```bash
sudo install -m 0755 arista-ssh-mcp /usr/local/bin/
```

## Integration

### Claude Code

Add a project-local `.mcp.json` at the root of your repository:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/usr/local/bin/arista-ssh-mcp"
    }
  }
}
```

With a default username:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/usr/local/bin/arista-ssh-mcp",
      "env": {
        "ARISTA_USERNAME": "admin"
      }
    }
  }
}
```

Claude Code runs in the terminal and inherits your shell environment, so `SSH_AUTH_SOCK` is available automatically — no extra configuration needed for SSH agent authentication.

Alternatively, using password authentication:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/usr/local/bin/arista-ssh-mcp",
      "env": {
        "ARISTA_USERNAME": "admin",
        "ARISTA_PASSWORD": "mysecret"
      }
    }
  }
}
```

Alternatively, register the server globally with the Claude Code CLI:

```bash
claude mcp add arista-ssh /usr/local/bin/arista-ssh-mcp
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/usr/local/bin/arista-ssh-mcp"
    }
  }
}
```

Claude Desktop does not inherit your shell environment, so `SSH_AUTH_SOCK` must be set explicitly. Get the current socket path from your terminal:

```bash
echo $SSH_AUTH_SOCK
```

Then add it to the config:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/usr/local/bin/arista-ssh-mcp",
      "env": {
        "ARISTA_USERNAME": "admin",
        "SSH_AUTH_SOCK": "/private/tmp/com.apple.launchd.XXXXX/Listeners"
      }
    }
  }
}
```

Note that the socket path changes on every reboot and must be updated in the config accordingly.

Alternatively, using password authentication:

```json
{
  "mcpServers": {
    "arista-ssh": {
      "command": "/usr/local/bin/arista-ssh-mcp",
      "env": {
        "ARISTA_USERNAME": "admin",
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
