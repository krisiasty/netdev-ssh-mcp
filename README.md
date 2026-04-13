# netdev-ssh-mcp

MCP server for interacting with network devices (switches, routers) over SSH.
Supports Arista EOS, Cisco NX-OS, and Cisco IOS/IOS-XE. Exposes network
device operations as tools for use with Claude Code and Claude Desktop (and
other MCP clients)

## Tools

### `get_config`

Retrieves the running or startup configuration from an Arista, Cisco Nexus,
or Cisco Catalyst device. Sensitive values (passwords, secrets, SNMP community
names, BGP/OSPF/TACACS/RADIUS/IKE keys) are automatically replaced with
deterministic SHA-256 hashes:

```text
enable secret [h:a3f4b2c1d5e6]
snmp-server community [h:f9e1d2b4c3a7] ro
username admin privilege 15 secret [h:a3f4b2c1d5e6]
```

The same secret value always produces the same hash, so configs from different
devices can be safely compared and diffed — identical hashes mean identical
secrets.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `config_type` | string | no | `running` | `running` or `startup` |

### `run_show_command`

Runs any `show` command on an Arista, Cisco Nexus, or Cisco Catalyst device
and returns the output. The command must start with `show`. Append `| json`
for structured output where supported, or `| no-more` to disable pagination
for text output.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `command` | string | yes | — | The show command to run |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |

Example commands:

```text
show bgp summary | json
show interfaces status | json
show lldp neighbors detail | json
show inventory | json
show version | json
show ip route | json
```

> `show running-config` and `show startup-config` are not allowed here — use
> the `get_config` tool instead.

### `run_ping`

Runs a ping command on an Arista, Cisco Nexus, or Cisco Catalyst device and
returns the output. Useful for verifying reachability from the device's
perspective — for example, testing connectivity to a BGP peer, next-hop, or
management target.

Use `device_type` to select the correct command syntax for the target platform.
If omitted, EOS/IOS syntax is used (`repeat`, `size` keywords).

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `destination` | string | yes | — | IP address or hostname to ping |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `count` | int | no | — | Number of echo requests to send |
| `source` | string | no | — | Source IP address or interface name |
| `vrf` | string | no | — | VRF name |
| `size` | int | no | — | Packet size in bytes |
| `device_type` | string | no | — | `eos`, `ios`, or `nxos` — controls ping syntax |

### `run_traceroute`

Shows the hop-by-hop path from the device to a destination and per-hop latency.
Useful for locating where connectivity breaks, verifying traffic follows the
expected path, and identifying which hop introduces latency.

Use `device_type` to ensure correct syntax. On IOS, `vrf` must precede the
destination in the command — specifying `device_type=ios` handles this
automatically.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `destination` | string | yes | — | IP address or hostname to trace to |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `max_hops` | int | no | — | Maximum number of hops (TTL) |
| `timeout` | int | no | — | Per-probe timeout in seconds |
| `probe` | int | no | — | Number of probes per hop |
| `source` | string | no | — | Source IP address or interface name |
| `vrf` | string | no | — | VRF name |
| `device_type` | string | no | — | `eos`, `ios`, or `nxos` — controls traceroute syntax |

## Default username

Set `DEVICE_USERNAME` to avoid specifying `username` in every tool call:

```bash
export DEVICE_USERNAME=admin
```

The `username` tool parameter takes precedence if provided.

## Authentication

Authentication methods are tried in order:

1. **SSH agent** — if `SSH_AUTH_SOCK` is set, the agent is used automatically.
   No configuration needed.
2. **Password** — set via the `DEVICE_PASSWORD` environment variable (see below).

At least one method must be available at call time.

> **Claude Desktop note:** Claude Desktop is a GUI application and does not
> inherit your shell environment, so `SSH_AUTH_SOCK` is not available to the
> MCP server process. Set it explicitly in the `env` block of the config (see
> the Claude Desktop section below). Claude Code runs in the terminal and
> inherits your shell environment, so no extra configuration is needed there.

### Password via environment variable

Set `DEVICE_PASSWORD` before starting the server:

```bash
export DEVICE_PASSWORD=mysecret
netdev-ssh-mcp
```

The password is never passed through tool parameters or the MCP protocol — it
is read once from the environment at call time and applies to all connections
made by the server process.

## Building

Requires Go 1.26 or later.

```bash
go build -o netdev-ssh-mcp .
```

To install the binary to `/usr/local/bin` after building (macOS and Linux):

```bash
sudo install -m 0755 netdev-ssh-mcp /usr/local/bin/
```

## Integration

### Claude Code

Add a project-local `.mcp.json` at the root of your repository:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp"
    }
  }
}
```

With a default username:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp",
      "env": {
        "DEVICE_USERNAME": "admin"
      }
    }
  }
}
```

Claude Code runs in the terminal and inherits your shell environment, so
`SSH_AUTH_SOCK` is available automatically — no extra configuration needed for
SSH agent authentication.

Alternatively, using password authentication:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp",
      "env": {
        "DEVICE_USERNAME": "admin",
        "DEVICE_PASSWORD": "mysecret"
      }
    }
  }
}
```

Alternatively, register the server globally with the Claude Code CLI:

```bash
claude mcp add netdev-ssh-mcp /usr/local/bin/netdev-ssh-mcp
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp"
    }
  }
}
```

Claude Desktop does not inherit your shell environment, so `SSH_AUTH_SOCK`
must be set explicitly. Get the current socket path from your terminal:

```bash
echo $SSH_AUTH_SOCK
```

Then add it to the config:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp",
      "env": {
        "DEVICE_USERNAME": "admin",
        "SSH_AUTH_SOCK": "/private/tmp/com.apple.launchd.XXXXX/Listeners"
      }
    }
  }
}
```

Note that the socket path changes on every reboot and must be updated in the
config accordingly.

Alternatively, using password authentication:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp",
      "env": {
        "DEVICE_USERNAME": "admin",
        "DEVICE_PASSWORD": "mysecret"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config.

## Example prompts

- Show me the running config of 10.0.0.1
- Compare the running configs of n9k-1 and n9k-2 and summarize the differences
- Check BGP neighbor status on arista1 and tell me if any sessions are down
- Get the interface status from 10.0.0.1 and list any interfaces that are down
- Review the running config of 10.0.0.1 and flag any security concerns
- Get the LLDP neighbors from 10.0.0.1 and draw a topology diagram
- How is traffic to 192.168.100.0/24 forwarded on 10.0.0.1?
- Check NTP consistency across 10.0.0.1, 10.0.0.2, and 10.0.0.3
- Discover spine-1 neighbors via LLDP/CDP and check EVPN fabric configuration
- Tell me what exact commands to use to fix configuration issues you detected
- Verify if all previously spotted issues are fixed now
- Ping 10.0.0.2 from 10.0.0.1 and tell me if it's reachable
- Check if arista1 can reach all its BGP peers by pinging each one
- Ping 8.8.8.8 from the management VRF on n9k-1
- Traceroute from arista1 to 10.0.0.2 and show me the path
- Run a traceroute from spine-1 to each of its BGP peers and identify any asymmetric paths

## Obfuscation

Sensitive values are obfuscated by default in `get_config` and
`run_show_command` output. The `run_ping` tool is not affected — ping output
contains no sensitive values. To disable obfuscation, pass `--no-obfuscate`:

```bash
netdev-ssh-mcp --no-obfuscate
```

In an MCP config file, pass it via `args`:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "/usr/local/bin/netdev-ssh-mcp",
      "args": ["--no-obfuscate"]
    }
  }
}
```

## Logging

The server logs to stderr (never stdout, which is reserved for the MCP
protocol). The log level is controlled by the `LOG_LEVEL` environment
variable:

| Value | Description |
| --- | --- |
| `debug` | Connection details, command strings, byte counts |
| `info` | Default — tool calls, connect/disconnect, success/failure |
| `warn` | Warnings only |
| `error` | Errors only |

```bash
LOG_LEVEL=debug netdev-ssh-mcp
```

## Author

Krzysztof Ciepłucha

## Disclaimer

This tool was designed and built with the assistance of AI tools. The design
decisions, architecture, and all code have been reviewed and verified by a
human. The project goes through automated security checks, vulnerability
scanning, and static code analysis on every commit.

That said, this software is provided as-is with no guarantees. It may contain
bugs. **Use at your own risk.**

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
