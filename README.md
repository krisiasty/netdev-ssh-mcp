# netdev-ssh-mcp

MCP server for interacting with network devices (switches, routers, firewalls) over SSH.
Supports Arista EOS, Cisco NX-OS, Cisco IOS/IOS-XE, Juniper JunOS, and FortiGate FortiOS.
Exposes network device operations as tools for use with Claude Code / Claude Desktop / Codex
(and other MCP clients)

## Platform detection

Every tool that talks to a device takes an optional `device_type`: `eos`, `ios`, `nxos`, `junos` or `fortios`
(`fortigate` is accepted as an alias). Pass it when you know the platform, for example from an inventory system.

When `device_type` is omitted, the server detects the platform over SSH before running the command:

1. It reads the SSH server identification string, which narrows the candidates and picks one probe command that the
   likely platform accepts.
2. It runs that read-only probe on the same connection: `show version`, or `get system status` when the server looks
   like a FortiGate.
3. It matches platform-specific lines at the start of the probe output: the `Arista <model>` line (EOS), `Junos:` (JunOS),
   `Cisco Nexus Operating System` (NX-OS), `Cisco IOS Software` / `Cisco IOS XE Software` (IOS), and
   `Version: FortiGate` (FortiOS). Exactly one platform must match; otherwise the call fails and asks for
   `device_type` instead of guessing.

The result is cached per host and port for an hour, so only the first call to a host pays for the extra connection.
A command that fails with a syntax error drops the cached entry, so the next call probes again. Only the start of a
successful command's output is checked for a rejection message, so text later in it, such as a login banner in a
configuration, is not mistaken for one.

Calls that used detection end with a note such as
`device_type: junos (auto-detected over SSH). Pass device_type=junos on later calls to this host to skip detection.`,
kept as a separate content block after the device output. If a command run with an explicit `device_type` is rejected
as invalid syntax, the result ends with a hint that the type may be wrong. Use [`detect_platform`](#detect_platform)
to resolve a list of hosts up front.

Without `device_type`, `run_show_command` rejects a command that no supported platform accepts (for example `reload`
or a command joined with `;`) before detection logs in to the device.

When a command fails, the error names the command and its exit status and, if the device rejected the syntax, says so.
It never includes what the device printed: that output is untrusted, can contain secrets, and would bypass the
obfuscation applied to successful output.

Some platforms are recognised from the SSH identification string and refused before any command runs:

| Platform | Reason |
| --- | --- |
| Cumulus Linux and other Debian or Ubuntu based systems | SSH exec reaches a Linux shell; not supported yet |
| Cisco Business switch OS (Catalyst 1200/1300, CBS) | Does not answer SSH exec requests |

## Tools

### `get_config`

Retrieves the running or startup configuration from an Arista, Cisco Nexus,
Cisco IOS/IOS-XE, Juniper JunOS, or FortiGate FortiOS device. Sensitive values (passwords, secrets, SNMP community
names, BGP/OSPF/TACACS/RADIUS/IKE keys) are automatically replaced with keyed
hash tokens:

```text
enable secret 5 [h:3c91e0a47b2d]
snmp-server community [h:8f02d6c51e9a] ro
username admin privilege 15 secret 5 [h:3c91e0a47b2d]
```

Under the same key, the same secret always produces the same token, so configs
from different devices can be compared and diffed — identical tokens mean
identical secrets. See [Obfuscation](#obfuscation) for how the key is chosen.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `config_type` | string | no | `running` | `running` or `startup`; `startup` is not supported on JunOS or FortiOS |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, or `fortios`; see [Platform detection](#platform-detection) |

Cisco IOS notes:

- `device_type=ios` covers any Cisco IOS or IOS-XE device — Catalyst switches, ISR/ASR routers, and others.
- IOS does not support `| no-more`, so the config is retrieved with plain `show running-config` or
  `show startup-config`. On EOS and NX-OS, `| no-more` is appended.

FortiOS notes:

- Use `device_type=fortios` to retrieve config with `show full-configuration`.
- `fortigate` is accepted as an alias for `fortios`.
- FortiOS does not support `config_type=startup`.

### `run_show_command`

Runs operational read commands on a network device and returns the output.
For Arista/Cisco/JunOS, the command must start with `show`. For FortiOS, the
command must start with `get`. Append `| json` for structured output where
supported, or `| no-more` to disable pagination for text output.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `command` | string | yes | — | The operational read command to run |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, or `fortios`; see [Platform detection](#platform-detection) |

Example commands:

```text
show bgp summary | json
show interfaces status | json
show lldp neighbors detail | json
show inventory | json
show version | json
show ip route | json
get system status
get router info routing-table all
```

> `show running-config` and `show startup-config` are not allowed here — use
> the `get_config` tool instead.
>
> On FortiOS, `show`, `config`, `execute`, and `diagnose` commands are blocked
> here. Use `get_config`, `run_ping`, or `run_traceroute` instead.

The command must be a single line holding a single command (no `;`), may not
use `<` or `>` redirection, and may only pipe into output filters. Filters that write files, send messages or run
other commands (such as `save`, `redirect`, `tee` and `append`) are refused.
The allowed filters are:

| `device_type` | Allowed after `\|` |
| --- | --- |
| `eos` | `json`, `no-more`, `include`, `exclude`, `begin`, `section` |
| `ios` | `include`, `exclude`, `begin`, `section`, `count` |
| `nxos` | the `ios` filters, plus `json`, `json-pretty`, `xml`, `no-more`, `grep`, `egrep`, `last`, `head` |
| `junos` | `display json`/`xml`/`set`, `no-more`, `match`, `except`, `count`, `last`, `find`, `trim` |
| `fortios` | `grep` |
| not set | the `eos` and `ios` filters combined |

A `|` inside a filter's pattern is read as another pipe, so use separate
filters rather than regular-expression alternation. A literal `;` cannot be
sent either. The closest filter is the regular-expression wildcard `.`, which
matches any single character: `| include foo.bar` matches `foo;bar`, but also
`foo-bar` or `foo bar`, so it can return extra lines. Include more of the
surrounding text in the pattern to narrow it.

### `run_ping`

Runs a ping command on network device and returns the output.
Useful for verifying reachability from the device's
perspective — for example, testing connectivity to a BGP peer, next-hop, or
management target.

The command syntax follows the platform (`device_type`, or detected). On FortiOS,
the tool uses `execute ping-options ...`, runs `execute ping`, then resets the
options within the same SSH session.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `destination` | string | yes | — | IP address or hostname to ping |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `count` | int | no | — | Number of echo requests to send |
| `timeout` | int | no | — | Per-probe timeout in seconds; supported on FortiOS |
| `source` | string | no | — | Source IP address or interface name |
| `vrf` | string | no | — | VRF name |
| `size` | int | no | — | Packet size in bytes |
| `outgoing_interface` | string | no | — | Outgoing interface; supported on FortiOS |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, or `fortios` — controls ping syntax |

`destination`, `source`, `vrf` and `outgoing_interface` may only contain
letters, digits and `. _ : / @ % -`, which covers addresses, hostnames and
interface names. Anything else is refused before the device is contacted.

FortiOS limitations:

- `vrf` is not supported in this tool for FortiOS 7.4+.
- `| json` is not supported for FortiOS operational output.

### `run_traceroute`

Shows the hop-by-hop path from the device to a destination and per-hop latency.
Useful for locating where connectivity breaks, verifying traffic follows the
expected path, and identifying which hop introduces latency.

The command syntax follows the platform (`device_type`, or detected). On IOS,
`vrf` is placed before the destination in the command. On FortiOS, the tool uses `execute traceroute-options ...`,
runs `execute traceroute`, then resets the options within the same SSH session.

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
| `outgoing_interface` | string | no | — | Outgoing interface; supported on FortiOS |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, or `fortios` — controls traceroute syntax |

The same character restrictions as `run_ping` apply to `destination`, `source`,
`vrf` and `outgoing_interface`.

FortiOS limitations:

- `vrf`, `max_hops`, and `timeout` are not supported in this tool for FortiOS 7.4+.
- `| json` is not supported for FortiOS operational output.

### `detect_platform`

Identifies a device's platform and returns the `device_type` to pass to the other tools, using the same probe and
cache as [Platform detection](#platform-detection). Useful before working through a list of hosts.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `refresh` | bool | no | `false` | Ignore a cached result and probe the device again |

Example result:

```text
device_type: junos
version: 23.4R2.13 (reported by the device)
ssh_server: SSH-2.0-OpenSSH_7.5 (reported by the device)
detected: now, over SSH
Pass device_type=junos on later calls to this host to skip detection.
```

### `trust_host_key`

Fetches the SSH host key currently presented by a device and optionally adds it
to the configured `known_hosts` file. Use it in two steps:

1. Call with `confirm=false` to inspect the current fingerprint.
2. After verifying that fingerprint out of band, call again with
   `confirm=true` to write it to `known_hosts`.

If a device host key has legitimately changed, call with
`replace_existing=true` after verifying the new fingerprint.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `port` | int | no | 22 | SSH port |
| `confirm` | bool | no | `false` | When `false`, only inspect the current key; when `true`, write it |
| `replace_existing` | bool | no | `false` | Replace an existing mismatched key after verification |

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

## Host Key Verification

SSH host key verification is enabled by default. The server uses the current
user's OpenSSH `known_hosts` file:

- macOS and Linux: `~/.ssh/known_hosts`
- Windows: `%USERPROFILE%\\.ssh\\known_hosts`

You can override the path with either:

- command-line flag: `--known-hosts /path/to/known_hosts`
- environment variable: `SSH_KNOWN_HOSTS`

If a device is not present in `known_hosts`, tool calls fail with a clear error
that includes the presented fingerprint and suggests using `trust_host_key`.

As OpenSSH does, the server first asks a device for the host key types already
stored for it in `known_hosts`, so a device with several host keys (for example
ECDSA and ed25519) is checked against the key you trusted rather than reported
as a mismatch. For a device with nothing stored, it prefers ed25519, then ECDSA,
then RSA, also as OpenSSH does, so that is the key `trust_host_key` shows.

DSA (`ssh-dss`) host keys are refused because they are cryptographically weak. A
device that offers only a DSA host key cannot be connected to or trusted. A DSA
key stored in `known_hosts` is never asked for; if the device presents another
key, it is reported as a mismatch so you can replace the stored DSA key.

To disable host key verification entirely, use either:

- command-line flag: `--insecure-skip-host-key-check`
- environment variable: `SKIP_HOST_KEY_CHECK=true`

Disabling verification is insecure and should only be used as a temporary
escape hatch.

## Command timeout

Each device command may run for at most 60 seconds, counted from when the SSH session is requested. A device that
accepts a command but never answers — for example one that ignores SSH exec requests — fails with a timeout error
instead of blocking the tool call. Raise the limit for very large configurations with either:

- command-line flag: `--command-timeout 2m`
- environment variable: `SSH_COMMAND_TIMEOUT=2m`

`run_ping` and `run_traceroute` wait on the network rather than the device, so they get at least 5 minutes: a
traceroute towards an unreachable destination can take minutes to give up. A longer `--command-timeout` applies to
them too.

The SSH handshake, including authentication, has its own 15-second limit.

If the MCP client cancels a tool call, for example because it gave up waiting, the server closes the device
connection straight away, at whatever stage it has reached, instead of running on until one of these limits.

## Installation

### macOS (Homebrew)

```bash
brew install --cask krisiasty/tap/netdev-ssh-mcp
```

The binary is installed to `$(brew --prefix)/bin/netdev-ssh-mcp`. The prefix
depends on the Mac architecture:

| Architecture | Path |
| --- | --- |
| Apple Silicon (M1/M2/M3/M4) | `/opt/homebrew/bin/netdev-ssh-mcp` |
| Intel | `/usr/local/bin/netdev-ssh-mcp` |

Run `brew --prefix` to confirm which applies to your machine.

### Build from source

Requires Go 1.26 or later.

```bash
go build -o netdev-ssh-mcp .
```

To install the binary to `/usr/local/bin` after building (macOS and Linux):

```bash
sudo install -m 0755 netdev-ssh-mcp /usr/local/bin/
```

## Integration

In the examples below, replace `<path-to-binary>` with the full path to the
binary. If installed via Homebrew, run `brew --prefix` to determine the correct
path (`/opt/homebrew` on Apple Silicon, `/usr/local` on Intel), then append
`/bin/netdev-ssh-mcp`.

Replace `<path-to-key-file>` with the absolute path to your obfuscation key
file. Create one before configuring the server — see
[Obfuscation key](#obfuscation-key). Without it the server uses a random key
for each run, so obfuscated secrets cannot be compared across sessions.

### Claude Code

Add a project-local `.mcp.json` at the root of your repository:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "<path-to-binary>",
      "env": {
        "OBFUSCATION_KEY_FILE": "<path-to-key-file>"
      }
    }
  }
}
```

With a default username:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "<path-to-binary>",
      "env": {
        "DEVICE_USERNAME": "admin",
        "OBFUSCATION_KEY_FILE": "<path-to-key-file>"
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
      "command": "<path-to-binary>",
      "env": {
        "DEVICE_USERNAME": "admin",
        "DEVICE_PASSWORD": "mysecret",
        "OBFUSCATION_KEY_FILE": "<path-to-key-file>"
      }
    }
  }
}
```

Alternatively, register the server globally with the Claude Code CLI:

```bash
claude mcp add netdev-ssh-mcp -e OBFUSCATION_KEY_FILE=<path-to-key-file> -- <path-to-binary>
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "<path-to-binary>",
      "env": {
        "OBFUSCATION_KEY_FILE": "<path-to-key-file>"
      }
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
      "command": "<path-to-binary>",
      "env": {
        "DEVICE_USERNAME": "admin",
        "SSH_AUTH_SOCK": "/private/tmp/com.apple.launchd.XXXXX/Listeners",
        "OBFUSCATION_KEY_FILE": "<path-to-key-file>"
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
      "command": "<path-to-binary>",
      "env": {
        "DEVICE_USERNAME": "admin",
        "DEVICE_PASSWORD": "mysecret",
        "OBFUSCATION_KEY_FILE": "<path-to-key-file>"
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
`run_show_command` output. The `run_ping` and `run_traceroute` tools are not
affected — their output contains no sensitive values.

Each secret is replaced with a token of the form `[h:<12 hex digits>]`: a
truncated HMAC-SHA256 of the secret under an obfuscation key. Without the key,
a token cannot be checked against guessed values, so short secrets such as SNMP
communities cannot be recovered from the output.

> **Obfuscation is best-effort.** Secrets are found by matching known
> configuration syntax for each supported platform. A secret in syntax the
> server does not recognise — a new or rarely used command, an unusual
> platform version, or free-form `show` output — can appear in clear text.
> Treat tool output as sensitive even with obfuscation on, and review it before
> sharing it further. If you find a secret that is not obfuscated, please
> report it privately as described in [SECURITY.md](SECURITY.md) rather than
> in a public issue.

### Obfuscation key

**Supply your own key.** Generate a random key file once:

```bash
mkdir -p ~/.config
(umask 077 && openssl rand -hex 32 > ~/.config/netdev-ssh-mcp.key)
```

Then point the server at it with `--obfuscation-key-file` or the
`OBFUSCATION_KEY_FILE` environment variable (as in the
[Integration](#integration) examples), or pass the key itself in the
`OBFUSCATION_KEY` environment variable. Set only one. The value is trimmed of
surrounding whitespace and must be at least 16 bytes. The server only reads the
key and never writes it anywhere.

The same key gives the same tokens on every machine, so share the key file to
compare output collected on different machines or by different people.

If you supply no key, the server generates a random key in memory for each
run. That is safe — the key never leaves the process, so tokens cannot be
checked against guessed values — but tokens only match within one server run.
Tokens from earlier sessions, other machines or other people are not
comparable. While no key is configured, the server:

- logs a warning on every start,
- tells the calling agent in its MCP server instructions,
- appends a short note to every `get_config` and `run_show_command` result
  that contains obfuscated secrets, suggesting that you configure a key.

Tokens produced by v1.6.6 and earlier were unkeyed and are not comparable with
current tokens.

### Disabling obfuscation

To disable obfuscation, pass `--no-obfuscate`:

```bash
netdev-ssh-mcp --no-obfuscate
```

In an MCP config file, pass it via `args`:

```json
{
  "mcpServers": {
    "netdev-ssh-mcp": {
      "command": "<path-to-binary>",
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
