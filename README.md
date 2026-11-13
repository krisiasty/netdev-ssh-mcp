# netdev-ssh-mcp

MCP server for interacting with network devices (switches, routers, firewalls) over SSH.
Supports Arista EOS, Cisco NX-OS, Cisco IOS/IOS-XE, Juniper JunOS, FortiGate FortiOS, and Cumulus Linux 4.x.
Exposes network device operations as tools for use with Claude Code / Claude Desktop / Codex
(and other MCP clients)

## Platform detection

Every tool that talks to a device takes an optional `device_type`: `eos`, `ios`, `nxos`, `junos`, `fortios` or
`cumulus4x` (`fortigate` is accepted as an alias for `fortios`; `cumulus4x` has no alias).
Pass it when you know the platform, for example from an inventory system.

When `device_type` is omitted, the server detects the platform over SSH before running the command:

1. It reads the SSH server identification string, which narrows the candidates and picks one probe command that the
   likely platform accepts.
2. It runs that read-only probe on the same connection: `show version`, `get system status` when the server looks
   like a FortiGate, or `cat /etc/os-release` when the server identifies as Debian or Ubuntu (Cumulus Linux 4.x is
   Debian based).
3. It matches platform-specific lines at the start of the probe output: the `Arista <model>` line (EOS), `Junos:` (JunOS),
   `Cisco Nexus Operating System` (NX-OS), `Cisco IOS Software` / `Cisco IOS XE Software` (IOS), and
   `Version: FortiGate` (FortiOS). For the os-release probe, `cumulus4x` needs both `ID=cumulus-linux` and a
   `VERSION_ID` starting with `4.`, each as a whole line (quotes around the value are accepted).
   Exactly one platform must match; otherwise the call fails and asks for
   `device_type` instead of guessing.

A Cumulus Linux switch whose SSH banner does not mention Debian cannot be detected; pass `device_type=cumulus4x`.

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
obfuscation applied to successful output. The one exception is `run_ping` and `run_traceroute` on Cumulus Linux 4.x,
where Linux states the reason only in the output and the output holds no secrets; there it follows the exit status.

Some platforms are recognised and refused. The Cisco Business switch OS is recognised from the SSH identification
string before any command runs; Linux systems are identified by the `/etc/os-release` probe. Unsupported results are
not cached:

| Platform | Reason |
| --- | --- |
| Cumulus Linux 5.x | Not supported; 5.x is configured through NVUE rather than NCLU |
| Other Debian or Ubuntu based systems | Not supported; only Cumulus Linux 4.x is |
| Cisco Business switch OS (Catalyst 1200/1300, CBS) | Does not answer SSH exec requests |

## Tools

### `get_config`

Retrieves the running or startup configuration from an Arista, Cisco Nexus,
Cisco IOS/IOS-XE, Juniper JunOS, FortiGate FortiOS, or Cumulus Linux 4.x device.
Sensitive values (passwords, secrets, SNMP community names, BGP/OSPF/TACACS/RADIUS/IKE keys) are automatically
replaced with keyed hash tokens:

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
| `config_type` | string | no | `running` | `running` or `startup` (not on JunOS, FortiOS or Cumulus Linux) |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, `fortios`, or `cumulus4x`; see [Platform detection](#platform-detection) |

Cisco IOS notes:

- `device_type=ios` covers any Cisco IOS or IOS-XE device — Catalyst switches, ISR/ASR routers, and others.
- IOS does not support `| no-more`, so the config is retrieved with plain `show running-config` or
  `show startup-config`. On EOS and NX-OS, `| no-more` is appended.

FortiOS notes:

- Use `device_type=fortios` to retrieve config with `show full-configuration`.
- `fortigate` is accepted as an alias for `fortios`.
- FortiOS does not support `config_type=startup`.
- FortiOS pages output at `--More--` when the console output mode is `more`, even over SSH exec, and no per-session
  command turns that off. On `fortios` (and while detecting it) every tool answers each prompt with a space and removes
  the prompt, and what the device writes to clear it, from the output.
- A prompt is a line that holds only `--More--`, with optional whitespace around it, after which the device stops
  sending. The first prompt of a command is answered only after the device has been silent for one second, so a
  device with the pager off is never sent a key for a line of its output. Once the device has waited at a prompt, the
  later prompts of that command are answered at once, so long output costs that one second only.
- On a device with the pager on, a line of real output that holds only `--More--`, such as a line inside a multi-line
  `set buffer` or `set script` value, cannot be told from a prompt if an SSH read happens to end right after it, and
  is removed from the output. This is rare, but turning the pager off on the device rules it out and is recommended:

  ```
  config global
  config system console
      set output standard
  end
  end
  ```

  On a FortiGate without VDOMs, leave out `config global` and the last `end`. Even with the pager off, such a line is
  removed if the device pauses for more than a second right after it.

Cumulus Linux notes:

- `device_type=cumulus4x` retrieves the configuration with `net show configuration commands`, the NCLU command list.
- Cumulus Linux has no separate startup configuration, so `config_type=startup` is refused.

### `run_show_command`

Runs operational read commands on a network device and returns the output.
For Arista/Cisco/JunOS, the command must start with `show`. For FortiOS, the
command must start with `get`. For Cumulus Linux 4.x, the command must start with `net show`. Append
`| json` for structured output where
supported, or `| no-more` to disable pagination for text output.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `command` | string | yes | — | The operational read command to run |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, `fortios`, or `cumulus4x`; see [Platform detection](#platform-detection) |

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
net show interface json
```

> `show running-config` and `show startup-config` (and their abbreviations, such as `show run` or `show start`) are not
> allowed here — use the `get_config` tool instead. On JunOS, `show configuration` and its abbreviations, such as
> `show conf`, are refused too.
>
> On FortiOS, `show`, `config`, `execute`, and `diagnose` commands are blocked
> here. Use `get_config`, `run_ping`, or `run_traceroute` instead.
>
> On Cumulus Linux 4.x, `net show configuration`, `net show commit` and `net show rollback` (and their
> abbreviations) are refused here. Use `get_config` instead.

On Cumulus Linux 4.x, the command may end with `json` for structured output. It takes no pipes or redirection:
every word must contain only letters, digits and `. _ : / , @ %` and `-`, no word may start with `-`, and words are
separated by spaces. The server appends `2>&1` itself so that error messages are returned.

On the other platforms, the command must be a single line holding a single command (no `;`), must start with the
verb in lower case (`show`, or `get` on FortiOS), and may not use `<` or `>` redirection. Words are separated by
spaces, and every word may contain only letters, digits and `. _ : / , @ % + = ^ $ -`, so quotes, brackets, braces,
globs and other shell syntax are refused. `^` and `$` are there for regexes such as `show ip bgp regexp ^65000_`.

After `|` (with or without spaces around it), only the filters below are accepted, written exactly as shown, in lower
case. `W` is one plain word: letters, digits and `. _ : / , @ % + = -`, not starting with `-`. `N` is a number of up
to 6 digits. Filters can be chained, as in `show interfaces status | include Ethernet | exclude down`. Filters that
write files, send messages or run other commands (such as `save`, `redirect`, `tee`, `append` and JunOS `find`) are
refused.

| Filter after `\|` | `eos` | `ios` | `nxos` | `junos` | `fortios` |
| --- | --- | --- | --- | --- | --- |
| `json` | yes | | yes | | |
| `json-pretty`, `xml` | | | yes | | |
| `no-more` | yes | | yes | yes | |
| `include W`, `exclude W`, `begin W`, `section W` | yes | yes | yes | | |
| `count W` | | yes | | | |
| `count` | | | yes | yes | |
| `grep W` | | | yes | | yes |
| `egrep W`, `head`, `head lines N` | | | yes | | |
| `last`, `last N` | | | yes | yes | |
| `display json`, `display xml`, `display set` | | | | yes | |
| `match W`, `except W`, `trim N` | | | | yes | |

`cumulus4x` takes no filters; end the command with `json` instead. Without `device_type`, the detected platform's
filters apply.

Filter arguments cannot use regular expressions beyond `.`, because `^`, `$`, `*`, `?`, brackets, braces, quotes and
backslashes are not plain-word characters; options (`-v`) and a second word are refused too. The device still reads
`W` as a regular expression, so `.` matches any single character: `| include foo.bar` matches `foo;bar`, but also
`foo-bar` or `foo bar`, so it can return extra lines. A `|` always starts a filter, even inside a regular expression
given to the command itself. When no filter fits, run the command without one (output is obfuscated either way) and
extract what you need from the full output.

### `run_ping`

Runs a ping command on network device and returns the output.
Useful for verifying reachability from the device's
perspective — for example, testing connectivity to a BGP peer, next-hop, or
management target.

The command syntax follows the platform (`device_type`, or detected). On FortiOS,
the tool uses `execute ping-options ...`, runs `execute ping`, then resets the
options within the same SSH session. On Cumulus Linux 4.x it runs Linux `ping`:
`ping -c <count> [-s size] [-W timeout] [-I source | -I vrf] destination`, with 5 probes unless `count` is set.
`vrf=default` adds no `-I`.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `host` | string | yes | — | Hostname or IP address of the device |
| `destination` | string | yes | — | IP address or hostname to ping |
| `username` | string | no | `DEVICE_USERNAME` | SSH username |
| `port` | int | no | 22 | SSH port |
| `count` | int | no | 5 on Cumulus | Number of echo requests to send |
| `timeout` | int | no | — | Per-probe timeout in seconds; supported on FortiOS and Cumulus Linux |
| `source` | string | no | — | Source IP address or interface name |
| `vrf` | string | no | — | VRF name |
| `size` | int | no | — | Packet size in bytes |
| `outgoing_interface` | string | no | — | Outgoing interface; supported on FortiOS |
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, `fortios`, `cumulus4x`; sets ping syntax |

`destination`, `source`, `vrf` and `outgoing_interface` may only contain
letters, digits and `. _ : / @ % -`, which covers addresses, hostnames and
interface names. Anything else is refused before the device is contacted.

Cumulus Linux 4.x notes:

- `source` is an address or an interface, and `vrf` is the VRF device; both map to `-I`. `vrf` cannot be combined
  with `source`, `outgoing_interface` is not supported, and `destination`, `source` and `vrf` may not start with `-`.
- Without `vrf` or `source`, ping runs in the default VRF: Cumulus wraps `ping` in `vrf-wrapper.sh`, which moves it
  out of the management VRF the SSH login runs in, and prints a line saying so. Use `vrf=mgmt` to ping from the
  management VRF.
- Linux `ping` exits with status 1 when nothing answered. That is a normal result here: the output, with its
  statistics, is returned instead of an error. Any other failure is still an error, and carries the device output.

FortiOS limitations:

- `vrf` is not supported in this tool for FortiOS 7.4+.
- `| json` is not supported for FortiOS operational output.

### `run_traceroute`

Shows the hop-by-hop path from the device to a destination and per-hop latency.
Useful for locating where connectivity breaks, verifying traffic follows the
expected path, and identifying which hop introduces latency.

The command syntax follows the platform (`device_type`, or detected). On IOS,
`vrf` is placed before the destination in the command. On FortiOS, the tool uses `execute traceroute-options ...`,
runs `execute traceroute`, then resets the options within the same SSH session. On Cumulus Linux 4.x it runs Linux
`traceroute [--no-vrf-switch] [-m max_hops] [-w timeout] [-q probe] [-s source-ip | -i source-iface | -i vrf] destination`.

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
| `device_type` | string | no | detected | `eos`, `ios`, `nxos`, `junos`, `fortios`, `cumulus4x`; sets syntax |

The same character restrictions as `run_ping` apply to `destination`, `source`,
`vrf` and `outgoing_interface`.

Cumulus Linux 4.x notes:

- `source` with `vrf` is refused and `outgoing_interface` is not supported, as for `run_ping`.
- Without `vrf`, or with `vrf=default`, the trace runs in the default VRF: `vrf-wrapper.sh` moves it out of the
  management VRF the SSH login runs in, and prints a line saying so.
- `vrf=mgmt` becomes `--no-vrf-switch`, which keeps the trace in the login's VRF. This relies on management VRF
  being enabled, the Cumulus default; without it, the trace runs in the default VRF.
- An interface `source`, and any other `vrf`, become `-i`, which binds to the device. On Cumulus 4.x that needs a root
  login; other users get `setsockopt SO_BINDTODEVICE: Operation not permitted`. An address `source` (`-s`) works for
  any user.
- A completed trace exits with status 0 even when the destination is unreachable, so any non-zero exit status is
  reported as an error, with the device output that states the reason.

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

Sensitive values are obfuscated by default in `get_config` and `run_show_command` output. Besides each platform's
configuration syntax, which includes the Cumulus Linux 4.x NCLU commands (BGP neighbor passwords, OSPF keys, SNMP
communities and SNMPv3 keys, 802.1X RADIUS secrets) and the `snmpd.conf` and `/etc/tacplus_servers` syntax, JSON output
is covered on every platform: the value under a key that names a secret (for example `password`, `secret`, `community`
or `psk`, or any key containing `key` or `md5`, such as `tacacsKey` or `keyMaterial`) is replaced, including every key
and value nested under such a key. The value is replaced whatever its form: a JSON string or number, a bare word that is
not JSON, or a single-quoted string as in Python output; only `true`, `false` and `null` (and Python's `True`, `False`
and `None`) are kept. Only `keyId`, `keychain`, `keyChainName`, `keyType` and `keyAlgorithm` are kept, since they name a
key rather than hold it. BGP community values in JSON output (for example `show ip bgp … | json` or `net show bgp …
json`) are therefore hashed, because `community` is a secret key name; text output keeps them. The `run_ping` and
`run_traceroute` tools are not affected — their output contains no sensitive values.

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
