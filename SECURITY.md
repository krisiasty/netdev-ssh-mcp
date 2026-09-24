# Security policy

## Reporting a vulnerability

Report it privately through GitHub, not as an issue: open the repository's
**Security** tab and choose **Report a vulnerability**. That opens a private
advisory only the maintainers can see, so the problem is not public before there
is a fix.

Please do not open a public issue, a pull request, or a discussion for anything
you believe is a security problem.

Include enough to reproduce it: the output of `netdev-ssh-mcp --version`, which
names the version, the commit and the build date; the platform and
`device_type`; the MCP client; the tool call that shows the problem; and what an
attacker would gain. Use made-up values in examples. Never include a real device
configuration, password, key, SNMP community or obfuscation key, and remove
hostnames, addresses and usernames from any logs you attach.

**Response is best effort.** netdev-ssh-mcp is maintained by one person
alongside other work. Reports are read and taken seriously, but no response time
is promised.

## Supported versions

The latest release. Fixes go into a new release rather than being backported.

## What counts as a vulnerability

netdev-ssh-mcp connects to network devices with the caller's credentials on
behalf of an AI agent, and promises two things: it only runs read-only
operations, and it hides secrets in what it returns. The classes below are in
scope:

- **Anything beyond a single read-only operation.** Input to any tool that makes
  a device run an additional command, change its configuration or state, write
  a file, or send data anywhere — for example through line breaks, command
  separators, output pipes or redirection.
- **Secret disclosure in tool output.** A password, key or SNMP community from
  `get_config` or `run_show_command` output left in clear text, or recoverable
  from its token without the obfuscation key.
- **Obfuscation key exposure.** The key appearing in logs, tool output or
  errors, or being written anywhere.
- **Credential disclosure.** `DEVICE_PASSWORD` or other credentials appearing
  in logs, tool output or errors.
- **Host key verification defeated.** An unknown or changed host key accepted
  while verification is enabled, or `trust_host_key` writing to `known_hosts`
  without `confirm=true`.
- **Log injection** through tool arguments.

## What is not a vulnerability

These are documented, deliberate, and opt-in. Reporting them is welcome as an
issue, not as an advisory:

- Secrets in output with `--no-obfuscate`, or unverified host keys with
  `--insecure-skip-host-key-check` / `SKIP_HOST_KEY_CHECK=true`.
- Tokens that do not match across runs when no obfuscation key is configured.
- A secret in syntax that obfuscation does not recognise yet. Obfuscation is
  best-effort; please still report it privately, because it is fixed like a
  vulnerability, but it does not break a documented guarantee.
- The device password, obfuscation key or SSH agent being readable by the
  process that has to use them, or by whoever controls the MCP client
  configuration or the environment.
- What a device account is permitted to read. The server does not enforce
  device-side privileges; use accounts with read-only privileges.
- Anything that requires root on the host the server runs on, or write access to
  its configuration.

## What netdev-ssh-mcp already does

So a report need not re-cover this ground:

- `run_show_command` accepts a single command on a single line — no control
  characters, no `;`, no `<`/`>` redirection — and pipes only into a
  per-platform allowlist of output filters. Ping and traceroute arguments are
  limited to letters, digits and `. _ : / @ % -`. Refused input never reaches
  the device.
- Secrets are replaced with HMAC-SHA256 tokens under an obfuscation key. The key
  is only read, never logged or written; without one, a random key held in
  memory is used for each run. Obfuscation fails closed if no key is set.
- Host key verification is on by default against the user's `known_hosts`, and
  `trust_host_key` only writes after an explicit `confirm=true`.
- The device password is read from the environment and never logged. Logged
  tool arguments are stripped of control characters.
- CI runs `golangci-lint` (including `gosec`), CodeQL, `govulncheck` and the
  test suite on every push and pull request, and `govulncheck` weekly.

## Scope

This policy covers netdev-ssh-mcp itself: the binary, the Homebrew cask, and the
documentation and examples in this repository. It does not cover the network
devices, their operating systems, the MCP clients, or the models that call the
server.

## Past advisories

Published advisories are listed on the repository's
[security advisories](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories)
page.
