package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/netdev"
	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

func main() {
	knownHostsDefault, err := sshclient.DefaultKnownHostsPath()
	if err != nil {
		knownHostsDefault = ""
	}
	if envPath := strings.TrimSpace(os.Getenv(sshclient.EnvKnownHostsPath)); envPath != "" {
		knownHostsDefault = envPath
	}
	skipHostKeyValidationDefault, err := envBool(sshclient.EnvSkipHostKeyValidation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s: %v\n", sshclient.EnvSkipHostKeyValidation, err)
		os.Exit(1)
	}

	noObfuscate := flag.Bool("no-obfuscate", false, "disable obfuscation of sensitive values in tool output")
	knownHostsPath := flag.String("known-hosts", knownHostsDefault, "path to OpenSSH known_hosts file used for SSH host verification")
	skipHostKeyValidation := flag.Bool("insecure-skip-host-key-check", skipHostKeyValidationDefault, "disable SSH host key verification (insecure)")
	printVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("version: %s\ncommit: %s\ndate: %s\n", version, commit, date)
		return
	}

	if *noObfuscate {
		netdev.Obfuscate = false
	}
	if err := sshclient.Configure(sshclient.Options{
		KnownHostsPath:           *knownHostsPath,
		InsecureSkipHostKeyCheck: *skipHostKeyValidation,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "configure ssh client: %v\n", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	})))

	slog.Info("starting netdev-ssh-mcp",
		"version", version,
		"commit", commit,
		"date", date,
	)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "netdev-ssh-mcp",
		Version: version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_config",
		Description: "Connect to an Arista, Cisco Nexus, Cisco Catalyst, or Juniper JunOS device via SSH and retrieve its " +
			"running or startup configuration. Sensitive values (passwords, secrets, SNMP community names, " +
			"BGP/OSPF/TACACS/RADIUS/IKE keys) are automatically obfuscated with deterministic hashes, " +
			"allowing safe comparison across devices. " +
			"Set device_type='junos' for Juniper routers — this issues 'show configuration' instead of " +
			"'show running-config'. JunOS does not support config_type='startup'.",
	}, netdev.GetConfig)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_show_command",
		Description: "Connect to an Arista, Cisco Nexus, Cisco Catalyst, or Juniper JunOS device via SSH and run a show command. " +
			"The command must start with 'show'. " +
			"Running-config and startup-config are not allowed here — use the get_config tool instead. " +
			"For JunOS, set device_type='junos'; 'show configuration' is also blocked and redirected to get_config. " +
			"Append '| json' for structured output (Arista/Cisco), or '| no-more' to disable pagination. " +
			"Examples: 'show bgp summary | json', 'show interfaces status | json', " +
			"'show lldp neighbors detail | json', 'show inventory | json', 'show version | json'.",
	}, netdev.RunShowCommand)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_ping",
		Description: "Connect to an Arista, Cisco Nexus, Cisco Catalyst, or Juniper JunOS device via SSH and run a ping command. " +
			"Useful for verifying reachability from the device's perspective — for example, testing connectivity " +
			"to a BGP peer, next-hop, or management target. " +
			"Use device_type to select the correct syntax: 'eos' (Arista), 'ios' (Cisco IOS/IOS-XE), 'nxos' " +
			"(Cisco NX-OS), or 'junos' (Juniper JunOS). If device_type is omitted, EOS/IOS syntax is used. " +
			"Optional parameters: count (number of probes), source (source IP or interface), " +
			"vrf (VRF or routing-instance name on JunOS), size (packet size in bytes).",
	}, netdev.RunPing)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_traceroute",
		Description: "Connect to an Arista, Cisco Nexus, Cisco Catalyst, or Juniper JunOS device via SSH and run a traceroute. " +
			"Shows the hop-by-hop path to a destination and per-hop latency. " +
			"Useful for locating where connectivity breaks, verifying traffic follows the expected path, " +
			"and identifying which hop introduces latency. " +
			"Use device_type to select the correct syntax: 'eos' (Arista), 'ios' (Cisco IOS/IOS-XE), 'nxos' " +
			"(Cisco NX-OS), or 'junos' (Juniper JunOS). On IOS, vrf must be specified via device_type='ios' " +
			"so it is placed correctly before the destination in the command. " +
			"On JunOS, max_hops maps to the ttl keyword, timeout maps to wait, probe is not supported, " +
			"and vrf maps to routing-instance. " +
			"Optional parameters: max_hops, timeout (per-probe seconds), probe (probes per hop, not used on JunOS), " +
			"source (source IP or interface), vrf (routing-instance on JunOS).",
	}, netdev.RunTraceroute)

	mcp.AddTool(server, &mcp.Tool{
		Name: "trust_host_key",
		Description: "Fetch the SSH host key currently presented by a device and optionally add it to the configured known_hosts file. " +
			"Call it first with confirm=false to inspect the fingerprint, then call it again with confirm=true after the user verifies the fingerprint. " +
			"If a host key has legitimately changed, set replace_existing=true to replace the stored key after verification.",
	}, netdev.TrustHostKey)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func envBool(name string) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("expected boolean value, got %q", value)
	}
	return parsed, nil
}
