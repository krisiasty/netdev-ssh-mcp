package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/netdev"
)

func main() {
	noObfuscate := flag.Bool("no-obfuscate", false, "disable obfuscation of sensitive values in tool output")
	printVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("version: %s\ncommit: %s\ndate: %s\n", version, commit, date)
		return
	}

	if *noObfuscate {
		netdev.Obfuscate = false
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
		Description: "Connect to an Arista, Cisco Nexus, or Cisco Catalyst switch via SSH and retrieve its " +
			"running or startup configuration. Sensitive values (passwords, secrets, SNMP community names, " +
			"BGP/OSPF/TACACS/RADIUS/IKE keys) are automatically obfuscated with deterministic hashes, " +
			"allowing safe comparison across devices.",
	}, netdev.GetConfig)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_show_command",
		Description: "Connect to an Arista, Cisco Nexus, or Cisco Catalyst switch via SSH and run a show command. " +
			"The command must start with 'show'. " +
			"Running-config and startup-config are not allowed here — use the get_config tool instead. " +
			"Append '| json' for structured output where supported, or '| no-more' to disable pagination for text output. " +
			"Examples: 'show bgp summary | json', 'show interfaces status | json', " +
			"'show lldp neighbors detail | json', 'show inventory | json', 'show version | json'.",
	}, netdev.RunShowCommand)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_ping",
		Description: "Connect to an Arista, Cisco Nexus, or Cisco Catalyst switch via SSH and run a ping command. " +
			"Useful for verifying reachability from the device's perspective — for example, testing connectivity " +
			"to a BGP peer, next-hop, or management target. " +
			"Use device_type to select the correct syntax: 'eos' (Arista), 'ios' (Cisco IOS/IOS-XE), or 'nxos' " +
			"(Cisco NX-OS). If device_type is omitted, EOS/IOS syntax is used (repeat, size keywords). " +
			"Optional parameters: count (number of probes), source (source IP or interface), " +
			"vrf (VRF name), size (packet size in bytes).",
	}, netdev.RunPing)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_traceroute",
		Description: "Connect to an Arista, Cisco Nexus, or Cisco Catalyst switch via SSH and run a traceroute. " +
			"Shows the hop-by-hop path to a destination and per-hop latency. " +
			"Useful for locating where connectivity breaks, verifying traffic follows the expected path, " +
			"and identifying which hop introduces latency. " +
			"Use device_type to select the correct syntax: 'eos' (Arista), 'ios' (Cisco IOS/IOS-XE), or 'nxos' " +
			"(Cisco NX-OS). On IOS, vrf must be specified via device_type='ios' so it is placed correctly " +
			"before the destination in the command. " +
			"Optional parameters: max_hops, timeout (per-probe seconds), probe (probes per hop), " +
			"source (source IP or interface), vrf.",
	}, netdev.RunTraceroute)

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
