package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp-mcp/internal/netdev"
)

func main() {
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
