package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/arista-ssh-mcp/internal/arista"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	})))

	slog.Info("starting arista-ssh-mcp")

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "arista-ssh-mcp",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_config",
		Description: "Connect to an Arista switch via SSH and retrieve its running or startup configuration.",
	}, arista.GetConfig)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_inventory",
		Description: "Connect to an Arista switch via SSH and retrieve hardware inventory as JSON.",
	}, arista.GetInventory)

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
