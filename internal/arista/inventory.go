package arista

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/arista-ssh-mcp/internal/sshclient"
)

// GetInventoryInput defines the input parameters for the get_inventory tool.
type GetInventoryInput struct {
	Host     string `json:"host"     jsonschema:"hostname or IP address of the Arista switch"`
	Username string `json:"username" jsonschema:"SSH username"`
	Port     int    `json:"port"     jsonschema:"SSH port, defaults to 22"`
}

// GetInventory retrieves hardware inventory from an Arista switch as JSON.
func GetInventory(ctx context.Context, req *mcp.CallToolRequest, args GetInventoryInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("ARISTA_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set ARISTA_USERNAME")
	}

	slog.Info("get_inventory", "host", args.Host, "user", args.Username)

	out, err := sshclient.RunCommand(sshclient.ConnConfig{
		Host:     args.Host,
		Port:     args.Port,
		Username: args.Username,
	}, "show inventory | json")
	if err != nil {
		slog.Error("get_inventory failed", "host", args.Host, "err", err)
		return nil, nil, fmt.Errorf("get_inventory: %w", err)
	}

	slog.Info("get_inventory done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}
