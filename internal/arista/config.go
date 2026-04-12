package arista

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/arista-ssh-mcp/internal/sshclient"
)

// GetConfigInput defines the input parameters for the get_config tool.
type GetConfigInput struct {
	Host       string `json:"host"        jsonschema:"hostname or IP address of the Arista switch"`
	Username   string `json:"username"    jsonschema:"SSH username"`
	Port       int    `json:"port"        jsonschema:"SSH port, defaults to 22"`
	ConfigType string `json:"config_type" jsonschema:"configuration type: running (default) or startup"`
}

// GetConfig retrieves the running or startup configuration from an Arista switch.
func GetConfig(ctx context.Context, req *mcp.CallToolRequest, args GetConfigInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required")
	}

	configType := args.ConfigType
	if configType == "" {
		configType = "running"
	}
	if configType != "running" && configType != "startup" {
		return nil, nil, fmt.Errorf("config_type must be 'running' or 'startup', got %q", configType)
	}

	cmd := fmt.Sprintf("show %s-config | no-more", configType)

	slog.Info("get_config", "host", args.Host, "user", args.Username, "config_type", configType)

	out, err := sshclient.RunCommand(sshclient.ConnConfig{
		Host:     args.Host,
		Port:     args.Port,
		Username: args.Username,
	}, cmd)
	if err != nil {
		slog.Error("get_config failed", "host", args.Host, "err", err)
		return nil, nil, fmt.Errorf("get_config: %w", err)
	}

	slog.Info("get_config done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}
