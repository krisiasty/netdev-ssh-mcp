package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp-mcp/internal/sshclient"
)

// GetConfigInput defines the input parameters for the get_config tool.
type GetConfigInput struct {
	Host       string `json:"host"        jsonschema:"hostname or IP address of the network device"`
	Username   string `json:"username"    jsonschema:"SSH username"`
	Port       int    `json:"port"        jsonschema:"SSH port, defaults to 22"`
	ConfigType string `json:"config_type" jsonschema:"configuration type: running (default) or startup"`
}

// GetConfig retrieves the running or startup configuration from a network device.
func GetConfig(ctx context.Context, req *mcp.CallToolRequest, args GetConfigInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}

	configType := args.ConfigType
	if configType == "" {
		configType = "running"
	}
	if configType != "running" && configType != "startup" {
		return nil, nil, fmt.Errorf("config_type must be 'running' or 'startup', got %q", configType)
	}

	cmd := fmt.Sprintf("show %s-config | no-more", configType)

	slog.Info("get_config", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "config_type", configType) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := sshclient.RunCommand(sshclient.ConnConfig{
		Host:     args.Host,
		Port:     args.Port,
		Username: args.Username,
	}, cmd)
	if err != nil {
		slog.Error("get_config failed", "host", args.Host, "err", err)
		return nil, nil, fmt.Errorf("get_config: %w", err)
	}

	out = obfuscateConfig(out)
	slog.Info("get_config done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}

// sanitizeLog strips ASCII control characters from s to prevent log injection.
func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
