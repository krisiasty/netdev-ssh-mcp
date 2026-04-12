package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/arista-ssh-mcp/internal/sshclient"
)

// RunShowCommandInput defines the input parameters for the run_show_command tool.
type RunShowCommandInput struct {
	Host     string `json:"host"     jsonschema:"hostname or IP address of the network device"`
	Command  string `json:"command"  jsonschema:"show command to execute, e.g. 'show bgp summary | json' or 'show interfaces status | json'"`
	Username string `json:"username" jsonschema:"SSH username"`
	Port     int    `json:"port"     jsonschema:"SSH port, defaults to 22"`
}

// RunShowCommand executes an arbitrary show command on a network device.
func RunShowCommand(ctx context.Context, req *mcp.CallToolRequest, args RunShowCommandInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}
	cmd := strings.ToLower(strings.TrimSpace(args.Command))
	if !strings.HasPrefix(cmd, "show") {
		return nil, nil, fmt.Errorf("command must start with 'show'")
	}
	if strings.HasPrefix(cmd, "show ru") || strings.HasPrefix(cmd, "show sta") {
		return nil, nil, fmt.Errorf("use the get_config tool for running-config and startup-config")
	}

	slog.Info("run_show_command", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "command", sanitizeLog(args.Command)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := sshclient.RunCommand(sshclient.ConnConfig{
		Host:     args.Host,
		Port:     args.Port,
		Username: args.Username,
	}, args.Command)
	if err != nil {
		slog.Error("run_show_command failed", "host", args.Host, "command", args.Command, "err", err)
		return nil, nil, fmt.Errorf("run_show_command: %w", err)
	}

	slog.Info("run_show_command done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}
