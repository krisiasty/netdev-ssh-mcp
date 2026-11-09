package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DetectPlatformInput defines the input parameters for the detect_platform tool.
type DetectPlatformInput struct {
	Host     string `json:"host"     jsonschema:"hostname or IP address of the network device"`
	Username string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port     int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
	Refresh  bool   `json:"refresh,omitempty" jsonschema:"ignore a cached detection and probe the device again"`
}

// DetectPlatform identifies a device's platform and returns the device_type
// to pass to the other tools.
func DetectPlatform(ctx context.Context, req *mcp.CallToolRequest, args DetectPlatformInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}

	slog.Info("detect_platform", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "refresh", args.Refresh) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	rt, err := resolveDeviceType(connConfig(args.Host, args.Port, args.Username), "", args.Refresh)
	if err != nil {
		return nil, nil, fmt.Errorf("detect_platform: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: detectPlatformReport(rt)}},
	}, nil, nil
}

// detectPlatformReport formats a detection. The version and SSH server
// strings come from the device; they are sanitized and labelled as such.
func detectPlatformReport(rt resolvedType) string {
	var b strings.Builder
	fmt.Fprintf(&b, "device_type: %s\n", rt.dt)
	if rt.version != "" {
		fmt.Fprintf(&b, "version: %s (reported by the device)\n", rt.version)
	}
	if rt.serverVersion != "" {
		fmt.Fprintf(&b, "ssh_server: %s (reported by the device)\n", rt.serverVersion)
	}
	switch rt.source {
	case sourceCache:
		b.WriteString("detected: earlier, cached by this server (pass refresh=true to probe again)\n")
	default:
		b.WriteString("detected: now, over SSH\n")
	}
	fmt.Fprintf(&b, "Pass device_type=%s on later calls to this host to skip detection.", rt.dt)
	return b.String()
}
