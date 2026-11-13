package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// FortigateListVDOMsInput defines the input parameters for the
// fortigate_list_vdoms tool.
type FortigateListVDOMsInput struct {
	Host     string `json:"host"     jsonschema:"hostname or IP address of the FortiGate"`
	Username string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port     int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
}

// FortigateListVDOMs lists the VDOMs the account can reach on a FortiGate.
func FortigateListVDOMs(ctx context.Context, req *mcp.CallToolRequest, args FortigateListVDOMsInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}

	cfg, rt, err := resolveTarget(ctx, args.Host, args.Port, args.Username, "")
	if err != nil {
		return nil, nil, fmt.Errorf("fortigate_list_vdoms: %w", err)
	}
	if rt.dt != deviceTypeFortiOS {
		return nil, nil, fmt.Errorf("fortigate_list_vdoms: %q is not a FortiGate: its device_type is %s", args.Host, rt.dt)
	}

	slog.Info("fortigate_list_vdoms", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	info, err := listVDOMs(ctx, cfg)
	if err != nil {
		logFailure(ctx, "fortigate_list_vdoms", err, "host", args.Host)
		return nil, nil, runError(ctx, "fortigate_list_vdoms", cfg, rt, err)
	}
	slog.Info("fortigate_list_vdoms done", "host", args.Host, "vdoms", len(info.names))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: vdomReport(info)}},
	}, nil, nil
}

// vdomReport formats vdomInfo. The names come from the device and passed
// vdomNameRe.
func vdomReport(info vdomInfo) string {
	var b strings.Builder
	if !info.enabled {
		b.WriteString("This FortiGate does not use VDOMs, or this account cannot reach them; omit vdom on the other tools.")
		if info.current != "" {
			fmt.Fprintf(&b, "\nCurrent virtual domain: %s (reported by the device)", info.current)
		}
		return b.String()
	}
	b.WriteString("VDOMs this account can reach (reported by the device):\n")
	for _, name := range info.names {
		b.WriteString(name)
		if name == info.current {
			b.WriteString(" (sessions start here)")
		}
		b.WriteByte('\n')
	}
	b.WriteString("Pass one of these as vdom to get_config, run_show_command, run_ping or run_traceroute")
	if info.current != "" && slices.Contains(info.names, info.current) {
		fmt.Fprintf(&b, "; without vdom, commands run in %s", info.current)
	}
	b.WriteString(".")
	return b.String()
}
