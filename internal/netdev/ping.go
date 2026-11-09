package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RunPingInput defines the input parameters for the run_ping tool.
type RunPingInput struct {
	Host        string `json:"host"        jsonschema:"hostname or IP address of the network device to connect to"`
	Destination string `json:"destination" jsonschema:"IP address or hostname to ping"`
	Username    string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port        int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
	Count       int    `json:"count,omitempty" jsonschema:"number of echo requests to send"`
	Timeout     int    `json:"timeout,omitempty" jsonschema:"per-probe timeout in seconds; supported on FortiOS"`
	Source      string `json:"source,omitempty" jsonschema:"source IP address or interface name"`
	VRF         string `json:"vrf,omitempty" jsonschema:"VRF name"`
	Size        int    `json:"size,omitempty" jsonschema:"packet size in bytes"`
	OutgoingIf  string `json:"outgoing_interface,omitempty" jsonschema:"outgoing interface for FortiOS ping"`
	DeviceType  string `json:"device_type,omitempty" jsonschema:"device OS type: eos (Arista), ios (Cisco IOS/IOS-XE), nxos (Cisco NX-OS), junos (Juniper JunOS), or fortios (FortiGate/FortiOS); if omitted, the platform is auto-detected over SSH and reported in the result"`
}

// RunPing executes a ping command on a network device.
func RunPing(ctx context.Context, req *mcp.CallToolRequest, args RunPingInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	if args.Destination == "" {
		return nil, nil, fmt.Errorf("destination is required")
	}
	if args.Username == "" {
		args.Username = os.Getenv("DEVICE_USERNAME")
	}
	if args.Username == "" {
		return nil, nil, fmt.Errorf("username is required: pass it as a parameter or set DEVICE_USERNAME")
	}
	if args.Count < 0 {
		return nil, nil, fmt.Errorf("count must be a positive integer")
	}
	if args.Timeout < 0 {
		return nil, nil, fmt.Errorf("timeout must be a positive integer")
	}
	if args.Size < 0 {
		return nil, nil, fmt.Errorf("size must be a positive integer")
	}
	// Reject unsafe arguments before detection opens a connection.
	if err := checkCommandArgs(args.Destination, args.Source, args.VRF, args.OutgoingIf); err != nil {
		return nil, nil, err
	}

	cfg := connConfig(args.Host, args.Port, args.Username)
	rt, err := resolveDeviceType(ctx, cfg, args.DeviceType, false)
	if err != nil {
		return nil, nil, fmt.Errorf("run_ping: %w", err)
	}
	commands, err := buildPingCommands(args.Destination, rt.dt, args.Count, args.Size, args.Timeout, args.Source, args.VRF, args.OutgoingIf)
	if err != nil {
		return nil, nil, err
	}
	commandLog := strings.Join(commands, "\n")

	slog.Info("run_ping", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "cmd", sanitizeLog(commandLog)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	cfg.CommandTimeout = longCommandTimeout
	var out string
	if rt.dt == deviceTypeFortiOS {
		out, err = runCommands(ctx, cfg, commands)
	} else {
		out, err = runCommand(ctx, cfg, commands[0])
	}
	if err != nil {
		logFailure("run_ping", err, "host", args.Host, "destination", args.Destination)
		return nil, nil, runError("run_ping", cfg, rt, err)
	}

	slog.Info("run_ping done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: append([]mcp.Content{&mcp.TextContent{Text: out}}, afterRun(cfg, rt, out, nil)...),
	}, nil, nil
}
