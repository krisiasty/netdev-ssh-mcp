package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RunTracerouteInput defines the input parameters for the run_traceroute tool.
type RunTracerouteInput struct {
	Host        string `json:"host"        jsonschema:"hostname or IP address of the network device to connect to"`
	Destination string `json:"destination" jsonschema:"IP address or hostname to trace the path to"`
	Username    string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port        int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
	MaxHops     int    `json:"max_hops,omitempty" jsonschema:"maximum number of hops (TTL); defaults to device default (usually 30)"`
	Timeout     int    `json:"timeout,omitempty" jsonschema:"per-probe timeout in seconds"`
	Probe       int    `json:"probe,omitempty" jsonschema:"number of probes per hop"`
	Source      string `json:"source,omitempty" jsonschema:"source IP address or interface name; on cumulus4x and cumulus5x an address, or an interface with a root login (on cumulus5x only on 5.0 and 5.1), not combinable with vrf"`
	VRF         string `json:"vrf,omitempty" jsonschema:"VRF name; maps to routing-instance on JunOS; on cumulus4x and cumulus5x mgmt or default, or another VRF device with a root login (on cumulus5x only on 5.0 and 5.1), not combinable with source"`
	OutgoingIf  string `json:"outgoing_interface,omitempty" jsonschema:"outgoing interface; FortiOS only"`
	DeviceType  string `json:"device_type,omitempty" jsonschema:"device OS type: eos (Arista), ios (Cisco IOS/IOS-XE), nxos (Cisco NX-OS), junos (Juniper JunOS), fortios (FortiGate/FortiOS), cumulus4x (Cumulus Linux 4.x) or cumulus5x (Cumulus Linux 5.x); if omitted, the platform is auto-detected over SSH and reported in the result"`
}

// RunTraceroute executes a traceroute command on a network device.
func RunTraceroute(ctx context.Context, req *mcp.CallToolRequest, args RunTracerouteInput) (*mcp.CallToolResult, any, error) {
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
	if args.MaxHops < 0 {
		return nil, nil, fmt.Errorf("max_hops must be a positive integer")
	}
	if args.Timeout < 0 {
		return nil, nil, fmt.Errorf("timeout must be a positive integer")
	}
	if args.Probe < 0 {
		return nil, nil, fmt.Errorf("probe must be a positive integer")
	}
	// Reject unsafe arguments before detection opens a connection.
	if err := checkCommandArgs(args.Destination, args.Source, args.VRF, args.OutgoingIf); err != nil {
		return nil, nil, err
	}

	cfg, rt, err := resolveTarget(ctx, args.Host, args.Port, args.Username, args.DeviceType)
	if err != nil {
		return nil, nil, fmt.Errorf("run_traceroute: %w", err)
	}
	commands, err := buildTracerouteCommands(args.Destination, rt.dt, args.MaxHops, args.Timeout, args.Probe, args.Source, args.VRF, args.OutgoingIf)
	if err != nil {
		return nil, nil, err
	}
	commandLog := strings.Join(commands, "\n")

	slog.Info("run_traceroute", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "cmd", sanitizeLog(commandLog)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	cfg.CommandTimeout = longCommandTimeout
	var out string
	if rt.dt == deviceTypeFortiOS {
		out, err = runCommands(ctx, cfg, commands)
	} else {
		out, err = runDeviceCommand(ctx, cfg, rt.dt, commands[0])
	}
	if err != nil {
		logFailure(ctx, "run_traceroute", err, "host", args.Host, "destination", args.Destination)
		return nil, nil, runError(ctx, "run_traceroute", cfg, rt, cumulusNetError(rt.dt, err))
	}

	slog.Info("run_traceroute done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: append([]mcp.Content{&mcp.TextContent{Text: out}}, afterRun(cfg, rt, out, nil)...),
	}, nil, nil
}
