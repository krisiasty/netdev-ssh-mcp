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
	Port        int    `json:"port"        jsonschema:"SSH port, defaults to 22"`
	MaxHops     int    `json:"max_hops"    jsonschema:"maximum number of hops (TTL); defaults to device default (usually 30)"`
	Timeout     int    `json:"timeout"     jsonschema:"per-probe timeout in seconds"`
	Probe       int    `json:"probe"       jsonschema:"number of probes per hop"`
	Source      string `json:"source"      jsonschema:"source IP address or interface name"`
	VRF         string `json:"vrf"         jsonschema:"VRF name; maps to routing-instance on JunOS"`
	OutgoingIf  string `json:"outgoing_interface,omitempty" jsonschema:"outgoing interface for FortiOS traceroute"`
	DeviceType  string `json:"device_type" jsonschema:"device type controlling traceroute syntax: eos (Arista), ios (Cisco IOS/IOS-XE), nxos (Cisco NX-OS), junos (Juniper JunOS), or fortios (FortiGate/FortiOS)"`
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
	dt, err := normalizeDeviceType(args.DeviceType)
	if err != nil {
		return nil, nil, err
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

	commands, err := buildTracerouteCommands(args.Destination, dt, args.MaxHops, args.Timeout, args.Probe, args.Source, args.VRF, args.OutgoingIf)
	if err != nil {
		return nil, nil, err
	}
	commandLog := strings.Join(commands, "\n")

	slog.Info("run_traceroute", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "cmd", sanitizeLog(commandLog)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	var out string
	if dt == deviceTypeFortiOS {
		out, err = runCommands(connConfig(args.Host, args.Port, args.Username), commands)
	} else {
		out, err = runCommand(connConfig(args.Host, args.Port, args.Username), commands[0])
	}
	if err != nil {
		slog.Error("run_traceroute failed", "host", args.Host, "destination", args.Destination, "err", err)
		return nil, nil, fmt.Errorf("run_traceroute: %w", err)
	}

	slog.Info("run_traceroute done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}
