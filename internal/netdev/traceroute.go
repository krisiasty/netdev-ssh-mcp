package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
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
	VRF         string `json:"vrf"         jsonschema:"VRF name"`
	DeviceType  string `json:"device_type" jsonschema:"device type controlling traceroute syntax: eos (Arista), ios (Cisco IOS/IOS-XE), or nxos (Cisco NX-OS)"`
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
	dt := strings.ToLower(args.DeviceType)
	if dt != "" && dt != "eos" && dt != "ios" && dt != "nxos" {
		return nil, nil, fmt.Errorf("device_type must be 'eos', 'ios', or 'nxos', got %q", args.DeviceType)
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

	cmd := buildTracerouteCommand(args.Destination, dt, args.MaxHops, args.Timeout, args.Probe, args.Source, args.VRF)

	slog.Info("run_traceroute", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "cmd", sanitizeLog(cmd)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := sshclient.RunCommand(sshclient.ConnConfig{
		Host:     args.Host,
		Port:     args.Port,
		Username: args.Username,
	}, cmd)
	if err != nil {
		slog.Error("run_traceroute failed", "host", args.Host, "destination", args.Destination, "err", err)
		return nil, nil, fmt.Errorf("run_traceroute: %w", err)
	}

	slog.Info("run_traceroute done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}

// buildTracerouteCommand constructs the traceroute command string.
// On IOS, VRF must precede the destination; on EOS and NX-OS it follows.
func buildTracerouteCommand(destination, deviceType string, maxHops, timeout, probe int, source, vrf string) string {
	parts := []string{"traceroute"}

	if vrf != "" && deviceType == "ios" {
		parts = append(parts, "vrf", vrf)
	}

	parts = append(parts, destination)

	if maxHops > 0 {
		parts = append(parts, "maximum-hops", fmt.Sprintf("%d", maxHops))
	}
	if timeout > 0 {
		parts = append(parts, "timeout", fmt.Sprintf("%d", timeout))
	}
	if probe > 0 {
		parts = append(parts, "probe", fmt.Sprintf("%d", probe))
	}
	if source != "" {
		parts = append(parts, "source", source)
	}
	if vrf != "" && deviceType != "ios" {
		parts = append(parts, "vrf", vrf)
	}

	return strings.Join(parts, " ")
}
