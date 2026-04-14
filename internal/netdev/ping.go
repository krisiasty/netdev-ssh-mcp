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

// RunPingInput defines the input parameters for the run_ping tool.
type RunPingInput struct {
	Host        string `json:"host"        jsonschema:"hostname or IP address of the network device to connect to"`
	Destination string `json:"destination" jsonschema:"IP address or hostname to ping"`
	Username    string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port        int    `json:"port"        jsonschema:"SSH port, defaults to 22"`
	Count       int    `json:"count"       jsonschema:"number of echo requests to send"`
	Source      string `json:"source"      jsonschema:"source IP address or interface name"`
	VRF         string `json:"vrf"         jsonschema:"VRF name"`
	Size        int    `json:"size"        jsonschema:"packet size in bytes"`
	DeviceType  string `json:"device_type" jsonschema:"device type controlling ping syntax: eos (Arista), ios (Cisco IOS/IOS-XE), or nxos (Cisco NX-OS); defaults to eos/ios syntax if omitted"`
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
	dt := strings.ToLower(args.DeviceType)
	if dt != "" && dt != "eos" && dt != "ios" && dt != "nxos" {
		return nil, nil, fmt.Errorf("device_type must be 'eos', 'ios', or 'nxos', got %q", args.DeviceType)
	}
	if args.Count < 0 {
		return nil, nil, fmt.Errorf("count must be a positive integer")
	}
	if args.Size < 0 {
		return nil, nil, fmt.Errorf("size must be a positive integer")
	}

	cmd := buildPingCommand(args.Destination, dt, args.Count, args.Size, args.Source, args.VRF)

	slog.Info("run_ping", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "cmd", sanitizeLog(cmd)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := sshclient.RunCommand(sshclient.ConnConfig{
		Host:     args.Host,
		Port:     args.Port,
		Username: args.Username,
	}, cmd)
	if err != nil {
		slog.Error("run_ping failed", "host", args.Host, "destination", args.Destination, "err", err)
		return nil, nil, fmt.Errorf("run_ping: %w", err)
	}

	slog.Info("run_ping done", "host", args.Host, "bytes", len(out))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: out}},
	}, nil, nil
}

func buildPingCommand(destination, deviceType string, count, size int, source, vrf string) string {
	parts := []string{"ping", destination}
	nxos := deviceType == "nxos"

	if count > 0 {
		if nxos {
			parts = append(parts, "count", fmt.Sprintf("%d", count))
		} else {
			parts = append(parts, "repeat", fmt.Sprintf("%d", count))
		}
	}
	if size > 0 {
		if nxos {
			parts = append(parts, "packet-size", fmt.Sprintf("%d", size))
		} else {
			parts = append(parts, "size", fmt.Sprintf("%d", size))
		}
	}
	if source != "" {
		parts = append(parts, "source", source)
	}
	if vrf != "" {
		parts = append(parts, "vrf", vrf)
	}

	return strings.Join(parts, " ")
}
