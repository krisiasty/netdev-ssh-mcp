package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RunShowCommandInput defines the input parameters for the run_show_command tool.
type RunShowCommandInput struct {
	Host       string `json:"host"       jsonschema:"hostname or IP address of the network device"`
	Command    string `json:"command"    jsonschema:"command to execute: use 'show ...' on Arista/Cisco/JunOS or 'get ...' on FortiOS"`
	Username   string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port       int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
	DeviceType string `json:"device_type,omitempty" jsonschema:"device OS type: eos (Arista), ios (Cisco IOS/IOS-XE), nxos (Cisco NX-OS), junos (Juniper JunOS), or fortios (FortiGate/FortiOS); if omitted, the platform is auto-detected over SSH and reported in the result"`
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

	// Without device_type, detection would log in to the device first, so
	// reject a command that no platform accepts before it does. With one,
	// the platform's own check below gives the more specific message.
	if strings.TrimSpace(args.DeviceType) == "" {
		if err := checkCommandOnAnyPlatform(args.Command); err != nil {
			return nil, nil, err
		}
	}

	cfg := connConfig(args.Host, args.Port, args.Username)
	rt, err := resolveDeviceType(cfg, args.DeviceType, false)
	if err != nil {
		return nil, nil, fmt.Errorf("run_show_command: %w", err)
	}
	command, err := normalizeOperationalCommand(args.Command, rt.dt)
	if err != nil {
		if rt.source != sourceExplicit {
			return nil, nil, fmt.Errorf("%w (device_type %s was auto-detected)", err, rt.dt)
		}
		return nil, nil, err
	}

	slog.Info("run_show_command", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "command", sanitizeLog(command)) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := runCommand(cfg, command)
	if err != nil {
		slog.Error("run_show_command failed", "host", args.Host, "command", command, "err", err)
		return nil, nil, runError("run_show_command", cfg, rt, err)
	}

	res, err := obfuscatedResult(out)
	if err != nil {
		return nil, nil, fmt.Errorf("run_show_command: %w", err)
	}
	res.Content = append(res.Content, afterRun(cfg, rt, out, nil)...)
	slog.Info("run_show_command done", "host", args.Host, "bytes", len(out))
	return res, nil, nil
}
