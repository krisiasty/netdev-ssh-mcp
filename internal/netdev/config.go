package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetConfigInput defines the input parameters for the get_config tool.
type GetConfigInput struct {
	Host       string `json:"host"        jsonschema:"hostname or IP address of the network device"`
	Username   string `json:"username,omitempty" jsonschema:"SSH username; if omitted, falls back to the DEVICE_USERNAME environment variable"`
	Port       int    `json:"port,omitempty" jsonschema:"SSH port, defaults to 22"`
	ConfigType string `json:"config_type,omitempty" jsonschema:"configuration type: running (default) or startup; startup is not supported for JunOS or FortiOS"`
	DeviceType string `json:"device_type,omitempty" jsonschema:"device OS type: eos (Arista), ios (Cisco IOS/IOS-XE), nxos (Cisco NX-OS), junos (Juniper JunOS), or fortios (FortiGate/FortiOS); if omitted, the platform is auto-detected over SSH and reported in the result"`
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

	configType, err := normalizeConfigType(args.ConfigType)
	if err != nil {
		return nil, nil, err
	}
	cfg := connConfig(args.Host, args.Port, args.Username)
	rt, err := resolveDeviceType(ctx, cfg, args.DeviceType, false)
	if err != nil {
		return nil, nil, fmt.Errorf("get_config: %w", err)
	}
	cmd, err := buildConfigCommand(configType, rt.dt)
	if err != nil {
		if rt.source != sourceExplicit {
			return nil, nil, fmt.Errorf("%w (device_type %s was auto-detected)", err, rt.dt)
		}
		return nil, nil, err
	}

	slog.Info("get_config", "host", sanitizeLog(args.Host), "user", sanitizeLog(args.Username), "config_type", configType) //nolint:gosec // G706: values are sanitized by sanitizeLog before logging

	out, err := runCommand(ctx, cfg, cmd)
	if err != nil {
		logFailure(ctx, "get_config", err, "host", args.Host)
		return nil, nil, runError(ctx, "get_config", cfg, rt, err)
	}

	res, err := obfuscatedResult(out)
	if err != nil {
		return nil, nil, fmt.Errorf("get_config: %w", err)
	}
	res.Content = append(res.Content, afterRun(cfg, rt, out, nil)...)
	slog.Info("get_config done", "host", args.Host, "bytes", len(out))
	return res, nil, nil
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
