package netdev

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// TrustHostKeyInput defines the input parameters for the trust_host_key tool.
type TrustHostKeyInput struct {
	Host            string `json:"host"             jsonschema:"hostname or IP address of the network device"`
	Port            int    `json:"port"             jsonschema:"SSH port, defaults to 22"`
	Confirm         bool   `json:"confirm"          jsonschema:"when false, only fetch and display the presented host key; when true, add it to known_hosts"`
	ReplaceExisting bool   `json:"replace_existing" jsonschema:"replace an existing mismatched key after you verify the new fingerprint"`
}

// TrustHostKey fetches and optionally stores an SSH host key in known_hosts.
func TrustHostKey(ctx context.Context, req *mcp.CallToolRequest, args TrustHostKeyInput) (*mcp.CallToolResult, any, error) {
	if args.Host == "" {
		return nil, nil, fmt.Errorf("host is required")
	}

	port := args.Port
	if port == 0 {
		port = 22
	}

	slog.Info("trust_host_key", "host", sanitizeLog(args.Host), "port", port, "confirm", args.Confirm, "replace_existing", args.ReplaceExisting)

	if !args.Confirm {
		info, err := sshclient.InspectHostKey(args.Host, port)
		if err != nil {
			slog.Error("trust_host_key inspect failed", "host", args.Host, "port", port, "err", err)
			return nil, nil, fmt.Errorf("trust_host_key: %w", err)
		}
		text := strings.Join([]string{
			fmt.Sprintf("Fetched SSH host key for %s.", info.Address),
			fmt.Sprintf("Type: %s", info.KeyType),
			fmt.Sprintf("Fingerprint (SHA256): %s", info.FingerprintSHA256),
			fmt.Sprintf("Known hosts target: %s", info.KnownHostsPath),
			"If this fingerprint matches what you expect, call trust_host_key again with confirm=true to add it.",
		}, "\n")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: text}},
		}, nil, nil
	}

	result, err := sshclient.TrustHostKey(args.Host, port, args.ReplaceExisting)
	if err != nil {
		slog.Error("trust_host_key failed", "host", args.Host, "port", port, "err", err)
		return nil, nil, fmt.Errorf("trust_host_key: %w", err)
	}

	var summary string
	switch result.Action {
	case "already_trusted":
		summary = "The current SSH host key is already trusted."
	case "replaced":
		summary = "Replaced the stored SSH host key with the currently presented key."
	default:
		summary = "Added the currently presented SSH host key to known_hosts."
	}

	text := strings.Join([]string{
		summary,
		fmt.Sprintf("Host: %s", result.Address),
		fmt.Sprintf("Type: %s", result.KeyType),
		fmt.Sprintf("Fingerprint (SHA256): %s", result.FingerprintSHA256),
		fmt.Sprintf("Known hosts file: %s", result.KnownHostsPath),
	}, "\n")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}
