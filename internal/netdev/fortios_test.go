package netdev

import (
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The byte sequences below follow what a FortiGate running FortiOS 7.4.12
// sent in an SSH exec session.
func TestFortiOSOutput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"prompt around one command", "FGT-1 $ Version: FortiGate-1100E v7.4.12\nHostname: FGT-1\n\nFGT-1 $ ", "Version: FortiGate-1100E v7.4.12\nHostname: FGT-1\n"},
		{"admin prompt", "FGT-1 # config system global\nend\n\nFGT-1 # ", "config system global\nend\n"},
		{"vdom prompt", "FGT-1 (root) $ a\n\nFGT-1 (root) $ ", "a\n"},
		{"output on the next line", "FGT-1 $ \ncommand parse error before 'x'\nCommand fail. Return code -61\n\nFGT-1 $ ", "command parse error before 'x'\nCommand fail. Return code -61\n"},
		{
			"several commands",
			"FGT-1 $ 8826: Unknown action 0\nCommand fail. Return code -1\n\nFGT-1 $ PING 192.0.2.1: 56 data bytes\n\nFGT-1 $ ",
			"8826: Unknown action 0\nCommand fail. Return code -1\n\nPING 192.0.2.1: 56 data bytes\n",
		},
		{"commands without output", "FGT-1 $ \nFGT-1 $ \nFGT-1 $ ", ""},
		{"no prompt", "Version: FortiGate-100F v7.4.4\n", "Version: FortiGate-100F v7.4.4\n"},
		{"prompt text inside a line is kept", "FGT-1 $ set comments \"FGT-1 $ x\"\n\nFGT-1 $ ", "set comments \"FGT-1 $ x\"\n"},
		{"prompt text in data is kept", "FGT-1 $ --More--\nset x\n\nFGT-1 $ ", "--More--\nset x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fortiOSOutput(tt.in)
			if err != nil || got != tt.want {
				t.Fatalf("fortiOSOutput(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

// TestFortiOSOutputRefusesPagedOutput checks that output FortiOS paged, and
// therefore cut short, is refused rather than returned incomplete.
func TestFortiOSOutputRefusesPagedOutput(t *testing.T) {
	for name, in := range map[string]string{
		"carriage return erase": "FGT-1 $ a\n--More-- \r         \r        set b\n\nFGT-1 $ ",
		"backspace erase":       "a\n--More--\b\b\b\b\b\b\b\bb\n",
		"erase-line":            "a\n--More--\x1b[Kb\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := fortiOSOutput(in); !errors.Is(err, errFortiOSPaged) || got != "" {
				t.Fatalf("fortiOSOutput(%q) = %q, %v; want errFortiOSPaged", in, got, err)
			}
		})
	}
}

// TestToolsCheckFortiOSOutput checks that every tool refuses paged FortiOS
// output, and leaves the output of other platforms alone.
func TestToolsCheckFortiOSOutput(t *testing.T) {
	paged := "a\n--More-- \r         \rb\n"
	for name, call := range commandToolCalls {
		t.Run(name, func(t *testing.T) {
			for _, d := range allDeviceTypes {
				stubRunCommandConfigs(t, paged)
				err := call(t.Context(), string(d))
				if d == deviceTypeFortiOS {
					if !errors.Is(err, errFortiOSPaged) {
						t.Fatalf("%s: error = %v, want errFortiOSPaged", d, err)
					}
				} else if err != nil {
					t.Fatalf("%s: error = %v", d, err)
				}
			}
		})
	}
}

func TestGetConfigFortiOSRemovesPrompts(t *testing.T) {
	stubRunCommandConfigs(t, "FGT-1 $ #config-version=FG10E0-7.4.12\nconfig system global\nend\n\nFGT-1 $ ")
	res, _, err := GetConfig(t.Context(), nil, GetConfigInput{Host: "fw1", Username: "u", DeviceType: "fortios"})
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if strings.Contains(text, "FGT-1 $") || !strings.HasPrefix(text, "#config-version=") {
		t.Fatalf("GetConfig() text = %q, want the configuration without the CLI prompts", text)
	}
}
