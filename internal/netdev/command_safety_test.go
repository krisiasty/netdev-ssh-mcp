package netdev

import (
	"context"
	"strings"
	"testing"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

func TestNormalizeOperationalCommandBlocksInjection(t *testing.T) {
	tests := []struct {
		name    string
		dt      deviceType
		command string
		wantErr string
	}{
		// Extra lines would run as separate commands.
		{"eos newline", deviceTypeEOS, "show version\nconfigure terminal", "single line"},
		{"ios carriage return", deviceTypeIOS, "show version\rreload", "single line"},
		{"nxos crlf", deviceTypeNXOS, "show version\r\nconfigure terminal", "single line"},
		{"junos newline", deviceTypeJunos, "show version\nrequest system reboot", "single line"},
		{"fortios newline", deviceTypeFortiOS, "get system status\nconfig system admin", "single line"},
		{"unicode line separator", deviceTypeEOS, "show version configure terminal", "single line"},
		{"nul byte", deviceTypeEOS, "show version\x00", "single line"},
		{"tab", deviceTypeEOS, "show\tversion", "single line"},

		// Some CLIs treat ";" as a command separator.
		{"ios semicolon", deviceTypeIOS, "show version ; configure terminal", "';'"},
		{"nxos semicolon", deviceTypeNXOS, "show version;configure terminal", "';'"},
		{"eos semicolon", deviceTypeEOS, "show version ; reload", "';'"},
		{"junos semicolon", deviceTypeJunos, "show version ; request system reboot", "';'"},
		{"fortios semicolon", deviceTypeFortiOS, "get system status ; execute reboot", "';'"},
		{"no type semicolon", "", "show version ; configure terminal", "';'"},
		{"semicolon inside pipe", deviceTypeIOS, "show version | include x;configure terminal", "';'"},

		// Redirection writes files on the device.
		{"nxos redirect", deviceTypeNXOS, "show version > bootflash:out.txt", "redirection"},
		{"eos append redirect", deviceTypeEOS, "show version >> flash:out.txt", "redirection"},
		{"input redirect", deviceTypeIOS, "show version < flash:x", "redirection"},

		// Pipes that write files, send messages or run commands.
		{"junos save", deviceTypeJunos, "show version | save /var/tmp/out", "not allowed"},
		{"junos append", deviceTypeJunos, "show version | append /var/tmp/out", "not allowed"},
		{"junos request", deviceTypeJunos, "show version | request message all message hi", "not allowed"},
		{"junos display bad", deviceTypeJunos, "show version | display omit", "display"},
		{"eos redirect pipe", deviceTypeEOS, "show version | redirect flash:out.txt", "not allowed"},
		{"eos tee", deviceTypeEOS, "show version | tee flash:out.txt", "not allowed"},
		{"ios append", deviceTypeIOS, "show version | append flash:out.txt", "not allowed"},
		{"ios redirect", deviceTypeIOS, "show version | redirect tftp://192.0.2.1/x", "not allowed"},
		{"nxos tee", deviceTypeNXOS, "show version | tee bootflash:out.txt", "not allowed"},
		{"no type redirect", "", "show version | redirect flash:out.txt", "not allowed"},
		{"empty pipe", deviceTypeEOS, "show version |", "empty pipe"},
		{"empty pipe in middle", deviceTypeEOS, "show version || json", "empty pipe"},

		// The verb must be a whole word.
		{"verb prefix only", deviceTypeEOS, "showx version", "must start with 'show'"},
		{"fortios verb prefix only", deviceTypeFortiOS, "getx system status", "must start with 'get'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeOperationalCommand(tt.command, tt.dt)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("normalizeOperationalCommand(%q, %q) = %q, %v; want error containing %q", tt.command, tt.dt, got, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeOperationalCommandAllowsReads(t *testing.T) {
	tests := []struct {
		name    string
		dt      deviceType
		command string
	}{
		{"eos json", deviceTypeEOS, "show bgp summary | json"},
		{"eos include no-more", deviceTypeEOS, "show interfaces status | include connected | no-more"},
		{"ios section", deviceTypeIOS, "show ip interface brief | include up"},
		{"ios count", deviceTypeIOS, "show ip route | count via"},
		{"nxos json-pretty", deviceTypeNXOS, "show version | json-pretty"},
		{"nxos grep", deviceTypeNXOS, "show interface brief | grep Eth1/1"},
		{"junos display json", deviceTypeJunos, "show interfaces terse | display json"},
		{"junos match no-more", deviceTypeJunos, "show route | match 10.0.0 | no-more"},
		{"fortios get", deviceTypeFortiOS, "get system status"},
		{"fortios grep", deviceTypeFortiOS, "get router info routing-table all | grep 10.0.0"},
		{"no type json", "", "show version | json"},
		{"no type section", "", "show ip route | section 10.0.0.0"},
		{"uppercase verb", deviceTypeEOS, "SHOW version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeOperationalCommand(tt.command, tt.dt); err != nil {
				t.Fatalf("normalizeOperationalCommand(%q, %q) error = %v", tt.command, tt.dt, err)
			}
		})
	}
}

func TestBuildCommandsRejectUnsafeArgs(t *testing.T) {
	bad := []string{
		"192.0.2.1\nconfigure terminal",
		"192.0.2.1\rreload",
		"192.0.2.1 vrf mgmt",
		"192.0.2.1|save x",
		"192.0.2.1>x",
		`"192.0.2.1"`,
		"192.0.2.1;reload",
		strings.Repeat("a", maxArgLen+1),
	}
	platforms := []deviceType{"", deviceTypeEOS, deviceTypeIOS, deviceTypeNXOS, deviceTypeJunos, deviceTypeFortiOS}

	for _, dt := range platforms {
		for _, v := range bad {
			// vrf is rejected on FortiOS for other reasons, so it is only
			// checked on the other platforms.
			cases := map[string][4]string{
				"destination": {v, "", "", ""},
				"source":      {"192.0.2.1", v, "", ""},
			}
			if dt == deviceTypeFortiOS {
				cases["outgoing_interface"] = [4]string{"192.0.2.1", "", "", v}
			} else {
				cases["vrf"] = [4]string{"192.0.2.1", "", v, ""}
			}
			for field, a := range cases {
				if _, err := buildPingCommands(a[0], dt, 0, 0, 0, a[1], a[2], a[3]); err == nil {
					t.Errorf("buildPingCommands %s=%q on %q: want error", field, v, dt)
				}
				if _, err := buildTracerouteCommands(a[0], dt, 0, 0, 0, a[1], a[2], a[3]); err == nil {
					t.Errorf("buildTracerouteCommands %s=%q on %q: want error", field, v, dt)
				}
			}
		}
	}
}

func TestCheckCommandArgAllowsRealValues(t *testing.T) {
	for _, v := range []string{
		"192.0.2.1", "2001:db8::1", "fe80::1%eth0", "router-1.example.net",
		"Ethernet1/1", "GigabitEthernet0/0.100", "ae0.0", "port-channel10",
		"MGMT", "mgmt_vrf", "Loopback0", "user@host",
	} {
		if err := checkCommandArg("destination", v); err != nil {
			t.Errorf("checkCommandArg(%q) error = %v", v, err)
		}
	}
}

// A refused command must never reach the device.
func TestRunShowCommandInjectionNeverReachesSSH(t *testing.T) {
	original := runCommand
	defer func() { runCommand = original }()
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
		t.Fatalf("runCommand called with %q", cmd)
		return "", nil
	}

	_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{
		Host:       "192.0.2.10",
		Username:   "admin",
		Command:    "show version\nconfigure terminal",
		DeviceType: "eos",
	})
	if err == nil {
		t.Fatal("RunShowCommand() error = nil, want injection rejected")
	}
}

func TestRunPingInjectionNeverReachesSSH(t *testing.T) {
	originalOne, originalMany := runCommand, runCommands
	defer func() { runCommand, runCommands = originalOne, originalMany }()
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
		t.Fatalf("runCommand called with %q", cmd)
		return "", nil
	}
	runCommands = func(cfg sshclient.ConnConfig, cmds []string) (string, error) {
		t.Fatalf("runCommands called with %q", cmds)
		return "", nil
	}

	for _, dt := range []string{"eos", "fortios"} {
		_, _, err := RunPing(context.Background(), nil, RunPingInput{
			Host:        "192.0.2.10",
			Username:    "admin",
			Destination: "192.0.2.1\nconfig system admin",
			DeviceType:  dt,
		})
		if err == nil {
			t.Fatalf("RunPing(%s) error = nil, want injection rejected", dt)
		}
	}
}
