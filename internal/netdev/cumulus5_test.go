package netdev

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

func TestNormalizeCumulus5Command(t *testing.T) {
	tests := []struct {
		command string
		want    string
		wantErr string
	}{
		{command: "nv show interface", want: "nv show interface 2>&1"},
		{command: "nv show interface swp1 link", want: "nv show interface swp1 link 2>&1"},
		{command: "nv show  vrf default router bgp neighbor", want: "nv show  vrf default router bgp neighbor 2>&1"},
		{command: "nv show system snmp-server", want: "nv show system snmp-server 2>&1"},
		{command: "nv show system snmp-server -o json", want: "nv show system snmp-server -o json 2>&1"},
		{command: "nv show interface -o json", want: "nv show interface -o json 2>&1"},
		{command: "nv show system snmp-server username", want: "nv show system snmp-server username 2>&1"},
		{command: "nv show system aaa user", want: "nv show system aaa user 2>&1"},
		{command: "nv show router policy community-list", want: "nv show router policy community-list 2>&1"},

		{command: "nv set interface swp1", wantErr: "must start with 'nv show'"},
		{command: "nv config show", wantErr: "must start with 'nv show'"},
		{command: "nv action reboot system", wantErr: "must start with 'nv show'"},
		{command: "nv", wantErr: "must start with 'nv show'"},
		{command: "show interface", wantErr: "must start with 'nv show'"},
		{command: "NV SHOW interface", wantErr: "must start with 'nv show'"},

		{command: "nv show -o json interface", wantErr: "only '-o json' at the end"},
		{command: "nv show interface -o yaml", wantErr: "only '-o json' at the end"},
		{command: "nv show interface -o JSON", wantErr: "only '-o json' at the end"},
		{command: "nv show interface -ojson", wantErr: "only '-o json' at the end"},
		{command: "nv show interface --output json", wantErr: "only '-o json' at the end"},
		{command: "nv show interface -o", wantErr: "only '-o json' at the end"},
		{command: "nv show interface --color off", wantErr: "only '-o json' at the end"},

		{command: "nv show interface;id", wantErr: "may only contain"},
		{command: "nv show interface | grep x", wantErr: "may only contain"},
		{command: "nv show 'interface'", wantErr: "may only contain"},
		{command: "nv show interface > /tmp/x", wantErr: "may only contain"},

		{command: "nv show system snmp-server readonly-community", wantErr: "secret"},
		{command: "nv show system snmp-server readwrite-community public", wantErr: "secret"},
		{command: "nv show system snmp-server READONLY-COMMUNITY", wantErr: "secret"},
		{command: "nv show system snmp-server trap-destination 10.0.0.1 community-password", wantErr: "secret"},
		{command: "nv show system snmp-server username monitor auth-sha", wantErr: "secret"},
		{command: "nv show system snmp-server username monitor auth-md5", wantErr: "secret"},
		{command: "nv show system snmp-server username monitor encrypt-aes", wantErr: "secret"},
		{command: "nv show system snmp-server username monitor encrypt-des", wantErr: "secret"},
		{command: "nv show vrf default router bgp neighbor swp51 password", wantErr: "secret"},
		{command: "nv show system aaa user admin hashed-password", wantErr: "secret"},
		{command: "nv show system aaa radius server 10.0.0.9 secret", wantErr: "secret"},
		{command: "nv show interface swp1 router ospf authentication md5-key", wantErr: "secret"},
		{command: "nv show system aaa tacacs shared-secret", wantErr: "secret"},
		{command: "nv show x enable-password", wantErr: "secret"},
		{command: "nv show system snmp-server readonly-comm", wantErr: "secret"},
		{command: "nv show system snmp-server username u auth-s", wantErr: "secret"},
		{command: "nv show vrf default router bgp neighbor swp51 pass", wantErr: "secret"},
		{command: "nv show system aaa user admin hashed", wantErr: "secret"},
		{command: "nv show system snmp-server readonly-community -o json", wantErr: "secret"},
		{command: "nv show system snmp-server readonly-community-v6", wantErr: "secret"},
		{command: "nv show system snmp-server readwrite-community-v6 public", wantErr: "secret"},
		{command: "nv show system snmp-server readonly-community-v", wantErr: "secret"},
		{command: "nv show service snmp-server readonly-community", wantErr: "secret"},
		{command: "nv show interface swp1 link", want: "nv show interface swp1 link 2>&1"},
		{command: "nv show sys conf", wantErr: "to retrieve device configuration"},
		{command: "nv show sy con", wantErr: "to retrieve device configuration"},
		{command: "nv show system  config", wantErr: "to retrieve device configuration"},
		{command: "nv show System Config", wantErr: "to retrieve device configuration"},
		// "s" abbreviates "secret", so the secret check refuses it first.
		{command: "nv show s c", wantErr: `path word "s" may show a secret`},
		{command: "nv show system aaa user secretary", wantErr: `path word "secretary" may show a secret`},
		{command: "nv show interface\nnv set x", wantErr: "may only contain"},
		{command: "nv show interface\tx", wantErr: "may only contain"},
		{command: "nv show x -o json", want: "nv show x -o json 2>&1"},

		{command: "nv show system config", wantErr: "to retrieve device configuration"},
		{command: "nv show system config snippet", wantErr: "to retrieve device configuration"},
		// The JSON of the whole tree and of "system" holds the snippets too.
		{command: "nv show -o json", wantErr: "to retrieve device configuration"},
		{command: "nv show system -o json", wantErr: "to retrieve device configuration"},
		{command: "nv show sys -o json", wantErr: "to retrieve device configuration"},
		{command: "nv show", want: "nv show 2>&1"},
		{command: "nv show system", want: "nv show system 2>&1"},
		{command: "nv show system snmp-server -o json", want: "nv show system snmp-server -o json 2>&1"},

		// Words joined with '/' or ',' are checked part by part.
		{command: "nv show system snmp-server/readonly-community", wantErr: "secret"},
		{command: "nv show system/snmp-server/readwrite-comm", wantErr: "secret"},
		{command: "nv show interface swp1,password", wantErr: "secret"},
		{command: "nv show system/config", wantErr: "to retrieve device configuration"},
		{command: "nv show interface swp1,swp2", want: "nv show interface swp1,swp2 2>&1"},
		{command: "nv show vrf default router rib ipv4 route 10.0.0.0/8", want: "nv show vrf default router rib ipv4 route 10.0.0.0/8 2>&1"},

		// NTP authentication keys hold their secret in a "value" row.
		{command: "nv show service ntp mgmt key", wantErr: "NTP authentication keys"},
		{command: "nv show service ntp mgmt key 1", wantErr: "NTP authentication keys"},
		{command: "nv show serv nt default k 1", wantErr: "NTP authentication keys"},
		{command: "nv show service/ntp/default/key/1", wantErr: "NTP authentication keys"},
		{command: "nv show service ntp mgmt server", want: "nv show service ntp mgmt server 2>&1"},
		{command: "nv show service ntp mgmt -o json", want: "nv show service ntp mgmt -o json 2>&1"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, err := normalizeCumulus5Command(tt.command)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("normalizeCumulus5Command(%q) error = %v, want substring %q", tt.command, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCumulus5Command(%q) unexpected error: %v", tt.command, err)
			}
			if got != tt.want {
				t.Errorf("normalizeCumulus5Command(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestCheckCommandOnAnyPlatformNVUE(t *testing.T) {
	if err := checkCommandOnAnyPlatform("nv show interface"); err != nil {
		t.Errorf("nv show interface: unexpected error %v", err)
	}
	err := checkCommandOnAnyPlatform("nv set x")
	if err == nil || !strings.Contains(err.Error(), "must start with 'nv show'") {
		t.Errorf("nv set x: error = %v, want must start with 'nv show'", err)
	}
}

func TestNormalizeOperationalCommandCumulus5x(t *testing.T) {
	got, err := normalizeOperationalCommand("  nv show interface ", deviceTypeCumulus5x)
	if err != nil || got != "nv show interface 2>&1" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := normalizeOperationalCommand("net show interface", deviceTypeCumulus5x); err == nil {
		t.Error("net show accepted on cumulus5x")
	}
}

func TestStripANSI(t *testing.T) {
	if got := stripANSI("\x1b[1mpassword\x1b[0m  FAKE"); got != "password  FAKE" {
		t.Errorf("stripANSI = %q", got)
	}
	if got := stripANSI("plain text\n"); got != "plain text\n" {
		t.Errorf("stripANSI = %q", got)
	}
	if got := stripANSI("a\x1bb"); got != "ab" {
		t.Errorf("lone ESC: stripANSI = %q", got)
	}
}

func TestRunDeviceCommandStripsANSIOnCumulus5x(t *testing.T) {
	const coloured = "\x1b[1mpassword\x1b[0m  FAKE"
	for _, tt := range []struct {
		dt   deviceType
		want string
	}{
		{deviceTypeCumulus5x, "password  FAKE"},
		{deviceTypeCumulus4x, coloured},
		{deviceTypeEOS, coloured},
	} {
		stubRunCommand(t, coloured, &sshclient.CommandError{Command: "c", ExitStatus: 1, Output: []byte(coloured)})
		out, err := runDeviceCommand(context.Background(), sshclient.ConnConfig{}, tt.dt, "c")
		var cmdErr *sshclient.CommandError
		if !errors.As(err, &cmdErr) {
			t.Fatalf("%s: error = %v, want a CommandError", tt.dt, err)
		}
		if out != tt.want || string(cmdErr.Output) != tt.want {
			t.Errorf("%s: output %q, error output %q, want %q", tt.dt, out, cmdErr.Output, tt.want)
		}
	}
}

func TestCumulus5CommandErrorEphemeralKeyNotice(t *testing.T) {
	savedKey, savedSource := obfuscationKey, obfuscationKeySource
	defer func() { obfuscationKey, obfuscationKeySource = savedKey, savedSource }()

	base := errors.New("exit status 1")
	tests := []struct {
		name       string
		source     string
		output     string
		wantNotice bool
	}{
		{name: "ephemeral key with token", source: KeySourceEphemeral, output: "Error: x\nmd5-key  $nvsec$FAKE01ab\n", wantNotice: true},
		{name: "ephemeral key without token", source: KeySourceEphemeral, output: "Error: Invalid path\n"},
		{name: "env key with token", source: KeySourceEnv, output: "Error: x\nmd5-key  $nvsec$FAKE01ab\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetObfuscationKey([]byte(testObfuscationKey), tt.source)
			err := cumulus5CommandError(deviceTypeCumulus5x, &sshclient.CommandError{Command: "c", Err: base, ExitStatus: 1, Output: []byte(tt.output)})
			msg := err.Error()
			if strings.Contains(msg, "FAKE") {
				t.Fatalf("secret leaked in error: %s", msg)
			}
			if got := strings.Contains(msg, EphemeralKeyNotice); got != tt.wantNotice {
				t.Errorf("error %q contains EphemeralKeyNotice = %v, want %v", msg, got, tt.wantNotice)
			}
		})
	}
}
