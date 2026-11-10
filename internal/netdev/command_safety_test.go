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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeOperationalCommand(tt.command, tt.dt); err != nil {
				t.Fatalf("normalizeOperationalCommand(%q, %q) error = %v", tt.command, tt.dt, err)
			}
		})
	}
}

// On a Linux system, such as Cumulus Linux, a shell runs the exec request.
// Shell syntax must be refused on every platform, so a wrong device_type
// cannot turn a show command into a shell command. This table pins the
// whole set, including constructs refused by the older checks.
func TestNormalizeOperationalCommandRefusesShellSyntax(t *testing.T) {
	commands := map[deviceType]string{
		deviceTypeEOS:     "show version",
		deviceTypeIOS:     "show version",
		deviceTypeNXOS:    "show version",
		deviceTypeJunos:   "show version",
		deviceTypeFortiOS: "get system status",
	}
	tests := []struct {
		suffix  string
		wantErr string
	}{
		{" & net del all & net commit", "shell syntax"},
		{" && net del all", "shell syntax"},
		{" |& net del all", "shell syntax"},
		{" `id`", "shell syntax"},
		{" $(net del all)", "shell syntax"},
		{" $((1))", "shell syntax"},
		{" ${HOME}", "shell syntax"},
		{" x&y", "shell syntax"},
		{" <(id)", "redirection"},
		{" >(id)", "redirection"},
		{" << EOF", "redirection"},
		{" ; id", "';'"},
		{"\nid", "single line"},
		{" || id", "empty pipe"},
	}
	for dt, base := range commands {
		for _, tt := range tests {
			command := base + tt.suffix
			got, err := normalizeOperationalCommand(command, dt)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want error containing %q", command, dt, got, err, tt.wantErr)
			}
		}
	}
}

// Several allowed filters are also Linux programs (grep, egrep, head, last),
// where an option can read files or change behaviour, and bash expands many
// constructs into a leading "-". Filter arguments are therefore allowlisted
// on every platform; each bypass found in review is pinned here against each
// platform's filters.
func TestNormalizeOperationalCommandRefusesFilterArguments(t *testing.T) {
	filters := []struct {
		dt     deviceType
		prefix string
	}{
		{deviceTypeEOS, "show version | include"},
		{deviceTypeIOS, "show version | include"},
		{deviceTypeNXOS, "show version | grep"},
		{deviceTypeNXOS, "show version | egrep"},
		{deviceTypeNXOS, "show version | head"},
		{deviceTypeNXOS, "show version | last"},
		{deviceTypeJunos, "show version | match"},
		{deviceTypeJunos, "show version | last"},
		{deviceTypeFortiOS, "get system status | grep"},
	}
	words := []string{
		// Options, plain or spelled through quotes and escapes.
		"-f", "-r FAKE /", "FAKE -r /", `"-f"`, `'-f'`, `\-f`, `a\-f`,
		// Unset or empty parameters before a "-".
		"$x-r", "$1-f", `"$1"-f`, "$@-f", "$!-f", "$NOPE--file=/etc/shadow",
		// Arithmetic, globbing, brace expansion, ANSI-C and locale quoting, tilde.
		"$[-1]f", "$[-1]0", "[-]*", "?r", "*", "{-f,}", "x{1,3}", `$'\x2df'`, `$"-r"`, "~", "~-",
		// Quotes are refused even around harmless text.
		"'up$'", `"a b"`,
	}
	for _, f := range filters {
		for _, w := range words {
			command := f.prefix + " " + w + " x"
			got, err := normalizeOperationalCommand(command, f.dt)
			if err == nil || !strings.Contains(err.Error(), "pipe filter arguments") {
				t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want the filter argument refused", command, f.dt, got, err)
			}
		}
	}
}

// The verb must be exactly "show", or "get" on FortiOS: on a Linux system
// GET is lwp-request, which fetches URLs.
func TestNormalizeOperationalCommandRequiresLowerCaseVerb(t *testing.T) {
	tests := []struct {
		dt      deviceType
		command string
		wantErr string
	}{
		{deviceTypeEOS, "SHOW version", "lower case"},
		{deviceTypeIOS, "Show version", "lower case"},
		{deviceTypeNXOS, "SHOW version", "lower case"},
		{deviceTypeJunos, "Show version", "lower case"},
		{deviceTypeFortiOS, "GET http://192.0.2.1/ | grep x", "lower case"},
		{deviceTypeFortiOS, "Get system status", "lower case"},
		// FortiOS still routes the other lower-case verbs to their tools.
		{deviceTypeFortiOS, "show full-configuration", "get_config"},
		{deviceTypeFortiOS, "config system admin", "configuration mode"},
		{deviceTypeFortiOS, "execute ping 192.0.2.1", "run_ping"},
		{deviceTypeFortiOS, "diagnose sys top", "diagnose"},
	}
	for _, tt := range tests {
		got, err := normalizeOperationalCommand(tt.command, tt.dt)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want error containing %q", tt.command, tt.dt, got, err, tt.wantErr)
		}
	}
}

// JunOS "| find" is not allowed: on a Linux system it is find(1), which can
// run programs and delete files.
func TestNormalizeOperationalCommandRefusesJunosFind(t *testing.T) {
	for _, command := range []string{"show log messages | find bgp", "show version | find / -exec id +", "show version | find / -delete"} {
		got, err := normalizeOperationalCommand(command, deviceTypeJunos)
		if err == nil || !strings.Contains(err.Error(), "pipe '| find' is not allowed") {
			t.Errorf("normalizeOperationalCommand(%q, junos) = %q, %v; want '| find' refused", command, got, err)
		}
	}
}

func TestNormalizeOperationalCommandAllowsFilters(t *testing.T) {
	tests := []struct {
		dt      deviceType
		command string
	}{
		{deviceTypeEOS, "show interfaces | include up$"},
		{deviceTypeEOS, "show interfaces status | include Ethernet1/1"},
		{deviceTypeIOS, "show ip route | include 10.0.0.1"},
		{deviceTypeIOS, "show ip interface brief | include ^Gi.*up"},
		{deviceTypeIOS, "show interfaces | exclude down"},
		{deviceTypeIOS, "show interfaces | begin interface"},
		{deviceTypeIOS, "show version | count"},
		{deviceTypeEOS, "show ip bgp | section bgp"},
		{deviceTypeEOS, "show version | include a+b"},
		{deviceTypeEOS, "show version | include x?y"},
		{deviceTypeEOS, "show version | include key=val"},
		{deviceTypeEOS, "show version | json"},
		{deviceTypeEOS, "show version | no-more"},
		{deviceTypeNXOS, "show interface brief | include Ethernet1/1"},
		{deviceTypeNXOS, "show interface brief | grep port1"},
		{deviceTypeNXOS, "show logging | last 20"},
		{deviceTypeNXOS, "show logging | head 5"},
		{deviceTypeNXOS, "show version | json"},
		{deviceTypeJunos, "show interfaces terse | match bgp"},
		{deviceTypeJunos, "show interfaces terse | except down"},
		{deviceTypeJunos, "show interfaces terse | display json"},
		{deviceTypeJunos, "show log messages | match bgp | last 20"},
		{deviceTypeFortiOS, "get system interface | grep port1"},
		{deviceTypeIOS, "show interfaces | include up-down"},
	}
	for _, tt := range tests {
		if _, err := normalizeOperationalCommand(tt.command, tt.dt); err != nil {
			t.Errorf("normalizeOperationalCommand(%q, %q) error = %v", tt.command, tt.dt, err)
		}
	}
}

func TestNormalizeOperationalCommandAllowsRegexAnchor(t *testing.T) {
	commands := map[deviceType]string{
		deviceTypeEOS:     "show interfaces | include up$",
		deviceTypeIOS:     "show interfaces | include up$",
		deviceTypeNXOS:    "show interfaces | include up$",
		deviceTypeJunos:   "show interfaces | match up$",
		deviceTypeFortiOS: "get system interface | grep up$",
	}
	for dt, command := range commands {
		if _, err := normalizeOperationalCommand(command, dt); err != nil {
			t.Errorf("normalizeOperationalCommand(%q, %q) error = %v", command, dt, err)
		}
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
	platforms := allDeviceTypes

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
	runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
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

func TestRunShowCommandShellSyntaxNeverReachesSSH(t *testing.T) {
	ran := stubRunCommand(t, "", nil)
	resetDetection(t)
	runProbe = func(context.Context, sshclient.ConnConfig, func(string) (string, error)) (sshclient.ProbeResult, error) {
		t.Fatal("detection ran, want the command refused first")
		return sshclient.ProbeResult{}, nil
	}
	for _, command := range []string{"show x & net del all", "show `id`", "show $(net del all)"} {
		for _, dt := range []string{"eos", "ios", "nxos", "junos", ""} {
			_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{
				Host: "192.0.2.10", Username: "admin", Command: command, DeviceType: dt,
			})
			if err == nil || !strings.Contains(err.Error(), "shell syntax") {
				t.Errorf("RunShowCommand(%q, device_type %q) error = %v, want shell syntax refused", command, dt, err)
			}
		}
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %q, want nothing", *ran)
	}
}

func TestRunPingInjectionNeverReachesSSH(t *testing.T) {
	originalOne, originalMany := runCommand, runCommands
	defer func() { runCommand, runCommands = originalOne, originalMany }()
	runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
		t.Fatalf("runCommand called with %q", cmd)
		return "", nil
	}
	runCommands = func(_ context.Context, cfg sshclient.ConnConfig, cmds []string) (string, error) {
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

func TestNormalizeCumulusCommand(t *testing.T) {
	accepted := []struct{ command, want string }{
		{"net show interface", "net show interface 2>&1"},
		{"  net show bgp vrf RED summary json  ", "net show bgp vrf RED summary json 2>&1"},
		{"net show interface swp1-4,swp6", "net show interface swp1-4,swp6 2>&1"},
		{"net show route 2001:db8::/32", "net show route 2001:db8::/32 2>&1"},
		{"net show lldp swp1 json", "net show lldp swp1 json 2>&1"},
		{"net show", "net show 2>&1"},
		{"net  show   interface", "net  show   interface 2>&1"},
		{"net show counters", "net show counters 2>&1"},
		{"net show clag", "net show clag 2>&1"},
		{"net show route", "net show route 2>&1"},
	}
	for _, tt := range accepted {
		t.Run("accept "+tt.command, func(t *testing.T) {
			got, err := normalizeOperationalCommand(tt.command, deviceTypeCumulus4x)
			if err != nil || got != tt.want {
				t.Fatalf("normalizeOperationalCommand(%q) = %q, %v; want %q", tt.command, got, err, tt.want)
			}
		})
	}

	var refused []struct{ command, want string }
	add := func(want string, commands ...string) {
		for _, c := range commands {
			refused = append(refused, struct{ command, want string }{c, want})
		}
	}
	add("use the get_config tool", "net show configuration", "net show configuration commands", "net show configuration files",
		"net show conf", "net show co", "net show c", "net show commit history", "net show commit last", "net show rollback 3",
		"net show ro", "net show r", "net show Configuration")
	add("must start with 'net show'", "show version", "net add bgp neighbor swp1 password x", "net del all", "net commit",
		"NET show interface", "net SHOW interface", "sudo net show interface", "net")
	for _, ch := range []string{"'", `"`, `\`, "$", "`", ";", "&", "|", "<", ">", "(", ")", "{", "}", "[", "]", "*", "?", "~", "!", "#", "="} {
		add("may only contain", "net show inter"+ch+"face")
	}
	add("may only contain", "net show interface\tswp1", "net show interface\nswp1", "net show é", "net show interface 2>&1")
	add("must not start with '-'", "net show interface -h", "net show --help")
	for _, tt := range refused {
		t.Run("refuse "+tt.command, func(t *testing.T) {
			got, err := normalizeOperationalCommand(tt.command, deviceTypeCumulus4x)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("normalizeOperationalCommand(%q) = %q, %v; want error containing %q", tt.command, got, err, tt.want)
			}
		})
	}
}

func TestCheckCommandOnAnyPlatformCumulus(t *testing.T) {
	if err := checkCommandOnAnyPlatform("net show interface"); err != nil {
		t.Fatalf("net show interface: %v", err)
	}
	err := checkCommandOnAnyPlatform("net show interface; reboot")
	if err == nil || !strings.Contains(err.Error(), "may only contain") {
		t.Fatalf("got %v, want Cumulus allowlist error", err)
	}
}
