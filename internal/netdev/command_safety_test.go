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

// Every filter form of every platform is accepted, alone and chained, with
// or without spaces around "|".
func TestNormalizeOperationalCommandAcceptsFilterForms(t *testing.T) {
	tests := []struct {
		dt      deviceType
		command string
	}{
		{deviceTypeEOS, "show ip bgp summary | json"},
		{deviceTypeEOS, "show interfaces status | no-more"},
		{deviceTypeEOS, "show interfaces Ethernet1/1 status | include up"},
		{deviceTypeEOS, "show interfaces | exclude down"},
		{deviceTypeEOS, "show interfaces | begin Ethernet1"},
		{deviceTypeEOS, "show ip bgp | section bgp"},
		{deviceTypeEOS, "show interfaces status | include Ethernet | exclude down"},
		{deviceTypeEOS, "show version | include key=val,a+b@c%d"},
		{deviceTypeEOS, "show version | include foo.bar"},

		{deviceTypeIOS, "show ip interface brief | include up"},
		{deviceTypeIOS, "show interfaces | exclude down"},
		{deviceTypeIOS, "show interfaces | begin interface"},
		{deviceTypeIOS, "show ip bgp | section neighbor"},
		{deviceTypeIOS, "show ip route | count via"},
		{deviceTypeIOS, "show interfaces | include up-down"},

		{deviceTypeNXOS, "show version | json"},
		{deviceTypeNXOS, "show version | json-pretty"},
		{deviceTypeNXOS, "show version | xml"},
		{deviceTypeNXOS, "show logging | no-more"},
		{deviceTypeNXOS, "show interface brief | include Ethernet1/1"},
		{deviceTypeNXOS, "show interface brief | exclude down"},
		{deviceTypeNXOS, "show interface | begin Ethernet1/1"},
		{deviceTypeNXOS, "show interface | section Ethernet1/1"},
		{deviceTypeNXOS, "show interface brief | count"},
		{deviceTypeNXOS, "show interface brief | grep port1"},
		{deviceTypeNXOS, "show interface brief | egrep Eth1/1"},
		{deviceTypeNXOS, "show logging | head"},
		{deviceTypeNXOS, "show logging | head lines 5"},
		{deviceTypeNXOS, "show logging | last"},
		{deviceTypeNXOS, "show logging | last 50"},
		{deviceTypeNXOS, "show logging | grep bgp | last 999999"},

		{deviceTypeJunos, "show version | display json"},
		{deviceTypeJunos, "show interfaces terse | display xml"},
		{deviceTypeJunos, "show interfaces terse | display set"},
		{deviceTypeJunos, "show route | no-more"},
		{deviceTypeJunos, "show route | match 10.0.0.0/8"},
		{deviceTypeJunos, "show interfaces terse | except down"},
		{deviceTypeJunos, "show route | count"},
		{deviceTypeJunos, "show log messages | last"},
		{deviceTypeJunos, "show log messages | last 20"},
		{deviceTypeJunos, "show log messages | trim 10"},
		{deviceTypeJunos, "show log messages | match bgp | last 20"},

		{deviceTypeFortiOS, "get system interface | grep port1"},
		{deviceTypeFortiOS, "get router info routing-table all | grep 10.0.0.0/8"},

		// "|" need not be surrounded by spaces, and runs of spaces are fine.
		{deviceTypeEOS, "show interfaces|include up"},
		{deviceTypeEOS, "show interfaces |include up| no-more"},
		{deviceTypeEOS, "show  interfaces   status  |  include   up"},
		{deviceTypeFortiOS, "get system interface|grep port1"},
	}
	for _, tt := range tests {
		if got, err := normalizeOperationalCommand(tt.command, tt.dt); err != nil || got != tt.command {
			t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want it accepted unchanged", tt.command, tt.dt, got, err)
		}
	}
}

// Only the platform's filter forms are accepted after "|", each with exactly
// its arguments: no regex patterns, options, quotes, globs, expansions or
// second words. Several filters are also Linux programs (grep, egrep, head,
// last), so each shell bypass found in review is pinned here against each
// platform's filters that take a word.
func TestNormalizeOperationalCommandRefusesFilters(t *testing.T) {
	var tests []struct {
		dt      deviceType
		command string
	}
	add := func(dt deviceType, commands ...string) {
		for _, c := range commands {
			tests = append(tests, struct {
				dt      deviceType
				command string
			}{dt, c})
		}
	}

	wordFilters := []struct {
		dt     deviceType
		prefix string
	}{
		{deviceTypeEOS, "show version | include"},
		{deviceTypeEOS, "show version | section"},
		{deviceTypeIOS, "show version | include"},
		{deviceTypeIOS, "show version | count"},
		{deviceTypeNXOS, "show version | include"},
		{deviceTypeNXOS, "show version | grep"},
		{deviceTypeNXOS, "show version | egrep"},
		{deviceTypeJunos, "show version | match"},
		{deviceTypeJunos, "show version | except"},
		{deviceTypeFortiOS, "get system status | grep"},
	}
	badWords := []string{
		// Options, plain or spelled through quotes and escapes.
		"-v", "-f", "--file=/etc/shadow", `"-f"`, `'-f'`, `\-f`, `a\-f`,
		// Parameters, arithmetic, globs, brace expansion, ANSI-C and locale
		// quoting, tilde.
		"$x-r", "$1-f", `"$1"-f`, "$@-f", "$!-f", "$[-1]f", "[-]*", "?r", "*", "x*", "/etc/*",
		"{-f,}", "x{1,3}", `$'\x2df'`, `$"-r"`, "~", "~-",
		// Quotes and backslashes even around harmless text.
		"'up'", `"up"`, `up\`,
		// Regular expressions beyond '.'.
		"^Gi", "up$", "a.*b", "x?y", "(a)", "a!b", "a#b",
		// Two words.
		"a b", "x /etc/shadow", "-r FAKE /",
		// Missing argument.
		"",
	}
	for _, f := range wordFilters {
		for _, w := range badWords {
			add(f.dt, strings.TrimSpace(f.prefix+" "+w))
		}
	}

	// Filters that write files, send messages or run commands, unknown
	// filters, and names or keywords not in lower case.
	for _, dt := range []deviceType{deviceTypeEOS, deviceTypeIOS, deviceTypeNXOS, deviceTypeJunos} {
		add(dt, "show version | save /var/tmp/out", "show version | append flash:x", "show version | redirect flash:x",
			"show version | tee flash:x", "show version | request message all message hi", "show version | find x",
			"show version | tail", "show version | sh", "show version | bash", "show version | HEAD", "show version | Include x",
			"show version | JSON", "show version | GREP x", "show version | MATCH x", "show version | | json")
	}
	add(deviceTypeFortiOS, "get system status | GREP x", "get system status | Grep x", "get system status | include x",
		"get system status | sh", "get system status | head", "get system status | grep")

	// Filters that exist only on another platform.
	add(deviceTypeEOS, "show version | count", "show version | count x", "show version | grep x", "show version | head",
		"show version | match x", "show version | display json", "show version | json-pretty")
	add(deviceTypeIOS, "show version | json", "show version | no-more", "show version | count", "show version | grep x",
		"show version | last 5", "show version | match x")
	add(deviceTypeNXOS, "show version | match x", "show version | except x", "show version | display json", "show version | trim 5")
	add(deviceTypeJunos, "show version | include x", "show version | grep x", "show version | json", "show version | head",
		"show version | begin x")

	// Wrong or extra arguments.
	add(deviceTypeEOS, "show version | json x", "show version | no-more x", "show version | include a b")
	add(deviceTypeNXOS, "show version | json x", "show version | count x", "show version | head 5", "show version | head /etc/shadow",
		"show version | head lines", "show version | head lines x", "show version | head lines 5 x", "show version | head -n 5",
		"show version | head lines -5", "show version | last x", "show version | last /etc/shadow", "show version | last 1234567",
		"show version | last 5 x", "show version | last -f", "show version | grep x /etc/shadow", "show version | egrep -r x /")
	add(deviceTypeJunos, "show version | display", "show version | display omit", "show version | display json x",
		"show version | display JSON", "show version | Display json", "show version | trim", "show version | trim x",
		"show version | last x", "show version | count x", "show version | match a b")

	for _, tt := range tests {
		got, err := normalizeOperationalCommand(tt.command, tt.dt)
		if err == nil || !strings.Contains(err.Error(), "not allowed") && !strings.Contains(err.Error(), "empty pipe") &&
			!strings.Contains(err.Error(), "shell syntax") {
			t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want the filter refused", tt.command, tt.dt, got, err)
		}
	}
}

// The verb's own arguments, before the first "|", may hold "^" and "$" for
// regexes, which filter arguments may not, but every other character outside
// commandWordChars is refused there with its own message.
func TestNormalizeOperationalCommandVerbArguments(t *testing.T) {
	accepted := []struct {
		dt      deviceType
		command string
	}{
		{deviceTypeIOS, "show ip bgp regexp ^65000_"},
		{deviceTypeEOS, "show ip bgp regexp ^65000_"},
		{deviceTypeEOS, "show ip bgp regexp ^65000_ | include 10.0.0.0/8"},
		{deviceTypeIOS, "show ip bgp regexp _65000$"},
		{deviceTypeNXOS, "show interface ethernet1/1-4,1/7 status"},
		{deviceTypeEOS, "show interfaces | include up"},
		{deviceTypeIOS, "show interfaces Gi0/1 | include up"},
		{deviceTypeNXOS, "show interface Ethernet1/1 | include up"},
		{deviceTypeJunos, "show interfaces ge-0/0/0 | match up"},
		{deviceTypeFortiOS, "get system interface physical | grep up"},
	}
	for _, tt := range accepted {
		if got, err := normalizeOperationalCommand(tt.command, tt.dt); err != nil || got != tt.command {
			t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want it accepted unchanged", tt.command, tt.dt, got, err)
		}
	}

	verbs := map[deviceType]string{
		deviceTypeEOS:     "show",
		deviceTypeIOS:     "show",
		deviceTypeNXOS:    "show",
		deviceTypeJunos:   "show",
		deviceTypeFortiOS: "get",
	}
	refused := []struct {
		args    string
		wantErr string
	}{
		{"$(id)", "shell syntax"},
		{"${HOME}", "shell syntax"},
		{"`id`", "shell syntax"},
		{"a&b", "shell syntax"},
		{"a;b", "';'"},
		{"a>b", "redirection"},
		{"a<b", "redirection"},
		{"a\nb", "single line"},
		{"a\u00a0b", "spaces"},
		{"a\u3000b", "spaces"},
		{"a\u2003b", "spaces"},
		// Bash brace expansion can exhaust memory on a Linux host.
		{"{1..9}", "shell syntax"},
		{"{1..99999999}", "shell syntax"},
		{"a{b,c}", "shell syntax"},
		{"a}", "shell syntax"},
		{"x | include {a,b}", "shell syntax"},
		{"x | include a}", "shell syntax"},
		// Other shell syntax is refused by the allowlist, not by name.
		{"$[1+1]", "shell syntax"},
		{"~root", "shell syntax"},
		{"/*/*/*", "shell syntax"},
		{"a?", "shell syntax"},
		{"'a b'", "shell syntax"},
		{`"a b"`, "shell syntax"},
		{`a\b`, "shell syntax"},
		{"!1", "shell syntax"},
		{"a#b", "shell syntax"},
		{"(a)", "shell syntax"},
		{"x | include ^a", "not allowed"},
		// A "|" always starts a filter, even inside the verb's own regex.
		{"ip bgp regexp a|b", "not allowed"},
	}
	for dt, verb := range verbs {
		for _, tt := range refused {
			command := verb + " " + tt.args
			got, err := normalizeOperationalCommand(command, dt)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("normalizeOperationalCommand(%q, %q) = %q, %v; want error containing %q", command, dt, got, err, tt.wantErr)
			}
		}
	}
}

// A refused filter's error names the platform's filters and what a plain
// word may contain, so the caller can correct the command.
func TestNormalizeOperationalCommandFilterErrorListsFilters(t *testing.T) {
	tests := []struct {
		dt      deviceType
		command string
		want    []string
	}{
		{deviceTypeEOS, "show version | count", []string{"'| count'", "eos", "json, no-more, include W, exclude W, begin W, section W", "letters, digits and . _ : / , @ % + = -", "'-'"}},
		{deviceTypeIOS, "show version | json", []string{"ios", "include W, exclude W, begin W, section W, count W"}},
		{deviceTypeNXOS, "show version | head 5", []string{"nxos", "head, head lines N, last, last N", "N is a number"}},
		{deviceTypeJunos, "show version | display omit", []string{"junos", "display json, display xml, display set", "trim N"}},
		{deviceTypeFortiOS, "get system status | include x", []string{"fortios", "grep W"}},
	}
	for _, tt := range tests {
		_, err := normalizeOperationalCommand(tt.command, tt.dt)
		if err == nil {
			t.Errorf("normalizeOperationalCommand(%q, %q) error = nil", tt.command, tt.dt)
			continue
		}
		for _, w := range tt.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("normalizeOperationalCommand(%q, %q) error = %q, want it to contain %q", tt.command, tt.dt, err, w)
			}
		}
	}
}

// A command starting with "get" can only be FortiOS, so its error is the
// FortiOS one rather than EOS's "must start with 'show'".
func TestCheckCommandOnAnyPlatformGetUsesFortiOSError(t *testing.T) {
	for _, tt := range []struct{ command, want string }{
		{"get system status | grep -v x", "grep W"},
		{"get system status | grep -v x", "plain word"},
		{"get system status | include x", "filters allowed on fortios"},
		{"get system {a,b}", "shell syntax"},
		{"GET http://192.0.2.1/", "'get' in lower case"},
	} {
		err := checkCommandOnAnyPlatform(tt.command)
		if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "must start with 'show'") {
			t.Errorf("checkCommandOnAnyPlatform(%q) error = %v, want error containing %q and not the eos one", tt.command, err, tt.want)
		}
	}
}

// Without device_type a command is checked against every platform before
// detection: one that some platform accepts passes, one that none accepts
// fails.
func TestCheckCommandOnAnyPlatformFilters(t *testing.T) {
	for _, command := range []string{"show logging | last 50", "show version | display json", "get system interface | grep port1", "show ip route | count via"} {
		if err := checkCommandOnAnyPlatform(command); err != nil {
			t.Errorf("checkCommandOnAnyPlatform(%q) error = %v", command, err)
		}
	}
	for _, command := range []string{"show version | find x", "show version | include ^Gi", "show version | head /etc/shadow", "show $(id)", "show a&b", "show a;b", "get system status | grep -v x",
		"show {1..9}", "show a{b,c}", "show x | include {a,b}", "show ip bgp regexp a|b"} {
		if err := checkCommandOnAnyPlatform(command); err == nil {
			t.Errorf("checkCommandOnAnyPlatform(%q) error = nil, want refused", command)
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
		{deviceTypeFortiOS, "SHOW system interface", "lower case"},
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
	original := runCommands
	defer func() { runCommands = original }()
	runCommands = func(_ context.Context, cfg sshclient.ConnConfig, cmds []string) (string, error) {
		t.Fatalf("runCommands called with %q", cmds)
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
	runProbe = func(context.Context, sshclient.ConnConfig, func(string) (string, *sshclient.Terminal, error)) (sshclient.ProbeResult, error) {
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
	original := runCommands
	defer func() { runCommands = original }()
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

// Each word class accepts exactly letters, digits and its listed punctuation,
// and states those characters in its rule.
func TestWordClasses(t *testing.T) {
	classes := []struct {
		name  string
		class wordClass
		chars string
		rule  string
	}{
		{"arg", argChars, "._:/@%-", "letters, digits and . _ : / @ % -"},
		{"plain word", plainWordChars, "._:/,@%+=-", "letters, digits and . _ : / , @ % + = -"},
		{"command word", commandWordChars, "._:/,@%+=^$-", "letters, digits and . _ : / , @ % + = ^ $ -"},
		{"cumulus word", cumulusWordChars, "._:/,@%-", "letters, digits and . _ : / , @ % -"},
	}
	for _, tt := range classes {
		if tt.class.rule != tt.rule {
			t.Errorf("%s: rule = %q, want %q", tt.name, tt.class.rule, tt.rule)
		}
		for c := byte(0x20); c < 0x7f; c++ {
			alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			want := alnum || strings.IndexByte(tt.chars, c) >= 0
			if got := tt.class.match("a" + string(c) + "b"); got != want {
				t.Errorf("%s: match(%q) = %v, want %v", tt.name, "a"+string(c)+"b", got, want)
			}
		}
	}
}
