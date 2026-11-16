package netdev

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// resultTexts returns the text of every content block in res.
func resultTexts(res *mcp.CallToolResult) []string {
	var texts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			texts = append(texts, t.Text)
		}
	}
	return texts
}

func TestNormalizeLogSince(t *testing.T) {
	accepted := map[string]string{
		"":                    "-1h",
		"   ":                 "-1h",
		"-15min":              "-15min",
		" -1h ":               "-1h",
		"-1h30min":            "-1h30min",
		"-2d":                 "-2d",
		"-90s":                "-90s",
		"-1week":              "-1week",
		"-3hours":             "-3hours",
		"-10m":                "-10m",
		"today":               "today",
		"yesterday":           "yesterday",
		"2026-11-16":          "2026-11-16",
		"2026-11-16 08:30":    "2026-11-16 08:30",
		"2026-11-16 08:30:15": "2026-11-16 08:30:15",
		"2024-02-29 23:59:59": "2024-02-29 23:59:59",
	}
	for in, want := range accepted {
		got, err := normalizeLogSince(in)
		if err != nil || got != want {
			t.Errorf("normalizeLogSince(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	rejected := []string{
		"1h",                      // relative needs the leading '-'
		"+1h",                     // the future is not useful
		"-1",                      // no unit
		"-h",                      // no number
		"-1M",                     // months are not accepted
		"-1y",                     // nor years
		"-1 h",                    // no spaces in a relative time
		"-1h ago",                 // no "ago" form
		"-1234567s",               // more than 6 digits
		"Today",                   // systemd keywords are lower case
		"now",                     // not in the keyword list
		"2026-02-30",              // impossible date
		"2026-11-16 24:00",        // impossible time
		"2026-11-16T08:30",        // ISO 'T' separator is not accepted
		"2026-11-16  08:30",       // two spaces
		"2026-11-16 8:30",         // single-digit hour
		"2026-11-16 08:30:15 UTC", // no timezone suffix
		"-1h'; reboot; echo '",    // quote breaking out
		"-1h$(reboot)",            // command substitution
		"-1h`reboot`",             // backticks
		"-1h\nreboot",             // newline
		"-1h;reboot",              // separator
		"-1h|cat",                 // pipe
		"-1h>/tmp/x",              // redirection
		"-1h -u ssh",              // a second option
		strings.Repeat("-1h", 30), // too long
	}
	for _, in := range rejected {
		if got, err := normalizeLogSince(in); err == nil {
			t.Errorf("normalizeLogSince(%q) = %q, want an error", in, got)
		}
	}
}

func TestNormalizeLogLines(t *testing.T) {
	for in, want := range map[int]int{0: defaultLogLines, 1: 1, 100: 100, maxLogLines: maxLogLines} {
		if got, err := normalizeLogLines(in); err != nil || got != want {
			t.Errorf("normalizeLogLines(%d) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, n := range []int{-1, maxLogLines + 1} {
		if got, err := normalizeLogLines(n); err == nil {
			t.Errorf("normalizeLogLines(%d) = %d, want an error", n, got)
		}
	}
}

func TestBuildLogsCommand(t *testing.T) {
	tests := []struct {
		name  string
		dt    deviceType
		unit  string
		since string
		lines int
		want  string
		err   string
	}{
		{name: "lines", dt: deviceTypeCumulus4x, unit: "clagd", since: "-15min", lines: 100,
			want: "journalctl -u clagd --since '-15min' --lines 100 --no-pager 2>&1"},
		{name: "absolute since", dt: deviceTypeCumulus4x, unit: "switchd", since: "2026-11-16 08:30", lines: 1000,
			want: "journalctl -u switchd --since '2026-11-16 08:30' --lines 1000 --no-pager 2>&1"},
		{name: "lines not normalized", dt: deviceTypeCumulus4x, unit: "switchd", since: "-1h", err: "out of range"},
		{name: "unit not on platform", dt: deviceTypeCumulus4x, unit: "sshd", since: "-1h", lines: 10, err: `unit "sshd" is not allowed on cumulus4x`},
		{name: "platform without units", dt: deviceTypeEOS, unit: "clagd", since: "-1h", err: "supports no log units on eos"},
		{name: "unresolved", dt: "", unit: "clagd", since: "-1h", err: "not resolved"},
		{name: "quote guard", dt: deviceTypeCumulus4x, unit: "clagd", since: "-1h'", lines: 10, err: "quotes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildLogsCommand(tt.dt, tt.unit, tt.since, tt.lines)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("buildLogsCommand() = %q, %v; want error containing %q", got, err, tt.err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("buildLogsCommand() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestGetLogsRunsJournalctl(t *testing.T) {
	ran := stubRunCommand(t, "-- Logs begin at Mon 2026-11-16 07:00:00 UTC. --\nNov 16 08:00:01 sw1 clagd[812]: peer is alive\n", nil)
	res, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host:       "sw1",
		Username:   "netops",
		DeviceType: "cumulus4x",
		Unit:       " clagd ",
		Since:      "-15min",
		Lines:      100,
	})
	if err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}
	want := "journalctl -u clagd --since '-15min' --lines 100 --no-pager 2>&1"
	if len(*ran) != 1 || (*ran)[0] != want {
		t.Fatalf("ran %q, want [%q]", *ran, want)
	}
	texts := resultTexts(res)
	if len(texts) != 1 || !strings.Contains(texts[0], "peer is alive") {
		t.Fatalf("result = %q, want only the log output", texts)
	}
}

func TestGetLogsDefaults(t *testing.T) {
	ran := stubRunCommand(t, "-- No entries --\n", nil)
	if _, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host: "sw1", Username: "netops", DeviceType: "cumulus4x", Unit: "switchd",
	}); err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}
	want := "journalctl -u switchd --since '-1h' --lines 1000 --no-pager 2>&1"
	if len(*ran) != 1 || (*ran)[0] != want {
		t.Fatalf("ran %q, want [%q]", *ran, want)
	}
}

func TestGetLogsObfuscatesOutput(t *testing.T) {
	stubRunCommand(t, "Nov 16 08:00:01 sw1 clagd[812]: loaded key\n-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEKEYMATERIAL\n-----END RSA PRIVATE KEY-----\n", nil)
	res, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host: "sw1", Username: "netops", DeviceType: "cumulus4x", Unit: "clagd",
	})
	if err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}
	if text := strings.Join(resultTexts(res), "\n"); strings.Contains(text, "MIIFAKEKEYMATERIAL") {
		t.Fatalf("result leaks the key: %q", text)
	}
}

func TestGetLogsRejectsBeforeConnecting(t *testing.T) {
	resetDetection(t)
	probe := &fakeProbe{ident: identCumulus}
	runProbe = probe.probe
	ran := stubRunCommand(t, "", nil)

	tests := []struct {
		name string
		args GetLogsInput
		err  string
	}{
		{name: "no unit", args: GetLogsInput{Host: "sw1", Username: "u"}, err: "unit is required"},
		{name: "unknown unit", args: GetLogsInput{Host: "sw1", Username: "u", Unit: "sshd"}, err: "allowed units are cumulus4x: clagd, switchd"},
		{name: "unit injection", args: GetLogsInput{Host: "sw1", Username: "u", Unit: "clagd; reboot"}, err: "is not allowed"},
		{name: "bad since", args: GetLogsInput{Host: "sw1", Username: "u", Unit: "clagd", Since: "-1h'; reboot'"}, err: "since must be"},
		{name: "negative lines", args: GetLogsInput{Host: "sw1", Username: "u", Unit: "clagd", Lines: -5}, err: "lines must be"},
		{name: "too many lines", args: GetLogsInput{Host: "sw1", Username: "u", Unit: "clagd", Lines: maxLogLines + 1}, err: "lines must be"},
		{name: "no host", args: GetLogsInput{Username: "u", Unit: "clagd"}, err: "host is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := GetLogs(context.Background(), nil, tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("GetLogs() error = %v, want %q", err, tt.err)
			}
		})
	}
	if probe.calls != 0 || len(*ran) != 0 {
		t.Fatalf("probe calls = %d, commands = %q; want no connection", probe.calls, *ran)
	}
}

func TestGetLogsRefusesPlatformWithoutUnits(t *testing.T) {
	ran := stubRunCommand(t, "", nil)
	_, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host: "rtr1", Username: "u", DeviceType: "eos", Unit: "clagd",
	})
	if err == nil || !strings.Contains(err.Error(), "supports no log units on eos") {
		t.Fatalf("GetLogs() error = %v, want refusal", err)
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %q, want nothing", *ran)
	}
}

func TestGetLogsDetectedPlatformWithoutUnits(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identEOS, outputs: map[string]string{"show version": readFixture(t, "eos_show_version.txt")}}).probe
	ran := stubRunCommand(t, "", nil)
	_, _, err := GetLogs(context.Background(), nil, GetLogsInput{Host: "rtr1", Username: "u", Unit: "clagd"})
	if err == nil || !strings.Contains(err.Error(), "supports no log units on eos") || !strings.Contains(err.Error(), "auto-detected") {
		t.Fatalf("GetLogs() error = %v, want refusal naming the detected type", err)
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %q, want nothing", *ran)
	}
}

func TestGetLogsDetectsCumulus(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identCumulus, outputs: map[string]string{probeOSRelease: readFixture(t, "cumulus43_os_release.txt")}}).probe
	ran := stubRunCommand(t, "-- No entries --\n", nil)
	res, _, err := GetLogs(context.Background(), nil, GetLogsInput{Host: "sw1", Username: "u", Unit: "switchd", Since: "today"})
	if err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}
	if want := "journalctl -u switchd --since 'today' --lines 1000 --no-pager 2>&1"; len(*ran) != 1 || (*ran)[0] != want {
		t.Fatalf("ran %q, want [%q]", *ran, want)
	}
	if text := strings.Join(resultTexts(res), "\n"); !strings.Contains(text, "device_type: cumulus4x (auto-detected") {
		t.Fatalf("result = %q, want the detection notice", text)
	}
}

func TestGetLogsJournalAccessNotice(t *testing.T) {
	stubRunCommand(t, "Hint: You are currently not seeing messages from other users and the system.\n"+
		"      Users in groups 'adm', 'systemd-journal' can see all messages.\n"+
		"      Pass -q to turn off this notice.\n-- No entries --\n", nil)
	res, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host: "sw1", Username: "u", DeviceType: "cumulus4x", Unit: "clagd",
	})
	if err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}
	if text := strings.Join(resultTexts(res), "\n"); !strings.Contains(text, journalNoAccessNotice) {
		t.Fatalf("result = %q, want the journal access notice", text)
	}
}

func TestGetLogsNoAccessNoticeIgnoresLogEntries(t *testing.T) {
	stubRunCommand(t, "Nov 16 08:00:01 sw1 clagd[812]: Hint: You are currently not seeing messages from other users and the system\n", nil)
	res, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host: "sw1", Username: "u", DeviceType: "cumulus4x", Unit: "clagd",
	})
	if err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}
	if text := strings.Join(resultTexts(res), "\n"); strings.Contains(text, journalNoAccessNotice) {
		t.Fatalf("result = %q, want no access notice for a log entry", text)
	}
}

func TestGetLogsErrorIncludesObfuscatedOutput(t *testing.T) {
	cmdErr := &sshclient.CommandError{
		Command:    "journalctl",
		Err:        &gossh.ExitError{},
		ExitStatus: 1,
		Output:     []byte("Failed to parse timestamp\n-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEKEYMATERIAL\n-----END RSA PRIVATE KEY-----\n"),
	}
	stubRunCommand(t, "", cmdErr)
	_, _, err := GetLogs(context.Background(), nil, GetLogsInput{
		Host: "sw1", Username: "u", DeviceType: "cumulus4x", Unit: "clagd",
	})
	if err == nil || !strings.Contains(err.Error(), "Failed to parse timestamp") {
		t.Fatalf("GetLogs() error = %v, want the device output", err)
	}
	if strings.Contains(err.Error(), "MIIFAKEKEYMATERIAL") {
		t.Fatalf("GetLogs() error leaks the key: %v", err)
	}
	if !errors.As(err, new(*sshclient.CommandError)) {
		t.Fatalf("GetLogs() error = %v, want it to wrap the CommandError", err)
	}
}

func TestListLogUnitsWithDeviceType(t *testing.T) {
	resetDetection(t)
	probe := &fakeProbe{ident: identCumulus}
	runProbe = probe.probe

	res, _, err := ListLogUnits(context.Background(), nil, ListLogUnitsInput{DeviceType: "cumulus4x"})
	if err != nil {
		t.Fatalf("ListLogUnits() error = %v", err)
	}
	if text := strings.Join(resultTexts(res), "\n"); !strings.Contains(text, "clagd\nswitchd") {
		t.Fatalf("result = %q, want clagd and switchd", text)
	}

	res, _, err = ListLogUnits(context.Background(), nil, ListLogUnitsInput{DeviceType: "fortigate"})
	if err != nil {
		t.Fatalf("ListLogUnits() error = %v", err)
	}
	if text := strings.Join(resultTexts(res), "\n"); !strings.Contains(text, "No log units on fortios") {
		t.Fatalf("result = %q, want no units on fortios", text)
	}

	if _, _, err := ListLogUnits(context.Background(), nil, ListLogUnitsInput{DeviceType: "bogus"}); err == nil {
		t.Fatalf("ListLogUnits() with a bad device_type = nil error")
	}
	if probe.calls != 0 {
		t.Fatalf("probe calls = %d, want none with device_type", probe.calls)
	}
}

func TestListLogUnitsDetects(t *testing.T) {
	resetDetection(t)
	probe := &fakeProbe{ident: identCumulus, outputs: map[string]string{probeOSRelease: readFixture(t, "cumulus43_os_release.txt")}}
	runProbe = probe.probe

	res, _, err := ListLogUnits(context.Background(), nil, ListLogUnitsInput{Host: "sw1", Username: "u"})
	if err != nil {
		t.Fatalf("ListLogUnits() error = %v", err)
	}
	text := strings.Join(resultTexts(res), "\n")
	if !strings.Contains(text, "on cumulus4x:\nclagd\nswitchd") || !strings.Contains(text, "device_type: cumulus4x (auto-detected over SSH)") {
		t.Fatalf("result = %q, want the units and the detection notice", text)
	}
	if probe.calls != 1 {
		t.Fatalf("probe calls = %d, want 1", probe.calls)
	}
}

func TestListLogUnitsNeedsHostOrDeviceType(t *testing.T) {
	_, _, err := ListLogUnits(context.Background(), nil, ListLogUnitsInput{})
	if err == nil || !strings.Contains(err.Error(), "host or device_type is required") {
		t.Fatalf("ListLogUnits() error = %v, want host or device_type required", err)
	}
}

// journalOutput returns journalctl output holding n entries.
func journalOutput(n int) string {
	var b strings.Builder
	b.WriteString("-- Logs begin at Thu 2026-11-12 08:26:41 CET, end at Mon 2026-11-16 20:48:58 CET. --\n")
	for i := range n {
		fmt.Fprintf(&b, "Nov 16 20:%02d:%02d leaf5 switchd[3320]: entry %d\n", i/60%60, i%60, i)
	}
	return b.String()
}

func TestCountLogEntries(t *testing.T) {
	out := "-- Logs begin at Thu 2026-11-12 08:26:41 CET, end at Mon 2026-11-16 20:48:58 CET. --\n" +
		"Hint: You are currently not seeing messages from other users and the system.\n" +
		"      Users in groups 'adm', 'systemd-journal' can see all messages.\n" +
		"Nov 16 08:00:01 sw1 clagd[812]: first\n" +
		"                                second line of the first entry\n" +
		"-- Reboot --\n" +
		"Nov 16 09:00:01 sw1 clagd[812]: second\n"
	if got := countLogEntries(out); got != 2 {
		t.Fatalf("countLogEntries() = %d, want 2", got)
	}
	if got := countLogEntries("-- Logs begin at ... --\n-- No entries --\n"); got != 0 {
		t.Fatalf("countLogEntries(no entries) = %d, want 0", got)
	}
}

func TestGetLogsLimitNotices(t *testing.T) {
	const limitReached = "the lines limit, so older entries"
	const sizeWarning = "Warning: this result holds"
	tests := []struct {
		name        string
		lines       int
		entries     int
		wantLimit   bool
		wantWarning bool
		wantCommand string
	}{
		{name: "default, under the limit", entries: 20, wantCommand: "--lines 1000 "},
		{name: "default, limit reached", entries: defaultLogLines, wantLimit: true, wantCommand: "--lines 1000 "},
		{name: "larger limit, small output", lines: 5000, entries: 20, wantCommand: "--lines 5000 "},
		{name: "larger limit, large output", lines: 5000, entries: 1500, wantWarning: true, wantCommand: "--lines 5000 "},
		{name: "larger limit reached", lines: 2000, entries: 2000, wantLimit: true, wantWarning: true, wantCommand: "--lines 2000 "},
		{name: "small limit reached", lines: 5, entries: 5, wantLimit: true, wantCommand: "--lines 5 "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ran := stubRunCommand(t, journalOutput(tt.entries), nil)
			res, _, err := GetLogs(context.Background(), nil, GetLogsInput{
				Host: "sw1", Username: "u", DeviceType: "cumulus4x", Unit: "switchd", Lines: tt.lines,
			})
			if err != nil {
				t.Fatalf("GetLogs() error = %v", err)
			}
			if len(*ran) != 1 || !strings.Contains((*ran)[0], tt.wantCommand) {
				t.Fatalf("ran %q, want %q in it", *ran, tt.wantCommand)
			}
			texts := resultTexts(res)
			notes := strings.Join(texts[1:], "\n")
			if got := strings.Contains(notes, limitReached); got != tt.wantLimit {
				t.Errorf("limit notice = %v, want %v; notes %q", got, tt.wantLimit, notes)
			}
			if got := strings.Contains(notes, sizeWarning); got != tt.wantWarning {
				t.Errorf("size warning = %v, want %v; notes %q", got, tt.wantWarning, notes)
			}
		})
	}
}
