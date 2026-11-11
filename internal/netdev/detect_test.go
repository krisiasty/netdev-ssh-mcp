package netdev

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// SSH identification strings captured from real devices, except where noted.
const (
	identEOS      = "SSH-2.0-OpenSSH_9.9"
	identJunos    = "SSH-2.0-OpenSSH_7.5"
	identNXOS     = "SSH-2.0-OpenSSH_9.6 PKIX[12.5.1]"
	identIOS      = "SSH-2.0-Cisco-1.25"
	identFortiOS  = "SSH-2.0-pOn0cZbl"
	identCumulus  = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
	identC1200    = "SSH-2.0-OpenSSH_7.3p1.RL"
	identUbuntu   = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" // not captured
	identDropbear = "SSH-2.0-dropbear_2022.83"                 // not captured
	identFortiSSH = "SSH-2.0-FortiSSH_3.0"                     // older FortiOS, not captured
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "probe", name)) //nolint:gosec // G304: test fixture names are constants in this package
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// resetDetection gives a test an empty detection cache and restores the
// probe and clock afterwards.
func resetDetection(t *testing.T) {
	t.Helper()
	origProbe, origNow := runProbe, now
	detectCache.Lock()
	detectCache.m = map[string]cacheEntry{}
	detectCache.Unlock()
	t.Cleanup(func() {
		runProbe, now = origProbe, origNow
		detectCache.Lock()
		detectCache.m = map[string]cacheEntry{}
		detectCache.Unlock()
	})
}

// fakeProbe answers like a device with the given identification string and
// per-command output, and records which commands it was asked to run.
type fakeProbe struct {
	ident   string
	outputs map[string]string
	err     error
	calls   int
	ran     []string
}

func (f *fakeProbe) probe(_ context.Context, cfg sshclient.ConnConfig, choose func(string) (string, error)) (sshclient.ProbeResult, error) {
	f.calls++
	res := sshclient.ProbeResult{ServerVersion: f.ident}
	if f.err != nil {
		return res, f.err
	}
	cmd, err := choose(f.ident)
	if err != nil || cmd == "" {
		return res, err
	}
	f.ran = append(f.ran, cmd)
	res.Command = cmd
	res.Output = f.outputs[cmd]
	return res, nil
}

func TestClassifyIdent(t *testing.T) {
	tests := []struct {
		ident string
		want  identClass
	}{
		{identEOS, identPlainOpenSSH},
		{identJunos, identPlainOpenSSH},
		{identNXOS, identPKIX},
		{identIOS, identCisco},
		{identFortiOS, identObfuscated},
		{identFortiSSH, identObfuscated},
		{identCumulus, identLinux},
		{identUbuntu, identLinux},
		{identC1200, identCiscoBusiness},
		{identDropbear, identUnknown},
		{"SSH-1.99-OpenSSH_6.0", identPlainOpenSSH},
		{"SSH-2.0-", identUnknown},
		{"", identUnknown},
	}
	for _, tt := range tests {
		if got := classifyIdent(tt.ident); got != tt.want {
			t.Errorf("classifyIdent(%q) = %d, want %d", tt.ident, got, tt.want)
		}
	}
}

func TestProbeCommandFor(t *testing.T) {
	tests := []struct {
		ident       string
		want        string
		unsupported bool
	}{
		{ident: identEOS, want: probeShowVersion},
		{ident: identJunos, want: probeShowVersion},
		{ident: identNXOS, want: probeShowVersion},
		{ident: identIOS, want: probeShowVersion},
		{ident: identDropbear, want: probeShowVersion},
		{ident: identFortiOS, want: probeSystemStatus},
		{ident: identCumulus, want: probeOSRelease},
		{ident: identUbuntu, want: probeOSRelease},
		{ident: identC1200, unsupported: true},
	}
	for _, tt := range tests {
		got, err := probeCommandFor(classifyIdent(tt.ident), tt.ident)
		if tt.unsupported {
			if !errors.Is(err, errUnsupportedPlatform) || got != "" {
				t.Errorf("probeCommandFor(%q) = %q, %v; want no command and errUnsupportedPlatform", tt.ident, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("probeCommandFor(%q) = %q, %v; want %q", tt.ident, got, err, tt.want)
		}
	}
}

func TestMatchProbeOutput(t *testing.T) {
	tests := []struct {
		fixture     string
		command     string
		want        deviceType
		wantVersion string
	}{
		{"eos_show_version.txt", probeShowVersion, deviceTypeEOS, "4.35.7.2M"},
		{"nxos_show_version.txt", probeShowVersion, deviceTypeNXOS, "9.3(14)"},
		{"junos_show_version.txt", probeShowVersion, deviceTypeJunos, "23.4R2.13"},
		{"ios_show_version.txt", probeShowVersion, deviceTypeIOS, "12.2(55)SE12"},
		{"iosxe_show_version.txt", probeShowVersion, deviceTypeIOS, "17.09.04a"},
		{"fortios_get_system_status.txt", probeSystemStatus, deviceTypeFortiOS, "v7.4.4"},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			out := readFixture(t, tt.fixture)
			got, err := matchProbeOutput(tt.command, out)
			if err != nil || got != tt.want {
				t.Fatalf("matchProbeOutput() = %q, %v; want %q", got, err, tt.want)
			}
			if v := extractVersion(got, out); v != tt.wantVersion {
				t.Fatalf("extractVersion() = %q, want %q", v, tt.wantVersion)
			}
		})
	}

	t.Run("ios device named Arista", func(t *testing.T) {
		out := strings.ReplaceAll(readFixture(t, "ios_show_version.txt"), "switch1 uptime", "Arista uptime")
		if !strings.Contains(out, "\nArista uptime is") {
			t.Fatal("fixture no longer has the uptime line this test edits")
		}
		if got, err := matchProbeOutput(probeShowVersion, out); err != nil || got != deviceTypeIOS {
			t.Fatalf("matchProbeOutput() = %q, %v; want ios", got, err)
		}
	})

	t.Run("crlf line endings", func(t *testing.T) {
		out := strings.ReplaceAll(readFixture(t, "junos_show_version.txt"), "\n", "\r\n")
		if got, err := matchProbeOutput(probeShowVersion, out); err != nil || got != deviceTypeJunos {
			t.Fatalf("matchProbeOutput() = %q, %v; want junos", got, err)
		}
	})
}

func TestMatchProbeOutputRejects(t *testing.T) {
	tests := []struct {
		name    string
		command string
		output  string
		wantErr string
	}{
		{"cisco business os", probeShowVersion, readFixture(t, "c1200_show_version.txt"), "matched no supported platform"},
		{"linux shell", probeShowVersion, "bash: show: command not found\n", "matched no supported platform"},
		{"empty", probeShowVersion, "", "matched no supported platform"},
		{"fortios marker under show version", probeShowVersion, readFixture(t, "fortios_get_system_status.txt"), "matched no supported platform"},
		{"marker not at line start", probeShowVersion, "Hostname: Arista DCS-7050\nModel: x\n", "matched no supported platform"},
		{"ambiguous", probeShowVersion, "Arista DCS-7050\nJunos: 23.4R2\n", "matched several platforms"},
		{"unknown command", "dir", "Arista DCS-7050\n", "matched no supported platform"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchProbeOutput(tt.command, tt.output)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("matchProbeOutput() = %q, %v; want error containing %q", got, err, tt.wantErr)
			}
		})
	}
}

func TestResolveDeviceType(t *testing.T) {
	cfg := sshclient.ConnConfig{Host: "SW1", Port: 0, Username: "u"}
	eos := map[string]string{probeShowVersion: readFixture(t, "eos_show_version.txt")}

	t.Run("explicit skips probe", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identEOS, outputs: eos}
		runProbe = f.probe
		r, err := resolveDeviceType(t.Context(), cfg, "junos", false)
		if err != nil || r.dt != deviceTypeJunos || r.source != sourceExplicit || f.calls != 0 {
			t.Fatalf("resolveDeviceType() = %+v, %v, probes=%d; want explicit junos without probing", r, err, f.calls)
		}
	})

	t.Run("invalid explicit", func(t *testing.T) {
		resetDetection(t)
		if _, err := resolveDeviceType(t.Context(), cfg, "asa", false); err == nil || !strings.Contains(err.Error(), "device_type must be") {
			t.Fatalf("resolveDeviceType() error = %v, want device_type validation error", err)
		}
	})

	t.Run("probe then cache", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identEOS, outputs: eos}
		runProbe = f.probe

		r, err := resolveDeviceType(t.Context(), cfg, "", false)
		if err != nil || r.dt != deviceTypeEOS || r.source != sourceProbe {
			t.Fatalf("first resolveDeviceType() = %+v, %v; want probed eos", r, err)
		}
		if r.version != "4.35.7.2M" || r.serverVersion != identEOS {
			t.Fatalf("first resolveDeviceType() version = %q, server = %q", r.version, r.serverVersion)
		}

		// Same host in a different case and with an explicit default port.
		r, err = resolveDeviceType(t.Context(), sshclient.ConnConfig{Host: "sw1", Port: 22, Username: "u"}, "", false)
		if err != nil || r.dt != deviceTypeEOS || r.source != sourceCache {
			t.Fatalf("second resolveDeviceType() = %+v, %v; want cached eos", r, err)
		}
		if f.calls != 1 {
			t.Fatalf("probes = %d, want 1", f.calls)
		}

		if r, err = resolveDeviceType(t.Context(), cfg, "", true); err != nil || r.source != sourceProbe || f.calls != 2 {
			t.Fatalf("refresh resolveDeviceType() = %+v, %v, probes=%d; want a new probe", r, err, f.calls)
		}
	})

	t.Run("cache expires", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identEOS, outputs: eos}
		runProbe = f.probe
		start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
		now = func() time.Time { return start }
		if _, err := resolveDeviceType(t.Context(), cfg, "", false); err != nil {
			t.Fatal(err)
		}
		now = func() time.Time { return start.Add(detectCacheTTL + time.Second) }
		if r, err := resolveDeviceType(t.Context(), cfg, "", false); err != nil || r.source != sourceProbe || f.calls != 2 {
			t.Fatalf("resolveDeviceType() after TTL = %+v, %v, probes=%d; want a new probe", r, err, f.calls)
		}
	})

	t.Run("fortios uses get system status", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identFortiOS, outputs: map[string]string{
			probeSystemStatus: readFixture(t, "fortios_get_system_status.txt"),
		}}
		runProbe = f.probe
		r, err := resolveDeviceType(t.Context(), cfg, "", false)
		if err != nil || r.dt != deviceTypeFortiOS {
			t.Fatalf("resolveDeviceType() = %+v, %v; want fortios", r, err)
		}
		if len(f.ran) != 1 || f.ran[0] != probeSystemStatus {
			t.Fatalf("ran %v, want only %q", f.ran, probeSystemStatus)
		}
	})

	t.Run("unsupported "+identC1200, func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identC1200}
		runProbe = f.probe
		_, err := resolveDeviceType(t.Context(), cfg, "", false)
		if !errors.Is(err, errUnsupportedPlatform) {
			t.Fatalf("resolveDeviceType() error = %v, want errUnsupportedPlatform", err)
		}
		if len(f.ran) != 0 {
			t.Fatalf("ran %v on an unsupported platform, want nothing", f.ran)
		}
		if strings.Contains(err.Error(), "pass device_type") {
			t.Fatalf("error %q suggests device_type, which cannot help here", err)
		}
	})

	t.Run("cumulus 4.x from os-release", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identCumulus, outputs: map[string]string{probeOSRelease: readFixture(t, "cumulus43_os_release.txt")}}
		runProbe = f.probe
		r, err := resolveDeviceType(t.Context(), cfg, "", false)
		if err != nil || r.dt != deviceTypeCumulus4x || r.source != sourceProbe || r.version != "4.3.0" {
			t.Fatalf("resolveDeviceType() = %+v, %v; want probed cumulus4x 4.3.0", r, err)
		}
		if len(f.ran) != 1 || f.ran[0] != probeOSRelease {
			t.Fatalf("ran %v, want only %q", f.ran, probeOSRelease)
		}
		if r, err = resolveDeviceType(t.Context(), cfg, "", false); err != nil || r.source != sourceCache || f.calls != 1 {
			t.Fatalf("second resolveDeviceType() = %+v, %v, probes=%d; want cached", r, err, f.calls)
		}
	})

	t.Run("cumulus 5.x is unsupported and not cached", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identCumulus, outputs: map[string]string{probeOSRelease: readFixture(t, "cumulus54_os_release.txt")}}
		runProbe = f.probe
		for range 2 {
			_, err := resolveDeviceType(t.Context(), cfg, "", false)
			if !errors.Is(err, errUnsupportedPlatform) || strings.Contains(err.Error(), "pass device_type") {
				t.Fatalf("resolveDeviceType() error = %v, want errUnsupportedPlatform without a device_type suggestion", err)
			}
		}
		if f.calls != 2 || len(f.ran) != 2 || f.ran[0] != probeOSRelease {
			t.Fatalf("probes = %d, ran %v; want 2 probes of %q (not cached)", f.calls, f.ran, probeOSRelease)
		}
	})

	t.Run("no match is not cached", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identC1200 + "x", outputs: map[string]string{
			probeShowVersion: readFixture(t, "c1200_show_version.txt"),
		}}
		runProbe = f.probe
		for range 2 {
			if _, err := resolveDeviceType(t.Context(), cfg, "", false); err == nil || !strings.Contains(err.Error(), "pass device_type") {
				t.Fatalf("resolveDeviceType() error = %v, want detection failure suggesting device_type", err)
			}
		}
		if f.calls != 2 {
			t.Fatalf("probes = %d, want 2 (failures are not cached)", f.calls)
		}
	})

	t.Run("connection error", func(t *testing.T) {
		resetDetection(t)
		runProbe = (&fakeProbe{err: errors.New("dial sw1:22: connection refused")}).probe
		_, err := resolveDeviceType(t.Context(), cfg, "", false)
		if err == nil || !strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "device_type") {
			t.Fatalf("resolveDeviceType() error = %v, want the connection error without a device_type suggestion", err)
		}
	})
}

func contentTexts(c []mcp.Content) []string {
	var out []string
	for _, item := range c {
		if t, ok := item.(*mcp.TextContent); ok {
			out = append(out, t.Text)
		}
	}
	return out
}

func TestAfterRun(t *testing.T) {
	cfg := sshclient.ConnConfig{Host: "sw1", Username: "u"}
	key := cacheKey(cfg.Host, cfg.Port)
	detected := resolvedType{dt: deviceTypeEOS, source: sourceProbe}

	t.Run("detected success adds notice and keeps cache", func(t *testing.T) {
		resetDetection(t)
		storeType(key, detected)
		got := contentTexts(afterRun(cfg, detected, "Arista DCS-7050\n", nil))
		if len(got) != 1 || !strings.Contains(got[0], "device_type: eos (auto-detected") || !strings.Contains(got[0], "Pass device_type=eos") {
			t.Fatalf("afterRun() = %q, want the detection notice", got)
		}
		if _, ok := cachedType(key); !ok {
			t.Fatal("cache entry dropped after a successful command")
		}
	})

	t.Run("cached notice says cached", func(t *testing.T) {
		got := contentTexts(afterRun(cfg, resolvedType{dt: deviceTypeNXOS, source: sourceCache}, "", nil))
		if len(got) != 1 || !strings.Contains(got[0], "cached by this server") {
			t.Fatalf("afterRun() = %q, want the cached notice", got)
		}
	})

	t.Run("detected syntax error drops cache", func(t *testing.T) {
		resetDetection(t)
		storeType(key, detected)
		got := contentTexts(afterRun(cfg, detected, "show foo\n% Invalid input\n", nil))
		if _, ok := cachedType(key); ok {
			t.Fatal("cache entry kept after a syntax error")
		}
		if len(got) != 2 || got[1] != detectedRejectedNotice {
			t.Fatalf("afterRun() = %q, want the detection notice and the rejection notice", got)
		}
	})

	t.Run("rejection text later in the output is ignored", func(t *testing.T) {
		resetDetection(t)
		storeType(key, detected)
		out := strings.Repeat("hostname sw1\n", syntaxCheckLines) + "banner motd ^\nSyntax error: unauthorised access\n^\n"
		if got := contentTexts(afterRun(cfg, detected, out, nil)); len(got) != 1 {
			t.Fatalf("afterRun() = %q, want only the detection notice", got)
		}
		if _, ok := cachedType(key); !ok {
			t.Fatal("cache entry dropped for a rejection message in the configuration")
		}
		if got := afterRun(cfg, resolvedType{dt: deviceTypeIOS, source: sourceExplicit}, out, nil); len(got) != 0 {
			t.Fatalf("afterRun() = %q, want no hint", contentTexts(got))
		}
	})

	t.Run("explicit success adds nothing", func(t *testing.T) {
		if got := afterRun(cfg, resolvedType{dt: deviceTypeJunos, source: sourceExplicit}, "Junos: 23.4\n", nil); len(got) != 0 {
			t.Fatalf("afterRun() = %q, want no notices", contentTexts(got))
		}
	})

	t.Run("explicit syntax error adds hint", func(t *testing.T) {
		outputs := []string{
			"                ^\nunknown command.\n",             // JunOS
			"% Invalid input detected at '^' marker.\n",         // IOS
			"% Invalid command at '^' marker.\n",                // NX-OS
			"command parse error before 'foo'\nCommand fail.\n", // FortiOS
		}
		for _, out := range outputs {
			got := contentTexts(afterRun(cfg, resolvedType{dt: deviceTypeJunos, source: sourceExplicit}, out, nil))
			if len(got) != 1 || !strings.Contains(got[0], "omit device_type to auto-detect") {
				t.Errorf("afterRun(%q) = %q, want the explicit-type hint", out, got)
			}
		}
	})
}

func TestRunErrorAddsHint(t *testing.T) {
	cfg := sshclient.ConnConfig{Host: "sw1", Username: "u"}
	rejected := &sshclient.CommandError{
		Command: "show running-config",
		Err:     errors.New("process exited with status 1"),
		Output:  []byte("% Invalid input detected at '^' marker.\nenable secret 5 $1$abcd$efgh\n"),
	}
	err := runError(t.Context(), "get_config", cfg, resolvedType{dt: deviceTypeIOS, source: sourceExplicit}, rejected)
	if !strings.Contains(err.Error(), "get_config: ") || !strings.Contains(err.Error(), "omit device_type") {
		t.Fatalf("runError() = %v, want the tool prefix and the hint", err)
	}
	if strings.Contains(err.Error(), "Invalid input") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("runError() = %v, want no device output in the message", err)
	}

	// Only the output kept in a CommandError is classified, never error text.
	for _, plain := range []error{
		errors.New("dial sw1:22: connection refused"),
		errors.New("% Invalid input detected at '^' marker."),
	} {
		if err := runError(t.Context(), "get_config", cfg, resolvedType{dt: deviceTypeIOS, source: sourceExplicit}, plain); !errors.Is(err, plain) || strings.Contains(err.Error(), "omit device_type") {
			t.Fatalf("runError(%v) = %v, want the wrapped error without a hint", plain, err)
		}
	}
}

func TestFirstLines(t *testing.T) {
	for _, tt := range []struct {
		in   string
		n    int
		want string
	}{
		{"a\nb\nc\n", 2, "a\nb\n"},
		{"a\nb", 5, "a\nb"},
		{"a\nb\n", 2, "a\nb\n"},
		{"", 3, ""},
		{"a\n", 0, ""},
	} {
		if got := firstLines(tt.in, tt.n); got != tt.want {
			t.Errorf("firstLines(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}

func TestDisplayValue(t *testing.T) {
	if got := displayValue(" OpenSSH_9.9\x1b[31m\n "); got != "OpenSSH_9.9[31m" {
		t.Fatalf("displayValue() = %q", got)
	}
	if got := displayValue(strings.Repeat("a", 200)); len(got) != 83 {
		t.Fatalf("displayValue() length = %d, want 83", len(got))
	}
}

func TestMatchOSRelease(t *testing.T) {
	c43 := readFixture(t, "cumulus43_os_release.txt")
	tests := []struct {
		name        string
		output      string
		want        deviceType
		wantVersion string
		wantErr     string
	}{
		{name: "4.2", output: readFixture(t, "cumulus42_os_release.txt"), want: deviceTypeCumulus4x, wantVersion: "4.2.0"},
		{name: "4.3", output: c43, want: deviceTypeCumulus4x, wantVersion: "4.3.0"},
		{name: "CRLF", output: strings.ReplaceAll(c43, "\n", "\r\n"), want: deviceTypeCumulus4x, wantVersion: "4.3.0"},
		{name: "quoted", output: "ID=\"cumulus-linux\"\nVERSION_ID=\"4.3.0\"\n", want: deviceTypeCumulus4x, wantVersion: "4.3.0"},
		{name: "5.4", output: readFixture(t, "cumulus54_os_release.txt"), wantErr: "Cumulus Linux 5.4.0 is not supported"},
		{name: "debian", output: readFixture(t, "debian10_os_release.txt"), wantErr: "not Cumulus Linux 4.x"},
		{name: "ubuntu", output: readFixture(t, "ubuntu2204_os_release.txt"), wantErr: "not Cumulus Linux 4.x"},
		{name: "empty", output: "", wantErr: "not Cumulus Linux 4.x"},
		{name: "id without version", output: "ID=cumulus-linux\n", wantErr: "not Cumulus Linux 4.x"},
		{name: "markers inside other lines", output: "NAME=\"ID=cumulus-linux\"\nPRETTY_NAME=VERSION_ID=4.3\n", wantErr: "not Cumulus Linux 4.x"},
		{name: "version marker inside another line", output: "ID=cumulus-linux\nVERSION_ID=5.4.0\nHOME_URL_VERSION_ID=4.3\n", wantErr: "Cumulus Linux 5.4.0 is not supported"},
		{name: "id prefix only", output: "ID=cumulus-linux-x\nVERSION_ID=4.3.0\n", wantErr: "not Cumulus Linux 4.x"},
		{name: "version not a whole line", output: "ID=cumulus-linux\nVERSION_ID=4.junk extra text\n", wantErr: "not Cumulus Linux 4.x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchOSRelease(tt.output)
			if tt.wantErr == "" {
				if err != nil || got != tt.want {
					t.Fatalf("matchOSRelease() = %q, %v; want %q", got, err, tt.want)
				}
				if v := extractVersion(got, tt.output); v != tt.wantVersion {
					t.Fatalf("extractVersion() = %q, want %q", v, tt.wantVersion)
				}
				return
			}
			if !errors.Is(err, errUnsupportedPlatform) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("matchOSRelease() = %q, %v; want errUnsupportedPlatform containing %q", got, err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "pass device_type") {
				t.Fatalf("error %q suggests device_type, which cannot help here", err)
			}
			if tt.name == "5.4" && !strings.Contains(err.Error(), "cumulus4x") {
				t.Fatalf("error %q does not name cumulus4x", err)
			}
		})
	}
}

func TestLooksLikeSyntaxErrorCumulus(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"ERROR: Command not found\nInvalid value here.", true},
		{"bash: show: command not found", true},
		{"bash: line 1: show: command not found", true},
		{"-bash: show: command not found", true},
		{"  ERROR: Command not found", true},
		{"Description: ERROR: Command not found", false},
	}
	for _, tt := range tests {
		if got := looksLikeSyntaxError(tt.text); got != tt.want {
			t.Errorf("looksLikeSyntaxError(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
}
