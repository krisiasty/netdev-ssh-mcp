package netdev

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

func TestGetConfigFortiOSUsesShowFullConfiguration(t *testing.T) {
	original := runCommand
	defer func() { runCommand = original }()

	var gotCmd string
	runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
		gotCmd = cmd
		return "ok", nil
	}

	_, _, err := GetConfig(context.Background(), nil, GetConfigInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortios",
	})
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if gotCmd != "show full-configuration" {
		t.Fatalf("GetConfig() command = %q, want %q", gotCmd, "show full-configuration")
	}
}

func TestGetConfigIOSOmitsNoMore(t *testing.T) {
	tests := []struct {
		name       string
		deviceType string
		configType string
		want       string
	}{
		{name: "ios running", deviceType: "ios", want: "show running-config"},
		{name: "ios startup", deviceType: "ios", configType: "startup", want: "show startup-config"},
		{name: "ios mixed case and spaces", deviceType: " IOS ", want: "show running-config"},
		{name: "nxos keeps no-more", deviceType: "nxos", want: "show running-config | no-more"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := runCommand
			defer func() { runCommand = original }()

			var gotCmd string
			runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
				gotCmd = cmd
				return "ok", nil
			}

			_, _, err := GetConfig(context.Background(), nil, GetConfigInput{
				Host:       "rtr1",
				Username:   "admin",
				DeviceType: tt.deviceType,
				ConfigType: tt.configType,
			})
			if err != nil {
				t.Fatalf("GetConfig() error = %v", err)
			}
			if gotCmd != tt.want {
				t.Fatalf("GetConfig() command = %q, want %q", gotCmd, tt.want)
			}
		})
	}
}

func TestGetConfigFortiOSRejectsStartup(t *testing.T) {
	_, _, err := GetConfig(context.Background(), nil, GetConfigInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortios",
		ConfigType: "startup",
	})
	if err == nil || !strings.Contains(err.Error(), "FortiOS does not have a startup-config") {
		t.Fatalf("GetConfig() error = %v, want FortiOS startup rejection", err)
	}
}

func TestRunShowCommandFortiOSAllowsGet(t *testing.T) {
	original := runCommand
	defer func() { runCommand = original }()

	var gotCmd string
	runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
		gotCmd = cmd
		return "Version: FortiGate", nil
	}

	_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortigate",
		Command:    "get system status",
	})
	if err != nil {
		t.Fatalf("RunShowCommand() error = %v", err)
	}
	if gotCmd != "get system status" {
		t.Fatalf("RunShowCommand() command = %q, want %q", gotCmd, "get system status")
	}
}

func TestRunShowCommandFortiOSRejectsExecute(t *testing.T) {
	_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortios",
		Command:    "execute ping 8.8.8.8",
	})
	if err == nil || !strings.Contains(err.Error(), "use run_ping or run_traceroute") {
		t.Fatalf("RunShowCommand() error = %v, want execute rejection", err)
	}
}

// stubRunCommand records the commands a handler runs and answers with out.
func stubRunCommand(t *testing.T, out string, err error) *[]string {
	t.Helper()
	origOne, origMany := runCommand, runCommands
	t.Cleanup(func() { runCommand, runCommands = origOne, origMany })
	var ran []string
	runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
		ran = append(ran, cmd)
		return out, err
	}
	runCommands = func(_ context.Context, cfg sshclient.ConnConfig, cmds []string) (string, error) {
		ran = append(ran, strings.Join(cmds, "\n"))
		return out, err
	}
	return &ran
}

func TestHandlersDetectOmittedDeviceType(t *testing.T) {
	type call func() (*mcp.CallToolResult, any, error)
	tests := []struct {
		name    string
		ident   string
		fixture string
		call    call
		want    string
	}{
		{
			name: "get_config on junos", ident: identJunos, fixture: "junos_show_version.txt",
			call: func() (*mcp.CallToolResult, any, error) {
				return GetConfig(context.Background(), nil, GetConfigInput{Host: "r1", Username: "u"})
			},
			want: "show configuration | no-more",
		},
		{
			name: "get_config on ios omits no-more", ident: identIOS, fixture: "ios_show_version.txt",
			call: func() (*mcp.CallToolResult, any, error) {
				return GetConfig(context.Background(), nil, GetConfigInput{Host: "sw2", Username: "u"})
			},
			want: "show running-config",
		},
		{
			name: "run_show_command on eos", ident: identEOS, fixture: "eos_show_version.txt",
			call: func() (*mcp.CallToolResult, any, error) {
				return RunShowCommand(context.Background(), nil, RunShowCommandInput{Host: "sw1", Username: "u", Command: "show bgp summary | json"})
			},
			want: "show bgp summary | json",
		},
		{
			name: "run_ping on nxos", ident: identNXOS, fixture: "nxos_show_version.txt",
			call: func() (*mcp.CallToolResult, any, error) {
				return RunPing(context.Background(), nil, RunPingInput{Host: "sw3", Username: "u", Destination: "192.0.2.1", Count: 2})
			},
			want: "ping 192.0.2.1 count 2",
		},
		{
			name: "run_traceroute on junos", ident: identJunos, fixture: "junos_show_version.txt",
			call: func() (*mcp.CallToolResult, any, error) {
				return RunTraceroute(context.Background(), nil, RunTracerouteInput{Host: "r1", Username: "u", Destination: "192.0.2.1", MaxHops: 5})
			},
			want: "traceroute 192.0.2.1 ttl 5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetDetection(t)
			runProbe = (&fakeProbe{ident: tt.ident, outputs: map[string]string{probeShowVersion: readFixture(t, tt.fixture)}}).probe
			ran := stubRunCommand(t, "output", nil)

			res, _, err := tt.call()
			if err != nil {
				t.Fatalf("handler error = %v", err)
			}
			if len(*ran) != 1 || (*ran)[0] != tt.want {
				t.Fatalf("ran %q, want %q", *ran, tt.want)
			}
			texts := contentTexts(res.Content)
			if len(texts) != 2 || texts[0] != "output" || !strings.Contains(texts[1], "auto-detected over SSH") {
				t.Fatalf("content = %q, want the device output followed by the detection notice", texts)
			}
		})
	}
}

func TestHandlersExplicitDeviceTypeHasNoNotice(t *testing.T) {
	resetDetection(t)
	f := &fakeProbe{ident: identEOS}
	runProbe = f.probe
	stubRunCommand(t, "output", nil)

	res, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{Host: "sw1", Username: "u", Command: "show version", DeviceType: "eos"})
	if err != nil {
		t.Fatalf("RunShowCommand() error = %v", err)
	}
	if texts := contentTexts(res.Content); len(texts) != 1 || f.calls != 0 {
		t.Fatalf("content = %q, probes = %d; want only the output and no probe", texts, f.calls)
	}
}

func TestHandlersExplicitDeviceTypeSyntaxErrorHint(t *testing.T) {
	resetDetection(t)
	stubRunCommand(t, "% Invalid input detected at '^' marker.\n", nil)

	res, _, err := GetConfig(context.Background(), nil, GetConfigInput{Host: "sw1", Username: "u", DeviceType: "eos"})
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if texts := contentTexts(res.Content); len(texts) != 2 || !strings.Contains(texts[1], "omit device_type to auto-detect") {
		t.Fatalf("content = %q, want the output followed by the hint", texts)
	}
}

// TestHandlersFailedCommandHidesDeviceOutput checks that when a command
// fails, nothing the device printed reaches the tool error or the log, while
// the rejection is still reported.
func TestHandlersFailedCommandHidesDeviceOutput(t *testing.T) {
	resetDetection(t)
	const secret = "enable secret 5 $1$abcd$efgh"
	stubRunCommand(t, "", &sshclient.CommandError{
		Command: "show running-config",
		Err:     errors.New("process exited with status 1"),
		Output:  []byte("% Invalid input detected at '^' marker.\n" + secret + "\n"),
	})
	var logs bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	_, _, err := GetConfig(context.Background(), nil, GetConfigInput{Host: "sw1", Username: "u", DeviceType: "ios"})
	if err == nil || !strings.Contains(err.Error(), "rejected the command syntax") {
		t.Fatalf("GetConfig() error = %v, want the rejection reported", err)
	}
	for name, text := range map[string]string{"error": err.Error(), "log": logs.String()} {
		if strings.Contains(text, "secret") || strings.Contains(text, "Invalid input") {
			t.Fatalf("%s contains device output: %q", name, text)
		}
	}
}

// TestRunShowCommandInvalidCommandSkipsDetection checks that a command no
// platform accepts is rejected before detection logs in to the device, and
// that a command some platform accepts still goes through detection.
func TestRunShowCommandInvalidCommandSkipsDetection(t *testing.T) {
	for _, cmd := range []string{"reload", "show version ; configure terminal", "show version | redirect flash:x", "show version\nconf t"} {
		t.Run(cmd, func(t *testing.T) {
			resetDetection(t)
			f := &fakeProbe{ident: identEOS}
			runProbe = f.probe
			ran := stubRunCommand(t, "output", nil)

			if _, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{Host: "sw1", Username: "u", Command: cmd}); err == nil {
				t.Fatal("RunShowCommand() error = nil, want the command rejected")
			}
			if f.calls != 0 || len(*ran) != 0 {
				t.Fatalf("probes = %d, ran %q; want no connection", f.calls, *ran)
			}
		})
	}

	t.Run("get system status is valid on FortiOS", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: readFixture(t, "fortios_get_system_status.txt")}}
		runProbe = f.probe
		stubRunCommand(t, "output", nil)

		if _, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{Host: "fw1", Username: "u", Command: "get system status"}); err != nil {
			t.Fatalf("RunShowCommand() error = %v", err)
		}
		if f.calls != 1 {
			t.Fatalf("probes = %d, want detection to run", f.calls)
		}
	})
}

func TestHandlersUnsupportedPlatformRunsNothing(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identC1200}).probe
	ran := stubRunCommand(t, "output", nil)

	_, _, err := GetConfig(context.Background(), nil, GetConfigInput{Host: "mgmt1", Username: "u"})
	if !errors.Is(err, errUnsupportedPlatform) || !strings.HasPrefix(err.Error(), "get_config: ") {
		t.Fatalf("GetConfig() error = %v, want errUnsupportedPlatform with the tool prefix", err)
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %q, want nothing", *ran)
	}
}

func TestHandlersRejectBadArgsBeforeDetection(t *testing.T) {
	resetDetection(t)
	f := &fakeProbe{ident: identEOS}
	runProbe = f.probe

	if _, _, err := RunPing(context.Background(), nil, RunPingInput{Host: "sw1", Username: "u", Destination: "192.0.2.1;reload"}); err == nil {
		t.Fatal("RunPing() accepted an unsafe destination")
	}
	if _, _, err := GetConfig(context.Background(), nil, GetConfigInput{Host: "sw1", Username: "u", ConfigType: "candidate"}); err == nil {
		t.Fatal("GetConfig() accepted an invalid config_type")
	}
	if f.calls != 0 {
		t.Fatalf("probes = %d, want 0 for invalid input", f.calls)
	}
}

func TestDetectPlatform(t *testing.T) {
	resetDetection(t)
	f := &fakeProbe{ident: identJunos, outputs: map[string]string{probeShowVersion: readFixture(t, "junos_show_version.txt")}}
	runProbe = f.probe

	res, _, err := DetectPlatform(context.Background(), nil, DetectPlatformInput{Host: "r1", Username: "u"})
	if err != nil {
		t.Fatalf("DetectPlatform() error = %v", err)
	}
	text := strings.Join(contentTexts(res.Content), "\n")
	for _, want := range []string{"device_type: junos", "version: 23.4R2.13", "ssh_server: " + identJunos, "detected: now", "Pass device_type=junos"} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q:\n%s", want, text)
		}
	}

	res, _, err = DetectPlatform(context.Background(), nil, DetectPlatformInput{Host: "r1", Username: "u"})
	if err != nil || !strings.Contains(strings.Join(contentTexts(res.Content), "\n"), "cached by this server") || f.calls != 1 {
		t.Fatalf("second DetectPlatform() = %v, probes = %d; want a cached report", err, f.calls)
	}

	if _, _, err = DetectPlatform(context.Background(), nil, DetectPlatformInput{Host: "r1", Username: "u", Refresh: true}); err != nil || f.calls != 2 {
		t.Fatalf("refresh DetectPlatform() = %v, probes = %d; want a new probe", err, f.calls)
	}
}

// TestCommandTimeoutPerTool checks that ping and traceroute ask for the long
// command timeout, on both the single-command and FortiOS multi-command
// paths, and that other tools keep the configured one.
func TestCommandTimeoutPerTool(t *testing.T) {
	originalOne, originalMany := runCommand, runCommands
	t.Cleanup(func() { runCommand, runCommands = originalOne, originalMany })

	var got time.Duration
	runCommand = func(_ context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
		got = cfg.CommandTimeout
		return "ok", nil
	}
	runCommands = func(_ context.Context, cfg sshclient.ConnConfig, cmds []string) (string, error) {
		got = cfg.CommandTimeout
		return "ok", nil
	}

	tests := []struct {
		name string
		call func() error
		want time.Duration
	}{
		{name: "ping", want: longCommandTimeout, call: func() error {
			_, _, err := RunPing(context.Background(), nil, RunPingInput{Host: "r1", Username: "u", DeviceType: "eos", Destination: "192.0.2.1"})
			return err
		}},
		{name: "ping fortios", want: longCommandTimeout, call: func() error {
			_, _, err := RunPing(context.Background(), nil, RunPingInput{Host: "fw1", Username: "u", DeviceType: "fortios", Destination: "192.0.2.1", Count: 3})
			return err
		}},
		{name: "traceroute", want: longCommandTimeout, call: func() error {
			_, _, err := RunTraceroute(context.Background(), nil, RunTracerouteInput{Host: "r1", Username: "u", DeviceType: "junos", Destination: "192.0.2.1"})
			return err
		}},
		{name: "traceroute fortios", want: longCommandTimeout, call: func() error {
			_, _, err := RunTraceroute(context.Background(), nil, RunTracerouteInput{Host: "fw1", Username: "u", DeviceType: "fortios", Destination: "192.0.2.1", Source: "192.0.2.2"})
			return err
		}},
		{name: "show", want: 0, call: func() error {
			_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{Host: "r1", Username: "u", DeviceType: "eos", Command: "show version"})
			return err
		}},
		{name: "config", want: 0, call: func() error {
			_, _, err := GetConfig(context.Background(), nil, GetConfigInput{Host: "r1", Username: "u", DeviceType: "eos"})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = -1
			if err := tt.call(); err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("CommandTimeout = %v, want %v", got, tt.want)
			}
		})
	}
}

type ctxKey struct{}

// TestHandlersPassRequestContext checks that each handler passes its request
// context to detection and to the SSH command, so cancelling the request
// reaches the device connection.
func TestHandlersPassRequestContext(t *testing.T) {
	resetDetection(t)
	ctx := context.WithValue(t.Context(), ctxKey{}, "request")
	var missing []string
	check := func(name string, got context.Context) {
		if got.Value(ctxKey{}) != "request" {
			missing = append(missing, name)
		}
	}
	f := &fakeProbe{ident: identEOS, outputs: map[string]string{probeShowVersion: readFixture(t, "eos_show_version.txt")}}
	runProbe = func(pctx context.Context, cfg sshclient.ConnConfig, choose func(string) (string, error)) (sshclient.ProbeResult, error) {
		check("probe", pctx)
		return f.probe(pctx, cfg, choose)
	}
	origOne, origMany, origInspect, origTrust := runCommand, runCommands, inspectHostKey, trustHostKey
	t.Cleanup(func() {
		runCommand, runCommands, inspectHostKey, trustHostKey = origOne, origMany, origInspect, origTrust
	})
	inspectHostKey = func(cctx context.Context, host string, port int) (sshclient.HostKeyInfo, error) {
		check("inspectHostKey", cctx)
		return sshclient.HostKeyInfo{}, nil
	}
	trustHostKey = func(cctx context.Context, host string, port int, replace bool) (sshclient.TrustHostKeyResult, error) {
		check("trustHostKey", cctx)
		return sshclient.TrustHostKeyResult{}, nil
	}
	runCommand = func(cctx context.Context, cfg sshclient.ConnConfig, cmd string) (string, error) {
		check("runCommand "+cmd, cctx)
		return "ok", nil
	}
	runCommands = func(cctx context.Context, cfg sshclient.ConnConfig, cmds []string) (string, error) {
		check("runCommands", cctx)
		return "ok", nil
	}

	calls := map[string]func() error{
		"run_show_command": func() error {
			_, _, err := RunShowCommand(ctx, nil, RunShowCommandInput{Host: "sw1", Username: "u", Command: "show version"})
			return err
		},
		"get_config": func() error {
			_, _, err := GetConfig(ctx, nil, GetConfigInput{Host: "sw2", Username: "u"})
			return err
		},
		"run_ping": func() error {
			_, _, err := RunPing(ctx, nil, RunPingInput{Host: "sw3", Username: "u", Destination: "192.0.2.1"})
			return err
		},
		"run_ping fortios": func() error {
			_, _, err := RunPing(ctx, nil, RunPingInput{Host: "fw1", Username: "u", DeviceType: "fortios", Destination: "192.0.2.1", Count: 3})
			return err
		},
		"run_traceroute": func() error {
			_, _, err := RunTraceroute(ctx, nil, RunTracerouteInput{Host: "sw4", Username: "u", Destination: "192.0.2.1"})
			return err
		},
		"detect_platform": func() error {
			_, _, err := DetectPlatform(ctx, nil, DetectPlatformInput{Host: "sw5", Username: "u"})
			return err
		},
		"trust_host_key inspect": func() error {
			_, _, err := TrustHostKey(ctx, nil, TrustHostKeyInput{Host: "sw6"})
			return err
		},
		"trust_host_key confirm": func() error {
			_, _, err := TrustHostKey(ctx, nil, TrustHostKeyInput{Host: "sw6", Confirm: true})
			return err
		},
	}
	for name, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if f.calls == 0 {
		t.Fatal("no detection ran, so the probe context was not checked")
	}
	if len(missing) > 0 {
		t.Fatalf("request context not passed to: %q", missing)
	}
}

// TestCancelledRequestLogsAtInfo checks that a request the client cancelled
// is logged at Info, not as a device failure at Error, and that its error
// carries no detection notice.
func TestCancelledRequestLogsAtInfo(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identEOS, outputs: map[string]string{probeShowVersion: readFixture(t, "eos_show_version.txt")}}).probe
	stubRunCommand(t, "", fmt.Errorf("run \"show version\" on sw1:22: %w", context.Canceled))
	logs := captureLogs(t)
	// The fakes ignore ctx, so the call reaches the command and fails there
	// as it would had the client cancelled during the command.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, _, err := RunShowCommand(ctx, nil, RunShowCommandInput{Host: "sw1", Username: "u", Command: "show version"})
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "device_type") {
		t.Fatalf("RunShowCommand() error = %v, want the cancellation without a detection notice", err)
	}
	if strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "run_show_command cancelled by the client") {
		t.Fatalf("logs = %q, want the cancellation at INFO and no ERROR", logs.String())
	}
}

// TestDeviceTimeoutIsNotCancellation checks that a timeout towards the device
// is reported as a device failure while the client is still waiting. A TCP
// connect or DNS timeout matches context.DeadlineExceeded under errors.Is,
// just as the client's own deadline would.
func TestDeviceTimeoutIsNotCancellation(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identEOS, outputs: map[string]string{probeShowVersion: readFixture(t, "eos_show_version.txt")}}).probe
	if _, err := resolveDeviceType(t.Context(), connConfig("sw1", 0, "u"), "", false); err != nil {
		t.Fatal(err)
	}
	stubRunCommand(t, "", fmt.Errorf("dial sw1:22: dial tcp 192.0.2.1:22: %w", context.DeadlineExceeded))
	logs := captureLogs(t)

	_, _, err := RunShowCommand(t.Context(), nil, RunShowCommandInput{Host: "sw1", Username: "u", Command: "show version"})
	if err == nil || !strings.Contains(err.Error(), "auto-detected earlier and cached") {
		t.Fatalf("RunShowCommand() error = %v, want the cached detection notice", err)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "run_show_command failed") {
		t.Fatalf("logs = %q, want the failure at ERROR", logs.String())
	}
}

// TestProbeFailureLogged checks that a failed detection probe is logged like
// a failed command: at Error, or at Info when the client cancelled. A device
// identified as unsupported is an answer, logged at Info.
func TestProbeFailureLogged(t *testing.T) {
	tests := []struct {
		name      string
		cancelled bool
		want      string
		wantError bool
	}{
		{"failure", false, "platform detection failed", true},
		{"cancelled", true, "platform detection cancelled by the client", false},
		{"unsupported platform", false, "platform detection: unsupported platform", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetDetection(t)
			probeErr := errors.New("dial sw1:22: connection refused")
			switch {
			case tt.cancelled:
				probeErr = fmt.Errorf("SSH handshake with sw1:22: %w", context.Canceled)
			case tt.name == "unsupported platform":
				probeErr = fmt.Errorf("%w: the SSH server is a Linux distribution", errUnsupportedPlatform)
			}
			runProbe = (&fakeProbe{err: probeErr}).probe
			logs := captureLogs(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelled {
				cancel()
			}

			if _, _, err := DetectPlatform(ctx, nil, DetectPlatformInput{Host: "sw1", Username: "u"}); !errors.Is(err, probeErr) {
				t.Fatalf("DetectPlatform() error = %v, want the probe error", err)
			}
			if !strings.Contains(logs.String(), tt.want) || strings.Contains(logs.String(), "level=ERROR") != tt.wantError {
				t.Fatalf("logs = %q, want %q (at ERROR: %v)", logs.String(), tt.want, tt.wantError)
			}
		})
	}
}

// captureLogs sends the default logger to a buffer for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	return &logs
}
