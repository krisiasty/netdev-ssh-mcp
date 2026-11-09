package netdev

import (
	"context"
	"errors"
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
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
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
			runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
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
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
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
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
		ran = append(ran, cmd)
		return out, err
	}
	runCommands = func(cfg sshclient.ConnConfig, cmds []string) (string, error) {
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
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
		got = cfg.CommandTimeout
		return "ok", nil
	}
	runCommands = func(cfg sshclient.ConnConfig, cmds []string) (string, error) {
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
