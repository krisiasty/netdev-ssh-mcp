package netdev

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// The byte sequences below follow what a FortiGate-1100E on FortiOS 7.4.12
// sent, with the hostname replaced.

// vdomHelp is what an interactive shell shows for "edit ?" in "config vdom".
const vdomHelp = "edit \r\n<vdom>    Virtual Domain Name\r\nads_mgmt\r\nopenstack\r\nopenstk-tst\r\n\r\nFGT-1 (vdom) $ edit "

// fakeVDOMShell answers like a FortiOS shell: each Send appends the reply
// for that text, and ReadUntil consumes what was written up to a match.
type fakeVDOMShell struct {
	buf     string
	replies map[string]string
	sent    []string
}

func (f *fakeVDOMShell) Send(text string) error {
	f.sent = append(f.sent, text)
	f.buf += f.replies[text]
	return nil
}

func (f *fakeVDOMShell) ReadUntil(_ context.Context, re *regexp.Regexp) (string, error) {
	loc := re.FindStringIndex(f.buf)
	if loc == nil {
		return "", fmt.Errorf("no match for %v in %q", re, f.buf)
	}
	out := f.buf[:loc[1]]
	f.buf = f.buf[loc[1]:]
	return out, nil
}

func TestFortiOSVDOMs(t *testing.T) {
	for _, prompt := range []string{"$", "#"} {
		t.Run(prompt, func(t *testing.T) {
			sh := &fakeVDOMShell{
				buf: "FGT-1 " + prompt + " ",
				replies: map[string]string{
					"config vdom\r": "config vdom\r\r\n\r\nFGT-1 (vdom) " + prompt + " ",
					"edit ?":        strings.ReplaceAll(vdomHelp, "(vdom) $", "(vdom) "+prompt),
				},
			}
			got, err := fortiOSVDOMs(t.Context(), sh)
			if err != nil || !slices.Equal(got, []string{"ads_mgmt", "openstack", "openstk-tst"}) {
				t.Fatalf("fortiOSVDOMs() = %q, %v", got, err)
			}
			// Nothing may be entered after "edit": the caller closes the shell.
			if !slices.Equal(sh.sent, []string{"config vdom\r", "edit ?"}) {
				t.Fatalf("sent %q, want config vdom entered and edit ? only typed", sh.sent)
			}
		})
	}
}

func TestFortiOSVDOMsWithoutVDOMs(t *testing.T) {
	sh := &fakeVDOMShell{
		buf:     "FGT-1 # ",
		replies: map[string]string{"config vdom\r": "config vdom\r\r\ncommand parse error before 'vdom'\r\nCommand fail. Return code -61\r\n\r\nFGT-1 # "},
	}
	if got, err := fortiOSVDOMs(t.Context(), sh); !errors.Is(err, errNoVDOMs) {
		t.Fatalf("fortiOSVDOMs() = %q, %v; want errNoVDOMs", got, err)
	}
	if !slices.Equal(sh.sent, []string{"config vdom\r"}) {
		t.Fatalf("sent %q, want nothing after config vdom", sh.sent)
	}
}

func TestParseVDOMList(t *testing.T) {
	if got, err := parseVDOMList(vdomHelp); err != nil || !slices.Equal(got, []string{"ads_mgmt", "openstack", "openstk-tst"}) {
		t.Fatalf("parseVDOMList() = %q, %v", got, err)
	}
	for name, help := range map[string]string{
		"no header":        "edit \r\nads_mgmt\r\n\r\nFGT-1 (vdom) $ edit ",
		"no names":         "edit \r\n<vdom>    Virtual Domain Name\r\n\r\nFGT-1 (vdom) $ edit ",
		"not a VDOM name":  "edit \r\n<vdom>    Virtual Domain Name\r\nroot\r\nnot a name\r\n\r\nFGT-1 (vdom) $ edit ",
		"injected command": "edit \r\n<vdom>    Virtual Domain Name\r\nroot;end\r\n\r\nFGT-1 (vdom) $ edit ",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseVDOMList(help); !errors.Is(err, errUnexpectedVDOMs) {
				t.Fatalf("parseVDOMList() = %q, %v; want errUnexpectedVDOMs", got, err)
			}
		})
	}
}

func TestCheckVDOMName(t *testing.T) {
	for _, name := range []string{"root", "ads_mgmt", "openstk-tst", "VDOM1", strings.Repeat("a", 64)} {
		if err := checkVDOMName(name); err != nil {
			t.Errorf("checkVDOMName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "a b", "root\nend", "root;end", "a.b", "?", strings.Repeat("a", 65)} {
		if err := checkVDOMName(name); err == nil {
			t.Errorf("checkVDOMName(%q) = nil, want an error", name)
		}
	}
}

func TestCheckVDOM(t *testing.T) {
	available := []string{"ads_mgmt", "openstack", "openstk-tst"}
	if err := checkVDOM("openstack", available, "fw1"); err != nil {
		t.Fatalf("checkVDOM(exact) = %v", err)
	}
	tests := []struct {
		name    string
		suggest []string
	}{
		{"openstak", []string{"openstack"}},
		{"OpenStack", []string{"openstack"}},
		{"openstk", []string{"openstk-tst", "openstack"}},
		{"ads", []string{"ads_mgmt"}},
		{"production", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkVDOM(tt.name, available, "fw1")
			if !errors.Is(err, errVDOMNotOnTheList) || !strings.Contains(err.Error(), "fortigate_list_vdoms") {
				t.Fatalf("checkVDOM() = %v, want errVDOMNotOnTheList pointing at fortigate_list_vdoms", err)
			}
			if got := suggestVDOMs(tt.name, available); !slices.Equal(got, tt.suggest) {
				t.Fatalf("suggestVDOMs() = %q, want %q", got, tt.suggest)
			}
			for _, s := range tt.suggest {
				if !strings.Contains(err.Error(), fmt.Sprintf("%q", s)) {
					t.Fatalf("error %q does not suggest %q", err, s)
				}
			}
			if tt.suggest == nil && strings.Contains(err.Error(), "Did you mean") {
				t.Fatalf("error %q suggests something", err)
			}
		})
	}
}

func TestSuggestVDOMsAtMostThree(t *testing.T) {
	got := suggestVDOMs("vd", []string{"vd1", "vd2", "vd3", "vd4", "vd5"})
	if !slices.Equal(got, []string{"vd1", "vd2", "vd3"}) {
		t.Fatalf("suggestVDOMs() = %q, want the first three", got)
	}
}

func TestVDOMCommand(t *testing.T) {
	got := vdomCommand("openstack", []string{"execute ping 192.0.2.1", "execute ping-options reset"})
	want := "config vdom\nedit openstack\nexecute ping 192.0.2.1\nexecute ping-options reset\nend"
	if got != want {
		t.Fatalf("vdomCommand() = %q, want %q", got, want)
	}
}

func TestFortiOSVDOMOutput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			"one command",
			"FGT-1 $ \nFGT-1 (vdom) $ current vf=openstack:6\n\nFGT-1 (openstack) $ Version: FortiGate-1100E v7.4.12\nCurrent virtual domain: openstack\n\nFGT-1 (openstack) $ \nFGT-1 $ ",
			"Version: FortiGate-1100E v7.4.12\nCurrent virtual domain: openstack\n",
		},
		{
			"admin prompt",
			"FGT-1 # \nFGT-1 (vdom) # current vf=openstack:6\n\nFGT-1 (openstack) # a\n\nFGT-1 (openstack) # \nFGT-1 # ",
			"a\n",
		},
		{
			"several commands",
			"FGT-1 $ \nFGT-1 (vdom) $ current vf=openstack:6\n\nFGT-1 (openstack) $ \nFGT-1 (openstack) $ PING 192.0.2.1: 56 data bytes\n2 packets transmitted\n\nFGT-1 (openstack) $ \nFGT-1 (openstack) $ \nFGT-1 $ ",
			"PING 192.0.2.1: 56 data bytes\n2 packets transmitted\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fortiOSVDOMOutput(tt.in, "openstack")
			if err != nil || got != tt.want {
				t.Fatalf("fortiOSVDOMOutput() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// TestFortiOSVDOMOutputUnconfirmed checks that output is discarded unless
// FortiOS confirmed the switch to the requested VDOM.
func TestFortiOSVDOMOutputUnconfirmed(t *testing.T) {
	for name, in := range map[string]string{
		"edit failed":       "FGT-1 $ \nFGT-1 (vdom) $ entry not found in datasource\nCommand fail. Return code -3\n\nFGT-1 (vdom) $ Version: x\n\nFGT-1 (vdom) $ \nFGT-1 $ ",
		"another VDOM":      "FGT-1 $ \nFGT-1 (vdom) $ current vf=ads_mgmt:5\n\nFGT-1 (ads_mgmt) $ Version: x\n\nFGT-1 (ads_mgmt) $ \nFGT-1 $ ",
		"no config vdom":    "FGT-1 $ command parse error before 'vdom'\n\nFGT-1 $ Version: x\n\nFGT-1 $ ",
		"name only as text": "FGT-1 $ \nFGT-1 (vdom) $ current vf=openstack-old:7\n\nFGT-1 (openstack-old) $ x\n\nFGT-1 $ ",
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := fortiOSVDOMOutput(in, "openstack"); !errors.Is(err, errVDOMNotConfirmed) || got != "" {
				t.Fatalf("fortiOSVDOMOutput() = %q, %v; want errVDOMNotConfirmed", got, err)
			}
		})
	}
	paged := "FGT-1 $ \nFGT-1 (vdom) $ current vf=openstack:6\n\nFGT-1 (openstack) $ a\n--More-- \r         \rb\n\nFGT-1 (openstack) $ \nFGT-1 $ "
	if _, err := fortiOSVDOMOutput(paged, "openstack"); !errors.Is(err, errFortiOSPaged) {
		t.Fatalf("fortiOSVDOMOutput(paged) error = %v, want errFortiOSPaged", err)
	}
}

// vdomToolCalls runs each tool that takes vdom on a FortiGate.
var vdomToolCalls = map[string]func(ctx context.Context, dt, vdom string) error{
	"get_config": func(ctx context.Context, dt, vdom string) error {
		_, _, err := GetConfig(ctx, nil, GetConfigInput{Host: "fw1", Username: "u", DeviceType: dt, VDOM: vdom})
		return err
	},
	"run_show_command": func(ctx context.Context, dt, vdom string) error {
		command := "get system status"
		if dt != "fortios" {
			command = "show version"
		}
		_, _, err := RunShowCommand(ctx, nil, RunShowCommandInput{Host: "fw1", Username: "u", Command: command, DeviceType: dt, VDOM: vdom})
		return err
	},
	"run_ping": func(ctx context.Context, dt, vdom string) error {
		_, _, err := RunPing(ctx, nil, RunPingInput{Host: "fw1", Username: "u", Destination: "192.0.2.1", Count: 2, DeviceType: dt, VDOM: vdom})
		return err
	},
	"run_traceroute": func(ctx context.Context, dt, vdom string) error {
		_, _, err := RunTraceroute(ctx, nil, RunTracerouteInput{Host: "fw1", Username: "u", Destination: "192.0.2.1", DeviceType: dt, VDOM: vdom})
		return err
	},
}

type vdomRun struct {
	vdom     string
	commands []string
}

// stubRunInVDOM records the calls to runInVDOM and answers them with out
// and err; runCommand and runCommands must not be called.
func stubRunInVDOM(t *testing.T, out string, err error) *[]vdomRun {
	t.Helper()
	orig, origOne, origMany := runInVDOM, runCommand, runCommands
	t.Cleanup(func() { runInVDOM, runCommand, runCommands = orig, origOne, origMany })
	var runs []vdomRun
	runInVDOM = func(_ context.Context, _ sshclient.ConnConfig, vdom string, commands []string) (string, error) {
		runs = append(runs, vdomRun{vdom, commands})
		return out, err
	}
	runCommand = func(context.Context, sshclient.ConnConfig, string) (string, error) {
		t.Fatal("runCommand called")
		return "", nil
	}
	runCommands = func(context.Context, sshclient.ConnConfig, []string) (string, error) {
		t.Fatal("runCommands called")
		return "", nil
	}
	return &runs
}

func TestToolsRunInVDOM(t *testing.T) {
	want := map[string][]string{
		"get_config":       {"show full-configuration"},
		"run_show_command": {"get system status"},
		"run_ping":         {"execute ping-options repeat-count 2", "execute ping 192.0.2.1", "execute ping-options reset"},
		"run_traceroute":   {"execute traceroute 192.0.2.1", "execute traceroute-options reset"},
	}
	for name, call := range vdomToolCalls {
		t.Run(name, func(t *testing.T) {
			runs := stubRunInVDOM(t, "output\n", nil)
			if err := call(t.Context(), "fortios", "openstack"); err != nil {
				t.Fatalf("error = %v", err)
			}
			if len(*runs) != 1 || (*runs)[0].vdom != "openstack" || !slices.Equal((*runs)[0].commands, want[name]) {
				t.Fatalf("runInVDOM calls = %+v, want one in openstack running %q", *runs, want[name])
			}
		})
	}
}

func TestRunShowCommandReportsVDOM(t *testing.T) {
	stubRunInVDOM(t, "Version: FortiGate\n", nil)
	res, _, err := RunShowCommand(t.Context(), nil, RunShowCommandInput{Host: "fw1", Username: "u", Command: "get system status", DeviceType: "fortios", VDOM: "openstack"})
	if err != nil {
		t.Fatalf("RunShowCommand() error = %v", err)
	}
	texts := contentTexts(res.Content)
	if len(texts) != 2 || texts[0] != "Version: FortiGate\n" || !strings.HasPrefix(texts[1], "vdom: openstack") {
		t.Fatalf("content = %q, want the output and the vdom note", texts)
	}
}

// TestToolsRefuseVDOMBeforeRunning checks that a vdom that cannot be used is
// refused before anything runs.
func TestToolsRefuseVDOMBeforeRunning(t *testing.T) {
	for name, call := range vdomToolCalls {
		t.Run(name, func(t *testing.T) {
			stubRunInVDOM(t, "", nil)
			orig := runInVDOM
			runInVDOM = func(context.Context, sshclient.ConnConfig, string, []string) (string, error) {
				t.Fatal("runInVDOM called")
				return "", nil
			}
			t.Cleanup(func() { runInVDOM = orig })

			if err := call(t.Context(), "fortios", "open stack"); err == nil || !strings.Contains(err.Error(), "vdom may only contain") {
				t.Fatalf("invalid name: error = %v", err)
			}
			if err := call(t.Context(), "eos", "openstack"); err == nil || !strings.Contains(err.Error(), "only to device_type fortios") {
				t.Fatalf("eos: error = %v", err)
			}
		})
	}
}

func TestToolsReportVDOMErrors(t *testing.T) {
	notOnList := checkVDOM("openstak", []string{"openstack"}, "fw1")
	for name, call := range vdomToolCalls {
		t.Run(name, func(t *testing.T) {
			stubRunInVDOM(t, "", notOnList)
			err := call(t.Context(), "fortios", "openstak")
			if !errors.Is(err, errVDOMNotOnTheList) || !strings.Contains(err.Error(), `Did you mean "openstack"?`) {
				t.Fatalf("error = %v, want the not-on-the-list error with its suggestion", err)
			}
		})
	}
}

func stubListVDOMs(t *testing.T, info vdomInfo, err error) {
	t.Helper()
	orig := listVDOMs
	t.Cleanup(func() { listVDOMs = orig })
	listVDOMs = func(context.Context, sshclient.ConnConfig) (vdomInfo, error) { return info, err }
}

func TestFortigateListVDOMs(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: readFixture(t, "fortios_get_system_status.txt")}}).probe
	stubListVDOMs(t, vdomInfo{enabled: true, names: []string{"ads_mgmt", "openstack"}, current: "ads_mgmt"}, nil)

	res, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "fw1", Username: "u"})
	if err != nil {
		t.Fatalf("FortigateListVDOMs() error = %v", err)
	}
	want := "VDOMs this account can reach (reported by the device):\nads_mgmt (sessions start here)\nopenstack\n" +
		"Pass one of these as vdom to get_config, run_show_command, run_ping or run_traceroute; without vdom, commands run in ads_mgmt."
	if texts := contentTexts(res.Content); len(texts) != 1 || texts[0] != want {
		t.Fatalf("content = %q, want %q", texts, want)
	}
}

func TestFortigateListVDOMsRefusesOtherPlatforms(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identEOS, outputs: map[string]string{probeShowVersion: readFixture(t, "eos_show_version.txt")}}).probe
	stubListVDOMs(t, vdomInfo{}, errors.New("listVDOMs called"))
	if _, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "sw1", Username: "u"}); err == nil || !strings.Contains(err.Error(), "not a FortiGate") {
		t.Fatalf("FortigateListVDOMs() error = %v, want not a FortiGate", err)
	}
}

func TestVDOMReportWithoutVDOMs(t *testing.T) {
	got := vdomReport(vdomInfo{current: "root"})
	if !strings.HasPrefix(got, "This FortiGate does not use VDOMs") || !strings.Contains(got, "root") {
		t.Fatalf("vdomReport() = %q", got)
	}
}
