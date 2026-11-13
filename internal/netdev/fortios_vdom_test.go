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
// for that text, and ReadUntil consumes what was written up to the earliest
// point where re matches, as if it arrived byte by byte. late is written
// after the first ReadUntil, like a prompt arriving after a banner.
type fakeVDOMShell struct {
	buf     string
	late    string
	replies map[string]string
	sent    []string
	reads   int
}

func (f *fakeVDOMShell) Send(text string) error {
	f.sent = append(f.sent, text)
	f.buf += f.replies[text]
	return nil
}

func (f *fakeVDOMShell) ReadUntil(_ context.Context, re *regexp.Regexp) (string, error) {
	defer func() {
		if f.reads++; f.reads == 1 {
			f.buf += f.late
		}
	}()
	for end := 1; end <= len(f.buf); end++ {
		if re.MatchString(f.buf[:end]) {
			out := f.buf[:end]
			f.buf = f.buf[end:]
			return out, nil
		}
	}
	// Like a shell whose wait for more output ran out.
	return "", fmt.Errorf("no match for %v in %q: %w", re, f.buf, context.DeadlineExceeded)
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

// TestFortiOSVDOMsAfterPromptShapedBanner checks that a banner ending in
// something prompt-shaped, read as the login prompt, does not make the real
// prompt that follows pass for the reply to "config vdom".
func TestFortiOSVDOMsAfterPromptShapedBanner(t *testing.T) {
	sh := &fakeVDOMShell{
		buf:  "Authorised use only\r\nNOTICE # ",
		late: "\r\nFGT-1 # ",
		replies: map[string]string{
			"config vdom\r": "config vdom\r\r\n\r\nFGT-1 (vdom) # ",
			"edit ?":        strings.ReplaceAll(vdomHelp, "(vdom) $", "(vdom) #"),
		},
	}
	got, err := fortiOSVDOMs(t.Context(), sh)
	if err != nil || !slices.Equal(got, []string{"ads_mgmt", "openstack", "openstk-tst"}) {
		t.Fatalf("fortiOSVDOMs() = %q, %v", got, err)
	}
}

func TestFortiOSVDOMsRefusesBannerToAccept(t *testing.T) {
	for _, banner := range []string{"(Press 'a' to accept):", "Press 'a' to accept or 'd' to decline: ", "PRESS A TO ACCEPT?"} {
		sh := &fakeVDOMShell{buf: "This system is for authorised use only.\r\n" + banner}
		if _, err := fortiOSVDOMs(t.Context(), sh); !errors.Is(err, errBannerToAccept) {
			t.Fatalf("%q: fortiOSVDOMs() error = %v, want errBannerToAccept", banner, err)
		}
		if len(sh.sent) != 0 {
			t.Fatalf("%q: sent %q, want nothing", banner, sh.sent)
		}
	}
}

// TestFortiOSVDOMsAfterNoticeCutAtColon checks that a notice line that
// reads like a request to accept, cut off by a read right after its ":", is
// not taken for one when the prompt follows.
func TestFortiOSVDOMsAfterNoticeCutAtColon(t *testing.T) {
	sh := &fakeVDOMShell{
		buf:  "Press Enter to continue; you accept monitoring (see policy):",
		late: "\r\nAuthorised use only.\r\nFGT-1 $ ",
		replies: map[string]string{
			"config vdom\r": "config vdom\r\r\n\r\nFGT-1 (vdom) $ ",
			"edit ?":        vdomHelp,
		},
	}
	if got, err := fortiOSVDOMs(t.Context(), sh); err != nil || len(got) != 3 {
		t.Fatalf("fortiOSVDOMs() = %q, %v; want the list", got, err)
	}
}

// TestFortiOSVDOMsInVDOMNamedVDOM checks that an account whose session
// starts in a VDOM named "vdom", where "config vdom" fails but the prompt
// still reads "(vdom)", is reported as having no VDOMs to reach, without
// typing "edit ?".
func TestFortiOSVDOMsInVDOMNamedVDOM(t *testing.T) {
	sh := &fakeVDOMShell{
		buf:     "FGT-1 (vdom) $ ",
		replies: map[string]string{"config vdom\r": "config vdom\r\r\ncommand parse error before 'vdom'\r\nCommand fail. Return code -61\r\n\r\nFGT-1 (vdom) $ "},
	}
	if _, err := fortiOSVDOMs(t.Context(), sh); !errors.Is(err, errNoVDOMs) {
		t.Fatalf("fortiOSVDOMs() error = %v, want errNoVDOMs", err)
	}
	if !slices.Equal(sh.sent, []string{"config vdom\r"}) {
		t.Fatalf("sent %q, want nothing after config vdom", sh.sent)
	}
}

// TestToolsRefuseVDOMWhereDetectionFoundNone checks that vdom on a FortiGate
// detection found without VDOMs is refused without logging in again.
func TestToolsRefuseVDOMWhereDetectionFoundNone(t *testing.T) {
	for name, call := range vdomToolCalls {
		t.Run(name, func(t *testing.T) {
			resetDetection(t)
			runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "disable", "root")}}).probe
			stubRunInVDOM(t, "", nil)
			orig := runInVDOM
			runInVDOM = func(context.Context, sshclient.ConnConfig, string, []string) (string, error) {
				t.Fatal("runInVDOM called")
				return "", nil
			}
			t.Cleanup(func() { runInVDOM = orig })
			err := call(t.Context(), "", "root")
			if !errors.Is(err, errVDOMsDisabled) || !strings.Contains(err.Error(), "omit vdom") || strings.Contains(err.Error(), "auto-detected") {
				t.Fatalf("error = %v, want errVDOMsDisabled telling to omit vdom, without notices", err)
			}
		})
	}
}

func TestShowVerbDeviceTypes(t *testing.T) {
	want := []deviceType{deviceTypeEOS, deviceTypeIOS, deviceTypeNXOS, deviceTypeJunos}
	if !slices.Equal(showVerbDeviceTypes, want) {
		t.Fatalf("showVerbDeviceTypes = %v, want %v", showVerbDeviceTypes, want)
	}
	for _, dt := range showVerbDeviceTypes {
		if _, err := normalizeOperationalCommand("show version", dt); err != nil {
			t.Errorf("%s does not take 'show version': %v", dt, err)
		}
	}
}

// TestFortiOSVDOMsAfterNoticeMentioningAccept checks that a notice that
// mentions pressing and accepting but goes on to the prompt is not taken for
// a banner to accept, even read in pieces (the fake delivers it as if byte
// by byte).
func TestFortiOSVDOMsAfterNoticeMentioningAccept(t *testing.T) {
	sh := &fakeVDOMShell{
		buf: "Press Ctrl-C to exit; continued use means you accept monitoring.\r\nFGT-1 $ ",
		replies: map[string]string{
			"config vdom\r": "config vdom\r\r\n\r\nFGT-1 (vdom) $ ",
			"edit ?":        vdomHelp,
		},
	}
	if got, err := fortiOSVDOMs(t.Context(), sh); err != nil || len(got) != 3 {
		t.Fatalf("fortiOSVDOMs() = %q, %v; want the list", got, err)
	}
}

func TestParseVDOMList(t *testing.T) {
	want := []string{"ads_mgmt", "openstack", "openstk-tst"}
	for name, help := range map[string]string{
		"as captured":          vdomHelp,
		"no blank line":        "edit \r\n<vdom>    Virtual Domain Name\r\nads_mgmt\r\nopenstack\r\nopenstk-tst\r\nFGT-1 (vdom) $ edit ",
		"padded names":         "edit \r\n<vdom>    Virtual Domain Name\r\n  ads_mgmt  \r\nopenstack \r\n\topenstk-tst\r\n\r\nFGT-1 (vdom) # edit ",
		"spaces on blank line": "edit \r\n<vdom>    Virtual Domain Name\r\nads_mgmt\r\nopenstack\r\nopenstk-tst\r\n   \r\nFGT-1 (vdom) $ edit ",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseVDOMList(help); err != nil || !slices.Equal(got, want) {
				t.Fatalf("parseVDOMList() = %q, %v; want %q", got, err, want)
			}
		})
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
	for _, name := range []string{"", "root", "ads_mgmt", "openstk-tst", "VDOM1", strings.Repeat("a", 64)} {
		if err := checkVDOMName(name); err != nil {
			t.Errorf("checkVDOMName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{" ", "a b", "root\nend", "root;end", "a.b", "?", strings.Repeat("a", 65)} {
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

// stubListVDOMs answers listVDOMs with info and err, and records the
// resolved types it was called with.
func stubListVDOMs(t *testing.T, info vdomInfo, err error) *[]resolvedType {
	t.Helper()
	orig := listVDOMs
	t.Cleanup(func() { listVDOMs = orig })
	var calls []resolvedType
	listVDOMs = func(_ context.Context, _ sshclient.ConnConfig, rt resolvedType) (vdomInfo, error) {
		calls = append(calls, rt)
		return info, err
	}
	return &calls
}

// fortiOSStatus is the probe output of a FortiGate with the given VDOM mode
// and current VDOM, after its CLI prompt.
func fortiOSStatus(t *testing.T, mode, current string) string {
	t.Helper()
	status := readFixture(t, "fortios_get_system_status.txt")
	status = strings.Replace(status, "Virtual domain configuration: disable", "Virtual domain configuration: "+mode, 1)
	status = strings.Replace(status, "Current virtual domain: root", "Current virtual domain: "+current, 1)
	if !strings.Contains(status, "Current virtual domain: "+current) {
		t.Fatal("fixture no longer has the lines this helper edits")
	}
	return "FGT-1 $ " + status + "\nFGT-1 $ "
}

// TestFortigateListVDOMsUsesDetection checks that the VDOM the detection
// probe just read reaches listVDOMs on that call only, and that a FortiGate
// detection found without VDOMs is answered without connecting again.
func TestFortigateListVDOMsUsesDetection(t *testing.T) {
	t.Run("current VDOM from this call's probe only", func(t *testing.T) {
		resetDetection(t)
		runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "multiple", "ads_mgmt")}}).probe
		calls := stubListVDOMs(t, vdomInfo{names: []string{"ads_mgmt"}, current: "ads_mgmt"}, nil)
		for range 2 {
			if _, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "fw1", Username: "u"}); err != nil {
				t.Fatal(err)
			}
		}
		if len(*calls) != 2 || (*calls)[0].currentVDOM != "ads_mgmt" || (*calls)[1].currentVDOM != "" {
			t.Fatalf("listVDOMs got %+v; want the current VDOM on the probing call only", *calls)
		}
	})
	t.Run("VDOMs disabled", func(t *testing.T) {
		resetDetection(t)
		runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "disable", "root")}}).probe
		calls := stubListVDOMs(t, vdomInfo{}, errors.New("listVDOMs called"))
		res, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "fw1", Username: "u"})
		if err != nil || len(*calls) != 0 {
			t.Fatalf("FortigateListVDOMs() = %v, listVDOMs calls = %d; want an answer without connecting", err, len(*calls))
		}
		if text := contentTexts(res.Content)[0]; !strings.HasPrefix(text, "This FortiGate does not use VDOMs") || !strings.Contains(text, "disable") {
			t.Fatalf("report = %q", text)
		}
	})
}

func TestVDOMReportGlobalScope(t *testing.T) {
	// fortiOSListVDOMs never sets current for a global account.
	got := vdomReport(vdomInfo{globalScope: true, names: []string{"root", "dmz"}})
	if strings.Contains(got, "sessions start here") || !strings.Contains(got, "global context") {
		t.Fatalf("vdomReport() = %q; want no VDOM marked and the global context named", got)
	}
}

func TestFortiOSGlobalPrompt(t *testing.T) {
	// Captured from a VDOM-scoped account; an account with global scope gets
	// the "(global)" prompt instead.
	vdomScoped := "fg2-cds $ 8826: Unknown action 3\nCommand fail. Return code -1\n\nfg2-cds $ 8826: Unknown action 0\nCommand fail. Return code -1\n\nfg2-cds $ "
	global := "FGT-1 # \nFGT-1 (global) # \nFGT-1 # "
	if fortiOSGlobalPromptRe.MatchString(vdomScoped) || !fortiOSGlobalPromptRe.MatchString(global) {
		t.Fatal("fortiOSGlobalPromptRe does not tell the scopes apart")
	}
}

// TestVDOMErrorsAreAnswers checks that a vdom the device does not list is
// logged as an answer and returned without the detection notice.
func TestVDOMErrorsAreAnswers(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "multiple", "ads_mgmt")}}).probe
	stubRunInVDOM(t, "", checkVDOM("openstak", []string{"openstack"}, "fw1"))
	_, _, err := RunShowCommand(t.Context(), nil, RunShowCommandInput{Host: "fw1", Username: "u", Command: "get system status", VDOM: "openstak"})
	if !errors.Is(err, errVDOMNotOnTheList) || strings.Contains(err.Error(), "auto-detected") {
		t.Fatalf("error = %v; want the VDOM error without the detection notice", err)
	}
	for _, e := range []error{errVDOMNotOnTheList, errVDOMNotApplicable, errNoVDOMs, errFortiOSPaged, errBannerToAccept} {
		if !answerError(fmt.Errorf("x: %w", e)) {
			t.Errorf("answerError(%v) = false", e)
		}
	}
	for _, e := range []error{errVDOMNotConfirmed, errUnexpectedVDOMs, errors.New("dial tcp: connection refused")} {
		if answerError(e) {
			t.Errorf("answerError(%v) = true; a device or connection failure is not an answer", e)
		}
	}
}

func TestFortigateListVDOMs(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "multiple", "ads_mgmt")}}).probe
	stubListVDOMs(t, vdomInfo{names: []string{"ads_mgmt", "openstack"}, current: "ads_mgmt"}, nil)

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
	if got := vdomReport(vdomInfo{}); !strings.HasPrefix(got, "This FortiGate does not use VDOMs") {
		t.Fatalf("vdomReport() = %q", got)
	}
}

// TestCheckCommandOnAnyPlatformShowRunningConfig checks that accepting
// FortiOS "show <path>" did not let through, before detection connects, the
// commands every "show" platform sends to get_config.
func TestCheckCommandOnAnyPlatformShowRunningConfig(t *testing.T) {
	for _, command := range []string{"show running-config", "show run", "show startup-config", "show running-config | include hostname"} {
		if err := checkCommandOnAnyPlatform(command); err == nil || !strings.Contains(err.Error(), "get_config") {
			t.Errorf("checkCommandOnAnyPlatform(%q) = %v, want the get_config redirect", command, err)
		}
	}
	for _, command := range []string{"show firewall service custom VersityGW-S3", "show router static | grep 10.0.0.0", "show full-configuration system interface"} {
		if err := checkCommandOnAnyPlatform(command); err != nil {
			t.Errorf("checkCommandOnAnyPlatform(%q) = %v, want a FortiOS show with a path accepted", command, err)
		}
	}
}

func TestRequireFortiOSServer(t *testing.T) {
	for _, ident := range []string{identFortiOS, identFortiSSH} {
		if err := requireFortiOSServer(ident); err != nil {
			t.Errorf("requireFortiOSServer(%q) = %v", ident, err)
		}
	}
	for _, ident := range []string{identEOS, identIOS, identNXOS, identJunos, identCumulus, identUbuntu} {
		if err := requireFortiOSServer(ident); !errors.Is(err, errUnsupportedPlatform) || !strings.Contains(err.Error(), "check device_type") {
			t.Errorf("requireFortiOSServer(%q) = %v, want an unsupported platform pointing at device_type", ident, err)
		}
	}
}

// TestFortiOSVDOMOutputClosingPrompt checks that the prompt after "end" is
// removed even when it is not the one the session started at.
func TestFortiOSVDOMOutputClosingPrompt(t *testing.T) {
	for name, in := range map[string]string{
		"start prompt with a context": "FGT (root) $ \nFGT (vdom) $ current vf=vd1:3\n\nFGT (vd1) $ out\n\nFGT (vd1) $ \nFGT $ ",
		"closing prompt redrawn":      "FGT $ \nFGT (vdom) $ current vf=vd1:3\n\nFGT (vd1) $ out\n\nFGT (vd1) $ \nFGT $ \n",
		"no prompt after end":         "FGT $ \nFGT (vdom) $ current vf=vd1:3\n\nFGT (vd1) $ out\n\nFGT (vd1) $ ",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := fortiOSVDOMOutput(in, "vd1"); err != nil || got != "out\n" {
				t.Fatalf("fortiOSVDOMOutput() = %q, %v; want %q", got, err, "out\n")
			}
		})
	}
}

// TestUnconfirmedVDOMHasNoNotice checks that a VDOM switch FortiOS did not
// confirm is reported without detection notices.
func TestUnconfirmedVDOMHasNoNotice(t *testing.T) {
	resetDetection(t)
	runProbe = (&fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "multiple", "ads_mgmt")}}).probe
	stubRunInVDOM(t, "", fmt.Errorf("%w (vdom %q)", errVDOMNotConfirmed, "openstack"))
	_, _, err := RunShowCommand(t.Context(), nil, RunShowCommandInput{Host: "fw1", Username: "u", Command: "get system status", VDOM: "openstack"})
	if !errors.Is(err, errVDOMNotConfirmed) || strings.Contains(err.Error(), "auto-detected") {
		t.Fatalf("error = %v; want the unconfirmed switch without the detection notice", err)
	}
}

// TestFortigateListVDOMsErrors checks that a failed listing suggests no
// device_type, which the tool does not take, and keeps the detection.
func TestFortigateListVDOMsErrors(t *testing.T) {
	resetDetection(t)
	f := &fakeProbe{ident: identFortiOS, outputs: map[string]string{probeSystemStatus: fortiOSStatus(t, "multiple", "ads_mgmt")}}
	runProbe = f.probe
	stubListVDOMs(t, vdomInfo{}, &sshclient.CommandError{Command: "get system status", Output: []byte("8826: Unknown action 0\nCommand fail. Return code -1\n")})
	for range 2 {
		_, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "fw1", Username: "u"})
		if err == nil || strings.Contains(err.Error(), "device_type") {
			t.Fatalf("error = %v; want the failure without a device_type suggestion", err)
		}
	}
	if f.calls != 1 {
		t.Fatalf("probes = %d, want 1: a failed listing must not drop the detection", f.calls)
	}
}

func TestStoreTypeDropsCurrentVDOM(t *testing.T) {
	resetDetection(t)
	storeType("fw1:22", resolvedType{dt: deviceTypeFortiOS, source: sourceProbe, vdomMode: "multiple", currentVDOM: "ads_mgmt"})
	r, ok := cachedType("fw1:22")
	if !ok || r.vdomMode != "multiple" || r.currentVDOM != "" {
		t.Fatalf("cachedType() = %+v, %v; want the VDOM mode kept and the current VDOM dropped", r, ok)
	}
}

// TestFortigateListVDOMsDeviceType checks the optional device_type: fortios
// skips detection, anything else is refused, and a device detected as
// another platform gets a way out.
func TestFortigateListVDOMsDeviceType(t *testing.T) {
	t.Run("fortios skips detection", func(t *testing.T) {
		resetDetection(t)
		f := &fakeProbe{ident: identFortiOS}
		runProbe = f.probe
		calls := stubListVDOMs(t, vdomInfo{names: []string{"root"}}, nil)
		if _, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "fw1", Username: "u", DeviceType: "fortigate"}); err != nil {
			t.Fatal(err)
		}
		if f.calls != 0 || len(*calls) != 1 {
			t.Fatalf("probes = %d, listVDOMs calls = %d; want no probe and one listing", f.calls, len(*calls))
		}
	})
	t.Run("other device_type", func(t *testing.T) {
		resetDetection(t)
		stubListVDOMs(t, vdomInfo{}, errors.New("listVDOMs called"))
		_, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "fw1", Username: "u", DeviceType: "eos"})
		if err == nil || !strings.Contains(err.Error(), "can only be fortios") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("detected as another platform", func(t *testing.T) {
		resetDetection(t)
		runProbe = (&fakeProbe{ident: identEOS, outputs: map[string]string{probeShowVersion: readFixture(t, "eos_show_version.txt")}}).probe
		stubListVDOMs(t, vdomInfo{}, errors.New("listVDOMs called"))
		_, _, err := FortigateListVDOMs(t.Context(), nil, FortigateListVDOMsInput{Host: "sw1", Username: "u"})
		if err == nil || !strings.Contains(err.Error(), "device_type=fortios") || !strings.Contains(err.Error(), "refresh=true") {
			t.Fatalf("error = %v, want the way out", err)
		}
	})
}
