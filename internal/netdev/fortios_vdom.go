package netdev

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// A FortiGate with multiple VDOMs runs each command in one of them. Without a
// vdom the tools run commands where the account's session starts. With one,
// the command is wrapped in "config vdom" / "edit <vdom>" / ... / "end",
// which is configuration mode: for an account that may create VDOMs, "edit"
// with a name that does not exist creates one. So the name is first checked
// against the VDOMs the device lists for this account, fetched on the same
// connection just before the command runs, and the command's output is only
// returned once FortiOS has confirmed the switch to that VDOM.
//
// FortiOS lists the VDOMs only interactively: "edit ?" in a shell shows the
// names, while in an exec session "?" is taken as part of the name. The
// listing types "config vdom" and Enter, then "edit ?" without Enter, reads
// the names, and closes the shell, which discards the typed "edit ".

// vdomNameRe is what a VDOM name may be: FortiOS allows letters, digits, "-"
// and "_". The length is left to the device's list.
var vdomNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// checkVDOMName rejects a vdom argument that cannot be a VDOM name, before
// anything connects. A valid name cannot carry another line into a command.
func checkVDOMName(name string) error {
	if !vdomNameRe.MatchString(name) {
		return fmt.Errorf("vdom may only contain letters, digits, '-' and '_' (up to 64 characters)")
	}
	return nil
}

// checkVDOMArg rejects a vdom argument on a device type without VDOMs.
func checkVDOMArg(vdom string, dt deviceType) error {
	if vdom != "" && dt != deviceTypeFortiOS {
		return fmt.Errorf("vdom applies only to device_type fortios, not %s", dt)
	}
	return nil
}

var (
	// fortiOSShellPromptRe matches a FortiOS CLI prompt at the end of what
	// was read: the login prompt, or the one after a command.
	fortiOSShellPromptRe = regexp.MustCompile(`(?:\A|\n)` + fortiOSPromptPattern + `\z`)
	// fortiOSVDOMModePromptRe matches the prompt inside "config vdom".
	fortiOSVDOMModePromptRe = regexp.MustCompile(`\(vdom\) [#$] \z`)
	// fortiOSEditHelpRe matches the end of the help "edit ?" shows: the
	// prompt again, with the typed "edit " redrawn after it.
	fortiOSEditHelpRe = regexp.MustCompile(`\n[\w.-]+ \(vdom\) [#$] edit \z`)
)

var (
	errNoVDOMs          = errors.New("this FortiGate does not use VDOMs, or this account cannot reach them")
	errUnexpectedVDOMs  = errors.New("FortiOS listed the VDOMs in an unexpected format")
	errVDOMNotConfirmed = errors.New("FortiOS did not confirm the switch to the VDOM, so the output was discarded")
	errVDOMNotOnTheList = errors.New("VDOM not found")
)

const listVDOMsCommandHint = "Call fortigate_list_vdoms to see the available VDOMs."

// vdomShell is the part of *sshclient.Shell the VDOM listing uses.
type vdomShell interface {
	Send(text string) error
	ReadUntil(ctx context.Context, re *regexp.Regexp) (string, error)
}

// fortiOSVDOMs lists the VDOMs the account can reach, over sh, an
// interactive FortiOS shell that has just started. It never enters anything
// after "edit": the caller closes sh, which discards the typed "edit ".
func fortiOSVDOMs(ctx context.Context, sh vdomShell) ([]string, error) {
	if _, err := sh.ReadUntil(ctx, fortiOSShellPromptRe); err != nil {
		return nil, fmt.Errorf("wait for the FortiOS prompt: %w", err)
	}
	if err := sh.Send("config vdom\r"); err != nil {
		return nil, err
	}
	prompt, err := sh.ReadUntil(ctx, fortiOSShellPromptRe)
	if err != nil {
		return nil, fmt.Errorf("enter config vdom: %w", err)
	}
	if !fortiOSVDOMModePromptRe.MatchString(prompt) {
		return nil, errNoVDOMs
	}
	if err := sh.Send("edit ?"); err != nil {
		return nil, err
	}
	help, err := sh.ReadUntil(ctx, fortiOSEditHelpRe)
	if err != nil {
		return nil, fmt.Errorf("read the VDOM list: %w", err)
	}
	return parseVDOMList(help)
}

// parseVDOMList reads the names FortiOS lists under "<vdom>" in its help for
// "edit ?", up to the first blank line. Anything else there, or no names at
// all, is an error rather than a partial list.
func parseVDOMList(help string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(help, "\r", ""), "\n")
	start := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "<vdom>") })
	if start < 0 {
		return nil, errUnexpectedVDOMs
	}
	var names []string
	for _, l := range lines[start+1:] {
		if l == "" {
			break
		}
		if !vdomNameRe.MatchString(l) {
			return nil, errUnexpectedVDOMs
		}
		names = append(names, l)
	}
	if len(names) == 0 {
		return nil, errUnexpectedVDOMs
	}
	return names, nil
}

// checkVDOM requires name to be one of available, exactly. Otherwise the
// error suggests up to three close names and points at fortigate_list_vdoms;
// it never picks one, since output from the wrong VDOM looks just as real.
func checkVDOM(name string, available []string, host string) error {
	if slices.Contains(available, name) {
		return nil
	}
	msg := fmt.Sprintf("VDOM %q is not one this account can reach on %q.", name, host)
	if s := suggestVDOMs(name, available); len(s) > 0 {
		quoted := make([]string, len(s))
		for i, v := range s {
			quoted[i] = fmt.Sprintf("%q", v)
		}
		msg += " Did you mean " + strings.Join(quoted, " or ") + "?"
	}
	return fmt.Errorf("%w: %s %s", errVDOMNotOnTheList, msg, listVDOMsCommandHint)
}

// maxVDOMSuggestions is how many close names an error suggests at most.
const maxVDOMSuggestions = 3

// suggestVDOMs returns the available names closest to name: one that differs
// only in case, then ones that start with name or that name starts with,
// then ones within a small edit distance, all ignoring case.
func suggestVDOMs(name string, available []string) []string {
	type candidate struct {
		name       string
		rank, dist int
	}
	lower := strings.ToLower(name)
	limit := max(2, len(name)/3)
	var found []candidate
	for _, v := range available {
		lv := strings.ToLower(v)
		d := editDistance(lower, lv)
		switch {
		case lv == lower:
			found = append(found, candidate{v, 0, 0})
		case strings.HasPrefix(lv, lower) || strings.HasPrefix(lower, lv):
			found = append(found, candidate{v, 1, d})
		case d <= limit:
			found = append(found, candidate{v, 2, d})
		}
	}
	slices.SortFunc(found, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(a.dist, b.dist), cmp.Compare(a.name, b.name))
	})
	var out []string
	for _, c := range found[:min(len(found), maxVDOMSuggestions)] {
		out = append(out, c.name)
	}
	return out
}

// editDistance is the Levenshtein distance between a and b, by bytes; VDOM
// names are ASCII.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// vdomCommand wraps commands so FortiOS runs them in vdom, which must have
// passed checkVDOM.
func vdomCommand(vdom string, commands []string) string {
	return "config vdom\nedit " + vdom + "\n" + strings.Join(commands, "\n") + "\nend"
}

// fortiOSVDOMOutput checks the output of vdomCommand: FortiOS must have
// confirmed the switch with "current vf=<vdom>:<index>" and a prompt naming
// the VDOM, as in
//
//	FGT-1 $
//	FGT-1 (vdom) $ current vf=<vdom>:6
//
//	FGT-1 (<vdom>) $ <output>
//
//	FGT-1 (<vdom>) $
//	FGT-1 $
//
// Otherwise the output may come from another context and is discarded. It
// returns the commands' output without the prompts, and refuses output that
// FortiOS paged, as fortiOSOutput does.
func fortiOSVDOMOutput(out, vdom string) (string, error) {
	if fortiOSPagedRe.MatchString(out) {
		return "", errFortiOSPaged
	}
	q := regexp.QuoteMeta(vdom)
	re := regexp.MustCompile(`\A(` + fortiOSPromptPattern + `)\n?[\w.-]+ \(vdom\) [#$] current vf=` + q + `:\d+\n+([\w.-]+ \(` + q + `\) [#$] )`)
	m := re.FindStringSubmatchIndex(out)
	if m == nil {
		return "", fmt.Errorf("%w (vdom %q)", errVDOMNotConfirmed, vdom)
	}
	startPrompt, vdomPrompt := out[m[2]:m[3]], out[m[4]:m[5]]
	rest := strings.TrimSuffix(out[m[1]:], startPrompt)
	return trimFortiOSPrompts(vdomPrompt + rest), nil
}

// listVDOMsOn lists the VDOMs over a shell on conn, and closes the shell.
func listVDOMsOn(ctx context.Context, conn *sshclient.Conn) ([]string, error) {
	sh, err := conn.Shell(ctx, terminalFor(deviceTypeFortiOS))
	if err != nil {
		return nil, err
	}
	defer func() { _ = sh.Close() }()
	return fortiOSVDOMs(ctx, sh)
}

// runInVDOM runs commands in vdom on the FortiGate cfg points at, and returns
// their output ready to report. A variable so that tests can stub it.
var runInVDOM = fortiOSRunInVDOM

// fortiOSRunInVDOM lists the VDOMs the account can reach over a shell,
// refuses vdom unless it is one of them, and only then runs commands in it
// over exec, all on one connection.
func fortiOSRunInVDOM(ctx context.Context, cfg sshclient.ConnConfig, vdom string, commands []string) (string, error) {
	conn, err := sshclient.Connect(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	available, err := listVDOMsOn(ctx, conn)
	if err != nil {
		return "", fmt.Errorf("list VDOMs: %w", err)
	}
	if err := checkVDOM(vdom, available, cfg.Host); err != nil {
		return "", err
	}
	out, err := conn.Run(ctx, vdomCommand(vdom, commands))
	if err != nil {
		return "", err
	}
	return fortiOSVDOMOutput(out, vdom)
}

// vdomInfo is what fortigate_list_vdoms reports.
type vdomInfo struct {
	enabled bool     // the FortiGate uses VDOMs and this account reaches them
	names   []string // the VDOMs this account can reach
	current string   // where this account's sessions start, if reported
}

// listVDOMs fetches vdomInfo for the FortiGate cfg points at. A variable so
// that tests can stub it.
var listVDOMs = fortiOSListVDOMs

var (
	vdomConfigRe  = regexp.MustCompile(`(?m)^Virtual domain configuration: ([\w-]+)`)
	currentVDOMRe = regexp.MustCompile(`(?m)^Current virtual domain: ([\w-]+)`)
)

// fortiOSListVDOMs reads "get system status" for whether VDOMs are in use
// and where the session starts, then lists the VDOMs, on one connection.
func fortiOSListVDOMs(ctx context.Context, cfg sshclient.ConnConfig) (vdomInfo, error) {
	conn, err := sshclient.Connect(ctx, cfg)
	if err != nil {
		return vdomInfo{}, err
	}
	defer func() { _ = conn.Close() }()

	status, err := conn.Run(ctx, "get system status")
	if err != nil {
		return vdomInfo{}, err
	}
	if status, err = fortiOSOutput(status); err != nil {
		return vdomInfo{}, err
	}
	var info vdomInfo
	if m := currentVDOMRe.FindStringSubmatch(status); m != nil {
		info.current = m[1]
	}
	if m := vdomConfigRe.FindStringSubmatch(status); m != nil && m[1] == "disable" {
		return info, nil
	}
	names, err := listVDOMsOn(ctx, conn)
	if errors.Is(err, errNoVDOMs) {
		return info, nil
	}
	if err != nil {
		return vdomInfo{}, fmt.Errorf("list VDOMs: %w", err)
	}
	info.enabled, info.names = true, names
	return info, nil
}
