package netdev

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

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
// anything connects; "" (no vdom) passes. A valid name cannot carry another
// line into a command. Whether the device type takes a vdom at all is
// runOn's check.
func checkVDOMName(name string) error {
	if name != "" && !vdomNameRe.MatchString(name) {
		return fmt.Errorf("vdom may only contain letters, digits, '-' and '_' (up to 64 characters)")
	}
	return nil
}

// fortiOSErrorPattern matches the messages FortiOS prints for a command it
// refuses ("command parse error before ...", "Unknown action 0", "Command
// fail. Return code ...").
const fortiOSErrorPattern = `(?:command parse error|Unknown action|Command fail)`

var (
	// fortiOSLoginRe matches the end of what an interactive FortiOS shell
	// writes before it takes commands: a prompt, or a post-login banner that
	// asks to be accepted (fortiOSBannerRe), which the tools never do.
	fortiOSLoginRe = regexp.MustCompile(`(?:` + fortiOSShellPromptPattern + `)|` + fortiOSBannerPattern)
	// fortiOSShellPromptRe matches a prompt at the end of what was read.
	fortiOSShellPromptRe = regexp.MustCompile(fortiOSShellPromptPattern)
	fortiOSBannerRe      = regexp.MustCompile(fortiOSBannerPattern)
	// fortiOSConfigVDOMReplyRe matches the end of FortiOS's reply to "config
	// vdom": the prompt inside it, or a prompt after an error. Text that only
	// looks like a prompt, such as the end of a banner or a prompt drawn
	// again, matches neither, so it is read past rather than taken for the
	// reply.
	fortiOSConfigVDOMReplyRe = regexp.MustCompile(fortiOSVDOMModePromptPattern + `|(?s)` +
		fortiOSErrorPattern + `.*\n` + fortiOSPromptPattern + `\z`)
	fortiOSVDOMModePromptRe = regexp.MustCompile(fortiOSVDOMModePromptPattern)
	fortiOSErrorRe          = regexp.MustCompile(fortiOSErrorPattern)
	// fortiOSEditHelpRe matches the end of the help "edit ?" shows: the
	// prompt again, with the typed "edit " redrawn after it.
	fortiOSEditHelpRe = regexp.MustCompile(`\n` + fortiOSContextPromptPattern("vdom") + `edit \z`)
	// fortiOSEditRedrawRe matches that redrawn line on its own.
	fortiOSEditRedrawRe = regexp.MustCompile(`^` + fortiOSContextPromptPattern("vdom") + `edit$`)
)

// fortiOSShellPromptPattern matches a FortiOS prompt at the end of what was
// read.
const fortiOSShellPromptPattern = `(?:\A|\n)` + fortiOSPromptPattern + `\z`

// fortiOSVDOMModePromptPattern matches the prompt inside "config vdom" at the
// end of what was read. A VDOM named "vdom" gives the same prompt, so the
// reply to "config vdom" is also checked for an error.
const fortiOSVDOMModePromptPattern = `(?:\A|\n)` + fortiOSHostnamePattern + ` \(vdom\) [#$] \z`

// fortiOSBannerQuiet is how long the device must stay silent after a line
// that reads like a request to accept a banner before it is taken for one: a
// device asking for the key stops and waits, while a notice that only reads
// like it, cut off at the end of a read, goes on to the prompt. A variable
// so that tests can shorten it.
var fortiOSBannerQuiet = time.Second

// fortiOSBannerPattern matches FortiOS asking to accept a post-login banner
// ("(Press 'a' to accept):"): a line about pressing a key to accept that
// ends like a question, as the last thing the device wrote, since it then
// waits for the key. A notice that merely mentions both words and goes on
// to the prompt does not match, even if a read happens to end inside it.
// The wording is matched loosely: it has not been seen from a device here.
const fortiOSBannerPattern = `(?i)press\b[^\n]*\baccept[^\n]*[:?)] *\z`

var (
	errNoVDOMs           = newAnswer("this FortiGate does not use VDOMs, or this account cannot reach them; omit vdom")
	errUnexpectedVDOMs   = errors.New("FortiOS listed the VDOMs in an unexpected format")
	errVDOMNotConfirmed  = errors.New("FortiOS did not confirm the switch to the VDOM, so the output was discarded")
	errVDOMNotOnTheList  = newAnswer("VDOM not found")
	errVDOMNotApplicable = newAnswer("vdom applies only to device_type fortios")
	errVDOMsDisabled     = newAnswer("this FortiGate does not use VDOMs ('Virtual domain configuration: disable', from platform detection); " +
		"omit vdom, or call detect_platform with refresh=true if that has changed")
	errBannerToAccept = newAnswer("FortiOS asks to accept a post-login banner before its CLI takes commands, and the tools do not accept it on the user's behalf")
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
	login, err := sh.ReadUntil(ctx, fortiOSLoginRe)
	if err != nil {
		return nil, fmt.Errorf("wait for the FortiOS prompt: %w", err)
	}
	if fortiOSBannerRe.MatchString(login) {
		if err := awaitPromptAfterBanner(ctx, sh); err != nil {
			return nil, err
		}
	}
	if err := sh.Send("config vdom\r"); err != nil {
		return nil, err
	}
	reply, err := sh.ReadUntil(ctx, fortiOSConfigVDOMReplyRe)
	if err != nil {
		return nil, fmt.Errorf("enter config vdom: %w", err)
	}
	if fortiOSErrorRe.MatchString(reply) || !fortiOSVDOMModePromptRe.MatchString(reply) {
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

// awaitPromptAfterBanner waits up to fortiOSBannerQuiet for the prompt after
// a line that reads like a request to accept a banner. If the device stays
// silent it is waiting for the key, which the tools never press.
func awaitPromptAfterBanner(ctx context.Context, sh vdomShell) error {
	waitCtx, cancel := context.WithTimeout(ctx, fortiOSBannerQuiet)
	defer cancel()
	_, err := sh.ReadUntil(waitCtx, fortiOSShellPromptRe)
	switch {
	case err == nil:
		return nil
	case ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded):
		return errBannerToAccept
	default:
		return fmt.Errorf("wait for the FortiOS prompt: %w", err)
	}
}

// parseVDOMList reads the names FortiOS lists under "<vdom>" in its help for
// "edit ?", one per line, up to a blank line or the redrawn "edit" prompt.
// Spaces around a name are ignored. Anything else there, or no names at all,
// is an error rather than a partial list.
func parseVDOMList(help string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(help, "\r", ""), "\n")
	start := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "<vdom>") })
	if start < 0 {
		return nil, errUnexpectedVDOMs
	}
	var names []string
	for _, l := range lines[start+1:] {
		l = strings.TrimSpace(l)
		if l == "" || fortiOSEditRedrawRe.MatchString(l) {
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
	m := fortiOSVDOMSwitchRe.FindStringSubmatchIndex(out)
	if m == nil || out[m[2]:m[3]] != vdom || out[m[6]:m[7]] != vdom {
		return "", fmt.Errorf("%w (vdom %q)", errVDOMNotConfirmed, vdom)
	}
	vdomPrompt, rest := out[m[4]:m[5]], out[m[1]:]
	// The prompt after "end" may differ from the one the session started
	// at, so whichever prompt ends the output goes.
	if loc := fortiOSClosingPromptRe.FindStringIndex(rest); loc != nil {
		rest = rest[:loc[0]+1]
	}
	return fortiOSOutput(vdomPrompt + rest)
}

var (
	// fortiOSVDOMSwitchRe matches the start of vdomCommand's output, up to
	// the prompt the first command's output follows. It captures the VDOM
	// named in "current vf=", that prompt, and the VDOM the prompt names,
	// which fortiOSVDOMOutput compares with the one asked for.
	fortiOSVDOMSwitchRe = regexp.MustCompile(`\A` + fortiOSPromptPattern + `\n?` + fortiOSContextPromptPattern("vdom") +
		`current vf=([\w-]+):\d+\n+(` + fortiOSHostnamePattern + ` \(([\w-]+)\) [#$] )`)
	// fortiOSClosingPromptRe matches the prompt that ends vdomCommand's
	// output, after "end", in whatever context.
	fortiOSClosingPromptRe = regexp.MustCompile(`\n` + fortiOSPromptPattern + `\s*\z`)
)

// requireFortiOSServer is the CheckServerVersion for the VDOM paths, which
// type into an interactive FortiOS CLI. FortiOS identifies its SSH server
// with a random token, or as FortiSSH on older releases; anything else is
// refused before a session opens, so a device_type wrongly given as fortios
// never has "config vdom" typed into another CLI or a long wait for a
// FortiOS prompt.
func requireFortiOSServer(serverVersion string) error {
	if classifyIdent(serverVersion) != identObfuscated {
		return fmt.Errorf("%w: it identifies as %q, not as a FortiGate; vdom works only on FortiOS, so check device_type",
			errUnsupportedPlatform, displayValue(serverVersion))
	}
	return nil
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
	cfg.CheckServerVersion = requireFortiOSServer
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

// vdomInfo is what fortigate_list_vdoms reports. No names means the
// FortiGate does not use VDOMs, or the account cannot reach any.
type vdomInfo struct {
	names       []string // the VDOMs this account can reach
	globalScope bool     // the account's sessions start in the global context
	current     string   // the VDOM where the account's sessions start; never set with globalScope
}

// listVDOMs fetches vdomInfo for the FortiGate cfg points at; rt is its
// detected or explicit type. A variable so that tests can stub it.
var listVDOMs = fortiOSListVDOMs

var (
	vdomConfigRe  = regexp.MustCompile(`(?m)^Virtual domain configuration: ([\w-]+)`)
	currentVDOMRe = regexp.MustCompile(`(?m)^Current virtual domain: ([\w-]+)`)
	// fortiOSGlobalPromptRe matches the prompt inside "config global",
	// which only an account with global scope reaches.
	fortiOSGlobalPromptRe = regexp.MustCompile(`(?:\A|\n)` + fortiOSContextPromptPattern("global"))
)

// fortiOSScopeCommand enters the global context and leaves it again,
// changing nothing; an account without global scope gets an error instead
// ("Unknown action 3").
const fortiOSScopeCommand = "config global\nend"

// fortiOSListVDOMs finds out, on one connection, which VDOMs the account
// can reach and where its sessions start. The list comes first: with no
// VDOMs there is nothing more to find out. An account with global scope
// starts in the global context, although "get system status" names a VDOM
// there too ("Current virtual domain: root"); only for an account without it
// is that VDOM where its sessions start. The VDOM the probe read is used when
// this call detected the platform, so "get system status" does not run
// twice.
func fortiOSListVDOMs(ctx context.Context, cfg sshclient.ConnConfig, rt resolvedType) (vdomInfo, error) {
	cfg.CheckServerVersion = requireFortiOSServer
	conn, err := sshclient.Connect(ctx, cfg)
	if err != nil {
		return vdomInfo{}, err
	}
	defer func() { _ = conn.Close() }()

	names, err := listVDOMsOn(ctx, conn)
	if errors.Is(err, errNoVDOMs) {
		return vdomInfo{}, nil
	}
	if err != nil {
		return vdomInfo{}, fmt.Errorf("list VDOMs: %w", err)
	}
	info := vdomInfo{names: names}

	scope, err := conn.Run(ctx, fortiOSScopeCommand)
	var cmdErr *sshclient.CommandError
	if err != nil && !errors.As(err, &cmdErr) {
		return vdomInfo{}, err
	}
	if info.globalScope = fortiOSGlobalPromptRe.MatchString(scope); info.globalScope {
		return info, nil
	}
	if info.current = rt.currentVDOM; info.current == "" {
		status, err := conn.Run(ctx, probeSystemStatus)
		if err != nil {
			return vdomInfo{}, err
		}
		if status, err = fortiOSOutput(status); err != nil {
			return vdomInfo{}, err
		}
		info.current = fortiOSStatusField(currentVDOMRe, status)
	}
	return info, nil
}
