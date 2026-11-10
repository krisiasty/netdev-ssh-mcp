package netdev

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Every device command is sent in a single SSH exec request, and devices may
// run each line of that request as a separate command. Everything a caller
// supplies must therefore stay on one line and must not reach commands or
// pipes that change device state or write files.

// argPattern is what a destination, source, VRF or interface name may contain:
// IPv4/IPv6 addresses (with zone), hostnames and interface names such as
// Ethernet1/1, Gi0/0.100 or ae0.0. No whitespace, quotes, pipes or redirection.
var argPattern = regexp.MustCompile(`^[A-Za-z0-9._:/@%-]+$`)

const maxArgLen = 255

// checkCommandArg rejects a value that could change the command it is
// inserted into. An empty value is allowed; callers check required fields.
func checkCommandArg(name, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxArgLen || !argPattern.MatchString(value) {
		return fmt.Errorf("%s may only contain letters, digits and . _ : / @ %% -", name)
	}
	return nil
}

// checkCommandArgs checks the user-supplied parts of a ping or traceroute.
func checkCommandArgs(destination, source, vrf, outgoingInterface string) error {
	for _, a := range []struct{ name, value string }{
		{"destination", destination},
		{"source", source},
		{"vrf", vrf},
		{"outgoing_interface", outgoingInterface},
	} {
		if err := checkCommandArg(a.name, a.value); err != nil {
			return err
		}
	}
	return nil
}

// allowedPipes lists the output filters permitted after "|" in
// run_show_command, per platform. Filters that write files, send messages or
// run other commands (save, redirect, tee, append, request, ...) are absent,
// and so is JunOS find: on a Linux system it is find(1), which can run
// programs and delete files.
var allowedPipes = map[deviceType][]string{
	deviceTypeEOS:     {"json", "no-more", "include", "exclude", "begin", "section"},
	deviceTypeIOS:     {"include", "exclude", "begin", "section", "count"},
	deviceTypeNXOS:    {"json", "json-pretty", "xml", "no-more", "include", "exclude", "begin", "section", "count", "grep", "egrep", "last", "head"},
	deviceTypeJunos:   {"display", "no-more", "match", "except", "count", "last", "trim"},
	deviceTypeFortiOS: {"grep"},
}

// junosDisplayFormats are the arguments allowed after JunOS "| display".
var junosDisplayFormats = []string{"json", "xml", "set"}

// shellSyntax lists the shell constructs refused in run_show_command on every
// platform: command substitution, parameter expansion and "&" (background
// job, "&&").
var shellSyntax = []string{"`", "$(", "${", "&"}

const shellSyntaxList = "'`', '$(', '${' or '&'"

// filterArgPattern is what a word after a pipe filter's name may be. On a
// Linux system such as Cumulus Linux bash runs the command, and several
// filters (grep, egrep, head, last) are also Linux programs, so a word must
// not be able to start a command or expand to a leading "-": no quotes,
// backslashes, brackets, braces, "~" or parameters. "$" is allowed only as
// the last character, where bash leaves it alone, for regex anchors such as
// "up$". A glob after the first character ("x*", "/etc/*") can still expand
// to file names with the same prefix.
var filterArgPattern = regexp.MustCompile(`^[A-Za-z0-9._:/,@%^*+?=-]+\$?$`)

const filterArgChars = "letters, digits and . _ : / , @ % ^ * + ? = -"

// checkOperationalCommand verifies that command is a single line holding a
// single command (no ";"), starts with verb exactly (lower case) as a whole
// word, uses no redirection or shell syntax, and pipes only into filters
// allowed for the platform, named exactly (lower case), each argument of
// which matches filterArgPattern and does not start with "-", "*" or "?".
func checkOperationalCommand(command, verb string, dt deviceType) error {
	for _, r := range command {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return fmt.Errorf("command must be a single line without control characters")
		}
	}
	// Some CLIs (IOS XE, NX-OS) accept ";" as a command separator.
	if strings.Contains(command, ";") {
		return fmt.Errorf("command must be a single command without ';'; a filter can match it with the regex wildcard '.', which matches any character and may return extra lines (for example '| include foo.bar')")
	}
	if strings.ContainsAny(command, "<>") {
		return fmt.Errorf("command must not use redirection ('<' or '>')")
	}
	// On a Linux system such as Cumulus Linux a shell runs the command, so a
	// wrong device_type must not let shell substitution or "&" through. A
	// bare "$" stays allowed for regex anchors such as "| include up$".
	for _, s := range shellSyntax {
		if strings.Contains(command, s) {
			return fmt.Errorf("command must not use shell syntax (%s)", shellSyntaxList)
		}
	}

	segments := strings.Split(command, "|")
	fields := strings.Fields(segments[0])
	if len(fields) == 0 || !strings.EqualFold(fields[0], verb) {
		return fmt.Errorf("command must start with '%s'", verb)
	}
	// On a Linux system the verb is a program name, and those are case
	// sensitive: GET is lwp-request, which fetches URLs.
	if fields[0] != verb {
		return fmt.Errorf("command must start with '%s' in lower case", verb)
	}

	allowed := allowedPipes[dt]
	for _, seg := range segments[1:] {
		// Words are split on spaces only; any other whitespace fails the
		// argument pattern below.
		words := slices.DeleteFunc(strings.Split(seg, " "), func(w string) bool { return w == "" })
		if len(words) == 0 {
			return fmt.Errorf("empty pipe in command")
		}
		// The name must match exactly, like the verb: on a Linux system
		// HEAD and GET are lwp-request, which fetches URLs.
		filter := words[0]
		if !slices.Contains(allowed, filter) {
			if slices.Contains(allowed, strings.ToLower(filter)) {
				return fmt.Errorf("pipe filter '| %s' must be in lower case", filter)
			}
			return fmt.Errorf("pipe '| %s' is not allowed; allowed filters: %s", filter, strings.Join(allowed, ", "))
		}
		for _, arg := range words[1:] {
			if !filterArgPattern.MatchString(arg) {
				return fmt.Errorf("pipe filter arguments may contain only %s, with '$' only as the last character of a word; quotes, brackets and backslashes are not accepted (use '.' to match a space or any character)", filterArgChars)
			}
			// A leading "-" is an option; a leading "*" or "?" is a glob
			// that can expand to a file name starting with "-".
			if strings.ContainsAny(arg[:1], "-*?") {
				return fmt.Errorf("pipe filter arguments must not start with '-', '*' or '?'")
			}
		}
		if dt == deviceTypeJunos && filter == "display" &&
			(len(words) != 2 || !slices.Contains(junosDisplayFormats, words[1])) {
			if len(words) == 2 && slices.Contains(junosDisplayFormats, strings.ToLower(words[1])) {
				return fmt.Errorf("'| display' format must be in lower case")
			}
			return fmt.Errorf("'| display' must be followed by one of: %s", strings.Join(junosDisplayFormats, ", "))
		}
	}
	return nil
}
