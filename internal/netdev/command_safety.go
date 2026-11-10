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

// plainWordPattern is what a filter's argument (W in filterForms) may
// contain. On a Linux system bash runs the command and several filters (grep,
// egrep, head, last) are Linux programs, so a word holds no quotes,
// backslashes, "$", globs, brackets, braces, "~" or regex syntax other than
// "."; it also must not start with "-", so it cannot be an option.
var plainWordPattern = regexp.MustCompile(`^[A-Za-z0-9._:/,@%+=-]+$`)

const plainWordRule = "letters, digits and . _ : / , @ % + = -, not starting with '-'"

// numberPattern is what an N in filterForms may be.
var numberPattern = regexp.MustCompile(`^[0-9]{1,6}$`)

// filterForms lists, per platform, the only segments accepted after a "|" in
// run_show_command. In a form, "W" stands for one plain word and "N" for a
// number; every other word must match exactly, in lower case. Filters that
// write files, send messages or run other commands (save, redirect, tee,
// append, request, ...) are absent, and so is JunOS find: on a Linux system
// it is find(1), which can run programs and delete files.
var filterForms = map[deviceType][]string{
	deviceTypeEOS:     {"json", "no-more", "include W", "exclude W", "begin W", "section W"},
	deviceTypeIOS:     {"include W", "exclude W", "begin W", "section W", "count W"},
	deviceTypeNXOS:    {"json", "json-pretty", "xml", "no-more", "include W", "exclude W", "begin W", "section W", "count", "grep W", "egrep W", "head", "head lines N", "last", "last N"},
	deviceTypeJunos:   {"display json", "display xml", "display set", "no-more", "match W", "except W", "count", "last", "last N", "trim N"},
	deviceTypeFortiOS: {"grep W"},
}

// shellSyntax lists the shell constructs refused in run_show_command on every
// platform: command substitution, braces (parameter and brace expansion;
// "show {1..99999999}" makes bash build the whole list in memory) and "&"
// (background job, "&&"). The verb's arguments are not limited to plain
// words, so this is what keeps them from starting another command or
// exhausting memory; in filter arguments plainWordPattern excludes them as
// well.
var shellSyntax = []string{"`", "$(", "{", "}", "&"}

const shellSyntaxList = "'`', '$(', '{', '}' or '&'"

func isPlainWord(w string) bool {
	return plainWordPattern.MatchString(w) && !strings.HasPrefix(w, "-")
}

// spaceSeparated splits s into words on spaces; runs of spaces are allowed.
// checkOperationalCommand refuses any other whitespace first.
func spaceSeparated(s string) []string {
	return slices.DeleteFunc(strings.Split(s, " "), func(w string) bool { return w == "" })
}

// matchesForm reports whether words is exactly the filter form, a
// space-separated entry of filterForms.
func matchesForm(words []string, form string) bool {
	want := strings.Split(form, " ")
	if len(words) != len(want) {
		return false
	}
	for i, w := range want {
		switch w {
		case "W":
			if !isPlainWord(words[i]) {
				return false
			}
		case "N":
			if !numberPattern.MatchString(words[i]) {
				return false
			}
		default:
			if words[i] != w {
				return false
			}
		}
	}
	return true
}

// checkOperationalCommand verifies that command is a single line holding a
// single command (no ";"), uses no redirection or shell syntax, starts with
// verb exactly (lower case) as a whole word, and pipes only into the
// platform's filterForms. The command is split on "|" first, so "|" need not
// be surrounded by spaces, and each part is then split on spaces.
func checkOperationalCommand(command, verb string, dt deviceType) error {
	for _, r := range command {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return fmt.Errorf("command must be a single line without control characters")
		}
		if unicode.IsSpace(r) && r != ' ' {
			return fmt.Errorf("command words must be separated by plain spaces only")
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
	// wrong device_type must not let shell substitution or "&" through.
	for _, s := range shellSyntax {
		if strings.Contains(command, s) {
			return fmt.Errorf("command must not use shell syntax (%s)", shellSyntaxList)
		}
	}

	segments := strings.Split(command, "|")
	words := spaceSeparated(segments[0])
	if len(words) == 0 || !strings.EqualFold(words[0], verb) {
		return fmt.Errorf("command must start with '%s'", verb)
	}
	// On a Linux system the verb is a program name, and those are case
	// sensitive: GET is lwp-request, which fetches URLs.
	if words[0] != verb {
		return fmt.Errorf("command must start with '%s' in lower case", verb)
	}
	// The verb's own arguments are not limited to plain words, so that
	// commands such as "show ip bgp regexp ^65000_" work: on a Linux system
	// they only reach a "show" or "get" program that does not exist, and the
	// checks above already stop them from starting another command.

	forms := filterForms[dt]
	for _, seg := range segments[1:] {
		words := spaceSeparated(seg)
		if len(words) == 0 {
			return fmt.Errorf("empty pipe in command")
		}
		if !slices.ContainsFunc(forms, func(form string) bool { return matchesForm(words, form) }) {
			return fmt.Errorf("pipe '| %s' is not allowed; filters allowed on %s: %s; %s; "+
				"filter names are lower case and regular expressions other than '.' are not supported, "+
				"so when no filter fits, run the command without one and extract what you need from the output",
				strings.Join(words, " "), dt, strings.Join(forms, ", "), filterPlaceholders(forms))
		}
	}
	return nil
}

// filterPlaceholders explains the W and N placeholders used in forms.
func filterPlaceholders(forms []string) string {
	s := "W is one plain word (" + plainWordRule + ")"
	if slices.ContainsFunc(forms, func(form string) bool { return strings.HasSuffix(form, " N") }) {
		s += " and N is a number of up to 6 digits"
	}
	return s
}
