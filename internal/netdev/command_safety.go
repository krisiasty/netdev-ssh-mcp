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
// run other commands (save, redirect, tee, append, request, ...) are absent.
var allowedPipes = map[deviceType][]string{
	deviceTypeEOS:     {"json", "no-more", "include", "exclude", "begin", "section"},
	deviceTypeIOS:     {"include", "exclude", "begin", "section", "count"},
	deviceTypeNXOS:    {"json", "json-pretty", "xml", "no-more", "include", "exclude", "begin", "section", "count", "grep", "egrep", "last", "head"},
	deviceTypeJunos:   {"display", "no-more", "match", "except", "count", "last", "find", "trim"},
	deviceTypeFortiOS: {"grep"},
}

// junosDisplayFormats are the arguments allowed after JunOS "| display".
var junosDisplayFormats = []string{"json", "xml", "set"}

func pipesFor(dt deviceType) []string {
	if dt == "" {
		// No device_type means EOS/IOS syntax.
		return slices.Concat(allowedPipes[deviceTypeEOS], allowedPipes[deviceTypeIOS])
	}
	return allowedPipes[dt]
}

// checkOperationalCommand verifies that command is a single line holding a
// single command (no ";"), starts with verb as a whole word, uses no
// redirection, and pipes only into filters allowed for the platform.
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

	segments := strings.Split(command, "|")
	if fields := strings.Fields(segments[0]); len(fields) == 0 || !strings.EqualFold(fields[0], verb) {
		return fmt.Errorf("command must start with '%s'", verb)
	}

	allowed := pipesFor(dt)
	for _, seg := range segments[1:] {
		fields := strings.Fields(strings.ToLower(seg))
		if len(fields) == 0 {
			return fmt.Errorf("empty pipe in command")
		}
		if !slices.Contains(allowed, fields[0]) {
			return fmt.Errorf("pipe '| %s' is not allowed; allowed filters: %s", fields[0], strings.Join(allowed, ", "))
		}
		if dt == deviceTypeJunos && fields[0] == "display" &&
			(len(fields) != 2 || !slices.Contains(junosDisplayFormats, fields[1])) {
			return fmt.Errorf("'| display' must be followed by one of: %s", strings.Join(junosDisplayFormats, ", "))
		}
	}
	return nil
}
