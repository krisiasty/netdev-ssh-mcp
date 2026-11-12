package netdev

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// cumulusMergeStderr is appended to every command built for Cumulus Linux 4.x.
// NCLU's error stream is undocumented, so stderr is merged into stdout to make
// sure it reaches obfuscation. It is the only shell syntax the server adds.
const cumulusMergeStderr = " 2>&1"

// On Cumulus Linux, ping and traceroute are wrapped by vrf-wrapper.sh, which
// moves a command started in the management VRF to the default VRF unless it
// is given --no-vrf-switch. An SSH login runs in the management VRF while that
// VRF is enabled, which is the Cumulus default.
const (
	cumulusMgmtVRF    = "mgmt"
	cumulusDefaultVRF = "default"
	// cumulusNoVRFSwitch keeps the command in the login's VRF.
	cumulusNoVRFSwitch = "--no-vrf-switch"
)

// cumulusWordChars is what each word of a Cumulus "net show" command may
// contain. An SSH exec request is run by bash on Cumulus, so every shell
// metacharacter (quotes, $, ;, &, |, <, >, parentheses, globs, ~, !, #, =)
// must be excluded, along with whitespace other than ' '.
var cumulusWordChars = newWordClass("._:/,@%-")

// cumulusBlockedFamilies are NCLU "net show" sub-commands that return
// configuration or pending-change data; NCLU accepts any unambiguous prefix.
var cumulusBlockedFamilies = []string{"configuration", "commit", "rollback"}

// cumulusShowWords splits command (already trimmed) into its words and
// verifies that bash cannot split it into anything else and that it starts
// with "<tool> show". It is the check shared by NCLU (net) and NVUE (nv).
func cumulusShowWords(command, tool string) ([]string, error) {
	words := spaceSeparated(command)
	for _, w := range words {
		if !cumulusWordChars.match(w) {
			return nil, fmt.Errorf("command may only contain %s in words separated by spaces", cumulusWordChars.rule)
		}
	}
	if len(words) < 2 || words[0] != tool || words[1] != "show" {
		return nil, fmt.Errorf("command must start with '%s show'", tool)
	}
	return words, nil
}

// normalizeCumulusCommand verifies that command (already trimmed) is a single
// "net show" command that bash cannot split into anything else, and appends
// cumulusMergeStderr. The returned command is otherwise exactly as written.
func normalizeCumulusCommand(command string) (string, error) {
	words, err := cumulusShowWords(command, "net")
	if err != nil {
		return "", err
	}
	for _, w := range words[2:] {
		if isOption(w) {
			return "", fmt.Errorf("command words must not start with '-'")
		}
	}
	if len(words) > 2 {
		lower := strings.ToLower(words[2])
		for _, family := range cumulusBlockedFamilies {
			if strings.HasPrefix(family, lower) {
				return "", fmt.Errorf("use the get_config tool to retrieve device configuration")
			}
		}
	}
	return command + cumulusMergeStderr, nil
}

// checkCumulusNetArgs applies the Cumulus-only rules for ping and traceroute
// arguments: bash would read a leading '-' as an option, vrf and source
// cannot both be given, and outgoing_interface does not exist.
func checkCumulusNetArgs(destination, source, vrf, outgoingInterface string) error {
	for _, a := range []struct{ name, value string }{
		{"destination", destination},
		{"source", source},
		{"vrf", vrf},
	} {
		if isOption(a.value) {
			return fmt.Errorf("%s must not start with '-'", a.name)
		}
	}
	if vrf != "" && source != "" {
		return fmt.Errorf("on Cumulus Linux, vrf cannot be combined with source")
	}
	if outgoingInterface != "" {
		return fmt.Errorf("outgoing_interface is only supported for device_type 'fortios'")
	}
	return nil
}

// isAddress reports whether s is an IP address rather than an interface name.
func isAddress(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// buildCumulusPing builds the Linux iputils ping command. The count defaults
// to 5 because ping would otherwise run until the command timeout.
func buildCumulusPing(destination string, count, size, timeout int, source, vrf, outgoingInterface string) ([]string, error) {
	if err := checkCumulusNetArgs(destination, source, vrf, outgoingInterface); err != nil {
		return nil, err
	}
	if count <= 0 {
		count = 5
	}
	parts := []string{"ping", "-c", fmt.Sprintf("%d", count)}
	if size > 0 {
		parts = append(parts, "-s", fmt.Sprintf("%d", size))
	}
	if timeout > 0 {
		parts = append(parts, "-W", fmt.Sprintf("%d", timeout))
	}
	// -I takes an address, an interface or a VRF device. The default VRF
	// has no device; vrf-wrapper.sh already runs ping there.
	switch {
	case source != "":
		parts = append(parts, "-I", source)
	case vrf != "" && vrf != cumulusDefaultVRF:
		parts = append(parts, "-I", vrf)
	}
	parts = append(parts, destination)
	return []string{strings.Join(parts, " ") + cumulusMergeStderr}, nil
}

// buildCumulusTraceroute builds the Linux traceroute command. -s takes a
// source address and -i an interface or VRF device. -i binds the socket to
// that device, which on the 4.19 kernel of Cumulus 4.x needs root, and
// traceroute, unlike ping, has no capability to do it for other users. So the
// management VRF is reached by staying in the login's VRF (--no-vrf-switch),
// and the default VRF, which has no device, by letting vrf-wrapper.sh switch.
func buildCumulusTraceroute(destination string, maxHops, timeout, probe int, source, vrf, outgoingInterface string) ([]string, error) {
	if err := checkCumulusNetArgs(destination, source, vrf, outgoingInterface); err != nil {
		return nil, err
	}
	parts := []string{"traceroute"}
	if vrf == cumulusMgmtVRF {
		parts = append(parts, cumulusNoVRFSwitch)
	}
	if maxHops > 0 {
		parts = append(parts, "-m", fmt.Sprintf("%d", maxHops))
	}
	if timeout > 0 {
		parts = append(parts, "-w", fmt.Sprintf("%d", timeout))
	}
	if probe > 0 {
		parts = append(parts, "-q", fmt.Sprintf("%d", probe))
	}
	switch {
	case source != "" && isAddress(source):
		parts = append(parts, "-s", source)
	case source != "":
		parts = append(parts, "-i", source)
	case vrf != "" && vrf != cumulusMgmtVRF && vrf != cumulusDefaultVRF:
		parts = append(parts, "-i", vrf)
	}
	parts = append(parts, destination)
	return []string{strings.Join(parts, " ") + cumulusMergeStderr}, nil
}

// isCumulus reports whether dt is a Cumulus Linux platform.
func isCumulus(dt deviceType) bool {
	return dt == deviceTypeCumulus4x || dt == deviceTypeCumulus5x
}

// cumulusPingNoReplyOutput returns the command output when a Cumulus ping
// exited with status 1, which Linux ping uses for "no reply received". That
// is a result, not a failure; any other status stays an error. It is not used
// for traceroute: Linux traceroute exits 0 for a completed trace, reachable or
// not, and uses a non-zero status, 1 included, for errors such as a source
// interface it cannot bind.
func cumulusPingNoReplyOutput(dt deviceType, err error) (string, bool) {
	var cmdErr *sshclient.CommandError
	if !isCumulus(dt) || !errors.As(err, &cmdErr) || cmdErr.ExitStatus != 1 {
		return "", false
	}
	return string(cmdErr.Output), true
}

// cumulusNetError adds the device output to the error of a failed Cumulus
// ping or traceroute. Linux states the reason only there ("connect: Network
// is unreachable", "setsockopt SO_BINDTODEVICE: Operation not permitted"),
// and that output holds no secrets: it is returned unobfuscated on success.
// Call it after logging, so the output stays out of the log.
func cumulusNetError(dt deviceType, err error) error {
	var cmdErr *sshclient.CommandError
	if !isCumulus(dt) || !errors.As(err, &cmdErr) {
		return err
	}
	out := strings.TrimSpace(string(cmdErr.Output))
	if out == "" {
		return err
	}
	return fmt.Errorf("%w; device output:\n%s", err, out)
}
