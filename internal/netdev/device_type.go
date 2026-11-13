package netdev

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

type deviceType string

const (
	deviceTypeEOS     deviceType = "eos"
	deviceTypeIOS     deviceType = "ios"
	deviceTypeNXOS    deviceType = "nxos"
	deviceTypeJunos   deviceType = "junos"
	deviceTypeFortiOS deviceType = "fortios"

	deviceTypeCumulus4x deviceType = "cumulus4x"
)

var (
	runCommand  = sshclient.RunCommand
	runCommands = sshclient.RunCommands
)

// runOn runs a tool's commands and returns their output ready to report. With
// vdom, which checkVDOMName has accepted, they run in that VDOM (runInVDOM);
// a vdom on any device type but fortios is refused here, so no tool can send
// "config vdom" to another platform. Otherwise one command runs on its own
// and several are sent together in one exec request, and the output goes
// through deviceOutput.
func runOn(ctx context.Context, cfg sshclient.ConnConfig, dt deviceType, vdom string, commands []string) (string, error) {
	if vdom != "" {
		if dt != deviceTypeFortiOS {
			return "", fmt.Errorf("%w, not %s", errVDOMNotApplicable, dt)
		}
		return runInVDOM(ctx, cfg, vdom, commands)
	}
	var out string
	var err error
	if len(commands) == 1 {
		out, err = runCommand(ctx, cfg, commands[0])
	} else {
		out, err = runCommands(ctx, cfg, commands)
	}
	if err != nil {
		return out, err
	}
	return deviceOutput(dt, out)
}

// vdomNotice tells the caller which VDOM a command ran in, or nothing when
// none was asked for.
func vdomNotice(vdom string) []mcp.Content {
	if vdom == "" {
		return nil
	}
	return []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("vdom: %s (FortiOS confirmed the switch to it)", vdom)}}
}

// longCommandTimeout is the command timeout for ping and traceroute, which
// wait on the network rather than the device: a traceroute towards an
// unreachable destination can probe every hop until it gives up, which takes
// minutes. A longer --command-timeout still wins.
const longCommandTimeout = 5 * time.Minute

func connConfig(host string, port int, username string) sshclient.ConnConfig {
	return sshclient.ConnConfig{
		Host:     host,
		Port:     port,
		Username: username,
	}
}

// terminalFor returns the pseudo-terminal the client must request on dt, or
// nil.
//
// FortiOS pages its output at "--More--" when the console output mode is
// "more", even in an SSH exec session, where it does not wait for a key: it
// erases the prompt, carries on, and ends the command a few pages in, so long
// output such as show full-configuration comes back cut short. The page
// follows the terminal height, which an exec session without a terminal does
// not set. A terminal fortiOSTerminalRows high leaves nothing to page in
// output of up to that many lines; longer output still pages, and
// fortiOSOutput refuses it. "set output standard" under "config system
// console" turns the pager off altogether, but changes the configuration.
//
// The other platforms do not page exec output, or have it disabled with
// "| no-more" by the command builders.
func terminalFor(dt deviceType) *sshclient.Terminal {
	if dt == deviceTypeFortiOS {
		return &sshclient.Terminal{Rows: fortiOSTerminalRows, Cols: 512}
	}
	return nil
}

// fortiOSTerminalRows is the most rows FortiOS takes: it keeps only the low
// 16 bits of the requested height, so 65536 rows would be 0.
const fortiOSTerminalRows = 65535

// errDeviceTypeUnresolved guards the command builders: callers must resolve
// an omitted device_type (resolveDeviceType) before building a command, so
// no platform's syntax is ever assumed.
var errDeviceTypeUnresolved = errors.New("device type is not resolved")

// normalizeDeviceType parses a caller-supplied device_type. An empty value
// returns "" and means "detect it".
func normalizeDeviceType(raw string) (deviceType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(deviceTypeEOS):
		return deviceTypeEOS, nil
	case string(deviceTypeIOS):
		return deviceTypeIOS, nil
	case string(deviceTypeNXOS):
		return deviceTypeNXOS, nil
	case string(deviceTypeJunos):
		return deviceTypeJunos, nil
	case "fortigate", string(deviceTypeFortiOS):
		return deviceTypeFortiOS, nil
	case string(deviceTypeCumulus4x):
		return deviceTypeCumulus4x, nil
	default:
		return "", fmt.Errorf("device_type must be 'eos', 'ios', 'nxos', 'junos', 'fortios', or 'cumulus4x', got %q", raw)
	}
}

func normalizeConfigType(raw string) (string, error) {
	configType := strings.ToLower(strings.TrimSpace(raw))
	if configType == "" {
		configType = "running"
	}
	if configType != "running" && configType != "startup" {
		return "", fmt.Errorf("config_type must be 'running' or 'startup', got %q", raw)
	}
	return configType, nil
}

func buildConfigCommand(configType string, dt deviceType) (string, error) {
	switch dt {
	case deviceTypeJunos:
		if configType == "startup" {
			return "", fmt.Errorf("JunOS does not have a startup-config; use config_type 'running' or omit it")
		}
		return "show configuration | no-more", nil
	case deviceTypeFortiOS:
		if configType == "startup" {
			return "", fmt.Errorf("FortiOS does not have a startup-config; use config_type 'running' or omit it")
		}
		return "show full-configuration", nil
	case deviceTypeCumulus4x:
		if configType == "startup" {
			return "", fmt.Errorf("config_type startup: Cumulus Linux does not have a separate startup-config; use config_type 'running' or omit it")
		}
		return "net show configuration commands" + cumulusMergeStderr, nil
	case deviceTypeIOS:
		return fmt.Sprintf("show %s-config", configType), nil
	case deviceTypeEOS, deviceTypeNXOS:
		return fmt.Sprintf("show %s-config | no-more", configType), nil
	default:
		return "", fmt.Errorf("%w: %q", errDeviceTypeUnresolved, dt)
	}
}

// allDeviceTypes lists every supported platform.
var allDeviceTypes = []deviceType{deviceTypeEOS, deviceTypeIOS, deviceTypeNXOS, deviceTypeJunos, deviceTypeFortiOS, deviceTypeCumulus4x}

// checkCommandOnAnyPlatform rejects a run_show_command command that no
// supported platform would accept, so it fails before detection logs in to
// the device. The platform's own check still runs once the type is known.
func checkCommandOnAnyPlatform(command string) error {
	// Only Cumulus commands start with "net", and only FortiOS commands with
	// "get"; that platform's error is the useful one. A "show" command is
	// tried on every platform, FortiOS included.
	first, _, _ := strings.Cut(strings.TrimSpace(command), " ")
	switch {
	case first == "net":
		_, err := normalizeCumulusCommand(strings.TrimSpace(command))
		return err
	case strings.EqualFold(first, "get"):
		_, err := normalizeOperationalCommand(command, deviceTypeFortiOS)
		return err
	}
	var firstErr error
	for _, dt := range allDeviceTypes {
		_, err := normalizeOperationalCommand(command, dt)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func normalizeOperationalCommand(command string, dt deviceType) (string, error) {
	if dt == "" {
		return "", errDeviceTypeUnresolved
	}
	trimmed := strings.TrimSpace(command)
	lower := strings.ToLower(trimmed)

	if dt == deviceTypeCumulus4x {
		return normalizeCumulusCommand(trimmed)
	}
	if dt == deviceTypeFortiOS {
		return normalizeFortiOSOperationalCommand(trimmed, lower)
	}

	if err := checkOperationalCommand(trimmed, "show", dt); err != nil {
		return "", err
	}
	// The second word is checked on its own, so runs of spaces do not hide
	// it; the command itself is sent as written. "sta" means startup-config
	// on EOS and NX-OS; on IOS it is ambiguous and the device rejects it anyway, so it
	// is refused everywhere. Longer words that are not abbreviations of
	// startup-config, such as standby, stacks or statistics, are allowed.
	words := spaceSeparated(strings.Split(lower, "|")[0])
	second := ""
	if len(words) > 1 {
		second = words[1]
	}
	if strings.HasPrefix(second, "ru") || second == "sta" || strings.HasPrefix(second, "star") {
		return "", fmt.Errorf("use the get_config tool for running-config and startup-config")
	}
	// The JunOS CLI accepts any unambiguous abbreviation of "configuration"
	// ("show conf"); "con" and shorter are ambiguous there.
	if dt == deviceTypeJunos && len(second) >= 4 && strings.HasPrefix("configuration", second) {
		return "", fmt.Errorf("use the get_config tool to retrieve device configuration")
	}

	return trimmed, nil
}

// normalizeFortiOSOperationalCommand accepts "get" commands and "show" of
// part of the configuration on FortiOS. Both only read; the whole
// configuration is get_config's job, and configuration mode, execute and
// diagnose are refused or sent to their tools.
func normalizeFortiOSOperationalCommand(command, lower string) (string, error) {
	switch {
	case lower == "show" || strings.HasPrefix(lower, "show ") || strings.HasPrefix(lower, "show|"):
		return normalizeFortiOSShow(command)
	case strings.HasPrefix(lower, "config"):
		return "", fmt.Errorf("FortiOS configuration mode is not supported here; use get_config to retrieve configuration")
	case strings.HasPrefix(lower, "execute ping"), strings.HasPrefix(lower, "execute traceroute"):
		return "", fmt.Errorf("use run_ping or run_traceroute for FortiOS diagnostics")
	case strings.HasPrefix(lower, "execute"):
		return "", fmt.Errorf("FortiOS execute commands are not supported here; use run_ping or run_traceroute for diagnostics")
	case strings.HasPrefix(lower, "diagnose"):
		return "", fmt.Errorf("FortiOS diagnose commands are not supported by run_show_command")
	case !strings.HasPrefix(lower, "get"):
		return "", fmt.Errorf("FortiOS reads must use a 'get' command, or 'show' with a configuration path")
	}
	if err := checkOperationalCommand(command, "get", deviceTypeFortiOS); err != nil {
		return "", err
	}
	return command, nil
}

// errFortiOSWholeConfig redirects a "show" without a path to get_config.
var errFortiOSWholeConfig = fmt.Errorf("use the get_config tool to retrieve the whole FortiOS configuration; " +
	"run_show_command takes 'show' or 'show full-configuration' only with a path, such as 'show firewall service custom' or 'show router static'")

// normalizeFortiOSShow accepts "show <path> [entry]" and "show
// full-configuration <path> [entry]", which print that part of the
// configuration, with the same word and filter rules as "get". Without a
// path they print all of it, which get_config retrieves. FortiOS accepts
// any unambiguous abbreviation, and where few commands are offered (an exec
// session outside a VDOM) even "show f" means "show full-configuration", so
// every prefix of full-configuration counts as one.
func normalizeFortiOSShow(command string) (string, error) {
	if err := checkOperationalCommand(command, "show", deviceTypeFortiOS); err != nil {
		return "", err
	}
	path := spaceSeparated(strings.Split(command, "|")[0])[1:]
	if len(path) > 0 && strings.HasPrefix("full-configuration", strings.ToLower(path[0])) {
		path = path[1:]
	}
	if len(path) == 0 {
		return "", errFortiOSWholeConfig
	}
	return command, nil
}

func buildPingCommands(destination string, dt deviceType, count, size, timeout int, source, vrf, outgoingInterface string) ([]string, error) {
	if dt == "" {
		return nil, errDeviceTypeUnresolved
	}
	if err := checkCommandArgs(destination, source, vrf, outgoingInterface); err != nil {
		return nil, err
	}
	if dt == deviceTypeCumulus4x {
		return buildCumulusPing(destination, count, size, timeout, source, vrf, outgoingInterface)
	}
	if dt == deviceTypeFortiOS {
		if vrf != "" {
			return nil, fmt.Errorf("FortiOS 7.4+ does not support vrf for run_ping")
		}

		commands := make([]string, 0, 6)
		if count > 0 {
			commands = append(commands, fmt.Sprintf("execute ping-options repeat-count %d", count))
		}
		if size > 0 {
			commands = append(commands, fmt.Sprintf("execute ping-options data-size %d", size))
		}
		if timeout > 0 {
			commands = append(commands, fmt.Sprintf("execute ping-options timeout %d", timeout))
		}
		if source != "" {
			commands = append(commands, fmt.Sprintf("execute ping-options source %s", source))
		}
		if outgoingInterface != "" {
			commands = append(commands, fmt.Sprintf("execute ping-options interface %s", outgoingInterface))
		}
		commands = append(commands,
			fmt.Sprintf("execute ping %s", destination),
			"execute ping-options reset",
		)
		return commands, nil
	}

	if timeout > 0 {
		return nil, fmt.Errorf("timeout is only supported for device_type 'fortios' or 'cumulus4x'")
	}
	if outgoingInterface != "" {
		return nil, fmt.Errorf("outgoing_interface is only supported for device_type 'fortios'")
	}

	parts := []string{"ping", destination}
	nxos := dt == deviceTypeNXOS
	junos := dt == deviceTypeJunos

	if count > 0 {
		if nxos || junos {
			parts = append(parts, "count", fmt.Sprintf("%d", count))
		} else {
			parts = append(parts, "repeat", fmt.Sprintf("%d", count))
		}
	}
	if size > 0 {
		if nxos {
			parts = append(parts, "packet-size", fmt.Sprintf("%d", size))
		} else {
			parts = append(parts, "size", fmt.Sprintf("%d", size))
		}
	}
	if source != "" {
		parts = append(parts, "source", source)
	}
	if vrf != "" {
		if junos {
			parts = append(parts, "routing-instance", vrf)
		} else {
			parts = append(parts, "vrf", vrf)
		}
	}

	return []string{strings.Join(parts, " ")}, nil
}

func buildTracerouteCommands(destination string, dt deviceType, maxHops, timeout, probe int, source, vrf, outgoingInterface string) ([]string, error) {
	if dt == "" {
		return nil, errDeviceTypeUnresolved
	}
	if err := checkCommandArgs(destination, source, vrf, outgoingInterface); err != nil {
		return nil, err
	}
	if dt == deviceTypeCumulus4x {
		return buildCumulusTraceroute(destination, maxHops, timeout, probe, source, vrf, outgoingInterface)
	}
	if dt == deviceTypeFortiOS {
		switch {
		case vrf != "":
			return nil, fmt.Errorf("FortiOS 7.4+ does not support vrf for run_traceroute")
		case maxHops > 0:
			return nil, fmt.Errorf("FortiOS 7.4+ does not support max_hops for run_traceroute")
		case timeout > 0:
			return nil, fmt.Errorf("FortiOS 7.4+ does not support timeout for run_traceroute")
		}

		commands := make([]string, 0, 5)
		if probe > 0 {
			commands = append(commands, fmt.Sprintf("execute traceroute-options queries %d", probe))
		}
		if source != "" {
			commands = append(commands, fmt.Sprintf("execute traceroute-options source %s", source))
		}
		if outgoingInterface != "" {
			commands = append(commands, fmt.Sprintf("execute traceroute-options device %s", outgoingInterface))
		}
		commands = append(commands,
			fmt.Sprintf("execute traceroute %s", destination),
			"execute traceroute-options reset",
		)
		return commands, nil
	}

	if outgoingInterface != "" {
		return nil, fmt.Errorf("outgoing_interface is only supported for device_type 'fortios'")
	}

	parts := []string{"traceroute"}
	junos := dt == deviceTypeJunos

	if vrf != "" && dt == deviceTypeIOS {
		parts = append(parts, "vrf", vrf)
	}

	parts = append(parts, destination)

	if maxHops > 0 {
		if junos {
			parts = append(parts, "ttl", fmt.Sprintf("%d", maxHops))
		} else {
			parts = append(parts, "maximum-hops", fmt.Sprintf("%d", maxHops))
		}
	}
	if timeout > 0 {
		if junos {
			parts = append(parts, "wait", fmt.Sprintf("%d", timeout))
		} else {
			parts = append(parts, "timeout", fmt.Sprintf("%d", timeout))
		}
	}
	if probe > 0 && !junos {
		parts = append(parts, "probe", fmt.Sprintf("%d", probe))
	}
	if source != "" {
		parts = append(parts, "source", source)
	}
	if vrf != "" && dt != deviceTypeIOS {
		if junos {
			parts = append(parts, "routing-instance", vrf)
		} else {
			parts = append(parts, "vrf", vrf)
		}
	}

	return []string{strings.Join(parts, " ")}, nil
}
