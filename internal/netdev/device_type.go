package netdev

import (
	"fmt"
	"strings"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

type deviceType string

const (
	deviceTypeEOS     deviceType = "eos"
	deviceTypeIOS     deviceType = "ios"
	deviceTypeNXOS    deviceType = "nxos"
	deviceTypeJunos   deviceType = "junos"
	deviceTypeFortiOS deviceType = "fortios"
)

var (
	runCommand  = sshclient.RunCommand
	runCommands = sshclient.RunCommands
)

func connConfig(host string, port int, username string) sshclient.ConnConfig {
	return sshclient.ConnConfig{
		Host:     host,
		Port:     port,
		Username: username,
	}
}

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
	default:
		return "", fmt.Errorf("device_type must be 'eos', 'ios', 'nxos', 'junos', or 'fortios', got %q", raw)
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
	default:
		return fmt.Sprintf("show %s-config | no-more", configType), nil
	}
}

func normalizeOperationalCommand(command string, dt deviceType) (string, error) {
	trimmed := strings.TrimSpace(command)
	lower := strings.ToLower(trimmed)

	if dt == deviceTypeFortiOS {
		return normalizeFortiOSOperationalCommand(trimmed, lower)
	}

	if !strings.HasPrefix(lower, "show") {
		return "", fmt.Errorf("command must start with 'show'")
	}
	if strings.HasPrefix(lower, "show ru") || strings.HasPrefix(lower, "show sta") {
		return "", fmt.Errorf("use the get_config tool for running-config and startup-config")
	}
	if dt == deviceTypeJunos && strings.HasPrefix(lower, "show configuration") {
		return "", fmt.Errorf("use the get_config tool to retrieve device configuration")
	}

	return trimmed, nil
}

func normalizeFortiOSOperationalCommand(command, lower string) (string, error) {
	switch {
	case strings.HasPrefix(lower, "show full-configuration"), strings.HasPrefix(lower, "show"):
		return "", fmt.Errorf("use the get_config tool to retrieve FortiOS configuration")
	case strings.HasPrefix(lower, "config"):
		return "", fmt.Errorf("FortiOS configuration mode is not supported here; use get_config to retrieve configuration")
	case strings.HasPrefix(lower, "execute ping"), strings.HasPrefix(lower, "execute traceroute"):
		return "", fmt.Errorf("use run_ping or run_traceroute for FortiOS diagnostics")
	case strings.HasPrefix(lower, "execute"):
		return "", fmt.Errorf("FortiOS execute commands are not supported here; use run_ping or run_traceroute for diagnostics")
	case strings.HasPrefix(lower, "diagnose"):
		return "", fmt.Errorf("FortiOS diagnose commands are not supported by run_show_command")
	case !strings.HasPrefix(lower, "get"):
		return "", fmt.Errorf("FortiOS operational reads must use a 'get' command")
	default:
		return command, nil
	}
}

func buildPingCommands(destination string, dt deviceType, count, size, timeout int, source, vrf, outgoingInterface string) ([]string, error) {
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
		return nil, fmt.Errorf("timeout is only supported for device_type 'fortios'")
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
