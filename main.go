package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/krisiasty/netdev-ssh-mcp/internal/netdev"
	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

func main() {
	knownHostsDefault, err := sshclient.DefaultKnownHostsPath()
	if err != nil {
		knownHostsDefault = ""
	}
	if envPath := strings.TrimSpace(os.Getenv(sshclient.EnvKnownHostsPath)); envPath != "" {
		knownHostsDefault = envPath
	}
	skipHostKeyValidationDefault, err := envBool(sshclient.EnvSkipHostKeyValidation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s: %v\n", sshclient.EnvSkipHostKeyValidation, err)
		os.Exit(1)
	}
	commandTimeoutDefault := sshclient.DefaultCommandTimeout
	if v := strings.TrimSpace(os.Getenv(sshclient.EnvCommandTimeout)); v != "" {
		commandTimeoutDefault, err = time.ParseDuration(v)
		if err != nil || commandTimeoutDefault <= 0 {
			fmt.Fprintf(os.Stderr, "invalid %s: expected a positive duration such as 90s, got %q\n", sshclient.EnvCommandTimeout, v)
			os.Exit(1)
		}
	}

	noObfuscate := flag.Bool("no-obfuscate", false, "disable obfuscation of sensitive values in tool output")
	obfuscationKeyFile := flag.String("obfuscation-key-file", os.Getenv(netdev.EnvObfuscationKeyFile), "path to a file holding the key for obfuscation tokens; share it to get matching tokens across machines")
	knownHostsPath := flag.String("known-hosts", knownHostsDefault, "path to OpenSSH known_hosts file used for SSH host verification")
	skipHostKeyValidation := flag.Bool("insecure-skip-host-key-check", skipHostKeyValidationDefault, "disable SSH host key verification (insecure)")
	commandTimeout := flag.Duration("command-timeout", commandTimeoutDefault, "maximum time a device command may run, counted from the SSH session request (run_ping and run_traceroute get at least 5m)")
	printVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("version: %s\ncommit: %s\ndate: %s\n", version, commit, date)
		return
	}

	if *commandTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "invalid --command-timeout: expected a positive duration such as 90s, got %s\n", *commandTimeout)
		os.Exit(1)
	}
	if *noObfuscate {
		netdev.Obfuscate = false
	}
	if err := sshclient.Configure(sshclient.Options{
		KnownHostsPath:           *knownHostsPath,
		InsecureSkipHostKeyCheck: *skipHostKeyValidation,
		CommandTimeout:           *commandTimeout,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "configure ssh client: %v\n", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	})))

	slog.Info("starting netdev-ssh-mcp",
		"version", version,
		"commit", commit,
		"date", date,
	)

	if netdev.Obfuscate {
		key, source, err := netdev.LoadObfuscationKey(os.Getenv(netdev.EnvObfuscationKey), *obfuscationKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "configure obfuscation: %v\n", err)
			os.Exit(1)
		}
		netdev.SetObfuscationKey(key, source)
		if source == netdev.KeySourceEphemeral {
			slog.Warn(netdev.EphemeralKeyLogMessage, "source", source)
		} else {
			slog.Info("obfuscation key loaded", "source", source)
		}
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "netdev-ssh-mcp",
		Version: version,
	}, &mcp.ServerOptions{Instructions: netdev.ServerInstructions()})

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_config",
		Description: "Connect to an Arista, Cisco Nexus, Cisco IOS/IOS-XE, Juniper JunOS, FortiGate FortiOS, or Cumulus Linux 4.x device via SSH and retrieve its " +
			"running or startup configuration. Sensitive values (passwords, secrets, SNMP community names, " +
			"BGP/OSPF/TACACS/RADIUS/IKE keys) are automatically replaced with keyed hash tokens; " +
			"identical tokens mean identical secrets, so configs from different devices can be compared. " +
			deviceTypeGuidance +
			"The command depends on the platform: 'show configuration' on JunOS, 'show full-configuration' on FortiOS, " +
			"'show running-config' on IOS, 'show running-config | no-more' on EOS and NX-OS and 'net show configuration commands' on Cumulus Linux 4.x. " +
			"JunOS, FortiOS and Cumulus Linux do not support config_type='startup'.",
	}, netdev.GetConfig)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_show_command",
		Description: "Connect to an Arista, Cisco Nexus, Cisco IOS/IOS-XE, Juniper JunOS, FortiGate FortiOS, or Cumulus Linux 4.x device via SSH and run an operational read command. " +
			"Arista/Cisco/JunOS commands must start with 'show'. FortiOS commands must start with 'get'. Cumulus Linux 4.x commands must start with 'net show'. " +
			deviceTypeGuidance +
			"Running-config and startup-config are not allowed here — use the get_config tool instead. " +
			"On JunOS, 'show configuration' is also blocked and redirected to get_config. " +
			"For FortiOS, 'show', 'config', 'execute', and 'diagnose' commands are blocked here. " +
			"On Cumulus Linux 4.x, 'net show configuration', 'net show commit' and 'net show rollback' (or any abbreviation of them) are blocked and redirected to get_config, " +
			"the command may end with 'json' for structured output, takes no pipes or redirection, and its words may contain only " +
			"letters, digits and . _ : / , @ % -. " +
			"On the other platforms the command must be a single line holding one command, start with the verb in lower case ('show', or 'get' on FortiOS), " +
			"and have no ';' or '<'/'>' redirection; its words may contain only letters, digits and . _ : / , @ % + = ^ $ -. " +
			"It may pipe only into these filters, written exactly in lower case, where N is a number of up to 6 digits and W is one plain word: " +
			"letters, digits and . _ : / , @ % + = -, not starting with '-'. Filters per device_type: " +
			"eos: json, no-more, include W, exclude W, begin W, section W; " +
			"ios: include W, exclude W, begin W, section W, count W; " +
			"nxos: json, json-pretty, xml, no-more, include W, exclude W, begin W, section W, count, grep W, egrep W, head, head lines N, last, last N; " +
			"junos: display json, display xml, display set, no-more, match W, except W, count, last, last N, trim N; " +
			"fortios: grep W. Filters can be chained ('| include Ethernet | exclude down'). " +
			"Filter arguments cannot use regular expressions other than '.' (which matches any character, including a space), quotes, options or a second word; " +
			"when no filter fits, run the command without one and extract what you need from the full output. " +
			"Examples: 'show bgp summary | json', 'show interfaces status | json', " +
			"'show lldp neighbors detail | json', 'show inventory | json', 'show version | json', " +
			"'get system status', 'get router info routing-table all', 'net show interface json'.",
	}, netdev.RunShowCommand)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_ping",
		Description: "Connect to an Arista, Cisco Nexus, Cisco IOS/IOS-XE, Juniper JunOS, FortiGate FortiOS, or Cumulus Linux 4.x device via SSH and run a ping command. " +
			"Useful for verifying reachability from the device's perspective — for example, testing connectivity " +
			"to a BGP peer, next-hop, or management target. " +
			deviceTypeGuidance +
			"Optional parameters: count (number of probes), source (source IP or interface), " +
			"vrf (VRF or routing-instance name on JunOS), size (packet size in bytes), timeout (FortiOS and Cumulus Linux 4.x only), " +
			"outgoing_interface (FortiOS only). FortiOS 7.4+ does not support vrf for ping via this tool. " +
			"On Cumulus Linux 4.x the tool runs 'ping -c <count> [-s size] [-W timeout] [-I source|vrf] destination' with 5 probes unless count is set; " +
			"vrf cannot be combined with source, outgoing_interface is not supported, and when nothing answers the output with its statistics " +
			"is returned instead of an error.",
	}, netdev.RunPing)

	mcp.AddTool(server, &mcp.Tool{
		Name: "run_traceroute",
		Description: "Connect to an Arista, Cisco Nexus, Cisco IOS/IOS-XE, Juniper JunOS, FortiGate FortiOS, or Cumulus Linux 4.x device via SSH and run a traceroute. " +
			"Shows the hop-by-hop path to a destination and per-hop latency. " +
			"Useful for locating where connectivity breaks, verifying traffic follows the expected path, " +
			"and identifying which hop introduces latency. " +
			deviceTypeGuidance +
			"On IOS, vrf is placed before the destination in the command. " +
			"On JunOS, max_hops maps to the ttl keyword, timeout maps to wait, probe is not supported, " +
			"and vrf maps to routing-instance. " +
			"On FortiOS 7.4+, probe maps to execute traceroute-options queries, source maps to source, " +
			"and outgoing_interface maps to device; max_hops, timeout, and vrf are not supported. " +
			"On Cumulus Linux 4.x the tool runs 'traceroute [-m max_hops] [-w timeout] [-q probe] [-s source-ip | -i source-iface | -i vrf] destination'; " +
			"vrf cannot be combined with source, and outgoing_interface is not supported. " +
			"Optional parameters: max_hops, timeout (per-probe seconds), probe (probes per hop, not used on JunOS), " +
			"source (source IP or interface), vrf (routing-instance on JunOS), outgoing_interface (FortiOS only).",
	}, netdev.RunTraceroute)

	mcp.AddTool(server, &mcp.Tool{
		Name: "detect_platform",
		Description: "Connect to a network device via SSH and identify its platform, returning the device_type to pass to the other tools " +
			"(eos, ios, nxos, junos, fortios, cumulus4x or cumulus5x) and a short software version. Detection reads the SSH server identification and runs " +
			"one read-only command ('show version', 'get system status' on FortiOS, or 'cat /etc/os-release' on Debian or Ubuntu based systems). Results are cached by this server per host; " +
			"set refresh=true to probe again. Use it to resolve a list of hosts before working through them. " +
			"Other Linux systems and the Cisco Business switch OS (e.g. Catalyst 1200) are recognised and reported as unsupported.",
	}, netdev.DetectPlatform)

	mcp.AddTool(server, &mcp.Tool{
		Name: "trust_host_key",
		Description: "Fetch the SSH host key currently presented by a device and optionally add it to the configured known_hosts file. " +
			"Call it first with confirm=false to inspect the fingerprint, then call it again with confirm=true after the user verifies the fingerprint. " +
			"If a host key has legitimately changed, set replace_existing=true to replace the stored key after verification.",
	}, netdev.TrustHostKey)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// deviceTypeGuidance is shared by the tools that take device_type.
const deviceTypeGuidance = "device_type selects the platform syntax: 'eos' (Arista), 'ios' (Cisco IOS/IOS-XE), 'nxos' (Cisco NX-OS), " +
	"'junos' (Juniper JunOS), 'fortios' (FortiGate/FortiOS), 'cumulus4x' (Cumulus Linux 4.x) or 'cumulus5x' (Cumulus Linux 5.x). Pass it when you know the platform, for example from an inventory " +
	"system. If it is omitted, the platform is auto-detected over SSH, cached for the host, and reported in a note after the output; " +
	"pass that value on later calls. To work through many hosts, call detect_platform for each one first. "

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func envBool(name string) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("expected boolean value, got %q", value)
	}
	return parsed, nil
}
