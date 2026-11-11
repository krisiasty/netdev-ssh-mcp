package netdev

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDeviceType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    deviceType
		wantErr string
	}{
		{name: "empty", input: "", want: ""},
		{name: "fortios", input: "fortios", want: deviceTypeFortiOS},
		{name: "fortigate alias", input: "fortigate", want: deviceTypeFortiOS},
		{name: "junos", input: "junos", want: deviceTypeJunos},
		{name: "cumulus4x", input: "cumulus4x", want: deviceTypeCumulus4x},
		{name: "cumulus4x mixed case", input: " CUMULUS4X ", want: deviceTypeCumulus4x},
		{name: "cumulus without version", input: "cumulus", wantErr: "'cumulus4x'"},
		{name: "invalid", input: "asa", wantErr: "device_type must be"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDeviceType(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("normalizeDeviceType(%q) error = %v, want substring %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeDeviceType(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeDeviceType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildConfigCommand(t *testing.T) {
	tests := []struct {
		name       string
		configType string
		deviceType deviceType
		want       string
		wantErr    string
	}{
		{name: "unresolved running", configType: "running", wantErr: "device type is not resolved"},
		{name: "unresolved startup", configType: "startup", wantErr: "device type is not resolved"},
		{name: "ios running", configType: "running", deviceType: deviceTypeIOS, want: "show running-config"},
		{name: "ios startup", configType: "startup", deviceType: deviceTypeIOS, want: "show startup-config"},
		{name: "nxos running", configType: "running", deviceType: deviceTypeNXOS, want: "show running-config | no-more"},
		{name: "nxos startup", configType: "startup", deviceType: deviceTypeNXOS, want: "show startup-config | no-more"},
		{name: "eos running", configType: "running", deviceType: deviceTypeEOS, want: "show running-config | no-more"},
		{name: "junos running", configType: "running", deviceType: deviceTypeJunos, want: "show configuration | no-more"},
		{name: "fortios running", configType: "running", deviceType: deviceTypeFortiOS, want: "show full-configuration"},
		{name: "cumulus4x running", configType: "running", deviceType: deviceTypeCumulus4x, want: "net show configuration commands 2>&1"},
		{name: "cumulus4x startup rejected", configType: "startup", deviceType: deviceTypeCumulus4x, wantErr: "Cumulus Linux does not have a separate startup-config"},
		{name: "junos startup rejected", configType: "startup", deviceType: deviceTypeJunos, wantErr: "JunOS does not have a startup-config"},
		{name: "fortios startup rejected", configType: "startup", deviceType: deviceTypeFortiOS, wantErr: "FortiOS does not have a startup-config"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildConfigCommand(tt.configType, tt.deviceType)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("buildConfigCommand(%q, %q) error = %v, want substring %q", tt.configType, tt.deviceType, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildConfigCommand(%q, %q) error = %v", tt.configType, tt.deviceType, err)
			}
			if got != tt.want {
				t.Fatalf("buildConfigCommand(%q, %q) = %q, want %q", tt.configType, tt.deviceType, got, tt.want)
			}
		})
	}
}

func TestNormalizeOperationalCommand(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		deviceType deviceType
		want       string
		wantErr    string
	}{
		{name: "show on eos", command: "show version", deviceType: deviceTypeEOS, want: "show version"},
		{name: "unresolved type", command: "show version", wantErr: "device type is not resolved"},
		{name: "junos config blocked", command: "show configuration", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "fortios get allowed", command: "get system status", deviceType: deviceTypeFortiOS, want: "get system status"},
		{name: "fortios show blocked", command: "show system interface", deviceType: deviceTypeFortiOS, wantErr: "use the get_config tool"},
		{name: "fortios execute blocked", command: "execute ping 1.1.1.1", deviceType: deviceTypeFortiOS, wantErr: "use run_ping or run_traceroute"},
		{name: "fortios diagnose blocked", command: "diagnose debug enable", deviceType: deviceTypeFortiOS, wantErr: "diagnose commands are not supported"},
		// Runs of spaces must not skip the get_config redirects.
		{name: "running-config with two spaces", command: "show  running-config", deviceType: deviceTypeEOS, wantErr: "use the get_config tool"},
		{name: "startup-config with three spaces", command: "show   startup-config", deviceType: deviceTypeIOS, wantErr: "use the get_config tool"},
		{name: "running-config spaces nxos", command: "show  run | include hostname", deviceType: deviceTypeNXOS, wantErr: "use the get_config tool"},
		{name: "junos configuration with two spaces", command: "show  configuration", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "junos configuration with spaces and filter", command: "show   configuration | display set", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "running-config before pipe without space", command: "show run|include hostname", deviceType: deviceTypeEOS, wantErr: "use the get_config tool"},
		{name: "startup-config abbreviated", command: "show start", deviceType: deviceTypeIOS, wantErr: "use the get_config tool"},
		{name: "startup-config abbreviation star", command: "show star", deviceType: deviceTypeIOS, wantErr: "use the get_config tool"},
		{name: "eos startup-config shortest abbreviation", command: "show sta", deviceType: deviceTypeEOS, wantErr: "use the get_config tool"},
		{name: "nxos startup-config sta", command: "show  STA | no-more", deviceType: deviceTypeNXOS, wantErr: "use the get_config tool"},
		{name: "eos stat is not startup-config", command: "show stat", deviceType: deviceTypeEOS, want: "show stat"},
		// Other commands that start with "sta" are not startup-config.
		{name: "ios standby", command: "show standby brief", deviceType: deviceTypeIOS, want: "show standby brief"},
		{name: "ios stacks", command: "show stacks", deviceType: deviceTypeIOS, want: "show stacks"},
		{name: "ios statistics", command: "show statistics", deviceType: deviceTypeIOS, want: "show statistics"},
		{name: "eos standby", command: "show standby", deviceType: deviceTypeEOS, want: "show standby"},
		// JunOS accepts abbreviations of "configuration".
		{name: "junos conf", command: "show conf", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "junos config", command: "show config | display set", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "junos configurati", command: "show configurati", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "junos connections", command: "show connections", deviceType: deviceTypeJunos, want: "show connections"},
		{name: "eos show configuration sessions", command: "show configuration sessions", deviceType: deviceTypeEOS, want: "show configuration sessions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeOperationalCommand(tt.command, tt.deviceType)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("normalizeOperationalCommand(%q, %q) error = %v, want substring %q", tt.command, tt.deviceType, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeOperationalCommand(%q, %q) error = %v", tt.command, tt.deviceType, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeOperationalCommand(%q, %q) = %q, want %q", tt.command, tt.deviceType, got, tt.want)
			}
		})
	}
}

func TestBuildPingCommands(t *testing.T) {
	t.Run("fortios batch commands", func(t *testing.T) {
		got, err := buildPingCommands("8.8.8.8", deviceTypeFortiOS, 3, 1400, 5, "10.0.0.1", "", "port1")
		if err != nil {
			t.Fatalf("buildPingCommands() error = %v", err)
		}

		want := []string{
			"execute ping-options repeat-count 3",
			"execute ping-options data-size 1400",
			"execute ping-options timeout 5",
			"execute ping-options source 10.0.0.1",
			"execute ping-options interface port1",
			"execute ping 8.8.8.8",
			"execute ping-options reset",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("buildPingCommands() = %#v, want %#v", got, want)
		}
	})

	t.Run("fortios vrf rejected", func(t *testing.T) {
		_, err := buildPingCommands("8.8.8.8", deviceTypeFortiOS, 0, 0, 0, "", "root", "")
		if err == nil || !strings.Contains(err.Error(), "does not support vrf") {
			t.Fatalf("buildPingCommands() error = %v, want vrf rejection", err)
		}
	})

	t.Run("nxos command preserved", func(t *testing.T) {
		got, err := buildPingCommands("8.8.8.8", deviceTypeNXOS, 2, 1500, 0, "loopback0", "management", "")
		if err != nil {
			t.Fatalf("buildPingCommands() error = %v", err)
		}
		want := "ping 8.8.8.8 count 2 packet-size 1500 source loopback0 vrf management"
		if len(got) != 1 || got[0] != want {
			t.Fatalf("buildPingCommands() = %#v, want %#v", got, []string{want})
		}
	})
}

func TestBuildTracerouteCommands(t *testing.T) {
	t.Run("fortios batch commands", func(t *testing.T) {
		got, err := buildTracerouteCommands("example.com", deviceTypeFortiOS, 0, 0, 2, "10.0.0.1", "", "port2")
		if err != nil {
			t.Fatalf("buildTracerouteCommands() error = %v", err)
		}

		want := []string{
			"execute traceroute-options queries 2",
			"execute traceroute-options source 10.0.0.1",
			"execute traceroute-options device port2",
			"execute traceroute example.com",
			"execute traceroute-options reset",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("buildTracerouteCommands() = %#v, want %#v", got, want)
		}
	})

	t.Run("fortios unsupported args rejected", func(t *testing.T) {
		cases := []struct {
			name    string
			maxHops int
			timeout int
			vrf     string
			wantErr string
		}{
			{name: "vrf", vrf: "root", wantErr: "does not support vrf"},
			{name: "max hops", maxHops: 20, wantErr: "does not support max_hops"},
			{name: "timeout", timeout: 3, wantErr: "does not support timeout"},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				_, err := buildTracerouteCommands("example.com", deviceTypeFortiOS, tc.maxHops, tc.timeout, 0, "", tc.vrf, "")
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("buildTracerouteCommands() error = %v, want substring %q", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("ios vrf ordering preserved", func(t *testing.T) {
		got, err := buildTracerouteCommands("8.8.8.8", deviceTypeIOS, 10, 2, 3, "loopback0", "mgmt", "")
		if err != nil {
			t.Fatalf("buildTracerouteCommands() error = %v", err)
		}
		want := "traceroute vrf mgmt 8.8.8.8 maximum-hops 10 timeout 2 probe 3 source loopback0"
		if len(got) != 1 || got[0] != want {
			t.Fatalf("buildTracerouteCommands() = %#v, want %#v", got, []string{want})
		}
	})
}

// TestBuildersRejectUnresolvedType checks that no builder falls back to a
// default platform when the device type was never resolved.
func TestBuildersRejectUnresolvedType(t *testing.T) {
	if _, err := buildConfigCommand("running", ""); !errors.Is(err, errDeviceTypeUnresolved) {
		t.Errorf("buildConfigCommand() error = %v", err)
	}
	if _, err := normalizeOperationalCommand("show version", ""); !errors.Is(err, errDeviceTypeUnresolved) {
		t.Errorf("normalizeOperationalCommand() error = %v", err)
	}
	if _, err := buildPingCommands("192.0.2.1", "", 0, 0, 0, "", "", ""); !errors.Is(err, errDeviceTypeUnresolved) {
		t.Errorf("buildPingCommands() error = %v", err)
	}
	if _, err := buildTracerouteCommands("192.0.2.1", "", 0, 0, 0, "", "", ""); !errors.Is(err, errDeviceTypeUnresolved) {
		t.Errorf("buildTracerouteCommands() error = %v", err)
	}
}

func TestBuildCumulusPing(t *testing.T) {
	tests := []struct {
		name                        string
		dest                        string
		count, size, timeout        int
		source, vrf, outgoing, want string
		wantErr                     string
	}{
		{name: "default", dest: "192.0.2.1", want: "ping -c 5 192.0.2.1 2>&1"},
		{name: "all", dest: "192.0.2.1", count: 3, size: 1400, timeout: 2, source: "10.0.0.1", want: "ping -c 3 -s 1400 -W 2 -I 10.0.0.1 192.0.2.1 2>&1"},
		{name: "source interface", dest: "192.0.2.1", source: "swp1", want: "ping -c 5 -I swp1 192.0.2.1 2>&1"},
		{name: "vrf", dest: "192.0.2.1", vrf: "mgmt", want: "ping -c 5 -I mgmt 192.0.2.1 2>&1"},
		{name: "default vrf", dest: "192.0.2.1", vrf: "default", want: "ping -c 5 192.0.2.1 2>&1"},
		{name: "ipv6", dest: "2001:db8::1", want: "ping -c 5 2001:db8::1 2>&1"},
		{name: "vrf and source", dest: "192.0.2.1", source: "10.0.0.1", vrf: "mgmt", wantErr: "vrf cannot be combined with source"},
		{name: "outgoing interface", dest: "192.0.2.1", outgoing: "swp1", wantErr: "outgoing_interface is only supported"},
		{name: "option destination", dest: "-f", wantErr: "destination must not start with '-'"},
		{name: "option source", dest: "192.0.2.1", source: "-I", wantErr: "source must not start with '-'"},
		{name: "option vrf", dest: "192.0.2.1", vrf: "-x", wantErr: "vrf must not start with '-'"},
		{name: "metacharacter", dest: "a;b", wantErr: "destination may only contain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildPingCommands(tt.dest, deviceTypeCumulus4x, tt.count, tt.size, tt.timeout, tt.source, tt.vrf, tt.outgoing)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0] != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestBuildCumulusTraceroute(t *testing.T) {
	tests := []struct {
		name                        string
		dest                        string
		maxHops, timeout, probe     int
		source, vrf, outgoing, want string
		wantErr                     string
	}{
		{name: "default", dest: "192.0.2.1", want: "traceroute 192.0.2.1 2>&1"},
		{name: "all", dest: "192.0.2.1", maxHops: 10, timeout: 2, probe: 1, source: "10.0.0.1", want: "traceroute -m 10 -w 2 -q 1 -s 10.0.0.1 192.0.2.1 2>&1"},
		{name: "source interface", dest: "192.0.2.1", source: "swp1", want: "traceroute -i swp1 192.0.2.1 2>&1"},
		{name: "source link-local", dest: "192.0.2.1", source: "fe80::1%swp1", want: "traceroute -s fe80::1%swp1 192.0.2.1 2>&1"},
		{name: "mgmt vrf", dest: "192.0.2.1", vrf: "mgmt", want: "traceroute --no-vrf-switch 192.0.2.1 2>&1"},
		{name: "mgmt vrf with options", dest: "192.0.2.1", maxHops: 2, vrf: "mgmt", want: "traceroute --no-vrf-switch -m 2 192.0.2.1 2>&1"},
		{name: "default vrf", dest: "192.0.2.1", vrf: "default", want: "traceroute 192.0.2.1 2>&1"},
		{name: "other vrf", dest: "192.0.2.1", vrf: "blue", want: "traceroute -i blue 192.0.2.1 2>&1"},
		{name: "vrf and source", dest: "192.0.2.1", source: "10.0.0.1", vrf: "mgmt", wantErr: "vrf cannot be combined with source"},
		{name: "outgoing interface", dest: "192.0.2.1", outgoing: "swp1", wantErr: "outgoing_interface is only supported"},
		{name: "option destination", dest: "-f", wantErr: "destination must not start with '-'"},
		{name: "option source", dest: "192.0.2.1", source: "-I", wantErr: "source must not start with '-'"},
		{name: "option vrf", dest: "192.0.2.1", vrf: "-x", wantErr: "vrf must not start with '-'"},
		{name: "metacharacter", dest: "a;b", wantErr: "destination may only contain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTracerouteCommands(tt.dest, deviceTypeCumulus4x, tt.maxHops, tt.timeout, tt.probe, tt.source, tt.vrf, tt.outgoing)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0] != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestPingTimeoutMessageNamesCumulus(t *testing.T) {
	_, err := buildPingCommands("192.0.2.1", deviceTypeEOS, 0, 0, 2, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "timeout is only supported for device_type 'fortios' or 'cumulus4x'") {
		t.Fatalf("error = %v", err)
	}
}
