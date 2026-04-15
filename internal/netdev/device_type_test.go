package netdev

import (
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
		{name: "default running", configType: "running", want: "show running-config | no-more"},
		{name: "junos running", configType: "running", deviceType: deviceTypeJunos, want: "show configuration | no-more"},
		{name: "fortios running", configType: "running", deviceType: deviceTypeFortiOS, want: "show full-configuration"},
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
		{name: "show on eos", command: "show version", want: "show version"},
		{name: "junos config blocked", command: "show configuration", deviceType: deviceTypeJunos, wantErr: "use the get_config tool"},
		{name: "fortios get allowed", command: "get system status", deviceType: deviceTypeFortiOS, want: "get system status"},
		{name: "fortios show blocked", command: "show system interface", deviceType: deviceTypeFortiOS, wantErr: "use the get_config tool"},
		{name: "fortios execute blocked", command: "execute ping 1.1.1.1", deviceType: deviceTypeFortiOS, wantErr: "use run_ping or run_traceroute"},
		{name: "fortios diagnose blocked", command: "diagnose debug enable", deviceType: deviceTypeFortiOS, wantErr: "diagnose commands are not supported"},
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

func TestObfuscateConfigFortiOS(t *testing.T) {
	input := strings.Join([]string{
		`set passwd ENC ENC123`,
		`set community "public"`,
		`set psksecret ENC SECRET456`,
	}, "\n")

	got := obfuscateConfig(input)
	want := strings.Join([]string{
		`set passwd ENC [h:0f977b8986fa]`,
		`set community "[h:efa1f375d761]"`,
		`set psksecret ENC [h:6859a44534e0]`,
	}, "\n")

	if got != want {
		t.Fatalf("obfuscateConfig() = %q, want %q", got, want)
	}
}
