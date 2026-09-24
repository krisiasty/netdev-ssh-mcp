package netdev

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testObfuscationKey = "netdev-ssh-mcp test key"

func TestMain(m *testing.M) {
	SetObfuscationKey([]byte(testObfuscationKey), KeySourceEnv)
	os.Exit(m.Run())
}

// obfuscateConfig is obfuscate without the hashed flag.
func obfuscateConfig(config string) (string, error) {
	out, _, err := obfuscate(config)
	return out, err
}

// secretMarker marks a secret in a want string: <<value>> stands for the
// token hashSecret produces for value.
var secretMarker = regexp.MustCompile(`<<(.*?)>>`)

func expand(want string) string {
	return secretMarker.ReplaceAllStringFunc(want, func(m string) string {
		return hashSecret(secretMarker.FindStringSubmatch(m)[1])
	})
}

func unmark(want string) string {
	return secretMarker.ReplaceAllString(want, "$1")
}

// Every secret below contains FAKE, and no non-secret text does, so any FAKE
// left in the output is a leak.
func TestObfuscateConfigHidesSecrets(t *testing.T) {
	tests := []struct {
		name string
		want string // input line with each secret wrapped in <<...>>
	}{
		// Arista EOS
		{"eos enable secret sha512", `enable password sha512 <<$6$FAKEsalt$FAKEhash>>`},
		{"eos username role secret sha512", `username admin role network-admin secret sha512 <<$6$FAKEsalt$FAKEhash>>`},
		{"eos username privilege role secret", `username admin privilege 15 role network-admin secret sha512 <<$6$FAKEsalt$FAKEhash>>`},
		{"eos aaa root secret", `aaa root secret sha512 <<$6$FAKEroot$FAKEhash>>`},
		{"eos snmp community", `snmp-server community <<FAKEcommunity>> ro`},
		{"eos snmp host v2c", `snmp-server host 192.0.2.50 version 2c <<FAKEcommunity>>`},
		{"eos snmp host vrf informs", `snmp-server host 192.0.2.50 vrf MGMT informs version 2c <<FAKEcommunity>>`},
		{"eos snmp user auth priv", `snmp-server user admin netops v3 localized 800028 auth sha <<0xFAKEauth>> priv aes <<0xFAKEpriv>>`},
		{"eos bgp neighbor password", `   neighbor 192.0.2.1 password 7 <<FAKEbgp>>`},
		{"eos tacacs host vrf key", `tacacs-server host 192.0.2.40 vrf MGMT key 7 <<FAKEtacacs>>`},
		{"eos tacacs global key", `tacacs-server key 7 <<FAKEtacacs>>`},
		{"eos radius host key", `radius-server host 192.0.2.41 vrf MGMT key 7 <<FAKEradius>>`},
		{"eos ntp key md5 type", `ntp authentication-key 1 md5 7 <<FAKEntpKey>>`},
		{"eos ntp key sha1 plain", `ntp authentication-key 2 sha1 <<FAKEntpKey>>`},
		{"eos ospf md5 type", `   ip ospf message-digest-key 1 md5 7 <<FAKEospfKey>>`},
		{"eos ospf auth key", `   ip ospf authentication-key 7 <<FAKEospfKey>>`},
		{"eos isis router auth key", `   authentication key 0 <<FAKEisis>> level-1`},
		{"eos isis interface auth key", `   isis authentication key 7 <<FAKEisis>>`},
		{"eos key-string type", `   key-string 7 <<FAKEkeyString>>`},

		// Cisco IOS / IOS-XE
		{"ios enable secret 5", `enable secret 5 <<$1$FAKE$FAKEhash>>`},
		{"ios enable secret level", `enable secret level 15 9 <<$9$FAKEsalt$FAKEhash>>`},
		{"ios username privilege secret", `username admin privilege 15 secret 9 <<$9$FAKEsalt$FAKEhash>>`},
		{"ios snmp host v1", `snmp-server host 192.0.2.50 <<FAKEcommunity>>`},
		{"ios snmp host informs", `snmp-server host 192.0.2.50 informs version 2c <<FAKEcommunity>> config bgp`},
		{"ios snmp user priv aes 128", `snmp-server user admin netops v3 auth sha <<FAKEauthpw>> priv aes 128 <<FAKEprivpw>>`},
		{"ios tacacs block key", ` key 7 <<FAKEtacacs>>`},
		{"ios tacacs block plain key", ` key <<FAKEtacacs>>`},
		{"ios radius pac key", ` pac key 7 <<FAKEpac>>`},
		{"ios ntp key trailing type", `ntp authentication-key 1 md5 <<FAKE0A0618>> 7`},
		{"ios key-string plain", ` key-string <<FAKEkeyString>>`},
		{"ios hsrp key-string", ` standby 1 authentication md5 key-string 7 <<FAKEhsrp>>`},
		{"ios isis passwords", ` area-password <<FAKEarea>>`},
		{"ios isis domain password", ` domain-password <<FAKEdomain>>`},
		{"ios isakmp key", `crypto isakmp key 6 <<FAKEisakmp>> address 0.0.0.0`},
		{"ios keyring psk", ` pre-shared-key address 192.0.2.9 key <<FAKEpsk>>`},
		{"ios ikev2 psk", `  pre-shared-key local 6 <<FAKEpsk>>`},
		{"ios ikev2 psk plain", `  pre-shared-key <<FAKEpsk>>`},
		{"ios ppp chap", ` ppp chap password 7 <<FAKEchap>>`},
		{"ios ppp pap", ` ppp pap sent-username user password 7 <<FAKEpap>>`},
		{"ios line password", ` password 7 <<FAKEline>>`},
		{"ios show key chain quoted", `    key 1 -- text "<<FAKEshow>>"`},
		{"ios show key chain unquoted", `    key 1 -- text <<FAKEshow>>`},
		{"show snmp community", `Community name: <<FAKEcommunity>>`},

		// Cisco NX-OS
		{"nxos username password role", `username admin password 5 <<$5$FAKEsalt$FAKEhash>>  role network-admin`},
		{"nxos snmp host traps", `snmp-server host 192.0.2.50 traps version 2c <<FAKEcommunity>>`},
		{"nxos snmp user auth priv", `snmp-server user admin network-admin auth md5 <<0xFAKEauth>> priv <<0xFAKEpriv>> localizedkey`},
		{"nxos snmp user priv aes-128", `snmp-server user admin network-admin auth sha <<0xFAKEauth>> priv aes-128 <<0xFAKEpriv>> localizedkey`},
		{"nxos radius host quoted", `radius-server host 192.0.2.41 key 7 "<<FAKEkey>>" authentication accounting`},
		{"nxos tacacs host quoted", `tacacs-server host 192.0.2.40 key 7 "<<FAKEkey>>"`},
		{"nxos radius global quoted", `radius-server key 7 "<<FAKEkey>>"`},
		{"nxos bgp neighbor block", `    password 3 <<FAKEbgp>>`},

		// Juniper JunOS, hierarchy format
		{"junos encrypted-password", `            encrypted-password "<<$6$FAKEsalt$FAKEhash>>"; ## SECRET-DATA`},
		{"junos bgp authentication-key", `        authentication-key "<<$9$FAKEbgp>>"; ## SECRET-DATA`},
		{"junos ospf md5", `                md5 1 key "<<$9$FAKEospf>>"; ## SECRET-DATA`},
		{"junos ike psk", `    pre-shared-key ascii-text "<<$9$FAKEpsk>>"; ## SECRET-DATA`},
		{"junos ike psk hex", `    pre-shared-key hexadecimal "<<$9$FAKEpsk>>"; ## SECRET-DATA`},
		{"junos snmpv3 auth", `                authentication-password "<<$9$FAKEauth>>"; ## SECRET-DATA`},
		{"junos snmpv3 priv", `                privacy-password "<<$9$FAKEpriv>>"; ## SECRET-DATA`},
		{"junos tacplus secret", `        secret "<<$9$FAKEtacplus>>"; ## SECRET-DATA`},
		{"junos ntp key", `    authentication-key 1 type md5 value "<<$9$FAKEntp>>"; ## SECRET-DATA`},
		{"junos snmp community block", `    community <<FAKEcommunity>> {`},
		{"junos snmp community leaf", `    community <<FAKEcommunity>>;`},
		{"junos unknown secret-data", `        some-new-knob "<<FAKEunknown>>"; ## SECRET-DATA`},

		// Juniper JunOS, display set format
		{"junos set encrypted-password", `set system login user admin authentication encrypted-password "<<$6$FAKEsalt$FAKEhash>>"`},
		{"junos set bgp key", `set protocols bgp group ibgp authentication-key "<<$9$FAKEbgp>>"`},
		{"junos set ike psk", `set security ike policy p1 pre-shared-key ascii-text "<<$9$FAKEpsk>>"`},
		{"junos set tacplus", `set system tacplus-server 192.0.2.40 secret "<<$9$FAKEtacplus>>"`},
		{"junos set radius", `set system radius-server 192.0.2.41 secret "<<$9$FAKEradius>>"`},
		{"junos set ntp key", `set system ntp authentication-key 1 type md5 value "<<$9$FAKEntp>>"`},
		{"junos set snmp community", `set snmp community <<FAKEcommunity>> authorization read-only`},
		{"junos bare $9$", `set some thing <<$9$FAKEbare>>`},

		// FortiOS
		{"fortios passwd enc", `set passwd ENC <<FAKEenc123>>`},
		{"fortios community", `set community "<<FAKEcommunity>>"`},
		{"fortios psksecret enc", `set psksecret ENC <<FAKEsecret456>>`},
		{"fortios key quoted", `set key "<<FAKEkey>>"`},

		// Escaped quotes inside quoted values must not end the secret early.
		{"escaped quote junos set community", `set snmp community "<<FAKE\"tail>>" authorization read-only`},
		{"escaped quote junos secret-data", `    authentication-key "<<FAKE\"tail>>"; ## SECRET-DATA`},
		{"escaped quote junos secret", `        secret "<<FAKE\"tail\"FAKEmore>>"; ## SECRET-DATA`},
		{"escaped quote nxos radius", `radius-server host 192.0.2.41 key 7 "<<FAKE\"tail>>" authentication`},
		{"escaped quote fortios", `set password "<<FAKE\"tail>>"`},
		{"escaped quote fortios community", `set community "<<FAKE\"tail>>"`},
		{"escaped backslash before close", `set key "<<FAKE\\>>"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := unmark(tt.want)
			got, err := obfuscateConfig(input)
			if err != nil {
				t.Fatalf("obfuscateConfig() error = %v", err)
			}
			if strings.Contains(got, "FAKE") {
				t.Errorf("secret leaked:\n in: %s\nout: %s", input, got)
			}
			if want := expand(tt.want); got != want {
				t.Errorf("obfuscateConfig(%q)\n got: %s\nwant: %s", input, got, want)
			}
		})
	}
}

func TestObfuscateConfigLeavesNonSecretsAlone(t *testing.T) {
	lines := []string{
		`interface Ethernet1`,
		`key chain KC1`,
		`key 1`,
		`service password-encryption`,
		`username admin privilege 15 nopassword`,
		`snmp-server host 192.0.2.50 use-vrf management`,
		`ip ospf authentication message-digest`,
		`ntp server 192.0.2.1 key 1`,
		`    authentication-order [ tacplus password ];`,
		`    community CUST members 65000:100;`,
		`set policy-options community CUST members 65000:100`,
	}
	input := strings.Join(lines, "\n")
	got, err := obfuscateConfig(input)
	if err != nil {
		t.Fatalf("obfuscateConfig() error = %v", err)
	}
	if got != input {
		t.Fatalf("obfuscateConfig() changed non-secret lines:\n got: %s\nwant: %s", got, input)
	}
}

func TestObfuscateConfigMultiLine(t *testing.T) {
	want := strings.Join([]string{
		`hostname sw1`,
		`snmp-server community <<FAKEcommunity>> ro`,
		`interface Ethernet1`,
		`   ip ospf message-digest-key 1 md5 7 <<FAKEospfKey>>`,
		``,
	}, "\n")
	got, err := obfuscateConfig(unmark(want))
	if err != nil {
		t.Fatalf("obfuscateConfig() error = %v", err)
	}
	if got != expand(want) {
		t.Fatalf("obfuscateConfig() =\n%s\nwant\n%s", got, expand(want))
	}
}

func TestObfuscateConfigDisabled(t *testing.T) {
	Obfuscate = false
	defer func() { Obfuscate = true }()

	input := `snmp-server community FAKEcommunity ro`
	got, err := obfuscateConfig(input)
	if err != nil || got != input {
		t.Fatalf("obfuscateConfig() = %q, %v; want input unchanged", got, err)
	}
}

func TestObfuscateConfigWithoutKeyFails(t *testing.T) {
	saved := obfuscationKey
	obfuscationKey = nil
	defer func() { obfuscationKey = saved }()

	got, err := obfuscateConfig(`snmp-server community FAKEcommunity ro`)
	if !errors.Is(err, errObfuscationKeyNotSet) {
		t.Fatalf("obfuscateConfig() error = %v, want %v", err, errObfuscationKeyNotSet)
	}
	if got != "" {
		t.Fatalf("obfuscateConfig() returned output %q without a key", got)
	}
}

func TestHashSecretIsKeyed(t *testing.T) {
	saved := obfuscationKey
	defer func() { obfuscationKey = saved }()

	SetObfuscationKey([]byte("first key 0123456789"), KeySourceEnv)
	a1, a2 := hashSecret("public"), hashSecret("public")
	SetObfuscationKey([]byte("second key 0123456789"), KeySourceEnv)
	b := hashSecret("public")

	if a1 != a2 {
		t.Fatalf("same key gave different tokens: %s, %s", a1, a2)
	}
	if a1 == b {
		t.Fatalf("different keys gave the same token %s", a1)
	}
	// The unkeyed SHA-256 token for "public" from v1.6.6 must never come back.
	if a1 == "[h:efa1f375d761]" || b == "[h:efa1f375d761]" {
		t.Fatal("token matches unkeyed SHA-256")
	}
	if !regexp.MustCompile(`^\[h:[0-9a-f]{12}\]$`).MatchString(a1) {
		t.Fatalf("token %q does not have the [h:<12 hex>] shape", a1)
	}
}

func TestLoadObfuscationKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("shared team key 0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shortFile := filepath.Join(dir, "short")
	if err := os.WriteFile(shortFile, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		key, file  string
		wantRaw    string
		wantSource string
		wantErr    string
	}{
		{name: "env", key: "shared team key 0123456789", wantRaw: "shared team key 0123456789", wantSource: KeySourceEnv},
		{name: "env trimmed", key: "  shared team key 0123456789\n", wantRaw: "shared team key 0123456789", wantSource: KeySourceEnv},
		{name: "file trimmed", file: keyFile, wantRaw: "shared team key 0123456789", wantSource: KeySourceFile},
		{name: "both set", key: "shared team key 0123456789", file: keyFile, wantErr: "set only one"},
		{name: "env too short", key: "short", wantErr: "at least 16 bytes"},
		{name: "file too short", file: shortFile, wantErr: "at least 16 bytes"},
		{name: "file missing", file: filepath.Join(dir, "missing"), wantErr: "read obfuscation key file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, source, err := LoadObfuscationKey(tt.key, tt.file)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadObfuscationKey() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadObfuscationKey() error = %v", err)
			}
			if string(raw) != tt.wantRaw || source != tt.wantSource {
				t.Fatalf("LoadObfuscationKey() = %q, %q; want %q, %q", raw, source, tt.wantRaw, tt.wantSource)
			}
		})
	}
}

func TestLoadObfuscationKeyEphemeralFallback(t *testing.T) {
	a, source, err := LoadObfuscationKey("", "")
	if err != nil || source != KeySourceEphemeral || len(a) != 32 {
		t.Fatalf("LoadObfuscationKey() = %d bytes, %q, %v; want 32 bytes, %q", len(a), source, err, KeySourceEphemeral)
	}
	b, _, _ := LoadObfuscationKey("", "")
	if string(a) == string(b) {
		t.Fatal("ephemeral keys repeat between calls")
	}
}

// An env key and a key file with the same contents must give the same tokens,
// so teams can deliver the shared key either way.
func TestSameKeySameTokensAcrossSources(t *testing.T) {
	saved := obfuscationKey
	defer func() { obfuscationKey = saved }()

	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("shared team key 0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fromEnv, _, err := LoadObfuscationKey("shared team key 0123456789", "")
	if err != nil {
		t.Fatal(err)
	}
	fromFile, _, err := LoadObfuscationKey("", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	SetObfuscationKey(fromEnv, KeySourceEnv)
	envToken := hashSecret("FAKEcommunity")
	SetObfuscationKey(fromFile, KeySourceFile)
	if fileToken := hashSecret("FAKEcommunity"); fileToken != envToken {
		t.Fatalf("env token %s != file token %s", envToken, fileToken)
	}
}

func TestObfuscatedResultEphemeralKeyNotice(t *testing.T) {
	savedKey, savedSource := obfuscationKey, obfuscationKeySource
	defer func() { obfuscationKey, obfuscationKeySource = savedKey, savedSource }()

	const withSecret = "snmp-server community FAKEcommunity ro" //nolint:gosec // G101: fake test fixture
	const withoutSecret = "interface Ethernet1"

	tests := []struct {
		name       string
		source     string
		output     string
		wantNotice bool
	}{
		{name: "ephemeral key with token", source: KeySourceEphemeral, output: withSecret, wantNotice: true},
		{name: "ephemeral key without token", source: KeySourceEphemeral, output: withoutSecret},
		{name: "env key with token", source: KeySourceEnv, output: withSecret},
		{name: "file key with token", source: KeySourceFile, output: withSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetObfuscationKey([]byte(testObfuscationKey), tt.source)
			res, err := obfuscatedResult(tt.output)
			if err != nil {
				t.Fatalf("obfuscatedResult() error = %v", err)
			}
			want := 1
			if tt.wantNotice {
				want = 2
			}
			if len(res.Content) != want {
				t.Fatalf("obfuscatedResult() has %d content blocks, want %d", len(res.Content), want)
			}
			if text := res.Content[0].(*mcp.TextContent).Text; strings.Contains(text, "FAKE") {
				t.Fatalf("secret leaked in result: %s", text)
			}
			if tt.wantNotice {
				if got := res.Content[1].(*mcp.TextContent).Text; got != EphemeralKeyNotice {
					t.Fatalf("notice = %q, want EphemeralKeyNotice", got)
				}
			}
		})
	}
}

func TestServerInstructions(t *testing.T) {
	savedKey, savedSource := obfuscationKey, obfuscationKeySource
	defer func() { obfuscationKey, obfuscationKeySource = savedKey, savedSource; Obfuscate = true }()

	for _, source := range []string{KeySourceEnv, KeySourceFile} {
		SetObfuscationKey([]byte(testObfuscationKey), source)
		if got := ServerInstructions(); got != "" {
			t.Fatalf("ServerInstructions() with %s key = %q, want empty", source, got)
		}
	}

	SetObfuscationKey([]byte(testObfuscationKey), KeySourceEphemeral)
	if got := ServerInstructions(); got != EphemeralKeyInstructions {
		t.Fatalf("ServerInstructions() with ephemeral key = %q, want EphemeralKeyInstructions", got)
	}

	Obfuscate = false
	if got := ServerInstructions(); got != "" {
		t.Fatalf("ServerInstructions() with obfuscation off = %q, want empty", got)
	}
}
