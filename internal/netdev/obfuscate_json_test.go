package netdev

import (
	"strings"
	"testing"
)

// Every secret below contains FAKE, and no non-secret text does, so any FAKE
// left in the output is a leak. Numbers are the exception: they are written
// as numbers in the input and as quoted tokens in want.
func TestObfuscateJSONHidesSecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // expected output with each secret wrapped in <<...>>
	}{
		{
			"compact object",
			`{"neighbor":"swp51","password":"FAKEbgp","remoteAs":65000}`,
			`{"neighbor":"swp51","password":"<<FAKEbgp>>","remoteAs":65000}`,
		},
		{"pretty line", `    "password": "FAKEbgp",`, `    "password": "<<FAKEbgp>>",`},
		{"camel case key", `"snmpCommunity": "FAKEc"`, `"snmpCommunity": "<<FAKEc>>"`},
		{"dashed key", `"community-password":"FAKEc"`, `"community-password":"<<FAKEc>>"`},
		{"underscored key", `"shared_secret": "FAKEr"`, `"shared_secret": "<<FAKEr>>"`},
		{"auth password key", `"authPassword": "FAKEa"`, `"authPassword": "<<FAKEa>>"`},
		{"md5 key", `"md5Key": "FAKEm"`, `"md5Key": "<<FAKEm>>"`},
		{"escaped quote", `"password": "FAKE\"quoted"`, `"password": "<<FAKE\"quoted>>"`},
		{"number", `"community": 12345`, `"community": "<<12345>>"`},
		{"array", `"communities": ["FAKEone", "FAKEtwo"]`, `"communities": ["<<FAKEone>>", "<<FAKEtwo>>"]`},
		{
			"object",
			`"community": {"name": "FAKEc", "access": "any"}`,
			`"community": {"name": "<<FAKEc>>", "access": "<<any>>"}`,
		},
		{
			"pretty array",
			"\"communities\": [\n  \"FAKEone\",\n  \"FAKEtwo\"\n]",
			"\"communities\": [\n  \"<<FAKEone>>\",\n  \"<<FAKEtwo>>\"\n]",
		},
		{
			"pretty object",
			"\"snmp-community\": {\n  \"name\": \"FAKEc\"\n}",
			"\"snmp-community\": {\n  \"name\": \"<<FAKEc>>\"\n}",
		},
		{"colon on next line", "\"password\"\n  : \"FAKEp\"", "\"password\"\n  : \"<<FAKEp>>\""},
		{
			"nested containers",
			`{"communities": [{"name": "FAKEa", "ports": [161, 1161]}, "FAKEb"], "keepalive": 60}`,
			`{"communities": [{"name": "<<FAKEa>>", "ports": ["<<161>>", "<<1161>>"]}, "<<FAKEb>>"], "keepalive": 60}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, hashed := obfuscateJSON(tt.input)
			if want := expand(tt.want); got != want {
				t.Errorf("obfuscateJSON(%q)\n got: %s\nwant: %s", tt.input, got, want)
			}
			if !hashed {
				t.Errorf("obfuscateJSON(%q) hashed = false, want true", tt.input)
			}
		})
	}
}

func TestObfuscateJSONLeavesNonSecretsAlone(t *testing.T) {
	inputs := []string{
		`{"keepalive": 60}`,
		`{"passwordSet": true}`,
		`{"authentication": "md5"}`,
		`{"description": "community"}`,
		`{"password": null}`,
		`{"password": false}`,
		`{"password": ""}`,
		`snmp-server community public ro`,
		`description "not JSON": still not a key`,
	}
	for _, input := range inputs {
		got, hashed := obfuscateJSON(input)
		if got != input || hashed {
			t.Errorf("obfuscateJSON(%q) = %q, %v; want input unchanged, false", input, got, hashed)
		}
	}
}

// Malformed input must never panic or loop, and must not leave the start of a
// secret value in clear text.
func TestObfuscateJSONMalformedInput(t *testing.T) {
	inputs := []string{
		`"password": "FAKEunterminated`,
		`"password": [1, "FAKEa"`,
		`"password": {"name": "FAKEa", "inner": ["FAKEb"`,
		`"password": "\`,
		`"password": "FAKE\`,
		`"password":`,
		`"password":   `,
		`"password`,
		`"`,
		`\`,
		`]}]}`,
		`"password": ]`,
		`"password": -`,
		`"password": [-, "FAKEa"]`,
	}
	for _, input := range inputs {
		got, _ := obfuscateJSON(input)
		if strings.Contains(got, "FAKE") {
			t.Errorf("obfuscateJSON(%q) = %q, leaks FAKE", input, got)
		}
	}
}

func TestIsSecretJSONKey(t *testing.T) {
	secret := []string{
		"password", "PASSWD", "passPhrase", "clientSecret", "snmp_community", "psk", "pre-shared-key", "snmpCommunities",
		"preSharedKey", "key-string", "keyString", "authentication-key", "authKey", "md5_key", "privacyProtocolKey",
	}
	for _, k := range secret {
		if !isSecretJSONKey(k) {
			t.Errorf("isSecretJSONKey(%q) = false, want true", k)
		}
	}
	plain := []string{"keepalive", "authentication", "key", "description", "remoteAs", "privilege"}
	for _, k := range plain {
		if isSecretJSONKey(k) {
			t.Errorf("isSecretJSONKey(%q) = true, want false", k)
		}
	}
}

func TestObfuscateRunsJSONAndLinePasses(t *testing.T) {
	tests := []struct {
		name string
		want string // input with each secret wrapped in <<...>>
	}{
		{
			"json and eos line",
			"{\n  \"password\": \"<<FAKEjson>>\"\n}\nsnmp-server community <<FAKEeos>> ro",
		},
		// The JUNOS `secret "..."` and tacplus `secret=` line patterns must not
		// hash the JSON pass's token a second time.
		{"json secret key", `"secret": "<<FAKEs>>"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, hashed, err := obfuscate(unmark(tt.want))
			if err != nil {
				t.Fatalf("obfuscate() error = %v", err)
			}
			if want := expand(tt.want); got != want {
				t.Errorf("obfuscate()\n got: %s\nwant: %s", got, want)
			}
			if !hashed {
				t.Error("obfuscate() hashed = false, want true")
			}
		})
	}
}
