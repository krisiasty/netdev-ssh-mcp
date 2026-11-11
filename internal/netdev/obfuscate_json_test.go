package netdev

import (
	"strings"
	"testing"
	"time"
)

// jsonPass hashes only what the JSON pass finds. obfuscate merges these spans
// with the line pass's; TestObfuscateRunsJSONAndLinePasses covers the two
// together.
func jsonPass(text string) (string, bool) {
	return hashSpans(text, jsonSpans(text))
}

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
		{
			"nvue snmp v3 keys",
			`{"username": {"monitor": {"auth-sha": {"FAKEauth": {"encrypt-aes": {"FAKEpriv": {}}}}}}}`,
			`{"username": {"monitor": {"auth-sha": {"<<FAKEauth>>": {"<<encrypt-aes>>": {"<<FAKEpriv>>": {}}}}}}}`,
		},
		{
			"nvue snmp v3 keys md5 des",
			`{"username": {"monitor": {"auth-md5": {"FAKEauth": {"encrypt-des": {"FAKEpriv": {}}}}}}}`,
			`{"username": {"monitor": {"auth-md5": {"<<FAKEauth>>": {"<<encrypt-des>>": {"<<FAKEpriv>>": {}}}}}}}`,
		},
		{"pretty line", `    "password": "FAKEbgp",`, `    "password": "<<FAKEbgp>>",`},
		{"camel case key", `"snmpCommunity": "FAKEc"`, `"snmpCommunity": "<<FAKEc>>"`},
		// Keys are classified after decoding their JSON escapes.
		{"unicode escaped key", `{"pa\u0073sword":"FAKEescaped"}`, `{"pa\u0073sword":"<<FAKEescaped>>"}`},
		{"upper-case unicode escape", `{"pa\u0053sword":"FAKEescaped"}`, `{"pa\u0053sword":"<<FAKEescaped>>"}`},
		{"invalid escape falls back to raw key", `{"password\q":"FAKEbad"}`, `{"password\q":"<<FAKEbad>>"}`},
		{"escaped dash", `{"shared\u002dsecret":"FAKEs","x":1}`, `{"shared\u002dsecret":"<<FAKEs>>","x":1}`},
		{
			"escaped communities key with nested names",
			`{"comm\u0075nities": {"FAKEpublic": {"access": "ro"}}}`,
			`{"comm\u0075nities": {"<<FAKEpublic>>": {"<<access>>": "<<ro>>"}}}`,
		},
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
			`"community": {"<<name>>": "<<FAKEc>>", "<<access>>": "<<any>>"}`,
		},
		{
			// EOS "show snmp community | json" keys communities by name.
			"secret as key",
			`{"communities": {"FAKEpublic": {"access": "ro"}}}`,
			`{"communities": {"<<FAKEpublic>>": {"<<access>>": "<<ro>>"}}}`,
		},
		{
			"pretty array",
			"\"communities\": [\n  \"FAKEone\",\n  \"FAKEtwo\"\n]",
			"\"communities\": [\n  \"<<FAKEone>>\",\n  \"<<FAKEtwo>>\"\n]",
		},
		{
			"pretty object",
			"\"snmp-community\": {\n  \"name\": \"FAKEc\"\n}",
			"\"snmp-community\": {\n  \"<<name>>\": \"<<FAKEc>>\"\n}",
		},
		{"colon on next line", "\"password\"\n  : \"FAKEp\"", "\"password\"\n  : \"<<FAKEp>>\""},
		{
			// true, false and null are valid JSON values: the walk goes on past them.
			"literals inside array",
			`"communities": [true, false, null, "FAKEa"]`,
			`"communities": [true, false, null, "<<FAKEa>>"]`,
		},
		// A secret value is hashed whatever its form.
		{"bare word", `"password": FAKEbare`, `"password": <<FAKEbare>>`},
		{"bare word with digits", `"secret": 7FAKE`, `"secret": <<7FAKE>>`},
		{"bare word in pretty json", "{\n  \"password\": FAKEbare,\n  \"x\": 1\n}", "{\n  \"password\": <<FAKEbare>>,\n  \"x\": 1\n}"},
		// Python's repr, which some NCLU commands print, quotes with '.
		{"single-quoted value", `"password": 'FAKEsq'`, `"password": '<<FAKEsq>>'`},
		{"single-quoted array", `"communities": ['FAKEpublic', 'FAKEprivate']`, `"communities": ['<<FAKEpublic>>', '<<FAKEprivate>>']`},
		{"python dict", `{'password': 'FAKEp', 'keepalive': 60}`, `{'password': '<<FAKEp>>', 'keepalive': 60}`},
		{"escaped single quote", `'password': 'FAKE\'q'`, `'password': '<<FAKE\'q>>'`},
		{
			"python literals inside list",
			`'communities': [True, False, None, 'FAKEa']`,
			`'communities': [True, False, None, '<<FAKEa>>']`,
		},
		{"apostrophe before key", `it's "password": "FAKEp" isn't`, `it's "password": "<<FAKEp>>" isn't`},
		// Single quotes inside an earlier single-quoted scan are skipped, but
		// the keys around and inside that scan are still found.
		{"escaped apostrophes before key", `'a\'b' 'password': 'FAKEx'`, `'a\'b' 'password': '<<FAKEx>>'`},
		{"key inside escaped apostrophes", `it\'s "password": "FAKEp" isn\'t`, `it\'s "password": "<<FAKEp>>" isn\'t`},
		{
			"nested containers",
			`{"communities": [{"name": "FAKEa", "ports": [161, 1161]}, "FAKEb"], "keepalive": 60}`,
			`{"communities": [{"<<name>>": "<<FAKEa>>", "<<ports>>": ["<<161>>", "<<1161>>"]}, "<<FAKEb>>"], "keepalive": 60}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, hashed := jsonPass(tt.input)
			if want := expand(tt.want); got != want {
				t.Errorf("jsonPass(%q)\n got: %s\nwant: %s", tt.input, got, want)
			}
			if !hashed {
				t.Errorf("jsonPass(%q) hashed = false, want true", tt.input)
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
		`{'password': None}`,
		`{'passwordSet': True}`,
		`snmp-server community public ro`,
		`description "not JSON": still not a key`,
		`it's the "user's" choice: don't`,
	}
	for _, input := range inputs {
		got, hashed := jsonPass(input)
		if got != input || hashed {
			t.Errorf("jsonPass(%q) = %q, %v; want input unchanged, false", input, got, hashed)
		}
	}
}

// A container walk hashes the first bare word that is not JSON and stops
// there, so a stray bracket after a secret key in plain text costs one word,
// not the rest of the output. Digits inside a word are not a number.
func TestObfuscateJSONStopsAtFirstNonJSONWord(t *testing.T) {
	tests := []struct{ input, want string }{
		{"description \"secret\": [\nvlan 10 name core 2\n]", "description \"secret\": [\n<<vlan>> 10 name core 2\n]"},
		{`description "psk": {abc1, 2}`, `description "psk": {<<abc1>>, 2}`},
		{`"secret": [1a, 2]`, `"secret": [<<1a>>, 2]`},
	}
	for _, tt := range tests {
		got, hashed := jsonPass(tt.input)
		if want := expand(tt.want); got != want || !hashed {
			t.Errorf("jsonPass(%q) = %q, %v; want %q, true", tt.input, got, hashed, want)
		}
	}
}

// Every quote shape is scanned in linear time. A single-quoted scan used to
// restart at every escaped quote, so 256 kB of \' took seconds; this input
// now takes about a millisecond, and the quadratic scan over a minute.
func TestJSONSpansLinear(t *testing.T) {
	for _, unit := range []string{`\'`, `'x`, `\'"x"`, `'a': `, `\"`, `''   `} {
		input := strings.Repeat(unit, (1<<20)/len(unit))
		start := time.Now()
		jsonSpans(input)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("jsonSpans on 1 MB of %q took %v", unit, d)
		}
	}
}

// A secret that happens to look like a hash token is still a secret: both
// passes read the original text, so nothing is ever hashed twice.
func TestObfuscateJSONHashesTokenShapedSecrets(t *testing.T) {
	for _, input := range []string{
		`"password": "[h:0123456789ab]"`,
		`{"communities": ["[h:0123456789ab]", "[h:987654321098]"]}`,
	} {
		got, hashed := jsonPass(input)
		if !hashed || strings.Contains(got, "0123456789ab") || strings.Contains(got, "987654321098") {
			t.Errorf("jsonPass(%q) = %q, %v; want every token-shaped value hashed", input, got, hashed)
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
		// A string ends at the end of its line.
		"\"password\": \"FAKEa\nnext line\"",
		"\"password\": [\"FAKEa\nnext line\"]",
		`"password": 'FAKEunterminated`,
		`'password': ['FAKEa', FAKEb`,
		`"password": [FAKEa, 2]`,
		`'`,
		`'password'`,
	}
	for _, input := range inputs {
		got, _ := jsonPass(input)
		if strings.Contains(got, "FAKE") {
			t.Errorf("jsonPass(%q) = %q, leaks FAKE", input, got)
		}
	}
}

func TestIsSecretJSONKey(t *testing.T) {
	secret := []string{
		"password", "PASSWD", "passPhrase", "clientSecret", "snmp_community", "psk", "pre-shared-key", "snmpCommunities",
		"preSharedKey", "key-string", "keyString", "authentication-key", "authKey", "md5_key", "privacyProtocolKey",
		"auth-sha", "encrypt-aes", "encrypt-des", "key", "KEY", "tacacsKey", "radius_key", "ospfKey", "keys", "md5", "authMd5",
		// "key" and "md5" fail closed: any name holding them is secret
		// unless it is listed in nonSecretJSONKeys.
		"keyValue", "key_value", "keyData", "keyMaterial", "keyHex", "privateKeyPem", "md5Hash", "md5Digest",
		"keyIdValue", "keychainKey",
	}
	for _, k := range secret {
		if !isSecretJSONKey(k) {
			t.Errorf("isSecretJSONKey(%q) = false, want true", k)
		}
	}
	plain := []string{"keepalive", "authentication", "description", "remoteAs", "privilege", "keyId", "key_id", "KeyChain", "key-chain-name", "keyType", "keyAlgorithm"}
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
		// Both passes read the original text; a secret both find is hashed
		// once, and values only the JSON pass can see are still found.
		{
			"pretty json array",
			"{\n  \"communities\": [\n    \"<<FAKEone>>\",\n    \"<<FAKEtwo>>\"\n  ],\n  \"keepalive\": 60\n}",
		},
		{"crypt value in json", `"password": "<<$6$FAKEsalt$FAKEhash>>"`},
		// Keys named after a bare key or md5, as the line patterns treat them.
		{"tacacs key", `{"tacacsKey": "<<FAKEt>>"}`},
		{"bare key", `{"key": "<<FAKEk>>"}`},
		{"nested md5", `{"auth": {"md5": "<<FAKEm>>"}}`},
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

// Plain text that happens to contain a "secret": [ or "secret": "x shape must
// not stop the line pass from hashing secrets on the lines that follow.
func TestObfuscateCraftedJSONShapeDoesNotHideLineSecrets(t *testing.T) {
	openers := []string{
		`description "secret": [`,
		`description "secret": {`,
		`description "psk": [`,
		`set comments "secret": "x`,
	}
	lines := []struct{ line, secret string }{
		{`username admin password 0 FAKEplain role network-admin`, "FAKEplain"},
		{`neighbor 10.0.0.1 password 7 FAKEbgp`, "FAKEbgp"},
		{`tacacs-server host 10.1.1.1 key 7 FAKEtac`, "FAKEtac"},
		{` key 7 FAKEkey`, "FAKEkey"},
		{`set password "FAKEforti"`, "FAKEforti"},
	}
	for _, opener := range openers {
		for _, l := range lines {
			input := opener + "\nset other\n" + l.line
			got, err := obfuscateConfig(input)
			if err != nil {
				t.Fatalf("obfuscateConfig() error = %v", err)
			}
			if strings.Contains(got, "FAKE") || !strings.Contains(got, hashSecret(l.secret)) {
				t.Errorf("obfuscateConfig(%q)\n got: %s\nwant %s hashed once as %s", input, got, l.secret, hashSecret(l.secret))
			}
		}
	}
}

// A line pattern that matches inside an ordinary JSON string must not hide a
// JSON secret that follows it: both passes read the original text.
func TestObfuscateLineTriggerInsideJSONString(t *testing.T) {
	triggers := []string{"shared-secret", "auth-md5", "key-string", "encrypted-password", "secret="}
	keys := []string{"password", "snmpCommunity", "communities"}
	for _, trigger := range triggers {
		for _, key := range keys {
			input := `{"description": "x ` + trigger + ` y", "` + key + `": "FAKEp1"}`
			got, err := obfuscateConfig(input)
			if err != nil {
				t.Fatalf("obfuscateConfig() error = %v", err)
			}
			if strings.Contains(got, "FAKE") {
				t.Errorf("obfuscateConfig(%q) = %q, leaks FAKE", input, got)
			}
		}
	}
}

func TestObfuscateJSONEdgeCasesThroughObfuscate(t *testing.T) {
	inputs := []string{
		// Pretty secret array whose elements trip line patterns.
		"{\n  \"communities\": [\n    \"x secret=y\",\n    \"lab shared-secret q\",\n    \"FAKEthree\"\n  ]\n}",
		// EOS "show snmp community | json" shape with a line trigger in a field.
		"{\n  \"communities\": {\n    \"FAKEpub1\": {\n      \"view\": \"v auth-sha w\",\n      \"access\": \"ro\"\n    },\n" +
			"    \"FAKEpub2\": {\n      \"access\": \"rw\"\n    }\n  }\n}",
		// Python and NCLU print NaN and Infinity as bare tokens.
		`{"communities": [NaN, "FAKEnan"]}`,
		`{"communities": {"a": Infinity, "FAKEinf": 1}}`,
		`{"communities": [-Infinity, "FAKEneginf"]}`,
	}
	for _, input := range inputs {
		got, hashed, err := obfuscate(input)
		if err != nil {
			t.Fatalf("obfuscate() error = %v", err)
		}
		if strings.Contains(got, "FAKE") || !hashed {
			t.Errorf("obfuscate(%q) = %q, %v; leaks FAKE or not hashed", input, got, hashed)
		}
	}
}

// Line and JSON spans are merged, so a secret both passes find, in part or in
// full, is hashed once as their union.
func TestObfuscateOverlappingLineAndJSONSpans(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{
			"separate lines",
			"{\"secret\": \"FAKEs\", \"x\": \"y\"}\n        secret \"FAKEq\"; ## SECRET-DATA",
			"{\"secret\": \"<<FAKEs>>\", \"x\": \"y\"}\n        secret \"<<FAKEq>>\"; ## SECRET-DATA",
		},
		{
			// shared-secret captures `FAKEs"}`; the JSON value is `a shared-secret FAKEs`.
			"same line overlap",
			`{"password": "a shared-secret FAKEs"}`,
			`{"password": "<<a shared-secret FAKEs"}>>`,
		},
		{
			// Both passes find the same crypt value; one token.
			"identical spans",
			`{"password": "$6$FAKEsalt$FAKEhash"}`,
			`{"password": "<<$6$FAKEsalt$FAKEhash>>"}`,
		},
		{"json number", `{"community": 12345}`, `{"community": "<<12345>>"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, hashed, err := obfuscate(tt.input)
			if err != nil {
				t.Fatalf("obfuscate() error = %v", err)
			}
			if want := expand(tt.want); got != want || !hashed {
				t.Errorf("obfuscate(%q) = %q, %v\nwant: %q, true", tt.input, got, hashed, want)
			}
		})
	}
}
