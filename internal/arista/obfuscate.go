package arista

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// sensitivePattern matches a line containing a secret. Each pattern must have
// exactly three capture groups: (prefix)(secret)(suffix). The secret group is
// replaced with a deterministic hash; prefix and suffix are kept verbatim.
//
// Patterns cover Arista EOS, Cisco NX-OS, and Cisco IOS/IOS-XE syntax.
var sensitivePatterns = []*regexp.Regexp{
	// enable secret|password [level N] [type] <value>  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d+|\s+sha\d+)?\s+)(\S+)(.*)$`),
	// username NAME ... secret|password [type] <value>  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:role\s+\S+\s+)?(?:secret|password)(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// snmp-server community <name> ...  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(snmp-server\s+community\s+)(\S+)(.*)$`),
	// snmp-server user NAME GROUP [auth algo <authpw> [priv algo]] — NX-OS
	regexp.MustCompile(`(?i)^(snmp-server\s+user\s+\S+\s+\S+(?:\s+\S+)?\s+auth\s+\S+\s+)(\S+)(.*)$`),
	// neighbor IP password [type] <value>  (BGP, Arista, Cisco)
	regexp.MustCompile(`(?i)^(\s*neighbor\s+\S+\s+password(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// tacacs-server [host IP] key [type] <value>  (Arista, Cisco IOS)
	regexp.MustCompile(`(?i)^(tacacs-server\s+(?:host\s+\S+\s+)?key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// tacacs server block — key [type] <value>  (Cisco IOS-XE)
	regexp.MustCompile(`(?i)^(\s*key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// radius-server key [type] <value>  (Arista, Cisco IOS)
	regexp.MustCompile(`(?i)^(radius-server\s+key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// ntp authentication-key ID algo <value>  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(ntp\s+authentication-key\s+\d+\s+\S+\s+)(\S+)(.*)$`),
	// key-string <value>  (key chain, Arista, Cisco)
	regexp.MustCompile(`(?i)^(\s*key-string\s+)(\S+)(.*)$`),
	// [ip] ospf authentication-key [type] <value>  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(\s*(?:ip\s+)?ospf\s+authentication-key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// [ip] ospf message-digest-key ID algo <value>  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(\s*(?:ip\s+)?ospf\s+message-digest-key\s+\d+\s+\S+\s+)(\S+)(.*)$`),
	// isis authentication key [algo] <value>  (Arista, Cisco)
	regexp.MustCompile(`(?i)^(\s*isis\s+authentication\s+key(?:\s+\S+)?\s+)(\S+)(.*)$`),
	// crypto isakmp key <value> address|hostname ...  (Cisco IKEv1)
	regexp.MustCompile(`(?i)^(crypto\s+isakmp\s+key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// pre-shared-key [local|remote] [type] <value>  (Cisco IKEv2)
	regexp.MustCompile(`(?i)^(\s*pre-shared-key(?:\s+(?:local|remote))?(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// password [type] <value>  (Cisco line vty/con/aux context)
	regexp.MustCompile(`(?i)^(\s*password(?:\s+\d+)?\s+)(\S+)(.*)$`),
}

// obfuscateConfig replaces sensitive values in a running-config with
// deterministic SHA-256 hashes. Two configs with identical secret values
// will produce identical hashes, making the output safe to compare or diff.
// Supports Arista EOS, Cisco NX-OS, and Cisco IOS/IOS-XE syntax.
func obfuscateConfig(config string) string {
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		for _, re := range sensitivePatterns {
			if m := re.FindStringSubmatch(line); m != nil {
				lines[i] = m[1] + hashSecret(m[2]) + m[3]
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// hashSecret returns a short deterministic identifier for a secret value.
// The same input always produces the same output, enabling comparison across
// switches without revealing the actual secret.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("[h:%x]", sum[:6]) // 12 hex chars
}
