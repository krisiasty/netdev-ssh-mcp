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
var sensitivePatterns = []*regexp.Regexp{
	// enable secret|password [type] <value>
	regexp.MustCompile(`(?i)^(enable\s+(?:secret|password)(?:\s+\d+|\s+sha\d+)?\s+)(\S+)(.*)$`),
	// username NAME ... secret|password [type] <value>
	regexp.MustCompile(`(?i)^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:role\s+\S+\s+)?(?:secret|password)(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// snmp-server community <name> ...
	regexp.MustCompile(`(?i)^(snmp-server\s+community\s+)(\S+)(.*)$`),
	// neighbor IP password [type] <value>  (BGP)
	regexp.MustCompile(`(?i)^(\s*neighbor\s+\S+\s+password(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// tacacs-server [host IP] key [type] <value>
	regexp.MustCompile(`(?i)^(tacacs-server\s+(?:host\s+\S+\s+)?key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// radius-server key [type] <value>
	regexp.MustCompile(`(?i)^(radius-server\s+key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// ntp authentication-key ID algo <value>
	regexp.MustCompile(`(?i)^(ntp\s+authentication-key\s+\d+\s+\S+\s+)(\S+)(.*)$`),
	// key-string <value>  (key chain)
	regexp.MustCompile(`(?i)^(\s*key-string\s+)(\S+)(.*)$`),
	// [ip] ospf authentication-key [type] <value>
	regexp.MustCompile(`(?i)^(\s*(?:ip\s+)?ospf\s+authentication-key(?:\s+\d+)?\s+)(\S+)(.*)$`),
	// [ip] ospf message-digest-key ID algo <value>
	regexp.MustCompile(`(?i)^(\s*(?:ip\s+)?ospf\s+message-digest-key\s+\d+\s+\S+\s+)(\S+)(.*)$`),
	// isis authentication key [algo] <value>
	regexp.MustCompile(`(?i)^(\s*isis\s+authentication\s+key(?:\s+\S+)?\s+)(\S+)(.*)$`),
}

// obfuscateConfig replaces sensitive values in an Arista EOS running-config
// with deterministic SHA-256 hashes. Two configs with identical secret values
// will produce identical hashes, making the output safe to compare or diff.
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
