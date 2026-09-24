package netdev

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Building blocks shared by the patterns below.
const (
	// typeTokens matches the optional encryption type and hash algorithm words
	// that can sit between a keyword and its value, e.g. "7", "sha512", "md5 7".
	// Type codes are limited to two digits so an all-digit secret is never
	// mistaken for one.
	typeTokens = `(?:\s+(?:\d{1,2}|md5|sha\d*|sha-\d+))*` //nolint:gosec // G101: a regular expression, not a credential
	// quoted matches a double-quoted secret and captures its contents.
	// Backslash escapes are honoured, so an escaped \" does not end the value.
	quoted = `"((?:[^"\\]|\\.)*)"`
	// value matches a secret that is either quoted or a single word. Both
	// alternatives are capture groups; only the one that matched is hashed.
	value = `(?:` + quoted + `|(\S+))`
	// boundary anchors a keyword at the start of a line or after whitespace,
	// so one pattern covers JunOS hierarchy and "display set" output.
	boundary = `(?:^|\s)`
)

// sensitivePattern locates secrets in a line. Every capture group in re is a
// secret; use non-capturing groups for everything else.
type sensitivePattern struct {
	re *regexp.Regexp
	// skip lists captured words that are keywords rather than secrets, for
	// lines that share a pattern's shape but carry no secret.
	skip []string
}

func pattern(expr string, skip ...string) sensitivePattern {
	return sensitivePattern{re: regexp.MustCompile(`(?i)` + expr), skip: skip}
}

// sensitivePatterns covers Arista EOS, Cisco NX-OS, Cisco IOS/IOS-XE, Juniper
// JunOS and FortiOS syntax. Every pattern is applied to every line, so their
// order does not matter and a line can hold several secrets.
var sensitivePatterns = []sensitivePattern{
	// enable secret|password [level N] [type] <value>  (Arista, Cisco)
	pattern(`^\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?` + typeTokens + `\s+` + value),
	// username NAME [privilege N] [role R] secret|password [type] <value>  (Arista, Cisco)
	pattern(`^\s*username\s+\S+(?:\s+\S+)*?\s+(?:secret|password)` + typeTokens + `\s+` + value),
	// snmp-server community <name> ...  (Arista, Cisco)
	pattern(`^\s*snmp-server\s+community\s+` + value),
	// snmp-server host IP [informs|traps] [vrf V] [version 1|2c|3 [auth|noauth|priv]] <community>  (Arista, Cisco)
	pattern(`^\s*snmp-server\s+host\s+\S+(?:\s+(?:informs|traps|vrf\s+\S+|version\s+(?:1|2c|3(?:\s+(?:auth|noauth|priv))?)))*\s+`+value,
		"use-vrf", "filter-vrf", "source-interface"),
	// snmp-server user NAME ... auth ALGO <authpw>  (Arista, Cisco)
	pattern(`^\s*snmp-server\s+user\s+.*?\sauth\s+\S+\s+` + value),
	// snmp-server user NAME ... priv [ALGO [BITS]] <privpw>  (Arista, Cisco)
	pattern(`^\s*snmp-server\s+user\s+.*?\spriv(?:\s+(?:aes-?\d+|aes|3des|des|\d{3}))*\s+` + value),
	// Community name: <value> / Community: <value>  (show snmp community output)
	pattern(`^\s*Community(?:\s+name)?:\s+` + value),
	// neighbor IP|GROUP password [type] <value>  (BGP, Arista, Cisco)
	pattern(`^\s*neighbor\s+\S+\s+password` + typeTokens + `\s+` + value),
	// tacacs-server|radius-server [host IP [options]] key [type] <value>  (Arista, Cisco)
	pattern(`^\s*(?:tacacs|radius)-server\s+(?:host\s+\S+\s+(?:\S+\s+)*?)?key` + typeTokens + `\s+` + value),
	// key <type> <value> in a tacacs/radius server block  (Cisco IOS-XE)
	pattern(`^\s*key\s+\d{1,2}\s+` + value + `\s*$`),
	// key <value> in a tacacs/radius server block; not a numeric key-chain ID  (Cisco IOS-XE)
	pattern(`^\s*key\s+(\S*[^\d\s]\S*)\s*$`),
	// pac key [type] <value>  (Cisco IOS-XE radius server block)
	pattern(`^\s*pac\s+key` + typeTokens + `\s+` + value),
	// ntp authentication-key ID ALGO [type] <value>  (Arista, Cisco)
	pattern(`^\s*ntp\s+authentication-key\s+\d+\s+\S+` + typeTokens + `\s+` + value),
	// key-string [type] <value>  (key chains, HSRP, Arista, Cisco)
	pattern(boundary + `key-string` + typeTokens + `\s+` + value),
	// Key N -- text [type] <value>  (show key chain output, Cisco IOS/IOS-XE)
	pattern(`^\s*key\s+\d+\s+--\s+text\s+(?:\d+\s+)?` + value),
	// [ip] ospf authentication-key [type] <value>  (Arista, Cisco)
	pattern(`^\s*(?:ip\s+)?ospf\s+authentication-key` + typeTokens + `\s+` + value),
	// [ip] ospf message-digest-key ID ALGO [type] <value>  (Arista, Cisco)
	pattern(`^\s*(?:ip\s+)?ospf\s+message-digest-key\s+\d+\s+\S+` + typeTokens + `\s+` + value),
	// [isis] authentication key [type] <value>  (Arista, Cisco)
	pattern(`^\s*(?:isis\s+)?authentication\s+key` + typeTokens + `\s+` + value),
	// isis password / area-password / domain-password [type] <value>  (Cisco)
	pattern(`^\s*(?:isis\s+password|area-password|domain-password)` + typeTokens + `\s+` + value),
	// crypto isakmp key [type] <value> address|hostname ...  (Cisco IKEv1)
	pattern(`^\s*crypto\s+isakmp\s+key` + typeTokens + `\s+` + value),
	// pre-shared-key address|hostname X [mask] key [type] <value>  (Cisco IKEv1 keyring)
	pattern(`^\s*pre-shared-key\s+(?:address|hostname)\s+\S+(?:\s+\S+)*?\s+key` + typeTokens + `\s+` + value),
	// pre-shared-key [local|remote] [type] <value>  (Cisco IKEv2 keyring). The
	// value must end the line, so JunOS "pre-shared-key ascii-text ..." is not
	// mistaken for it.
	pattern(`^\s*pre-shared-key(?:\s+(?:local|remote))?` + typeTokens + `\s+([^\s"]\S*)\s*$`),
	// ppp chap password / ppp pap sent-username U password [type] <value>  (Cisco)
	pattern(`^\s*ppp\s+(?:chap|pap\s+sent-username\s+\S+)\s+password` + typeTokens + `\s+` + value),
	// password [type] <value>  (Cisco line vty/con/aux, NX-OS BGP neighbor block)
	pattern(`^\s*password` + typeTokens + `\s+` + value),

	// JunOS: encrypted-password "<hash>"  (login users, root-authentication)
	pattern(boundary + `encrypted-password\s+` + value),
	// JunOS: authentication-key "<key>"  (BGP, OSPF, IS-IS, ...)
	pattern(boundary + `authentication-key\s+` + quoted),
	// JunOS: authentication-key ID type ALGO value "<key>"  (NTP)
	pattern(boundary + `authentication-key\s+\d+\s+type\s+\S+\s+value\s+` + value),
	// JunOS: md5 N key "<key>"  (OSPF MD5 authentication)
	pattern(boundary + `md5\s+\d+\s+key\s+` + value),
	// JunOS: pre-shared-key ascii-text|hexadecimal "<key>"  (IKE)
	pattern(boundary + `pre-shared-key\s+(?:ascii-text|hexadecimal)\s+` + value),
	// JunOS: authentication-password / privacy-password "<key>"  (SNMPv3)
	pattern(boundary + `(?:authentication|privacy)-password\s+` + value),
	// JunOS: secret "<key>"  (tacplus-server, radius-server)
	pattern(boundary + `secret\s+` + quoted),
	// JunOS: community <name> { or community <name>;  (SNMP, hierarchy format)
	pattern(`^\s*community\s+` + value + `\s*[\{;]`),
	// JunOS: set snmp community <name> ...  (display set format)
	pattern(boundary + `snmp\s+community\s+` + value),

	// FortiOS: set <secret field> ENC <value>  (encrypted passwords, passphrases, PSKs, key material)
	pattern(`^\s*set\s+(?:passwd|password|passphrase|auth-passwd|group-password|psksecret(?:-remote|-local)?|ppk-secret|secret|community|snmp-community|private-key|local-key|peer-key|server-key|client-key|key)\s+ENC\s+(\S+)`),
	// FortiOS: set community "<name>" / set snmp-community "<name>"  (SNMP community names)
	pattern(`^\s*set\s+(?:community|snmp-community)\s+` + quoted),
	// FortiOS: set key "<value>" / set password "<value>"  (clear-text key-like values)
	pattern(`^\s*set\s+(?:passwd|password|passphrase|auth-passwd|group-password|psksecret(?:-remote|-local)?|ppk-secret|secret|private-key|local-key|peer-key|server-key|client-key|key)\s+` + quoted),

	// Catch-all: any quoted value on a line JunOS marks as secret. Covers
	// secret-bearing statements that have no specific pattern above.
	pattern(quoted + `\s*;?\s*##\s*SECRET-DATA`),
	// Catch-all: crypt-style and JunOS $9$ values wherever they appear
	// ($1$, $5$, $6$, $8$, $9$, $y$ ...).
	pattern(`(\$[0-9a-z]{1,2}\$[^\s";]+)`),
}

// Obfuscate controls whether sensitive values are replaced with hashes in
// tool output. Enabled by default; set to false via --no-obfuscate.
var Obfuscate = true

// obfuscationKeyLabel separates obfuscation keys from any other use of the
// same key material. Changing it changes every token.
const obfuscationKeyLabel = "netdev-ssh-mcp/obfuscation/v1"

var (
	obfuscationKey       []byte
	obfuscationKeySource string
)

var errObfuscationKeyNotSet = errors.New("obfuscation key not configured")

// SetObfuscationKey derives the key used to hash secrets from raw key
// material, and records where that material came from (one of the KeySource
// constants). It must be called before any tool output is obfuscated.
func SetObfuscationKey(raw []byte, source string) {
	obfuscationKey = hmacSHA256(raw, []byte(obfuscationKeyLabel))
	obfuscationKeySource = source
}

// obfuscate replaces sensitive values in device output with keyed hashes and
// reports whether any secret was hashed. The same secret under the same key
// always produces the same token, so outputs remain comparable without
// revealing the secret, and tokens cannot be checked against guesses without
// the key.
// Supports Arista EOS, Cisco NX-OS, Cisco IOS/IOS-XE, Juniper JunOS, and FortiOS syntax.
func obfuscate(config string) (out string, hashed bool, err error) {
	if !Obfuscate {
		return config, false, nil
	}
	if obfuscationKey == nil {
		return "", false, errObfuscationKeyNotSet
	}
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		var h bool
		lines[i], h = obfuscateLine(line)
		hashed = hashed || h
	}
	return strings.Join(lines, "\n"), hashed, nil
}

// obfuscatedResult obfuscates device output and wraps it in a tool result.
// When a secret was hashed under the random per-run key, it appends
// EphemeralKeyNotice as a second content block so the calling agent sees it
// and can encourage the user to configure a key.
func obfuscatedResult(output string) (*mcp.CallToolResult, error) {
	out, hashed, err := obfuscate(output)
	if err != nil {
		return nil, err
	}
	content := []mcp.Content{&mcp.TextContent{Text: out}}
	if hashed && EphemeralObfuscationKey() {
		content = append(content, &mcp.TextContent{Text: EphemeralKeyNotice})
	}
	return &mcp.CallToolResult{Content: content}, nil
}

type span struct{ start, end int }

// obfuscateLine hashes every secret any pattern finds in line and reports
// whether it found any. Overlapping matches are merged so no part of a secret
// survives.
func obfuscateLine(line string) (string, bool) {
	var spans []span
	for _, p := range sensitivePatterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(line, -1) {
			for g := 2; g+1 < len(m); g += 2 {
				s := span{m[g], m[g+1]}
				if s.start < 0 || s.start == s.end || p.skips(line[s.start:s.end]) {
					continue
				}
				spans = append(spans, s)
			}
		}
	}
	if len(spans) == 0 {
		return line, false
	}

	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start < last.end {
			last.end = max(last.end, s.end)
			continue
		}
		merged = append(merged, s)
	}

	var b strings.Builder
	prev := 0
	for _, s := range merged {
		b.WriteString(line[prev:s.start])
		b.WriteString(hashSecret(line[s.start:s.end]))
		prev = s.end
	}
	b.WriteString(line[prev:])
	return b.String(), true
}

func (p sensitivePattern) skips(v string) bool {
	return slices.ContainsFunc(p.skip, func(k string) bool { return strings.EqualFold(k, v) })
}

// hashSecret returns a short identifier for a secret value, keyed with the
// obfuscation key: HMAC-SHA256 truncated to 48 bits (12 hex chars).
func hashSecret(s string) string {
	return fmt.Sprintf("[h:%x]", hmacSHA256(obfuscationKey, []byte(s))[:6])
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
