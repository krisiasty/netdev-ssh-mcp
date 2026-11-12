package netdev

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

// cumulus5RefusedPathWords are the NVUE path words, besides any word that
// contains "password" or "secret", whose "nv show" output is a secret. They are
// compared lower-cased. NVUE accepts an unambiguous abbreviation of a path
// word, so a prefix of one is refused too (fail closed).
var cumulus5RefusedPathWords = []string{
	"readonly-community", "readwrite-community", "community-password",
	"auth-md5", "auth-sha", "encrypt-aes", "encrypt-des",
	"password", "hashed-password", "secret", "md5-key",
}

// isCumulus5SecretWord reports whether the word w, taken from NVUE output or
// from an "nv set" line, names a secret: it is one of cumulus5RefusedPathWords
// or contains "password" or "secret", compared lower-cased. Unlike
// isCumulus5RefusedPathWord it does not match a prefix of those words, so
// ordinary output that starts with "s" or "c" is not taken for a secret.
func isCumulus5SecretWord(w string) bool {
	lower := strings.ToLower(w)
	return slices.Contains(cumulus5RefusedPathWords, lower) ||
		strings.Contains(lower, "password") || strings.Contains(lower, "secret")
}

// isCumulus5RefusedPathWord reports whether the NVUE path word w points into a
// secret, or abbreviates a word that does.
func isCumulus5RefusedPathWord(w string) bool {
	lower := strings.ToLower(w)
	if lower == "" {
		return false
	}
	return isCumulus5SecretWord(lower) ||
		slices.ContainsFunc(cumulus5RefusedPathWords, func(r string) bool {
			// An abbreviation of a refused word, or a longer word that starts with
			// one, such as "readonly-community-v6".
			return strings.HasPrefix(r, lower) || strings.HasPrefix(lower, r)
		})
}

// normalizeCumulus5Command verifies that command (already trimmed) is a single
// "nv show" command that bash cannot split into anything else, and appends
// cumulusMergeStderr. The returned command is otherwise exactly as written.
// The only option accepted is a final "-o json".
func normalizeCumulus5Command(command string) (string, error) {
	words, err := cumulusShowWords(command, "nv")
	if err != nil {
		return "", err
	}
	path := words[2:]
	if n := len(path); n >= 2 && path[n-2] == "-o" && path[n-1] == "json" {
		path = path[:n-2]
	}
	for _, w := range path {
		if isOption(w) {
			return "", fmt.Errorf("only '-o json' at the end of the command is accepted as an option")
		}
	}
	segs := cumulus5PathSegments(path)
	if slices.ContainsFunc(segs, isCumulus5RefusedPathWord) || isCumulus5NTPKeyPath(segs) {
		return "", fmt.Errorf("this path shows a secret; use the get_config tool, or show the parent path with -o json")
	}
	// NVUE accepts abbreviations, so "sys conf" is "system config".
	if len(segs) >= 2 && isPrefixFold("system", segs[0]) && isPrefixFold("config", segs[1]) {
		return "", fmt.Errorf("use the get_config tool to retrieve device configuration")
	}
	return command + cumulusMergeStderr, nil
}

// cumulus5PathSegments splits the path words of an "nv show" command at every
// '/' and ',' too, which cumulusWordChars allows. Whether nv resolves a joined
// word such as "snmp-server/readonly-community" is not known, so each part is
// checked on its own (fail closed).
func cumulus5PathSegments(path []string) []string {
	var segs []string
	for _, w := range path {
		segs = append(segs, strings.FieldsFunc(w, func(r rune) bool { return r == '/' || r == ',' })...)
	}
	return segs
}

// isCumulus5NTPKeyPath reports whether the path segments reach the NTP
// authentication keys ("service ntp <vrf> key <id>"), whose "value" row is a
// secret that no word of the path names. Any abbreviation of "ntp" followed by
// any abbreviation of "key" is refused (fail closed).
func isCumulus5NTPKeyPath(segs []string) bool {
	i := slices.IndexFunc(segs, func(w string) bool { return isPrefixFold("ntp", w) })
	return i >= 0 && slices.ContainsFunc(segs[i+1:], func(w string) bool { return isPrefixFold("key", w) })
}

// isPrefixFold reports whether w is a non-empty, case-insensitive prefix of word.
func isPrefixFold(word, w string) bool {
	return w != "" && strings.HasPrefix(word, strings.ToLower(w))
}

// nvueWordPattern finds the words of a line and their offsets.
var nvueWordPattern = regexp.MustCompile(`\S+`)

// isNVUESecretName reports whether w names a secret in NVUE output.
func isNVUESecretName(w string) bool {
	return isSecretJSONKey(w) || isCumulus5SecretWord(w)
}

// nvueScanner finds the secrets that NVUE output and "nv set" lines hold
// beyond what the platform patterns cover. It is fed every line of one text in
// order, since a YAML subtree spans lines. Run it on cumulus5x output only: its
// secret names ("key", "community", "md5" ...) are too broad for other
// platforms' output.
type nvueScanner struct {
	secretIndent int // indentation of the open YAML secret key, or -1
}

func newNVUEScanner() *nvueScanner {
	return &nvueScanner{secretIndent: -1}
}

// lineSpans returns the spans the NVUE passes find in line, offset by the
// line's position in the text.
func (s *nvueScanner) lineSpans(line string, offset int) []span {
	words := nvueWordPattern.FindAllStringIndex(line, -1)
	spans := s.yamlSpans(line, words, offset)
	spans = append(spans, nvueCommandSpans(line, words, offset)...)
	return append(spans, nvueRowSpans(line, words, offset)...)
}

// shellWordEnd returns the end of the shell word that starts at line[start]:
// concatenated single-quoted (no escapes), double-quoted (backslash escapes)
// and unquoted (backslash escapes) segments up to unquoted whitespace. An
// unterminated quote runs to the end of the line.
func shellWordEnd(line string, start int) int {
	i := start
	for i < len(line) {
		switch c := line[i]; c {
		case ' ', '\t':
			return i
		case '\'':
			n := strings.IndexByte(line[i+1:], '\'')
			if n < 0 {
				return len(line)
			}
			i += n + 2
		case '"':
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(line) {
				return len(line)
			}
			i++
		case '\\':
			i += 2
		default:
			i++
		}
	}
	return len(line)
}

// isNVUECommandSecretName reports whether words[i] of an "nv set" line names
// a secret: a secret name, or "value" two words after one, as in the NTP
// authentication key "key <id> value <secret>".
func isNVUECommandSecretName(line string, words [][]int, i int) bool {
	word := func(i int) string { return line[words[i][0]:words[i][1]] }
	if isNVUESecretName(word(i)) {
		return true
	}
	return strings.EqualFold(word(i), "value") && i >= 4 && isNVUESecretName(word(i-2))
}

// nvueCommandSpans returns a span for the value after every secret-named word
// of an "nv set" line, such as "nv set system aaa radius server 10.0.0.9
// secret <value>". words are the line's word offsets (nvueWordPattern), and
// spans are offset by the line's position in the text.
func nvueCommandSpans(line string, words [][]int, offset int) []span {
	if len(words) < 3 || line[words[0][0]:words[0][1]] != "nv" || line[words[1][0]:words[1][1]] != "set" {
		return nil
	}
	var spans []span
	for i := 2; i+1 < len(words); i++ {
		if !isNVUECommandSecretName(line, words, i) {
			continue
		}
		// The value is a whole shell word, which quotes or backslashes can
		// carry across spaces: it runs to the next unquoted whitespace, or to
		// the end of the line. A line ending in CR keeps it.
		start := words[i+1][0]
		end := shellWordEnd(line, start)
		if end == len(line) && end > start+1 && line[end-1] == '\r' {
			end--
		}
		// Skip the words inside the value; the loop moves on to the word
		// after it.
		i++
		for i+1 < len(words) && words[i+1][0] < end {
			i++
		}
		spans = append(spans, span{start: offset + start, end: offset + end})
	}
	return spans
}

// yamlSpans returns a span for every word under a secret-named map key that
// stands alone on its line in YAML-like NVUE output ("readonly-community:"
// followed by its indented subtree), keys included, as the JSON pass does.
// The subtree ends at the first non-blank line indented no more than the key,
// except that a list item ("- value") at the key's indent still belongs to
// it, as YAML may write a key's list there. The key may itself be a list item
// ("- readonly-community:"); its indent is then that of the key, not the dash.
func (s *nvueScanner) yamlSpans(line string, words [][]int, offset int) []span {
	if len(words) == 0 {
		return nil
	}
	indent := words[0][0]
	first := line[words[0][0]:words[0][1]]
	if s.secretIndent >= 0 {
		if indent > s.secretIndent || (indent == s.secretIndent && strings.HasPrefix(first, "-")) {
			spans := make([]span, 0, len(words))
			for _, w := range words {
				if line[w[0]:w[1]] == "-" {
					continue // a list item marker
				}
				end := w[1]
				if line[end-1] == ':' && end-1 > w[0] {
					end--
				}
				spans = append(spans, span{start: offset + w[0], end: offset + end})
			}
			return spans
		}
		s.secretIndent = -1
	}
	key := words
	if first == "-" {
		key = words[1:]
	}
	if len(key) != 1 {
		return nil
	}
	name, ok := strings.CutSuffix(line[key[0][0]:key[0][1]], ":")
	if ok && isNVUESecretName(name) && !strings.ContainsAny(name, `"'{}`) {
		s.secretIndent = key[0][0]
	}
	return nil
}

// nvueRowSpans returns a span for every word after the first when the first
// word, without surrounding brackets and a trailing colon, names a secret (see
// isNVUESecretName), and the line has the shape of an NVUE row: the first
// word is bracketed or ends in a colon ("[readonly-community] value",
// "password: value"), or the next word starts after two or more spaces, as in
// a table ("password  *  *"). Other lines, such as "password 3 <value>" or
// 'secret "<value>"; ## note', are left to the platform patterns, so their
// trailing words stay readable, as does a single-spaced "key chain KC1".
// words are the line's word offsets (nvueWordPattern).
func nvueRowSpans(line string, words [][]int, offset int) []span {
	if len(words) < 2 {
		return nil
	}
	firstWord := line[words[0][0]:words[0][1]]
	first := strings.TrimSuffix(strings.Trim(firstWord, "[]"), ":")
	// A quoted or braced name is JSON, which the JSON pass handles.
	if !isNVUESecretName(first) || strings.ContainsAny(first, `"'{}`) {
		return nil
	}
	rowShaped := (strings.HasPrefix(firstWord, "[") && strings.HasSuffix(firstWord, "]")) ||
		strings.HasSuffix(firstWord, ":") || words[1][0]-words[0][1] >= 2
	if !rowShaped {
		return nil
	}
	spans := make([]span, 0, len(words)-1)
	for _, w := range words[1:] {
		spans = append(spans, span{start: offset + w[0], end: offset + w[1]})
	}
	return spans
}

// ansiRe matches a CSI sequence: ESC [, parameters, then a final byte.
var ansiRe = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]")

// stripANSI removes CSI escape sequences and any remaining lone ESC, which
// nv prints for bold or colour and which can split a secret row's words.
func stripANSI(s string) string {
	return strings.ReplaceAll(ansiRe.ReplaceAllString(s, ""), "\x1b", "")
}

// cumulus5CommandError adds the device output to the error of a failed
// cumulus5x command, since nv states the reason only there. The output may
// hold secrets, so it is obfuscated; if that fails the error is returned
// unchanged. When a secret was hashed under the random per-run key,
// EphemeralKeyNotice follows the output, as obfuscatedResult adds it to a
// result. Call it after logging, so the output stays out of the log.
func cumulus5CommandError(dt deviceType, err error) error {
	var cmdErr *sshclient.CommandError
	if dt != deviceTypeCumulus5x || !errors.As(err, &cmdErr) {
		return err
	}
	out := stripANSI(string(cmdErr.Output))
	if strings.TrimSpace(out) == "" {
		return err
	}
	safe, hashed, oerr := obfuscate(dt, out)
	if oerr != nil {
		return err
	}
	safe = strings.TrimSpace(safe)
	if hashed && EphemeralObfuscationKey() {
		return fmt.Errorf("%w; device output:\n%s\n%s", err, safe, EphemeralKeyNotice)
	}
	return fmt.Errorf("%w; device output:\n%s", err, safe)
}
