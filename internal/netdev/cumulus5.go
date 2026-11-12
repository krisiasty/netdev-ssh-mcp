package netdev

import (
	"context"
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

// isCumulus5SecretWord reports whether the word w of an "nv set" line names a
// secret: it is one of cumulus5RefusedPathWords or contains "password" or
// "secret", compared lower-cased. Unlike isCumulus5RefusedPathWord it does not
// match a prefix of those words.
func isCumulus5SecretWord(w string) bool {
	lower := strings.ToLower(w)
	return slices.Contains(cumulus5RefusedPathWords, lower) ||
		strings.Contains(lower, "password") || strings.Contains(lower, "secret")
}

// isCumulus5RefusedPathWord reports whether the NVUE path word w points into a
// secret: it contains "password" or "secret", abbreviates one of
// cumulus5RefusedPathWords (NVUE expands an unambiguous prefix), or starts with
// one, such as "readonly-community-v6". It is deliberately broad: a user's
// object name such as "secretary", or a non-secret word such as "community"
// that abbreviates "community-password", is refused too, since the path alone
// cannot tell them apart from a secret (fail closed).
func isCumulus5RefusedPathWord(w string) bool {
	lower := strings.ToLower(w)
	return strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
		slices.ContainsFunc(cumulus5RefusedPathWords, func(r string) bool {
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
	jsonOut := false
	if n := len(path); n >= 2 && path[n-2] == "-o" && path[n-1] == "json" {
		path, jsonOut = path[:n-2], true
	}
	for _, w := range path {
		if isOption(w) {
			return "", fmt.Errorf("only '-o json' at the end of the command is accepted as an option")
		}
	}
	segs := cumulus5PathSegments(path)
	if i := slices.IndexFunc(segs, isCumulus5RefusedPathWord); i >= 0 {
		return "", fmt.Errorf("the path word %q may show a secret (a word containing 'password' or 'secret', or a secret NVUE word or an abbreviation of one); "+
			"use the get_config tool, or show the parent path with -o json", segs[i])
	}
	if isCumulus5NTPKeyPath(segs) {
		return "", fmt.Errorf("this path shows the NTP authentication keys; use the get_config tool, or show the parent path with -o json")
	}
	// NVUE accepts abbreviations, so "sys conf" is "system config". The JSON of
	// the whole tree and of "system" holds "system config" too, configuration
	// snippets included.
	if (len(segs) >= 2 && isPrefixFold("system", segs[0]) && isPrefixFold("config", segs[1])) ||
		(jsonOut && (len(segs) == 0 || len(segs) == 1 && isPrefixFold("system", segs[0]))) {
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

// isNVUESecretName reports whether w labels a secret in NVUE output: a row
// label, YAML key, section header or table column. It is the JSON pass's
// secret key test, which also matches every cumulus5RefusedPathWords entry and
// any name containing "password" or "secret" (see
// TestNVUESecretNameCoversSecretWords). It matches "key", "community" and
// "md5" anywhere in a name, which is safe for labels but too broad for the
// object names of an "nv set" line; see isNVUESetSecretName.
func isNVUESecretName(w string) bool {
	return isSecretJSONKey(w)
}

// nvueSetIDKeys are "nv set" attribute names that end in "-key" but take a key
// ID or a public key name rather than a secret.
var nvueSetIDKeys = []string{"message-digest-key", "authorized-key"}

// isNVUESetSecretName reports whether words[i] of an "nv set" line is an
// attribute whose value is a secret: a secret word (isCumulus5SecretWord), a
// word ending in "-key" other than nvueSetIDKeys, "psk" or "-psk", a word
// containing "passphrase", or "value" after a word naming a key, as in the NTP
// authentication key "key <id> [type md5] value <secret>". User-chosen object
// names (a peer group "keystone", a server "radius-key.example.com") are
// matched only when they contain "password" or "secret", or end in "-key".
func isNVUESetSecretName(line string, words [][]int, i int) bool {
	word := func(i int) string { return strings.ToLower(line[words[i][0]:words[i][1]]) }
	w := word(i)
	switch {
	case isCumulus5SecretWord(w), strings.Contains(w, "passphrase"), w == "psk", strings.HasSuffix(w, "-psk"):
		return true
	case strings.HasSuffix(w, "-key"):
		return !slices.Contains(nvueSetIDKeys, w)
	case w == "value":
		for j := 2; j < i; j++ {
			if k := word(j); k == "key" || strings.HasSuffix(k, "-key") {
				return true
			}
		}
	}
	return false
}

// nvueScanner finds the secrets that NVUE output and "nv set" lines hold
// beyond what the platform patterns cover. It is fed every line of one text in
// order, since a YAML subtree, a section or a table spans lines. Run it on
// cumulus5x output only: its secret names ("key", "community", "md5" ...) are
// too broad for other platforms' output.
type nvueScanner struct {
	secretIndent int // indentation of the open YAML key or section, or -1
	// The last non-blank line and its words, for a table's header.
	prevLine  string
	prevWords [][]int
	// colStarts are the offsets where a table's columns start, and secretCol
	// whether each is secret, from the header above the table's rule of
	// dashes; both are nil outside a table with a secret column.
	colStarts []int
	secretCol []bool
}

func newNVUEScanner() *nvueScanner {
	return &nvueScanner{secretIndent: -1}
}

// lineSpans returns the spans the NVUE passes find in line, offset by the
// line's position in the text.
func (s *nvueScanner) lineSpans(line string, offset int) []span {
	words := nvueWordPattern.FindAllStringIndex(line, -1)
	spans := s.yamlSpans(line, words, offset)
	spans = append(spans, s.tableSpans(line, words, offset)...)
	spans = append(spans, nvueCommandSpans(line, words, offset)...)
	spans = append(spans, nvueRowSpans(line, words, offset)...)
	if len(words) > 0 {
		s.prevLine, s.prevWords = line, words
	}
	return spans
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

// nvueCommandSpans returns a span for the value after every secret attribute
// (isNVUESetSecretName) of an "nv set" line, such as "nv set system aaa radius
// server 10.0.0.9 secret <value>". words are the line's word offsets
// (nvueWordPattern), and spans are offset by the line's position in the text.
func nvueCommandSpans(line string, words [][]int, offset int) []span {
	if len(words) < 3 || line[words[0][0]:words[0][1]] != "nv" || line[words[1][0]:words[1][1]] != "set" {
		return nil
	}
	var spans []span
	for i := 2; i+1 < len(words); i++ {
		if !isNVUESetSecretName(line, words, i) {
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
		spans = append(spans, shellValueSpan(line, start, end, offset))
		// A one-word value may be an attribute instead, after an object name
		// taken for one ("user secretary password <value>"), so the loop looks
		// at it as a name too. The words inside a longer value are skipped.
		if end > words[i+1][1] {
			i++
			for i+1 < len(words) && words[i+1][0] < end {
				i++
			}
		}
	}
	return spans
}

// shellValueSpan returns the span of the shell word line[start:end]. A word
// that is one plain quoted string ('v' or "v" with no quote or backslash
// inside) loses its quotes, so the secret hashes to the same token as where
// it is shown unquoted (a row, JSON). Anything else is hashed whole.
func shellValueSpan(line string, start, end, offset int) span {
	if end-start > 2 {
		q, inner := line[start], line[start+1:end-1]
		if (q == '\'' || q == '"') && line[end-1] == q && !strings.ContainsAny(inner, `'"\`) {
			return span{start: offset + start + 1, end: offset + end - 1}
		}
	}
	return span{start: offset + start, end: offset + end}
}

// isRule reports whether w is a run of '-' or '=', as under an NVUE table
// header or section title, longer than a YAML list marker.
func isRule(w string) bool {
	return len(w) >= 2 && (strings.Trim(w, "-") == "" || strings.Trim(w, "=") == "")
}

// wordSpans returns a span for every word, without a trailing colon, except
// list markers and rules.
func wordSpans(line string, words [][]int, offset int) []span {
	spans := make([]span, 0, len(words))
	for _, w := range words {
		if word := line[w[0]:w[1]]; word == "-" || isRule(word) {
			continue
		}
		end := w[1]
		if line[end-1] == ':' && end-1 > w[0] {
			end--
		}
		spans = append(spans, span{start: offset + w[0], end: offset + end})
	}
	return spans
}

// yamlSpans returns a span for every word under a secret name that starts a
// YAML key ("readonly-community:", with or without a value on the line, which
// may be a block scalar indicator such as "|") or stands alone on its line as
// a section title (above a "===" rule), and for the rest of that line. The
// key may itself be a list item ("- password: <value>"). Everything indented
// deeper than the key belongs to it, as do list items, rules and "---" at the
// key's own indent, which is where YAML may write a key's list; the first
// other non-blank line indented no deeper ends it.
func (s *nvueScanner) yamlSpans(line string, words [][]int, offset int) []span {
	if len(words) == 0 {
		return nil
	}
	indent := words[0][0]
	first := line[words[0][0]:words[0][1]]
	if s.secretIndent >= 0 {
		if indent > s.secretIndent || (indent == s.secretIndent && (strings.HasPrefix(first, "-") || isRule(first))) {
			return wordSpans(line, words, offset)
		}
		s.secretIndent = -1
	}
	key := words
	if first == "-" {
		key = words[1:]
	}
	if len(key) == 0 {
		return nil
	}
	name, colon := strings.CutSuffix(line[key[0][0]:key[0][1]], ":")
	if (!colon && len(key) > 1) || name == "" || !isNVUESecretName(name) || strings.ContainsAny(name, `"'{}`) {
		return nil
	}
	s.secretIndent = key[0][0]
	return wordSpans(line, key[1:], offset)
}

// tableSpans returns a span for every word of a table row that falls in a
// secret column: one whose header, on the line above the table's rule of
// dashes ("Hostname  Port  Secret" over "--------  ----  ------"), holds a
// secret name. Columns start where the rule's dash runs start; a word belongs
// to the column it starts in. The table ends at the first blank line.
func (s *nvueScanner) tableSpans(line string, words [][]int, offset int) []span {
	if len(words) == 0 {
		s.colStarts, s.secretCol = nil, nil
		return nil
	}
	if s.isTableRule(line, words) {
		s.colStarts, s.secretCol = make([]int, len(words)), make([]bool, len(words))
		for k, w := range words {
			s.colStarts[k] = w[0]
		}
		for _, h := range s.prevWords {
			if isNVUESecretName(strings.TrimSuffix(s.prevLine[h[0]:h[1]], ":")) {
				s.secretCol[s.column(h[0])] = true
			}
		}
		if !slices.Contains(s.secretCol, true) {
			s.colStarts, s.secretCol = nil, nil
		}
		return nil
	}
	var spans []span
	for _, w := range words {
		if s.colStarts != nil && s.secretCol[s.column(w[0])] {
			spans = append(spans, span{start: offset + w[0], end: offset + w[1]})
		}
	}
	return spans
}

// isTableRule reports whether line, with its words, is the rule under a table
// header: only runs of dashes, at least one of them three long, below a
// non-blank line.
func (s *nvueScanner) isTableRule(line string, words [][]int) bool {
	if s.prevWords == nil {
		return false
	}
	long := false
	for _, w := range words {
		word := line[w[0]:w[1]]
		if strings.Trim(word, "-") != "" {
			return false
		}
		long = long || len(word) >= 3
	}
	return long
}

// column returns the index of the table column that offset pos falls in.
func (s *nvueScanner) column(pos int) int {
	k := 0
	for k+1 < len(s.colStarts) && pos >= s.colStarts[k+1] {
		k++
	}
	return k
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
// hold secrets, so it is obfuscated, and followed by the notice
// obfuscateForCaller returns; if obfuscation fails the error is returned
// unchanged. Call it after logging, so the output stays out of the log.
func cumulus5CommandError(dt deviceType, err error) error {
	var cmdErr *sshclient.CommandError
	if dt != deviceTypeCumulus5x || !errors.As(err, &cmdErr) || strings.TrimSpace(string(cmdErr.Output)) == "" {
		return err
	}
	safe, notice, oerr := obfuscateForCaller(dt, string(cmdErr.Output))
	if oerr != nil {
		return err
	}
	msg := strings.TrimSpace(safe)
	if notice != "" {
		msg += "\n" + notice
	}
	return fmt.Errorf("%w; device output:\n%s", err, msg)
}

// runDeviceCommand runs command on the device. On cumulus5x it strips the
// ANSI escapes nv prints for bold or colour from the output, and from the
// output kept in a CommandError, so that obfuscation, syntax classification
// and error output all see plain text.
func runDeviceCommand(ctx context.Context, cfg sshclient.ConnConfig, dt deviceType, command string) (string, error) {
	out, err := runCommand(ctx, cfg, command)
	if dt != deviceTypeCumulus5x {
		return out, err
	}
	var cmdErr *sshclient.CommandError
	if errors.As(err, &cmdErr) {
		cmdErr.Output = []byte(stripANSI(string(cmdErr.Output)))
	}
	return stripANSI(out), err
}
