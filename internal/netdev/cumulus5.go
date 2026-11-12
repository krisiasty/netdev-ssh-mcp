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
	words := spaceSeparated(command)
	for _, w := range words {
		if !cumulusWordChars.match(w) {
			return "", fmt.Errorf("command may only contain %s in words separated by spaces", cumulusWordChars.rule)
		}
	}
	if len(words) < 2 || words[0] != "nv" || words[1] != "show" {
		return "", fmt.Errorf("command must start with 'nv show'")
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
	for _, w := range path {
		if isCumulus5RefusedPathWord(w) {
			return "", fmt.Errorf("this path shows a secret; use the get_config tool, or show the parent path with -o json")
		}
	}
	// NVUE accepts abbreviations, so "sys conf" is "system config".
	if len(path) >= 2 && isPrefixFold("system", path[0]) && isPrefixFold("config", path[1]) {
		return "", fmt.Errorf("use the get_config tool to retrieve device configuration")
	}
	return command + cumulusMergeStderr, nil
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

// nvueCommandSpans returns a span for the word after every secret-named word
// of an "nv set" line, such as "nv set system aaa radius server 10.0.0.9
// secret <value>". Spans are offset by the line's position in the text.
func nvueCommandSpans(line string, offset int) []span {
	words := nvueWordPattern.FindAllStringIndex(line, -1)
	if len(words) < 3 || line[words[0][0]:words[0][1]] != "nv" || line[words[1][0]:words[1][1]] != "set" {
		return nil
	}
	var spans []span
	for i := 2; i+1 < len(words); i++ {
		if !isNVUESecretName(line[words[i][0]:words[i][1]]) {
			continue
		}
		start, end := words[i+1][0], words[i+1][1]
		if q := line[start]; q == '\'' || q == '"' {
			// A quoted value is a whole shell word: it runs to the next unquoted
			// whitespace, or to the end of the line.
			end = shellWordEnd(line, start)
			for i+1 < len(words) && words[i+1][0] < end {
				i++
			}
			i--
		}
		spans = append(spans, span{start: offset + start, end: offset + end})
	}
	return spans
}

// nvueYAMLSpans returns a span for every word under a secret-named map key
// that stands alone on its line in YAML-like NVUE output ("readonly-community:"
// followed by its indented subtree), keys included, as the JSON pass does. The
// subtree ends at the first non-blank line indented no more than the key.
func nvueYAMLSpans(text string) []span {
	var spans []span
	secretIndent := -1 // indentation of the open secret key, or -1
	offset := 0
	for line := range strings.SplitSeq(text, "\n") {
		start := offset
		offset += len(line) + 1
		trimmed := strings.TrimLeft(line, " \t")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		indent := len(line) - len(trimmed)
		if secretIndent >= 0 {
			if indent > secretIndent {
				for _, w := range nvueWordPattern.FindAllStringIndex(line, -1) {
					end := w[1]
					if line[end-1] == ':' && end-1 > w[0] {
						end--
					}
					spans = append(spans, span{start: start + w[0], end: start + end})
				}
				continue
			}
			secretIndent = -1
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 1 && strings.HasSuffix(fields[0], ":") {
			name := strings.TrimSuffix(fields[0], ":")
			if isNVUESecretName(name) && !strings.ContainsAny(name, `"'{}`) {
				secretIndent = indent
			}
		}
	}
	return spans
}

// nvueRowSpans returns a span for every word after the first when the first
// word, without surrounding brackets and a trailing colon, names a secret (see
// isNVUESecretName), and the line has the shape of an NVUE row: the first
// word is bracketed or ends in a colon ("[readonly-community] value",
// "password: value"), or the next word starts after two or more spaces, as in
// a table ("password  *  *"). Other lines, such as "password 3 <value>" or
// 'secret "<value>"; ## note', are left to the platform patterns, so their
// trailing words stay readable, as does a single-spaced "key chain KC1".
func nvueRowSpans(line string, offset int) []span {
	words := nvueWordPattern.FindAllStringIndex(line, -1)
	if len(words) < 2 {
		return nil
	}
	first := strings.TrimSuffix(strings.Trim(line[words[0][0]:words[0][1]], "[]"), ":")
	// A quoted or braced name is JSON, which the JSON pass handles.
	if !isNVUESecretName(first) || strings.ContainsAny(first, `"'{}`) {
		return nil
	}
	firstWord := line[words[0][0]:words[0][1]]
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
// unchanged. Call it after logging, so the output stays out of the log.
func cumulus5CommandError(dt deviceType, err error) error {
	var cmdErr *sshclient.CommandError
	if dt != deviceTypeCumulus5x || !errors.As(err, &cmdErr) {
		return err
	}
	out := stripANSI(string(cmdErr.Output))
	if strings.TrimSpace(out) == "" {
		return err
	}
	safe, _, oerr := obfuscate(out)
	if oerr != nil {
		return err
	}
	safe = strings.TrimSpace(safe)
	return fmt.Errorf("%w; device output:\n%s", err, safe)
}
