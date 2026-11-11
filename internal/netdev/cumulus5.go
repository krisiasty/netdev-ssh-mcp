package netdev

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
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
		slices.ContainsFunc(cumulus5RefusedPathWords, func(r string) bool { return strings.HasPrefix(r, lower) })
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
		if isNVUESecretName(line[words[i][0]:words[i][1]]) {
			spans = append(spans, span{start: offset + words[i+1][0], end: offset + words[i+1][1]})
		}
	}
	return spans
}

// nvueRowSpans returns a span for every word after the first when the first
// word, without surrounding brackets and a trailing colon, names a secret by
// isCumulus5SecretWord, and the line has the shape of an NVUE row: the first
// word is bracketed or ends in a colon ("[readonly-community] value",
// "password: value"), or the next word starts after two or more spaces, as in
// a table ("password  *  *"). Other lines, such as "password 3 <value>" or
// 'secret "<value>"; ## note', are left to the platform patterns, so their
// trailing words stay readable. isSecretJSONKey is deliberately not used:
// it matches "key", "community" and "md5", which begin ordinary rows on other
// platforms ("key chain KC1").
func nvueRowSpans(line string, offset int) []span {
	words := nvueWordPattern.FindAllStringIndex(line, -1)
	if len(words) < 2 {
		return nil
	}
	first := strings.TrimSuffix(strings.Trim(line[words[0][0]:words[0][1]], "[]"), ":")
	// A quoted or braced name is JSON, which the JSON pass handles.
	if !isCumulus5SecretWord(first) || strings.ContainsAny(first, `"'{}`) {
		return nil
	}
	rowShaped := strings.ContainsAny(line[words[0][0]:words[0][1]], "[:") ||
		words[1][0]-words[0][1] >= 2
	if !rowShaped {
		return nil
	}
	spans := make([]span, 0, len(words)-1)
	for _, w := range words[1:] {
		spans = append(spans, span{start: offset + w[0], end: offset + w[1]})
	}
	return spans
}
