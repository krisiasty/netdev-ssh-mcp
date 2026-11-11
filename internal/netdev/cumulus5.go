package netdev

import (
	"fmt"
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

// isCumulus5RefusedPathWord reports whether the NVUE path word w points into a
// secret, or abbreviates a word that does.
func isCumulus5RefusedPathWord(w string) bool {
	lower := strings.ToLower(w)
	if lower == "" {
		return false
	}
	return slices.ContainsFunc(cumulus5RefusedPathWords, func(r string) bool { return strings.HasPrefix(r, lower) }) ||
		strings.Contains(lower, "password") || strings.Contains(lower, "secret")
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
