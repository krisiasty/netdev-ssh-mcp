package netdev

import (
	"fmt"
	"regexp"
	"strings"
)

// cumulusMergeStderr is appended to every command built for Cumulus Linux 4.x.
// NCLU's error stream is undocumented, so stderr is merged into stdout to make
// sure it reaches obfuscation. It is the only shell syntax the server adds.
const cumulusMergeStderr = " 2>&1"

// cumulusWordPattern is what each word of a Cumulus "net show" command may
// contain. An SSH exec request is run by bash on Cumulus, so every shell
// metacharacter (quotes, $, ;, &, |, <, >, parentheses, globs, ~, !, #, =)
// must be excluded, along with whitespace other than ' '.
var cumulusWordPattern = regexp.MustCompile(`^[A-Za-z0-9._:/,@%-]+$`)

// cumulusBlockedFamilies are NCLU "net show" sub-commands that return
// configuration or pending-change data; NCLU accepts any unambiguous prefix.
var cumulusBlockedFamilies = []string{"configuration", "commit", "rollback"}

// normalizeCumulusCommand verifies that command (already trimmed) is a single
// "net show" command that bash cannot split into anything else, and appends
// cumulusMergeStderr. The returned command is otherwise exactly as written.
func normalizeCumulusCommand(command string) (string, error) {
	var words []string
	for _, w := range strings.Split(command, " ") {
		if w != "" {
			words = append(words, w)
		}
	}
	for _, w := range words {
		if !cumulusWordPattern.MatchString(w) {
			return "", fmt.Errorf("command may only contain letters, digits and . _ : / , @ %% - in words separated by spaces")
		}
	}
	if len(words) < 2 || words[0] != "net" || words[1] != "show" {
		return "", fmt.Errorf("command must start with 'net show'")
	}
	for _, w := range words[2:] {
		if strings.HasPrefix(w, "-") {
			return "", fmt.Errorf("command words must not start with '-'")
		}
	}
	if len(words) > 2 {
		lower := strings.ToLower(words[2])
		for _, family := range cumulusBlockedFamilies {
			if strings.HasPrefix(family, lower) {
				return "", fmt.Errorf("use the get_config tool to retrieve device configuration")
			}
		}
	}
	return command + cumulusMergeStderr, nil
}
