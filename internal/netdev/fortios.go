package netdev

import (
	"fmt"
	"regexp"
	"strings"
)

// fortiOSPromptPattern matches the CLI prompt FortiOS writes in an SSH exec
// session, such as "FGT-1 $ " or "FGT-1 (root) # ": once before each
// command's output, which follows it on the same line, and once more at the
// end. The hostname is set by the device.
const fortiOSPromptPattern = `[\w.-]+(?: \([\w.-]+\))? [#$] `

var fortiOSPromptRe = regexp.MustCompile(`^` + fortiOSPromptPattern)

// fortiOSPagedRe matches a "--More--" prompt that FortiOS erased: the sign
// that it paged the output and ended the command early (see terminalFor).
var fortiOSPagedRe = regexp.MustCompile(`(?m)^--More-- *(?:\r|\x08|\x1b\[K)`)

var errFortiOSPaged = fmt.Errorf("FortiOS paged the output and ended the command early, so it is incomplete: "+
	"this happens when the output is longer than %d lines or the device refused the terminal this tool requests; "+
	`"set output standard" under "config system console" turns the pager off`, fortiOSTerminalRows)

// deviceOutput returns a command's output as the tools report it. On FortiOS
// that is fortiOSOutput; elsewhere the output is unchanged.
func deviceOutput(dt deviceType, out string) (string, error) {
	if dt != deviceTypeFortiOS {
		return out, nil
	}
	return fortiOSOutput(out)
}

// fortiOSOutput refuses output that FortiOS paged, which is incomplete, and
// removes the CLI prompts from the rest.
func fortiOSOutput(out string) (string, error) {
	if fortiOSPagedRe.MatchString(out) {
		return "", errFortiOSPaged
	}
	return trimFortiOSPrompts(out), nil
}

// trimFortiOSPrompts removes the CLI prompts FortiOS writes around command
// output. The prompt is taken from the start of the output and removed there
// and wherever it starts a line, with the newline that follows it when no
// output does, so the output of several commands is separated by a blank
// line. A line of output that starts with that exact prompt would lose it
// too. Output that does not start with a prompt is returned unchanged.
func trimFortiOSPrompts(out string) string {
	prompt := fortiOSPromptRe.FindString(out)
	if prompt == "" {
		return out
	}
	for strings.HasPrefix(out, prompt) {
		out = strings.TrimPrefix(out[len(prompt):], "\n")
	}
	out = strings.ReplaceAll(out, "\n"+prompt+"\n", "\n")
	out = strings.ReplaceAll(out, "\n"+prompt, "\n")
	out = strings.TrimRight(out, "\n")
	if out == "" {
		return ""
	}
	return out + "\n"
}
