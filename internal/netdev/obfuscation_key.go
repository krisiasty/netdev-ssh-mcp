package netdev

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
)

// Environment variables that supply the obfuscation key.
const (
	EnvObfuscationKey     = "OBFUSCATION_KEY"
	EnvObfuscationKeyFile = "OBFUSCATION_KEY_FILE"
)

// Where LoadObfuscationKey found the key material.
const (
	KeySourceEnv       = "env"
	KeySourceFile      = "file"
	KeySourceEphemeral = "ephemeral"
)

const minObfuscationKeyLen = 16

// Notices about the ephemeral key. It is safe, because it never leaves the
// process, but tokens only match within one server run.
const (
	// EphemeralKeyLogMessage is logged at startup.
	EphemeralKeyLogMessage = "no obfuscation key configured; using a random key for this run only. " +
		"Tokens will not match tokens from other runs or machines. " +
		"Set " + EnvObfuscationKey + " or --obfuscation-key-file for stable tokens."
	// EphemeralKeyInstructions is sent to the client as server instructions.
	EphemeralKeyInstructions = "netdev-ssh-mcp has no obfuscation key configured and uses a random key for this " +
		"server run. Secret tokens ([h:...]) in get_config and run_show_command output can be compared with each " +
		"other within this run, but not with tokens from earlier sessions, other machines or other people. " +
		"Suggest that the user set " + EnvObfuscationKey + " or --obfuscation-key-file to get stable tokens."
	// EphemeralKeyNotice is appended to tool results that contain tokens.
	EphemeralKeyNotice = "Note from netdev-ssh-mcp: the [h:...] tokens above use a random key for this server run " +
		"only. Compare them only with tokens from this run. For tokens that stay stable across runs and machines, " +
		"the user should set " + EnvObfuscationKey + " or --obfuscation-key-file to a random key of their own."
)

// EphemeralObfuscationKey reports whether obfuscation is on and keyed with a
// random per-run key because no key was configured.
func EphemeralObfuscationKey() bool {
	return Obfuscate && obfuscationKeySource == KeySourceEphemeral
}

// ServerInstructions returns MCP server instructions for the current
// obfuscation setup, or "" when there is nothing to report.
func ServerInstructions() string {
	if EphemeralObfuscationKey() {
		return EphemeralKeyInstructions
	}
	return ""
}

// LoadObfuscationKey picks the raw key material for obfuscation tokens:
// key (from OBFUSCATION_KEY) or the contents of keyFile if either is set,
// otherwise random bytes held only in memory for this process.
//
// Configured keys are trimmed of surrounding whitespace and must be at least
// 16 bytes. Setting both key and keyFile is an error. Nothing is written.
func LoadObfuscationKey(key, keyFile string) (raw []byte, source string, err error) {
	key = strings.TrimSpace(key)
	keyFile = strings.TrimSpace(keyFile)

	switch {
	case key != "" && keyFile != "":
		return nil, "", fmt.Errorf("set only one of %s and %s", EnvObfuscationKey, EnvObfuscationKeyFile)
	case key != "":
		raw, err = checkKeyLen([]byte(key), EnvObfuscationKey)
		return raw, KeySourceEnv, err
	case keyFile != "":
		b, err := os.ReadFile(keyFile) //nolint:gosec // G304: path is operator configuration, read-only
		if err != nil {
			return nil, "", fmt.Errorf("read obfuscation key file: %w", err)
		}
		raw, err = checkKeyLen([]byte(strings.TrimSpace(string(b))), "obfuscation key file")
		return raw, KeySourceFile, err
	}

	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generate obfuscation key: %w", err)
	}
	return raw, KeySourceEphemeral, nil
}

func checkKeyLen(raw []byte, name string) ([]byte, error) {
	if len(raw) < minObfuscationKeyLen {
		return nil, fmt.Errorf("%s must be at least %d bytes", name, minObfuscationKeyLen)
	}
	return raw, nil
}
