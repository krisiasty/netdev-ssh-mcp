package sshclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	dialTimeout              = 15 * time.Second
	EnvKnownHostsPath        = "SSH_KNOWN_HOSTS"
	EnvSkipHostKeyValidation = "SKIP_HOST_KEY_CHECK"
)

var errHostKeyCaptured = errors.New("ssh host key captured")

// ConnConfig holds SSH connection parameters.
type ConnConfig struct {
	Host     string
	Port     int
	Username string
}

// Options controls SSH host key handling.
type Options struct {
	KnownHostsPath           string
	InsecureSkipHostKeyCheck bool
}

// HostKeyInfo describes the host key currently presented by an SSH server.
type HostKeyInfo struct {
	Host              string
	Port              int
	Address           string
	KnownHostsPath    string
	KeyType           string
	FingerprintSHA256 string
	KnownHostsLine    string
	publicKey         gossh.PublicKey
}

// TrustHostKeyResult describes the outcome of adding or replacing a host key.
type TrustHostKeyResult struct {
	HostKeyInfo
	Action string
}

var currentOptions Options

// Configure applies SSH client options.
func Configure(opts Options) error {
	resolved := opts
	resolved.KnownHostsPath = strings.TrimSpace(resolved.KnownHostsPath)
	if !resolved.InsecureSkipHostKeyCheck && resolved.KnownHostsPath == "" {
		defaultPath, err := DefaultKnownHostsPath()
		if err != nil {
			return err
		}
		resolved.KnownHostsPath = defaultPath
	}
	if resolved.KnownHostsPath != "" {
		resolved.KnownHostsPath = filepath.Clean(resolved.KnownHostsPath)
	}
	currentOptions = resolved
	return nil
}

// DefaultKnownHostsPath returns the default OpenSSH known_hosts path for the current user.
func DefaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for known_hosts: %w", err)
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

// RunCommand dials the SSH host, executes cmd, and returns stdout.
// A new connection is created for each call.
func RunCommand(cfg ConnConfig, cmd string) (string, error) {
	port := normalizedPort(cfg.Port)

	methods, err := buildAuthMethods()
	if err != nil {
		return "", err
	}

	hostKeyCallback, err := buildHostKeyCallback(cfg.Host, port)
	if err != nil {
		return "", err
	}

	sshCfg := &gossh.ClientConfig{
		User:            cfg.Username,
		Auth:            methods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         dialTimeout,
	}

	addr := joinHostPort(cfg.Host, port)
	client, err := gossh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = session.Close() }()

	out, err := session.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("run %q: %w", cmd, err)
	}

	return string(out), nil
}

// InspectHostKey fetches the host key presented by a remote SSH server without trusting it.
func InspectHostKey(host string, port int) (HostKeyInfo, error) {
	port = normalizedPort(port)
	addr := joinHostPort(host, port)

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return HostKeyInfo{}, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	var captured gossh.PublicKey
	sshCfg := &gossh.ClientConfig{
		User: "netdev-ssh-mcp-host-key-probe",
		Auth: []gossh.AuthMethod{gossh.Password("")},
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			captured = key
			return errHostKeyCaptured
		},
		Timeout: dialTimeout,
	}

	_, _, _, err = gossh.NewClientConn(conn, addr, sshCfg)
	if captured == nil {
		if err != nil {
			return HostKeyInfo{}, fmt.Errorf("fetch host key from %s: %w", addr, err)
		}
		return HostKeyInfo{}, fmt.Errorf("fetch host key from %s: no host key received", addr)
	}
	if err != nil && !errors.Is(err, errHostKeyCaptured) {
		return HostKeyInfo{}, fmt.Errorf("fetch host key from %s: %w", addr, err)
	}

	return HostKeyInfo{
		Host:              host,
		Port:              port,
		Address:           addr,
		KnownHostsPath:    currentOptions.KnownHostsPath,
		KeyType:           captured.Type(),
		FingerprintSHA256: gossh.FingerprintSHA256(captured),
		KnownHostsLine:    knownhosts.Line(knownHostAddresses(host, port), captured),
		publicKey:         captured,
	}, nil
}

// TrustHostKey adds or replaces the SSH host key in the configured known_hosts file.
func TrustHostKey(host string, port int, replace bool) (TrustHostKeyResult, error) {
	if currentOptions.InsecureSkipHostKeyCheck {
		return TrustHostKeyResult{}, fmt.Errorf("cannot manage host keys while %s is enabled", EnvSkipHostKeyValidation)
	}
	if currentOptions.KnownHostsPath == "" {
		return TrustHostKeyResult{}, fmt.Errorf("known_hosts path is not configured")
	}

	info, err := InspectHostKey(host, port)
	if err != nil {
		return TrustHostKeyResult{}, err
	}

	status, err := hostKeyStatus(info)
	if err != nil {
		return TrustHostKeyResult{}, err
	}
	if status == "trusted" {
		return TrustHostKeyResult{HostKeyInfo: info, Action: "already_trusted"}, nil
	}
	if status == "mismatch" && !replace {
		return TrustHostKeyResult{}, fmt.Errorf(
			"SSH host key mismatch for %s. Presented key fingerprint: %s. Verify the device identity, then re-run the tool with replace_existing=true to update %s",
			info.Address,
			info.FingerprintSHA256,
			info.KnownHostsPath,
		)
	}

	if err := upsertKnownHost(info, replace); err != nil {
		return TrustHostKeyResult{}, err
	}

	action := "added"
	if status == "mismatch" {
		action = "replaced"
	}
	return TrustHostKeyResult{HostKeyInfo: info, Action: action}, nil
}

func buildAuthMethods() ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		sock = filepath.Clean(sock)
		if filepath.IsAbs(sock) {
			conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", sock) //nolint:gosec // G704: SSH_AUTH_SOCK is set by the system SSH agent, path is validated to be absolute above
			if err == nil {
				methods = append(methods, gossh.PublicKeysCallback(agent.NewClient(conn).Signers))
			}
		}
	}

	if pw := os.Getenv("DEVICE_PASSWORD"); pw != "" {
		methods = append(methods, gossh.Password(pw))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no auth available: set SSH_AUTH_SOCK or DEVICE_PASSWORD")
	}

	return methods, nil
}

func buildHostKeyCallback(host string, port int) (gossh.HostKeyCallback, error) {
	if currentOptions.InsecureSkipHostKeyCheck {
		return gossh.InsecureIgnoreHostKey(), nil //nolint:gosec
	}
	if currentOptions.KnownHostsPath == "" {
		return nil, fmt.Errorf("known_hosts path is not configured")
	}

	callback, err := knownhosts.New(currentOptions.KnownHostsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf(
				"SSH known_hosts file not found at %s. Create it or use the trust_host_key tool to add %s before connecting",
				currentOptions.KnownHostsPath,
				joinHostPort(host, port),
			)
		}
		return nil, fmt.Errorf("load known_hosts file %s: %w", currentOptions.KnownHostsPath, err)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		err := callback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			return &HostKeyValidationError{
				Address:            joinHostPort(host, port),
				KnownHostsPath:     currentOptions.KnownHostsPath,
				PresentedKeyType:   key.Type(),
				PresentedSHA256:    gossh.FingerprintSHA256(key),
				MatchingKnownHosts: keyErr.Want,
			}
		}
		return err
	}, nil
}

// HostKeyValidationError describes an unknown or mismatched SSH host key.
type HostKeyValidationError struct {
	Address            string
	KnownHostsPath     string
	PresentedKeyType   string
	PresentedSHA256    string
	MatchingKnownHosts []knownhosts.KnownKey
}

func (e *HostKeyValidationError) Error() string {
	if len(e.MatchingKnownHosts) == 0 {
		return fmt.Sprintf(
			"SSH host key for %s is not trusted. Presented key type: %s, fingerprint: %s. Add it to %s or use the trust_host_key tool to add it interactively",
			e.Address,
			e.PresentedKeyType,
			e.PresentedSHA256,
			e.KnownHostsPath,
		)
	}

	known := make([]string, 0, len(e.MatchingKnownHosts))
	for _, entry := range e.MatchingKnownHosts {
		known = append(known, fmt.Sprintf("%s (%s:%d)", gossh.FingerprintSHA256(entry.Key), entry.Filename, entry.Line))
	}

	return fmt.Sprintf(
		"SSH host key mismatch for %s. Presented key type: %s, fingerprint: %s. Stored key(s): %s. Verify the device identity, then update %s manually or use the trust_host_key tool with replace_existing=true",
		e.Address,
		e.PresentedKeyType,
		e.PresentedSHA256,
		strings.Join(known, ", "),
		e.KnownHostsPath,
	)
}

func normalizedPort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", normalizedPort(port)))
}

func knownHostAddresses(host string, port int) []string {
	if normalizedPort(port) == 22 {
		return []string{knownhosts.Normalize(host)}
	}
	return []string{knownhosts.Normalize(joinHostPort(host, port))}
}

func hostKeyStatus(info HostKeyInfo) (string, error) {
	callback, err := knownhosts.New(info.KnownHostsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "unknown", nil
		}
		return "", fmt.Errorf("load known_hosts file %s: %w", info.KnownHostsPath, err)
	}

	remote := &net.TCPAddr{IP: net.IPv4zero, Port: info.Port}
	if err := callback(info.Address, remote, info.publicKey); err == nil {
		return "trusted", nil
	} else {
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				return "unknown", nil
			}
			return "mismatch", nil
		}
		return "", fmt.Errorf("check host key status for %s: %w", info.Address, err)
	}
}

func upsertKnownHost(info HostKeyInfo, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(info.KnownHostsPath), 0o700); err != nil {
		return fmt.Errorf("create directory for %s: %w", info.KnownHostsPath, err)
	}

	var existing []byte
	if data, err := os.ReadFile(info.KnownHostsPath); err == nil {
		existing = data
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", info.KnownHostsPath, err)
	}

	lines := make([]string, 0)
	if len(existing) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(existing)))
		for scanner.Scan() {
			line := scanner.Text()
			if replace && lineMatchesHost(line, info.Host, info.Port) {
				continue
			}
			lines = append(lines, line)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read %s: %w", info.KnownHostsPath, err)
		}
	}

	lines = append(lines, strings.TrimSpace(info.KnownHostsLine))
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(info.KnownHostsPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", info.KnownHostsPath, err)
	}
	return nil
}

func lineMatchesHost(line, host string, port int) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}

	_, hosts, _, _, _, err := gossh.ParseKnownHosts([]byte(trimmed))
	if err != nil {
		return false
	}

	targets := knownHostAddresses(host, port)
	hashedTargets := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		hashedTargets[knownhosts.HashHostname(target)] = struct{}{}
	}

	for _, existing := range hosts {
		for _, target := range targets {
			if existing == target {
				return true
			}
		}
		if _, ok := hashedTargets[existing]; ok {
			return true
		}
	}

	return false
}
