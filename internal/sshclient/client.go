package sshclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	dialTimeout              = 15 * time.Second
	EnvKnownHostsPath        = "SSH_KNOWN_HOSTS"
	EnvSkipHostKeyValidation = "SKIP_HOST_KEY_CHECK"
	EnvCommandTimeout        = "SSH_COMMAND_TIMEOUT"

	// DefaultCommandTimeout bounds how long a command may run once the
	// session is open. Large configurations on big chassis can take tens of
	// seconds, so it is generous.
	DefaultCommandTimeout = 60 * time.Second
)

var errHostKeyCaptured = errors.New("ssh host key captured")

// handshakeTimeout bounds the SSH handshake and authentication, which
// ClientConfig.Timeout does not cover: it applies only to the TCP connect in
// gossh.Dial. It is a variable so tests can shorten it.
var handshakeTimeout = 15 * time.Second

// errLimitReached is the reason closeOnLimit reports when its time limit
// passed.
var errLimitReached = errors.New("time limit reached")

// closeOnLimit closes c once d has passed or ctx is done, whichever comes
// first, unless the returned stop function is called first. stop reports why
// c was closed: errLimitReached when d passed, ctx's error when ctx was done
// (the caller cancelled the request), or nil when it was not closed. Calling
// stop again returns the same result. If ctx is already done, c is closed
// and stop reports it, so a cancelled request never carries on.
//
// Closing from a timer, rather than setting a deadline on the connection,
// says exactly whether the limit was hit. x/crypto starts a background reader
// during the handshake, so a deadline still set when the handshake returns
// could expire before it is cleared and drop a working connection.
func closeOnLimit(ctx context.Context, d time.Duration, c io.Closer) (stop func() error) {
	limitCtx, cancel := context.WithTimeoutCause(ctx, d, errLimitReached)
	stopClose := context.AfterFunc(limitCtx, func() { _ = c.Close() })
	return sync.OnceValue(func() error {
		defer cancel()
		if stopClose() {
			return nil // stopped before limitCtx was done: c was not closed
		}
		if errors.Is(context.Cause(limitCtx), errLimitReached) {
			return errLimitReached
		}
		// The caller cancelled. Report the context's error rather than its
		// cause, which can be anything: go-sdk cancels a request with the
		// transport's read error (io.EOF) when the client disconnects, and
		// callers rely on errors.Is(err, context.Canceled).
		return limitCtx.Err()
	})
}

// closers closes each of its members, so one limit can cover several
// connections.
type closers []io.Closer

func (cs closers) Close() error {
	var errs []error
	for _, c := range cs {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// closerFunc adapts a function to io.Closer.
type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }

// handshakeError describes a handshake that closeOnLimit cut short.
func handshakeError(addr string, reason error) error {
	if errors.Is(reason, errLimitReached) {
		return fmt.Errorf("SSH handshake with %s did not finish within %v: %w", addr, handshakeTimeout, os.ErrDeadlineExceeded)
	}
	return fmt.Errorf("SSH handshake with %s: %w", addr, reason)
}

// ErrCommandTimeout is returned when a device accepts a command but does not
// finish answering within the command timeout. Devices that do not support
// SSH exec requests (for example the Cisco Business switch OS) behave this way.
var ErrCommandTimeout = errors.New("no response within the command timeout")

// ConnConfig holds SSH connection parameters.
type ConnConfig struct {
	Host     string
	Port     int
	Username string
	// CommandTimeout, when longer than the configured command timeout, is
	// used instead of it for commands run with this config. Commands known
	// to take longer, such as ping and traceroute, set it.
	CommandTimeout time.Duration
}

// Options controls SSH host key handling and command timeouts.
type Options struct {
	KnownHostsPath           string
	InsecureSkipHostKeyCheck bool
	// CommandTimeout bounds each command after the session opens. Zero or
	// negative means DefaultCommandTimeout.
	CommandTimeout time.Duration
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
		validatedPath, err := validateKnownHostsPath(resolved.KnownHostsPath)
		if err != nil {
			return err
		}
		resolved.KnownHostsPath = validatedPath
	}
	if resolved.CommandTimeout <= 0 {
		resolved.CommandTimeout = DefaultCommandTimeout
	}
	currentOptions = resolved
	return nil
}

func commandTimeout() time.Duration {
	if currentOptions.CommandTimeout <= 0 {
		return DefaultCommandTimeout
	}
	return currentOptions.CommandTimeout
}

// commandTimeoutFor returns the command timeout for cfg: the configured one,
// or cfg.CommandTimeout when that is longer.
func commandTimeoutFor(cfg ConnConfig) time.Duration {
	return max(commandTimeout(), cfg.CommandTimeout)
}

// DefaultKnownHostsPath returns the default OpenSSH known_hosts path for the current user.
func DefaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for known_hosts: %w", err)
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

func validateKnownHostsPath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("known_hosts path must be absolute: %s", path)
	}

	return cleaned, nil
}

// RunCommand dials the SSH host, executes cmd, and returns stdout.
// A new connection is created for each call. Cancelling ctx closes the
// connection and returns ctx's error.
func RunCommand(ctx context.Context, cfg ConnConfig, cmd string) (string, error) {
	if strings.TrimSpace(cmd) == "" {
		return "", fmt.Errorf("command is required")
	}

	return runSessionCommand(ctx, cfg, cmd)
}

// RunCommands dials the SSH host, executes multiple newline-delimited commands
// in a single non-PTY exec session, and returns stdout. Cancelling ctx closes
// the connection and returns ctx's error.
func RunCommands(ctx context.Context, cfg ConnConfig, commands []string) (string, error) {
	if len(commands) == 0 {
		return "", fmt.Errorf("at least one command is required")
	}

	joined := make([]string, 0, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			return "", fmt.Errorf("command is required")
		}
		joined = append(joined, command)
	}

	return runSessionCommand(ctx, cfg, strings.Join(joined, "\n"))
}

// ProbeResult is what Probe learned about a device.
type ProbeResult struct {
	// ServerVersion is the SSH identification string the server sent, such
	// as "SSH-2.0-OpenSSH_9.9". It is chosen by the device and is untrusted.
	ServerVersion string
	// Command is the command that was run, or "" if choose ran none.
	Command string
	// Output is the command's stdout. It is kept even when the command exits
	// non-zero, because an error message also identifies a platform.
	Output string
}

// Probe dials the SSH host and passes the server's identification string to
// choose, which returns the command to run on the same connection. If choose
// returns an error, Probe returns it without running anything; if it returns
// "", Probe runs nothing. Cancelling ctx closes the connection and returns
// ctx's error.
func Probe(ctx context.Context, cfg ConnConfig, choose func(serverVersion string) (string, error)) (ProbeResult, error) {
	client, addr, err := dial(ctx, cfg)
	if err != nil {
		return ProbeResult{}, err
	}
	defer func() { _ = client.Close() }()

	res := ProbeResult{ServerVersion: string(client.ServerVersion())}
	cmd, err := choose(res.ServerVersion)
	if err != nil || cmd == "" {
		return res, err
	}
	res.Command = cmd

	out, err := runOnClient(ctx, client, addr, cmd, commandTimeout())
	res.Output = out
	var exitErr *gossh.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return res, err
	}
	return res, nil
}

func runSessionCommand(ctx context.Context, cfg ConnConfig, cmd string) (string, error) {
	client, addr, err := dial(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	out, err := runOnClient(ctx, client, addr, cmd, commandTimeoutFor(cfg))
	if err != nil {
		return "", err
	}
	return out, nil
}

func dial(ctx context.Context, cfg ConnConfig) (*gossh.Client, string, error) {
	// A cancelled request must report the cancellation, not whatever step
	// first trips over it (such as "no auth available").
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	port := normalizedPort(cfg.Port)

	methods, closeAgent, err := buildAuthMethods()
	if err != nil {
		return nil, "", err
	}
	defer closeAgent()

	hostKeyCallback, knownHosts, err := buildHostKeyCallback(cfg.Host, port)
	if err != nil {
		return nil, "", err
	}

	addr := joinHostPort(cfg.Host, port)
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("dial %s: %w", addr, err)
	}

	sshCfg := &gossh.ClientConfig{
		User:              cfg.Username,
		Auth:              methods,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: preferredHostKeyAlgorithms(knownHosts, addr, conn.RemoteAddr()),
	}

	// The limit closes the agent connection too: authentication can be stuck
	// waiting on the agent (for example one that asks the user to confirm
	// each use), and closing the TCP connection alone does not unblock it.
	stop := closeOnLimit(ctx, handshakeTimeout, closers{conn, closerFunc(closeAgent)})
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, sshCfg)
	if reason := stop(); reason != nil {
		if err == nil {
			_ = sshConn.Close()
		}
		return nil, "", handshakeError(addr, reason)
	}
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("dial %s: %w", addr, err)
	}
	return gossh.NewClient(sshConn, chans, reqs), addr, nil
}

// runOnClient runs cmd in a new exec session on client. If opening the
// session and running the command take longer than timeout, the connection
// is closed and ErrCommandTimeout is returned; if ctx is cancelled first, it
// is closed and ctx's error is returned. On a non-zero exit status it
// returns the output together with a *CommandError.
func runOnClient(ctx context.Context, client *gossh.Client, addr, cmd string, timeout time.Duration) (string, error) {
	// Start the limit before opening the session: a device can also stall
	// on the session request.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("run %q on %s: %w", cmd, addr, err)
	}
	stop := closeOnLimit(ctx, timeout, client)
	defer func() { _ = stop() }() // releases the timer once the command is done
	limitErr := func(reason error) error {
		if errors.Is(reason, errLimitReached) {
			return fmt.Errorf("run %q on %s: %w (%s); the device may not support SSH exec requests, or the command needs more time than the command timeout allows",
				cmd, addr, ErrCommandTimeout, timeout)
		}
		return fmt.Errorf("run %q on %s: %w", cmd, addr, reason)
	}

	session, err := client.NewSession()
	if err != nil {
		if reason := stop(); reason != nil {
			return "", limitErr(reason)
		}
		return "", fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr

	out, err := session.Output(cmd)
	if reason := stop(); reason != nil {
		return "", limitErr(reason)
	}
	if err != nil {
		return string(out), &CommandError{Command: cmd, Err: err, Output: append(stderr.Bytes(), out...)}
	}
	return string(out), nil
}

// CommandError is returned when a command fails after it was sent, usually
// with a non-zero exit status. Its message holds only the command and the
// exit status: device output is untrusted, can hold secrets, and would reach
// the caller and the logs without obfuscation, so it is kept in Output for
// callers that need to classify the failure and never put in the message.
type CommandError struct {
	Command string
	// Err is the underlying error, usually a *ssh.ExitError.
	Err error
	// Output is what the device wrote to stderr followed by stdout. Treat it
	// as untrusted and do not show it to callers.
	Output []byte
}

func (e *CommandError) Error() string {
	// ExitError's own message appends the device-chosen exit-signal reason,
	// so describe it from the status and signal only. The signal name also
	// comes from the device, so it is shown only if it looks like one.
	var exitErr *gossh.ExitError
	if errors.As(e.Err, &exitErr) {
		if signalNameRe.MatchString(exitErr.Signal()) {
			return fmt.Sprintf("run %q: process exited with status %d from signal %s", e.Command, exitErr.ExitStatus(), exitErr.Signal())
		}
		return fmt.Sprintf("run %q: process exited with status %d", e.Command, exitErr.ExitStatus())
	}
	return fmt.Sprintf("run %q: %v", e.Command, e.Err)
}

func (e *CommandError) Unwrap() error { return e.Err }

var signalNameRe = regexp.MustCompile(`^[A-Z0-9]{1,10}$`)

// InspectHostKey fetches the host key presented by a remote SSH server without
// trusting it. Cancelling ctx closes the connection and returns ctx's error.
func InspectHostKey(ctx context.Context, host string, port int) (HostKeyInfo, error) {
	// Ask for the key types already stored for this host, so the key shown
	// is the one known_hosts would be checked against.
	knownHosts, err := loadKnownHosts()
	if err != nil {
		return HostKeyInfo{}, err
	}
	return inspectHostKey(ctx, host, port, knownHosts)
}

// inspectHostKey fetches the host key presented by a remote SSH server,
// asking first for the key types knownHosts stores for it (knownHosts may
// be nil).
func inspectHostKey(ctx context.Context, host string, port int, knownHosts gossh.HostKeyCallback) (HostKeyInfo, error) {
	port = normalizedPort(port)
	addr := joinHostPort(host, port)

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return HostKeyInfo{}, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	var captured gossh.PublicKey
	sshCfg := &gossh.ClientConfig{
		User: "netdev-ssh-mcp-host-key-probe",
		Auth: []gossh.AuthMethod{gossh.Password("")},
		HostKeyCallback: rejectProhibitedHostKey(func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			captured = key
			return errHostKeyCaptured
		}),
		HostKeyAlgorithms: preferredHostKeyAlgorithms(knownHosts, addr, conn.RemoteAddr()),
	}

	stop := closeOnLimit(ctx, handshakeTimeout, conn)
	_, _, _, err = gossh.NewClientConn(conn, addr, sshCfg)
	// A key captured just as the limit passed is still good, but a cancelled
	// request is reported as cancelled.
	if reason := stop(); reason != nil && (captured == nil || !errors.Is(reason, errLimitReached)) {
		return HostKeyInfo{}, handshakeError(addr, reason)
	}
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

// testHookBeforeKnownHostsWrite, when set by a test, runs just before
// TrustHostKey checks for cancellation and writes known_hosts.
var testHookBeforeKnownHostsWrite func()

// TrustHostKey adds or replaces the SSH host key in the configured
// known_hosts file. Cancelling ctx before the key is fetched closes the
// connection and returns ctx's error; nothing is written then.
func TrustHostKey(ctx context.Context, host string, port int, replace bool) (TrustHostKeyResult, error) {
	if currentOptions.InsecureSkipHostKeyCheck {
		return TrustHostKeyResult{}, fmt.Errorf("cannot manage host keys while %s is enabled", EnvSkipHostKeyValidation)
	}
	if currentOptions.KnownHostsPath == "" {
		return TrustHostKeyResult{}, fmt.Errorf("known_hosts path is not configured")
	}

	// Load known_hosts once, both to choose the host key algorithms and to
	// check the presented key.
	knownHosts, err := loadKnownHosts()
	if err != nil {
		return TrustHostKeyResult{}, err
	}

	info, err := inspectHostKey(ctx, host, port, knownHosts)
	if err != nil {
		return TrustHostKeyResult{}, err
	}

	status, err := hostKeyStatus(info, knownHosts)
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

	// The caller may have given up while the key was fetched and checked;
	// then the trust store must not change.
	if testHookBeforeKnownHostsWrite != nil {
		testHookBeforeKnownHostsWrite()
	}
	if err := ctx.Err(); err != nil {
		return TrustHostKeyResult{}, fmt.Errorf("trust host key for %s: %w", info.Address, err)
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

// buildAuthMethods returns the available authentication methods, and a
// function that closes the SSH agent connection they use. The caller must
// call it once the connection is done with, or every call leaks a socket.
func buildAuthMethods() ([]gossh.AuthMethod, func(), error) {
	var methods []gossh.AuthMethod
	closeAgent := func() {}

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		sock = filepath.Clean(sock)
		if filepath.IsAbs(sock) {
			// A local socket connects at once; the agent is cut off by the
			// handshake limit instead (see dial).
			conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", sock) //nolint:gosec // G704: SSH_AUTH_SOCK is set by the system SSH agent, path is validated to be absolute above
			if err == nil {
				closeAgent = func() { _ = conn.Close() }
				methods = append(methods, gossh.PublicKeysCallback(agent.NewClient(conn).Signers))
			}
		}
	}

	if pw := os.Getenv("DEVICE_PASSWORD"); pw != "" {
		methods = append(methods, gossh.Password(pw))
	}

	if len(methods) == 0 {
		return nil, nil, fmt.Errorf("no auth available: set SSH_AUTH_SOCK or DEVICE_PASSWORD")
	}

	return methods, closeAgent, nil
}

// buildHostKeyCallback returns the callback that verifies a server's host
// key, and the underlying known_hosts callback (nil when verification is
// disabled) for preferredHostKeyAlgorithms. The callback refuses keys of a
// prohibited type even when verification is disabled.
func buildHostKeyCallback(host string, port int) (gossh.HostKeyCallback, gossh.HostKeyCallback, error) {
	if currentOptions.InsecureSkipHostKeyCheck {
		return rejectProhibitedHostKey(gossh.InsecureIgnoreHostKey()), nil, nil //nolint:gosec
	}
	if currentOptions.KnownHostsPath == "" {
		return nil, nil, fmt.Errorf("known_hosts path is not configured")
	}

	callback, err := loadKnownHosts()
	if err != nil {
		return nil, nil, err
	}
	if callback == nil {
		return nil, nil, fmt.Errorf(
			"SSH known_hosts file not found at %s. Create it or use the trust_host_key tool to add %s before connecting",
			currentOptions.KnownHostsPath,
			joinHostPort(host, port),
		)
	}

	return rejectProhibitedHostKey(verifyKnownHost(callback, host, port)), callback, nil
}

// loadKnownHosts parses the configured known_hosts file. It returns a nil
// callback, and no error, when host key checking is disabled or the file does
// not exist yet, since then nothing is stored.
func loadKnownHosts() (gossh.HostKeyCallback, error) {
	if currentOptions.InsecureSkipHostKeyCheck || currentOptions.KnownHostsPath == "" {
		return nil, nil
	}
	callback, err := knownhosts.New(currentOptions.KnownHostsPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load known_hosts file %s: %w", currentOptions.KnownHostsPath, err)
	}
	return callback, nil
}

// rejectProhibitedHostKey wraps callback so a host key of a prohibited type
// is refused, even when known_hosts stores it.
func rejectProhibitedHostKey(callback gossh.HostKeyCallback) gossh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if err := checkHostKeyAllowed(key); err != nil {
			return err
		}
		return callback(hostname, remote, key)
	}
}

// checkHostKeyAllowed returns an error when key, or the key a certificate
// certifies, is of a prohibited type.
func checkHostKeyAllowed(key gossh.PublicKey) error {
	keyType := key.Type()
	if cert, ok := key.(*gossh.Certificate); ok {
		keyType = cert.Key.Type()
	}
	if slices.Contains(prohibitedHostKeyAlgorithms, keyType) {
		return fmt.Errorf("host key type %s is not allowed: DSA keys are cryptographically weak", key.Type())
	}
	return nil
}

// verifyKnownHost wraps a known_hosts callback so unknown and mismatched
// keys produce a HostKeyValidationError.
func verifyKnownHost(callback gossh.HostKeyCallback, host string, port int) gossh.HostKeyCallback {
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
	}
}

// placeholderHostKey returns a key that is in no known_hosts file. Checking
// it against known_hosts makes the callback list the keys stored for a host.
var placeholderHostKey = sync.OnceValue(func() gossh.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	key, err := gossh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	return key
})

// prohibitedHostKeyAlgorithms are never offered to a server, and keys of
// these types are refused. DSA (ssh-dss) is limited to 1024-bit keys and
// SHA-1 signatures and is cryptographically weak. The library's default
// host key algorithms still include it, so HostKeyAlgorithms is always set.
var prohibitedHostKeyAlgorithms = []string{gossh.InsecureKeyAlgoDSA, gossh.InsecureCertAlgoDSAv01} //nolint:staticcheck // SA1019: referenced only to refuse DSA.

// sha1HostKeyAlgorithms sign with SHA-1. x/crypto drops them from its default
// algorithms in FIPS 140 mode, and so does allowedHostKeyAlgorithms, since it
// replaces that default.
var sha1HostKeyAlgorithms = []string{gossh.KeyAlgoRSA, gossh.CertAlgoRSAv01}

// allowedHostKeyAlgorithms returns every host key algorithm the library
// implements, except the prohibited ones, ordered by hostKeyAlgorithmRank.
// Building it from the library's lists covers new key types without edits.
func allowedHostKeyAlgorithms() []string {
	var algorithms []string
	for _, a := range slices.Concat(gossh.SupportedAlgorithms().HostKeys, gossh.InsecureAlgorithms().HostKeys) {
		if slices.Contains(prohibitedHostKeyAlgorithms, a) || slices.Contains(algorithms, a) {
			continue
		}
		if fips140.Enabled() && slices.Contains(sha1HostKeyAlgorithms, a) {
			continue
		}
		algorithms = append(algorithms, a)
	}
	slices.SortStableFunc(algorithms, func(a, b string) int {
		return hostKeyAlgorithmRank(a) - hostKeyAlgorithmRank(b)
	})
	return algorithms
}

// hostKeyAlgorithmRank orders host key algorithms as OpenSSH does:
// certificates before plain keys, and within each, ed25519, then ECDSA, then
// RSA, with SHA-1 ssh-rsa after the SHA-2 variants. Key types OpenSSH does
// not rank (ML-DSA, and any the library adds later) go between ECDSA and
// RSA. Equal ranks keep the library's order.
func hostKeyAlgorithmRank(algorithm string) int {
	base, _, isCert := strings.Cut(algorithm, "-cert-v01@")
	rank := 0
	if !isCert {
		rank = 10
	}
	switch {
	case base == gossh.KeyAlgoED25519:
		return rank
	case strings.HasPrefix(base, "ecdsa-sha2-"):
		return rank + 1
	case base == gossh.KeyAlgoRSASHA512:
		return rank + 3
	case base == gossh.KeyAlgoRSASHA256:
		return rank + 4
	case base == gossh.KeyAlgoRSA:
		return rank + 5
	default:
		return rank + 2
	}
}

// hostKeyType returns the key type a host key algorithm verifies: the RSA
// SHA-2 signature algorithms verify ssh-rsa keys, and every other algorithm
// verifies keys of its own name.
func hostKeyType(algorithm string) string {
	switch algorithm {
	case gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSASHA512:
		return gossh.KeyAlgoRSA
	default:
		return algorithm
	}
}

// preferredHostKeyAlgorithms returns the host key algorithms to offer a
// server: those that verify the key types stored for it in known_hosts
// first, then every other allowed algorithm, as OpenSSH does.
//
// Without this the library's default order wins. It prefers ECDSA to
// ed25519, so a server holding both presents its ECDSA key even when
// known_hosts stores only the ed25519 one, and the connection fails with a
// host key mismatch although the stored key is correct.
//
// It returns allowedHostKeyAlgorithms unchanged when nothing allowed is
// stored for the host or knownHosts is nil. It never returns nil, because
// the library default would offer prohibited algorithms.
func preferredHostKeyAlgorithms(knownHosts gossh.HostKeyCallback, hostname string, remote net.Addr) []string {
	allowed := allowedHostKeyAlgorithms()
	placeholder := placeholderHostKey()
	if knownHosts == nil || placeholder == nil {
		return allowed
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(knownHosts(hostname, remote, placeholder), &keyErr) || len(keyErr.Want) == 0 {
		return allowed
	}

	stored := make(map[string]bool, len(keyErr.Want))
	for _, k := range keyErr.Want {
		stored[k.Key.Type()] = true
	}
	preferred := make([]string, 0, len(allowed))
	var rest []string
	for _, a := range allowed {
		if stored[hostKeyType(a)] {
			preferred = append(preferred, a)
		} else {
			rest = append(rest, a)
		}
	}
	return append(preferred, rest...)
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

// hostKeyStatus reports whether knownHosts trusts the presented key
// ("trusted"), stores a different key for the host ("mismatch"), or stores
// nothing for it ("unknown"). A nil knownHosts stores nothing.
func hostKeyStatus(info HostKeyInfo, knownHosts gossh.HostKeyCallback) (string, error) {
	if knownHosts == nil {
		return "unknown", nil
	}

	remote := &net.TCPAddr{IP: net.IPv4zero, Port: info.Port}
	if err := knownHosts(info.Address, remote, info.publicKey); err == nil {
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
	if err := os.WriteFile(info.KnownHostsPath, []byte(content), 0o600); err != nil { //nolint:gosec // KnownHostsPath is validated in Configure to be a cleaned absolute path before use.
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
