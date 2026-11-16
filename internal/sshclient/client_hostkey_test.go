package sshclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// golang.org/x/crypto/ssh no longer implements DSA (ssh-dss) at all: it can
// neither create a DSA signer, nor parse a DSA public key, nor negotiate one.
// A DSA server therefore cannot be built for a test, and the tests below
// cover what is left: a stale ssh-dss line in known_hosts, and the client's
// own refusal of the type, kept in case the library ever offers it again.

// dsaKeyBlob is the wire encoding of an ssh-dss public key ("ssh-dss", p,
// q, g, y). The numbers are arbitrary: the library no longer parses the
// type, so nothing checks them.
var dsaKeyBlob = gossh.Marshal(struct {
	Name       string
	P, Q, G, Y *big.Int
}{gossh.InsecureKeyAlgoDSA, big.NewInt(23), big.NewInt(11), big.NewInt(4), big.NewInt(8)}) //nolint:staticcheck // SA1019: referenced only to build a stale DSA entry.

// dsaKnownHostsLine returns a known_hosts line storing an ssh-dss key for
// addr, as an older OpenSSH client would have written it.
func dsaKnownHostsLine(addr *net.TCPAddr) string {
	return strings.Join(knownHostAddresses(addr.IP.String(), addr.Port), ",") + " ssh-dss " + base64.StdEncoding.EncodeToString(dsaKeyBlob)
}

// appendKnownHostsLine adds line to the known_hosts file at path.
func appendKnownHostsLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is a test temp file.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// dsaPublicKey stands in for an ssh-dss key, which the library can no longer
// produce, to check the client's own refusal of the type.
type dsaPublicKey struct{}

func (dsaPublicKey) Type() string    { return gossh.InsecureKeyAlgoDSA } //nolint:staticcheck // SA1019: referenced only to stand in for a DSA key.
func (dsaPublicKey) Marshal() []byte { return dsaKeyBlob }
func (dsaPublicKey) Verify([]byte, *gossh.Signature) error {
	return errors.New("ssh-dss is not supported")
}

func newSigner(t *testing.T, kind string) gossh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startHostKeyServer runs an SSH server holding the given host keys. It
// accepts any password and answers every exec request with "ok".
func startHostKeyServer(t *testing.T, hostKeys ...gossh.Signer) *net.TCPAddr {
	t.Helper()
	return startSSHServer(t, func(ch gossh.Channel) {
		_, _ = ch.Write([]byte("ok"))
		_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
		_ = ch.Close()
	}, hostKeys...)
}

// startSSHServer runs an SSH server holding the given host keys. It accepts
// any password and calls exec for every exec request.
func startSSHServer(t *testing.T, exec func(gossh.Channel), hostKeys ...gossh.Signer) *net.TCPAddr {
	t.Helper()
	cfg := &gossh.ServerConfig{
		PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { return nil, nil },
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go gossh.DiscardRequests(reqs)
				for nc := range chans {
					ch, chReqs, err := nc.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range chReqs {
							_ = req.Reply(req.Type == "exec", nil)
							if req.Type == "exec" {
								exec(ch)
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// useKnownHosts writes a known_hosts file storing keys for addr and points
// the client at it with password authentication.
func useKnownHosts(t *testing.T, addr *net.TCPAddr, keys ...gossh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	var content []byte
	for _, k := range keys {
		content = append(content, knownhosts.Line(knownHostAddresses(addr.IP.String(), addr.Port), k)+"\n"...)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "test")
	if err := Configure(Options{KnownHostsPath: path}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPreferredHostKeyAlgorithms(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}
	hostname := "192.0.2.10:22"
	rsaAlgorithms := []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA}
	if fips140.Enabled() {
		rsaAlgorithms = rsaAlgorithms[:2] // no SHA-1 ssh-rsa
	}

	tests := []struct {
		name string
		keys []string
		// staleDSA adds an ssh-dss line for the host, which the library
		// skips when it reads known_hosts.
		staleDSA bool
		// first lists, in any order, the algorithms expected ahead of all others.
		first []string
	}{
		{name: "ed25519", keys: []string{"ed25519"}, first: []string{gossh.KeyAlgoED25519}},
		{name: "ecdsa", keys: []string{"ecdsa"}, first: []string{gossh.KeyAlgoECDSA256}},
		{name: "rsa", keys: []string{"rsa"}, first: rsaAlgorithms},
		{name: "rsa and ed25519", keys: []string{"rsa", "ed25519"}, first: append([]string{gossh.KeyAlgoED25519}, rsaAlgorithms...)},
		{name: "stale dsa and ed25519", keys: []string{"ed25519"}, staleDSA: true, first: []string{gossh.KeyAlgoED25519}},
		{name: "nothing stored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pub []gossh.PublicKey
			for _, k := range tt.keys {
				pub = append(pub, newSigner(t, k).PublicKey())
			}
			path := useKnownHosts(t, addr, pub...)
			if tt.staleDSA {
				appendKnownHostsLine(t, path, dsaKnownHostsLine(addr))
			}
			known, err := knownhosts.New(path)
			if err != nil {
				t.Fatal(err)
			}

			got := preferredHostKeyAlgorithms(known, hostname, addr)
			if len(got) < len(tt.first) || !sameElements(got[:len(tt.first)], tt.first) {
				t.Fatalf("preferredHostKeyAlgorithms() = %v, want it to start with %v", got, tt.first)
			}
			checkAllowedAlgorithms(t, got)
		})
	}

	t.Run("verification disabled", func(t *testing.T) {
		checkAllowedAlgorithms(t, preferredHostKeyAlgorithms(nil, hostname, addr))
	})
}

// TestAllowedHostKeyAlgorithmsOrder checks the OpenSSH order used when nothing
// is stored: certificates first, then ed25519, ECDSA and RSA, with SHA-1
// ssh-rsa last.
func TestAllowedHostKeyAlgorithmsOrder(t *testing.T) {
	got := allowedHostKeyAlgorithms()
	want := []string{
		gossh.CertAlgoED25519v01,
		gossh.CertAlgoECDSA256v01,
		gossh.CertAlgoRSASHA512v01,
		gossh.CertAlgoRSAv01,
		gossh.KeyAlgoED25519,
		gossh.KeyAlgoECDSA256,
		gossh.KeyAlgoECDSA384,
		gossh.KeyAlgoECDSA521,
		gossh.KeyAlgoRSASHA512,
		gossh.KeyAlgoRSASHA256,
		gossh.KeyAlgoRSA,
	}
	if fips140.Enabled() {
		want = slices.DeleteFunc(want, func(a string) bool { return a == gossh.KeyAlgoRSA || a == gossh.CertAlgoRSAv01 })
	}
	last := -1
	for _, a := range want {
		i := slices.Index(got, a)
		if i <= last {
			t.Fatalf("allowedHostKeyAlgorithms() = %v; want %s after %v", got, a, want[:slices.Index(want, a)])
		}
		last = i
	}
	firstPlain := slices.IndexFunc(got, func(a string) bool { return !strings.Contains(a, "-cert-v01@") })
	if slices.ContainsFunc(got[firstPlain:], func(a string) bool { return strings.Contains(a, "-cert-v01@") }) {
		t.Fatalf("allowedHostKeyAlgorithms() = %v; want every certificate algorithm before the plain keys", got)
	}
	if fips140.Enabled() {
		t.Skip("ssh-rsa is not offered in FIPS 140 mode")
	}
	if got[len(got)-1] != gossh.KeyAlgoRSA {
		t.Fatalf("allowedHostKeyAlgorithms() = %v; want ssh-rsa last", got)
	}
}

func sameElements(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// checkAllowedAlgorithms fails unless got offers every algorithm the library
// implements except DSA (and SHA-1 ssh-rsa in FIPS 140 mode), so a server
// that dropped the stored key type still negotiates and reports a mismatch,
// and never offers DSA.
func checkAllowedAlgorithms(t *testing.T, got []string) {
	t.Helper()
	for _, a := range slices.Concat(gossh.SupportedAlgorithms().HostKeys, gossh.InsecureAlgorithms().HostKeys) {
		excluded := a == "ssh-dss" || a == "ssh-dss-cert-v01@openssh.com" ||
			fips140.Enabled() && (a == "ssh-rsa" || a == "ssh-rsa-cert-v01@openssh.com")
		if slices.Contains(got, a) == excluded {
			t.Fatalf("preferredHostKeyAlgorithms() = %v; want every algorithm except DSA, got %s wrong", got, a)
		}
	}
}

// TestRunCommandUsesStoredHostKeyType checks that a server holding ECDSA and
// ed25519 host keys is verified against whichever one known_hosts stores.
// Whatever the library's preference order, in one of the two cases the
// stored key is not the one the server would present by default, which is
// the case that used to fail with a host key mismatch.
func TestRunCommandUsesStoredHostKeyType(t *testing.T) {
	ecdsaKey, edKey := newSigner(t, "ecdsa"), newSigner(t, "ed25519")
	addr := startHostKeyServer(t, ecdsaKey, edKey)

	for _, stored := range []gossh.PublicKey{ecdsaKey.PublicKey(), edKey.PublicKey()} {
		t.Run(stored.Type(), func(t *testing.T) {
			path := useKnownHosts(t, addr, stored)
			cfg := ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}
			out, err := RunCommand(t.Context(), cfg, "show version")
			if err != nil || out != "ok" {
				t.Fatalf("RunCommand() = %q, %v; want ok", out, err)
			}

			info, err := InspectHostKey(t.Context(), addr.IP.String(), addr.Port)
			if err != nil || info.KeyType != stored.Type() {
				t.Fatalf("InspectHostKey() = %s, %v; want the stored %s key type", info.KeyType, err, stored.Type())
			}
			known, err := knownhosts.New(path)
			if err != nil {
				t.Fatal(err)
			}
			if status, err := hostKeyStatus(info, known); err != nil || status != "trusted" {
				t.Fatalf("hostKeyStatus() = %q, %v; want trusted", status, err)
			}
		})
	}
}

func TestRunCommandStillReportsMismatch(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ecdsa"), newSigner(t, "ed25519"))
	useKnownHosts(t, addr, newSigner(t, "ed25519").PublicKey()) // a different ed25519 key

	_, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	var hkErr *HostKeyValidationError
	if !errors.As(err, &hkErr) || len(hkErr.MatchingKnownHosts) == 0 || hkErr.PresentedKeyType != gossh.KeyAlgoED25519 {
		t.Fatalf("RunCommand() error = %v, want a host key mismatch on the ed25519 key", err)
	}
}

func TestRunCommandMismatchWhenStoredTypeIsGone(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ecdsa"))
	useKnownHosts(t, addr, newSigner(t, "ed25519").PublicKey())

	_, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	var hkErr *HostKeyValidationError
	if !errors.As(err, &hkErr) || hkErr.PresentedKeyType != gossh.KeyAlgoECDSA256 {
		t.Fatalf("RunCommand() error = %v, want a host key mismatch, not a negotiation failure", err)
	}
}

// TestRunCommandSkipsStoredDSAKey checks that a stale ssh-dss line in
// known_hosts is skipped: the host's ed25519 key stored next to it verifies
// the server, and without it the server is reported as unknown, with no
// stored key to match.
func TestRunCommandSkipsStoredDSAKey(t *testing.T) {
	edKey := newSigner(t, "ed25519")
	addr := startHostKeyServer(t, edKey)
	cfg := ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}

	t.Run("ed25519 stored too", func(t *testing.T) {
		path := useKnownHosts(t, addr, edKey.PublicKey())
		appendKnownHostsLine(t, path, dsaKnownHostsLine(addr))
		if out, err := RunCommand(t.Context(), cfg, "show version"); err != nil || out != "ok" {
			t.Fatalf("RunCommand() = %q, %v; want ok", out, err)
		}
	})

	t.Run("only dsa stored for the host", func(t *testing.T) {
		// Another host's key keeps the file valid: with only the DSA line,
		// it would have no entry the library can read.
		other := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 22}
		path := useKnownHosts(t, other, newSigner(t, "ed25519").PublicKey())
		appendKnownHostsLine(t, path, dsaKnownHostsLine(addr))
		_, err := RunCommand(t.Context(), cfg, "show version")
		var hkErr *HostKeyValidationError
		if !errors.As(err, &hkErr) || hkErr.PresentedKeyType != gossh.KeyAlgoED25519 || len(hkErr.MatchingKnownHosts) != 0 {
			t.Fatalf("RunCommand() error = %v, want an unknown ed25519 host key with no stored key", err)
		}
	})
}

// TestTrustHostKey walks trust_host_key through adding a key to a
// known_hosts file that does not exist yet, finding it already trusted on a
// server with several host keys, and replacing a mismatched key.
func TestTrustHostKey(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ecdsa"), newSigner(t, "ed25519"))
	host := addr.IP.String()

	path := useKnownHosts(t, addr)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	added, err := TrustHostKey(t.Context(), host, addr.Port, false)
	if err != nil || added.Action != "added" {
		t.Fatalf("TrustHostKey() = %q, %v; want added", added.Action, err)
	}
	if again, err := TrustHostKey(t.Context(), host, addr.Port, false); err != nil || again.Action != "already_trusted" || again.FingerprintSHA256 != added.FingerprintSHA256 {
		t.Fatalf("TrustHostKey() = %q %s, %v; want already_trusted %s", again.Action, again.FingerprintSHA256, err, added.FingerprintSHA256)
	}

	// Store a different key of each type the server holds, as if both had
	// been regenerated on the device.
	useKnownHosts(t, addr, newSigner(t, "ecdsa").PublicKey(), newSigner(t, "ed25519").PublicKey())
	if _, err := TrustHostKey(t.Context(), host, addr.Port, false); err == nil {
		t.Fatal("TrustHostKey() error = nil, want a mismatch without replace_existing")
	}
	if replaced, err := TrustHostKey(t.Context(), host, addr.Port, true); err != nil || replaced.Action != "replaced" {
		t.Fatalf("TrustHostKey(replace) = %q, %v; want replaced", replaced.Action, err)
	}
	if again, err := TrustHostKey(t.Context(), host, addr.Port, false); err != nil || again.Action != "already_trusted" {
		t.Fatalf("TrustHostKey() after replace = %q, %v; want already_trusted", again.Action, err)
	}
}

// TestMalformedKnownHosts checks both steps of trust_host_key report a
// known_hosts file that cannot be parsed, rather than one ignoring it.
func TestMalformedKnownHosts(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ed25519"))
	path := useKnownHosts(t, addr)
	if err := os.WriteFile(path, []byte("192.0.2.1 ssh-ed25519 not-base64!\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := InspectHostKey(t.Context(), addr.IP.String(), addr.Port); err == nil {
		t.Fatal("InspectHostKey() error = nil, want the malformed known_hosts reported")
	}
	if _, err := TrustHostKey(t.Context(), addr.IP.String(), addr.Port, false); err == nil {
		t.Fatal("TrustHostKey() error = nil, want the malformed known_hosts reported")
	}
}

// TestHostKeyCallbackRejectsDSA checks the callback refuses a DSA key on its
// own, before known_hosts is consulted, and when verification is disabled.
func TestHostKeyCallbackRejectsDSA(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}
	var key gossh.PublicKey = dsaPublicKey{}

	t.Run("verification enabled", func(t *testing.T) {
		useKnownHosts(t, addr, newSigner(t, "ed25519").PublicKey())
		callback, _, err := buildHostKeyCallback(addr.IP.String(), addr.Port)
		if err != nil {
			t.Fatal(err)
		}
		err = callback(joinHostPort(addr.IP.String(), addr.Port), addr, key)
		if err == nil || !strings.Contains(err.Error(), "DSA keys are cryptographically weak") {
			t.Fatalf("callback() = %v, want the DSA key refused by type", err)
		}
	})

	t.Run("verification disabled", func(t *testing.T) {
		orig := currentOptions
		t.Cleanup(func() { currentOptions = orig })
		currentOptions = Options{InsecureSkipHostKeyCheck: true}
		callback, _, err := buildHostKeyCallback(addr.IP.String(), addr.Port)
		if err != nil {
			t.Fatal(err)
		}
		if err := callback(joinHostPort(addr.IP.String(), addr.Port), addr, key); err == nil {
			t.Fatal("callback() = nil, want the DSA key refused")
		}
		if err := callback(joinHostPort(addr.IP.String(), addr.Port), addr, newSigner(t, "ed25519").PublicKey()); err != nil {
			t.Fatalf("callback() = %v, want other keys accepted", err)
		}
	})
}

// TestHandshakeTimeout checks that a server which accepts the TCP connection
// and then never speaks SSH does not hang RunCommand or InspectHostKey.
func TestHandshakeTimeout(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	useKnownHosts(t, addr, newSigner(t, "ed25519").PublicKey())

	orig := handshakeTimeout
	t.Cleanup(func() { handshakeTimeout = orig })
	handshakeTimeout = 200 * time.Millisecond

	calls := map[string]func() error{
		"RunCommand": func() error {
			_, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
			return err
		},
		"InspectHostKey": func() error {
			_, err := InspectHostKey(t.Context(), addr.IP.String(), addr.Port)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- call() }()
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("%s() error = %v, want a handshake deadline error", name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s() still running after 5s, want it to give up after %v", name, handshakeTimeout)
			}
		})
	}
}

// TestRunCommandClosesAgentConnection checks that the connection to the SSH
// agent is closed after each command, so a long-running server does not leak
// a socket per call.
func TestRunCommandClosesAgentConnection(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ed25519"))
	useKnownHosts(t, addr)
	if _, err := TrustHostKey(t.Context(), addr.IP.String(), addr.Port, false); err != nil {
		t.Fatal(err)
	}

	// A short directory keeps the socket path under the platform limit.
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	closed := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// An empty keyring offers no keys, so password auth is used; the
		// agent returns once the client closes its end.
		_ = agent.ServeAgent(agent.NewKeyring(), conn)
		closed <- struct{}{}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	if out, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version"); err != nil || out != "ok" {
		t.Fatalf("RunCommand() = %q, %v; want ok", out, err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("agent connection still open after RunCommand returned")
	}
}

// TestRunCommandTimesOutOpeningSession checks that the command timeout also
// covers opening the session: a device that authenticates and then never
// answers the session request does not hang RunCommand.
func TestRunCommandTimesOutOpeningSession(t *testing.T) {
	cfg := &gossh.ServerConfig{
		PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(newSigner(t, "ed25519"))
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go gossh.DiscardRequests(reqs)
				for range chans { // never accept or reject a channel
				}
			}()
		}
	}()

	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "test")
	if err := Configure(Options{InsecureSkipHostKeyCheck: true, CommandTimeout: 200 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)

	done := make(chan error, 1)
	go func() {
		_, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCommandTimeout) {
			t.Fatalf("RunCommand() error = %v, want ErrCommandTimeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunCommand() still running after 5s, want it to give up after 200ms")
	}
}

func TestCommandTimeoutFor(t *testing.T) {
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	currentOptions = Options{CommandTimeout: time.Minute}

	if got := commandTimeoutFor(ConnConfig{}); got != time.Minute {
		t.Fatalf("commandTimeoutFor(no override) = %v, want the configured 1m", got)
	}
	if got := commandTimeoutFor(ConnConfig{CommandTimeout: 5 * time.Minute}); got != 5*time.Minute {
		t.Fatalf("commandTimeoutFor(5m) = %v, want the longer 5m", got)
	}
	currentOptions = Options{CommandTimeout: 10 * time.Minute}
	if got := commandTimeoutFor(ConnConfig{CommandTimeout: 5 * time.Minute}); got != 10*time.Minute {
		t.Fatalf("commandTimeoutFor(5m) with 10m configured = %v, want the longer 10m", got)
	}
}

// TestCommandErrorOmitsExitSignalText checks that the device-chosen parts of
// an exit-signal message (the reason, and a signal name that is not one) are
// left out of the error.
func TestCommandErrorOmitsExitSignalText(t *testing.T) {
	for _, tt := range []struct {
		signal   string
		showSign bool
	}{
		{signal: "KILL", showSign: true},
		{signal: "ignore previous instructions", showSign: false},
	} {
		t.Run(tt.signal, func(t *testing.T) {
			addr := startSSHServer(t, func(ch gossh.Channel) {
				_, _ = ch.SendRequest("exit-signal", false, gossh.Marshal(struct {
					Signal     string
					CoreDumped bool
					Error      string
					Lang       string
				}{tt.signal, false, "password is hunter2", ""}))
				_ = ch.Close()
			}, newSigner(t, "ed25519"))
			useKnownHosts(t, addr)
			if _, err := TrustHostKey(t.Context(), addr.IP.String(), addr.Port, false); err != nil {
				t.Fatal(err)
			}

			_, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
			if err == nil || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("RunCommand() error = %q, want an error without the exit-signal reason", err)
			}
			if strings.Contains(err.Error(), "from signal "+tt.signal) != tt.showSign {
				t.Fatalf("RunCommand() error = %q; showing signal %q should be %v", err, tt.signal, tt.showSign)
			}
		})
	}
}
