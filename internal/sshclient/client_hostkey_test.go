package sshclient

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // SA1019: the tests need DSA keys to check that they are refused.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// dsaParameters are generated once, because generating them is slow.
var dsaParameters = sync.OnceValues(func() (dsa.Parameters, error) {
	var params dsa.Parameters
	err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
	return params, err
})

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
	case "dsa":
		var params dsa.Parameters
		if params, err = dsaParameters(); err == nil {
			dsaKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
			err = dsa.GenerateKey(dsaKey, rand.Reader)
			key = dsaKey
		}
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
								_, _ = ch.Write([]byte("ok"))
								_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
								_ = ch.Close()
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
		// first lists, in any order, the algorithms expected ahead of all others.
		first []string
	}{
		{name: "ed25519", keys: []string{"ed25519"}, first: []string{gossh.KeyAlgoED25519}},
		{name: "ecdsa", keys: []string{"ecdsa"}, first: []string{gossh.KeyAlgoECDSA256}},
		{name: "rsa", keys: []string{"rsa"}, first: rsaAlgorithms},
		{name: "rsa and ed25519", keys: []string{"rsa", "ed25519"}, first: append([]string{gossh.KeyAlgoED25519}, rsaAlgorithms...)},
		{name: "dsa and ed25519", keys: []string{"dsa", "ed25519"}, first: []string{gossh.KeyAlgoED25519}},
		{name: "dsa only", keys: []string{"dsa"}},
		{name: "nothing stored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pub []gossh.PublicKey
			for _, k := range tt.keys {
				pub = append(pub, newSigner(t, k).PublicKey())
			}
			path := useKnownHosts(t, addr, pub...)
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
			out, err := RunCommand(cfg, "show version")
			if err != nil || out != "ok" {
				t.Fatalf("RunCommand() = %q, %v; want ok", out, err)
			}

			info, err := InspectHostKey(addr.IP.String(), addr.Port)
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

	_, err := RunCommand(ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	var hkErr *HostKeyValidationError
	if !errors.As(err, &hkErr) || len(hkErr.MatchingKnownHosts) == 0 || hkErr.PresentedKeyType != gossh.KeyAlgoED25519 {
		t.Fatalf("RunCommand() error = %v, want a host key mismatch on the ed25519 key", err)
	}
}

func TestRunCommandMismatchWhenStoredTypeIsGone(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ecdsa"))
	useKnownHosts(t, addr, newSigner(t, "ed25519").PublicKey())

	_, err := RunCommand(ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	var hkErr *HostKeyValidationError
	if !errors.As(err, &hkErr) || hkErr.PresentedKeyType != gossh.KeyAlgoECDSA256 {
		t.Fatalf("RunCommand() error = %v, want a host key mismatch, not a negotiation failure", err)
	}
}

// TestRunCommandRefusesDSAHostKey checks that a DSA host key is never
// negotiated, even when known_hosts stores it.
func TestRunCommandRefusesDSAHostKey(t *testing.T) {
	dsaKey := newSigner(t, "dsa")
	addr := startHostKeyServer(t, dsaKey)
	useKnownHosts(t, addr, dsaKey.PublicKey())

	out, err := RunCommand(ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	if err == nil {
		t.Fatalf("RunCommand() = %q, nil; want an error for a DSA-only server", out)
	}
}

// TestRunCommandIgnoresStoredDSAKey checks that a stored DSA key is not
// preferred: the server presents its ed25519 key, which is then reported as
// a mismatch against the stored DSA key.
func TestRunCommandIgnoresStoredDSAKey(t *testing.T) {
	dsaKey := newSigner(t, "dsa")
	addr := startHostKeyServer(t, dsaKey, newSigner(t, "ed25519"))
	useKnownHosts(t, addr, dsaKey.PublicKey())

	_, err := RunCommand(ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	var hkErr *HostKeyValidationError
	if !errors.As(err, &hkErr) || hkErr.PresentedKeyType != gossh.KeyAlgoED25519 {
		t.Fatalf("RunCommand() error = %v, want a host key mismatch on the ed25519 key", err)
	}
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
	added, err := TrustHostKey(host, addr.Port, false)
	if err != nil || added.Action != "added" {
		t.Fatalf("TrustHostKey() = %q, %v; want added", added.Action, err)
	}
	if again, err := TrustHostKey(host, addr.Port, false); err != nil || again.Action != "already_trusted" || again.FingerprintSHA256 != added.FingerprintSHA256 {
		t.Fatalf("TrustHostKey() = %q %s, %v; want already_trusted %s", again.Action, again.FingerprintSHA256, err, added.FingerprintSHA256)
	}

	// Store a different key of each type the server holds, as if both had
	// been regenerated on the device.
	useKnownHosts(t, addr, newSigner(t, "ecdsa").PublicKey(), newSigner(t, "ed25519").PublicKey())
	if _, err := TrustHostKey(host, addr.Port, false); err == nil {
		t.Fatal("TrustHostKey() error = nil, want a mismatch without replace_existing")
	}
	if replaced, err := TrustHostKey(host, addr.Port, true); err != nil || replaced.Action != "replaced" {
		t.Fatalf("TrustHostKey(replace) = %q, %v; want replaced", replaced.Action, err)
	}
	if again, err := TrustHostKey(host, addr.Port, false); err != nil || again.Action != "already_trusted" {
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

	if _, err := InspectHostKey(addr.IP.String(), addr.Port); err == nil {
		t.Fatal("InspectHostKey() error = nil, want the malformed known_hosts reported")
	}
	if _, err := TrustHostKey(addr.IP.String(), addr.Port, false); err == nil {
		t.Fatal("TrustHostKey() error = nil, want the malformed known_hosts reported")
	}
}

func TestTrustHostKeyRefusesDSAHostKey(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "dsa"))
	path := useKnownHosts(t, addr)

	if _, err := TrustHostKey(addr.IP.String(), addr.Port, false); err == nil {
		t.Fatal("TrustHostKey() error = nil, want an error for a DSA-only server")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Fatalf("known_hosts stat = %v, %v; want it left empty", fi, err)
	}
}

// TestHostKeyCallbackRejectsDSA checks the callback refuses a DSA key on its
// own, whether known_hosts stores it or verification is disabled.
func TestHostKeyCallbackRejectsDSA(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}
	key := newSigner(t, "dsa").PublicKey()

	t.Run("stored in known_hosts", func(t *testing.T) {
		useKnownHosts(t, addr, key)
		callback, _, err := buildHostKeyCallback(addr.IP.String(), addr.Port)
		if err != nil {
			t.Fatal(err)
		}
		if err := callback(joinHostPort(addr.IP.String(), addr.Port), addr, key); err == nil {
			t.Fatal("callback() = nil, want the stored DSA key refused")
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
			_, err := RunCommand(ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
			return err
		},
		"InspectHostKey": func() error {
			_, err := InspectHostKey(addr.IP.String(), addr.Port)
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
