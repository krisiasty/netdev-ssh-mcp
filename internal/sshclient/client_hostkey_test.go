package sshclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

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

	tests := []struct {
		name  string
		keys  []string
		first []string
	}{
		{name: "ed25519", keys: []string{"ed25519"}, first: []string{gossh.KeyAlgoED25519}},
		{name: "ecdsa", keys: []string{"ecdsa"}, first: []string{gossh.KeyAlgoECDSA256}},
		{name: "rsa", keys: []string{"rsa"}, first: []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA}},
		{name: "rsa and ed25519", keys: []string{"rsa", "ed25519"}, first: []string{
			gossh.KeyAlgoED25519, gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA,
		}},
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
			if len(got) < len(tt.first) || !slices.Equal(got[:len(tt.first)], tt.first) {
				t.Fatalf("preferredHostKeyAlgorithms() = %v, want it to start with %v", got, tt.first)
			}
			// The other algorithms follow, so a server that dropped the
			// stored key type still negotiates and reports a mismatch.
			for _, a := range gossh.SupportedAlgorithms().HostKeys {
				if !slices.Contains(got, a) {
					t.Fatalf("preferredHostKeyAlgorithms() = %v, missing %s", got, a)
				}
			}
		})
	}

	t.Run("nothing stored", func(t *testing.T) {
		path := useKnownHosts(t, addr)
		known, err := knownhosts.New(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := preferredHostKeyAlgorithms(known, hostname, addr); got != nil {
			t.Fatalf("preferredHostKeyAlgorithms() = %v, want nil (library default)", got)
		}
	})

	t.Run("verification disabled", func(t *testing.T) {
		if got := preferredHostKeyAlgorithms(nil, hostname, addr); got != nil {
			t.Fatalf("preferredHostKeyAlgorithms() = %v, want nil", got)
		}
	})
}

// TestRunCommandUsesStoredHostKeyType reproduces a server holding ECDSA and
// ed25519 host keys while known_hosts stores only the ed25519 one.
func TestRunCommandUsesStoredHostKeyType(t *testing.T) {
	ed := newSigner(t, "ed25519")
	addr := startHostKeyServer(t, newSigner(t, "ecdsa"), ed)

	// With nothing stored, the library default makes the server present
	// its ECDSA key; this is what used to be compared with the stored
	// ed25519 key.
	useKnownHosts(t, addr)
	info, err := InspectHostKey(addr.IP.String(), addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyType != gossh.KeyAlgoECDSA256 {
		t.Fatalf("default negotiation presented %s, want %s for this test to be meaningful", info.KeyType, gossh.KeyAlgoECDSA256)
	}

	useKnownHosts(t, addr, ed.PublicKey())
	cfg := ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}
	out, err := RunCommand(cfg, "show version")
	if err != nil || out != "ok" {
		t.Fatalf("RunCommand() = %q, %v; want ok", out, err)
	}

	info, err = InspectHostKey(addr.IP.String(), addr.Port)
	if err != nil || info.KeyType != gossh.KeyAlgoED25519 {
		t.Fatalf("InspectHostKey() = %s, %v; want the stored ed25519 key type", info.KeyType, err)
	}
	if status, err := hostKeyStatus(info); err != nil || status != "trusted" {
		t.Fatalf("hostKeyStatus() = %q, %v; want trusted", status, err)
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
