package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// testServer is a minimal SSH server for exercising the client. Exec requests
// are answered by commands; a command missing from the map never answers,
// like a device that ignores exec requests.
type testServer struct {
	addr     *net.TCPAddr
	commands map[string]testReply
}

type testReply struct {
	output string
	stderr string
	status uint32
}

func startTestServer(t *testing.T, serverVersion string, commands map[string]testReply) *testServer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gossh.ServerConfig{
		ServerVersion: serverVersion,
		PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	s := &testServer{addr: ln.Addr().(*net.TCPAddr), commands: commands}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cfg)
		}
	}()
	return s
}

func (s *testServer) serve(conn net.Conn, cfg *gossh.ServerConfig) {
	sconn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	go gossh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(gossh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range chReqs {
				if req.Type != "exec" || len(req.Payload) < 4 ||
					uint64(len(req.Payload)) < 4+uint64(binary.BigEndian.Uint32(req.Payload)) {
					_ = req.Reply(false, nil)
					continue
				}
				_ = req.Reply(true, nil)
				reply, ok := s.commands[string(req.Payload[4:4+binary.BigEndian.Uint32(req.Payload)])]
				if !ok {
					continue // never answer
				}
				_, _ = ch.Write([]byte(reply.output))
				_, _ = ch.Stderr().Write([]byte(reply.stderr))
				_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{reply.status}))
				_ = ch.Close()
			}
		}()
	}
}

// useTestServer points the client at s with password auth and no host key
// checks, and restores the previous options afterwards.
func useTestServer(t *testing.T, s *testServer, timeout time.Duration) ConnConfig {
	t.Helper()
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "test")
	if err := Configure(Options{InsecureSkipHostKeyCheck: true, CommandTimeout: timeout}); err != nil {
		t.Fatal(err)
	}
	return ConnConfig{Host: s.addr.IP.String(), Port: s.addr.Port, Username: "u"}
}

func TestProbeReturnsServerVersionAndOutput(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6 PKIX[12.5.1]", map[string]testReply{
		"show version": {output: "Cisco Nexus Operating System (NX-OS) Software\n"},
	})
	cfg := useTestServer(t, s, 5*time.Second)

	var seen string
	res, err := Probe(cfg, func(serverVersion string) (string, error) {
		seen = serverVersion
		return "show version", nil
	})
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if seen != "SSH-2.0-OpenSSH_9.6 PKIX[12.5.1]" || res.ServerVersion != seen {
		t.Fatalf("server version passed to choose = %q, in result = %q", seen, res.ServerVersion)
	}
	if res.Command != "show version" || !strings.Contains(res.Output, "NX-OS") {
		t.Fatalf("Probe() = %+v", res)
	}
}

func TestProbeKeepsOutputOnNonZeroExit(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.9", map[string]testReply{
		"show version": {output: "% Invalid input\n", status: 1},
	})
	cfg := useTestServer(t, s, 5*time.Second)

	res, err := Probe(cfg, func(string) (string, error) { return "show version", nil })
	if err != nil || res.Output != "% Invalid input\n" {
		t.Fatalf("Probe() = %+v, %v; want the output and no error", res, err)
	}
}

func TestProbeRunsNothingWhenChooseRefuses(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_7.3p1.RL", map[string]testReply{})
	cfg := useTestServer(t, s, 5*time.Second)

	refused := errors.New("unsupported")
	res, err := Probe(cfg, func(string) (string, error) { return "", refused })
	if !errors.Is(err, refused) || res.Command != "" || res.ServerVersion != "SSH-2.0-OpenSSH_7.3p1.RL" {
		t.Fatalf("Probe() = %+v, %v; want the refusal, the server version and no command", res, err)
	}
}

func TestRunCommandTimesOut(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_7.3p1.RL", map[string]testReply{})
	cfg := useTestServer(t, s, 300*time.Millisecond)

	start := time.Now()
	_, err := RunCommand(cfg, "show version")
	if !errors.Is(err, ErrCommandTimeout) {
		t.Fatalf("RunCommand() error = %v, want ErrCommandTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("RunCommand() took %s, want about the 300ms timeout", elapsed)
	}
}

func TestRunCommandReturnsOutput(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.9", map[string]testReply{
		"show clock": {output: "12:00:00\n"},
	})
	cfg := useTestServer(t, s, 5*time.Second)

	out, err := RunCommand(cfg, "show clock")
	if err != nil || out != "12:00:00\n" {
		t.Fatalf("RunCommand() = %q, %v", out, err)
	}
}

func TestConfigureDefaultsCommandTimeout(t *testing.T) {
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	if err := Configure(Options{InsecureSkipHostKeyCheck: true}); err != nil {
		t.Fatal(err)
	}
	if got := commandTimeout(); got != DefaultCommandTimeout {
		t.Fatalf("commandTimeout() = %s, want %s", got, DefaultCommandTimeout)
	}
}

// TestRunCommandErrorOmitsDeviceOutput checks that a failed command's error
// message holds only the command and exit status, while the device output
// stays available in CommandError.Output for classifying the failure.
func TestRunCommandErrorOmitsDeviceOutput(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.9", map[string]testReply{
		"show foo": {stderr: "% Invalid input detected at '^' marker.\n", output: "enable secret 5 $1$abcd$efgh\n", status: 1},
		"show bar": {output: "% Incomplete command\n", status: 1},
	})
	cfg := useTestServer(t, s, 5*time.Second)

	_, err := RunCommand(cfg, "show foo")
	if err == nil || err.Error() != `run "show foo": process exited with status 1` {
		t.Fatalf("RunCommand() error = %q, want only the command and exit status", err)
	}
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || !strings.Contains(string(cmdErr.Output), "% Invalid input") || !strings.Contains(string(cmdErr.Output), "enable secret") {
		t.Fatalf("CommandError.Output = %q, want stderr and stdout", cmdErr.Output)
	}
	var exitErr *gossh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 {
		t.Fatalf("RunCommand() error = %v, want it to wrap the ExitError", err)
	}

	_, err = RunCommand(cfg, "show bar")
	if !errors.As(err, &cmdErr) || string(cmdErr.Output) != "% Incomplete command\n" || strings.Contains(err.Error(), "Incomplete") {
		t.Fatalf("RunCommand() error = %q, Output %q; want stdout in Output only", err, cmdErr.Output)
	}
}
