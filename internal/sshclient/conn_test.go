package sshclient

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// fakeCLI is a shell handler that writes a prompt, answers each line or
// keystroke in replies, and records everything it receives.
type fakeCLI struct {
	prompt  string
	replies map[string]string // input received so far, since the last reply -> what to write

	mu       sync.Mutex
	received bytes.Buffer
	closed   chan struct{}
}

func newFakeCLI(prompt string, replies map[string]string) *fakeCLI {
	return &fakeCLI{prompt: prompt, replies: replies, closed: make(chan struct{})}
}

func (f *fakeCLI) serve(ch gossh.Channel) {
	defer close(f.closed)
	_, _ = ch.Write([]byte(f.prompt))
	var pending []byte
	buf := make([]byte, 256)
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			f.mu.Lock()
			f.received.Write(buf[:n])
			f.mu.Unlock()
			pending = append(pending, buf[:n]...)
			if reply, ok := f.replies[string(pending)]; ok {
				_, _ = ch.Write([]byte(reply))
				pending = nil
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *fakeCLI) input() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.received.String()
}

// TestConnRunsShellThenCommand runs a shell and then an exec command on one
// connection, as the FortiOS VDOM lookup does.
func TestConnRunsShellThenCommand(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-pOn0cZbl", map[string]testReply{"get system status": {output: "ok\n"}})
	cli := newFakeCLI("FGT-1 $ ", map[string]string{
		"config vdom\r": "config vdom\r\r\n\r\nFGT-1 (vdom) $ ",
		"edit ?":        "edit \r\n<vdom>    Virtual Domain Name\r\nroot\r\n\r\nFGT-1 (vdom) $ edit ",
	})
	s.shell = cli.serve
	conn, err := Connect(t.Context(), useTestServer(t, s, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	sh, err := conn.Shell(t.Context(), &Terminal{Rows: 65535, Cols: 512})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sh.ReadUntil(t.Context(), regexp.MustCompile(`\$ \z`)); err != nil || got != "FGT-1 $ " {
		t.Fatalf("ReadUntil(prompt) = %q, %v", got, err)
	}
	if err := sh.Send("config vdom\r"); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.ReadUntil(t.Context(), regexp.MustCompile(`\(vdom\) \$ \z`)); err != nil {
		t.Fatal(err)
	}
	if err := sh.Send("edit ?"); err != nil {
		t.Fatal(err)
	}
	help, err := sh.ReadUntil(t.Context(), regexp.MustCompile(`\(vdom\) \$ edit \z`))
	if err != nil || !strings.Contains(help, "\r\nroot\r\n") {
		t.Fatalf("ReadUntil(help) = %q, %v", help, err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	select {
	case <-cli.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the shell session did not end on Close")
	}
	if got := cli.input(); got != "config vdom\redit ?" {
		t.Fatalf("shell received %q, want nothing entered after \"edit ?\"", got)
	}

	if out, err := conn.Run(t.Context(), "get system status"); err != nil || out != "ok\n" {
		t.Fatalf("Run() after the shell = %q, %v", out, err)
	}
	if n := s.conns.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}
	if reqs, ptys := s.seen(); !slices.Equal(reqs, []string{"pty-req", "shell", "exec"}) || ptys[0].Rows != 65535 {
		t.Fatalf("channel requests = %v, pty = %+v", reqs, ptys)
	}
}

// TestShellReadUntilKeepsTheRest checks that text after a match is kept for
// the next call.
func TestShellReadUntilKeepsTheRest(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6", nil)
	s.shell = newFakeCLI("one> two> ", nil).serve
	conn, err := Connect(t.Context(), useTestServer(t, s, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sh, err := conn.Shell(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	re := regexp.MustCompile(`> `)
	for _, want := range []string{"one> ", "two> "} {
		if got, err := sh.ReadUntil(t.Context(), re); err != nil || got != want {
			t.Fatalf("ReadUntil() = %q, %v; want %q", got, err, want)
		}
	}
}

func TestShellReadUntilTimesOut(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6", nil)
	s.shell = newFakeCLI("no prompt here", nil).serve
	conn, err := Connect(t.Context(), useTestServer(t, s, 300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sh, err := conn.Shell(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	start := time.Now()
	if _, err := sh.ReadUntil(t.Context(), regexp.MustCompile(`\$ \z`)); !errors.Is(err, ErrCommandTimeout) {
		t.Fatalf("ReadUntil() error = %v, want ErrCommandTimeout", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("ReadUntil() took %v", d)
	}
}

func TestShellReadUntilCancelled(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6", nil)
	s.shell = newFakeCLI("", nil).serve
	conn, err := Connect(t.Context(), useTestServer(t, s, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sh, err := conn.Shell(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := sh.ReadUntil(ctx, regexp.MustCompile(`x`)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadUntil() error = %v, want the context's error", err)
	}
}

func TestShellReadUntilSessionEnded(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6", nil)
	s.shell = func(ch gossh.Channel) {
		_, _ = ch.Write([]byte("bye\n"))
		_ = ch.Close()
	}
	conn, err := Connect(t.Context(), useTestServer(t, s, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sh, err := conn.Shell(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	if _, err := sh.ReadUntil(t.Context(), regexp.MustCompile(`\$ \z`)); !errors.Is(err, errShellEnded) {
		t.Fatalf("ReadUntil() error = %v, want errShellEnded", err)
	}
}

func TestConnectChecksServerVersion(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6 Ubuntu", nil)
	cfg := useTestServer(t, s, 5*time.Second)
	refused := errors.New("refused")
	cfg.CheckServerVersion = func(string) error { return refused }
	if _, err := Connect(t.Context(), cfg); !errors.Is(err, refused) {
		t.Fatalf("Connect() error = %v, want the check's error", err)
	}
}
