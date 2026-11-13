package sshclient

import (
	"slices"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// TestRunCommandRequestsTerminal checks that cfg.Terminal is requested
// before the command, with echo and output processing off.
func TestRunCommandRequestsTerminal(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-pOn0cZbl", map[string]testReply{"show full-configuration": {output: "config\nend\n"}})
	cfg := useTestServer(t, s, 5*time.Second)
	cfg.Terminal = &Terminal{Rows: 65535, Cols: 512}

	out, err := RunCommand(t.Context(), cfg, "show full-configuration")
	if err != nil || out != "config\nend\n" {
		t.Fatalf("RunCommand() = %q, %v", out, err)
	}
	reqs, ptys := s.seen()
	if !slices.Equal(reqs, []string{"pty-req", "exec"}) {
		t.Fatalf("channel requests = %v, want pty-req before exec", reqs)
	}
	if p := ptys[0]; p.Rows != 65535 || p.Cols != 512 {
		t.Fatalf("pty-req = %d rows, %d cols; want 65535 by 512", p.Rows, p.Cols)
	}
	modes := ptys[0].modes()
	for _, op := range []uint8{gossh.ECHO, gossh.OPOST, gossh.ONLCR} {
		if v, ok := modes[op]; !ok || v != 0 {
			t.Errorf("terminal mode %d = %d (set: %v), want 0", op, v, ok)
		}
	}
}

func TestRunCommandWithoutTerminal(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-OpenSSH_9.6", map[string]testReply{"show version": {output: "ok\n"}})
	cfg := useTestServer(t, s, 5*time.Second)

	if out, err := RunCommand(t.Context(), cfg, "show version"); err != nil || out != "ok\n" {
		t.Fatalf("RunCommand() = %q, %v", out, err)
	}
	if reqs, _ := s.seen(); !slices.Equal(reqs, []string{"exec"}) {
		t.Fatalf("channel requests = %v, want exec alone", reqs)
	}
}

// TestRunCommandRunsWhenTerminalRefused checks that a server refusing the
// terminal still gets the command.
func TestRunCommandRunsWhenTerminalRefused(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-pOn0cZbl", map[string]testReply{"get system status": {output: "Version: FortiGate\n"}})
	s.refusePTY = true
	cfg := useTestServer(t, s, 5*time.Second)
	cfg.Terminal = &Terminal{Rows: 65535, Cols: 512}

	if out, err := RunCommand(t.Context(), cfg, "get system status"); err != nil || out != "Version: FortiGate\n" {
		t.Fatalf("RunCommand() = %q, %v", out, err)
	}
	if reqs, _ := s.seen(); !slices.Equal(reqs, []string{"pty-req", "exec"}) {
		t.Fatalf("channel requests = %v, want pty-req, then exec", reqs)
	}
}

// TestProbeRequestsChosenTerminal checks that Probe requests the terminal
// choose returns, not cfg.Terminal.
func TestProbeRequestsChosenTerminal(t *testing.T) {
	s := startTestServer(t, "SSH-2.0-pOn0cZbl", map[string]testReply{"get system status": {output: "Version: FortiGate\n"}})
	cfg := useTestServer(t, s, 5*time.Second)
	cfg.Terminal = &Terminal{Rows: 1, Cols: 1}

	_, err := Probe(t.Context(), cfg, func(string) (string, *Terminal, error) {
		return "get system status", &Terminal{Rows: 65535, Cols: 512}, nil
	})
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if _, ptys := s.seen(); len(ptys) != 1 || ptys[0].Rows != 65535 {
		t.Fatalf("pty requests = %+v, want one of 65535 rows", ptys)
	}
}
