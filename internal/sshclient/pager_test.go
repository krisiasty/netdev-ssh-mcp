package sshclient

import (
	"io"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

var fortiPager = &Pager{Prompt: "--More--", Key: " "}

// pagingDevice is an exec handler that writes its chunks in order and, before
// each chunk marked wait, waits for a key on stdin, like a FortiGate at
// "--More--". keys receives every byte the client sent on stdin; extra
// counts the ones left over when the command finished.
type pagingDevice struct {
	chunks []deviceChunk
	keys   chan byte
	extra  chan int
}

type deviceChunk struct {
	text string
	wait bool // wait for a key before writing text
}

func newPagingDevice(chunks ...deviceChunk) *pagingDevice {
	return &pagingDevice{chunks: chunks, keys: make(chan byte, 64), extra: make(chan int, 1)}
}

func (d *pagingDevice) exec(ch gossh.Channel) {
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := ch.Read(buf); err != nil {
				return
			}
			d.keys <- buf[0]
		}
	}()
	for _, c := range d.chunks {
		if c.wait {
			select {
			case <-d.keys:
			case <-time.After(5 * time.Second):
				_, _ = ch.Write([]byte("\nDEVICE: no key at the prompt\n"))
				_ = ch.Close()
				return
			}
		}
		_, _ = ch.Write([]byte(c.text))
		time.Sleep(10 * time.Millisecond) // deliver chunks in separate reads
	}
	time.Sleep(50 * time.Millisecond) // let a stray key arrive
	d.extra <- len(d.keys)
	_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
	_ = ch.Close()
}

func runPaged(t *testing.T, d *pagingDevice, pager *Pager) (string, error) {
	t.Helper()
	addr := startSSHServer(t, d.exec, newSigner(t, "ed25519"))
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "test")
	if err := Configure(Options{InsecureSkipHostKeyCheck: true, CommandTimeout: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	cfg := ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u", Pager: pager}
	return RunCommand(t.Context(), cfg, "show full-configuration")
}

func checkNoExtraKeys(t *testing.T, d *pagingDevice) {
	t.Helper()
	select {
	case n := <-d.extra:
		if n != 0 {
			t.Fatalf("device got %d keys it did not ask for", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("device did not finish")
	}
}

// TestRunCommandAnswersPager replays the byte sequence a FortiGate sends:
// "--More-- " without a newline, then, after the key, "\r", spaces and "\r"
// to erase it, and the next line with its indentation.
func TestRunCommandAnswersPager(t *testing.T) {
	d := newPagingDevice(
		deviceChunk{text: "config system interface\n    edit \"ha\"\n        set fortilink disable\n--More-- "},
		deviceChunk{wait: true, text: "\r           \r        set management-ip 0.0.0.0 0.0.0.0\n--More-- "},
		deviceChunk{wait: true, text: "\r           \r    next\nend\n"},
	)
	out, err := runPaged(t, d, fortiPager)
	if err != nil {
		t.Fatalf("RunCommand() error = %v", err)
	}
	want := "config system interface\n    edit \"ha\"\n        set fortilink disable\n        set management-ip 0.0.0.0 0.0.0.0\n    next\nend\n"
	if out != want {
		t.Fatalf("RunCommand() = %q, want %q", out, want)
	}
	checkNoExtraKeys(t, d)
}

// TestRunCommandAnswersSplitPromptOnce checks that a prompt arriving in
// several reads gets one key: a second one would skip a page.
func TestRunCommandAnswersSplitPromptOnce(t *testing.T) {
	d := newPagingDevice(
		deviceChunk{text: "line 1\n--Mo"},
		deviceChunk{text: "re--"},
		deviceChunk{text: " "},
		deviceChunk{wait: true, text: "\r         \rline 2\n"},
	)
	out, err := runPaged(t, d, fortiPager)
	if err != nil || out != "line 1\nline 2\n" {
		t.Fatalf("RunCommand() = %q, %v; want both lines without the prompt", out, err)
	}
	checkNoExtraKeys(t, d)
}

// TestRunCommandLeavesPromptTextInData checks that the prompt text inside a
// line, or on a line of its own that ends with a newline, is data: no key is
// sent and the output is unchanged.
func TestRunCommandLeavesPromptTextInData(t *testing.T) {
	data := "set description \"--More--\"\n--More--\n  --More--  \nend\n"
	d := newPagingDevice(
		deviceChunk{text: "set description \"--More--"},
		deviceChunk{text: "\"\n--More--"},
		deviceChunk{text: "\n  --More--  \nend\n"},
	)
	out, err := runPaged(t, d, fortiPager)
	if err != nil || out != data {
		t.Fatalf("RunCommand() = %q, %v; want %q", out, err, data)
	}
	// "--More--" at the end of the second chunk looks like a device at its
	// prompt, so it may be answered. The newline that follows shows it was
	// data, and it is kept.
	select {
	case n := <-d.extra:
		if n > 1 {
			t.Fatalf("device got %d keys, want at most one", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("device did not finish")
	}
}

func TestRunCommandWithoutPagerClosesStdin(t *testing.T) {
	addr := startSSHServer(t, func(ch gossh.Channel) {
		// Without a pager stdin must reach EOF, as before.
		_, err := io.ReadAll(ch)
		reply := "stdin closed\n"
		if err != nil {
			reply = "stdin error\n"
		}
		_, _ = ch.Write([]byte(reply))
		_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}, newSigner(t, "ed25519"))
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "test")
	if err := Configure(Options{InsecureSkipHostKeyCheck: true, CommandTimeout: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	out, err := RunCommand(t.Context(), ConnConfig{Host: addr.IP.String(), Port: addr.Port, Username: "u"}, "show version")
	if err != nil || out != "stdin closed\n" {
		t.Fatalf("RunCommand() = %q, %v; want stdin closed", out, err)
	}
}

func TestRemovePagerPrompts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"FortiOS carriage return and spaces", "a\n--More-- \r           \r        set x\n", "a\n        set x\n"},
		{"backspaces", "a\n--More--\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\bb\n", "a\nb\n"},
		{"ANSI erase line", "a\n--More--\r\x1b[K  b\n", "a\n  b\n"},
		{"prompt left at the end", "a\n--More-- ", "a\n"},
		{"leading carriage return", "a\n\r--More-- \r        \rb\n", "a\nb\n"},
		{"first line", "--More-- \r     \rb\n", "b\n"},
		{"several prompts", "a\n--More-- \r   \rb\n--More-- \r   \r  c\n", "a\nb\n  c\n"},
		{"data line with newline", "a\n--More--\nb\n", "a\n--More--\nb\n"},
		{"data line with CRLF", "a\r\n--More--\r\nb\r\n", "a\r\n--More--\r\nb\r\n"},
		{"data in a line", "set description \"--More--\" \r\n", "set description \"--More--\" \r\n"},
		{"prompt then text on the line", "--More-- x\n", "--More-- x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(removePagerPrompts([]byte(tt.in), "--More--"))
			if got != tt.want {
				t.Fatalf("removePagerPrompts(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsPagerPrompt(t *testing.T) {
	for line, want := range map[string]bool{
		"--More--":             true,
		"--More-- ":            true,
		" \r--More--\t":        true,
		"--More":               false,
		"x --More--":           false,
		"--More-- x":           false,
		"":                     false,
		strings.Repeat(" ", 3): false,
	} {
		if got := isPagerPrompt([]byte(line), "--More--"); got != want {
			t.Errorf("isPagerPrompt(%q) = %v, want %v", line, got, want)
		}
	}
	if isPagerPrompt([]byte(""), "") {
		t.Error("isPagerPrompt with an empty prompt matched")
	}
}
