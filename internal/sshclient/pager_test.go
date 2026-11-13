package sshclient

import (
	"fmt"
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

// setPagerQuiet sets pagerQuiet for the rest of the test.
func setPagerQuiet(t *testing.T, d time.Duration) {
	t.Helper()
	orig := pagerQuiet
	t.Cleanup(func() { pagerQuiet = orig })
	pagerQuiet = d
}

// runPaged runs a command on d. Unless the test has set it, pagerQuiet is
// shortened, but stays well above the 10ms between the device's chunks.
func runPaged(t *testing.T, d *pagingDevice, pager *Pager) (string, error) {
	t.Helper()
	if pagerQuiet == defaultPagerQuiet {
		setPagerQuiet(t, 100*time.Millisecond)
	}
	addr := startSSHServer(t, d.exec, newSigner(t, "ed25519"))
	cfg := useTestServer(t, &testServer{addr: addr}, 10*time.Second)
	cfg.Pager = pager
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
// line, or on a line of its own in the middle of a read, is data: no key is
// sent and the output is unchanged. A line that holds only the prompt and
// ends a read is taken for a prompt (see TestPagedOutput).
func TestRunCommandLeavesPromptTextInData(t *testing.T) {
	data := "set description \"--More--\"\n--More--\n  --More--  \nend\n"
	d := newPagingDevice(
		deviceChunk{text: "set description \"--More--"},
		deviceChunk{text: "\"\n--More--\n  --More--  \nend\n"},
	)
	out, err := runPaged(t, d, fortiPager)
	if err != nil || out != data {
		t.Fatalf("RunCommand() = %q, %v; want %q", out, err, data)
	}
	checkNoExtraKeys(t, d)
}

// TestRunCommandKeepsPromptLineFromDeviceThatDoesNotPage replays a device
// with its pager off whose data holds a line with only the prompt text, at
// the end of a read: the device keeps writing, so no key is sent and the
// line is kept.
func TestRunCommandKeepsPromptLineFromDeviceThatDoesNotPage(t *testing.T) {
	for name, chunks := range map[string][]deviceChunk{
		"with newline":    {{text: "set buffer \"x\n--More--\n"}, {text: "y\"\nend\n"}},
		"without newline": {{text: "set buffer \"x\n--More--"}, {text: "\ny\"\nend\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			d := newPagingDevice(chunks...)
			out, err := runPaged(t, d, fortiPager)
			want := "set buffer \"x\n--More--\ny\"\nend\n"
			if err != nil || out != want {
				t.Fatalf("RunCommand() = %q, %v; want %q", out, err, want)
			}
			checkNoExtraKeys(t, d)
		})
	}
}

// TestRunCommandWaitsOnlyForFirstPrompt checks that the device must be quiet
// at the first prompt before it is answered, and that once it has waited
// there, the later prompts are answered without waiting.
func TestRunCommandWaitsOnlyForFirstPrompt(t *testing.T) {
	const quiet = 300 * time.Millisecond
	setPagerQuiet(t, quiet)
	chunks := []deviceChunk{{text: "line 0\n--More-- "}}
	want := "line 0\n"
	for i := 1; i <= 6; i++ {
		chunks = append(chunks, deviceChunk{wait: true, text: fmt.Sprintf("\r         \rline %d\n--More-- ", i)})
		want += fmt.Sprintf("line %d\n", i)
	}
	chunks = append(chunks, deviceChunk{wait: true, text: "\r         \rend\n"})
	want += "end\n"
	d := newPagingDevice(chunks...)
	start := time.Now()
	out, err := runPaged(t, d, fortiPager)
	elapsed := time.Since(start)
	if err != nil || out != want {
		t.Fatalf("RunCommand() = %q, %v; want %q", out, err, want)
	}
	// Seven prompts: waiting at each would take 7 × quiet.
	if elapsed < quiet || elapsed > 3*quiet {
		t.Fatalf("RunCommand() took %v, want one quiet period of %v and little more", elapsed, quiet)
	}
	checkNoExtraKeys(t, d)
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
	cfg := useTestServer(t, &testServer{addr: addr}, 5*time.Second)
	out, err := RunCommand(t.Context(), cfg, "show version")
	if err != nil || out != "stdin closed\n" {
		t.Fatalf("RunCommand() = %q, %v; want stdin closed", out, err)
	}
}

// TestPagedOutput feeds what a device writes, one read per chunk, and answers
// wherever a chunk ends at a prompt, as if the device then went quiet, and
// checks the cleaned output.
func TestPagedOutput(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   string
	}{
		{"FortiOS carriage return and spaces", []string{"a\n--More-- ", "\r           \r        set x\n"}, "a\n        set x\n"},
		{"backspaces", []string{"a\n--More--", "\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\bb\n"}, "a\nb\n"},
		{"ANSI erase line", []string{"a\n--More--", "\r\x1b[K  b\n"}, "a\n  b\n"},
		{"leading carriage return", []string{"a\n\r--More-- ", "\r        \rb\n"}, "a\nb\n"},
		{"carriage return after text", []string{"a\r--More--", "\r   \rb\n"}, "a\rb\n"},
		{"first line", []string{"--More-- ", "\r     \rb\n"}, "b\n"},
		{"several prompts", []string{"a\n--More-- ", "\r   \rb\n--More-- ", "\r   \r  c\n"}, "a\nb\n  c\n"},
		{"erase in a read of its own", []string{"a\n--More-- ", "\r     \r", "b\n"}, "a\nb\n"},
		{"split prompt", []string{"a\n--Mo", "re-- ", "\r     \rb\n"}, "a\nb\n"},
		{"erase then a blank line", []string{"a\n--More-- ", "\r     \r\nb\n"}, "a\n\nb\n"},
		{"prompt ended with a newline", []string{"a\n  --More--  \n", "b\n"}, "a\nb\n"},
		{"prompt ended with CRLF", []string{"a\r\n--More--\r\n", "b\r\n"}, "a\r\nb\r\n"},
		{"CRLF split by the key", []string{"a\r\n--More--\r", "\nb\r\n"}, "a\r\nb\r\n"},
		{"newline after the key", []string{"a\n--More--", "\nb\n"}, "a\nb\n"},
		{"carriage return before the wait", []string{"a\n--More--\r", "b\n"}, "a\nb\n"},
		{"two prompts in a row", []string{"a\n--More--\n", "--More--\n", "b\n"}, "a\nb\n"},
		// A real prompt is never last: after the key the device writes more.
		{"prompt at the end is kept", []string{"a\n--More-- "}, "a\n--More-- "},
		{"prompt with newline at the end is kept", []string{"a\n--More--\n"}, "a\n--More--\n"},
		{"prompt-only line inside a read", []string{"a\n--More--\nb\n"}, "a\n--More--\nb\n"},
		{"prompt-only line with CRLF inside a read", []string{"a\r\n--More--\r\nb\r\n"}, "a\r\n--More--\r\nb\r\n"},
		{"prompt text in a line", []string{"set description \"--More--", "\" \r\n"}, "set description \"--More--\" \r\n"},
		{"prompt then text on the line", []string{"--More-- x\n", "y\n"}, "--More-- x\ny\n"},
		// The documented risk: a line of data that holds only the prompt,
		// after which the device pauses, cannot be told from a prompt, and
		// is removed.
		{"data line the device pauses after", []string{"set buffer \"x\n--More--\n", "y\"\n"}, "set buffer \"x\ny\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := pagedOutput{prompt: "--More--"}
			for _, c := range tt.chunks {
				if at := o.add([]byte(c)); at >= 0 {
					o.answer(at)
				}
			}
			if got := string(o.clean()); got != tt.want {
				t.Fatalf("clean() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPagedOutputAnswersOnce checks which reads end at a prompt that has not
// been answered.
func TestPagedOutputAnswersOnce(t *testing.T) {
	o := pagedOutput{prompt: "--More--"}
	for _, step := range []struct {
		chunk  string
		answer bool
	}{
		{"a\n--Mo", false},
		{"re--", true},
		{" ", false},
		{"\r     \r", false},
		{"b\n--More--\n", true},
		{"\n", false},
		{"c\n", false},
	} {
		at := o.add([]byte(step.chunk))
		if got := at >= 0; got != step.answer {
			t.Fatalf("add(%q) = %d, want a prompt: %v", step.chunk, at, step.answer)
		}
		if at >= 0 {
			o.answer(at)
		}
	}
}

func TestTrailingPrompt(t *testing.T) {
	for out, want := range map[string]int{
		"--More--":                   0,
		"--More-- ":                  0,
		" \r--More--\t":              2,
		"a\n--More--":                2,
		"a\n  --More--  ":            4,
		"a\n--More--\n":              2,
		"a\n--More--\r\n":            2,
		"a\n--More--\r":              2,
		"a\n--More-- \n\n":           2,
		"a\r--More--":                2,
		"a\n--More-- \r     \r":      2, // erased, but nothing new yet
		"--More":                     -1,
		"x --More--":                 -1,
		"x --More--\n":               -1,
		"--More-- x":                 -1,
		"--More--\nx":                -1,
		"--More-- \r     \rb\n":      -1,
		"":                           -1,
		strings.Repeat(" ", 3):       -1,
		strings.Repeat("\n", 3):      -1,
		"set description \"--More--": -1,
	} {
		if got := trailingPrompt([]byte(out), "--More--"); got != want {
			t.Errorf("trailingPrompt(%q) = %d, want %d", out, got, want)
		}
	}
	if got := trailingPrompt([]byte(""), ""); got != -1 {
		t.Errorf("trailingPrompt with an empty prompt = %d, want -1", got)
	}
}

// TestRunCommandAnswersPromptWithLineEnding checks that a prompt the device
// ends with a line ending before it waits is answered, once, even when the
// line ending arrives in a read of its own, and is removed from the output.
func TestRunCommandAnswersPromptWithLineEnding(t *testing.T) {
	for name, chunks := range map[string][]deviceChunk{
		"newline":               {{text: "line 1\n--More--\n"}, {wait: true, text: "line 2\n"}},
		"CRLF":                  {{text: "line 1\r\n--More--\r\n"}, {wait: true, text: "line 2\r\n"}},
		"carriage return":       {{text: "line 1\n--More--\r"}, {wait: true, text: "line 2\n"}},
		"line ending split off": {{text: "line 1\n--More--"}, {text: "\n"}, {wait: true, text: "line 2\n"}},
		"spaces and newline":    {{text: "line 1\n  --More--  \n"}, {wait: true, text: "line 2\n"}},
		"two prompts in a row":  {{text: "line 1\n--More--\n"}, {wait: true, text: "--More--\n"}, {wait: true, text: "line 2\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			d := newPagingDevice(chunks...)
			out, err := runPaged(t, d, fortiPager)
			if err != nil {
				t.Fatalf("RunCommand() error = %v", err)
			}
			want := "line 1\nline 2\n"
			if name == "CRLF" {
				want = "line 1\r\nline 2\r\n"
			}
			if out != want {
				t.Fatalf("RunCommand() = %q, want %q", out, want)
			}
			checkNoExtraKeys(t, d)
		})
	}
}
