package sshclient

import (
	"bytes"
	"errors"
	"io"

	gossh "golang.org/x/crypto/ssh"
)

// outputWithPager runs cmd like session.Output, but keeps stdin open and
// sends p.Key whenever the device stops at p.Prompt. The prompts, and the
// sequences the device writes to erase them, are removed from the output
// (see removePagerPrompts), so it reads as if nothing had paged.
//
// A prompt is answered when the output received so far ends with a line that
// holds nothing but the prompt: the device writes it without a newline and
// then waits. Each such line is answered once, even when it arrives in
// several reads. A data line that holds only the prompt text and happens to
// end a read is answered too, since it looks the same; the device then has a
// key in hand at its next prompt and does not wait, which loses nothing,
// because every byte it writes is read.
func outputWithPager(session *gossh.Session, cmd string, p *Pager) ([]byte, error) {
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := session.Start(cmd); err != nil {
		return nil, err
	}

	var (
		out       []byte
		lineStart int // offset in out of the last, unterminated line
		answered  = -1
		readErr   error
	)
	buf := make([]byte, 32*1024)
	for readErr == nil {
		var n int
		n, readErr = stdout.Read(buf)
		if n == 0 {
			continue
		}
		out = append(out, buf[:n]...)
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			lineStart = len(out) - n + i + 1
		}
		if answered != lineStart && isPagerPrompt(out[lineStart:], p.Prompt) {
			answered = lineStart
			// A failed write means the session is going away, which the
			// next read reports.
			_, _ = io.WriteString(stdin, p.Key)
		}
	}

	err = session.Wait()
	if err == nil && !errors.Is(readErr, io.EOF) {
		err = readErr
	}
	return removePagerPrompts(out, p.Prompt), err
}

// pagerSpace is what may surround a prompt on its line.
const pagerSpace = " \t\r"

// isPagerPrompt reports whether line is the prompt and nothing else.
func isPagerPrompt(line []byte, prompt string) bool {
	return prompt != "" && string(bytes.Trim(line, pagerSpace)) == prompt
}

// removePagerPrompts removes every pager prompt from out, together with the
// erase sequence the device wrote after it: a prompt at the start of a line
// that an erase sequence follows, or that ends the output. The next line,
// which the device writes in the prompt's place, is kept whole. The prompt
// text in any other position, such as a line of data that holds only the
// prompt and ends with a newline, is left alone.
func removePagerPrompts(out []byte, prompt string) []byte {
	var clean []byte
	removed := false
	i, kept := 0, 0
	for i < len(out) {
		if n := promptEnd(out[i:], prompt); n > 0 {
			clean = append(clean, out[kept:i]...)
			removed = true
			i += n
			kept = i
		}
		nl := bytes.IndexByte(out[i:], '\n')
		if nl < 0 {
			break
		}
		i += nl + 1
	}
	if !removed {
		return out
	}
	return append(clean, out[kept:]...)
}

// promptEnd returns the length of the prompt at the start of b and of the
// erase sequence after it, or 0 if b does not start with a prompt that was
// erased or ends the output. Devices erase a prompt by returning the cursor
// and overwriting it with spaces ("\r         \r", which is what FortiOS
// sends), with backspaces, or with an ANSI erase-line, and then write the
// next line in its place. Spaces count as part of the erase only when a
// carriage return, backspace or erase-line follows them, so the next line
// keeps its indentation.
func promptEnd(b []byte, prompt string) int {
	if prompt == "" {
		return 0
	}
	i := len(b) - len(bytes.TrimLeft(b, pagerSpace))
	if !bytes.HasPrefix(b[i:], []byte(prompt)) {
		return 0
	}
	i += len(prompt)
	if len(bytes.TrimLeft(b[i:], pagerSpace)) == 0 {
		return len(b) // the output ended at the prompt
	}
	erased := false
	for {
		j := i + len(b[i:]) - len(bytes.TrimLeft(b[i:], " \t"))
		rest := b[j:]
		switch {
		case bytes.HasPrefix(rest, []byte("\r\n")):
			// A line ending, not an erase.
		case len(rest) > 0 && (rest[0] == '\r' || rest[0] == '\b'):
			i, erased = j+1, true
			continue
		case bytes.HasPrefix(rest, []byte("\x1b[K")):
			i, erased = j+3, true
			continue
		}
		if !erased {
			return 0 // followed by text or a line ending: data
		}
		return i
	}
}
