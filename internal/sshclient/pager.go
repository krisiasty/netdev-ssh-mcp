package sshclient

import (
	"bytes"
	"errors"
	"io"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// pagerQuiet is how long the device must stay silent after a prompt-like
// line before that line is taken for a prompt, until a prompt is confirmed.
// It is long enough to ride out a TCP retransmission or a short stall while
// the device builds its output, and costs a pager that is on one wait per
// command. A variable so that tests can shorten it.
var pagerQuiet = defaultPagerQuiet

const defaultPagerQuiet = time.Second

// outputWithPager runs cmd like session.Output, but keeps stdin open and
// sends p.Key whenever the device stops at p.Prompt. The prompts it answered,
// and what the device wrote to clear them, are removed from the output (see
// pagedOutput), so it reads as if nothing had paged.
//
// A prompt is a line that holds only p.Prompt, at the end of the output
// received so far (see trailingPrompt): the device writes it, with or without
// a line ending, and then waits, so nothing follows it until the key. A line
// of data that holds only the prompt text looks the same when a read happens
// to end after it, but the device keeps writing. So the first prompt is
// answered only once the device has stayed silent for pagerQuiet; if data
// arrives first, the line was data and is kept. That prompt shows the device
// pages, so the later ones are answered as soon as they arrive. Each prompt
// is answered once, even when what follows it arrives in several reads.
//
// What remains: on a device that pages, a data line that ends a read after
// the first prompt is answered and removed, and on one that does not, so is
// a data line the device pauses after for longer than pagerQuiet. The extra
// key does no harm, but the removed line is lost. Turning the device's pager
// off rules out the first case; on FortiOS that is "set output standard"
// under "config system console".
//
// stdin stays open until the session ends, since a prompt may come at any
// time. A command that reads stdin therefore waits for input until the
// command timeout instead of reading end of file at once, as it does without
// a pager. Closing stdin when the device goes quiet would not help: a device
// at "--More--" with stdin closed also waits until the timeout, so a pause in
// the middle of a page would turn into one. Callers must give a pager only
// for commands that never ask for input.
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

	// Read in the background, so that silence can be timed. The reader
	// ends with the first error, which closing the session or its
	// connection always brings. It reuses one buffer: after each read it
	// waits on next until the loop has copied the data out. next holds one
	// signal, so the loop's last one, after the reader has ended, does not
	// block.
	type readResult struct {
		data []byte
		err  error
	}
	reads := make(chan readResult)
	next := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			reads <- readResult{buf[:n], err}
			if err != nil {
				return
			}
			<-next
		}
	}()

	o := pagedOutput{prompt: p.Prompt}
	var (
		readErr   error
		pending   int              // offset of the prompt being timed
		quiet     <-chan time.Time // nil when no prompt is being timed
		confirmed bool             // the device was seen waiting at a prompt
	)
	answer := func(at int) {
		o.answer(at)
		// A failed write means the session is going away, which the next
		// read reports.
		_, _ = io.WriteString(stdin, p.Key)
	}
	for readErr == nil {
		select {
		case r := <-reads:
			readErr = r.err
			if len(r.data) == 0 {
				next <- struct{}{}
				continue
			}
			at := o.add(r.data)
			next <- struct{}{} // r.data is copied; the reader may reuse it
			switch {
			case at < 0:
				quiet = nil
			case confirmed:
				answer(at)
			default:
				// Time the silence from the last byte, which may be more
				// of the prompt's line.
				pending, quiet = at, time.After(pagerQuiet)
			}
		case <-quiet:
			answer(pending)
			confirmed, quiet = true, nil
		}
	}

	err = session.Wait()
	if err == nil && !errors.Is(readErr, io.EOF) {
		err = readErr
	}
	return o.clean(), err
}

// pagedOutput collects the output of a command that pages, and the prompts
// answered in it.
type pagedOutput struct {
	prompt string
	out    []byte
	spans  []promptSpan
}

// promptSpan is a prompt that was answered: out[at:] began with the prompt,
// and out[:end] is what the device had written when the key was sent. What
// lies between the prompt and end is whitespace and line endings the device
// wrote before it waited, so all of it belongs to the prompt.
type promptSpan struct{ at, end int }

// add appends b, read from the device, and returns the offset of the prompt
// the output now ends at, or -1 if it does not end at one or that prompt was
// answered already.
func (o *pagedOutput) add(b []byte) int {
	o.out = append(o.out, b...)
	at := trailingPrompt(o.out, o.prompt)
	if n := len(o.spans); at >= 0 && n > 0 && o.spans[n-1].at == at {
		return -1 // already answered; the rest of it arrived late
	}
	return at
}

// answer records that the prompt at offset at, which add returned, was
// answered, with everything received so far.
func (o *pagedOutput) answer(at int) {
	o.spans = append(o.spans, promptSpan{at: at, end: len(o.out)})
}

// clean removes the answered prompts from the output, in place, and returns
// it. With each prompt go the spaces and tabs before it on its line and what
// the device wrote to clear it after the key (see clearedLen). A prompt that
// nothing follows is kept: a device at its prompt writes at least the next
// line after the key, so a prompt at the very end is data, or the session
// ended while the device waited.
func (o *pagedOutput) clean() []byte {
	out := o.out
	w, kept := 0, 0
	for _, s := range o.spans {
		if s.end >= len(out) || s.at < kept {
			continue
		}
		start := lineStart(out, s.at, kept)
		w += copy(out[w:], out[kept:start])
		kept = s.end + clearedLen(out[s.end:], out[s.at:s.end])
	}
	w += copy(out[w:], out[kept:])
	return out[:w]
}

// lineStart returns where the prompt at out[at:] begins its line, no earlier
// than floor: before the spaces and tabs ahead of it, and before a carriage
// return ahead of those that starts the line. A carriage return after other
// text on the line is kept, so that text does not run into the next line.
func lineStart(out []byte, at, floor int) int {
	i := at
	for i > floor && (out[i-1] == ' ' || out[i-1] == '\t') {
		i--
	}
	if i > floor && out[i-1] == '\r' && (i-1 == floor || out[i-2] == '\n') {
		i--
	}
	return i
}

// trailingPrompt returns the offset of the prompt in out when out ends with a
// line that holds nothing but the prompt, or -1. The line starts at the
// beginning of out or after a carriage return or newline, may hold spaces and
// tabs on either side of the prompt, and may be ended by any number of
// carriage returns and newlines, or not ended at all. Only the tail of out is
// examined, so the cost does not grow with the output.
func trailingPrompt(out []byte, prompt string) int {
	if prompt == "" {
		return -1
	}
	body := bytes.TrimRight(out, " \t\r\n")
	if !bytes.HasSuffix(body, []byte(prompt)) {
		return -1
	}
	at := len(body) - len(prompt)
	before := bytes.TrimRight(body[:at], " \t")
	if n := len(before); n > 0 && before[n-1] != '\r' && before[n-1] != '\n' {
		return -1 // other text on the line before the prompt
	}
	return at
}

// clearedLen returns how much of after, what the device wrote once it had
// the key for a prompt, clears that prompt rather than continuing the output.
// prompt is the prompt and what the device wrote with it before it waited.
//
// When the device ended the prompt's line itself, it has nothing left to
// clear. Otherwise it either ends the line now, with a newline, or erases the
// prompt and writes the next line in its place. Devices erase by returning
// the cursor and overwriting the prompt with spaces ("\r         \r", which is
// what FortiOS sends), with backspaces, or with an ANSI erase-line. Spaces
// count as part of the erase only when a carriage return, backspace or
// erase-line follows them, so the next line keeps its indentation. A newline
// right after a lone carriage return completes a CRLF line ending; after a
// longer erase it ends the next line, which is blank, and is kept.
func clearedLen(after, prompt []byte) int {
	if bytes.HasSuffix(prompt, []byte("\n")) {
		return 0
	}
	i := 0
	for {
		j := i + len(after[i:]) - len(bytes.TrimLeft(after[i:], " \t"))
		switch {
		case j < len(after) && (after[j] == '\r' || after[j] == '\b'):
			i = j + 1
			continue
		case bytes.HasPrefix(after[j:], []byte("\x1b[K")):
			i = j + 3
			continue
		}
		break
	}
	if i < len(after) && after[i] == '\n' && (i == 0 || i == 1 && after[0] == '\r') {
		return i + 1
	}
	return i
}
