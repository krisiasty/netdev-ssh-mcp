package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Conn is an open SSH connection to a device, on which several sessions can
// run one after another: a shell to read something interactive, then a
// command over exec, without logging in twice. It is not safe for
// concurrent use.
type Conn struct {
	client *gossh.Client
	addr   string
	cfg    ConnConfig
}

// Connect dials cfg.Host and authenticates, as RunCommand does. If
// cfg.CheckServerVersion is set, it is called with the server's
// identification string before anything runs, and an error closes the
// connection. The caller must Close the Conn.
func Connect(ctx context.Context, cfg ConnConfig) (*Conn, error) {
	client, addr, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.CheckServerVersion != nil {
		if err := cfg.CheckServerVersion(string(client.ServerVersion())); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("SSH server %s: %w", addr, err)
		}
	}
	return &Conn{client: client, addr: addr, cfg: cfg}, nil
}

// Close closes the connection and any session still open on it.
func (c *Conn) Close() error {
	return c.client.Close()
}

// Run runs cmd in a new exec session, requesting cfg.Terminal first if it
// is set, and returns its stdout. The command timeout and cancellation work
// as in RunCommand, and a timeout or cancellation closes the connection. On a
// non-zero exit status it returns the output together with a *CommandError.
func (c *Conn) Run(ctx context.Context, cmd string) (string, error) {
	return runOnClient(ctx, c.client, c.addr, cmd, c.cfg.Terminal, commandTimeoutFor(c.cfg))
}

// maxShellBuffer bounds what a Shell holds while it waits for a pattern, so a
// device that keeps writing cannot exhaust memory before the time limit.
const maxShellBuffer = 1 << 20

// Shell is an interactive shell session on a Conn, for what a device's CLI
// offers only to a person at a terminal, such as FortiOS listing the names
// that can follow a command when "?" is typed. Text is typed with Send and
// read with ReadUntil. The session, from the request that opens it, is
// limited to the configured command timeout; ConnConfig.CommandTimeout,
// which lets slow commands such as ping run longer, does not apply, since a
// shell only waits for the device's prompts. Close discards anything typed
// but not entered.
type Shell struct {
	session  *gossh.Session
	stdin    io.Writer
	reads    chan []byte
	done     chan struct{}
	close    sync.Once
	addr     string
	timeout  time.Duration
	deadline time.Time
	buf      []byte
}

// Shell starts an interactive shell in a new session, requesting term first
// if it is not nil. A device can stall on any of these requests, so as in
// Run, the connection is closed if they take longer than the time limit or
// ctx is cancelled first. The caller must Close the Shell.
func (c *Conn) Shell(ctx context.Context, term *Terminal) (*Shell, error) {
	timeout := commandTimeout()
	deadline := time.Now().Add(timeout)
	stop := closeOnLimit(ctx, timeout, func() { _ = c.client.Close() })
	session, stdout, stdin, err := c.startShell(term)
	if reason := stop(); reason != nil {
		if err == nil {
			_ = session.Close()
		}
		if errors.Is(reason, errLimitReached) {
			return nil, fmt.Errorf("start a shell on %s: %w (%s)", c.addr, ErrCommandTimeout, timeout)
		}
		return nil, fmt.Errorf("start a shell on %s: %w", c.addr, reason)
	}
	if err != nil {
		return nil, err
	}
	s := &Shell{
		session:  session,
		stdin:    stdin,
		reads:    make(chan []byte),
		done:     make(chan struct{}),
		addr:     c.addr,
		timeout:  timeout,
		deadline: deadline,
	}
	go s.read(stdout)
	return s, nil
}

// startShell opens a session, requests term if it is not nil, and starts a
// shell in it. On error the session is closed.
func (c *Conn) startShell(term *Terminal) (*gossh.Session, io.Reader, io.Writer, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new session: %w", err)
	}
	if term != nil {
		requestTerminal(session, term)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}
	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, nil, nil, fmt.Errorf("start a shell on %s: %w", c.addr, err)
	}
	return session, stdout, stdin, nil
}

// read passes what the device writes to ReadUntil until the session ends or
// the Shell is closed.
func (s *Shell) read(stdout io.Reader) {
	defer close(s.reads)
	buf := make([]byte, 32*1024)
	for {
		n, err := stdout.Read(buf)
		if n > 0 {
			select {
			case s.reads <- bytes.Clone(buf[:n]):
			case <-s.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Send types text into the shell. Nothing is entered unless text holds a
// carriage return.
func (s *Shell) Send(text string) error {
	if _, err := io.WriteString(s.stdin, text); err != nil {
		return fmt.Errorf("write to the shell on %s: %w", s.addr, err)
	}
	return nil
}

// errShellEnded is returned by ReadUntil when the session ends first.
var errShellEnded = errors.New("the shell session ended")

// ReadUntil reads until what arrived since the previous call matches re, and
// returns it up to the end of the match; the rest is kept for the next call.
// It fails if the session ends first, if the shell's time limit passes
// (ErrCommandTimeout), or if ctx is cancelled. What the device wrote is
// untrusted: callers must match it, not obey it.
func (s *Shell) ReadUntil(ctx context.Context, re *regexp.Regexp) (string, error) {
	timer := time.NewTimer(time.Until(s.deadline))
	defer timer.Stop()
	for {
		if loc := re.FindIndex(s.buf); loc != nil {
			out := string(s.buf[:loc[1]])
			s.buf = s.buf[loc[1]:]
			return out, nil
		}
		if len(s.buf) > maxShellBuffer {
			return "", fmt.Errorf("shell on %s: more than %d bytes without the expected output", s.addr, maxShellBuffer)
		}
		select {
		case b, ok := <-s.reads:
			if !ok {
				return "", fmt.Errorf("shell on %s: %w before the expected output", s.addr, errShellEnded)
			}
			s.buf = append(s.buf, b...)
		case <-timer.C:
			return "", fmt.Errorf("shell on %s: %w (%s)", s.addr, ErrCommandTimeout, s.timeout)
		case <-ctx.Done():
			return "", fmt.Errorf("shell on %s: %w", s.addr, ctx.Err())
		}
	}
}

// Close ends the session without sending anything more, so text typed but
// not entered is discarded rather than run.
func (s *Shell) Close() error {
	var err error
	s.close.Do(func() {
		close(s.done)
		err = s.session.Close()
		if errors.Is(err, io.EOF) {
			err = nil // already closed by the server
		}
	})
	return err
}
