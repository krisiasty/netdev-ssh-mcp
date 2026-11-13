package sshclient

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// stallStage is where startStallingServer stops answering.
type stallStage int

const (
	stallHandshake stallStage = iota // accepts TCP, never speaks SSH
	stallSession                     // authenticates, never answers the session request
	stallCommand                     // accepts the command, never replies
)

func (s stallStage) String() string {
	return [...]string{"handshake", "session", "command"}[s]
}

// stallingServer is an SSH server that stops answering at one stage.
type stallingServer struct {
	addr *net.TCPAddr
	// reached receives each time a client gets to the stalled stage.
	reached chan struct{}
	// closed receives each time a client connection is closed.
	closed chan struct{}
	// accepted counts the TCP connections accepted.
	accepted atomic.Int32

	mu    sync.Mutex
	execs []string // commands received in exec requests
}

func (s *stallingServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.execs)
}

// startStallingServer runs an SSH server that stops answering at stage. It
// offers public key auth, which it always refuses, so that a client with an
// SSH agent asks the agent first, and accepts any password.
func startStallingServer(t *testing.T, stage stallStage) *stallingServer {
	t.Helper()
	cfg := &gossh.ServerConfig{
		PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { return nil, nil },
		PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return nil, errors.New("refused")
		},
	}
	cfg.AddHostKey(newSigner(t, "ed25519"))

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &stallingServer{
		addr:    ln.Addr().(*net.TCPAddr),
		reached: make(chan struct{}, 16),
		closed:  make(chan struct{}, 16),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.accepted.Add(1)
			go func() {
				defer func() { srv.closed <- struct{}{} }()
				defer func() { _ = conn.Close() }()
				if stage == stallHandshake {
					// Signal once the client sends its version line. It does
					// that from inside the handshake, after its time limit
					// and cancellation watch are set, so a test that
					// cancels now interrupts a handshake in progress.
					if _, err := conn.Read(make([]byte, 1)); err == nil {
						srv.reached <- struct{}{}
					}
					_, _ = io.Copy(io.Discard, conn) // returns when the client closes
					return
				}
				sconn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go gossh.DiscardRequests(reqs)
				go func() {
					for nc := range chans {
						if stage == stallSession {
							srv.reached <- struct{}{}
							continue // neither accept nor reject
						}
						ch, chReqs, err := nc.Accept()
						if err != nil {
							continue
						}
						go func() {
							defer func() { _ = ch.Close() }()
							for req := range chReqs {
								_ = req.Reply(req.Type == "exec", nil) // and never send output
								if req.Type == "exec" {
									var payload struct{ Command string }
									_ = gossh.Unmarshal(req.Payload, &payload)
									srv.mu.Lock()
									srv.execs = append(srv.execs, payload.Command)
									srv.mu.Unlock()
									srv.reached <- struct{}{}
								}
							}
						}()
					}
				}()
				_ = sconn.Wait() // returns when the client closes
			}()
		}
	}()
	return srv
}

func (s *stallingServer) connConfig() ConnConfig {
	return ConnConfig{Host: s.addr.IP.String(), Port: s.addr.Port, Username: "u", CommandTimeout: time.Hour}
}

// waitFor fails the test unless ch receives within 5 seconds.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// usePasswordAuth points the client at a test server with password auth and
// no host key checks, restoring the previous options afterwards.
func usePasswordAuth(t *testing.T) {
	t.Helper()
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "test")
	if err := Configure(Options{InsecureSkipHostKeyCheck: true}); err != nil {
		t.Fatal(err)
	}
}

// checkCancelled starts call, cancels its context once reached receives (the
// call has got to the stage under test), then checks that call returns
// context.Canceled promptly, not a timeout error, and that closed receives
// (the connection was closed).
func checkCancelled(t *testing.T, reached, closed <-chan struct{}, call func(ctx context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- call(ctx) }()
	waitFor(t, reached, "the call to reach the stage under test")
	cancelled := time.Now()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if errors.Is(err, ErrCommandTimeout) || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("error = %v, want a cancellation, not a timeout", err)
		}
		if elapsed := time.Since(cancelled); elapsed > 3*time.Second {
			t.Fatalf("returned %v after cancellation, want it promptly", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running 5s after cancellation")
	}
	waitFor(t, closed, "the connection to close")
}

func TestRunCommandCancelled(t *testing.T) {
	for _, stage := range []stallStage{stallHandshake, stallSession, stallCommand} {
		t.Run(stage.String(), func(t *testing.T) {
			srv := startStallingServer(t, stage)
			usePasswordAuth(t)
			checkCancelled(t, srv.reached, srv.closed, func(ctx context.Context) error {
				_, err := RunCommand(ctx, srv.connConfig(), "show version")
				return err
			})
		})
	}
}

// TestRunCommandCancelledWithCause checks that a request cancelled with a
// custom cause, as go-sdk does when the client disconnects, still returns an
// error matching context.Canceled.
func TestRunCommandCancelledWithCause(t *testing.T) {
	srv := startStallingServer(t, stallCommand)
	usePasswordAuth(t)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)

	done := make(chan error, 1)
	go func() {
		_, err := RunCommand(ctx, srv.connConfig(), "show version")
		done <- err
	}()
	waitFor(t, srv.reached, "the command")
	cancel(io.EOF)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunCommand() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running 5s after cancellation")
	}
}

func TestRunCommandsCancelled(t *testing.T) {
	srv := startStallingServer(t, stallCommand)
	usePasswordAuth(t)
	checkCancelled(t, srv.reached, srv.closed, func(ctx context.Context) error {
		_, err := RunCommands(ctx, srv.connConfig(), []string{"execute ping-options repeat-count 3", "execute ping 192.0.2.1"})
		return err
	})
}

func TestProbeCancelled(t *testing.T) {
	srv := startStallingServer(t, stallCommand)
	usePasswordAuth(t)
	checkCancelled(t, srv.reached, srv.closed, func(ctx context.Context) error {
		_, err := Probe(ctx, srv.connConfig(), func(string) (string, *Pager, error) { return "show version", nil, nil })
		return err
	})
}

func TestInspectHostKeyCancelled(t *testing.T) {
	srv := startStallingServer(t, stallHandshake)
	usePasswordAuth(t)
	checkCancelled(t, srv.reached, srv.closed, func(ctx context.Context) error {
		_, err := InspectHostKey(ctx, srv.addr.IP.String(), srv.addr.Port)
		return err
	})
}

// TestTrustHostKeyCancelledDuringHandshake checks that cancelling while the
// key is being fetched returns promptly. That nothing is written after a
// cancellation is checked by TestTrustHostKeyCancelledAfterFetch: this server
// never sends a key, so there would be nothing to write here anyway.
func TestTrustHostKeyCancelledDuringHandshake(t *testing.T) {
	srv := startStallingServer(t, stallHandshake)
	useKnownHosts(t, srv.addr)
	checkCancelled(t, srv.reached, srv.closed, func(ctx context.Context) error {
		_, err := TrustHostKey(ctx, srv.addr.IP.String(), srv.addr.Port, false)
		return err
	})
}

// TestHostKeyAlreadyCancelled checks that an already-cancelled request
// reports the cancellation before reading known_hosts, which here would fail.
func TestHostKeyAlreadyCancelled(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ed25519"))
	path := useKnownHosts(t, addr)
	if err := os.WriteFile(path, []byte("@cert-authority\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectHostKey(t.Context(), addr.IP.String(), addr.Port); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("InspectHostKey() with a live context: error = %v, want the known_hosts error", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := InspectHostKey(ctx, addr.IP.String(), addr.Port); !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), addr.String()) {
		t.Fatalf("InspectHostKey() error = %v, want context.Canceled naming %s", err, addr)
	}
	if _, err := TrustHostKey(ctx, addr.IP.String(), addr.Port, false); !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), addr.String()) {
		t.Fatalf("TrustHostKey() error = %v, want context.Canceled naming %s", err, addr)
	}
}

// TestTrustHostKeyCancelledAfterFetch checks that a request cancelled after
// the key was fetched, just before known_hosts would be written, leaves the
// file unchanged.
func TestTrustHostKeyCancelledAfterFetch(t *testing.T) {
	addr := startHostKeyServer(t, newSigner(t, "ed25519"))
	path := useKnownHosts(t, addr)
	knownHosts, err := loadKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	info, err := inspectHostKey(t.Context(), addr.IP.String(), addr.Port, knownHosts)
	if err != nil {
		t.Fatalf("inspectHostKey() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := trustFetchedKey(ctx, info, knownHosts, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("trustFetchedKey() error = %v, want context.Canceled", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Fatalf("known_hosts stat = %v, %v; want it left empty", fi, err)
	}
}

// TestRunCommandAlreadyCancelled checks that a request cancelled before the
// call starts never connects to the device, and reports the cancellation
// rather than a configuration error.
func TestRunCommandAlreadyCancelled(t *testing.T) {
	srv := startStallingServer(t, stallHandshake)
	orig := currentOptions
	t.Cleanup(func() { currentOptions = orig })
	if err := Configure(Options{InsecureSkipHostKeyCheck: true}); err != nil {
		t.Fatal(err)
	}
	// No auth configured: a call that got that far would fail with "no auth
	// available" instead of the cancellation.
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("DEVICE_PASSWORD", "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := RunCommand(ctx, srv.connConfig(), "show version")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), srv.addr.String()) {
		t.Fatalf("RunCommand() error = %v, want context.Canceled naming %s", err, srv.addr)
	}

	// Connections are accepted in order, so once a later connection has been
	// accepted, any from the cancelled call would have been counted.
	sentinel, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", srv.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sentinel.Close() }()
	if _, err := sentinel.Write([]byte("SSH-2.0-sentinel\r\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, srv.reached, "the sentinel connection")
	if n := srv.accepted.Load(); n != 1 {
		t.Fatalf("server accepted %d connections, want only the sentinel", n)
	}
}

// TestRunOnClientCancelledSendsNothing checks that a command whose request is
// already cancelled when the connection is ready is never sent to the device:
// the connection is closed before a session is requested. That the close
// comes first is checked deterministically in TestCloseOnLimit.
func TestRunOnClientCancelledSendsNothing(t *testing.T) {
	srv := startStallingServer(t, stallCommand)
	usePasswordAuth(t)
	client, addr, err := dial(t.Context(), srv.connConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := runOnClient(ctx, client, addr, "show version", nil, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("runOnClient() error = %v, want context.Canceled", err)
	}
	waitFor(t, srv.closed, "the connection to close")
	if got := srv.commands(); len(got) != 0 {
		t.Fatalf("device received %q, want nothing", got)
	}
}

// startSilentAgent runs an SSH agent socket that accepts connections and
// reads requests but never answers, like an agent waiting for the user to
// confirm a key use. got receives when a request arrives; closed receives
// when the client closes its connection.
func startSilentAgent(t *testing.T) (sock string, got, closed <-chan struct{}) {
	t.Helper()
	dir, err := os.MkdirTemp("", "agent") // short, for the socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = dir + "/s"
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	gotCh, closedCh := make(chan struct{}, 4), make(chan struct{}, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { closedCh <- struct{}{} }()
				buf := make([]byte, 4096)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				gotCh <- struct{}{}
				_, _ = io.Copy(io.Discard, conn) // never answer; returns when the client closes
			}()
		}
	}()
	return sock, gotCh, closedCh
}

// TestRunCommandCancelledWhileWaitingOnAgent checks that cancelling a call
// whose authentication is stuck waiting on the SSH agent returns promptly
// and closes the agent connection.
func TestRunCommandCancelledWhileWaitingOnAgent(t *testing.T) {
	srv := startStallingServer(t, stallCommand)
	usePasswordAuth(t)
	sock, got, agentClosed := startSilentAgent(t)
	t.Setenv("SSH_AUTH_SOCK", sock)

	checkCancelled(t, got, agentClosed, func(ctx context.Context) error {
		_, err := RunCommand(ctx, srv.connConfig(), "show version")
		return err
	})
}

// TestHandshakeTimeoutWhileWaitingOnAgent checks that the handshake limit
// also cuts off authentication stuck waiting on the SSH agent.
func TestHandshakeTimeoutWhileWaitingOnAgent(t *testing.T) {
	srv := startStallingServer(t, stallCommand)
	usePasswordAuth(t)
	sock, _, agentClosed := startSilentAgent(t)
	t.Setenv("SSH_AUTH_SOCK", sock)
	orig := handshakeTimeout
	t.Cleanup(func() { handshakeTimeout = orig })
	handshakeTimeout = 300 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := RunCommand(t.Context(), srv.connConfig(), "show version")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("RunCommand() error = %v, want the handshake timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunCommand() still running 5s after the 300ms handshake limit")
	}
	waitFor(t, agentClosed, "the agent connection to close")
}

// closeRecorder records calls to its close method and signals the first.
type closeRecorder struct {
	n      atomic.Int32
	closed chan struct{}
}

func newCloseRecorder() *closeRecorder { return &closeRecorder{closed: make(chan struct{})} }

func (c *closeRecorder) close() {
	if c.n.Add(1) == 1 {
		close(c.closed)
	}
}

func TestCloseOnLimit(t *testing.T) {
	t.Run("stopped first", func(t *testing.T) {
		c := newCloseRecorder()
		ctx, cancel := context.WithCancel(t.Context())
		stop := closeOnLimit(ctx, time.Hour, c.close)
		if reason := stop(); reason != nil {
			t.Fatalf("stop() = %v, want nil", reason)
		}
		// stop has deregistered the close, so cancelling cannot run it.
		cancel()
		if c.n.Load() != 0 {
			t.Fatal("closed after stop")
		}
	})

	t.Run("limit", func(t *testing.T) {
		c := newCloseRecorder()
		stop := closeOnLimit(t.Context(), 20*time.Millisecond, c.close)
		waitFor(t, c.closed, "the close at the limit")
		if reason := stop(); !errors.Is(reason, errLimitReached) || c.n.Load() != 1 {
			t.Fatalf("stop() = %v, closes = %d; want errLimitReached and one close", reason, c.n.Load())
		}
		if reason := stop(); !errors.Is(reason, errLimitReached) {
			t.Fatalf("second stop() = %v, want the same reason", reason)
		}
	})

	t.Run("cancelled with a cause", func(t *testing.T) {
		// go-sdk cancels in-flight requests with the transport's read error
		// (io.EOF) as the cause when the client disconnects.
		c := newCloseRecorder()
		ctx, cancel := context.WithCancelCause(t.Context())
		stop := closeOnLimit(ctx, time.Hour, c.close)
		cancel(io.EOF)
		waitFor(t, c.closed, "the close on cancellation")
		if reason := stop(); !errors.Is(reason, context.Canceled) || c.n.Load() != 1 {
			t.Fatalf("stop() = %v, closes = %d; want context.Canceled and one close", reason, c.n.Load())
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		c := newCloseRecorder()
		ctx, cancel := context.WithCancel(t.Context())
		stop := closeOnLimit(ctx, time.Hour, c.close)
		cancel()
		waitFor(t, c.closed, "the close on cancellation")
		if reason := stop(); !errors.Is(reason, context.Canceled) || c.n.Load() != 1 {
			t.Fatalf("stop() = %v, closes = %d; want context.Canceled and one close", reason, c.n.Load())
		}
	})

	t.Run("already cancelled", func(t *testing.T) {
		// The close must have happened by the time closeOnLimit returns,
		// before the caller can use the connection.
		c := newCloseRecorder()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		stop := closeOnLimit(ctx, time.Hour, c.close)
		if c.n.Load() != 1 {
			t.Fatalf("closes = %d when closeOnLimit returned; want one", c.n.Load())
		}
		if reason := stop(); !errors.Is(reason, context.Canceled) || c.n.Load() != 1 {
			t.Fatalf("stop() = %v, closes = %d; want context.Canceled and one close", reason, c.n.Load())
		}
	})
}
