package sshclient

import (
	"fmt"
	"net"
	"os"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const dialTimeout = 15 * time.Second

// ConnConfig holds SSH connection parameters.
type ConnConfig struct {
	Host     string
	Port     int
	Username string
}

// RunCommand dials the SSH host, executes cmd, and returns stdout.
// A new connection is created for each call.
func RunCommand(cfg ConnConfig, cmd string) (string, error) {
	port := cfg.Port
	if port == 0 {
		port = 22
	}

	methods, err := buildAuthMethods()
	if err != nil {
		return "", err
	}

	sshCfg := &gossh.ClientConfig{
		User:            cfg.Username,
		Auth:            methods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         dialTimeout,
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port))
	client, err := gossh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	out, err := session.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("run %q: %w", cmd, err)
	}

	return string(out), nil
}

func buildAuthMethods() ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			methods = append(methods, gossh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	if pw := os.Getenv("ARISTA_PASSWORD"); pw != "" {
		methods = append(methods, gossh.Password(pw))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no auth available: set SSH_AUTH_SOCK or ARISTA_PASSWORD")
	}

	return methods, nil
}
