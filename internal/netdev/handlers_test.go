package netdev

import (
	"context"
	"strings"
	"testing"

	"github.com/krisiasty/netdev-ssh-mcp/internal/sshclient"
)

func TestGetConfigFortiOSUsesShowFullConfiguration(t *testing.T) {
	original := runCommand
	defer func() { runCommand = original }()

	var gotCmd string
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
		gotCmd = cmd
		return "ok", nil
	}

	_, _, err := GetConfig(context.Background(), nil, GetConfigInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortios",
	})
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if gotCmd != "show full-configuration" {
		t.Fatalf("GetConfig() command = %q, want %q", gotCmd, "show full-configuration")
	}
}

func TestGetConfigFortiOSRejectsStartup(t *testing.T) {
	_, _, err := GetConfig(context.Background(), nil, GetConfigInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortios",
		ConfigType: "startup",
	})
	if err == nil || !strings.Contains(err.Error(), "FortiOS does not have a startup-config") {
		t.Fatalf("GetConfig() error = %v, want FortiOS startup rejection", err)
	}
}

func TestRunShowCommandFortiOSAllowsGet(t *testing.T) {
	original := runCommand
	defer func() { runCommand = original }()

	var gotCmd string
	runCommand = func(cfg sshclient.ConnConfig, cmd string) (string, error) {
		gotCmd = cmd
		return "Version: FortiGate", nil
	}

	_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortigate",
		Command:    "get system status",
	})
	if err != nil {
		t.Fatalf("RunShowCommand() error = %v", err)
	}
	if gotCmd != "get system status" {
		t.Fatalf("RunShowCommand() command = %q, want %q", gotCmd, "get system status")
	}
}

func TestRunShowCommandFortiOSRejectsExecute(t *testing.T) {
	_, _, err := RunShowCommand(context.Background(), nil, RunShowCommandInput{
		Host:       "fw1",
		Username:   "admin",
		DeviceType: "fortios",
		Command:    "execute ping 8.8.8.8",
	})
	if err == nil || !strings.Contains(err.Error(), "use run_ping or run_traceroute") {
		t.Fatalf("RunShowCommand() error = %v, want execute rejection", err)
	}
}
