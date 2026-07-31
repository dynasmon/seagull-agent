package ssh

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseLineFailedPassword(t *testing.T) {
	c := NewAuthLogCapturer("agent-1", AuthLogOptions{})
	c.hostIP = "10.0.0.5"

	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	line := "Failed password for invalid user root from 203.0.113.10 port 51514 ssh2"

	ev, key, ok := c.parseLine(now, line)
	if !ok {
		t.Fatalf("expected parsed event")
	}
	if ev.EventType != "ssh_auth" {
		t.Fatalf("unexpected event type: %s", ev.EventType)
	}
	if key.action != "failed_password" {
		t.Fatalf("unexpected action key: %s", key.action)
	}
}

func TestParseLineSudoCommand(t *testing.T) {
	c := NewAuthLogCapturer("agent-1", AuthLogOptions{})
	c.hostIP = "10.0.0.5"

	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	line := "sudo: nathan : TTY=pts/0 ; PWD=/home/nathan ; USER=root ; COMMAND=/usr/bin/id"

	ev, _, ok := c.parseLine(now, line)
	if !ok {
		t.Fatalf("expected parsed event")
	}
	if ev.EventType != "sudo_cmd" {
		t.Fatalf("unexpected event type: %s", ev.EventType)
	}
	if ev.Proto != "sudo" {
		t.Fatalf("unexpected proto: %s", ev.Proto)
	}
}

func TestResolveAuthLogPathUsesConfiguredPathWhenReadable(t *testing.T) {
	td := t.TempDir()
	authLog := filepath.Join(td, "auth.log")
	if err := os.WriteFile(authLog, []byte("ok\n"), 0o600); err != nil {
		t.Fatalf("write auth log: %v", err)
	}

	got, err := ResolveAuthLogPath(authLog)
	if err != nil || got != authLog {
		t.Fatalf("expected resolved path %s, got %s (err=%v)", authLog, got, err)
	}
}
