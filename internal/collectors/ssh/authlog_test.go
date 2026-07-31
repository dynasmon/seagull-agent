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

func TestAuthLogCheckpointResumesAfterCommittedOffset(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	checkpoint := filepath.Join(dir, "checkpoints", "authlog.json")
	initial := "sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n" +
		"sudo: bob : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/whoami\n"
	if err := os.WriteFile(authLog, []byte(initial), 0o600); err != nil {
		t.Fatalf("write auth log: %v", err)
	}

	first := NewAuthLogCapturer("agent-1", AuthLogOptions{Path: authLog, CheckpointPath: checkpoint})
	events, err := first.Capture(time.Now().UTC())
	if err != nil || len(events) != 2 {
		t.Fatalf("initial capture events=%d err=%v", len(events), err)
	}
	if err := first.Commit(); err != nil {
		t.Fatalf("commit checkpoint: %v", err)
	}
	info, err := os.Stat(checkpoint)
	if err != nil {
		t.Fatalf("stat checkpoint: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode=%o want 600", info.Mode().Perm())
	}

	file, err := os.OpenFile(authLog, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open auth log: %v", err)
	}
	if _, err := file.WriteString("sudo: carol : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/true\n"); err != nil {
		file.Close()
		t.Fatalf("append auth log: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close auth log: %v", err)
	}

	second := NewAuthLogCapturer("agent-1", AuthLogOptions{Path: authLog, CheckpointPath: checkpoint})
	events, err = second.Capture(time.Now().UTC())
	if err != nil || len(events) != 1 {
		t.Fatalf("resumed capture events=%d err=%v", len(events), err)
	}
}

func TestAuthLogRollbackReplaysUncommittedEvidence(t *testing.T) {
	authLog := filepath.Join(t.TempDir(), "auth.log")
	line := "sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n"
	if err := os.WriteFile(authLog, []byte(line), 0o600); err != nil {
		t.Fatalf("write auth log: %v", err)
	}
	capturer := NewAuthLogCapturer("agent-1", AuthLogOptions{Path: authLog})
	events, err := capturer.Capture(time.Now().UTC())
	if err != nil || len(events) != 1 {
		t.Fatalf("first capture events=%d err=%v", len(events), err)
	}
	firstEventID := events[0].EventID
	if firstEventID == "" || events[0].Extra["event_id"] != firstEventID {
		t.Fatalf("first capture has inconsistent event identity: %+v", events[0])
	}
	capturer.Rollback()
	events, err = capturer.Capture(time.Now().UTC())
	if err != nil || len(events) != 1 {
		t.Fatalf("replayed capture events=%d err=%v", len(events), err)
	}
	if events[0].EventID != firstEventID {
		t.Fatalf("replayed event id=%q want %q", events[0].EventID, firstEventID)
	}
	restarted := NewAuthLogCapturer("agent-1", AuthLogOptions{Path: authLog})
	events, err = restarted.Capture(time.Now().UTC())
	if err != nil || len(events) != 1 {
		t.Fatalf("restart capture events=%d err=%v", len(events), err)
	}
	if events[0].EventID != firstEventID {
		t.Fatalf("restarted event id=%q want %q", events[0].EventID, firstEventID)
	}
}

func TestAuthLogCorruptCheckpointFailsClosed(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	checkpoint := filepath.Join(dir, "checkpoint.json")
	if err := os.WriteFile(authLog, []byte("empty\n"), 0o600); err != nil {
		t.Fatalf("write auth log: %v", err)
	}
	if err := os.WriteFile(checkpoint, []byte(`{"version":`), 0o600); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
	capturer := NewAuthLogCapturer("agent-1", AuthLogOptions{Path: authLog, CheckpointPath: checkpoint})
	if _, err := capturer.Capture(time.Now().UTC()); err == nil {
		t.Fatal("corrupt checkpoint was accepted")
	}
}
