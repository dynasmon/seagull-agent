package procexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseProcStatLine(t *testing.T) {
	line := "1234 (python3) S 10 1 11 34817 0 0 0 0 0 0 0 0 0 0 20 0 1 0 765432 0 0 0 0 0 0 0 0 0 0 0 0 0"
	out, err := parseProcStatLine(line)
	if err != nil {
		t.Fatalf("parseProcStatLine error: %v", err)
	}
	if out.PID != 1234 {
		t.Fatalf("expected pid=1234 got=%d", out.PID)
	}
	if out.PPID != 10 {
		t.Fatalf("expected ppid=10 got=%d", out.PPID)
	}
	if out.Session != 11 {
		t.Fatalf("expected session=11 got=%d", out.Session)
	}
	if out.TTYNr != 34817 {
		t.Fatalf("expected tty=34817 got=%d", out.TTYNr)
	}
	if out.StartTicks != 765432 {
		t.Fatalf("expected start_ticks=765432 got=%d", out.StartTicks)
	}
}

func TestParseStatusUIDGID(t *testing.T) {
	uid, euid, gid, egid := parseStatusUIDGID("Name:\tbash\nUid:\t1000\t1001\t1001\t1001\nGid:\t2000\t2001\t2001\t2001\n")
	if uid != 1000 || euid != 1001 || gid != 2000 || egid != 2001 {
		t.Fatalf("unexpected ids uid=%d euid=%d gid=%d egid=%d", uid, euid, gid, egid)
	}
}

func TestHashExecutableCache(t *testing.T) {
	td := t.TempDir()
	bin := filepath.Join(td, "tool.bin")
	if err := os.WriteFile(bin, []byte("hello-world"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	c := New("agent-1", Options{
		HashExecutables: true,
		HashMaxBytes:    1024,
	})
	now := time.Now().UTC()
	h1, ok1 := c.hashExecutable(bin, now)
	if !ok1 || h1 == "" {
		t.Fatalf("expected first hash")
	}
	h2, ok2 := c.hashExecutable(bin, now.Add(10*time.Second))
	if !ok2 || h2 != h1 {
		t.Fatalf("expected cache hit with same hash")
	}
}

func TestCaptureSkipsInitialSnapshotByDefault(t *testing.T) {
	td := t.TempDir()
	procRoot := filepath.Join(td, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatalf("mkdir proc root: %v", err)
	}

	writeFakeProc(t, procRoot, 101, 1, 4500, "bash", "bash -c id", "/usr/bin/bash", "/tmp")
	writeFakeProc(t, procRoot, 1, 0, 1200, "systemd", "", "/usr/lib/systemd/systemd", "/")

	c := New("agent-test", Options{
		ProcRoot:        procRoot,
		HashExecutables: false,
	})

	first, err := c.Capture(time.Now().UTC())
	if err != nil {
		t.Fatalf("capture first: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("expected no initial events, got %d", len(first))
	}

	writeFakeProc(t, procRoot, 202, 101, 4700, "python3", "python3 -c print(1)", "/usr/bin/python3", "/tmp")
	second, err := c.Capture(time.Now().UTC().Add(2 * time.Second))
	if err != nil {
		t.Fatalf("capture second: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("expected one delta event, got %d", len(second))
	}
	if second[0].EventType != "proc_exec" {
		t.Fatalf("expected proc_exec got=%s", second[0].EventType)
	}
}

func TestShouldIgnore(t *testing.T) {
	c := New("agent-1", Options{
		IgnoreExeNames: map[string]bool{"sleep": true},
	})
	info := &procInfo{
		stat:    procStat{PID: 999},
		exeName: "sleep",
		cmdline: "sleep 10",
	}
	if !c.shouldIgnore(info) {
		t.Fatalf("expected ignore by exe name")
	}
}

func writeFakeProc(t *testing.T, procRoot string, pid, ppid int, startTicks uint64, comm, cmdline, exePath, cwd string) {
	t.Helper()
	pd := filepath.Join(procRoot, intToString(pid))
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatalf("mkdir pid dir: %v", err)
	}

	// pid (comm) state ppid pgrp session tty_nr ... starttime ...
	statLine := strings.Join([]string{
		intToString(pid), "(" + comm + ")", "S",
		intToString(ppid), "1", "1", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		"20", "0", "1", "0", uintToString(startTicks),
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
	}, " ") + "\n"
	if err := os.WriteFile(filepath.Join(pd, "stat"), []byte(statLine), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pd, "status"), []byte("Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pd, "cmdline"), []byte(cmdline+"\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	if exePath != "" {
		os.Remove(filepath.Join(pd, "exe"))
		if err := os.Symlink(exePath, filepath.Join(pd, "exe")); err != nil {
			t.Fatalf("symlink exe: %v", err)
		}
	}
	if cwd != "" {
		os.Remove(filepath.Join(pd, "cwd"))
		if err := os.Symlink(cwd, filepath.Join(pd, "cwd")); err != nil {
			t.Fatalf("symlink cwd: %v", err)
		}
	}
}

func intToString(v int) string {
	return fmt.Sprintf("%d", v)
}

func uintToString(v uint64) string {
	return fmt.Sprintf("%d", v)
}
