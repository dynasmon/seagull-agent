package fim

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClassifyPathCategory(t *testing.T) {
	if got := classifyPathCategory("/etc/systemd/system/test.service"); got != "systemd_unit" {
		t.Fatalf("expected systemd_unit got=%s", got)
	}
	if got := classifyPathCategory("/etc/cron.daily/job"); got != "cron" {
		t.Fatalf("expected cron got=%s", got)
	}
	if got := classifyPathCategory("/root/.ssh/authorized_keys"); got != "ssh_authorized_keys" {
		t.Fatalf("expected ssh_authorized_keys got=%s", got)
	}
}

func TestDiffCreateModifyDelete(t *testing.T) {
	td := t.TempDir()
	target := filepath.Join(td, "test.service")
	if err := os.WriteFile(target, []byte("a=1\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	c := New("agent-fim", Options{
		WatchPaths:  []string{target},
		MinInterval: 0,
		HashEnabled: true,
	})
	now := time.Now().UTC()
	first, err := c.Capture(now)
	if err != nil {
		t.Fatalf("first capture: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("expected zero events on baseline, got %d", len(first))
	}

	if err := os.WriteFile(target, []byte("a=2\n"), 0o644); err != nil {
		t.Fatalf("modify file: %v", err)
	}
	modified, err := c.Capture(now.Add(2 * time.Second))
	if err != nil {
		t.Fatalf("second capture: %v", err)
	}
	if len(modified) != 1 {
		t.Fatalf("expected one modify event got=%d", len(modified))
	}
	if modified[0].Extra["action"] != "modify" {
		t.Fatalf("expected action=modify got=%v", modified[0].Extra["action"])
	}

	if err := os.Remove(target); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	deleted, err := c.Capture(now.Add(4 * time.Second))
	if err != nil {
		t.Fatalf("third capture: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected one delete event got=%d", len(deleted))
	}
	if deleted[0].Extra["action"] != "delete" {
		t.Fatalf("expected action=delete got=%v", deleted[0].Extra["action"])
	}
}

func TestEventTypeForCategory(t *testing.T) {
	if eventTypeForCategory("cron") != "persistence_cron" {
		t.Fatalf("expected persistence_cron")
	}
	if eventTypeForCategory("systemd_unit") != "persistence_systemd" {
		t.Fatalf("expected persistence_systemd")
	}
	if eventTypeForCategory("ssh_authorized_keys") != "ssh_key_change" {
		t.Fatalf("expected ssh_key_change")
	}
	if eventTypeForCategory("security_file") != "fim_change" {
		t.Fatalf("expected fim_change")
	}
}

func TestDiffRenameIncludesPathFromTo(t *testing.T) {
	td := t.TempDir()
	orig := filepath.Join(td, "job.sh")
	next := filepath.Join(td, "job-renamed.sh")

	if err := os.WriteFile(orig, []byte("#!/bin/sh\necho hi\n"), 0o700); err != nil {
		t.Fatalf("write file: %v", err)
	}

	c := New("agent-fim", Options{
		WatchPaths:  []string{td},
		MinInterval: 0,
		HashEnabled: true,
	})
	now := time.Now().UTC()
	first, err := c.Capture(now)
	if err != nil {
		t.Fatalf("first capture: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("expected zero events on baseline, got %d", len(first))
	}

	if err := os.Rename(orig, next); err != nil {
		t.Fatalf("rename file: %v", err)
	}
	evs, err := c.Capture(now.Add(2 * time.Second))
	if err != nil {
		t.Fatalf("capture after rename: %v", err)
	}
	var rename map[string]interface{}
	for _, ev := range evs {
		if ev.Extra["action"] == "rename" {
			rename = ev.Extra
			break
		}
	}
	if rename == nil {
		t.Fatalf("expected at least one rename event, got=%d", len(evs))
	}
	if rename["path_from"] != orig || rename["path_to"] != next {
		t.Fatalf("rename paths mismatch: from=%v to=%v", rename["path_from"], rename["path_to"])
	}
}
