package spool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnqueueAndDrainPreservesOrderAndID(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}

	first, err := sp.Enqueue("batch-1", "events", []byte(`[{"a":1}]`))
	if err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	if _, err := sp.Enqueue("batch-2", "events", []byte(`[{"a":2}]`)); err != nil {
		t.Fatalf("enqueue second: %v", err)
	}
	if sp.Pending() != 2 {
		t.Fatalf("expected 2 pending, got %d", sp.Pending())
	}

	var seen []string
	delivered, err := sp.Drain(context.Background(), 10, func(env Envelope) error {
		seen = append(seen, env.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if delivered != 2 || len(seen) != 2 {
		t.Fatalf("expected 2 delivered, got %d (%v)", delivered, seen)
	}
	if seen[0] != first.ID || seen[1] != "batch-2" {
		t.Fatalf("unexpected drain order: %v", seen)
	}
	if sp.Pending() != 0 {
		t.Fatalf("expected empty spool, got %d", sp.Pending())
	}
}

func TestDrainStopsAndRetainsOnDeliveryFailure(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.Enqueue("", "events", []byte(`[{"a":1}]`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := sp.Enqueue("", "events", []byte(`[{"a":2}]`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	delivered, err := sp.Drain(context.Background(), 10, func(env Envelope) error {
		return errors.New("backend down")
	})
	if err == nil {
		t.Fatal("expected drain error")
	}
	if delivered != 0 {
		t.Fatalf("expected 0 delivered, got %d", delivered)
	}
	if sp.Pending() != 2 {
		t.Fatalf("expected entries retained, got %d", sp.Pending())
	}
}

func TestRetentionDropsOldestWhenOverByteBudget(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir(), MaxBytes: 300})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}

	payload := make([]byte, 120)
	for i := range payload {
		payload[i] = 'x'
	}
	quoted := append(append([]byte(`"`), payload...), '"')

	for i := 0; i < 6; i++ {
		if _, err := sp.Enqueue("", "events", quoted); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	stats := sp.Stats()
	if stats.Bytes > 300 {
		t.Fatalf("expected byte budget enforced, got %d bytes", stats.Bytes)
	}
	if stats.DroppedTotal == 0 {
		t.Fatal("expected dropped entries")
	}
	if stats.Pending == 0 {
		t.Fatal("expected newest entries retained")
	}
}

func TestExpiredEntriesAreDroppedOnDrain(t *testing.T) {
	dir := t.TempDir()
	sp, err := New(Options{Dir: dir, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.Enqueue("", "events", []byte(`[{"a":1}]`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	stale := time.Now().Add(-2 * time.Hour)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read entry: %v", err)
		}
		aged := []byte(`{"id":"old","kind":"events","created_at":"` + stale.UTC().Format(time.RFC3339Nano) + `","payload":` + string(raw[len(raw)-1:]) + `}`)
		if err := os.WriteFile(path, aged, 0o600); err != nil {
			t.Fatalf("rewrite entry: %v", err)
		}
	}

	delivered, err := sp.Drain(context.Background(), 10, func(env Envelope) error {
		t.Fatal("expired entry must not be delivered")
		return nil
	})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if delivered != 0 {
		t.Fatalf("expected no delivery, got %d", delivered)
	}
	if sp.Pending() != 0 {
		t.Fatalf("expected expired entry removed, got %d", sp.Pending())
	}
}

func TestNewRecoversPendingEntriesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := first.Enqueue("", "events", []byte(`[{"a":1}]`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	second, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatalf("reopen spool: %v", err)
	}
	if second.Pending() != 1 {
		t.Fatalf("expected 1 recovered entry, got %d", second.Pending())
	}
}

func TestDisabledSpoolIsInert(t *testing.T) {
	sp, err := New(Options{Dir: ""})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if sp.Enabled() {
		t.Fatal("expected disabled spool")
	}
	if sp.Pending() != 0 {
		t.Fatal("expected zero pending")
	}
	if _, err := sp.Drain(context.Background(), 10, func(Envelope) error { return nil }); err != nil {
		t.Fatalf("drain on disabled spool: %v", err)
	}
}
