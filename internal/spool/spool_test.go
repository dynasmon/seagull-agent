package spool

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestAcknowledgeCommitsWriteAheadEntry(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	envelope, err := sp.Enqueue("batch-1", "events", []byte(`[{"a":1}]`))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := sp.Acknowledge(envelope); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	stats := sp.Stats()
	if stats.Pending != 0 || stats.DeliveredTotal != 1 {
		t.Fatalf("unexpected acknowledgement stats: %+v", stats)
	}
}

func TestRejectAccountsForPermanentWriteAheadFailure(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	envelope, err := sp.Enqueue("batch-1", "events", []byte(`[{"a":1}]`))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := sp.Reject(envelope); err != nil {
		t.Fatalf("reject: %v", err)
	}
	stats := sp.Stats()
	if stats.Pending != 0 || stats.DroppedTotal != 1 || stats.PermanentTotal != 1 {
		t.Fatalf("unexpected rejection stats: %+v", stats)
	}
}

func TestEnqueueReportsImmediateCapacityEviction(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir(), MaxBytes: 1})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.Enqueue("batch-1", "events", []byte(`[{"a":1}]`)); err == nil {
		t.Fatal("capacity eviction was not reported")
	}
	stats := sp.Stats()
	if stats.Pending != 0 || stats.CapacityTotal != 1 {
		t.Fatalf("unexpected capacity stats: %+v", stats)
	}
}

func TestEnqueueFailureIsCounted(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "spool")
	sp, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	moved := filepath.Join(parent, "spool-moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("move spool directory: %v", err)
	}
	if err := os.WriteFile(dir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace spool directory: %v", err)
	}
	if _, err := sp.Enqueue("batch-1", "events", []byte(`[{"a":1}]`)); err == nil {
		t.Fatal("expected enqueue failure")
	}
	if sp.Stats().EnqueueErrorsTotal != 1 {
		t.Fatalf("enqueue errors=%d want 1", sp.Stats().EnqueueErrorsTotal)
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
	entries, err := os.ReadDir(sp.opts.Dir)
	if err != nil {
		t.Fatalf("read entries: %v", err)
	}
	var entryPath string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), fileSuffix) {
			entryPath = filepath.Join(sp.opts.Dir, entry.Name())
			break
		}
	}
	if entryPath == "" {
		t.Fatal("retained spool entry was not found")
	}
	raw, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatalf("read retained entry: %v", err)
	}
	var retained Envelope
	if err := json.Unmarshal(raw, &retained); err != nil {
		t.Fatalf("decode retained entry: %v", err)
	}
	if retained.Attempts != 1 {
		t.Fatalf("attempt count=%d want 1", retained.Attempts)
	}
	if sp.Stats().RetryTotal != 1 {
		t.Fatalf("retry count=%d want 1", sp.Stats().RetryTotal)
	}
}

func TestPermanentDeliveryFailureDoesNotBlockLaterEntries(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.Enqueue("bad", "events", []byte(`[{"a":1}]`)); err != nil {
		t.Fatalf("enqueue bad: %v", err)
	}
	if _, err := sp.Enqueue("good", "events", []byte(`[{"a":2}]`)); err != nil {
		t.Fatalf("enqueue good: %v", err)
	}

	delivered, err := sp.Drain(context.Background(), 10, func(env Envelope) error {
		if env.ID == "bad" {
			return Permanent(errors.New("schema rejected"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if delivered != 1 || sp.Pending() != 0 {
		t.Fatalf("delivered=%d pending=%d", delivered, sp.Pending())
	}
	if sp.Stats().PermanentTotal != 1 {
		t.Fatalf("permanent drops=%d want 1", sp.Stats().PermanentTotal)
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

func TestRetentionPreservesHigherPriorityEntries(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir(), MaxItems: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.EnqueuePriority("critical", "inventory", 100, []byte(`{"critical":true}`)); err != nil {
		t.Fatalf("enqueue critical: %v", err)
	}
	if _, err := sp.EnqueuePriority("low-1", "events", 10, []byte(`{"low":1}`)); err != nil {
		t.Fatalf("enqueue low-1: %v", err)
	}
	if _, err := sp.EnqueuePriority("low-2", "events", 10, []byte(`{"low":2}`)); err != nil {
		t.Fatalf("enqueue low-2: %v", err)
	}

	var ids []string
	if _, err := sp.Drain(context.Background(), 10, func(env Envelope) error {
		ids = append(ids, env.ID)
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	foundCritical := false
	for _, id := range ids {
		foundCritical = foundCritical || id == "critical"
	}
	if !foundCritical {
		t.Fatalf("higher priority entry was evicted: %v", ids)
	}
	if sp.Stats().CapacityTotal != 1 {
		t.Fatalf("capacity drops=%d want 1", sp.Stats().CapacityTotal)
	}
}

func TestDrainDeliversHigherPriorityFirst(t *testing.T) {
	sp, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.EnqueuePriority("low", "events", 10, []byte(`{"low":true}`)); err != nil {
		t.Fatalf("enqueue low: %v", err)
	}
	if _, err := sp.EnqueuePriority("high", "inventory", 100, []byte(`{"high":true}`)); err != nil {
		t.Fatalf("enqueue high: %v", err)
	}
	var deliveredID string
	delivered, err := sp.Drain(context.Background(), 1, func(env Envelope) error {
		deliveredID = env.ID
		return nil
	})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if delivered != 1 || deliveredID != "high" {
		t.Fatalf("delivered=%d id=%q", delivered, deliveredID)
	}
	if sp.Pending() != 1 {
		t.Fatalf("pending=%d want 1", sp.Pending())
	}
}

func TestEntryIDCannotEscapeTheSpoolDirectory(t *testing.T) {
	dir := t.TempDir()
	sp, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := sp.Enqueue("../../outside", "events", []byte(`{}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "outside.spool.json")); !os.IsNotExist(err) {
		t.Fatalf("entry escaped the spool directory: %v", err)
	}
	if sp.Pending() != 1 {
		t.Fatalf("pending=%d want 1", sp.Pending())
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
		if !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read entry: %v", err)
		}
		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode entry: %v", err)
		}
		env.CreatedAt = stale
		aged, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("encode aged entry: %v", err)
		}
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
	if sp.Stats().ExpiredTotal != 1 {
		t.Fatalf("expired count=%d want 1", sp.Stats().ExpiredTotal)
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

func TestStatsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := first.Enqueue("discard", "events", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("enqueue discard: %v", err)
	}
	if _, err := first.Enqueue("deliver", "events", []byte(`{"a":2}`)); err != nil {
		t.Fatalf("enqueue deliver: %v", err)
	}
	if _, err := first.Drain(context.Background(), 10, func(env Envelope) error {
		if env.ID == "discard" {
			return Permanent(errors.New("invalid"))
		}
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}

	second, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatalf("reopen spool: %v", err)
	}
	stats := second.Stats()
	if stats.EnqueuedTotal != 2 || stats.DeliveredTotal != 1 || stats.PermanentTotal != 1 || stats.DroppedTotal != 1 {
		t.Fatalf("unexpected persisted stats: %+v", stats)
	}
}

func TestNewRemovesInterruptedTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, ".interrupted.tmp")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write orphan: %v", err)
	}
	if _, err := New(Options{Dir: dir}); err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan temporary file remains: %v", err)
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
