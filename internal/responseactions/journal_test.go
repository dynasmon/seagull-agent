package responseactions

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/seagull-agent/protocol"
)

func journalAction(id int64) protocol.ResponseAction {
	return protocol.ResponseAction{
		ID:          id,
		ActionType:  protocol.ActionTriggerInventory,
		AgentID:     "agent-journal-1",
		Status:      "pending",
		Payload:     json.RawMessage(`{}`),
		RequestedAt: time.Now().UTC().Add(-time.Minute),
	}
}

func TestJournalPersistsAcceptedAndTerminalRecords(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	journal, err := NewJournal(dir, 32, 8<<20)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	if _, err := journal.Begin(journalAction(41), started); err != nil {
		t.Fatalf("begin action: %v", err)
	}
	if _, err := journal.MarkExecuting(41, started.Add(time.Millisecond)); err != nil {
		t.Fatalf("mark executing: %v", err)
	}
	finished := started.Add(time.Second)
	if _, err := journal.Complete(41, protocol.ResponseActionExecutionResult{
		Status:        "success",
		ResultPayload: map[string]interface{}{"ok": true},
		StartedAt:     timePointer(started),
		FinishedAt:    timePointer(finished),
	}, finished); err != nil {
		t.Fatalf("complete action: %v", err)
	}

	reopened, err := NewJournal(dir, 32, 8<<20)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	records, err := reopened.Terminal(10)
	if err != nil {
		t.Fatalf("list terminal records: %v", err)
	}
	if len(records) != 1 || records[0].Result == nil {
		t.Fatalf("unexpected terminal records: %+v", records)
	}
	if records[0].Result.Status != "success" || records[0].Result.ResultPayload["ok"] != true {
		t.Fatalf("unexpected terminal result: %+v", records[0].Result)
	}
	if err := reopened.Delete(41); err != nil {
		t.Fatalf("delete terminal record: %v", err)
	}
	if pending, err := reopened.Pending(); err != nil || pending != 0 {
		t.Fatalf("unexpected pending count=%d err=%v", pending, err)
	}
}

func TestJournalRecoversIndeterminateExecutionWithoutRepeatingIt(t *testing.T) {
	dir := t.TempDir()
	started := time.Now().UTC().Add(-time.Minute)
	journal, err := NewJournal(dir, 32, 8<<20)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	if _, err := journal.Begin(journalAction(52), started); err != nil {
		t.Fatalf("begin action: %v", err)
	}
	if _, err := journal.MarkExecuting(52, started.Add(time.Second)); err != nil {
		t.Fatalf("mark executing: %v", err)
	}

	reopened, err := NewJournal(dir, 32, 8<<20)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	accepted, err := reopened.Accepted(10)
	if err != nil {
		t.Fatalf("list accepted records: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("indeterminate action became executable again")
	}
	terminal, err := reopened.Terminal(10)
	if err != nil {
		t.Fatalf("list terminal records: %v", err)
	}
	if len(terminal) != 1 || terminal[0].Result == nil {
		t.Fatalf("missing recovered terminal result")
	}
	if terminal[0].Result.Status != "failed" || !strings.Contains(terminal[0].Result.Error, "indeterminate") {
		t.Fatalf("unexpected recovery result: %+v", terminal[0].Result)
	}
}

func TestJournalAcceptedActionCanResumeAfterRestart(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewJournal(dir, 32, 8<<20)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	if _, err := journal.Begin(journalAction(63), time.Now().UTC()); err != nil {
		t.Fatalf("begin action: %v", err)
	}
	reopened, err := NewJournal(dir, 32, 8<<20)
	if err != nil {
		t.Fatalf("reopen journal: %v", err)
	}
	accepted, err := reopened.Accepted(10)
	if err != nil {
		t.Fatalf("list accepted records: %v", err)
	}
	if len(accepted) != 1 || accepted[0].Action.ID != 63 {
		t.Fatalf("unexpected accepted records: %+v", accepted)
	}
}

func TestJournalRejectsDuplicateAndCapacityOverflow(t *testing.T) {
	journal, err := NewJournal(t.TempDir(), 1, 8<<20)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	if _, err := journal.Begin(journalAction(71), time.Now().UTC()); err != nil {
		t.Fatalf("begin first action: %v", err)
	}
	if _, err := journal.Begin(journalAction(71), time.Now().UTC()); !errors.Is(err, ErrJournalEntryExists) {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if _, err := journal.Begin(journalAction(72), time.Now().UTC()); !errors.Is(err, ErrJournalCapacity) {
		t.Fatalf("expected capacity error, got %v", err)
	}
}

func TestJournalFailsClosedOnCorruptState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000081.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write corrupt entry: %v", err)
	}
	if _, err := NewJournal(dir, 32, 8<<20); err == nil {
		t.Fatalf("expected corrupt journal rejection")
	}
}

func TestJournalBoundsResultPayload(t *testing.T) {
	journal, err := NewJournal(t.TempDir(), 32, 8<<20)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	if _, err := journal.Begin(journalAction(91), time.Now().UTC()); err != nil {
		t.Fatalf("begin action: %v", err)
	}
	if _, err := journal.MarkExecuting(91, time.Now().UTC()); err != nil {
		t.Fatalf("mark executing: %v", err)
	}
	record, err := journal.Complete(91, protocol.ResponseActionExecutionResult{
		Status:        "success",
		ResultPayload: map[string]interface{}{"data": strings.Repeat("x", maxResultPayloadSize+1)},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("complete action: %v", err)
	}
	if record.Result == nil || record.Result.ResultPayload != nil {
		t.Fatalf("oversized result payload was retained")
	}
	if !strings.Contains(record.Result.Error, "omitted") {
		t.Fatalf("missing result truncation signal: %+v", record.Result)
	}
}
