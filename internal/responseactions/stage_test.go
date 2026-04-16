package responseactions

import (
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
)

func TestStageDeduplicates(t *testing.T) {
	stage := NewStage(8)
	now := time.Now().UTC()

	actions := []controlplane.ResponseAction{
		{ID: 1001, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now},
		{ID: 1001, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now},
	}

	got := stage.Stage(now, actions, "agent-1")
	if got.Added != 1 {
		t.Fatalf("expected 1 staged action, got %d", got.Added)
	}
	if got.Ignored != 1 {
		t.Fatalf("expected 1 ignored action, got %d", got.Ignored)
	}
	if got.Dropped != 0 {
		t.Fatalf("expected 0 dropped action, got %d", got.Dropped)
	}
	if got.Pending != 1 {
		t.Fatalf("expected pending=1, got %d", got.Pending)
	}
}

func TestStageFiltersOwnershipAndExpiration(t *testing.T) {
	stage := NewStage(8)
	now := time.Now().UTC()
	expired := now.Add(-1 * time.Minute)
	future := now.Add(5 * time.Minute)

	actions := []controlplane.ResponseAction{
		{ID: 1001, ActionType: "block_ip", AgentID: "agent-2", Status: "pending", RequestedAt: now},
		{ID: 1002, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now, ExpiresAt: &expired},
		{ID: 1003, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now, ExpiresAt: &future},
	}

	got := stage.Stage(now, actions, "agent-1")
	if got.Added != 1 || got.Ignored != 2 || got.Dropped != 0 {
		t.Fatalf("unexpected stage result: added=%d ignored=%d dropped=%d", got.Added, got.Ignored, got.Dropped)
	}
	if got.Pending != 1 {
		t.Fatalf("expected pending=1, got %d", got.Pending)
	}
}

func TestStageBoundedCapacity(t *testing.T) {
	stage := NewStage(2)
	now := time.Now().UTC()

	actions := []controlplane.ResponseAction{
		{ID: 1, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now},
		{ID: 2, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now},
		{ID: 3, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: now},
	}

	got := stage.Stage(now, actions, "agent-1")
	if got.Added != 3 || got.Ignored != 0 || got.Dropped != 1 {
		t.Fatalf("unexpected stage result: added=%d ignored=%d dropped=%d", got.Added, got.Ignored, got.Dropped)
	}
	if got.Pending != 2 {
		t.Fatalf("expected pending=2, got %d", got.Pending)
	}
}

func TestStageIgnoresHandledIDs(t *testing.T) {
	stage := NewStage(8)
	now := time.Now().UTC()

	stage.MarkHandled(777)
	got := stage.Stage(now, []controlplane.ResponseAction{
		{ID: 777, ActionType: "collect_triage_bundle", AgentID: "agent-1", Status: "pending", RequestedAt: now},
	}, "agent-1")
	if got.Added != 0 || got.Ignored != 1 {
		t.Fatalf("unexpected stage result: %+v", got)
	}
}

func TestStageNextSkipsExpiredAndMismatched(t *testing.T) {
	stage := NewStage(8)
	now := time.Now().UTC()
	expired := now.Add(-1 * time.Minute)

	stage.Stage(now, []controlplane.ResponseAction{
		{ID: 1, ActionType: "collect_triage_bundle", AgentID: "other", Status: "pending", RequestedAt: now},
		{ID: 2, ActionType: "collect_triage_bundle", AgentID: "agent-1", Status: "pending", RequestedAt: now, ExpiresAt: &expired},
		{ID: 3, ActionType: "collect_triage_bundle", AgentID: "agent-1", Status: "pending", RequestedAt: now},
	}, "")

	next, ok := stage.Next(now, "agent-1")
	if !ok {
		t.Fatalf("expected one eligible action")
	}
	if next.Action.ID != 3 {
		t.Fatalf("expected action id=3, got %d", next.Action.ID)
	}
}
