package responseactions

import (
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/controlplane"
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
