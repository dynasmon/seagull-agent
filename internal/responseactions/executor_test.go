package responseactions

import (
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/controlplane"
)

func TestExecuteCollectTriageBundleSuccess(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          91,
		ActionType:  "collect_triage_bundle",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		BuildVersion:    "0.1.0",
		Now:             now,
	})
	if out.Status != "success" {
		t.Fatalf("expected success status, got %q error=%q", out.Status, out.Error)
	}
	if out.Result == nil {
		t.Fatalf("expected result payload")
	}
	if out.Result["schema_version"] != "v1" {
		t.Fatalf("unexpected schema_version: %v", out.Result["schema_version"])
	}
}

func TestExecuteRejectsUnknownType(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          92,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		Now:             now,
	})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
	if out.Error == "" {
		t.Fatalf("expected failure error")
	}
}

func TestExecuteRejectsExpiredAction(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Second)
	action := controlplane.ResponseAction{
		ID:          93,
		ActionType:  "collect_triage_bundle",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now.Add(-time.Minute),
		ExpiresAt:   &expired,
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		Now:             now,
	})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
	if out.Error == "" {
		t.Fatalf("expected error for expired action")
	}
}
