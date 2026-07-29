package responseactions

import (
	"testing"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
)

func TestSensorProfileRefusesResponseActions(t *testing.T) {
	action := controlplane.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Profile:         agentcfg.ProfileSensor,
		Now:             time.Now().UTC(),
	})
	if res.Status != "failed" {
		t.Fatalf("expected sensor profile to fail the action, got status=%s", res.Status)
	}
	if res.Error != "agent profile does not allow response actions" {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestManagedProfileExecutesResponseActions(t *testing.T) {
	action := controlplane.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Profile:         agentcfg.ProfileManaged,
		Now:             time.Now().UTC(),
	})
	if res.Error == "agent profile does not allow response actions" {
		t.Fatal("managed profile must not be blocked by the profile gate")
	}
}

func TestEmptyProfileKeepsLegacyBehavior(t *testing.T) {
	action := controlplane.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Now:             time.Now().UTC(),
	})
	if res.Error == "agent profile does not allow response actions" {
		t.Fatal("unset profile must not disable response actions on upgraded installs")
	}
}
