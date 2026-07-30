package responseactions

import (
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent/protocol"
)

func TestSensorProfileRefusesResponseActions(t *testing.T) {
	action := protocol.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Profile:         protocol.ProfileSensor,
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
	action := protocol.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Profile:         protocol.ProfileManaged,
		Now:             time.Now().UTC(),
	})
	if res.Error == "agent profile does not allow response actions" {
		t.Fatal("managed profile must not be blocked by the profile gate")
	}
}

func TestUnsetProfileFailsClosed(t *testing.T) {
	action := protocol.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Now:             time.Now().UTC(),
	})
	if res.Status != "failed" {
		t.Fatalf("expected an unset profile to fail closed, got status=%s", res.Status)
	}
	if res.Error != "agent profile does not allow response actions" {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestUnknownProfileFailsClosed(t *testing.T) {
	action := protocol.ResponseAction{
		ID:         42,
		AgentID:    "agent-test-1",
		ActionType: "agent_ping",
	}
	res := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-test-1",
		AgentID:         "agent-test-1",
		Profile:         "supervisor",
		Now:             time.Now().UTC(),
	})
	if res.Error != "agent profile does not allow response actions" {
		t.Fatalf("expected an unknown profile to fail closed, got %q", res.Error)
	}
}

func TestPrivilegedActionsRequireManagedProfile(t *testing.T) {
	for _, actionType := range protocol.PrivilegedActions() {
		res := Execute(protocol.ResponseAction{
			ID:         7,
			AgentID:    "agent-test-1",
			ActionType: actionType,
		}, ExecuteOptions{
			ExpectedAgentID: "agent-test-1",
			AgentID:         "agent-test-1",
			Profile:         protocol.ProfileSensor,
			AllowShellExec:  true,
			Now:             time.Now().UTC(),
		})
		if res.Status != "failed" || res.Error != "agent profile does not allow response actions" {
			t.Fatalf("sensor profile executed privileged action %q: status=%s error=%q", actionType, res.Status, res.Error)
		}
	}
}

func TestSupportedActionsIsEmptyForSensor(t *testing.T) {
	if got := protocol.SupportedActions(protocol.ProfileSensor); len(got) != 0 {
		t.Fatalf("sensor profile must advertise no response actions, got %v", got)
	}
	if got := protocol.SupportedActions(protocol.ProfileManaged); len(got) == 0 {
		t.Fatal("managed profile must advertise response actions")
	}
}
