package responseactions

import (
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
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
	if out.Result["schema_version"] != "v2" {
		t.Fatalf("unexpected schema_version: %v", out.Result["schema_version"])
	}
	if _, ok := out.Result["runtime"]; !ok {
		t.Fatalf("expected runtime collector output")
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

func TestExecuteCollectTriageBundleWithCollectorPayload(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          94,
		ActionType:  "collect_triage_bundle",
		AgentID:     "agent-1",
		Status:      "delivered",
		RequestedAt: now,
		Payload: []byte(`{
			"collectors": {
				"runtime": true,
				"host": true,
				"processes": false,
				"network": false,
				"auth_log": false,
				"recent_events": true,
				"effective_config": true
			},
			"limits": {"max_event_count": 120},
			"redaction": {"mask_secrets": true}
		}`),
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		BuildVersion:    "0.1.0",
		EffectiveConfig: map[string]interface{}{
			"api_token": "secret-value",
		},
		Now: now,
	})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	cfg, ok := out.Result["effective_config"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected effective_config object")
	}
	if got, _ := cfg["api_token"].(string); got != "***" {
		t.Fatalf("expected redacted token, got %q", got)
	}
	if _, ok := out.Result["network"]; ok {
		t.Fatalf("expected network collector to be disabled")
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

func TestExecuteRefreshRuntimeConfigSuccess(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          95,
		ActionType:  "refresh_runtime_config",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		BuildVersion:    "0.1.0",
		RefreshRuntimeConfig: func() (bool, int, string, error) {
			return true, 12, "abc123", nil
		},
		Now: now,
	})
	if out.Status != "success" {
		t.Fatalf("expected success status, got %q error=%q", out.Status, out.Error)
	}
	if changed, _ := out.Result["changed"].(bool); !changed {
		t.Fatalf("expected changed=true")
	}
	if keys, _ := out.Result["config_keys"].(int); keys != 12 {
		t.Fatalf("expected config_keys=12, got %v", out.Result["config_keys"])
	}
}

func TestExecuteTriggerInventorySnapshotSuccess(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          96,
		ActionType:  "trigger_inventory_snapshot",
		AgentID:     "agent-1",
		Status:      "delivered",
		RequestedAt: now,
		Payload: []byte(`{
			"limits": {
				"max_processes": 32,
				"max_connections": 64
			}
		}`),
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		Now:             now,
	})
	if out.Status != "success" {
		t.Fatalf("expected success status, got %q error=%q", out.Status, out.Error)
	}
	if out.Result["schema_version"] != "v1" {
		t.Fatalf("unexpected schema_version: %v", out.Result["schema_version"])
	}
	if _, ok := out.Result["processes"]; !ok {
		t.Fatalf("expected processes in inventory snapshot")
	}
	if _, ok := out.Result["network"]; !ok {
		t.Fatalf("expected network in inventory snapshot")
	}
}

func TestExecuteTriggerTopologyDiscoverySuccess(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          97,
		ActionType:  "trigger_topology_discovery",
		AgentID:     "agent-1",
		Status:      "delivered",
		RequestedAt: now,
	}
	out := Execute(action, ExecuteOptions{
		ExpectedAgentID: "agent-1",
		AgentID:         "agent-1",
		RunTopologyDiscovery: func() (map[string]interface{}, error) {
			return map[string]interface{}{"discovered_hosts": []string{"10.0.0.2"}}, nil
		},
		Now: now,
	})
	if out.Status != "success" {
		t.Fatalf("expected success status, got %q error=%q", out.Status, out.Error)
	}
	if _, ok := out.Result["action"]; !ok {
		t.Fatalf("expected action metadata in result")
	}
}

func TestExecuteTriggerTopologyDiscoveryUnavailable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          98,
		ActionType:  "trigger_topology_discovery",
		AgentID:     "agent-1",
		Status:      "delivered",
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
}
