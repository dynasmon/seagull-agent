package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ActionCollectTriageBundle  = "collect_triage_bundle"
	ActionRefreshRuntimeConfig = "refresh_runtime_config"
	ActionTriggerInventory     = "trigger_inventory_snapshot"
	ActionTriggerTopology      = "trigger_topology_discovery"
	ActionKillProcess          = "kill_process"
	ActionBlockOutboundIP      = "block_outbound_ip"
	ActionUnblockOutboundIP    = "unblock_outbound_ip"
	ActionQuarantineFile       = "quarantine_file"
	ActionRunShellCommand      = "run_shell_command"
	ResponseActionPending      = "pending"
	ResponseActionDelivered    = "delivered"
)

var ErrInvalidResponseAction = errors.New("invalid response action")

type ResponseAction struct {
	ID          int64           `json:"id"`
	ActionType  string          `json:"action_type"`
	AgentID     string          `json:"agent_id"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	RequestedAt time.Time       `json:"requested_at"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

type ResponseActionList struct {
	Items   []ResponseAction `json:"items"`
	Actions []ResponseAction `json:"actions"`
}

type ResponseActionExecutionResult struct {
	ResponseActionID int64                  `json:"response_action_id"`
	AgentID          string                 `json:"agent_id,omitempty"`
	Status           string                 `json:"status"`
	ResultPayload    map[string]interface{} `json:"result_payload,omitempty"`
	Error            string                 `json:"error,omitempty"`
	StartedAt        *time.Time             `json:"started_at,omitempty"`
	FinishedAt       *time.Time             `json:"finished_at,omitempty"`
}

func (a *ResponseAction) Normalize() error {
	if a == nil {
		return fmt.Errorf("%w: nil action", ErrInvalidResponseAction)
	}
	a.ActionType = strings.ToLower(strings.TrimSpace(a.ActionType))
	a.AgentID = strings.TrimSpace(a.AgentID)
	a.Status = strings.ToLower(strings.TrimSpace(a.Status))

	if a.ID <= 0 {
		return fmt.Errorf("%w: invalid id", ErrInvalidResponseAction)
	}
	if a.ActionType == "" {
		return fmt.Errorf("%w: empty action_type", ErrInvalidResponseAction)
	}
	if a.AgentID == "" {
		return fmt.Errorf("%w: empty agent_id", ErrInvalidResponseAction)
	}
	if a.Status == "" {
		return fmt.Errorf("%w: empty status", ErrInvalidResponseAction)
	}
	if a.Status != ResponseActionPending && a.Status != ResponseActionDelivered {
		return fmt.Errorf("%w: unsupported status %q", ErrInvalidResponseAction, a.Status)
	}
	if a.RequestedAt.IsZero() {
		return fmt.Errorf("%w: empty requested_at", ErrInvalidResponseAction)
	}
	if len(strings.TrimSpace(string(a.Payload))) == 0 {
		a.Payload = json.RawMessage(`{}`)
	}
	return nil
}

func OrchestrationActions() []string {
	return []string{
		ActionCollectTriageBundle,
		ActionRefreshRuntimeConfig,
		ActionTriggerInventory,
		ActionTriggerTopology,
	}
}

func PrivilegedActions() []string {
	return []string{
		ActionKillProcess,
		ActionBlockOutboundIP,
		ActionUnblockOutboundIP,
		ActionQuarantineFile,
		ActionRunShellCommand,
	}
}

func AllActions() []string {
	out := append(OrchestrationActions(), PrivilegedActions()...)
	sort.Strings(out)
	return out
}

func SupportedActions(profile string) []string {
	if !ProfileAllowsResponseActions(profile) {
		return []string{}
	}
	return AllActions()
}

func IsPrivilegedAction(actionType string) bool {
	target := strings.ToLower(strings.TrimSpace(actionType))
	for _, name := range PrivilegedActions() {
		if name == target {
			return true
		}
	}
	return false
}

func IsKnownAction(actionType string) bool {
	target := strings.ToLower(strings.TrimSpace(actionType))
	for _, name := range AllActions() {
		if name == target {
			return true
		}
	}
	return false
}
