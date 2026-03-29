package responseactions

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/controlplane"
)

type ExecuteOptions struct {
	ExpectedAgentID string
	AgentID         string
	BuildVersion    string
	Now             time.Time
}

type ExecuteResult struct {
	Status      string
	Result      map[string]interface{}
	Error       string
	StartedAt   time.Time
	FinishedAt  time.Time
	SkipReport  bool
	SkipHandled bool
}

func Execute(action controlplane.ResponseAction, opts ExecuteOptions) ExecuteResult {
	now := opts.Now.UTC()
	out := ExecuteResult{
		Status:    "failed",
		StartedAt: now,
	}
	defer func() {
		if out.FinishedAt.IsZero() {
			out.FinishedAt = time.Now().UTC()
		}
	}()

	if action.ID <= 0 {
		out.Error = "invalid action id"
		return out
	}
	if opts.ExpectedAgentID != "" && strings.TrimSpace(action.AgentID) != strings.TrimSpace(opts.ExpectedAgentID) {
		out.Error = "action agent does not match this agent"
		return out
	}
	if action.ExpiresAt != nil && !action.ExpiresAt.After(now) {
		out.Error = "action expired"
		return out
	}

	switch strings.ToLower(strings.TrimSpace(action.ActionType)) {
	case "collect_triage_bundle":
		result, err := buildTriageBundle(action, opts.AgentID, opts.BuildVersion, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	default:
		out.Error = fmt.Sprintf("unsupported action_type: %s", strings.TrimSpace(action.ActionType))
		return out
	}
}

func buildTriageBundle(action controlplane.ResponseAction, agentID string, buildVersion string, now time.Time) (map[string]interface{}, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	ifaceNames := make([]string, 0, 8)
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if strings.TrimSpace(iface.Name) == "" {
				continue
			}
			ifaceNames = append(ifaceNames, iface.Name)
			if len(ifaceNames) >= 16 {
				break
			}
		}
	}

	actionMeta := map[string]interface{}{
		"id":           action.ID,
		"action_type":  action.ActionType,
		"agent_id":     action.AgentID,
		"status":       action.Status,
		"requested_at": action.RequestedAt.UTC().Format(time.RFC3339),
		"expires_at":   nil,
	}
	if action.ExpiresAt != nil {
		actionMeta["expires_at"] = action.ExpiresAt.UTC().Format(time.RFC3339)
	}

	process := map[string]interface{}{
		"pid":         os.Getpid(),
		"goos":        runtime.GOOS,
		"goarch":      runtime.GOARCH,
		"go_version":  runtime.Version(),
		"gomaxprocs":  runtime.GOMAXPROCS(0),
		"num_cpu":     runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}

	out := map[string]interface{}{
		"schema_version": "v1",
		"collected_at":   now.UTC().Format(time.RFC3339),
		"agent_id":       strings.TrimSpace(agentID),
		"hostname":       hostname,
		"action":         actionMeta,
		"process":        process,
		"network": map[string]interface{}{
			"interface_count": len(interfaces),
			"interfaces":      ifaceNames,
		},
	}
	if strings.TrimSpace(buildVersion) != "" {
		out["agent_version"] = strings.TrimSpace(buildVersion)
	}
	return out, nil
}
