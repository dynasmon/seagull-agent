package responseactions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		ActionType:  "totally_unknown_action",
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

func startSleepProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start helper process: %v", err)
	}
	return cmd
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func killedEntries(t *testing.T, out ExecuteResult) []map[string]interface{} {
	t.Helper()
	killed, ok := out.Result["killed"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected killed entries, got %#v", out.Result["killed"])
	}
	return killed
}

func TestExecuteKillProcessByNameDryRunNoMatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          120,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"target":{"name":"seagull-no-such-process-xyz"},"signal":"SIGTERM","dry_run":true}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if dr, _ := out.Result["dry_run"].(bool); !dr {
		t.Fatalf("expected dry_run true")
	}
	if matched, _ := out.Result["matched"].(int); matched != 0 {
		t.Fatalf("expected 0 matches, got %v", out.Result["matched"])
	}
}

func TestExecuteKillProcessByPidDryRun(t *testing.T) {
	cmd := startSleepProcess(t)
	defer stopProcess(cmd)
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          121,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(fmt.Sprintf(`{"target":{"pid":%d},"signal":"SIGKILL","dry_run":true}`, cmd.Process.Pid)),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if matched, _ := out.Result["matched"].(int); matched != 1 {
		t.Fatalf("expected 1 match, got %v", out.Result["matched"])
	}
	killed := killedEntries(t, out)
	if len(killed) != 1 {
		t.Fatalf("expected one killed entry, got %#v", killed)
	}
	if ok, _ := killed[0]["ok"].(bool); !ok {
		t.Fatalf("expected dry-run entry ok=true")
	}
	if err := exec.Command("kill", "-0", fmt.Sprint(cmd.Process.Pid)).Run(); err != nil {
		t.Fatalf("dry run must not kill the process: %v", err)
	}
}

func TestExecuteKillProcessByPidReal(t *testing.T) {
	cmd := startSleepProcess(t)
	defer stopProcess(cmd)
	pid := cmd.Process.Pid
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          122,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(fmt.Sprintf(`{"target":{"pid":%d},"signal":"SIGKILL"}`, pid)),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	killed := killedEntries(t, out)
	if len(killed) != 1 {
		t.Fatalf("expected one killed entry, got %#v", killed)
	}
	if okFlag, _ := killed[0]["ok"].(bool); !okFlag {
		t.Fatalf("expected kill ok=true, entry=%#v", killed[0])
	}
}

func TestExecuteKillProcessRejectsSelf(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          123,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(fmt.Sprintf(`{"target":{"pid":%d},"signal":"SIGTERM"}`, os.Getpid())),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestExecuteKillProcessInvalidSignal(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          124,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"target":{"pid":4321},"signal":"SIGBOGUS"}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestExecuteKillProcessRequiresTarget(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          125,
		ActionType:  "kill_process",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"signal":"SIGTERM"}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestExecuteBlockOutboundIPDryRunIptables(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          130,
		ActionType:  "block_outbound_ip",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"ip":"185.220.101.45","port":4444,"protocol":"tcp","comment":"c2_block_incident_42","dry_run":true}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", FirewallTool: "iptables", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if added, _ := out.Result["rule_added"].(bool); added {
		t.Fatalf("dry run must not add a rule")
	}
	if tool, _ := out.Result["firewall_tool"].(string); tool != "iptables" {
		t.Fatalf("expected iptables tool, got %v", out.Result["firewall_tool"])
	}
	rule, _ := out.Result["rule_text"].(string)
	for _, want := range []string{"iptables -A OUTPUT", "-d 185.220.101.45", "-p tcp", "--dport 4444", "-j DROP", "--comment c2_block_incident_42"} {
		if !strings.Contains(rule, want) {
			t.Fatalf("rule_text missing %q: %s", want, rule)
		}
	}
}

func TestExecuteBlockOutboundIPv6DryRun(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          131,
		ActionType:  "block_outbound_ip",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"ip":"2001:db8::1","dry_run":true}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", FirewallTool: "iptables", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	rule, _ := out.Result["rule_text"].(string)
	if !strings.HasPrefix(rule, "ip6tables ") {
		t.Fatalf("expected ip6tables rule, got %s", rule)
	}
	if !strings.Contains(rule, "2001:db8::1") {
		t.Fatalf("rule_text missing ipv6 address: %s", rule)
	}
}

func TestExecuteBlockOutboundIPDryRunNft(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          132,
		ActionType:  "block_outbound_ip",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"ip":"185.220.101.45","port":53,"protocol":"udp","comment":"dns_block","dry_run":true}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", FirewallTool: "nft", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if tool, _ := out.Result["firewall_tool"].(string); tool != "nft" {
		t.Fatalf("expected nft tool, got %v", out.Result["firewall_tool"])
	}
	rule, _ := out.Result["rule_text"].(string)
	for _, want := range []string{"nft add rule inet seagull output", "ip daddr 185.220.101.45", "udp dport 53", "drop", `comment "dns_block"`} {
		if !strings.Contains(rule, want) {
			t.Fatalf("nft rule_text missing %q: %s", want, rule)
		}
	}
}

func TestExecuteBlockOutboundIPRejectsBadIP(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          133,
		ActionType:  "block_outbound_ip",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"ip":"not-an-ip","dry_run":true}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", FirewallTool: "iptables", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestExecuteBlockOutboundIPRejectsMissingIP(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          134,
		ActionType:  "block_outbound_ip",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"port":80,"protocol":"tcp"}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", FirewallTool: "iptables", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestExecuteUnblockOutboundIPDryRun(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          136,
		ActionType:  "unblock_outbound_ip",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"ip":"185.220.101.45","port":4444,"protocol":"tcp","comment":"c2_block_incident_42","dry_run":true}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", FirewallTool: "iptables", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if removed, _ := out.Result["rules_removed"].(int); removed != 0 {
		t.Fatalf("dry run must not remove rules, got %v", out.Result["rules_removed"])
	}
	rule, _ := out.Result["rule_text"].(string)
	if !strings.Contains(rule, "iptables -D OUTPUT") {
		t.Fatalf("expected delete rule preview, got %s", rule)
	}
}

func TestExecuteQuarantineFileDryRun(t *testing.T) {
	dir := t.TempDir()
	if err := validateQuarantinePath(filepath.Join(dir, "x")); err != nil {
		t.Skipf("temp dir under protected prefix: %v", err)
	}
	target := filepath.Join(dir, "evil.sh")
	content := []byte("#!/bin/sh\necho pwned\n")
	if err := os.WriteFile(target, content, 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatalf("chmod target: %v", err)
	}
	qdir := filepath.Join(dir, "quarantine")
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          140,
		ActionType:  "quarantine_file",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(fmt.Sprintf(`{"path":%q,"quarantine_dir":%q,"compute_hash":true,"dry_run":true}`, target, qdir)),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if q, _ := out.Result["quarantined"].(bool); q {
		t.Fatalf("dry run must not move the file")
	}
	expected := sha256.Sum256(content)
	if sum, _ := out.Result["sha256"].(string); sum != hex.EncodeToString(expected[:]) {
		t.Fatalf("sha256 mismatch: %v", out.Result["sha256"])
	}
	if perm, _ := out.Result["permissions_before"].(string); perm != "0755" {
		t.Fatalf("expected 0755, got %v", out.Result["permissions_before"])
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("dry run must leave the original in place: %v", err)
	}
}

func TestExecuteQuarantineFileReal(t *testing.T) {
	dir := t.TempDir()
	if err := validateQuarantinePath(filepath.Join(dir, "x")); err != nil {
		t.Skipf("temp dir under protected prefix: %v", err)
	}
	target := filepath.Join(dir, "evil.bin")
	content := []byte("malicious-bytes-1234567890")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	qdir := filepath.Join(dir, "q")
	now := time.Now().UTC().Truncate(time.Second)
	action := controlplane.ResponseAction{
		ID:          141,
		ActionType:  "quarantine_file",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(fmt.Sprintf(`{"path":%q,"quarantine_dir":%q,"compute_hash":true}`, target, qdir)),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "success" {
		t.Fatalf("expected success, got %q error=%q", out.Status, out.Error)
	}
	if q, _ := out.Result["quarantined"].(bool); !q {
		t.Fatalf("expected quarantined true")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("original file should be gone, stat err=%v", err)
	}
	dest, _ := out.Result["quarantine_path"].(string)
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("quarantine file missing: %v", err)
	}
	if info.Mode().Perm() != 0o000 {
		t.Fatalf("expected 0000 perms, got %04o", info.Mode().Perm())
	}
	expected := sha256.Sum256(content)
	if sum, _ := out.Result["sha256"].(string); sum != hex.EncodeToString(expected[:]) {
		t.Fatalf("sha256 mismatch")
	}
}

func TestExecuteQuarantineFileRejectsProtectedPath(t *testing.T) {
	now := time.Now().UTC()
	action := controlplane.ResponseAction{
		ID:          142,
		ActionType:  "quarantine_file",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(`{"path":"/etc/hosts"}`),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestExecuteQuarantineFileRejectsMissing(t *testing.T) {
	now := time.Now().UTC()
	missing := filepath.Join(t.TempDir(), "nope.bin")
	action := controlplane.ResponseAction{
		ID:          143,
		ActionType:  "quarantine_file",
		AgentID:     "agent-1",
		Status:      "pending",
		RequestedAt: now,
		Payload:     []byte(fmt.Sprintf(`{"path":%q}`, missing)),
	}
	out := Execute(action, ExecuteOptions{ExpectedAgentID: "agent-1", AgentID: "agent-1", Now: now})
	if out.Status != "failed" {
		t.Fatalf("expected failed status, got %q", out.Status)
	}
}

func TestParseNftHandles(t *testing.T) {
	sample := strings.Join([]string{
		"table inet seagull {",
		"  chain output {",
		`    ip daddr 185.220.101.45 tcp dport 4444 drop comment "c2_block" # handle 7`,
		`    ip daddr 9.9.9.9 drop comment "other_block" # handle 9`,
		"  }",
		"}",
	}, "\n")
	got := parseNftHandles(sample, "c2_block")
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("expected [7], got %v", got)
	}
	if h := parseNftHandles(sample, "missing"); len(h) != 0 {
		t.Fatalf("expected no handles, got %v", h)
	}
}

func TestSanitizeFirewallComment(t *testing.T) {
	raw := "c2 block; rm -rf /"
	got := sanitizeFirewallComment(&raw)
	if strings.ContainsAny(got, " ;/") {
		t.Fatalf("comment not sanitized: %q", got)
	}
	if got == "" {
		t.Fatalf("expected non-empty fallback")
	}
	empty := ""
	if def := sanitizeFirewallComment(&empty); def != "seagull_block" {
		t.Fatalf("expected default comment, got %q", def)
	}
}

func TestDetectFirewallTool(t *testing.T) {
	switch DetectFirewallTool() {
	case "", "iptables", "nft":
	default:
		t.Fatalf("unexpected firewall tool")
	}
}
