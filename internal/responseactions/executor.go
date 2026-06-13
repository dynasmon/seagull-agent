package responseactions

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
)

type ExecuteOptions struct {
	ExpectedAgentID      string
	AgentID              string
	BuildVersion         string
	EffectiveConfig      map[string]interface{}
	ModuleStates         map[string]interface{}
	RefreshRuntimeConfig func() (changed bool, configKeys int, configHash string, err error)
	RunTopologyDiscovery func() (map[string]interface{}, error)
	AgentStartedAt       time.Time
	Now                  time.Time
	FirewallTool         string
	AllowShellExec       bool
	ShellExecAllowlist   []string
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

type triageBundleOptions struct {
	Collectors struct {
		Runtime         bool
		Host            bool
		Processes       bool
		Network         bool
		AuthLog         bool
		RecentEvents    bool
		EffectiveConfig bool
	}
	Limits struct {
		MaxAuthLogLines int
		MaxProcesses    int
		MaxConnections  int
		MaxEventCount   int
	}
	Redaction struct {
		MaskSecrets bool
	}
}

type inventorySnapshotOptions struct {
	Limits struct {
		MaxProcesses   int
		MaxConnections int
	}
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
		result, err := buildTriageBundle(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "refresh_runtime_config":
		result, err := runRefreshRuntimeConfig(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "trigger_inventory_snapshot":
		result, err := buildInventorySnapshot(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "trigger_topology_discovery":
		result, err := runTopologyDiscovery(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "kill_process":
		result, err := runKillProcess(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "block_outbound_ip":
		result, err := runBlockOutboundIP(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "unblock_outbound_ip":
		result, err := runUnblockOutboundIP(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "quarantine_file":
		result, err := runQuarantineFile(action, opts, now)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		out.Status = "success"
		out.Result = result
		out.Error = ""
		return out
	case "run_shell_command":
		result, err := runShellCommand(action, opts, now)
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

func runTopologyDiscovery(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	if opts.RunTopologyDiscovery == nil {
		return nil, fmt.Errorf("trigger_topology_discovery is not available")
	}
	result, err := opts.RunTopologyDiscovery()
	if err != nil {
		return nil, err
	}
	if result == nil {
		result = map[string]interface{}{}
	}
	result["action"] = actionMeta(action)
	result["requested_at"] = now.UTC().Format(time.RFC3339)
	return result, nil
}

func runRefreshRuntimeConfig(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	if opts.RefreshRuntimeConfig == nil {
		return nil, fmt.Errorf("refresh_runtime_config is not available")
	}
	changed, configKeys, configHash, err := opts.RefreshRuntimeConfig()
	if err != nil {
		return nil, fmt.Errorf("refresh runtime config failed: %w", err)
	}
	out := map[string]interface{}{
		"schema_version": "v1",
		"refreshed_at":   now.UTC().Format(time.RFC3339),
		"changed":        changed,
		"config_keys":    configKeys,
		"config_hash":    strings.TrimSpace(configHash),
		"action":         actionMeta(action),
	}
	if strings.TrimSpace(opts.BuildVersion) != "" {
		out["agent_version"] = strings.TrimSpace(opts.BuildVersion)
	}
	return out, nil
}

func buildInventorySnapshot(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	snapshotOpts, err := parseInventorySnapshotOptions(action.Payload)
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	interfaces, _ := net.Interfaces()

	runtimeMeta := map[string]interface{}{
		"pid":           os.Getpid(),
		"goos":          runtime.GOOS,
		"goarch":        runtime.GOARCH,
		"go_version":    runtime.Version(),
		"gomaxprocs":    runtime.GOMAXPROCS(0),
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}
	out := map[string]interface{}{
		"schema_version": "v1",
		"collected_at":   now.UTC().Format(time.RFC3339),
		"agent_id":       strings.TrimSpace(opts.AgentID),
		"hostname":       hostname,
		"action":         actionMeta(action),
		"requested": map[string]interface{}{
			"limits": map[string]interface{}{
				"max_processes":   snapshotOpts.Limits.MaxProcesses,
				"max_connections": snapshotOpts.Limits.MaxConnections,
			},
		},
		"runtime":   runtimeMeta,
		"host":      collectHostSnapshot(hostname, interfaces),
		"processes": collectProcessSnapshot(snapshotOpts.Limits.MaxProcesses),
		"network":   collectNetworkSnapshot(snapshotOpts.Limits.MaxConnections, interfaces),
	}
	if strings.TrimSpace(opts.BuildVersion) != "" {
		out["agent_version"] = strings.TrimSpace(opts.BuildVersion)
	}
	if !opts.AgentStartedAt.IsZero() {
		out["agent_uptime_seconds"] = int(now.Sub(opts.AgentStartedAt.UTC()).Seconds())
	}

	modules := map[string]interface{}{}
	for k, v := range opts.ModuleStates {
		modules[k] = v
	}
	out["modules"] = modules
	return out, nil
}

func actionMeta(action controlplane.ResponseAction) map[string]interface{} {
	out := map[string]interface{}{
		"id":           action.ID,
		"action_type":  action.ActionType,
		"agent_id":     action.AgentID,
		"status":       action.Status,
		"requested_at": action.RequestedAt.UTC().Format(time.RFC3339),
		"expires_at":   nil,
	}
	if action.ExpiresAt != nil {
		out["expires_at"] = action.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return out
}

func buildTriageBundle(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	bundleOpts, err := parseTriageBundleOptions(action.Payload)
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	interfaces, _ := net.Interfaces()

	runtimeMeta := map[string]interface{}{
		"pid":           os.Getpid(),
		"goos":          runtime.GOOS,
		"goarch":        runtime.GOARCH,
		"go_version":    runtime.Version(),
		"gomaxprocs":    runtime.GOMAXPROCS(0),
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}

	out := map[string]interface{}{
		"schema_version": "v2",
		"collected_at":   now.UTC().Format(time.RFC3339),
		"agent_id":       strings.TrimSpace(opts.AgentID),
		"action":         actionMeta(action),
		"requested": map[string]interface{}{
			"collectors": map[string]interface{}{
				"runtime":          bundleOpts.Collectors.Runtime,
				"host":             bundleOpts.Collectors.Host,
				"processes":        bundleOpts.Collectors.Processes,
				"network":          bundleOpts.Collectors.Network,
				"auth_log":         bundleOpts.Collectors.AuthLog,
				"recent_events":    bundleOpts.Collectors.RecentEvents,
				"effective_config": bundleOpts.Collectors.EffectiveConfig,
			},
			"limits": map[string]interface{}{
				"max_auth_log_lines": bundleOpts.Limits.MaxAuthLogLines,
				"max_processes":      bundleOpts.Limits.MaxProcesses,
				"max_connections":    bundleOpts.Limits.MaxConnections,
				"max_event_count":    bundleOpts.Limits.MaxEventCount,
			},
			"redaction": map[string]interface{}{
				"mask_secrets": bundleOpts.Redaction.MaskSecrets,
			},
		},
	}
	if strings.TrimSpace(opts.BuildVersion) != "" {
		out["agent_version"] = strings.TrimSpace(opts.BuildVersion)
	}
	if !opts.AgentStartedAt.IsZero() {
		out["agent_uptime_seconds"] = int(now.Sub(opts.AgentStartedAt.UTC()).Seconds())
	}
	out["hostname"] = hostname

	if bundleOpts.Collectors.Runtime {
		out["runtime"] = runtimeMeta
	}
	if bundleOpts.Collectors.Host {
		out["host"] = collectHostSnapshot(hostname, interfaces)
	}
	if bundleOpts.Collectors.Processes {
		out["processes"] = collectProcessSnapshot(bundleOpts.Limits.MaxProcesses)
	}
	if bundleOpts.Collectors.Network {
		out["network"] = collectNetworkSnapshot(bundleOpts.Limits.MaxConnections, interfaces)
	}
	if bundleOpts.Collectors.AuthLog {
		authLog, source := collectAuthLogLines(bundleOpts.Limits.MaxAuthLogLines)
		out["auth_log"] = map[string]interface{}{
			"source": source,
			"lines":  authLog,
		}
	}
	if bundleOpts.Collectors.RecentEvents {
		out["recent_events"] = map[string]interface{}{
			"available":       false,
			"reason":          "local_event_buffer_not_exposed",
			"requested_limit": bundleOpts.Limits.MaxEventCount,
		}
	}
	if bundleOpts.Collectors.EffectiveConfig {
		cfg := map[string]interface{}{}
		for k, v := range opts.EffectiveConfig {
			cfg[k] = v
		}
		out["effective_config"] = cfg
	}

	// Add execution metadata independent of selected collectors.
	modules := map[string]interface{}{}
	for k, v := range opts.ModuleStates {
		modules[k] = v
	}
	out["modules"] = modules

	if bundleOpts.Redaction.MaskSecrets {
		out = redactAny(out).(map[string]interface{})
	}

	return out, nil
}

func parseTriageBundleOptions(raw json.RawMessage) (triageBundleOptions, error) {
	out := triageBundleOptions{}
	out.Collectors.Runtime = true
	out.Collectors.Host = true
	out.Collectors.Processes = true
	out.Collectors.Network = true
	out.Collectors.AuthLog = true
	out.Collectors.RecentEvents = true
	out.Collectors.EffectiveConfig = true
	out.Limits.MaxAuthLogLines = 500
	out.Limits.MaxProcesses = 200
	out.Limits.MaxConnections = 200
	out.Limits.MaxEventCount = 300
	out.Redaction.MaskSecrets = true

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return out, nil
	}

	var payload struct {
		Collectors struct {
			Runtime         *bool `json:"runtime"`
			Host            *bool `json:"host"`
			Processes       *bool `json:"processes"`
			Network         *bool `json:"network"`
			AuthLog         *bool `json:"auth_log"`
			RecentEvents    *bool `json:"recent_events"`
			EffectiveConfig *bool `json:"effective_config"`
		} `json:"collectors"`
		Limits struct {
			MaxAuthLogLines *int `json:"max_auth_log_lines"`
			MaxProcesses    *int `json:"max_processes"`
			MaxConnections  *int `json:"max_connections"`
			MaxEventCount   *int `json:"max_event_count"`
		} `json:"limits"`
		Redaction struct {
			MaskSecrets *bool `json:"mask_secrets"`
		} `json:"redaction"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, fmt.Errorf("invalid payload JSON: %w", err)
	}

	if payload.Collectors.Runtime != nil {
		out.Collectors.Runtime = *payload.Collectors.Runtime
	}
	if payload.Collectors.Host != nil {
		out.Collectors.Host = *payload.Collectors.Host
	}
	if payload.Collectors.Processes != nil {
		out.Collectors.Processes = *payload.Collectors.Processes
	}
	if payload.Collectors.Network != nil {
		out.Collectors.Network = *payload.Collectors.Network
	}
	if payload.Collectors.AuthLog != nil {
		out.Collectors.AuthLog = *payload.Collectors.AuthLog
	}
	if payload.Collectors.RecentEvents != nil {
		out.Collectors.RecentEvents = *payload.Collectors.RecentEvents
	}
	if payload.Collectors.EffectiveConfig != nil {
		out.Collectors.EffectiveConfig = *payload.Collectors.EffectiveConfig
	}
	if payload.Redaction.MaskSecrets != nil {
		out.Redaction.MaskSecrets = *payload.Redaction.MaskSecrets
	}
	if payload.Limits.MaxAuthLogLines != nil {
		out.Limits.MaxAuthLogLines = clamp(*payload.Limits.MaxAuthLogLines, 10, 5000)
	}
	if payload.Limits.MaxProcesses != nil {
		out.Limits.MaxProcesses = clamp(*payload.Limits.MaxProcesses, 10, 2000)
	}
	if payload.Limits.MaxConnections != nil {
		out.Limits.MaxConnections = clamp(*payload.Limits.MaxConnections, 10, 2000)
	}
	if payload.Limits.MaxEventCount != nil {
		out.Limits.MaxEventCount = clamp(*payload.Limits.MaxEventCount, 10, 5000)
	}
	return out, nil
}

func parseInventorySnapshotOptions(raw json.RawMessage) (inventorySnapshotOptions, error) {
	out := inventorySnapshotOptions{}
	out.Limits.MaxProcesses = 200
	out.Limits.MaxConnections = 200

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return out, nil
	}

	var payload struct {
		Limits struct {
			MaxProcesses   *int `json:"max_processes"`
			MaxConnections *int `json:"max_connections"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, fmt.Errorf("invalid payload JSON: %w", err)
	}
	if payload.Limits.MaxProcesses != nil {
		out.Limits.MaxProcesses = clamp(*payload.Limits.MaxProcesses, 10, 2000)
	}
	if payload.Limits.MaxConnections != nil {
		out.Limits.MaxConnections = clamp(*payload.Limits.MaxConnections, 10, 2000)
	}
	return out, nil
}

func collectHostSnapshot(hostname string, interfaces []net.Interface) map[string]interface{} {
	out := map[string]interface{}{
		"hostname": hostname,
		"goos":     runtime.GOOS,
		"goarch":   runtime.GOARCH,
	}
	ifaces := make([]map[string]interface{}, 0, len(interfaces))
	for _, iface := range interfaces {
		if strings.TrimSpace(iface.Name) == "" {
			continue
		}
		addrs, _ := iface.Addrs()
		ips := make([]string, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, strings.TrimSpace(a.String()))
			if len(ips) >= 8 {
				break
			}
		}
		ifaces = append(ifaces, map[string]interface{}{
			"name":  iface.Name,
			"mtu":   iface.MTU,
			"flags": iface.Flags.String(),
			"ips":   ips,
		})
		if len(ifaces) >= 32 {
			break
		}
	}
	out["interfaces"] = ifaces
	return out
}

func collectProcessSnapshot(limit int) []map[string]interface{} {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, clamp(limit, 1, 2000))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		comm, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		statusBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		state := ""
		uid := ""
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if strings.HasPrefix(line, "State:") {
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
			}
			if strings.HasPrefix(line, "Uid:") {
				uid = strings.TrimSpace(strings.TrimPrefix(line, "Uid:"))
			}
		}
		out = append(out, map[string]interface{}{
			"pid":   pid,
			"name":  strings.TrimSpace(string(comm)),
			"state": state,
			"uid":   uid,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		pi, _ := out[i]["pid"].(int)
		pj, _ := out[j]["pid"].(int)
		return pi > pj
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func collectNetworkSnapshot(limit int, interfaces []net.Interface) map[string]interface{} {
	out := map[string]interface{}{
		"interface_count": len(interfaces),
	}
	maxRows := clamp(limit, 1, 2000)
	out["tcp"] = parseProcNetTable("/proc/net/tcp", "tcp", maxRows)
	out["tcp6"] = parseProcNetTable("/proc/net/tcp6", "tcp6", maxRows)
	out["udp"] = parseProcNetTable("/proc/net/udp", "udp", maxRows)
	out["udp6"] = parseProcNetTable("/proc/net/udp6", "udp6", maxRows)
	return out
}

func parseProcNetTable(path string, proto string, limit int) []map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer f.Close()

	out := make([]map[string]interface{}, 0, limit)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if lineNo == 1 && strings.Contains(strings.ToLower(line), "local_address") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localIP, localPort := decodeProcAddress(fields[1])
		remoteIP, remotePort := decodeProcAddress(fields[2])
		out = append(out, map[string]interface{}{
			"proto":       proto,
			"local_ip":    localIP,
			"local_port":  localPort,
			"remote_ip":   remoteIP,
			"remote_port": remotePort,
			"state":       fields[3],
			"inode":       fields[9],
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func decodeProcAddress(raw string) (string, int) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return raw, 0
	}
	addrHex := strings.TrimSpace(parts[0])
	portHex := strings.TrimSpace(parts[1])
	portN, _ := strconv.ParseUint(portHex, 16, 16)

	// IPv4 addresses are little-endian in /proc/net/tcp.
	if len(addrHex) == 8 {
		b, err := hex.DecodeString(addrHex)
		if err == nil && len(b) == 4 {
			ip := net.IPv4(b[3], b[2], b[1], b[0]).String()
			return ip, int(portN)
		}
	}
	// Keep IPv6 raw hex if parsing is not straightforward.
	return addrHex, int(portN)
}

func collectAuthLogLines(limit int) ([]string, string) {
	candidates := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}
	for _, path := range candidates {
		lines, ok := readAuthLog(path, limit)
		if ok {
			return lines, path
		}
	}
	return []string{}, ""
}

func readAuthLog(path string, limit int) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	q := make([]string, 0, limit)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lc := strings.ToLower(line)
		if !strings.Contains(lc, "ssh") && !strings.Contains(lc, "sudo") && !strings.Contains(lc, "auth") {
			continue
		}
		q = append(q, line)
		if len(q) > limit {
			q = q[1:]
		}
	}
	return q, true
}

func redactAny(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			lk := strings.ToLower(strings.TrimSpace(k))
			if strings.Contains(lk, "secret") ||
				strings.Contains(lk, "token") ||
				strings.Contains(lk, "password") ||
				strings.Contains(lk, "credential") ||
				(strings.Contains(lk, "key") && lk != "keys") {
				out[k] = "***"
				continue
			}
			out[k] = redactAny(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(x))
		for _, item := range x {
			out = append(out, redactAny(item))
		}
		return out
	default:
		return v
	}
}

func clamp(v int, min int, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

const (
	nftTableName = "seagull"
	nftChainName = "output"
)

type killProcessPayload struct {
	pid        int
	name       string
	byName     bool
	signal     syscall.Signal
	signalName string
	dryRun     bool
}

type killTarget struct {
	pid  int
	name string
}

func runKillProcess(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	p, err := parseKillProcessPayload(action.Payload)
	if err != nil {
		return nil, err
	}
	targets, err := resolveKillTargets(p)
	if err != nil {
		return nil, err
	}
	killed := make([]map[string]interface{}, 0, len(targets))
	failures := make([]string, 0)
	for _, tgt := range targets {
		entry := map[string]interface{}{
			"pid":    tgt.pid,
			"name":   tgt.name,
			"signal": p.signalName,
		}
		if p.dryRun {
			entry["ok"] = true
			killed = append(killed, entry)
			continue
		}
		if kerr := syscall.Kill(tgt.pid, p.signal); kerr != nil {
			entry["ok"] = false
			entry["error"] = kerr.Error()
			failures = append(failures, fmt.Sprintf("pid %d: %s", tgt.pid, kerr.Error()))
		} else {
			entry["ok"] = true
		}
		killed = append(killed, entry)
	}
	return map[string]interface{}{
		"schema_version": "v1",
		"executed_at":    now.UTC().Format(time.RFC3339),
		"action":         actionMeta(action),
		"signal":         p.signalName,
		"matched":        len(targets),
		"killed":         killed,
		"errors":         failures,
		"dry_run":        p.dryRun,
	}, nil
}

func parseKillProcessPayload(raw json.RawMessage) (killProcessPayload, error) {
	out := killProcessPayload{}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return out, fmt.Errorf("payload.target is required")
	}
	var payload struct {
		Target struct {
			PID  *int    `json:"pid"`
			Name *string `json:"name"`
		} `json:"target"`
		Signal *string `json:"signal"`
		DryRun *bool   `json:"dry_run"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, fmt.Errorf("invalid payload JSON: %w", err)
	}
	hasPID := payload.Target.PID != nil
	hasName := payload.Target.Name != nil && strings.TrimSpace(*payload.Target.Name) != ""
	if hasPID == hasName {
		return out, fmt.Errorf("payload.target requires exactly one of pid or name")
	}
	if hasPID {
		if *payload.Target.PID <= 1 {
			return out, fmt.Errorf("payload.target.pid must be greater than 1")
		}
		out.pid = *payload.Target.PID
	} else {
		out.byName = true
		out.name = strings.TrimSpace(*payload.Target.Name)
	}
	sig, sigName, err := parseSignal(payload.Signal)
	if err != nil {
		return out, err
	}
	out.signal = sig
	out.signalName = sigName
	if payload.DryRun != nil {
		out.dryRun = *payload.DryRun
	}
	return out, nil
}

func parseSignal(raw *string) (syscall.Signal, string, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return syscall.SIGTERM, "SIGTERM", nil
	}
	s := strings.ToUpper(strings.TrimSpace(*raw))
	if !strings.HasPrefix(s, "SIG") {
		s = "SIG" + s
	}
	known := map[string]syscall.Signal{
		"SIGTERM": syscall.SIGTERM,
		"SIGKILL": syscall.SIGKILL,
		"SIGINT":  syscall.SIGINT,
		"SIGHUP":  syscall.SIGHUP,
		"SIGQUIT": syscall.SIGQUIT,
		"SIGSTOP": syscall.SIGSTOP,
		"SIGCONT": syscall.SIGCONT,
		"SIGUSR1": syscall.SIGUSR1,
		"SIGUSR2": syscall.SIGUSR2,
	}
	sig, ok := known[s]
	if !ok {
		return 0, "", fmt.Errorf("unsupported signal: %s", strings.TrimSpace(*raw))
	}
	return sig, s, nil
}

func resolveKillTargets(p killProcessPayload) ([]killTarget, error) {
	self := os.Getpid()
	ppid := os.Getppid()
	if !p.byName {
		if p.pid == self {
			return nil, fmt.Errorf("refusing to target the agent process")
		}
		if p.pid == ppid {
			return nil, fmt.Errorf("refusing to target a protected system process")
		}
		return []killTarget{{pid: p.pid, name: processNameByPID(p.pid)}}, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc failed: %w", err)
	}
	targets := make([]killTarget, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, perr := strconv.Atoi(entry.Name())
		if perr != nil || pid <= 1 || pid == self {
			continue
		}
		name := processNameByPID(pid)
		if processMatchesName(pid, name, p.name) {
			if pid == ppid {
				return nil, fmt.Errorf("refusing to target a protected system process")
			}
			targets = append(targets, killTarget{pid: pid, name: name})
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].pid < targets[j].pid })
	return targets, nil
}

func processNameByPID(pid int) string {
	comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}

func processMatchesName(pid int, comm string, want string) bool {
	if comm != "" && comm == want {
		return true
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(cmdline) == 0 {
		return false
	}
	first := string(cmdline)
	if idx := strings.IndexByte(first, 0); idx >= 0 {
		first = first[:idx]
	}
	first = strings.TrimSpace(first)
	if first == "" {
		return false
	}
	return filepath.Base(first) == want
}

type firewallPayload struct {
	ip       string
	isV6     bool
	port     int
	protocol string
	comment  string
	dryRun   bool
}

func parseFirewallPayload(raw json.RawMessage) (firewallPayload, error) {
	out := firewallPayload{}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return out, fmt.Errorf("payload.ip is required")
	}
	var payload struct {
		IP       *string `json:"ip"`
		Port     *int    `json:"port"`
		Protocol *string `json:"protocol"`
		Comment  *string `json:"comment"`
		DryRun   *bool   `json:"dry_run"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, fmt.Errorf("invalid payload JSON: %w", err)
	}
	if payload.IP == nil || strings.TrimSpace(*payload.IP) == "" {
		return out, fmt.Errorf("payload.ip is required")
	}
	ip := net.ParseIP(strings.TrimSpace(*payload.IP))
	if ip == nil {
		return out, fmt.Errorf("payload.ip is not a valid IP address")
	}
	out.ip = ip.String()
	out.isV6 = ip.To4() == nil
	if payload.Protocol != nil {
		proto := strings.ToLower(strings.TrimSpace(*payload.Protocol))
		if proto != "" && proto != "tcp" && proto != "udp" {
			return out, fmt.Errorf("payload.protocol must be tcp or udp")
		}
		out.protocol = proto
	}
	if payload.Port != nil {
		port := *payload.Port
		if port < 1 || port > 65535 {
			return out, fmt.Errorf("payload.port must be between 1 and 65535")
		}
		if out.protocol == "" {
			out.protocol = "tcp"
		}
		out.port = port
	}
	out.comment = sanitizeFirewallComment(payload.Comment)
	if payload.DryRun != nil {
		out.dryRun = *payload.DryRun
	}
	return out, nil
}

func sanitizeFirewallComment(raw *string) string {
	def := "seagull_block"
	if raw == nil {
		return def
	}
	var b strings.Builder
	for _, r := range strings.TrimSpace(*raw) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == ':' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return def
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func DetectFirewallTool() string {
	for _, name := range []string{"iptables", "nft"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

func resolveFirewallTool(opts ExecuteOptions) string {
	if t := strings.ToLower(strings.TrimSpace(opts.FirewallTool)); t == "iptables" || t == "nft" {
		return t
	}
	return DetectFirewallTool()
}

func iptablesBinary(isV6 bool) string {
	if isV6 {
		return "ip6tables"
	}
	return "iptables"
}

func buildIptablesRule(p firewallPayload, op string) (string, []string, string) {
	bin := iptablesBinary(p.isV6)
	args := []string{op, "OUTPUT", "-d", p.ip}
	if p.protocol != "" {
		args = append(args, "-p", p.protocol)
		if p.port > 0 {
			args = append(args, "--dport", strconv.Itoa(p.port))
		}
	}
	args = append(args, "-j", "DROP", "-m", "comment", "--comment", p.comment)
	return bin, args, bin + " " + strings.Join(args, " ")
}

func nftFamilyExpr(isV6 bool) string {
	if isV6 {
		return "ip6"
	}
	return "ip"
}

func buildNftAddRule(p firewallPayload) (string, []string, string) {
	args := []string{"add", "rule", "inet", nftTableName, nftChainName, nftFamilyExpr(p.isV6), "daddr", p.ip}
	if p.protocol != "" && p.port > 0 {
		args = append(args, p.protocol, "dport", strconv.Itoa(p.port))
	}
	args = append(args, "drop", "comment", fmt.Sprintf("%q", p.comment))
	return "nft", args, "nft " + strings.Join(args, " ")
}

func runBlockOutboundIP(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	p, err := parseFirewallPayload(action.Payload)
	if err != nil {
		return nil, err
	}
	tool := resolveFirewallTool(opts)
	if tool == "" && !p.dryRun {
		return nil, fmt.Errorf("no firewall tool available (tried iptables, nft)")
	}
	previewTool := tool
	if previewTool == "" {
		previewTool = "iptables"
	}
	var bin string
	var args []string
	var ruleText string
	if previewTool == "nft" {
		bin, args, ruleText = buildNftAddRule(p)
	} else {
		bin, args, ruleText = buildIptablesRule(p, "-A")
	}
	result := map[string]interface{}{
		"schema_version": "v1",
		"executed_at":    now.UTC().Format(time.RFC3339),
		"action":         actionMeta(action),
		"firewall_tool":  previewTool,
		"rule_text":      ruleText,
		"rule_added":     false,
		"dry_run":        p.dryRun,
	}
	if p.dryRun {
		return result, nil
	}
	if previewTool == "nft" {
		if cerr := ensureNftChain(); cerr != nil {
			return nil, cerr
		}
	}
	if cout, rerr := runCommand(bin, args); rerr != nil {
		return nil, fmt.Errorf("%s failed: %s", bin, firewallErr(cout, rerr))
	}
	result["rule_added"] = true
	return result, nil
}

func runUnblockOutboundIP(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	p, err := parseFirewallPayload(action.Payload)
	if err != nil {
		return nil, err
	}
	tool := resolveFirewallTool(opts)
	if tool == "" && !p.dryRun {
		return nil, fmt.Errorf("no firewall tool available (tried iptables, nft)")
	}
	previewTool := tool
	if previewTool == "" {
		previewTool = "iptables"
	}
	result := map[string]interface{}{
		"schema_version": "v1",
		"executed_at":    now.UTC().Format(time.RFC3339),
		"action":         actionMeta(action),
		"firewall_tool":  previewTool,
		"rules_removed":  0,
		"dry_run":        p.dryRun,
	}
	if p.dryRun {
		if previewTool == "nft" {
			result["rule_text"] = fmt.Sprintf("nft delete rule inet %s %s handle <match comment %q>", nftTableName, nftChainName, p.comment)
		} else {
			_, _, text := buildIptablesRule(p, "-D")
			result["rule_text"] = text
		}
		return result, nil
	}
	var removed int
	if previewTool == "nft" {
		removed, err = nftDeleteByComment(p)
	} else {
		removed, err = iptablesDeleteLoop(p)
	}
	if err != nil {
		return nil, err
	}
	result["rules_removed"] = removed
	return result, nil
}

func iptablesDeleteLoop(p firewallPayload) (int, error) {
	bin, args, _ := buildIptablesRule(p, "-D")
	removed := 0
	for i := 0; i < 128; i++ {
		out, err := runCommand(bin, args)
		if err == nil {
			removed++
			continue
		}
		if isNoMatchingRule(out) {
			break
		}
		return removed, fmt.Errorf("%s failed: %s", bin, firewallErr(out, err))
	}
	return removed, nil
}

func nftDeleteByComment(p firewallPayload) (int, error) {
	out, err := runCommand("nft", []string{"-a", "list", "chain", "inet", nftTableName, nftChainName})
	if err != nil {
		lc := strings.ToLower(out)
		if isNoMatchingRule(out) || strings.Contains(lc, "does not exist") || strings.Contains(lc, "no such file") {
			return 0, nil
		}
		return 0, fmt.Errorf("nft list failed: %s", firewallErr(out, err))
	}
	handles := parseNftHandles(out, p.comment)
	removed := 0
	for _, h := range handles {
		if _, derr := runCommand("nft", []string{"delete", "rule", "inet", nftTableName, nftChainName, "handle", strconv.Itoa(h)}); derr == nil {
			removed++
		}
	}
	return removed, nil
}

func parseNftHandles(listOutput string, comment string) []int {
	needle := fmt.Sprintf("comment %q", comment)
	handles := make([]int, 0)
	for _, line := range strings.Split(listOutput, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		idx := strings.LastIndex(line, "handle ")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line[idx+len("handle "):]))
		if len(fields) == 0 {
			continue
		}
		h, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		handles = append(handles, h)
	}
	return handles
}

func ensureNftChain() error {
	if _, err := runCommand("nft", []string{"list", "chain", "inet", nftTableName, nftChainName}); err == nil {
		return nil
	}
	if out, err := runCommand("nft", []string{"add", "table", "inet", nftTableName}); err != nil {
		return fmt.Errorf("nft add table failed: %s", firewallErr(out, err))
	}
	chainSpec := []string{"add", "chain", "inet", nftTableName, nftChainName, "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"}
	if out, err := runCommand("nft", chainSpec); err != nil {
		return fmt.Errorf("nft add chain failed: %s", firewallErr(out, err))
	}
	return nil
}

func isNoMatchingRule(output string) bool {
	lc := strings.ToLower(output)
	return strings.Contains(lc, "matching rule") ||
		strings.Contains(lc, "bad rule") ||
		strings.Contains(lc, "no chain")
}

func firewallErr(output string, err error) string {
	out := strings.TrimSpace(output)
	if out == "" {
		return err.Error()
	}
	if len(out) > 512 {
		out = out[:512]
	}
	return fmt.Sprintf("%s: %s", err.Error(), out)
}

func runCommand(bin string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return string(out), err
}

type quarantineFilePayload struct {
	path          string
	quarantineDir string
	computeHash   bool
	dryRun        bool
}

var quarantineForbiddenPrefixes = []string{"/proc", "/sys", "/dev", "/run", "/etc"}

func parseQuarantineFilePayload(raw json.RawMessage) (quarantineFilePayload, error) {
	out := quarantineFilePayload{
		quarantineDir: "/var/lib/seagull/quarantine",
		computeHash:   true,
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return out, fmt.Errorf("payload.path is required")
	}
	var payload struct {
		Path          *string `json:"path"`
		QuarantineDir *string `json:"quarantine_dir"`
		ComputeHash   *bool   `json:"compute_hash"`
		DryRun        *bool   `json:"dry_run"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, fmt.Errorf("invalid payload JSON: %w", err)
	}
	if payload.Path == nil || strings.TrimSpace(*payload.Path) == "" {
		return out, fmt.Errorf("payload.path is required")
	}
	out.path = filepath.Clean(strings.TrimSpace(*payload.Path))
	if payload.QuarantineDir != nil && strings.TrimSpace(*payload.QuarantineDir) != "" {
		out.quarantineDir = filepath.Clean(strings.TrimSpace(*payload.QuarantineDir))
	}
	if payload.ComputeHash != nil {
		out.computeHash = *payload.ComputeHash
	}
	if payload.DryRun != nil {
		out.dryRun = *payload.DryRun
	}
	return out, nil
}

func validateQuarantinePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("payload.path must be absolute")
	}
	for _, prefix := range quarantineForbiddenPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return fmt.Errorf("payload.path is in a protected location: %s", prefix)
		}
	}
	return nil
}

func runQuarantineFile(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	p, err := parseQuarantineFilePayload(action.Payload)
	if err != nil {
		return nil, err
	}
	if verr := validateQuarantinePath(p.path); verr != nil {
		return nil, verr
	}
	info, err := os.Lstat(p.path)
	if err != nil {
		return nil, fmt.Errorf("stat target failed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("payload.path is not a regular file")
	}
	dest := filepath.Join(p.quarantineDir, fmt.Sprintf("%s.%d.quar", filepath.Base(p.path), now.Unix()))
	result := map[string]interface{}{
		"schema_version":     "v1",
		"executed_at":        now.UTC().Format(time.RFC3339),
		"action":             actionMeta(action),
		"original_path":      p.path,
		"quarantine_path":    dest,
		"size_bytes":         info.Size(),
		"permissions_before": fmt.Sprintf("%04o", info.Mode().Perm()),
		"quarantined":        false,
		"dry_run":            p.dryRun,
	}
	if p.computeHash {
		sum, herr := sha256File(p.path)
		if herr != nil {
			return nil, fmt.Errorf("hash target failed: %w", herr)
		}
		result["sha256"] = sum
	}
	if p.dryRun {
		return result, nil
	}
	if err := os.MkdirAll(p.quarantineDir, 0o700); err != nil {
		return nil, fmt.Errorf("create quarantine dir failed: %w", err)
	}
	if err := os.Chmod(p.quarantineDir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod quarantine dir failed: %w", err)
	}
	if err := moveFile(p.path, dest); err != nil {
		return nil, fmt.Errorf("quarantine move failed: %w", err)
	}
	if err := os.Chmod(dest, 0o000); err != nil {
		return nil, fmt.Errorf("chmod quarantine file failed: %w", err)
	}
	result["quarantined"] = true
	result["permissions_after"] = "0000"
	return result, nil
}

func moveFile(src string, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

const maxShellOutputBytes = 1 << 20

type shellCommandPayload struct {
	command        string
	timeoutSeconds int
	workingDir     string
}

func parseShellCommandPayload(raw json.RawMessage) (shellCommandPayload, error) {
	out := shellCommandPayload{timeoutSeconds: 30}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return out, fmt.Errorf("payload.command is required")
	}
	var payload struct {
		Command        *string `json:"command"`
		TimeoutSeconds *int    `json:"timeout_seconds"`
		WorkingDir     *string `json:"working_dir"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return out, fmt.Errorf("invalid payload JSON: %w", err)
	}
	if payload.Command == nil || strings.TrimSpace(*payload.Command) == "" {
		return out, fmt.Errorf("payload.command is required")
	}
	out.command = strings.TrimSpace(*payload.Command)
	if payload.TimeoutSeconds != nil {
		out.timeoutSeconds = clamp(*payload.TimeoutSeconds, 1, 300)
	}
	if payload.WorkingDir != nil && strings.TrimSpace(*payload.WorkingDir) != "" {
		wd := strings.TrimSpace(*payload.WorkingDir)
		if !filepath.IsAbs(wd) {
			return out, fmt.Errorf("payload.working_dir must be absolute")
		}
		out.workingDir = filepath.Clean(wd)
	}
	return out, nil
}

func shellCommandFirstToken(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func shellCommandAllowed(command string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	firstToken := shellCommandFirstToken(command)
	if firstToken == "" {
		return false
	}
	base := filepath.Base(firstToken)
	for _, entry := range allowlist {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if strings.Contains(e, " ") {
			if strings.HasPrefix(command, e) {
				return true
			}
			continue
		}
		if firstToken == e || base == e {
			return true
		}
	}
	return false
}

func auditShellExec(opts ExecuteOptions, action controlplane.ResponseAction, command string, exitCode int, timedOut bool, blockedReason string) {
	fields := map[string]interface{}{
		"agent_id":  strings.TrimSpace(opts.AgentID),
		"action_id": action.ID,
		"command":   command,
		"exit_code": exitCode,
		"timed_out": timedOut,
	}
	reason := strings.TrimSpace(blockedReason)
	if reason != "" {
		fields["blocked"] = true
		fields["reason"] = reason
	}
	agentcfg.LogJSON(agentcfg.LevelInfo, "response_action.shell_exec", fields)
}

func truncateShellOutput(s string) string {
	if len(s) <= maxShellOutputBytes {
		return s
	}
	return s[:maxShellOutputBytes] + "\n[truncated]"
}

func runShellCommand(action controlplane.ResponseAction, opts ExecuteOptions, now time.Time) (map[string]interface{}, error) {
	p, err := parseShellCommandPayload(action.Payload)
	if err != nil {
		return nil, err
	}
	firstToken := shellCommandFirstToken(p.command)
	if !opts.AllowShellExec {
		auditShellExec(opts, action, p.command, -1, false, "shell exec disabled by agent config")
		return nil, fmt.Errorf("shell exec is disabled on this agent")
	}
	if !shellCommandAllowed(p.command, opts.ShellExecAllowlist) {
		auditShellExec(opts, action, p.command, -1, false, "command not permitted by allowlist")
		return nil, fmt.Errorf("command %q is not permitted by the shell exec allowlist", firstToken)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.timeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", p.command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	if p.workingDir != "" {
		cmd.Dir = p.workingDir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	durationMs := time.Since(start).Milliseconds()
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	auditShellExec(opts, action, p.command, exitCode, timedOut, "")

	result := map[string]interface{}{
		"schema_version":  "v1",
		"executed_at":     now.UTC().Format(time.RFC3339),
		"action":          actionMeta(action),
		"command":         p.command,
		"exit_code":       exitCode,
		"stdout":          truncateShellOutput(stdout.String()),
		"stderr":          truncateShellOutput(stderr.String()),
		"timed_out":       timedOut,
		"duration_ms":     durationMs,
		"command_allowed": true,
	}
	if p.workingDir != "" {
		result["working_dir"] = p.workingDir
	}
	return result, nil
}
