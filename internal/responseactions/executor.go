package responseactions

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/controlplane"
)

type ExecuteOptions struct {
	ExpectedAgentID string
	AgentID         string
	BuildVersion    string
	EffectiveConfig map[string]interface{}
	ModuleStates    map[string]interface{}
	RefreshRuntimeConfig func() (changed bool, configKeys int, configHash string, err error)
	AgentStartedAt  time.Time
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
	default:
		out.Error = fmt.Sprintf("unsupported action_type: %s", strings.TrimSpace(action.ActionType))
		return out
	}
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
		"pid":         os.Getpid(),
		"goos":        runtime.GOOS,
		"goarch":      runtime.GOARCH,
		"go_version":  runtime.Version(),
		"gomaxprocs":  runtime.GOMAXPROCS(0),
		"num_cpu":     runtime.NumCPU(),
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
