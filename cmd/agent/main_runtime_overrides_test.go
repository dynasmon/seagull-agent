package main

import (
	"testing"
	"time"
)

func TestApplyAgentRuntimeOverridesHostTelemetryModules(t *testing.T) {
	cfg := Config{
		Sources:                  []string{"proc"},
		ProcExecEvery:            2 * time.Second,
		ProcExecMaxBatch:         200,
		ProcExecHashEnabled:      true,
		ProcExecHashMaxBytes:     1024,
		FIMEvery:                 30 * time.Second,
		FIMMaxBatch:              200,
		FIMMaxDepth:              4,
		FIMHashEnabled:           true,
		FIMHashMaxBytes:          2048,
		L7Iface:                  "any",
		L7DedupTTL:               20 * time.Second,
		L7MaxBatch:               400,
		L7MaxPayloadBytes:        768,
		L7IncludePayload:         true,
		ProcExecIgnoreExeNames:   map[string]bool{"sleep": true},
		ProcExecIgnoreCmdContains: []string{"systemd --user"},
	}
	raw := map[string]interface{}{
		"modules": map[string]interface{}{
			"proc_exec": map[string]interface{}{
				"enabled":             true,
				"every":               "5s",
				"max_batch":           123,
				"hash_enabled":        false,
				"hash_max_bytes":      4096,
				"emit_initial":        true,
				"ignore_exe":          []interface{}{"sleep", "bash"},
				"ignore_cmd_contains": "healthcheck,systemd --user",
			},
			"fim": map[string]interface{}{
				"enabled":       true,
				"every":         "45s",
				"max_batch":     88,
				"max_depth":     6,
				"hash_enabled":  false,
				"hash_max_bytes": 4096,
				"emit_initial":  true,
				"paths":         []interface{}{"/etc/systemd/system", "/etc/cron.d"},
				"exclude_paths": "/tmp,/var/tmp",
			},
			"l7": map[string]interface{}{
				"enabled":           true,
				"iface":             "eth0",
				"dedup_ttl":         "45s",
				"max_batch":         88,
				"max_payload_bytes": 512,
				"include_payload":   false,
			},
		},
	}

	applyAgentRuntimeOverrides(&cfg, raw)

	if !contains(cfg.Sources, "proc_exec") || !contains(cfg.Sources, "fim") || !contains(cfg.Sources, "l7") {
		t.Fatalf("expected proc_exec/fim/l7 sources enabled, got=%v", cfg.Sources)
	}
	if cfg.ProcExecEvery != 5*time.Second || cfg.ProcExecMaxBatch != 123 {
		t.Fatalf("unexpected proc_exec runtime config: every=%s batch=%d", cfg.ProcExecEvery, cfg.ProcExecMaxBatch)
	}
	if cfg.ProcExecHashEnabled {
		t.Fatalf("expected proc_exec hash disabled")
	}
	if !cfg.ProcExecEmitInitial {
		t.Fatalf("expected proc_exec emit_initial enabled")
	}
	if !cfg.ProcExecIgnoreExeNames["bash"] || !cfg.ProcExecIgnoreExeNames["sleep"] {
		t.Fatalf("expected ignore_exe overrides applied: %#v", cfg.ProcExecIgnoreExeNames)
	}
	if len(cfg.FIMWatchPaths) != 2 || cfg.FIMWatchPaths[0] != "/etc/systemd/system" {
		t.Fatalf("unexpected fim paths: %#v", cfg.FIMWatchPaths)
	}
	if cfg.L7Iface != "eth0" || cfg.L7DedupTTL != 45*time.Second || cfg.L7IncludePayload {
		t.Fatalf("unexpected l7 runtime config: iface=%s dedup=%s include_payload=%v", cfg.L7Iface, cfg.L7DedupTTL, cfg.L7IncludePayload)
	}
}

func TestApplyAgentRuntimeOverridesCanDisableModules(t *testing.T) {
	cfg := Config{
		Sources: []string{"proc", "proc_exec", "fim", "l7", "ddos"},
	}
	raw := map[string]interface{}{
		"modules": map[string]interface{}{
			"proc_exec": map[string]interface{}{"enabled": false},
			"fim":       map[string]interface{}{"enabled": false},
			"l7":        map[string]interface{}{"enabled": false},
		},
	}
	applyAgentRuntimeOverrides(&cfg, raw)
	if contains(cfg.Sources, "proc_exec") || contains(cfg.Sources, "fim") || contains(cfg.Sources, "l7") {
		t.Fatalf("expected modules disabled, got=%v", cfg.Sources)
	}
}
