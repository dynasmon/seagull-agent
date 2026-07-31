package agentcfg

import "testing"

func TestRuntimeOverridesCannotEnableLocallyForbiddenSources(t *testing.T) {
	cfg := Config{
		Sources:        []string{"authlog"},
		AllowedSources: []string{"authlog"},
	}
	ApplyAgentRuntimeOverrides(&cfg, map[string]interface{}{
		"modules": map[string]interface{}{
			"ddos":      map[string]interface{}{"enabled": true},
			"proc_exec": map[string]interface{}{"enabled": true},
			"fim":       map[string]interface{}{"enabled": true},
			"l7":        map[string]interface{}{"enabled": true},
		},
	})
	if len(cfg.Sources) != 1 || cfg.Sources[0] != "authlog" {
		t.Fatalf("remote configuration expanded local sources: %v", cfg.Sources)
	}
}

func TestRuntimeOverridesCanDisableAndRestoreAllowedSource(t *testing.T) {
	cfg := Config{
		Sources:        []string{"authlog", "l7"},
		AllowedSources: []string{"authlog", "l7"},
	}
	ApplyAgentRuntimeOverrides(&cfg, map[string]interface{}{
		"modules": map[string]interface{}{
			"l7": map[string]interface{}{"enabled": false},
		},
	})
	if Contains(cfg.Sources, "l7") {
		t.Fatalf("remote configuration did not disable l7")
	}
	ApplyAgentRuntimeOverrides(&cfg, map[string]interface{}{
		"modules": map[string]interface{}{
			"l7": map[string]interface{}{"enabled": true},
		},
	})
	if !Contains(cfg.Sources, "l7") {
		t.Fatalf("remote configuration did not restore locally allowed l7")
	}
}

func TestRuntimeOverridesCannotEnablePayloadCaptureLocally(t *testing.T) {
	cfg := Config{
		Sources:          []string{"l7"},
		AllowedSources:   []string{"l7"},
		L7IncludePayload: false,
	}
	ApplyAgentRuntimeOverrides(&cfg, map[string]interface{}{
		"modules": map[string]interface{}{
			"l7": map[string]interface{}{"enabled": true, "include_payload": true},
		},
	})
	if cfg.L7IncludePayload {
		t.Fatalf("remote configuration enabled locally forbidden payload capture")
	}
}
