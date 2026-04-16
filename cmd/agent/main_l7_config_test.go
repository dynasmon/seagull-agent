package main

import (
	"testing"
	"time"
)

func resetL7Env(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"SEAGULL_API_URL",
		"SEAGULL_PCAP_IFACE",
		"SEAGULL_L7_PCAP_IFACE",
		"SEAGULL_L7_IFACE",
		"SEAGULL_L7_DEDUP_TTL",
		"SEAGULL_L7_MAX_BATCH",
		"SEAGULL_L7_BATCH_SIZE",
		"SEAGULL_L7_MAX_PAYLOAD_BYTES",
		"SEAGULL_L7_PAYLOAD_BYTES",
		"SEAGULL_L7_INCLUDE_PAYLOAD",
		"NETWATCH_L7_PCAP_IFACE",
		"NETWATCH_L7_IFACE",
		"NETWATCH_L7_DEDUP_TTL",
		"NETWATCH_L7_MAX_BATCH",
		"NETWATCH_L7_BATCH_SIZE",
		"NETWATCH_L7_MAX_PAYLOAD_BYTES",
		"NETWATCH_L7_PAYLOAD_BYTES",
		"NETWATCH_L7_INCLUDE_PAYLOAD",
		"SEAGULL_AGENT_BOOTSTRAP_TOKEN",
		"SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE",
		"NETWATCH_AGENT_BOOTSTRAP_TOKEN",
		"NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadConfigUsesSafeL7Defaults(t *testing.T) {
	resetL7Env(t)
	t.Setenv("SEAGULL_API_URL", "https://127.0.0.1:8443/agent")

	cfg := loadConfig()

	if !contains(cfg.Sources, "l7") {
		t.Fatalf("expected default sources to include l7, got=%v", cfg.Sources)
	}
	if cfg.L7Iface != "any" {
		t.Fatalf("expected default l7 iface any, got=%q", cfg.L7Iface)
	}
	if cfg.L7DedupTTL != 20*time.Second {
		t.Fatalf("expected default l7 dedup 20s, got=%s", cfg.L7DedupTTL)
	}
	if cfg.L7MaxBatch != 400 {
		t.Fatalf("expected default l7 max batch 400, got=%d", cfg.L7MaxBatch)
	}
	if cfg.L7MaxPayloadBytes != 512 {
		t.Fatalf("expected default l7 max payload 512, got=%d", cfg.L7MaxPayloadBytes)
	}
	if cfg.L7IncludePayload {
		t.Fatalf("expected payload capture disabled by default")
	}
}

func TestLoadConfigSupportsLegacyAndAliasL7EnvNames(t *testing.T) {
	resetL7Env(t)
	t.Setenv("SEAGULL_API_URL", "https://127.0.0.1:8443/agent")
	t.Setenv("SEAGULL_PCAP_IFACE", "any")
	t.Setenv("NETWATCH_L7_DEDUP_TTL", "45s")
	t.Setenv("NETWATCH_L7_MAX_BATCH", "600")
	t.Setenv("SEAGULL_L7_IFACE", "eth7")
	t.Setenv("SEAGULL_L7_PAYLOAD_BYTES", "1024")
	t.Setenv("NETWATCH_L7_INCLUDE_PAYLOAD", "true")

	cfg := loadConfig()

	if cfg.L7Iface != "eth7" {
		t.Fatalf("expected alias iface, got=%q", cfg.L7Iface)
	}
	if cfg.L7DedupTTL != 45*time.Second {
		t.Fatalf("expected legacy dedup ttl, got=%s", cfg.L7DedupTTL)
	}
	if cfg.L7MaxBatch != 600 {
		t.Fatalf("expected legacy max batch, got=%d", cfg.L7MaxBatch)
	}
	if cfg.L7MaxPayloadBytes != 1024 {
		t.Fatalf("expected alias max payload bytes, got=%d", cfg.L7MaxPayloadBytes)
	}
	if !cfg.L7IncludePayload {
		t.Fatalf("expected legacy include payload to be enabled")
	}
}

func TestSanitizeL7ConfigClampsUnsafeValues(t *testing.T) {
	cfg := Config{
		L7MaxBatch:        50000,
		L7MaxPayloadBytes: 64000,
	}

	sanitizeL7Config(&cfg)

	if cfg.L7Iface != "any" {
		t.Fatalf("expected iface defaulted to any, got=%q", cfg.L7Iface)
	}
	if cfg.L7DedupTTL != 20*time.Second {
		t.Fatalf("expected dedup ttl defaulted to 20s, got=%s", cfg.L7DedupTTL)
	}
	if cfg.L7MaxBatch != maxL7MaxBatch {
		t.Fatalf("expected l7 max batch clamped to %d, got=%d", maxL7MaxBatch, cfg.L7MaxBatch)
	}
	if cfg.L7MaxPayloadBytes != maxL7MaxPayloadBytes {
		t.Fatalf("expected l7 max payload bytes clamped to %d, got=%d", maxL7MaxPayloadBytes, cfg.L7MaxPayloadBytes)
	}
}
