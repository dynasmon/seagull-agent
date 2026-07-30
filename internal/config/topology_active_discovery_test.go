package agentcfg

import "testing"

func TestValidateActiveDiscoveryCIDRsStrict(t *testing.T) {
	if _, err := ValidateActiveDiscoveryCIDRs("10.0.0.0/24,not-a-cidr", false); err == nil {
		t.Fatalf("expected invalid CIDR to fail")
	}
}

func TestValidateActiveDiscoveryCIDRsRejectsPublicByDefault(t *testing.T) {
	if _, err := ValidateActiveDiscoveryCIDRs("8.8.8.0/24", false); err == nil {
		t.Fatalf("expected public CIDR rejection")
	}
	if _, err := ValidateActiveDiscoveryCIDRs("8.8.8.0/24", true); err != nil {
		t.Fatalf("expected explicit public allow to succeed: %v", err)
	}
}

func TestValidateActiveDiscoveryCIDRsRejectsOverbroadPrivateBase(t *testing.T) {
	if _, err := ValidateActiveDiscoveryCIDRs("10.0.0.0/7", false); err == nil {
		t.Fatalf("expected CIDR extending beyond private range to fail")
	}
}

func TestLoadConfigTopologyActiveDiscoveryDisabledByDefault(t *testing.T) {
	t.Setenv("SEAGULL_API_URL", "https://127.0.0.1:8443/agent")
	t.Setenv("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE", "")
	cfg := LoadConfig()
	if cfg.TopologyActiveDiscoveryEnabled {
		t.Fatalf("expected active discovery to be disabled by default")
	}
	if len(cfg.TopologyActiveDiscoveryCIDRs) != 0 {
		t.Fatalf("expected no configured discovery CIDRs by default")
	}
}
