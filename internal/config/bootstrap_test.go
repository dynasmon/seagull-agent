package agentcfg

import (
	"path/filepath"
	"testing"
)

func TestLoadBootstrapTokenValueAllowsMissingFileWithExistingIdentity(t *testing.T) {
	t.Setenv("SEAGULL_AGENT_BOOTSTRAP_TOKEN", "")
	t.Setenv("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE", filepath.Join(t.TempDir(), "missing.token"))

	token, tokenFile, err := LoadBootstrapTokenValue(true)
	if err != nil {
		t.Fatalf("LoadBootstrapTokenValue returned error: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if tokenFile == "" {
		t.Fatalf("expected bootstrap token file path to be preserved")
	}
}
