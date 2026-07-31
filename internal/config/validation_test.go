package agentcfg

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dynasmon/seagull-agent/protocol"
)

func TestValidateAgentID(t *testing.T) {
	for _, value := range []string{"host-1", "host.example_1", "A"} {
		if err := ValidateAgentID(value); err != nil {
			t.Fatalf("expected %q to be valid: %v", value, err)
		}
	}
	for _, value := range []string{"", "-host", "host:1", "host/1", "host 1"} {
		if err := ValidateAgentID(value); err == nil {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidateEndpointURL(t *testing.T) {
	for _, value := range []string{"https://agents.example.com:8444/agent", "https://[::1]:8444/agent"} {
		if err := ValidateEndpointURL("endpoint", value); err != nil {
			t.Fatalf("expected %q to be valid: %v", value, err)
		}
	}
	for _, value := range []string{"", "http://agents.example.com/agent", "https://user@agents.example.com/agent", "https://agents.example.com/agent?x=1"} {
		if err := ValidateEndpointURL("endpoint", value); err == nil {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidateSources(t *testing.T) {
	if err := ValidateSources([]string{"authlog", "proc", "vuln"}); err != nil {
		t.Fatalf("expected source set to be valid: %v", err)
	}
	if err := ValidateSources([]string{"authlog", "unknown"}); err == nil {
		t.Fatalf("expected unsupported source rejection")
	}
	if err := ValidateSources([]string{"proc", "proc"}); err == nil {
		t.Fatalf("expected duplicate source rejection")
	}
}

func TestValidateShellExec(t *testing.T) {
	executable, err := exec.LookPath("echo")
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		t.Fatalf("resolve absolute test executable: %v", err)
	}
	if err := ValidateShellExec(protocol.ProfileManaged, true, []string{executable}); err != nil {
		t.Fatalf("expected managed allowlist to be valid: %v", err)
	}
	for _, test := range []struct {
		profile   string
		allowlist []string
	}{
		{profile: protocol.ProfileSensor, allowlist: []string{executable}},
		{profile: protocol.ProfileManaged},
		{profile: protocol.ProfileManaged, allowlist: []string{"echo"}},
		{profile: protocol.ProfileManaged, allowlist: []string{"/missing/seagull-command"}},
	} {
		if err := ValidateShellExec(test.profile, true, test.allowlist); err == nil {
			t.Fatalf("expected shell execution configuration to be rejected: %#v", test)
		}
	}
}
