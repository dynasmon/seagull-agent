package agentcfg

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dynasmon/seagull-agent/protocol"
)

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var supportedSources = map[string]struct{}{
	"authlog":      {},
	"proc":         {},
	"proc_exec":    {},
	"fim":          {},
	"scan":         {},
	"ddos":         {},
	"l7":           {},
	"lateral":      {},
	"syscollector": {},
	"vuln":         {},
}

func ValidateAgentID(value string) error {
	value = strings.TrimSpace(value)
	if !agentIDPattern.MatchString(value) {
		return fmt.Errorf("agent ID must match %s", agentIDPattern.String())
	}
	return nil
}

func ValidateEndpointURL(name string, value string) error {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https", name)
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func ValidateSources(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("at least one telemetry source is required")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := supportedSources[value]; !ok {
			return fmt.Errorf("unsupported telemetry source %q", value)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("duplicate telemetry source %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func ValidateProfile(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case protocol.ProfileSensor, protocol.ProfileManaged:
		return nil
	default:
		return fmt.Errorf("unsupported agent profile %q", value)
	}
}

func ValidateShellExec(profile string, enabled bool, allowlist []string) error {
	if !enabled {
		return nil
	}
	if protocol.NormalizeProfile(profile) != protocol.ProfileManaged {
		return fmt.Errorf("shell execution requires the managed agent profile")
	}
	if len(allowlist) == 0 {
		return fmt.Errorf("shell execution requires an executable allowlist")
	}
	seen := make(map[string]struct{}, len(allowlist))
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if !filepath.IsAbs(entry) {
			return fmt.Errorf("shell executable allowlist entry must be absolute: %q", entry)
		}
		resolved, err := filepath.EvalSymlinks(filepath.Clean(entry))
		if err != nil {
			return fmt.Errorf("resolve shell executable allowlist entry %q: %w", entry, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("stat shell executable allowlist entry %q: %w", entry, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("shell executable allowlist entry is not an executable regular file: %q", entry)
		}
		if _, ok := seen[resolved]; ok {
			return fmt.Errorf("duplicate shell executable allowlist entry %q", entry)
		}
		seen[resolved] = struct{}{}
	}
	return nil
}
