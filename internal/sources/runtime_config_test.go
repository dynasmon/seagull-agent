package sources

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newRuntimeConfigForTest(path string) *RuntimeConfig {
	return NewRuntimeConfig(path, SyscollectorConfig{Enabled: true}, VulnScannerConfig{}, TopologyDiscoveryConfig{})
}

func TestRuntimeConfigRejectsStaleRevision(t *testing.T) {
	rc := newRuntimeConfigForTest("")
	if changed, err := rc.Apply(map[string]interface{}{
		"revision": float64(4),
		"modules":  map[string]interface{}{"syscollector": map[string]interface{}{"enabled": true}},
	}); err != nil || !changed {
		t.Fatalf("apply revision 4: changed=%v err=%v", changed, err)
	}

	changed, err := rc.Apply(map[string]interface{}{
		"revision": float64(3),
		"modules":  map[string]interface{}{"syscollector": map[string]interface{}{"enabled": false}},
	})
	if changed || !errors.Is(err, ErrStaleConfigRevision) {
		t.Fatalf("stale revision accepted: changed=%v err=%v", changed, err)
	}
	if rc.Revision() != 4 || !rc.Syscollector().Enabled {
		t.Fatalf("stale revision modified state: revision=%d enabled=%v", rc.Revision(), rc.Syscollector().Enabled)
	}
}

func TestRuntimeConfigRejectsSameRevisionWithDifferentContent(t *testing.T) {
	rc := newRuntimeConfigForTest("")
	if _, err := rc.Apply(map[string]interface{}{
		"revision": float64(2),
		"modules":  map[string]interface{}{"syscollector": map[string]interface{}{"enabled": true}},
	}); err != nil {
		t.Fatalf("apply revision 2: %v", err)
	}

	changed, err := rc.Apply(map[string]interface{}{
		"revision": float64(2),
		"modules":  map[string]interface{}{"syscollector": map[string]interface{}{"enabled": false}},
	})
	if changed || !errors.Is(err, ErrConfigRevisionConflict) {
		t.Fatalf("conflicting revision accepted: changed=%v err=%v", changed, err)
	}
}

func TestRuntimeConfigPersistsBeforePublishingState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	rc := newRuntimeConfigForTest(path)
	if _, err := rc.Apply(map[string]interface{}{"revision": float64(1)}); err != nil {
		t.Fatalf("apply initial config: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("make config directory read-only: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})

	if os.Geteuid() == 0 {
		t.Skip("root can write through the permission failure fixture")
	}
	changed, err := rc.Apply(map[string]interface{}{"revision": float64(2)})
	if err == nil || changed {
		t.Fatalf("persistence failure was not returned: changed=%v err=%v", changed, err)
	}
	if rc.Revision() != 1 {
		t.Fatalf("failed persistence published revision %d", rc.Revision())
	}
}

func TestRuntimeConfigAcceptsLegacyConfigurationOnFreshState(t *testing.T) {
	rc := newRuntimeConfigForTest("")
	changed, err := rc.Apply(map[string]interface{}{
		"modules": map[string]interface{}{"syscollector": map[string]interface{}{"enabled": true}},
	})
	if err != nil || !changed {
		t.Fatalf("legacy config rejected: changed=%v err=%v", changed, err)
	}
	if rc.Revision() != 0 {
		t.Fatalf("legacy config has revision %d", rc.Revision())
	}
	changed, err = rc.Apply(map[string]interface{}{
		"modules": map[string]interface{}{"syscollector": map[string]interface{}{"enabled": false}},
	})
	if changed || !errors.Is(err, ErrStaleConfigRevision) {
		t.Fatalf("second revisionless config accepted: changed=%v err=%v", changed, err)
	}
}

func TestRuntimeConfigRejectsInvalidRevision(t *testing.T) {
	rc := newRuntimeConfigForTest("")
	for _, revision := range []interface{}{float64(1.5), float64(0), float64(-1), "1"} {
		if changed, err := rc.Apply(map[string]interface{}{"revision": revision}); err == nil || changed {
			t.Fatalf("invalid revision accepted: value=%v changed=%v err=%v", revision, changed, err)
		}
	}
}

func TestRuntimeConfigReportsCorruptPersistedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"revision":`), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	rc := newRuntimeConfigForTest(path)
	if rc.LoadError() == nil {
		t.Fatalf("expected persisted config load error")
	}
	if len(rc.Raw()) != 0 {
		t.Fatalf("corrupt config was published: %v", rc.Raw())
	}
}

func TestRuntimeConfigCannotEnableLocallyDisabledModules(t *testing.T) {
	rc := NewRuntimeConfig(
		"",
		SyscollectorConfig{Enabled: false, HostRoot: "/local/sys"},
		VulnScannerConfig{Enabled: false, HostRoot: "/local/vuln"},
		TopologyDiscoveryConfig{Enabled: false, AllowPublic: false, Every: 30 * time.Minute, MaxHosts: 256, RateLimit: 20, Timeout: 30 * time.Second},
	)
	if _, err := rc.Apply(map[string]interface{}{
		"revision": float64(1),
		"modules": map[string]interface{}{
			"syscollector": map[string]interface{}{"enabled": true, "host_root": "/remote/sys"},
			"vulnscanner":  map[string]interface{}{"enabled": true, "host_root": "/remote/vuln"},
			"topology_active_discovery": map[string]interface{}{
				"enabled":      true,
				"allow_public": true,
			},
		},
	}); err != nil {
		t.Fatalf("apply remote configuration: %v", err)
	}
	if cfg := rc.Syscollector(); cfg.Enabled || cfg.HostRoot != "/local/sys" {
		t.Fatalf("remote syscollector policy escaped local bounds: %+v", cfg)
	}
	if cfg := rc.VulnScanner(); cfg.Enabled || cfg.HostRoot != "/local/vuln" {
		t.Fatalf("remote vulnerability policy escaped local bounds: %+v", cfg)
	}
	cfg, err := rc.TopologyDiscovery()
	if err != nil {
		t.Fatalf("resolve topology policy: %v", err)
	}
	if cfg.Enabled || cfg.AllowPublic {
		t.Fatalf("remote topology policy escaped local bounds: %+v", cfg)
	}
}

func TestRuntimeTopologyPolicyCannotExceedLocalBounds(t *testing.T) {
	_, localCIDR, err := net.ParseCIDR("10.20.0.0/16")
	if err != nil {
		t.Fatalf("parse local CIDR: %v", err)
	}
	rc := NewRuntimeConfig(
		"",
		SyscollectorConfig{},
		VulnScannerConfig{},
		TopologyDiscoveryConfig{
			Enabled:     true,
			CIDRs:       []*net.IPNet{localCIDR},
			AllowPublic: false,
			Every:       30 * time.Minute,
			MaxHosts:    256,
			RateLimit:   20,
			Timeout:     30 * time.Second,
		},
	)
	if _, err := rc.Apply(map[string]interface{}{
		"revision": float64(1),
		"modules": map[string]interface{}{
			"topology_active_discovery": map[string]interface{}{
				"enabled":      true,
				"allow_public": true,
				"every":        "1m",
				"max_hosts":    float64(1024),
				"rate_limit":   float64(100),
				"timeout":      "2m",
				"cidrs":        []interface{}{"10.20.8.0/24"},
			},
		},
	}); err != nil {
		t.Fatalf("apply bounded topology configuration: %v", err)
	}
	cfg, err := rc.TopologyDiscovery()
	if err != nil {
		t.Fatalf("resolve bounded topology configuration: %v", err)
	}
	if !cfg.Enabled || cfg.AllowPublic || cfg.Every != 30*time.Minute || cfg.MaxHosts != 256 || cfg.RateLimit != 20 || cfg.Timeout != 30*time.Second {
		t.Fatalf("remote topology limits escaped local bounds: %+v", cfg)
	}
	if len(cfg.CIDRs) != 1 || cfg.CIDRs[0].String() != "10.20.8.0/24" {
		t.Fatalf("bounded topology CIDR was not applied: %+v", cfg.CIDRs)
	}

	if _, err := rc.Apply(map[string]interface{}{
		"revision": float64(2),
		"modules": map[string]interface{}{
			"topology_active_discovery": map[string]interface{}{
				"enabled": true,
				"cidrs":   []interface{}{"10.21.0.0/16"},
			},
		},
	}); err != nil {
		t.Fatalf("persist out-of-policy topology configuration: %v", err)
	}
	if _, err := rc.TopologyDiscovery(); err == nil {
		t.Fatalf("out-of-policy topology CIDR was accepted")
	}
}
