package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
)

type SyscollectorConfig struct {
	Enabled        bool
	Every          time.Duration
	CmdTimeout     time.Duration
	MaxOutputBytes int64
	MaxPackages    int
	HostRoot       string
}

type VulnScannerConfig struct {
	Enabled         bool
	Every           time.Duration
	OSVURL          string
	MinSeverity     string
	AnalysisProfile string
	ExposureEnabled bool
	ScanNowToken    string
	QueryBatchSize  int
	MaxPackages     int
	CmdTimeout      time.Duration
	HTTPTimeout     time.Duration
	MaxOutputBytes  int64
	HostRoot        string
}

type RuntimeConfig struct {
	mu       sync.RWMutex
	raw      map[string]interface{}
	hash     string
	path     string
	defaults SyscollectorConfig
	vulnDef  VulnScannerConfig
	changed  chan struct{}
}

func NewRuntimeConfig(path string, defaults SyscollectorConfig, vulnDefaults VulnScannerConfig) *RuntimeConfig {
	rc := &RuntimeConfig{
		raw:      map[string]interface{}{},
		path:     path,
		defaults: defaults,
		vulnDef:  vulnDefaults,
		changed:  make(chan struct{}, 1),
	}
	_ = rc.loadFromFile()
	rc.hash = rc.computeHashLocked()
	return rc
}

func (r *RuntimeConfig) Changed() <-chan struct{} {
	return r.changed
}

func (r *RuntimeConfig) Hash() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hash
}

func (r *RuntimeConfig) Raw() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return agentcfg.DeepCopyMap(r.raw)
}

func (r *RuntimeConfig) Apply(raw map[string]interface{}) (bool, error) {
	if raw == nil {
		raw = map[string]interface{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.raw = agentcfg.DeepCopyMap(raw)
	newHash := r.computeHashLocked()
	if newHash == r.hash {
		return false, nil
	}

	r.hash = newHash
	if r.path != "" {
		b, err := json.Marshal(r.raw)
		if err != nil {
			return false, fmt.Errorf("marshal runtime config: %w", err)
		}
		if err := agentcfg.AtomicWriteFile(r.path, b, 0o600); err != nil {
			return false, err
		}
	}

	select {
	case r.changed <- struct{}{}:
	default:
	}

	return true, nil
}

func (r *RuntimeConfig) Syscollector() SyscollectorConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg := r.defaults

	modules, _ := r.raw["modules"].(map[string]interface{})
	if modules == nil {
		return cfg
	}
	sys, _ := modules["syscollector"].(map[string]interface{})
	if sys == nil {
		return cfg
	}

	if v, ok := sys["enabled"].(bool); ok {
		cfg.Enabled = v
	}
	if s, ok := sys["every"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.Every = d
		}
	}
	if s, ok := sys["cmd_timeout"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.CmdTimeout = d
		}
	}
	if n, ok := agentcfg.ToInt64(sys["max_output_bytes"]); ok && n > 0 {
		cfg.MaxOutputBytes = n
	}
	if n, ok := agentcfg.ToInt64(sys["max_packages"]); ok && n > 0 {
		cfg.MaxPackages = int(n)
	}
	if s, ok := sys["host_root"].(string); ok {
		s = strings.TrimSpace(s)
		if s != "" {
			cfg.HostRoot = s
		}
	}

	return cfg
}

func (r *RuntimeConfig) VulnScanner() VulnScannerConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg := r.vulnDef

	modules, _ := r.raw["modules"].(map[string]interface{})
	if modules == nil {
		return cfg
	}
	v, _ := modules["vulnscanner"].(map[string]interface{})
	if v == nil {
		return cfg
	}

	if b, ok := v["enabled"].(bool); ok {
		cfg.Enabled = b
	}
	if s, ok := v["every"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.Every = d
		}
	}
	if s, ok := v["osv_url"].(string); ok {
		s = strings.TrimSpace(s)
		if s != "" {
			cfg.OSVURL = s
		}
	}
	if s, ok := v["min_severity"].(string); ok {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			cfg.MinSeverity = s
		}
	}
	if s, ok := v["analysis_profile"].(string); ok {
		s = strings.TrimSpace(s)
		if s != "" {
			cfg.AnalysisProfile = s
		}
	}
	if b, ok := v["exposure_enabled"].(bool); ok {
		cfg.ExposureEnabled = b
	}
	if s, ok := v["scan_now_token"].(string); ok {
		cfg.ScanNowToken = strings.TrimSpace(s)
	}
	if n, ok := agentcfg.ToInt64(v["query_batch_size"]); ok && n > 0 {
		cfg.QueryBatchSize = int(n)
	}
	if n, ok := agentcfg.ToInt64(v["max_packages"]); ok && n > 0 {
		cfg.MaxPackages = int(n)
	}
	if s, ok := v["cmd_timeout"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.CmdTimeout = d
		}
	}
	if s, ok := v["http_timeout"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.HTTPTimeout = d
		}
	}
	if n, ok := agentcfg.ToInt64(v["max_output_bytes"]); ok && n > 0 {
		cfg.MaxOutputBytes = n
	}
	if s, ok := v["host_root"].(string); ok {
		s = strings.TrimSpace(s)
		if s != "" {
			cfg.HostRoot = s
		}
	}

	return cfg
}

func (r *RuntimeConfig) loadFromFile() error {
	if r.path == "" {
		return nil
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil
	}
	r.raw = agentcfg.DeepCopyMap(obj)
	return nil
}

func (r *RuntimeConfig) computeHashLocked() string {
	b, err := json.Marshal(r.raw)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
