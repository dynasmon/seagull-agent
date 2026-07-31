package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
)

var (
	ErrStaleConfigRevision    = errors.New("stale remote configuration revision")
	ErrConfigRevisionConflict = errors.New("conflicting remote configuration revision")
)

type SyscollectorConfig struct {
	Enabled        bool
	Every          time.Duration
	CmdTimeout     time.Duration
	MaxOutputBytes int64
	MaxPackages    int
	HostRoot       string

	NetCtxMaxIfaces    int
	NetCtxMaxNeighbors int
	NetCtxMaxRoutes    int
	NetCtxMaxResolvers int
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

type TopologyDiscoveryConfig struct {
	Enabled     bool
	CIDRs       []*net.IPNet
	AllowPublic bool
	Every       time.Duration
	MaxHosts    int
	RateLimit   int
	Timeout     time.Duration
}

type RuntimeConfig struct {
	mu       sync.RWMutex
	raw      map[string]interface{}
	hash     string
	path     string
	defaults SyscollectorConfig
	vulnDef  VulnScannerConfig
	topoDef  TopologyDiscoveryConfig
	changed  chan struct{}
	loadErr  error
}

func NewRuntimeConfig(
	path string,
	defaults SyscollectorConfig,
	vulnDefaults VulnScannerConfig,
	topologyDefaults TopologyDiscoveryConfig,
) *RuntimeConfig {
	rc := &RuntimeConfig{
		raw:      map[string]interface{}{},
		path:     path,
		defaults: defaults,
		vulnDef:  vulnDefaults,
		topoDef:  topologyDefaults,
		changed:  make(chan struct{}, 1),
	}
	rc.loadErr = rc.loadFromFile()
	rc.hash = rc.computeHashLocked()
	return rc
}

func (r *RuntimeConfig) LoadError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadErr
}

func (r *RuntimeConfig) Changed() <-chan struct{} {
	return r.changed
}

func (r *RuntimeConfig) Hash() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hash
}

func (r *RuntimeConfig) Revision() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return configRevision(r.raw)
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

	next := agentcfg.DeepCopyMap(raw)
	currentRevision, currentHasRevision, currentRevisionErr := parseConfigRevision(r.raw)
	if currentRevisionErr != nil {
		return false, currentRevisionErr
	}
	nextRevision, nextHasRevision, nextRevisionErr := parseConfigRevision(next)
	if nextRevisionErr != nil {
		return false, nextRevisionErr
	}
	currentHash := r.hash
	newHash := configHash(next)

	if newHash == r.hash {
		return false, nil
	}
	if len(r.raw) > 0 && !currentHasRevision && !nextHasRevision {
		return false, fmt.Errorf("%w: current configuration has no revision", ErrStaleConfigRevision)
	}
	if currentHasRevision {
		if !nextHasRevision || nextRevision < currentRevision {
			return false, fmt.Errorf(
				"%w: current=%d received=%d",
				ErrStaleConfigRevision,
				currentRevision,
				nextRevision,
			)
		}
		if nextRevision == currentRevision && newHash != currentHash {
			return false, fmt.Errorf(
				"%w: revision=%d",
				ErrConfigRevisionConflict,
				nextRevision,
			)
		}
	}

	if r.path != "" {
		b, err := json.Marshal(next)
		if err != nil {
			return false, fmt.Errorf("marshal runtime config: %w", err)
		}
		if err := agentcfg.AtomicWriteFile(r.path, b, 0o600); err != nil {
			return false, err
		}
	}

	r.raw = next
	r.hash = newHash

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
		cfg.Enabled = cfg.Enabled && v
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
		cfg.Enabled = cfg.Enabled && b
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
	return cfg
}

func (r *RuntimeConfig) TopologyDiscovery() (TopologyDiscoveryConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg := r.topoDef

	modules, _ := r.raw["modules"].(map[string]interface{})
	if modules == nil {
		return cfg, nil
	}
	v, _ := modules["topology_active_discovery"].(map[string]interface{})
	if v == nil {
		return cfg, nil
	}

	if b, ok := v["enabled"].(bool); ok {
		cfg.Enabled = cfg.Enabled && b
	}
	if b, ok := v["allow_public"].(bool); ok {
		cfg.AllowPublic = cfg.AllowPublic && b
	}
	if s, ok := v["every"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d >= cfg.Every {
			cfg.Every = d
		}
	}
	if n, ok := agentcfg.ToInt64(v["max_hosts"]); ok && n > 0 && (cfg.MaxHosts <= 0 || n <= int64(cfg.MaxHosts)) {
		cfg.MaxHosts = int(n)
	}
	if n, ok := agentcfg.ToInt64(v["rate_limit"]); ok && n > 0 && (cfg.RateLimit <= 0 || n <= int64(cfg.RateLimit)) {
		cfg.RateLimit = int(n)
	}
	if s, ok := v["timeout"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 && (cfg.Timeout <= 0 || d <= cfg.Timeout) {
			cfg.Timeout = d
		}
	}
	if vals := stringSliceValue(v["cidrs"]); len(vals) > 0 {
		cidrs, err := agentcfg.ValidateActiveDiscoveryCIDRs(strings.Join(vals, ","), cfg.AllowPublic)
		if err != nil {
			return cfg, err
		}
		if len(r.topoDef.CIDRs) > 0 && !cidrsWithin(cidrs, r.topoDef.CIDRs) {
			return cfg, fmt.Errorf("remote topology CIDRs exceed the local discovery policy")
		}
		cfg.CIDRs = cidrs
	}

	return cfg, nil
}

func cidrsWithin(requested []*net.IPNet, allowed []*net.IPNet) bool {
	for _, candidate := range requested {
		if candidate == nil || candidate.IP == nil {
			return false
		}
		ones, bits := candidate.Mask.Size()
		permitted := false
		for _, boundary := range allowed {
			if boundary == nil || boundary.IP == nil {
				continue
			}
			boundaryOnes, boundaryBits := boundary.Mask.Size()
			if bits == boundaryBits && ones >= boundaryOnes && boundary.Contains(candidate.IP) {
				permitted = true
				break
			}
		}
		if !permitted {
			return false
		}
	}
	return true
}

func stringSliceValue(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := strings.TrimSpace(fmt.Sprintf("%v", item))
			if s == "" || s == "<nil>" {
				continue
			}
			out = append(out, s)
		}
		return out
	case string:
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return nil
	}
}

func (r *RuntimeConfig) loadFromFile() error {
	if r.path == "" {
		return nil
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read persisted runtime config: %w", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("parse persisted runtime config: %w", err)
	}
	if obj == nil {
		return fmt.Errorf("persisted runtime config must be an object")
	}
	if _, _, err := parseConfigRevision(obj); err != nil {
		return err
	}
	r.raw = agentcfg.DeepCopyMap(obj)
	return nil
}

func (r *RuntimeConfig) computeHashLocked() string {
	return configHash(r.raw)
}

func configHash(raw map[string]interface{}) string {
	b, err := json.Marshal(raw)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func configRevision(raw map[string]interface{}) int64 {
	revision, present, err := parseConfigRevision(raw)
	if err != nil || !present {
		return 0
	}
	return revision
}

func parseConfigRevision(raw map[string]interface{}) (int64, bool, error) {
	value, present := raw["revision"]
	if !present {
		return 0, false, nil
	}
	revision, ok := agentcfg.ToInt64(value)
	if !ok || revision < 1 {
		return 0, true, fmt.Errorf("remote configuration revision must be a positive integer")
	}
	return revision, true, nil
}
