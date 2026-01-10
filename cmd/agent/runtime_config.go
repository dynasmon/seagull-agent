package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type SyscollectorConfig struct {
	Enabled        bool
	Every          time.Duration
	CmdTimeout     time.Duration
	MaxOutputBytes int64
	MaxPackages    int
}

type RuntimeConfig struct {
	mu       sync.RWMutex
	raw      map[string]interface{}
	hash     string
	path     string
	defaults SyscollectorConfig
	changed  chan struct{}
}

func NewRuntimeConfig(path string, defaults SyscollectorConfig) *RuntimeConfig {
	rc := &RuntimeConfig{
		raw:      map[string]interface{}{},
		path:     path,
		defaults: defaults,
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
	return deepCopyMap(r.raw)
}

func (r *RuntimeConfig) Apply(raw map[string]interface{}) (bool, error) {
	if raw == nil {
		raw = map[string]interface{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.raw = deepCopyMap(raw)
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
		if err := atomicWriteFile(r.path, b, 0o600); err != nil {
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
	if n, ok := toInt64(sys["max_output_bytes"]); ok && n > 0 {
		cfg.MaxOutputBytes = n
	}
	if n, ok := toInt64(sys["max_packages"]); ok && n > 0 {
		cfg.MaxPackages = int(n)
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
	r.raw = deepCopyMap(obj)
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

func deepCopyMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	b, err := json.Marshal(in)
	if err != nil {
		return map[string]interface{}{}
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]interface{}{}
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open temp file: %w", err)
	}
	_, werr := f.Write(data)
	_ = f.Sync()
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp file: %w", werr)
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp file: %w", cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

func toInt64(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		if err == nil {
			return i, true
		}
	}
	return 0, false
}
