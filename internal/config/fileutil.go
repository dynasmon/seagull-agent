package agentcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
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

func ReadTextFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func DeepCopyMap(in map[string]interface{}) map[string]interface{} {
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

func ToInt64(v interface{}) (int64, bool) {
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
