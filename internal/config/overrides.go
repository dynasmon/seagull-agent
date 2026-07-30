package agentcfg

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func ApplyAgentRuntimeOverrides(cfg *Config, raw map[string]interface{}) {
	if cfg == nil {
		return
	}
	modules := asMap(raw["modules"])
	if modules == nil {
		return
	}
	if dd := asMap(modules["ddos"]); dd != nil {
		if enabled, ok := asBool(dd["enabled"]); ok {
			if enabled {
				cfg.Sources = ensureSource(cfg.Sources, "ddos")
			} else {
				cfg.Sources = removeSource(cfg.Sources, "ddos")
			}
		}

		if s, ok := asString(dd["iface"]); ok {
			cfg.DDoSIface = s
		}
		cfg.DDoSWindow = asDuration(dd["window"], cfg.DDoSWindow)
		cfg.DDoSEvalEvery = asDuration(dd["eval_every"], cfg.DDoSEvalEvery)
		cfg.DDoSCooldown = asDuration(dd["cooldown"], cfg.DDoSCooldown)

		if n, ok := asInt(dd["sustain_windows"]); ok && n > 0 {
			cfg.DDoSSustainWindows = n
		}
		if n, ok := asInt(dd["baseline_warmup_windows"]); ok && n > 0 {
			cfg.DDoSBaselineWarmupWindows = n
		}
		if f, ok := asFloat(dd["baseline_alpha"]); ok && f > 0 {
			cfg.DDoSBaselineAlpha = f
		}
		if f, ok := asFloat(dd["baseline_factor"]); ok && f > 1 {
			cfg.DDoSBaselineFactor = f
		}
		if f, ok := asFloat(dd["min_pps"]); ok && f > 0 {
			cfg.DDoSMinPPS = f
		}
		if f, ok := asFloat(dd["min_bps"]); ok && f > 0 {
			cfg.DDoSMinBPS = f
		}
		if n, ok := asInt(dd["min_packets"]); ok && n >= 0 {
			cfg.DDoSMinPackets = n
		}
		if n, ok := asInt(dd["min_requests"]); ok && n >= 0 {
			cfg.DDoSMinRequests = n
		}
		if n, ok := asInt(dd["min_confidence"]); ok && n > 0 {
			cfg.DDoSMinConfidence = n
		}
		if f, ok := asFloat(dd["min_syn_ratio"]); ok && f > 0 {
			cfg.DDoSMinSynRatio = f
		}
		if n, ok := asInt(dd["min_src_ips"]); ok && n > 0 {
			cfg.DDoSMinSrcIPs = n
		}
		if f, ok := asFloat(dd["min_src_entropy_norm"]); ok && f > 0 {
			cfg.DDoSMinSrcEntropyNorm = f
		}
		if b, ok := asBool(dd["enable_l7"]); ok {
			cfg.DDoSEnableL7 = b
		}
		if f, ok := asFloat(dd["min_http_rps"]); ok && f > 0 {
			cfg.DDoSMinHTTPRPS = f
		}
		if f, ok := asFloat(dd["min_tls_hs_rps"]); ok && f > 0 {
			cfg.DDoSMinTLSHSRPS = f
		}
		if f, ok := asFloat(dd["min_l7_ratio"]); ok && f > 0 {
			cfg.DDoSMinL7Ratio = f
		}
		if b, ok := asBool(dd["enable_entropy"]); ok {
			cfg.DDoSEnableEntropy = b
		}
		if f, ok := asFloat(dd["min_src_entropy_norm_signal"]); ok && f > 0 {
			cfg.DDoSMinSrcEntropyNormSignal = f
		}
		if f, ok := asFloat(dd["min_port_entropy_norm"]); ok && f > 0 {
			cfg.DDoSMinPortEntropyNorm = f
		}
		if n, ok := asInt(dd["port_entropy_topn"]); ok && n > 0 {
			cfg.DDoSPortEntropyTopN = n
		}
		if s, ok := asString(dd["cardinality_mode"]); ok {
			cfg.DDoSCardinalityMode = strings.ToLower(s)
		}
		if n, ok := asInt(dd["hll_precision"]); ok && n > 0 {
			cfg.DDoSHLLPrecision = n
		}
		if n, ok := asInt(dd["bloom_bits"]); ok && n > 0 {
			cfg.DDoSBloomBits = n
		}
		if n, ok := asInt(dd["max_unique_src"]); ok && n > 0 {
			cfg.DDoSMaxUniqueSrc = n
		}
		if n, ok := asInt(dd["top_src"]); ok && n > 0 {
			cfg.DDoSTopSrc = n
		}
		if n, ok := asInt(dd["max_batch"]); ok && n > 0 {
			cfg.DDoSMaxBatch = n
		}
		if n, ok := asInt(dd["backpressure_high_watermark"]); ok && n > 0 {
			cfg.DDoSBackpressureHighWM = n
		}
		if n, ok := asInt(dd["backpressure_sample_every"]); ok && n > 0 {
			cfg.DDoSBackpressureSampleEvery = n
		}
	}

	if pe := asMap(modules["proc_exec"]); pe != nil {
		if enabled, ok := asBool(pe["enabled"]); ok {
			if enabled {
				cfg.Sources = ensureSource(cfg.Sources, "proc_exec")
			} else {
				cfg.Sources = removeSource(cfg.Sources, "proc_exec")
			}
		}
		cfg.ProcExecEvery = asDuration(pe["every"], cfg.ProcExecEvery)
		if n, ok := asInt(pe["max_batch"]); ok && n > 0 {
			cfg.ProcExecMaxBatch = n
		}
		if b, ok := asBool(pe["hash_enabled"]); ok {
			cfg.ProcExecHashEnabled = b
		}
		if n, ok := asInt(pe["hash_max_bytes"]); ok && n > 0 {
			cfg.ProcExecHashMaxBytes = int64(n)
		}
		if b, ok := asBool(pe["emit_initial"]); ok {
			cfg.ProcExecEmitInitial = b
		}
		if vals := asStringSlice(pe["ignore_exe"]); len(vals) > 0 {
			set := make(map[string]bool, len(vals))
			for _, v := range vals {
				kv := strings.ToLower(strings.TrimSpace(v))
				if kv == "" {
					continue
				}
				set[kv] = true
			}
			cfg.ProcExecIgnoreExeNames = set
		}
		if vals := asStringSlice(pe["ignore_cmd_contains"]); len(vals) > 0 {
			out := make([]string, 0, len(vals))
			seen := map[string]struct{}{}
			for _, v := range vals {
				kv := strings.ToLower(strings.TrimSpace(v))
				if kv == "" {
					continue
				}
				if _, ok := seen[kv]; ok {
					continue
				}
				seen[kv] = struct{}{}
				out = append(out, kv)
			}
			cfg.ProcExecIgnoreCmdContains = out
		}
	}

	if fm := asMap(modules["fim"]); fm != nil {
		if enabled, ok := asBool(fm["enabled"]); ok {
			if enabled {
				cfg.Sources = ensureSource(cfg.Sources, "fim")
			} else {
				cfg.Sources = removeSource(cfg.Sources, "fim")
			}
		}
		cfg.FIMEvery = asDuration(fm["every"], cfg.FIMEvery)
		if n, ok := asInt(fm["max_batch"]); ok && n > 0 {
			cfg.FIMMaxBatch = n
		}
		if n, ok := asInt(fm["max_depth"]); ok && n > 0 {
			cfg.FIMMaxDepth = n
		}
		if b, ok := asBool(fm["hash_enabled"]); ok {
			cfg.FIMHashEnabled = b
		}
		if n, ok := asInt(fm["hash_max_bytes"]); ok && n > 0 {
			cfg.FIMHashMaxBytes = int64(n)
		}
		if b, ok := asBool(fm["emit_initial"]); ok {
			cfg.FIMEmitInitial = b
		}
		if vals := asStringSlice(fm["paths"]); len(vals) > 0 {
			cfg.FIMWatchPaths = vals
		}
		if vals := asStringSlice(fm["exclude_paths"]); len(vals) > 0 {
			cfg.FIMExcludePaths = vals
		}
	}

	if l7m := asMap(modules["l7"]); l7m != nil {
		if enabled, ok := asBool(l7m["enabled"]); ok {
			if enabled {
				cfg.Sources = ensureSource(cfg.Sources, "l7")
			} else {
				cfg.Sources = removeSource(cfg.Sources, "l7")
			}
		}
		if s, ok := asString(l7m["iface"]); ok {
			cfg.L7Iface = s
		}
		cfg.L7DedupTTL = asDuration(l7m["dedup_ttl"], cfg.L7DedupTTL)
		if n, ok := asInt(l7m["max_batch"]); ok && n > 0 {
			cfg.L7MaxBatch = n
		}
		if n, ok := asInt(l7m["max_payload_bytes"]); ok && n > 0 {
			cfg.L7MaxPayloadBytes = n
		}
		if b, ok := asBool(l7m["include_payload"]); ok {
			cfg.L7IncludePayload = b
		}
	}
	sanitizeL7Config(cfg)
}

func ensureSource(sources []string, source string) []string {
	for _, s := range sources {
		if s == source {
			return sources
		}
	}
	return append(sources, source)
}

func removeSource(sources []string, source string) []string {
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		if s == source {
			continue
		}
		out = append(out, s)
	}
	return out
}

func asMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return m
}

func asString(v interface{}) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}

func asBool(v interface{}) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		if s == "" {
			return false, false
		}
		switch s {
		case "1", "true", "yes", "y", "on":
			return true, true
		case "0", "false", "no", "n", "off":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

func asStringSlice(v interface{}) []string {
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
		for _, x := range t {
			s := strings.TrimSpace(fmt.Sprintf("%v", x))
			if s == "" || s == "<nil>" {
				continue
			}
			out = append(out, s)
		}
		return out
	case string:
		return splitCSV(t)
	default:
		return nil
	}
}

func asInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func asFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func asDuration(v interface{}, def time.Duration) time.Duration {
	switch t := v.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(t))
		if err == nil && d > 0 {
			return d
		}
	case float64:
		if t > 0 {
			return time.Duration(t * float64(time.Second))
		}
	case int:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case int64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case json.Number:
		if f, err := t.Float64(); err == nil && f > 0 {
			return time.Duration(f * float64(time.Second))
		}
	}
	return def
}
