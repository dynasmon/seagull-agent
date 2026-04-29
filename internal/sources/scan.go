package sources

import (
	"sort"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

type ScanStats struct {
	Total          int
	Effective      int
	UniqueSrcs     int
	UniqueDstPorts int
	SSHPortHits    int
	Class          string
	Score          int
}

func computeScanStats(scanEvents []model.NetEvent) ScanStats {
	if len(scanEvents) == 0 {
		return ScanStats{Class: "none"}
	}

	srcs := map[string]bool{}
	ports := map[int]bool{}
	sshHits := 0
	total := 0

	for _, ev := range scanEvents {
		if ev.EventType != "scan_probe" {
			continue
		}
		total++
		if ev.SrcIP != "" {
			srcs[ev.SrcIP] = true
		}
		if ev.DstPort > 0 {
			ports[ev.DstPort] = true
			if ev.DstPort == 22 {
				sshHits++
			}
		}
	}

	uniquePorts := len(ports)
	class := classifyScan(total, uniquePorts, sshHits)
	score := computeScanScore(total, uniquePorts, sshHits)

	effective := total
	if class == "service_noise" {
		effective = 0
	}

	return ScanStats{
		Total:          total,
		Effective:      effective,
		UniqueSrcs:     len(srcs),
		UniqueDstPorts: uniquePorts,
		SSHPortHits:    sshHits,
		Class:          class,
		Score:          score,
	}
}

func classifyScan(total, uniquePorts, sshHits int) string {
	if total <= 0 {
		return "none"
	}

	sshRatio := float64(sshHits) / float64(max(1, total))

	if uniquePorts >= 20 && total >= 60 {
		return "scan"
	}

	if uniquePorts <= 2 && total >= 20 && sshRatio >= 0.80 {
		return "service_noise"
	}

	if uniquePorts >= 8 && total >= 80 {
		return "suspicious"
	}

	return "low"
}

func computeScanScore(total, uniquePorts, sshHits int) int {
	score := uniquePorts*12 + min(total, 800)/8

	sshRatio := float64(sshHits) / float64(max(1, total))
	if uniquePorts <= 2 && sshRatio >= 0.80 {
		score = score / 4
	}

	if score < 0 {
		score = 0
	}
	return score
}

type scanKey struct {
	src   string
	dst   string
	proto string
}

type scanAgg struct {
	src   string
	dst   string
	proto string

	total   int
	sshHits int

	dstPorts  map[int]bool
	scanTypes map[string]bool
}

func buildScanSummaries(agentID string, scanEvents []model.NetEvent, window time.Duration) []model.NetEvent {
	if len(scanEvents) == 0 {
		return nil
	}

	m := map[scanKey]*scanAgg{}

	for _, ev := range scanEvents {
		if ev.EventType != "scan_probe" {
			continue
		}

		k := scanKey{src: ev.SrcIP, dst: ev.DstIP, proto: ev.Proto}
		a, ok := m[k]
		if !ok {
			a = &scanAgg{
				src:       ev.SrcIP,
				dst:       ev.DstIP,
				proto:     ev.Proto,
				dstPorts:  make(map[int]bool, 128),
				scanTypes: make(map[string]bool, 8),
			}
			m[k] = a
		}

		a.total++
		if ev.DstPort > 0 {
			a.dstPorts[ev.DstPort] = true
			if ev.DstPort == 22 {
				a.sshHits++
			}
		}
		if ev.Extra != nil {
			if st, ok := ev.Extra["scan_type"].(string); ok && st != "" {
				a.scanTypes[st] = true
			}
		}
	}

	out := make([]model.NetEvent, 0, len(m))
	now := time.Now().UTC()

	windowSec := int(window.Seconds())
	if windowSec <= 0 {
		windowSec = 1
	}

	for _, a := range m {
		uniquePorts := len(a.dstPorts)
		class := classifyScan(a.total, uniquePorts, a.sshHits)
		score := computeScanScore(a.total, uniquePorts, a.sshHits)

		sshRatio := 0.0
		if a.total > 0 {
			sshRatio = float64(a.sshHits) / float64(a.total)
		}

		out = append(out, model.NetEvent{
			AgentID:   agentID,
			EventType: "scan_summary",
			Timestamp: now,
			SrcIP:     a.src,
			DstIP:     a.dst,
			Proto:     a.proto,
			Bytes:     0,
			Extra: map[string]interface{}{
				"window_seconds":    windowSec,
				"total_probes":      a.total,
				"unique_dst_ports":  uniquePorts,
				"ssh_port_hits":     a.sshHits,
				"ssh_ratio":         round2(sshRatio),
				"unique_scan_types": len(a.scanTypes),
				"scan_class":        class,
				"scan_score":        score,
				"effective":         class != "service_noise",
			},
		})
	}

	return out
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}

func topNKeysInt(m map[int]bool, n int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	if n <= 0 || len(out) <= n {
		return out
	}
	return out[:n]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
