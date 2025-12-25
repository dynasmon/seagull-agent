package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/capture"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/sender"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Config struct {
	AgentID        string
	APIURL         string
	Sources        []string
	Interval       time.Duration
	HTTPTimeout    time.Duration
	SenderMaxBatch int

	AuthLogPath         string
	AuthIncludeAccepted bool

	ProcTCP4Path string
	ProcTCP6Path string

	SkipLoopback         bool
	SkipLinkLocal        bool
	SkipPrivateToPrivate bool

	DedupTTL       time.Duration
	EstablishedTTL time.Duration

	DenyCIDRs    []*net.IPNet
	DenyDstPorts map[int]bool
	DenySrcPorts map[int]bool

	ScanIface    string
	ScanDedupTTL time.Duration
	ScanMaxBatch int

	ScanMode string // raw|summary|both

	LogLevel          LogLevel
	LogSummaryEvery   time.Duration
	LogHeartbeatEvery time.Duration
	LogMinEvents      int
}

type CycleResult struct {
	Sent       int
	Status     int
	DurationMS int64
	Error      string

	SendAttempted bool

	SSHAuthEvents int

	ScanProbes      int
	ScanSrcs        int
	ScanDstPorts    int
	ScanSSHPortHits int
	ScanClass       string
	ScanScore       int

	Mode string
}

type SummaryState struct {
	StartedAt time.Time

	TotalSent       int
	TotalSSHAuth    int
	TotalScanProbes int

	MaxSent  int
	MaxScan  int
	MaxPorts int

	LastSendStatus int
	LastSendErr    string

	SendAttempts int
	SendErrors   int

	LastSummaryAt        time.Time
	LastSummaryTotalSent int
	LastSummaryTotalScan int

	Cycles int
}

func main() {
	cfg := loadConfig()
	log.Printf("[AGENT] id=%s api=%s sources=%v interval=%s scan_mode=%s",
		cfg.AgentID, cfg.APIURL, cfg.Sources, cfg.Interval, cfg.ScanMode,
	)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	{
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
		if err := waitForHealth(ctx, cfg.APIURL); err != nil {
			logJSON(LevelWarn, "backend_not_ready", map[string]interface{}{
				"agent_id": cfg.AgentID,
				"error":    err.Error(),
			})
		}
		cancel()
	}

	s := sender.New(cfg.APIURL, cfg.HTTPTimeout, cfg.SenderMaxBatch)

	var procCapturer *capture.Capturer
	if contains(cfg.Sources, "proc") {
		opts := capture.Options{
			DedupTTL:             cfg.DedupTTL,
			EstablishedTTL:       cfg.EstablishedTTL,
			SkipLoopback:         cfg.SkipLoopback,
			SkipLinkLocal:        cfg.SkipLinkLocal,
			SkipPrivateToPrivate: cfg.SkipPrivateToPrivate,
			IncludeIPv6:          true,
			MaxBatchSize:         300,
			DenyCIDRs:            cfg.DenyCIDRs,
			DenyDstPorts:         cfg.DenyDstPorts,
			DenySrcPorts:         cfg.DenySrcPorts,
		}
		procCapturer = capture.New(cfg.AgentID, cfg.ProcTCP4Path, cfg.ProcTCP6Path, opts)
	}

	var authCapturer *capture.AuthLogCapturer
	if contains(cfg.Sources, "authlog") {
		authCapturer = capture.NewAuthLogCapturer(cfg.AgentID, capture.AuthLogOptions{
			Path:            cfg.AuthLogPath,
			MaxBatchSize:    200,
			DedupTTL:        30 * time.Second,
			IncludeAccepted: cfg.AuthIncludeAccepted,
		})
	}

	var scanCapturer *capture.PcapScanCapturer
	if contains(cfg.Sources, "scan") {
		sc, err := capture.NewPcapScanCapturer(cfg.AgentID, capture.PcapScanOptions{
			Interface:     cfg.ScanIface,
			DedupTTL:      cfg.ScanDedupTTL,
			MaxBatchSize:  cfg.ScanMaxBatch,
			SkipLoopback:  cfg.SkipLoopback,
			SkipLinkLocal: cfg.SkipLinkLocal,
			DenyCIDRs:     cfg.DenyCIDRs,
			DenyDstPorts:  cfg.DenyDstPorts,
			DenySrcPorts:  cfg.DenySrcPorts,
		})
		if err != nil {
			log.Fatalf("[AGENT] scan init error: %v", err)
		}
		scanCapturer = sc

		go func() {
			if err := scanCapturer.Start(rootCtx); err != nil {
				logJSON(LevelError, "scan_capture_stopped", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
				stop()
			}
		}()
	}

	now0 := time.Now().UTC()
	state := SummaryState{
		StartedAt:            now0,
		LastSummaryAt:        now0,
		LastSummaryTotalSent: 0,
		LastSummaryTotalScan: 0,
	}

	runOnce := func() *CycleResult {
		start := time.Now().UTC()

		events := make([]model.NetEvent, 0, 1024)
		scanRaw := make([]model.NetEvent, 0, 1024)

		if authCapturer != nil {
			evs, err := authCapturer.Capture(time.Now().UTC())
			if err != nil {
				logJSON(LevelWarn, "authlog_capture_error", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
			} else if len(evs) > 0 {
				events = append(events, evs...)
			}
		}

		if procCapturer != nil {
			evs, err := procCapturer.Capture()
			if err != nil {
				logJSON(LevelWarn, "proc_capture_error", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
			} else if len(evs) > 0 {
				events = append(events, evs...)
			}
		}

		if scanCapturer != nil {
			evs := scanCapturer.Drain()
			if len(evs) > 0 {
				scanRaw = append(scanRaw, evs...)
			}
		}

		sshAuthEvents := 0
		for _, ev := range events {
			if ev.EventType == "ssh_auth" {
				sshAuthEvents++
			}
		}

		scanStats := computeScanStats(scanRaw)
		scanMode := normalizeScanMode(cfg.ScanMode)

		if scanMode == "raw" || scanMode == "both" {
			events = append(events, scanRaw...)
		}
		if scanMode == "summary" || scanMode == "both" {
			events = append(events, buildScanSummaries(cfg.AgentID, scanRaw, cfg.Interval)...)
		}

		if len(events) == 0 {
			return &CycleResult{
				Sent:          0,
				Status:        0,
				DurationMS:    time.Since(start).Milliseconds(),
				Error:         "",
				SendAttempted: false,
				SSHAuthEvents: 0,
				ScanProbes:    scanStats.Total,
				ScanSrcs:      scanStats.UniqueSrcs,
				ScanDstPorts:  scanStats.UniqueDstPorts,
				ScanSSHPortHits: scanStats.SSHPortHits,
				ScanClass:       scanStats.Class,
				ScanScore:       scanStats.Score,
				Mode:            scanMode,
			}
		}

		ctx, cancel := context.WithTimeout(rootCtx, cfg.HTTPTimeout)
		status, err := s.SendEvents(ctx, events)
		cancel()

		res := &CycleResult{
			Sent:          len(events),
			Status:        status,
			DurationMS:    time.Since(start).Milliseconds(),
			SendAttempted: true,

			SSHAuthEvents: sshAuthEvents,

			ScanProbes:      scanStats.Total,
			ScanSrcs:        scanStats.UniqueSrcs,
			ScanDstPorts:    scanStats.UniqueDstPorts,
			ScanSSHPortHits: scanStats.SSHPortHits,
			ScanClass:       scanStats.Class,
			ScanScore:       scanStats.Score,

			Mode: scanMode,
		}

		if err != nil {
			res.Error = err.Error()
		}

		return res
	}

	logLine := func(level LogLevel, msg string, res *CycleResult) {
		fields := map[string]interface{}{
			"agent_id":        cfg.AgentID,
			"sent":            res.Sent,
			"http_status":     res.Status,
			"send_attempted":  res.SendAttempted,
			"duration_ms":     res.DurationMS,
			"ssh_auth_events": res.SSHAuthEvents,

			"scan_probes":    res.ScanProbes,
			"scan_srcs":      res.ScanSrcs,
			"scan_dst_ports": res.ScanDstPorts,
			"scan_ssh_hits":  res.ScanSSHPortHits,
			"scan_class":     res.ScanClass,
			"scan_score":     res.ScanScore,
			"scan_mode":      res.Mode,
		}
		if res.Error != "" {
			fields["error"] = res.Error
		}
		logJSON(level, msg, fields)
	}

	shouldLogCycle := func(res *CycleResult) bool {
		if cfg.LogLevel == LevelDebug {
			return res.Sent > 0 || res.Error != ""
		}
		if res.Error != "" {
			return true
		}
		if res.Sent >= cfg.LogMinEvents {
			return true
		}
		if res.SSHAuthEvents > 0 {
			return true
		}
		if res.ScanClass == "scan" || res.ScanClass == "suspicious" {
			return true
		}
		return false
	}

	applyToSummary := func(res *CycleResult) {
		state.Cycles++

		state.TotalSent += res.Sent
		state.TotalSSHAuth += res.SSHAuthEvents
		state.TotalScanProbes += res.ScanProbes

		if res.SendAttempted {
			state.SendAttempts++
			if res.Error != "" {
				state.SendErrors++
				state.LastSendErr = res.Error
			} else {
				state.LastSendErr = ""
			}
			if res.Status != 0 {
				state.LastSendStatus = res.Status
			}
		}

		if res.Sent > state.MaxSent {
			state.MaxSent = res.Sent
		}
		if res.ScanProbes > state.MaxScan {
			state.MaxScan = res.ScanProbes
		}
		if res.ScanDstPorts > state.MaxPorts {
			state.MaxPorts = res.ScanDstPorts
		}
	}

	flushSummary := func() {
		uptime := time.Since(state.StartedAt)
		avgRate := 0.0
		if uptime.Seconds() > 0 {
			avgRate = float64(state.TotalSent) / uptime.Seconds()
		}

		period := time.Since(state.LastSummaryAt)
		if period <= 0 {
			period = cfg.LogSummaryEvery
			if period <= 0 {
				period = 10 * time.Second
			}
		}

		sentDelta := state.TotalSent - state.LastSummaryTotalSent
		scanDelta := state.TotalScanProbes - state.LastSummaryTotalScan

		sentPerSec := 0.0
		scanPerSec := 0.0
		if period.Seconds() > 0 {
			sentPerSec = float64(sentDelta) / period.Seconds()
			scanPerSec = float64(scanDelta) / period.Seconds()
		}

		logJSON(LevelInfo, "agent_summary", map[string]interface{}{
			"agent_id":   cfg.AgentID,
			"uptime_sec": int(uptime.Seconds()),
			"cycles":     state.Cycles,

			"total_sent":        state.TotalSent,       // legacy
			"total_scan_probes": state.TotalScanProbes, // legacy
			"total_ssh_auth":    state.TotalSSHAuth,    // legacy

			"events_sent_total":           state.TotalSent,
			"scan_probes_observed_total":  state.TotalScanProbes,
			"ssh_auth_events_total":       state.TotalSSHAuth,

			"summary_period_sec":  int(period.Seconds()),
			"sent_delta":          sentDelta,
			"scan_probes_delta":   scanDelta,
			"sent_per_sec":        round2(sentPerSec),
			"scan_probes_per_sec": round2(scanPerSec),

			"avg_sent_per_sec": round2(avgRate),

			"max_sent_cycle":  state.MaxSent,
			"max_scan_cycle":  state.MaxScan,
			"max_ports_cycle": state.MaxPorts,

			"last_http_status":     state.LastSendStatus,
			"last_error":           state.LastSendErr,
			"send_attempts_total":  state.SendAttempts,
			"send_errors_total":    state.SendErrors,

			"scan_mode": normalizeScanMode(cfg.ScanMode),
		})

		state.LastSummaryAt = time.Now().UTC()
		state.LastSummaryTotalSent = state.TotalSent
		state.LastSummaryTotalScan = state.TotalScanProbes
	}

	lastHeartbeat := time.Now().UTC()

	if res := runOnce(); res != nil {
		applyToSummary(res)
		if shouldLogCycle(res) {
			level := LevelInfo
			if res.Error != "" {
				level = LevelWarn
			}
			if cfg.LogLevel == LevelDebug {
				level = LevelDebug
			}
			logLine(level, "cycle", res)
		}
	}

	pollTicker := time.NewTicker(cfg.Interval)
	defer pollTicker.Stop()

	summaryTicker := time.NewTicker(cfg.LogSummaryEvery)
	defer summaryTicker.Stop()

	for {
		select {
		case <-rootCtx.Done():
			logJSON(LevelInfo, "shutdown", map[string]interface{}{
				"agent_id": cfg.AgentID,
			})
			return

		case <-pollTicker.C:
			res := runOnce()
			if res == nil {
				continue
			}

			applyToSummary(res)

			if shouldLogCycle(res) {
				level := LevelInfo
				if res.Error != "" {
					level = LevelWarn
				} else if res.ScanClass == "scan" || res.ScanClass == "suspicious" {
					level = LevelInfo
				} else if cfg.LogLevel == LevelDebug {
					level = LevelDebug
				}
				logLine(level, "cycle", res)
			}

			if time.Since(lastHeartbeat) >= cfg.LogHeartbeatEvery {
				logJSON(LevelInfo, "heartbeat", map[string]interface{}{
					"agent_id":    cfg.AgentID,
					"uptime_sec":  int(time.Since(state.StartedAt).Seconds()),
					"cycles":      state.Cycles,
					"last_status": state.LastSendStatus,
				})
				lastHeartbeat = time.Now().UTC()
			}

		case <-summaryTicker.C:
			flushSummary()
		}
	}
}

func loadConfig() Config {
	agentID := getEnv("NETWATCH_AGENT_ID", "agent-unknown")
	apiURL := getEnv("NETWATCH_API_URL", "http://localhost:8000")
	sources := splitCSVLower(getEnv("NETWATCH_SOURCES", "authlog,proc"))

	interval := parseDuration(getEnv("NETWATCH_POLL_INTERVAL", "1s"), 1*time.Second)
	httpTimeout := parseDuration(getEnv("NETWATCH_HTTP_TIMEOUT", "10s"), 10*time.Second)
	senderMaxBatch := parseInt(getEnv("NETWATCH_SENDER_MAX_BATCH", "300"), 300)

	logPath := getEnv("NETWATCH_AUTHLOG_PATH", "/var/log/auth.log")
	includeAccepted := parseBool(getEnv("NETWATCH_AUTHLOG_INCLUDE_ACCEPTED", "false"), false)

	procTCP4Path := getEnv("NETWATCH_PROC_TCP4_PATH", "/proc/net/tcp")
	procTCP6Path := getEnv("NETWATCH_PROC_TCP6_PATH", "/proc/net/tcp6")

	skipLoopback := parseBool(getEnv("NETWATCH_SKIP_LOOPBACK", "true"), true)
	skipLinkLocal := parseBool(getEnv("NETWATCH_SKIP_LINK_LOCAL", "true"), true)
	skipPrivate := parseBool(getEnv("NETWATCH_SKIP_PRIVATE_TO_PRIVATE", "false"), false)

	dedupTTL := parseDuration(getEnv("NETWATCH_DEDUP_TTL", "30s"), 30*time.Second)
	establishedTTL := parseDuration(getEnv("NETWATCH_ESTABLISHED_TTL", "10m"), 10*time.Minute)

	denyCIDRs := parseCIDRs(getEnv("NETWATCH_DENY_CIDRS", ""))
	denyDstPorts := parseIntSet(getEnv("NETWATCH_DENY_DST_PORTS", ""))
	denySrcPorts := parseIntSet(getEnv("NETWATCH_DENY_SRC_PORTS", ""))

	scanIface := getEnv("NETWATCH_PCAP_IFACE", "any")
	scanDedup := parseDuration(getEnv("NETWATCH_SCAN_DEDUP_TTL", "2s"), 2*time.Second)
	scanMaxBatch := parseInt(getEnv("NETWATCH_SCAN_MAX_BATCH", "5000"), 5000)

	scanMode := getEnv("NETWATCH_SCAN_MODE", "summary")

	levelStr := getEnv("NETWATCH_LOG_LEVEL", "info")
	logLevel := parseLogLevel(levelStr)

	logSummaryEvery := parseDuration(getEnv("NETWATCH_LOG_SUMMARY_EVERY", "10s"), 10*time.Second)
	logHeartbeatEvery := parseDuration(getEnv("NETWATCH_LOG_HEARTBEAT_EVERY", "60s"), 60*time.Second)
	logMinEvents := parseInt(getEnv("NETWATCH_LOG_MIN_EVENTS", "50"), 50)

	return Config{
		AgentID:        agentID,
		APIURL:         apiURL,
		Sources:        sources,
		Interval:       interval,
		HTTPTimeout:    httpTimeout,
		SenderMaxBatch: senderMaxBatch,

		AuthLogPath:         logPath,
		AuthIncludeAccepted: includeAccepted,

		ProcTCP4Path: procTCP4Path,
		ProcTCP6Path: procTCP6Path,

		SkipLoopback:         skipLoopback,
		SkipLinkLocal:        skipLinkLocal,
		SkipPrivateToPrivate: skipPrivate,

		DedupTTL:       dedupTTL,
		EstablishedTTL: establishedTTL,

		DenyCIDRs:    denyCIDRs,
		DenyDstPorts: denyDstPorts,
		DenySrcPorts: denySrcPorts,

		ScanIface:    scanIface,
		ScanDedupTTL: scanDedup,
		ScanMaxBatch: scanMaxBatch,

		ScanMode: scanMode,

		LogLevel:          logLevel,
		LogSummaryEvery:   logSummaryEvery,
		LogHeartbeatEvery: logHeartbeatEvery,
		LogMinEvents:      logMinEvents,
	}
}

func waitForHealth(ctx context.Context, baseURL string) error {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/health"

	client := &http.Client{Timeout: 2 * time.Second}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("health check timeout: %w", ctx.Err())
		case <-t.C:
		}
	}
}

type ScanStats struct {
	Total          int
	UniqueSrcs     int
	UniqueDstPorts int
	SSHPortHits    int
	Class          string
	Score          int
}

func computeScanStats(scan []model.NetEvent) ScanStats {
	if len(scan) == 0 {
		return ScanStats{Class: "none"}
	}

	srcs := map[string]bool{}
	ports := map[int]bool{}
	sshHits := 0

	for _, ev := range scan {
		if ev.EventType != "scan_probe" {
			continue
		}
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

	total := len(scan)
	uniquePorts := len(ports)

	class := classifyScan(total, uniquePorts, sshHits)
	score := computeScanScore(total, uniquePorts, sshHits)

	return ScanStats{
		Total:          total,
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
	if uniquePorts >= 20 && total >= 60 {
		return "scan"
	}
	if uniquePorts <= 2 && total >= 20 {
		ratio := float64(sshHits) / float64(max(1, total))
		if ratio >= 0.80 {
			return "service_noise"
		}
	}
	if uniquePorts >= 8 && total >= 80 {
		return "suspicious"
	}
	return "low"
}

func computeScanScore(total, uniquePorts, sshHits int) int {
	base := uniquePorts*10 + min(total, 500)/5
	if uniquePorts <= 2 && float64(sshHits)/float64(max(1, total)) >= 0.80 {
		base = base / 3
	}
	return base
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

func buildScanSummaries(agentID string, scan []model.NetEvent, window time.Duration) []model.NetEvent {
	if len(scan) == 0 {
		return nil
	}

	m := map[scanKey]*scanAgg{}

	for _, ev := range scan {
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

	for _, a := range m {
		uniquePorts := len(a.dstPorts)
		class := classifyScan(a.total, uniquePorts, a.sshHits)
		score := computeScanScore(a.total, uniquePorts, a.sshHits)

		out = append(out, model.NetEvent{
			AgentID:   agentID,
			EventType: "scan_summary",
			Timestamp: now,
			SrcIP:     a.src,
			DstIP:     a.dst,
			Proto:     a.proto,
			Bytes:     0,
			Extra: map[string]interface{}{
				"window_seconds":    int(window.Seconds()),
				"total_probes":      a.total,
				"unique_dst_ports":  uniquePorts,
				"ssh_port_hits":     a.sshHits,
				"unique_scan_types": len(a.scanTypes),
				"scan_class":        class,
				"scan_score":        score,
			},
		})
	}

	return out
}

func logJSON(level LogLevel, msg string, fields map[string]interface{}) {
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["level"] = levelString(level)
	fields["msg"] = msg

	b, err := json.Marshal(fields)
	if err != nil {
		log.Printf("[LOG] marshal_error=%v msg=%s", err, msg)
		return
	}
	log.Println(string(b))
}

func parseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func levelString(l LogLevel) string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

func normalizeScanMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "raw", "both", "summary":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "summary"
	}
}

func getEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func splitCSVLower(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func parseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func parseInt(s string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func parseBool(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func parseCIDRs(csv string) []*net.IPNet {
	parts := strings.Split(csv, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err == nil && n != nil {
			out = append(out, n)
		}
	}
	return out
}

func parseIntSet(csv string) map[int]bool {
	parts := strings.Split(csv, ",")
	out := make(map[int]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 {
			out[n] = true
		}
	}
	return out
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
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
