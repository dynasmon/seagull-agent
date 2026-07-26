package runtime

import (
	"context"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/mathx"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/sources"
)

func (s *Service) loop(rootCtx context.Context) {
	pollTicker := time.NewTicker(s.cfg.Interval)
	defer pollTicker.Stop()

	summaryTicker := time.NewTicker(s.cfg.LogSummaryEvery)
	defer summaryTicker.Stop()

	s.runAndLog(rootCtx)

	for {
		select {
		case <-rootCtx.Done():
			agentcfg.LogJSON(agentcfg.LevelInfo, "shutdown", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
			})
			return
		case <-pollTicker.C:
			s.runAndLog(rootCtx)
			s.maybeHeartbeat()
		case <-summaryTicker.C:
			s.flushSummary()
		}
	}
}

func (s *Service) runAndLog(rootCtx context.Context) {
	res := s.sources.RunOnce(rootCtx)
	if res == nil {
		return
	}
	if res.SendAttempted {
		s.enrollment.MaybeRecoverIdentity(rootCtx, "event_ingest", res.Error, res.Status)
	}

	s.applyToSummary(res)

	if s.shouldLogCycle(res) {
		level := agentcfg.LevelInfo
		if res.Error != "" {
			level = agentcfg.LevelWarn
		}
		if s.cfg.LogLevel == agentcfg.LevelDebug {
			level = agentcfg.LevelDebug
		}
		s.logCycle(level, res)
	}
}

func (s *Service) shouldLogCycle(res *sources.CycleResult) bool {
	if s.cfg.LogLevel == agentcfg.LevelDebug {
		return res.Sent > 0 || res.Error != ""
	}
	if res.Error != "" {
		return true
	}
	if res.Sent >= s.cfg.LogMinEvents {
		return true
	}
	if res.SSHAuthEvents > 0 {
		return true
	}
	return res.ScanClass == "scan" || res.ScanClass == "suspicious"
}

func (s *Service) logCycle(level agentcfg.LogLevel, res *sources.CycleResult) {
	fields := map[string]interface{}{
		"agent_id":              s.cfg.AgentID,
		"sent":                  res.Sent,
		"http_status":           res.Status,
		"send_attempted":        res.SendAttempted,
		"duration_ms":           res.DurationMS,
		"ssh_auth_events":       res.SSHAuthEvents,
		"scan_probes_total":     res.ScanProbesTotal,
		"scan_probes_effective": res.ScanProbesEffective,
		"scan_srcs":             res.ScanSrcs,
		"scan_dst_ports":        res.ScanDstPorts,
		"scan_ssh_hits":         res.ScanSSHPortHits,
		"scan_class":            res.ScanClass,
		"scan_score":            res.ScanScore,
		"scan_mode":             res.Mode,
	}
	if res.Error != "" {
		fields["error"] = res.Error
	}
	agentcfg.LogJSON(level, "cycle", fields)
}

func (s *Service) applyToSummary(res *sources.CycleResult) {
	s.state.Cycles++
	s.state.EventsSentTotal += res.Sent
	s.state.SSHAuthEventsTotal += res.SSHAuthEvents
	s.state.ScanProbesTotal += res.ScanProbesTotal
	s.state.ScanProbesEffective += res.ScanProbesEffective

	if res.Sent > s.state.MaxSentCycle {
		s.state.MaxSentCycle = res.Sent
	}
	if res.ScanProbesTotal > s.state.MaxScanCycle {
		s.state.MaxScanCycle = res.ScanProbesTotal
	}
	if res.ScanDstPorts > s.state.MaxPortsCycle {
		s.state.MaxPortsCycle = res.ScanDstPorts
	}

	if res.SendAttempted {
		s.state.SendAttemptsTotal++
		if res.Error != "" {
			s.state.SendErrorsTotal++
			s.state.LastError = res.Error
		} else {
			s.state.LastError = ""
		}
		if res.Status != 0 {
			s.state.LastHTTPStatus = res.Status
		}
	}
}

func (s *Service) flushSummary() {
	now := time.Now().UTC()
	uptime := time.Since(s.state.StartedAt)

	period := now.Sub(s.state.LastSummaryAt)
	if period <= 0 {
		period = s.cfg.LogSummaryEvery
		if period <= 0 {
			period = 10 * time.Second
		}
	}

	sentDelta := s.state.EventsSentTotal - s.state.LastSummaryEventsSent
	scanDelta := s.state.ScanProbesTotal - s.state.LastSummaryScanTotal
	scanEffDelta := s.state.ScanProbesEffective - s.state.LastSummaryScanEffective

	sentPerSec := 0.0
	scanPerSec := 0.0
	scanEffPerSec := 0.0
	if period.Seconds() > 0 {
		sentPerSec = float64(sentDelta) / period.Seconds()
		scanPerSec = float64(scanDelta) / period.Seconds()
		scanEffPerSec = float64(scanEffDelta) / period.Seconds()
	}

	avgSentPerSec := 0.0
	if uptime.Seconds() > 0 {
		avgSentPerSec = float64(s.state.EventsSentTotal) / uptime.Seconds()
	}

	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_summary", map[string]interface{}{
		"agent_id":                           s.cfg.AgentID,
		"scan_mode":                          agentcfg.NormalizeScanMode(s.cfg.ScanMode),
		"uptime_sec":                         int(uptime.Seconds()),
		"cycles":                             s.state.Cycles,
		"events_sent_total":                  s.state.EventsSentTotal,
		"ssh_auth_events_total":              s.state.SSHAuthEventsTotal,
		"scan_probes_total":                  s.state.ScanProbesTotal,
		"scan_probes_effective":              s.state.ScanProbesEffective,
		"summary_period_sec":                 int(period.Seconds()),
		"sent_delta":                         sentDelta,
		"scan_probes_delta":                  scanDelta,
		"scan_probes_effective_delta":        scanEffDelta,
		"sent_per_sec":                       mathx.Round2(sentPerSec),
		"scan_probes_per_sec":                mathx.Round2(scanPerSec),
		"scan_probes_effective_per_sec":      mathx.Round2(scanEffPerSec),
		"avg_sent_per_sec":                   mathx.Round2(avgSentPerSec),
		"max_sent_cycle":                     s.state.MaxSentCycle,
		"max_scan_cycle":                     s.state.MaxScanCycle,
		"max_ports_cycle":                    s.state.MaxPortsCycle,
		"send_attempts_total":                s.state.SendAttemptsTotal,
		"send_errors_total":                  s.state.SendErrorsTotal,
		"response_actions_staged_total":      s.state.ResponseActionsStagedTotal,
		"response_actions_poll_errors_total": s.state.ResponseActionPollErrorsTotal,
		"last_http_status":                   s.state.LastHTTPStatus,
		"last_error":                         s.state.LastError,
	})

	s.state.LastSummaryAt = now
	s.state.LastSummaryEventsSent = s.state.EventsSentTotal
	s.state.LastSummaryScanTotal = s.state.ScanProbesTotal
	s.state.LastSummaryScanEffective = s.state.ScanProbesEffective
}

func (s *Service) maybeHeartbeat() {
	if time.Since(s.state.LastHeartbeatAt) < s.cfg.LogHeartbeatEvery {
		return
	}
	uptime := time.Since(s.state.StartedAt)

	agentcfg.LogJSON(agentcfg.LevelInfo, "heartbeat", map[string]interface{}{
		"agent_id":         s.cfg.AgentID,
		"uptime_sec":       int(uptime.Seconds()),
		"cycles":           s.state.Cycles,
		"last_http_status": s.state.LastHTTPStatus,
	})
	s.state.LastHeartbeatAt = time.Now().UTC()
}
