package sources

import (
	"context"
	"strings"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

type CycleResult struct {
	Sent          int
	Status        int
	DurationMS    int64
	Error         string
	SendAttempted bool

	SSHAuthEvents int

	ScanProbesTotal     int
	ScanProbesEffective int
	ScanSrcs            int
	ScanDstPorts        int
	ScanSSHPortHits     int
	ScanClass           string
	ScanScore           int

	Mode string
}

func (m *Manager) RunOnce(rootCtx context.Context) *CycleResult {
	start := time.Now().UTC()

	events := make([]model.NetEvent, 0, 1024)
	scanRaw := make([]model.NetEvent, 0, 1024)
	ddosEvs := make([]model.NetEvent, 0, 64)

	if m.authCapturer != nil {
		evs, err := m.authCapturer.Capture(time.Now().UTC())
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "authlog_capture_error", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if m.procCapturer != nil {
		evs, err := m.procCapturer.Capture()
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "proc_capture_error", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if m.procExecCapturer != nil {
		evs, err := m.procExecCapturer.Capture(time.Now().UTC())
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "proc_exec_capture_error", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if m.fimCapturer != nil {
		evs, err := m.fimCapturer.Capture(time.Now().UTC())
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "fim_capture_error", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if m.lateralProc != nil {
		evs, err := m.lateralProc.Capture()
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "lateral_proc_capture_error", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if m.lateralPcap != nil {
		evs := m.lateralPcap.Drain()
		if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if m.scanCapturer != nil {
		evs := m.scanCapturer.Drain()
		if len(evs) > 0 {
			scanRaw = append(scanRaw, evs...)
		}
	}

	if m.ddosCapturer != nil {
		evs := m.ddosCapturer.Drain()
		if len(evs) > 0 {
			ddosEvs = append(ddosEvs, evs...)
		}
	}

	if m.l7Capturer != nil {
		evs := m.l7Capturer.Drain()
		if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	sshAuthEvents := 0
	for _, ev := range events {
		if ev.EventType == "ssh_auth" {
			sshAuthEvents++
		}
	}

	scanStats := computeScanStats(scanRaw)
	mode := agentcfg.NormalizeScanMode(m.cfg.ScanMode)

	if scanStats.Class == "service_noise" {
		scanStats.Effective = 0
	}

	if mode == "raw" || mode == "both" {
		events = append(events, scanRaw...)
	}
	if mode == "summary" || mode == "both" {
		events = append(events, buildScanSummaries(m.cfg.AgentID, scanRaw, m.cfg.Interval)...)
	}

	if len(ddosEvs) > 0 {
		events = append(events, ddosEvs...)
	}

	if len(events) == 0 {
		return &CycleResult{
			Sent:          0,
			Status:        0,
			DurationMS:    time.Since(start).Milliseconds(),
			Error:         "",
			SendAttempted: false,

			SSHAuthEvents: sshAuthEvents,

			ScanProbesTotal:     scanStats.Total,
			ScanProbesEffective: scanStats.Effective,
			ScanSrcs:            scanStats.UniqueSrcs,
			ScanDstPorts:        scanStats.UniqueDstPorts,
			ScanSSHPortHits:     scanStats.SSHPortHits,
			ScanClass:           scanStats.Class,
			ScanScore:           scanStats.Score,

			Mode: mode,
		}
	}

	normalizeEvents(events, m.cfg.AgentID)
	ctx, cancel := context.WithTimeout(rootCtx, m.cfg.HTTPTimeout)
	status, err := m.sender.SendEvents(ctx, events)
	cancel()

	res := &CycleResult{
		Sent:          len(events),
		Status:        status,
		DurationMS:    time.Since(start).Milliseconds(),
		SendAttempted: true,

		SSHAuthEvents: sshAuthEvents,

		ScanProbesTotal:     scanStats.Total,
		ScanProbesEffective: scanStats.Effective,
		ScanSrcs:            scanStats.UniqueSrcs,
		ScanDstPorts:        scanStats.UniqueDstPorts,
		ScanSSHPortHits:     scanStats.SSHPortHits,
		ScanClass:           scanStats.Class,
		ScanScore:           scanStats.Score,

		Mode: mode,
	}

	if err != nil {
		res.Error = err.Error()
	}

	return res
}

func normalizeEvents(events []model.NetEvent, fallbackAgentID string) {
	if len(events) == 0 {
		return
	}
	now := time.Now().UTC()
	for i := range events {
		ev := &events[i]
		if strings.TrimSpace(ev.AgentID) == "" {
			ev.AgentID = fallbackAgentID
		}
		if ev.SchemaVersion <= 0 {
			ev.SchemaVersion = 1
		}
		if ev.Timestamp.IsZero() {
			ev.Timestamp = now
		}
		if ev.Extra == nil {
			ev.Extra = map[string]interface{}{}
		}
	}
}
