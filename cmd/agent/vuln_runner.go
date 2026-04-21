package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/syscollector"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/vuln"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

type VulnScannerStatus struct {
	LastRunAt        time.Time
	LastSentAt       time.Time
	LastError        string
	LastPackagesHash string
	LastFindingCount int
	LastStoredCount  int
	LastScanUUID     string
}

func cloneAnyMap(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func recordScanPhaseTimestamp(phaseTimestamps map[string]string, phase string, at time.Time) {
	phase = strings.TrimSpace(strings.ToLower(phase))
	if phase == "" || at.IsZero() {
		return
	}
	if _, exists := phaseTimestamps[phase]; exists {
		return
	}
	phaseTimestamps[phase] = at.UTC().Format(time.RFC3339Nano)
}

func (a *Agent) sendVulnScanUpdate(ctx context.Context, timeout time.Duration, meta vuln.ScanMeta) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	payload, err := json.Marshal(vuln.IngestBatch{
		Scan:     &meta,
		Findings: []vuln.Finding{},
	})
	if err != nil {
		return fmt.Errorf("marshal scan update: %w", err)
	}
	ctxSend, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, _, err = a.sender.SendVulnIngest(ctxSend, payload)
	return err
}

func (a *Agent) startVulnScanner(ctx context.Context) {
	if a == nil || a.runtime == nil || a.sender == nil {
		return
	}

	go func() {
		lastTriggerToken := ""
		startupDelayed := false
		for {
			cfg := a.runtime.VulnScanner()
			a.vulnMu.RLock()
			lastRun := a.vulnStatus.LastRunAt
			a.vulnMu.RUnlock()

			forceScanNow := false
			triggerToken := strings.TrimSpace(cfg.ScanNowToken)
			if triggerToken != "" && triggerToken != lastTriggerToken {
				lastTriggerToken = triggerToken
				forceScanNow = true
			}

			nextIn := 30 * time.Second
			if cfg.Enabled {
				if forceScanNow {
					nextIn = 0
				} else if lastRun.IsZero() {
					nextIn = 0
					if !startupDelayed {
						nextIn = stableJitter(a.cfg.AgentID, "vuln.startup", a.cfg.VulnStartupJitter)
						startupDelayed = true
					}
				} else {
					d := cfg.Every - time.Since(lastRun)
					if d < 0 {
						nextIn = 0
					} else {
						nextIn = d
					}
				}
			}

			t := time.NewTimer(nextIn)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-a.runtime.Changed():
				t.Stop()
				continue
			case <-t.C:
			}

			if !cfg.Enabled {
				continue
			}

			scanTimeout := cfg.HTTPTimeout
			if scanTimeout <= 0 {
				scanTimeout = 60 * time.Second
			}
			scanTimeout = scanTimeout + cfg.CmdTimeout + 60*time.Second
			if scanTimeout < 60*time.Second {
				scanTimeout = 60 * time.Second
			}
			ctxRun, cancel := context.WithTimeout(ctx, scanTimeout)
			a.runVulnOnce(ctxRun, cfg, forceScanNow)
			cancel()
		}
	}()
}

func (a *Agent) runVulnOnce(ctx context.Context, cfg VulnScannerConfig, forceScan bool) {
	start := time.Now().UTC()
	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = 60 * time.Second
	}

	scanUUID := newUUIDv4()
	if forceScan {
		if tok := strings.TrimSpace(cfg.ScanNowToken); len(tok) >= 8 && len(tok) <= 36 {
			scanUUID = tok
		}
	}
	triggerSource := "scheduled"
	if forceScan {
		triggerSource = "manual"
	}
	queuedAt := start
	var acknowledgedAt *time.Time
	phaseTimestamps := map[string]string{}
	recordScanPhaseTimestamp(phaseTimestamps, "queued", queuedAt)

	baseScope := map[string]interface{}{
		"type":             "host_packages_inventory",
		"host_root":        strings.TrimSpace(cfg.HostRoot),
		"analysis_profile": cfg.AnalysisProfile,
		"manual_trigger":   forceScan,
		"scan_now_token":   strings.TrimSpace(cfg.ScanNowToken),
	}
	baseConfig := map[string]interface{}{
		"min_severity":     cfg.MinSeverity,
		"query_batch_size": cfg.QueryBatchSize,
		"osv_url":          cfg.OSVURL,
		"analysis_profile": cfg.AnalysisProfile,
		"exposure_enabled": cfg.ExposureEnabled,
		"manual_trigger":   forceScan,
	}
	baseStats := map[string]interface{}{}

	buildMeta := func(state, phase string, progressAt time.Time, acknowledgedAt, startedAt, finishedAt *time.Time, errSummary string) vuln.ScanMeta {
		meta := vuln.ScanMeta{
			ScanUUID:        scanUUID,
			Target:          hostnameOrFallback(),
			Tool:            "osv-wazuh-like",
			ToolVersion:     "1",
			Status:          state,
			LifecycleState:  state,
			CurrentPhase:    phase,
			QueuedAt:        &queuedAt,
			AcknowledgedAt:  acknowledgedAt,
			StartedAt:       startedAt,
			FinishedAt:      finishedAt,
			LastProgressAt:  &progressAt,
			TriggerSource:   triggerSource,
			ErrorSummary:    errSummary,
			Scope:           cloneAnyMap(baseScope),
			Config:          cloneAnyMap(baseConfig),
			Stats:           cloneAnyMap(baseStats),
			PhaseTimestamps: cloneStringMap(phaseTimestamps),
		}
		return meta
	}

	if forceScan {
		ack := time.Now().UTC()
		acknowledgedAt = &ack
		recordScanPhaseTimestamp(phaseTimestamps, "acknowledged", ack)
		_ = a.sendVulnScanUpdate(
			ctx,
			httpTimeout,
			buildMeta("acknowledged", "acknowledged", ack, acknowledgedAt, nil, nil, ""),
		)
	}

	startedAt := time.Now().UTC()
	recordScanPhaseTimestamp(phaseTimestamps, "running", startedAt)
	recordScanPhaseTimestamp(phaseTimestamps, "collecting_inventory", startedAt)
	_ = a.sendVulnScanUpdate(
		ctx,
		httpTimeout,
		buildMeta("running", "collecting_inventory", startedAt, acknowledgedAt, &startedAt, nil, ""),
	)

	a.vulnMu.Lock()
	a.vulnStatus.LastRunAt = startedAt
	a.vulnMu.Unlock()

	res, err := syscollector.Collect(ctx, syscollector.Options{
		CmdTimeout:     cfg.CmdTimeout,
		MaxOutputBytes: cfg.MaxOutputBytes,
		MaxPackages:    cfg.MaxPackages,
		HostRoot:       cfg.HostRoot,
	})
	if err != nil {
		finishedAt := time.Now().UTC()
		recordScanPhaseTimestamp(phaseTimestamps, "failed", finishedAt)
		_ = a.sendVulnScanUpdate(
			ctx,
			httpTimeout,
			buildMeta("failed", "failed", finishedAt, acknowledgedAt, &startedAt, &finishedAt, err.Error()),
		)
		a.vulnMu.Lock()
		a.vulnStatus.LastError = err.Error()
		a.vulnStatus.LastScanUUID = scanUUID
		a.vulnMu.Unlock()
		return
	}

	a.vulnMu.RLock()
	lastPkgHash := a.vulnStatus.LastPackagesHash
	lastSent := a.vulnStatus.LastSentAt
	a.vulnMu.RUnlock()

	doPkg := true
	if !forceScan && res.Snapshot.PackagesHash != "" && res.Snapshot.PackagesHash == lastPkgHash && !lastSent.IsZero() {
		doPkg = false
	}

	ecosystem := vuln.InferEcosystem(res.Snapshot.Manager, res.Snapshot.OS)
	if strings.TrimSpace(cfg.OSVURL) == "" {
		cfg.OSVURL = "https://api.osv.dev"
		baseConfig["osv_url"] = cfg.OSVURL
	}

	baseScope["package_manager"] = res.Snapshot.Manager
	baseScope["ecosystem"] = ecosystem
	baseScope["packages_hash"] = res.Snapshot.PackagesHash
	baseStats["inventory_packages"] = len(res.Snapshot.Packages)

	assetKey := "self"
	assetAgentID := a.cfg.AgentID
	targetLabel := hostnameOrFallback()

	progressAt := time.Now().UTC()
	if cfg.ExposureEnabled {
		recordScanPhaseTimestamp(phaseTimestamps, "analyzing_exposure", progressAt)
		_ = a.sendVulnScanUpdate(
			ctx,
			httpTimeout,
			buildMeta("running", "analyzing_exposure", progressAt, acknowledgedAt, &startedAt, nil, ""),
		)
	}

	findings := make([]vuln.Finding, 0, 512)
	var stats vuln.OSVStats
	var exposure *vuln.HostExposure
	if cfg.ExposureEnabled {
		if prof, exErr := vuln.CollectHostExposure(vuln.ExposureOptions{
			HostRoot: cfg.HostRoot,
			MaxPorts: 512,
		}); exErr == nil {
			exposure = &prof
		} else {
			baseStats["exposure_collection_error"] = exErr.Error()
		}
	}
	if exposure != nil {
		baseScope["exposure"] = exposure.ToEvidence()
		baseStats["exposure_surface_score"] = exposure.SurfaceScore
		baseStats["exposed_ports"] = len(exposure.ExposedPorts)
	}

	if doPkg {
		progressAt = time.Now().UTC()
		recordScanPhaseTimestamp(phaseTimestamps, "querying_source", progressAt)
		_ = a.sendVulnScanUpdate(
			ctx,
			httpTimeout,
			buildMeta("running", "querying_source", progressAt, acknowledgedAt, &startedAt, nil, ""),
		)
		pkgFindings, pkgStats, qErr := vuln.QueryOSV(ctx, res.Snapshot.Packages, vuln.OSVOptions{
			BaseURL:         cfg.OSVURL,
			Ecosystem:       ecosystem,
			MinSeverity:     cfg.MinSeverity,
			AnalysisProfile: cfg.AnalysisProfile,
			Exposure:        exposure,
			BatchSize:       cfg.QueryBatchSize,
			HTTPTimeout:     httpTimeout,
			AssetKey:        assetKey,
			AssetAgentID:    assetAgentID,
			TargetLabel:     targetLabel,
			OS:              res.Snapshot.OS,
			PackageManager:  res.Snapshot.Manager,
		})
		if qErr != nil {
			finishedAt := time.Now().UTC()
			recordScanPhaseTimestamp(phaseTimestamps, "failed", finishedAt)
			_ = a.sendVulnScanUpdate(
				ctx,
				httpTimeout,
				buildMeta("failed", "failed", finishedAt, acknowledgedAt, &startedAt, &finishedAt, qErr.Error()),
			)
			a.vulnMu.Lock()
			a.vulnStatus.LastError = qErr.Error()
			a.vulnStatus.LastScanUUID = scanUUID
			a.vulnMu.Unlock()
			return
		}
		findings = append(findings, pkgFindings...)
		stats = pkgStats
		baseStats["queried_packages"] = stats.QueriedPackages
		baseStats["received_vulns"] = stats.ReceivedVulns
		baseStats["emitted_findings"] = stats.EmittedFindings
	} else {
		baseStats["inventory_unchanged"] = true
		baseStats["query_skipped"] = true
		baseStats["query_skip_reason"] = "packages_unchanged"
		baseStats["queried_packages"] = 0
		baseStats["received_vulns"] = 0
		baseStats["emitted_findings"] = 0
	}

	progressAt = time.Now().UTC()
	recordScanPhaseTimestamp(phaseTimestamps, "normalizing_findings", progressAt)
	_ = a.sendVulnScanUpdate(
		ctx,
		httpTimeout,
		buildMeta("running", "normalizing_findings", progressAt, acknowledgedAt, &startedAt, nil, ""),
	)

	progressAt = time.Now().UTC()
	recordScanPhaseTimestamp(phaseTimestamps, "ingesting_results", progressAt)
	_ = a.sendVulnScanUpdate(
		ctx,
		httpTimeout,
		buildMeta("running", "ingesting_results", progressAt, acknowledgedAt, &startedAt, nil, ""),
	)

	finishedAt := time.Now().UTC()
	recordScanPhaseTimestamp(phaseTimestamps, "completed", finishedAt)
	batch := vuln.IngestBatch{
		Scan: &vuln.ScanMeta{
			ScanUUID:        scanUUID,
			Target:          targetLabel,
			Tool:            "osv-wazuh-like",
			ToolVersion:     "1",
			Status:          "completed",
			LifecycleState:  "completed",
			CurrentPhase:    "completed",
			QueuedAt:        &queuedAt,
			AcknowledgedAt:  acknowledgedAt,
			StartedAt:       &startedAt,
			FinishedAt:      &finishedAt,
			LastProgressAt:  &finishedAt,
			TriggerSource:   triggerSource,
			Scope:           cloneAnyMap(baseScope),
			Config:          cloneAnyMap(baseConfig),
			Stats:           cloneAnyMap(baseStats),
			PhaseTimestamps: cloneStringMap(phaseTimestamps),
		},
		Findings: findings,
	}

	payload, mErr := json.Marshal(batch)
	if mErr != nil {
		errMsg := fmt.Sprintf("marshal ingest: %s", mErr.Error())
		failedAt := time.Now().UTC()
		recordScanPhaseTimestamp(phaseTimestamps, "failed", failedAt)
		_ = a.sendVulnScanUpdate(
			ctx,
			httpTimeout,
			buildMeta("failed", "failed", failedAt, acknowledgedAt, &startedAt, &failedAt, errMsg),
		)
		a.vulnMu.Lock()
		a.vulnStatus.LastError = errMsg
		a.vulnStatus.LastScanUUID = scanUUID
		a.vulnMu.Unlock()
		return
	}

	ctxSend, cancel := context.WithTimeout(ctx, httpTimeout)
	statusCode, respBody, sendErr := a.sender.SendVulnIngest(ctxSend, payload)
	cancel()
	_ = statusCode

	stored := parseStoredFindings(respBody)
	if sendErr != nil {
		failedAt := time.Now().UTC()
		recordScanPhaseTimestamp(phaseTimestamps, "failed", failedAt)
		_ = a.sendVulnScanUpdate(
			ctx,
			httpTimeout,
			buildMeta("failed", "failed", failedAt, acknowledgedAt, &startedAt, &failedAt, sendErr.Error()),
		)
		a.vulnMu.Lock()
		a.vulnStatus.LastError = sendErr.Error()
		a.vulnStatus.LastSentAt = time.Time{}
		a.vulnStatus.LastScanUUID = scanUUID
		a.vulnMu.Unlock()
		return
	}

	a.vulnMu.Lock()
	a.vulnStatus.LastError = ""
	a.vulnStatus.LastSentAt = time.Now().UTC()
	a.vulnStatus.LastPackagesHash = res.Snapshot.PackagesHash
	a.vulnStatus.LastFindingCount = len(findings)
	a.vulnStatus.LastStoredCount = stored
	a.vulnStatus.LastScanUUID = scanUUID
	a.vulnMu.Unlock()

	if a.cfg.VulnEmitSummaryEvent {
		ev := model.NetEvent{
			AgentID:       a.cfg.AgentID,
			SchemaVersion: 1,
			Timestamp:     finishedAt,
			EventType:     "vuln_scan",
			SrcIP:         "",
			DstIP:         "",
			SrcPort:       0,
			DstPort:       0,
			Proto:         "",
			Bytes:         0,
			Extra: map[string]interface{}{
				"scan_uuid":           scanUUID,
				"tool":                "osv",
				"package_manager":     res.Snapshot.Manager,
				"ecosystem":           ecosystem,
				"queried_packages":    baseStats["queried_packages"],
				"emitted_findings":    baseStats["emitted_findings"],
				"stored_findings":     stored,
				"analysis_profile":    cfg.AnalysisProfile,
				"exposure_enabled":    cfg.ExposureEnabled,
				"exposure_score":      mapExposureScore(exposure),
				"manual_trigger":      forceScan,
				"inventory_unchanged": !doPkg,
				"duration_ms":         time.Since(start).Milliseconds(),
			},
		}
		ctxEv, cancelEv := context.WithTimeout(ctx, a.cfg.HTTPTimeout)
		_, _ = a.sender.SendEvents(ctxEv, []model.NetEvent{ev})
		cancelEv()
	}
}

func mapExposureScore(exposure *vuln.HostExposure) int {
	if exposure == nil {
		return 0
	}
	return exposure.SurfaceScore
}

func hostnameOrFallback() string {
	h, err := os.Hostname()
	if err == nil {
		h = strings.TrimSpace(h)
		if h != "" {
			return h
		}
	}
	return "host"
}

func parseStoredFindings(resp []byte) int {
	if len(resp) == 0 {
		return 0
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(resp, &obj); err != nil {
		return 0
	}
	if v, ok := obj["stored_findings"]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		}
	}
	return 0
}
