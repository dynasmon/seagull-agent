package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/syscollector"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/vuln"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type VulnScannerStatus struct {
	LastRunAt       time.Time
	LastSentAt      time.Time
	LastError       string
	LastPackagesHash string
	LastFindingCount int
	LastStoredCount  int
	LastScanUUID     string
}

func (a *Agent) startVulnScanner(ctx context.Context) {
	if a == nil || a.runtime == nil || a.sender == nil {
		return
	}
	if !contains(a.cfg.Sources, "vuln") {
		return
	}

	go func() {
		for {
			cfg := a.runtime.VulnScanner()
			a.vulnMu.RLock()
			lastRun := a.vulnStatus.LastRunAt
			a.vulnMu.RUnlock()

			nextIn := 30 * time.Second
			if cfg.Enabled {
				if lastRun.IsZero() {
					nextIn = 0
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
				// proceed
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
			a.runVulnOnce(ctxRun, cfg)
			cancel()
		}
	}()
}

func (a *Agent) runVulnOnce(ctx context.Context, cfg VulnScannerConfig) {
	start := time.Now().UTC()
	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = 60 * time.Second
	}

	// Collect packages (best-effort host-root if configured).
	res, err := syscollector.Collect(ctx, syscollector.Options{
		CmdTimeout:     cfg.CmdTimeout,
		MaxOutputBytes: cfg.MaxOutputBytes,
		MaxPackages:    cfg.MaxPackages,
		HostRoot:       cfg.HostRoot,
	})

	a.vulnMu.Lock()
	a.vulnStatus.LastRunAt = time.Now().UTC()
	a.vulnMu.Unlock()

	if err != nil {
		a.vulnMu.Lock()
		a.vulnStatus.LastError = err.Error()
		a.vulnMu.Unlock()
		return
	}

	// Skip OSV query if package set didn't change since last successful send.
	a.vulnMu.RLock()
	lastHash := a.vulnStatus.LastPackagesHash
	lastSent := a.vulnStatus.LastSentAt
	a.vulnMu.RUnlock()

	if res.Snapshot.PackagesHash != "" && res.Snapshot.PackagesHash == lastHash && !lastSent.IsZero() {
		a.vulnMu.Lock()
		a.vulnStatus.LastError = ""
		a.vulnMu.Unlock()
		return
	}

	ecosystem := vuln.InferEcosystem(res.Snapshot.Manager, res.Snapshot.OS)
	if strings.TrimSpace(cfg.OSVURL) == "" {
		cfg.OSVURL = "https://api.osv.dev"
	}

	assetKey := "self"
	assetAgentID := a.cfg.AgentID
	targetLabel := hostnameOrFallback()

	findings, stats, qErr := vuln.QueryOSV(ctx, res.Snapshot.Packages, vuln.OSVOptions{
		BaseURL:        cfg.OSVURL,
		Ecosystem:      ecosystem,
		MinSeverity:    cfg.MinSeverity,
		BatchSize:      cfg.QueryBatchSize,
		HTTPTimeout:    httpTimeout,
		AssetKey:       assetKey,
		AssetAgentID:   assetAgentID,
		TargetLabel:    targetLabel,
		OS:             res.Snapshot.OS,
		PackageManager: res.Snapshot.Manager,
	})
	if qErr != nil {
		a.vulnMu.Lock()
		a.vulnStatus.LastError = qErr.Error()
		a.vulnMu.Unlock()
		return
	}

	// Build ingest payload.
	scanUUID := newUUIDv4()
	now := time.Now().UTC()
	finished := now
	started := start
	batch := vuln.IngestBatch{
		Scan: &vuln.ScanMeta{
			ScanUUID:    scanUUID,
			Target:      targetLabel,
			Tool:        "osv",
			ToolVersion: "1",
			Status:      "finished",
			StartedAt:   &started,
			FinishedAt:  &finished,
			Scope: map[string]interface{}{
				"type":          "host_packages",
				"host_root":     strings.TrimSpace(cfg.HostRoot),
				"package_manager": res.Snapshot.Manager,
				"ecosystem":     ecosystem,
				"packages_hash": res.Snapshot.PackagesHash,
			},
			Config: map[string]interface{}{
				"min_severity":     cfg.MinSeverity,
				"query_batch_size": cfg.QueryBatchSize,
				"osv_url":          cfg.OSVURL,
			},
			Stats: map[string]interface{}{
				"queried_packages": stats.QueriedPackages,
				"received_vulns":   stats.ReceivedVulns,
				"emitted_findings": stats.EmittedFindings,
			},
		},
		Findings: findings,
	}

	payload, mErr := json.Marshal(batch)
	if mErr != nil {
		a.vulnMu.Lock()
		a.vulnStatus.LastError = fmt.Sprintf("marshal ingest: %s", mErr.Error())
		a.vulnMu.Unlock()
		return
	}

	ctxSend, cancel := context.WithTimeout(ctx, httpTimeout)
	status, respBody, sendErr := a.sender.SendVulnIngest(ctxSend, payload)
	cancel()
	_ = status

	stored := parseStoredFindings(respBody)

	if sendErr != nil {
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

	// Optional: emit a single summary event for visibility in the events timeline.
	if a.cfg.VulnEmitSummaryEvent {
		ev := model.NetEvent{
			AgentID:        a.cfg.AgentID,
			SchemaVersion:  1,
			Timestamp:      now,
			EventType:      "vuln_scan",
				SrcIP:          "",
				DstIP:          "",
				SrcPort:        0,
				DstPort:        0,
				Proto:          "",
				Bytes:          0,
			Extra: map[string]interface{}{
				"scan_uuid":        scanUUID,
				"tool":             "osv",
				"package_manager":  res.Snapshot.Manager,
				"ecosystem":        ecosystem,
				"queried_packages": stats.QueriedPackages,
				"emitted_findings": stats.EmittedFindings,
				"stored_findings":  stored,
				"duration_ms":      time.Since(start).Milliseconds(),
			},
		}
		ctxEv, cancelEv := context.WithTimeout(ctx, a.cfg.HTTPTimeout)
		_, _ = a.sender.SendEvents(ctxEv, []model.NetEvent{ev})
		cancelEv()
	}
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
