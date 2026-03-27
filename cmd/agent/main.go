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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/ddos"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/lateral"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/proc"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/scan"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/ssh"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/netutil"
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

	AgentConfigFile string
	BootstrapToken  string
	AgentCredential string
	AgentCredentialExpiresAt string
	CredentialFile  string

	TLSCAFile     string
	TLSServerName string

	ControlHeartbeatEvery  time.Duration
	ControlHeartbeatJitter time.Duration
	ControlConfigEvery     time.Duration
	ControlConfigJitter    time.Duration
	ControlEnrollTimeout   time.Duration
	ForceEnrollOnStart     bool
	CredentialRotateEvery  time.Duration
	CredentialRotateBefore time.Duration

	SyscollectEvery          time.Duration
	SyscollectStartupJitter  time.Duration
	SyscollectCmdTimeout     time.Duration
	SyscollectMaxOutputBytes int64
	SyscollectMaxPackages    int
	SyscollectHostRoot       string

	VulnScanEvery        time.Duration
	VulnStartupJitter    time.Duration
	VulnOSVURL           string
	VulnMinSeverity      string
	VulnAnalysisProfile  string
	VulnExposureEnabled  bool
	VulnQueryBatchSize   int
	VulnCmdTimeout       time.Duration
	VulnHTTPTimeout      time.Duration
	VulnMaxOutputBytes   int64
	VulnMaxPackages      int
	VulnHostRoot         string
	VulnEmitSummaryEvent bool

	AuthLogPath         string
	AuthIncludeAccepted bool
	AuthDedupTTL        time.Duration

	ProcTCP4Path string
	ProcTCP6Path string

	SkipLoopback         bool
	SkipLinkLocal        bool
	SkipPrivateToPrivate bool

	ProcDropLikelyOutbound bool
	EphemeralPortMin       int

	DedupTTL       time.Duration
	EstablishedTTL time.Duration

	DenyCIDRs    []*net.IPNet
	DenyDstPorts map[int]bool
	DenySrcPorts map[int]bool

	LateralMode               string // pcap|proc|both
	LateralIface              string
	LateralPorts              map[int]bool
	LateralIncludeEstablished bool
	LateralDedupTTL           time.Duration
	LateralMaxBatch           int

	ScanIface    string
	ScanDedupTTL time.Duration
	ScanMaxBatch int

	ScanMode string // raw|summary|both

	DDoSIface                   string
	DDoSWindow                  time.Duration
	DDoSEvalEvery               time.Duration
	DDoSCooldown                time.Duration
	DDoSSustainWindows          int
	DDoSBaselineWarmupWindows   int
	DDoSBaselineAlpha           float64
	DDoSBaselineFactor          float64
	DDoSMinPPS                  float64
	DDoSMinBPS                  float64
	DDoSMinPackets              int
	DDoSMinRequests             int
	DDoSMinConfidence           int
	DDoSMinSynRatio             float64
	DDoSMinSrcIPs               int
	DDoSMinSrcEntropyNorm       float64
	DDoSEnableL7                bool
	DDoSMinHTTPRPS              float64
	DDoSMinTLSHSRPS             float64
	DDoSMinL7Ratio              float64
	DDoSEnableEntropy           bool
	DDoSMinSrcEntropyNormSignal float64
	DDoSMinPortEntropyNorm      float64
	DDoSPortEntropyTopN         int
	DDoSCardinalityMode         string
	DDoSHLLPrecision            int
	DDoSBloomBits               int
	DDoSMaxUniqueSrc            int
	DDoSTopSrc                  int
	DDoSMaxBatch                int
	DDoSBackpressureHighWM      int
	DDoSBackpressureSampleEvery int

	LogLevel          LogLevel
	LogSummaryEvery   time.Duration
	LogHeartbeatEvery time.Duration
	LogMinEvents      int
}

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

type SummaryState struct {
	StartedAt time.Time

	Cycles int

	EventsSentTotal int

	SSHAuthEventsTotal int

	ScanProbesTotal     int
	ScanProbesEffective int

	MaxSentCycle  int
	MaxScanCycle  int
	MaxPortsCycle int

	SendAttemptsTotal int
	SendErrorsTotal   int

	LastHTTPStatus int
	LastError      string

	LastSummaryAt            time.Time
	LastSummaryEventsSent    int
	LastSummaryScanTotal     int
	LastSummaryScanEffective int
	LastHeartbeatAt          time.Time
}

type Agent struct {
	cfg Config

	sender  *sender.Sender
	cp      *controlplane.Client
	runtime *RuntimeConfig
	credMu  sync.RWMutex
	cred    string
	credExp time.Time

	sysMu     sync.RWMutex
	sysStatus SyscollectorStatus

	procCapturer *proc.Capturer
	authCapturer *ssh.AuthLogCapturer
	lateralProc  *lateral.ProcLateralCapturer
	lateralPcap  *lateral.PcapLateralCapturer
	scanCapturer *scan.PcapScanCapturer
	ddosCapturer *ddos.PcapDDoSCapturer

	vulnMu     sync.RWMutex
	vulnStatus VulnScannerStatus

	state SummaryState

	enrollMu          sync.Mutex
	nextEnrollRetryAt time.Time
}

func main() {
	cfg := loadConfig()
	httpClient, err := netutil.NewHTTPClient(cfg.HTTPTimeout, netutil.TLSOptions{
		CAFile:     strings.TrimSpace(cfg.TLSCAFile),
		ServerName: strings.TrimSpace(cfg.TLSServerName),
	})
	if err != nil {
		log.Fatalf("[AGENT] TLS client init error: %v", err)
	}

	log.Printf("[AGENT] id=%s api=%s sources=%v interval=%s scan_mode=%s",
		cfg.AgentID, cfg.APIURL, cfg.Sources, cfg.Interval, normalizeScanMode(cfg.ScanMode),
	)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	{
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
		if err := waitForHealth(ctx, cfg.APIURL, httpClient); err != nil {
			logJSON(LevelWarn, "backend_not_ready", map[string]interface{}{
				"agent_id": cfg.AgentID,
				"error":    err.Error(),
			})
		}
		cancel()
	}

	// Control Plane enrollment with bootstrap token + rotating credential.
	{
		hostname, _ := os.Hostname()
		currentCredential := strings.TrimSpace(cfg.AgentCredential)
		cp := controlplane.New(cfg.APIURL, cfg.HTTPTimeout, cfg.AgentID, func() string { return currentCredential }, httpClient)

		bootstrapToken := strings.TrimSpace(cfg.BootstrapToken)
		shouldEnroll := bootstrapToken != "" && (cfg.ForceEnrollOnStart || currentCredential == "")
		if shouldEnroll && bootstrapToken == "" {
			logJSON(LevelWarn, "agent_enroll_skipped", map[string]interface{}{
				"agent_id": cfg.AgentID,
				"reason":   "missing_bootstrap_token",
			})
			shouldEnroll = false
		}
		if shouldEnroll {
			ctx, cancel := context.WithTimeout(rootCtx, cfg.ControlEnrollTimeout)
			resp, err := cp.Enroll(ctx, controlplane.EnrollRequest{
				AgentID:        cfg.AgentID,
				Hostname:       hostname,
				OS:             runtime.GOOS,
				Version:        "0.1.0",
				BootstrapToken: bootstrapToken,
			})
			cancel()
			if err != nil {
				logJSON(LevelWarn, "agent_enroll_failed", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
			} else {
				currentCredential = strings.TrimSpace(resp.Credential.Credential)
				cfg.AgentCredential = currentCredential
				cfg.AgentCredentialExpiresAt = strings.TrimSpace(resp.Credential.ExpiresAt)
				if cfg.CredentialFile != "" && currentCredential != "" {
					_ = atomicWriteFile(cfg.CredentialFile, []byte(currentCredential+"\n"), 0o600)
				}
				if cfg.AgentConfigFile != "" && len(resp.Config) > 0 {
					if b, mErr := json.Marshal(resp.Config); mErr == nil {
						_ = atomicWriteFile(cfg.AgentConfigFile, b, 0o600)
					}
				}
			}
		}
	}

	a, err := newAgent(cfg, rootCtx, stop, httpClient)
	if err != nil {
		log.Fatalf("[AGENT] init error: %v", err)
	}

	a.startControlPlane(rootCtx)
	a.startSyscollector(rootCtx)
	a.startVulnScanner(rootCtx)

	a.loop(rootCtx)
}

func newAgent(cfg Config, rootCtx context.Context, stop context.CancelFunc, httpClient *http.Client) (*Agent, error) {
	now := time.Now().UTC()

	a := &Agent{
		cfg:    cfg,
		cred:   strings.TrimSpace(cfg.AgentCredential),
		runtime: NewRuntimeConfig(
			cfg.AgentConfigFile,
			SyscollectorConfig{
				Enabled:        true,
				Every:          cfg.SyscollectEvery,
				CmdTimeout:     cfg.SyscollectCmdTimeout,
				MaxOutputBytes: cfg.SyscollectMaxOutputBytes,
				MaxPackages:    cfg.SyscollectMaxPackages,
				HostRoot:       cfg.SyscollectHostRoot,
			},
			VulnScannerConfig{
				Enabled:         contains(cfg.Sources, "vuln"),
				Every:           cfg.VulnScanEvery,
				OSVURL:          cfg.VulnOSVURL,
				MinSeverity:     cfg.VulnMinSeverity,
				AnalysisProfile: cfg.VulnAnalysisProfile,
				ExposureEnabled: cfg.VulnExposureEnabled,
				QueryBatchSize:  cfg.VulnQueryBatchSize,
				CmdTimeout:      cfg.VulnCmdTimeout,
				HTTPTimeout:     cfg.VulnHTTPTimeout,
				MaxOutputBytes:  cfg.VulnMaxOutputBytes,
				MaxPackages:     cfg.VulnMaxPackages,
				HostRoot:        cfg.VulnHostRoot,
			},
		),
		state: SummaryState{
			StartedAt:                now,
			LastSummaryAt:            now,
			LastHeartbeatAt:          now,
			LastSummaryEventsSent:    0,
			LastSummaryScanTotal:     0,
			LastSummaryScanEffective: 0,
		},
	}
	a.sender = sender.New(cfg.APIURL, cfg.HTTPTimeout, cfg.SenderMaxBatch, cfg.AgentID, a.currentCredential, httpClient)
	a.cp = controlplane.New(cfg.APIURL, cfg.HTTPTimeout, cfg.AgentID, a.currentCredential, httpClient)
	if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(cfg.AgentCredentialExpiresAt)); err == nil {
		a.credExp = ts.UTC()
	}

	// Best-effort: pull the current config once at startup.
	ctx, cancel := context.WithTimeout(rootCtx, cfg.ControlEnrollTimeout)
	if remoteCfg, err := a.cp.GetConfig(ctx); err == nil && len(remoteCfg) > 0 {
		_, _ = a.runtime.Apply(remoteCfg)
	}
	cancel()

	// Apply startup overrides from persisted/control-plane config so operators
	// can tune agent behavior without editing environment variables.
	applyAgentRuntimeOverrides(&cfg, a.runtime.Raw())
	a.cfg = cfg

	if contains(cfg.Sources, "proc") {
		opts := proc.Options{
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

			DropLikelyOutbound: cfg.ProcDropLikelyOutbound,
			EphemeralPortMin:   cfg.EphemeralPortMin,
		}
		a.procCapturer = proc.New(cfg.AgentID, cfg.ProcTCP4Path, cfg.ProcTCP6Path, opts)
	}

	if contains(cfg.Sources, "authlog") {
		resolvedPath, err := ssh.ResolveAuthLogPath(cfg.AuthLogPath)
		if err != nil {
			logJSON(LevelWarn, "authlog_source_disabled", map[string]interface{}{
				"agent_id": cfg.AgentID,
				"path":     cfg.AuthLogPath,
				"error":    err.Error(),
			})
		} else {
			if resolvedPath != cfg.AuthLogPath {
				logJSON(LevelInfo, "authlog_path_resolved", map[string]interface{}{
					"agent_id":   cfg.AgentID,
					"configured": cfg.AuthLogPath,
					"resolved":   resolvedPath,
				})
			}
			a.authCapturer = ssh.NewAuthLogCapturer(cfg.AgentID, ssh.AuthLogOptions{
				Path:            resolvedPath,
				MaxBatchSize:    200,
				DedupTTL:        cfg.AuthDedupTTL,
				IncludeAccepted: cfg.AuthIncludeAccepted,
			})
		}
	}

	if contains(cfg.Sources, "lateral") {
		mode := strings.ToLower(strings.TrimSpace(cfg.LateralMode))
		if mode == "" {
			mode = "pcap"
		}
		if mode != "pcap" && mode != "proc" && mode != "both" {
			mode = "pcap"
		}

		if mode == "proc" || mode == "both" {
			procOpts := proc.Options{
				DedupTTL:             cfg.LateralDedupTTL,
				EstablishedTTL:       cfg.EstablishedTTL,
				SkipLoopback:         cfg.SkipLoopback,
				SkipLinkLocal:        cfg.SkipLinkLocal,
				SkipPrivateToPrivate: cfg.SkipPrivateToPrivate,
				IncludeIPv6:          true,
				MaxBatchSize:         0,
				DenyCIDRs:            cfg.DenyCIDRs,
				DenyDstPorts:         cfg.DenyDstPorts,
				DenySrcPorts:         cfg.DenySrcPorts,
				DropLikelyOutbound:   cfg.ProcDropLikelyOutbound,
				EphemeralPortMin:     cfg.EphemeralPortMin,
			}
			a.lateralProc = lateral.NewProcLateralCapturer(
				cfg.AgentID,
				cfg.ProcTCP4Path,
				cfg.ProcTCP6Path,
				procOpts,
				lateral.Options{
					Ports:              cfg.LateralPorts,
					IncludeEstablished: cfg.LateralIncludeEstablished,
					MaxBatchSize:       cfg.LateralMaxBatch,
				},
			)
		}

		if mode == "pcap" || mode == "both" {
			lc, err := lateral.NewPcapLateralCapturer(cfg.AgentID, lateral.PcapLateralOptions{
				Interface:     cfg.LateralIface,
				DedupTTL:      cfg.LateralDedupTTL,
				MaxBatchSize:  cfg.LateralMaxBatch,
				SkipLoopback:  cfg.SkipLoopback,
				SkipLinkLocal: cfg.SkipLinkLocal,
				DenyCIDRs:     cfg.DenyCIDRs,
				Ports:         cfg.LateralPorts,
			})
			if err != nil {
				return nil, err
			}
			a.lateralPcap = lc

			go func() {
				if err := a.lateralPcap.Start(rootCtx); err != nil {
					logJSON(LevelError, "lateral_capture_stopped", map[string]interface{}{
						"agent_id": cfg.AgentID,
						"error":    err.Error(),
					})
					stop()
				}
			}()
		}
	}

	if contains(cfg.Sources, "scan") {
		sc, err := scan.NewPcapScanCapturer(cfg.AgentID, scan.PcapScanOptions{
			Interface:        cfg.ScanIface,
			DedupTTL:         cfg.ScanDedupTTL,
			MaxBatchSize:     cfg.ScanMaxBatch,
			SkipLoopback:     cfg.SkipLoopback,
			SkipLinkLocal:    cfg.SkipLinkLocal,
			DenyCIDRs:        cfg.DenyCIDRs,
			DenyDstPorts:     cfg.DenyDstPorts,
			DenySrcPorts:     cfg.DenySrcPorts,
			EphemeralPortMin: cfg.EphemeralPortMin,
		})
		if err != nil {
			return nil, err
		}
		a.scanCapturer = sc

		go func() {
			if err := a.scanCapturer.Start(rootCtx); err != nil {
				logJSON(LevelError, "scan_capture_stopped", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
				stop()
			}
		}()
	}

	if contains(cfg.Sources, "ddos") {
		dc, err := ddos.NewPcapDDoSCapturer(cfg.AgentID, ddos.PcapDDoSOptions{
			Interface: cfg.DDoSIface,

			Window:         cfg.DDoSWindow,
			EvalEvery:      cfg.DDoSEvalEvery,
			Cooldown:       cfg.DDoSCooldown,
			SustainWindows: cfg.DDoSSustainWindows,

			BaselineWarmupWindows: cfg.DDoSBaselineWarmupWindows,
			BaselineAlpha:         cfg.DDoSBaselineAlpha,
			BaselineFactor:        cfg.DDoSBaselineFactor,

			MinPPS:        cfg.DDoSMinPPS,
			MinBPS:        cfg.DDoSMinBPS,
			MinPackets:    cfg.DDoSMinPackets,
			MinRequests:   cfg.DDoSMinRequests,
			MinConfidence: cfg.DDoSMinConfidence,

			MinSynRatio: cfg.DDoSMinSynRatio,

			DDoSMinSrcIPs:         cfg.DDoSMinSrcIPs,
			DDoSMinSrcEntropyNorm: cfg.DDoSMinSrcEntropyNorm,

			EnableL7:    cfg.DDoSEnableL7,
			MinHTTPRPS:  cfg.DDoSMinHTTPRPS,
			MinTLSHSRPS: cfg.DDoSMinTLSHSRPS,
			MinL7Ratio:  cfg.DDoSMinL7Ratio,

			EnableEntropy:      cfg.DDoSEnableEntropy,
			MinSrcEntropyNorm:  cfg.DDoSMinSrcEntropyNormSignal,
			MinPortEntropyNorm: cfg.DDoSMinPortEntropyNorm,
			PortEntropyTopN:    cfg.DDoSPortEntropyTopN,

			CardinalityMode: cfg.DDoSCardinalityMode,
			HLLPrecision:    cfg.DDoSHLLPrecision,
			BloomBits:       cfg.DDoSBloomBits,
			MaxUniqueSrc:    cfg.DDoSMaxUniqueSrc,
			TopSrc:          cfg.DDoSTopSrc,

			MaxBatchSize:              cfg.DDoSMaxBatch,
			BackpressureHighWatermark: cfg.DDoSBackpressureHighWM,
			BackpressureSampleEvery:   cfg.DDoSBackpressureSampleEvery,

			DropLikelyOutbound: cfg.ProcDropLikelyOutbound,
			EphemeralPortMin:   cfg.EphemeralPortMin,

			SkipLoopback:  cfg.SkipLoopback,
			SkipLinkLocal: cfg.SkipLinkLocal,

			DenyCIDRs:    cfg.DenyCIDRs,
			DenyDstPorts: cfg.DenyDstPorts,
			DenySrcPorts: cfg.DenySrcPorts,
		})
		if err != nil {
			return nil, err
		}
		a.ddosCapturer = dc

		go func() {
			if err := a.ddosCapturer.Start(rootCtx); err != nil {
				logJSON(LevelError, "ddos_capture_stopped", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
				stop()
			}
		}()
	}

	return a, nil
}

func (a *Agent) loop(rootCtx context.Context) {
	pollTicker := time.NewTicker(a.cfg.Interval)
	defer pollTicker.Stop()

	summaryTicker := time.NewTicker(a.cfg.LogSummaryEvery)
	defer summaryTicker.Stop()

	a.runAndLog(rootCtx)

	for {
		select {
		case <-rootCtx.Done():
			logJSON(LevelInfo, "shutdown", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
			})
			return

		case <-pollTicker.C:
			a.runAndLog(rootCtx)
			a.maybeHeartbeat()

		case <-summaryTicker.C:
			a.flushSummary()
		}
	}
}

func (a *Agent) currentCredential() string {
	a.credMu.RLock()
	defer a.credMu.RUnlock()
	return strings.TrimSpace(a.cred)
}

func (a *Agent) setCredential(raw string, expiresAt string) {
	cred := strings.TrimSpace(raw)
	if cred == "" {
		return
	}
	a.credMu.Lock()
	a.cred = cred
	if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAt)); err == nil {
		a.credExp = ts.UTC()
	}
	a.credMu.Unlock()
	if a.cfg.CredentialFile != "" {
		_ = atomicWriteFile(a.cfg.CredentialFile, []byte(cred+"\n"), 0o600)
	}
}

func (a *Agent) startControlPlane(rootCtx context.Context) {
	if a.cp == nil {
		return
	}

	// Heartbeat loop
	go func() {
		initialDelay := stableJitter(a.cfg.AgentID, "control.heartbeat", a.cfg.ControlHeartbeatJitter)
		if initialDelay > 0 {
			t := time.NewTimer(initialDelay)
			select {
			case <-rootCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		t := time.NewTicker(a.cfg.ControlHeartbeatEvery)
		defer t.Stop()

		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(rootCtx, a.cfg.HTTPTimeout)
				metrics := map[string]interface{}{
					"events_sent_total":   a.state.EventsSentTotal,
					"send_errors_total":   a.state.SendErrorsTotal,
					"last_http_status":    a.state.LastHTTPStatus,
					"last_error":          a.state.LastError,
					"send_attempts_total": a.state.SendAttemptsTotal,
				}
				if a.runtime != nil {
					metrics["config_hash"] = a.runtime.Hash()
				}
				if contains(a.cfg.Sources, "syscollector") {
					a.sysMu.RLock()
					s := a.sysStatus
					a.sysMu.RUnlock()
					metrics["syscollector_enabled"] = a.runtime.Syscollector().Enabled
					metrics["syscollector_last_run_at"] = s.LastRunAt
					metrics["syscollector_last_sent_at"] = s.LastSentAt
					metrics["syscollector_last_error"] = s.LastError
					metrics["syscollector_last_hash"] = s.LastHash
					metrics["syscollector_last_packages_count"] = s.LastPkgCount
				}

				err := a.cp.Heartbeat(ctx, controlplane.HeartbeatRequest{
					Status:        "ok",
					UptimeSeconds: int64(time.Since(a.state.StartedAt).Seconds()),
					Modules: map[string]interface{}{
						"sources": a.cfg.Sources,
					},
					Metrics: metrics,
				})
				cancel()
				if err != nil {
					logJSON(LevelWarn, "controlplane_heartbeat_error", map[string]interface{}{
						"agent_id": a.cfg.AgentID,
						"error":    err.Error(),
					})
					a.maybeReEnroll(rootCtx, err.Error(), 0)
				}
			}
		}
	}()

	// Config pull loop (best-effort). Applies config and persists it locally.
	go func() {
		initialDelay := stableJitter(a.cfg.AgentID, "control.config", a.cfg.ControlConfigJitter)
		if initialDelay > 0 {
			t := time.NewTimer(initialDelay)
			select {
			case <-rootCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		t := time.NewTicker(a.cfg.ControlConfigEvery)
		defer t.Stop()

		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(rootCtx, a.cfg.HTTPTimeout)
				cfg, err := a.cp.GetConfig(ctx)
				cancel()
				if err != nil {
					logJSON(LevelWarn, "controlplane_config_error", map[string]interface{}{
						"agent_id": a.cfg.AgentID,
						"error":    err.Error(),
					})
					a.maybeReEnroll(rootCtx, err.Error(), 0)
					continue
				}
				if a.runtime != nil && len(cfg) > 0 {
					changed, _ := a.runtime.Apply(cfg)
					if changed {
						logJSON(LevelInfo, "controlplane_config_applied", map[string]interface{}{
							"agent_id":    a.cfg.AgentID,
							"config_hash": a.runtime.Hash(),
							"config_keys": len(cfg),
						})
					}
				}
			}
		}
	}()

	// Credential rotation loop.
	go func() {
		t := time.NewTicker(a.cfg.CredentialRotateEvery)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				a.credMu.RLock()
				exp := a.credExp
				a.credMu.RUnlock()
				if exp.IsZero() || time.Until(exp) > a.cfg.CredentialRotateBefore {
					continue
				}
				ctx, cancel := context.WithTimeout(rootCtx, a.cfg.ControlEnrollTimeout)
				rot, err := a.cp.RotateCredential(ctx)
				cancel()
				if err != nil {
					logJSON(LevelWarn, "agent_credential_rotate_failed", map[string]interface{}{
						"agent_id": a.cfg.AgentID,
						"error":    err.Error(),
					})
					continue
				}
				a.setCredential(rot.Credential, rot.ExpiresAt)
				logJSON(LevelInfo, "agent_credential_rotated", map[string]interface{}{
					"agent_id": a.cfg.AgentID,
				})
			}
		}
	}()
}

func (a *Agent) maybeReEnroll(rootCtx context.Context, errText string, status int) {
	if !a.cfg.ForceEnrollOnStart {
		return
	}
	et := strings.ToLower(strings.TrimSpace(errText))
	should := status == 401 ||
		strings.Contains(et, "status=401") ||
		strings.Contains(et, "unknown or revoked agent") ||
		strings.Contains(et, "invalid agent credential") ||
		strings.Contains(et, "credential expired") ||
		strings.Contains(et, "credential exhausted")
	if !should {
		return
	}

	now := time.Now().UTC()
	a.enrollMu.Lock()
	if !a.nextEnrollRetryAt.IsZero() && now.Before(a.nextEnrollRetryAt) {
		a.enrollMu.Unlock()
		return
	}
	// Keep retries bounded to avoid noisy loops under persistent auth failures.
	a.nextEnrollRetryAt = now.Add(30 * time.Second)
	a.enrollMu.Unlock()

	bootstrapToken := strings.TrimSpace(getSecretEnv("NETWATCH_AGENT_BOOTSTRAP_TOKEN", ""))
	if bootstrapToken == "" {
		logJSON(LevelWarn, "agent_reenroll_skipped", map[string]interface{}{
			"agent_id": a.cfg.AgentID,
			"reason":   "missing_bootstrap_token",
		})
		return
	}

	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(rootCtx, a.cfg.ControlEnrollTimeout)
	resp, err := a.cp.Enroll(ctx, controlplane.EnrollRequest{
		AgentID:        a.cfg.AgentID,
		Hostname:       hostname,
		OS:             runtime.GOOS,
		Version:        "0.1.0",
		BootstrapToken: bootstrapToken,
	})
	cancel()
	if err != nil {
		logJSON(LevelWarn, "agent_reenroll_failed", map[string]interface{}{
			"agent_id": a.cfg.AgentID,
			"error":    err.Error(),
		})
		return
	}
	a.setCredential(resp.Credential.Credential, resp.Credential.ExpiresAt)

	if a.cfg.AgentConfigFile != "" && len(resp.Config) > 0 {
		if b, mErr := json.Marshal(resp.Config); mErr == nil {
			_ = atomicWriteFile(a.cfg.AgentConfigFile, b, 0o600)
		}
	}
	logJSON(LevelInfo, "agent_reenroll_succeeded", map[string]interface{}{
		"agent_id": a.cfg.AgentID,
	})
}

func (a *Agent) runAndLog(rootCtx context.Context) {
	res := a.runOnce(rootCtx)
	if res == nil {
		return
	}
	if res.SendAttempted {
		a.maybeReEnroll(rootCtx, res.Error, res.Status)
	}

	a.applyToSummary(res)

	if a.shouldLogCycle(res) {
		level := LevelInfo
		if res.Error != "" {
			level = LevelWarn
		}
		if a.cfg.LogLevel == LevelDebug {
			level = LevelDebug
		}
		a.logCycle(level, res)
	}
}

func (a *Agent) runOnce(rootCtx context.Context) *CycleResult {
	start := time.Now().UTC()

	events := make([]model.NetEvent, 0, 1024)
	scanRaw := make([]model.NetEvent, 0, 1024)
	ddosEvs := make([]model.NetEvent, 0, 64)

	if a.authCapturer != nil {
		evs, err := a.authCapturer.Capture(time.Now().UTC())
		if err != nil {
			logJSON(LevelWarn, "authlog_capture_error", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if a.procCapturer != nil {
		evs, err := a.procCapturer.Capture()
		if err != nil {
			logJSON(LevelWarn, "proc_capture_error", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if a.lateralProc != nil {
		evs, err := a.lateralProc.Capture()
		if err != nil {
			logJSON(LevelWarn, "lateral_proc_capture_error", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if a.lateralPcap != nil {
		evs := a.lateralPcap.Drain()
		if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if a.scanCapturer != nil {
		evs := a.scanCapturer.Drain()
		if len(evs) > 0 {
			scanRaw = append(scanRaw, evs...)
		}
	}

	if a.ddosCapturer != nil {
		evs := a.ddosCapturer.Drain()
		if len(evs) > 0 {
			ddosEvs = append(ddosEvs, evs...)
		}
	}

	sshAuthEvents := 0
	for _, ev := range events {
		if ev.EventType == "ssh_auth" {
			sshAuthEvents++
		}
	}

	scanStats := computeScanStats(scanRaw)
	mode := normalizeScanMode(a.cfg.ScanMode)

	if scanStats.Class == "service_noise" {
		scanStats.Effective = 0
	}

	if mode == "raw" || mode == "both" {
		events = append(events, scanRaw...)
	}
	if mode == "summary" || mode == "both" {
		events = append(events, buildScanSummaries(a.cfg.AgentID, scanRaw, a.cfg.Interval)...)
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

	normalizeEvents(events, a.cfg.AgentID)
	ctx, cancel := context.WithTimeout(rootCtx, a.cfg.HTTPTimeout)
	status, err := a.sender.SendEvents(ctx, events)
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

func (a *Agent) shouldLogCycle(res *CycleResult) bool {
	if a.cfg.LogLevel == LevelDebug {
		return res.Sent > 0 || res.Error != ""
	}

	if res.Error != "" {
		return true
	}
	if res.Sent >= a.cfg.LogMinEvents {
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

func (a *Agent) logCycle(level LogLevel, res *CycleResult) {
	fields := map[string]interface{}{
		"agent_id":        a.cfg.AgentID,
		"sent":            res.Sent,
		"http_status":     res.Status,
		"send_attempted":  res.SendAttempted,
		"duration_ms":     res.DurationMS,
		"ssh_auth_events": res.SSHAuthEvents,

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
	logJSON(level, "cycle", fields)
}

func (a *Agent) applyToSummary(res *CycleResult) {
	a.state.Cycles++

	a.state.EventsSentTotal += res.Sent
	a.state.SSHAuthEventsTotal += res.SSHAuthEvents

	a.state.ScanProbesTotal += res.ScanProbesTotal
	a.state.ScanProbesEffective += res.ScanProbesEffective

	if res.Sent > a.state.MaxSentCycle {
		a.state.MaxSentCycle = res.Sent
	}
	if res.ScanProbesTotal > a.state.MaxScanCycle {
		a.state.MaxScanCycle = res.ScanProbesTotal
	}
	if res.ScanDstPorts > a.state.MaxPortsCycle {
		a.state.MaxPortsCycle = res.ScanDstPorts
	}

	if res.SendAttempted {
		a.state.SendAttemptsTotal++
		if res.Error != "" {
			a.state.SendErrorsTotal++
			a.state.LastError = res.Error
		} else {
			a.state.LastError = ""
		}
		if res.Status != 0 {
			a.state.LastHTTPStatus = res.Status
		}
	}
}

func (a *Agent) flushSummary() {
	now := time.Now().UTC()
	uptime := time.Since(a.state.StartedAt)

	period := now.Sub(a.state.LastSummaryAt)
	if period <= 0 {
		period = a.cfg.LogSummaryEvery
		if period <= 0 {
			period = 10 * time.Second
		}
	}

	sentDelta := a.state.EventsSentTotal - a.state.LastSummaryEventsSent
	scanDelta := a.state.ScanProbesTotal - a.state.LastSummaryScanTotal
	scanEffDelta := a.state.ScanProbesEffective - a.state.LastSummaryScanEffective

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
		avgSentPerSec = float64(a.state.EventsSentTotal) / uptime.Seconds()
	}

	logJSON(LevelInfo, "agent_summary", map[string]interface{}{
		"agent_id":   a.cfg.AgentID,
		"scan_mode":  normalizeScanMode(a.cfg.ScanMode),
		"uptime_sec": int(uptime.Seconds()),
		"cycles":     a.state.Cycles,

		"events_sent_total": a.state.EventsSentTotal,

		"ssh_auth_events_total": a.state.SSHAuthEventsTotal,

		"scan_probes_total":     a.state.ScanProbesTotal,
		"scan_probes_effective": a.state.ScanProbesEffective,

		"summary_period_sec": int(period.Seconds()),

		"sent_delta":                  sentDelta,
		"scan_probes_delta":           scanDelta,
		"scan_probes_effective_delta": scanEffDelta,

		"sent_per_sec":                  round2(sentPerSec),
		"scan_probes_per_sec":           round2(scanPerSec),
		"scan_probes_effective_per_sec": round2(scanEffPerSec),

		"avg_sent_per_sec": round2(avgSentPerSec),

		"max_sent_cycle":  a.state.MaxSentCycle,
		"max_scan_cycle":  a.state.MaxScanCycle,
		"max_ports_cycle": a.state.MaxPortsCycle,

		"send_attempts_total": a.state.SendAttemptsTotal,
		"send_errors_total":   a.state.SendErrorsTotal,
		"last_http_status":    a.state.LastHTTPStatus,
		"last_error":          a.state.LastError,
	})

	a.state.LastSummaryAt = now
	a.state.LastSummaryEventsSent = a.state.EventsSentTotal
	a.state.LastSummaryScanTotal = a.state.ScanProbesTotal
	a.state.LastSummaryScanEffective = a.state.ScanProbesEffective
}

func (a *Agent) maybeHeartbeat() {
	if time.Since(a.state.LastHeartbeatAt) < a.cfg.LogHeartbeatEvery {
		return
	}
	uptime := time.Since(a.state.StartedAt)

	logJSON(LevelInfo, "heartbeat", map[string]interface{}{
		"agent_id":         a.cfg.AgentID,
		"uptime_sec":       int(uptime.Seconds()),
		"cycles":           a.state.Cycles,
		"last_http_status": a.state.LastHTTPStatus,
	})
	a.state.LastHeartbeatAt = time.Now().UTC()
}

func loadConfig() Config {
	agentID := getEnv("NETWATCH_AGENT_ID", "agent-unknown")
	apiURL := strings.TrimSpace(getEnv("NETWATCH_API_URL", ""))
	if apiURL == "" {
		log.Fatal("[AGENT] NETWATCH_API_URL is required")
	}
	sources := splitCSVLower(getEnv("NETWATCH_SOURCES", "authlog,proc,scan,ddos"))

	interval := parseDuration(getEnv("NETWATCH_POLL_INTERVAL", "1s"), 1*time.Second)
	httpTimeout := parseDuration(getEnv("NETWATCH_HTTP_TIMEOUT", "10s"), 10*time.Second)
	senderMaxBatch := parseInt(getEnv("NETWATCH_SENDER_MAX_BATCH", "300"), 300)

	agentConfigFile := getEnv("NETWATCH_AGENT_CONFIG_FILE", "/var/lib/netwatch/agent.config.json")
	bootstrapToken := strings.TrimSpace(getSecretEnv("NETWATCH_AGENT_BOOTSTRAP_TOKEN", ""))
	credentialFile := strings.TrimSpace(getEnv("NETWATCH_AGENT_CREDENTIAL_FILE", "/var/lib/netwatch/agent.credential"))
	agentCredential := strings.TrimSpace(getSecretEnv("NETWATCH_AGENT_CREDENTIAL", ""))
	if agentCredential == "" && credentialFile != "" {
		agentCredential = strings.TrimSpace(readTextFile(credentialFile))
	}

	tlsCAFile := strings.TrimSpace(getEnv("NETWATCH_TLS_CA_FILE", ""))
	tlsServerName := strings.TrimSpace(getEnv("NETWATCH_TLS_SERVER_NAME", ""))

	controlHeartbeatEvery := parseDuration(getEnv("NETWATCH_CONTROL_HEARTBEAT_EVERY", "30s"), 30*time.Second)
	controlHeartbeatJitter := parseDuration(getEnv("NETWATCH_CONTROL_HEARTBEAT_JITTER", "5s"), 5*time.Second)
	controlConfigEvery := parseDuration(getEnv("NETWATCH_CONTROL_CONFIG_EVERY", "5m"), 5*time.Minute)
	controlConfigJitter := parseDuration(getEnv("NETWATCH_CONTROL_CONFIG_JITTER", "30s"), 30*time.Second)
	controlEnrollTimeout := parseDuration(getEnv("NETWATCH_CONTROL_ENROLL_TIMEOUT", "10s"), 10*time.Second)
	forceEnrollOnStart := parseBool(getEnv("NETWATCH_FORCE_ENROLL_ON_START", "true"), true)
	credentialRotateEvery := parseDuration(getEnv("NETWATCH_CONTROL_CREDENTIAL_ROTATE_EVERY", "5m"), 5*time.Minute)
	credentialRotateBefore := parseDuration(getEnv("NETWATCH_CONTROL_CREDENTIAL_ROTATE_BEFORE", "24h"), 24*time.Hour)

	syscollectEvery := parseDuration(getEnv("NETWATCH_SYSCOLLECT_EVERY", "5m"), 5*time.Minute)
	syscollectStartupJitter := parseDuration(getEnv("NETWATCH_SYSCOLLECT_STARTUP_JITTER", "45s"), 45*time.Second)
	syscollectCmdTimeout := parseDuration(getEnv("NETWATCH_SYSCOLLECT_CMD_TIMEOUT", "10s"), 10*time.Second)
	syscollectMaxOutputBytes := int64(parseInt(getEnv("NETWATCH_SYSCOLLECT_MAX_OUTPUT_BYTES", "8388608"), 8388608))
	syscollectMaxPackages := parseInt(getEnv("NETWATCH_SYSCOLLECT_MAX_PACKAGES", "50000"), 50000)
	syscollectHostRoot := strings.TrimSpace(getEnv("NETWATCH_HOST_ROOT", ""))

	vulnEvery := parseDuration(getEnv("NETWATCH_VULN_SCAN_EVERY", "12h"), 12*time.Hour)
	vulnStartupJitter := parseDuration(getEnv("NETWATCH_VULN_STARTUP_JITTER", "2m"), 2*time.Minute)
	vulnOSVURL := strings.TrimSpace(getEnv("NETWATCH_VULN_OSV_URL", "https://api.osv.dev"))
	vulnMinSeverity := strings.ToLower(strings.TrimSpace(getEnv("NETWATCH_VULN_MIN_SEVERITY", "medium")))
	vulnAnalysisProfile := strings.TrimSpace(getEnv("NETWATCH_VULN_ANALYSIS_PROFILE", "wazuh_like_v1"))
	vulnExposureEnabled := parseBool(getEnv("NETWATCH_VULN_EXPOSURE_ENABLED", "true"), true)
	vulnBatch := parseInt(getEnv("NETWATCH_VULN_QUERY_BATCH_SIZE", "200"), 200)
	vulnCmdTimeout := parseDuration(getEnv("NETWATCH_VULN_CMD_TIMEOUT", "15s"), 15*time.Second)
	vulnHTTPTimeout := parseDuration(getEnv("NETWATCH_VULN_HTTP_TIMEOUT", "60s"), 60*time.Second)
	vulnMaxOutputBytes := int64(parseInt(getEnv("NETWATCH_VULN_MAX_OUTPUT_BYTES", "8388608"), 8388608))
	vulnMaxPackages := parseInt(getEnv("NETWATCH_VULN_MAX_PACKAGES", strconv.Itoa(syscollectMaxPackages)), syscollectMaxPackages)
	vulnHostRoot := strings.TrimSpace(getEnv("NETWATCH_VULN_HOST_ROOT", syscollectHostRoot))
	vulnEmitSummaryEvent := parseBool(getEnv("NETWATCH_VULN_EMIT_SUMMARY_EVENT", "true"), true)

	logPath := getEnv("NETWATCH_AUTHLOG_PATH", "/var/log/auth.log")
	includeAccepted := parseBool(getEnv("NETWATCH_AUTHLOG_INCLUDE_ACCEPTED", "false"), false)
	authDedupTTL := parseDuration(getEnv("NETWATCH_AUTHLOG_DEDUP_TTL", "30s"), 30*time.Second)

	procTCP4Path := getEnv("NETWATCH_PROC_TCP4_PATH", "/proc/net/tcp")
	procTCP6Path := getEnv("NETWATCH_PROC_TCP6_PATH", "/proc/net/tcp6")

	skipLoopback := parseBool(getEnv("NETWATCH_SKIP_LOOPBACK", "true"), true)
	skipLinkLocal := parseBool(getEnv("NETWATCH_SKIP_LINK_LOCAL", "true"), true)
	skipPrivate := parseBool(getEnv("NETWATCH_SKIP_PRIVATE_TO_PRIVATE", "false"), false)

	procDropOutbound := parseBool(getEnv("NETWATCH_PROC_DROP_LIKELY_OUTBOUND", "true"), true)
	ephemeralMin := parseInt(getEnv("NETWATCH_EPHEMERAL_PORT_MIN", "49152"), 49152)

	dedupTTL := parseDuration(getEnv("NETWATCH_DEDUP_TTL", "30s"), 30*time.Second)
	establishedTTL := parseDuration(getEnv("NETWATCH_ESTABLISHED_TTL", "10m"), 10*time.Minute)

	denyCIDRs := parseCIDRs(getEnv("NETWATCH_DENY_CIDRS", ""))
	denyDstPorts := parseIntSet(getEnv("NETWATCH_DENY_DST_PORTS", ""))
	denySrcPorts := parseIntSet(getEnv("NETWATCH_DENY_SRC_PORTS", ""))

	lateralMode := strings.ToLower(strings.TrimSpace(getEnv("NETWATCH_LATERAL_MODE", "pcap")))
	lateralIface := getEnv("NETWATCH_LATERAL_PCAP_IFACE", getEnv("NETWATCH_PCAP_IFACE", "any"))
	lateralPorts := parseIntSet(getEnv("NETWATCH_LATERAL_PORTS", "22,445,3389,5985,5986,135,139"))
	lateralIncludeEstablished := parseBool(getEnv("NETWATCH_LATERAL_INCLUDE_ESTABLISHED", "true"), true)
	lateralDedup := parseDuration(getEnv("NETWATCH_LATERAL_DEDUP_TTL", "5s"), 5*time.Second)
	lateralMaxBatch := parseInt(getEnv("NETWATCH_LATERAL_MAX_BATCH", "500"), 500)

	scanIface := getEnv("NETWATCH_PCAP_IFACE", "any")
	scanDedup := parseDuration(getEnv("NETWATCH_SCAN_DEDUP_TTL", "2s"), 2*time.Second)
	scanMaxBatch := parseInt(getEnv("NETWATCH_SCAN_MAX_BATCH", "5000"), 5000)
	scanMode := getEnv("NETWATCH_SCAN_MODE", "summary")

	ddosIface := getEnv("NETWATCH_DDOS_PCAP_IFACE", scanIface)
	ddosWindow := parseDuration(getEnv("NETWATCH_DDOS_WINDOW", "1s"), 1*time.Second)
	ddosEvalEvery := parseDuration(getEnv("NETWATCH_DDOS_EVAL_EVERY", "1s"), 1*time.Second)
	ddosCooldown := parseDuration(getEnv("NETWATCH_DDOS_COOLDOWN", "30s"), 30*time.Second)
	ddosSustain := parseInt(getEnv("NETWATCH_DDOS_SUSTAIN_WINDOWS", "3"), 3)
	ddosWarmup := parseInt(getEnv("NETWATCH_DDOS_BASELINE_WARMUP_WINDOWS", "20"), 20)
	ddosAlpha := parseFloat(getEnv("NETWATCH_DDOS_BASELINE_ALPHA", "0.08"), 0.08)
	ddosFactor := parseFloat(getEnv("NETWATCH_DDOS_BASELINE_FACTOR", "4.0"), 4.0)
	ddosMinPPS := parseFloat(getEnv("NETWATCH_DDOS_MIN_PPS", "3000"), 3000)
	ddosMinBPS := parseFloat(getEnv("NETWATCH_DDOS_MIN_BPS", "500000"), 500000)
	ddosMinPackets := parseInt(getEnv("NETWATCH_DDOS_MIN_PACKETS", "0"), 0)
	ddosMinRequests := parseInt(getEnv("NETWATCH_DDOS_MIN_REQUESTS", "0"), 0)
	ddosMinConf := parseInt(getEnv("NETWATCH_DDOS_MIN_CONFIDENCE", "70"), 70)
	ddosMinSynRatio := parseFloat(getEnv("NETWATCH_DDOS_MIN_SYN_RATIO", "0.70"), 0.70)
	ddosMinSrcIPs := parseInt(getEnv("NETWATCH_DDOS_MIN_SRC_IPS", "30"), 30)
	ddosMinSrcEntropy := parseFloat(getEnv("NETWATCH_DDOS_MIN_SRC_ENTROPY_NORM", "0.70"), 0.70)

	ddosEnableL7 := parseBool(getEnv("NETWATCH_DDOS_ENABLE_L7", "true"), true)
	ddosMinHTTPRPS := parseFloat(getEnv("NETWATCH_DDOS_MIN_HTTP_RPS", "200"), 200)
	ddosMinTLS := parseFloat(getEnv("NETWATCH_DDOS_MIN_TLS_HS_RPS", "200"), 200)
	ddosMinL7Ratio := parseFloat(getEnv("NETWATCH_DDOS_MIN_L7_RATIO", "0.15"), 0.15)

	ddosEnableEntropy := parseBool(getEnv("NETWATCH_DDOS_ENABLE_ENTROPY", "true"), true)
	ddosMinSrcEntropySig := parseFloat(getEnv("NETWATCH_DDOS_MIN_SRC_ENTROPY_NORM_SIGNAL", "0.75"), 0.75)
	ddosMinPortEntropy := parseFloat(getEnv("NETWATCH_DDOS_MIN_PORT_ENTROPY_NORM", "0.35"), 0.35)
	ddosPortTopN := parseInt(getEnv("NETWATCH_DDOS_PORT_ENTROPY_TOPN", "16"), 16)

	ddosCardMode := strings.ToLower(strings.TrimSpace(getEnv("NETWATCH_DDOS_CARDINALITY_MODE", "hll")))
	ddosHLLP := parseInt(getEnv("NETWATCH_DDOS_HLL_PRECISION", "14"), 14)
	ddosBloomBits := parseInt(getEnv("NETWATCH_DDOS_BLOOM_BITS", "1048576"), 1048576)
	ddosMaxUnique := parseInt(getEnv("NETWATCH_DDOS_MAX_UNIQUE_SRC", "500000"), 500000)
	ddosTopSrc := parseInt(getEnv("NETWATCH_DDOS_TOP_SRC", "20"), 20)
	ddosMaxBatch := parseInt(getEnv("NETWATCH_DDOS_MAX_BATCH", "200"), 200)
	ddosBpHighWM := parseInt(getEnv("NETWATCH_DDOS_BACKPRESSURE_HIGH_WATERMARK", "160"), 160)
	ddosBpSampleEvery := parseInt(getEnv("NETWATCH_DDOS_BACKPRESSURE_SAMPLE_EVERY", "4"), 4)

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

		AgentConfigFile: agentConfigFile,
		BootstrapToken:  bootstrapToken,
		AgentCredential: agentCredential,
		AgentCredentialExpiresAt: "",
		CredentialFile:  credentialFile,

		TLSCAFile:     tlsCAFile,
		TLSServerName: tlsServerName,

		ControlHeartbeatEvery:  controlHeartbeatEvery,
		ControlHeartbeatJitter: controlHeartbeatJitter,
		ControlConfigEvery:     controlConfigEvery,
		ControlConfigJitter:    controlConfigJitter,
		ControlEnrollTimeout:   controlEnrollTimeout,
		ForceEnrollOnStart:     forceEnrollOnStart,
		CredentialRotateEvery:  credentialRotateEvery,
		CredentialRotateBefore: credentialRotateBefore,

		SyscollectEvery:          syscollectEvery,
		SyscollectStartupJitter:  syscollectStartupJitter,
		SyscollectCmdTimeout:     syscollectCmdTimeout,
		SyscollectMaxOutputBytes: syscollectMaxOutputBytes,
		SyscollectMaxPackages:    syscollectMaxPackages,
		SyscollectHostRoot:       syscollectHostRoot,

		VulnScanEvery:        vulnEvery,
		VulnStartupJitter:    vulnStartupJitter,
		VulnOSVURL:           vulnOSVURL,
		VulnMinSeverity:      vulnMinSeverity,
		VulnAnalysisProfile:  vulnAnalysisProfile,
		VulnExposureEnabled:  vulnExposureEnabled,
		VulnQueryBatchSize:   vulnBatch,
		VulnCmdTimeout:       vulnCmdTimeout,
		VulnHTTPTimeout:      vulnHTTPTimeout,
		VulnMaxOutputBytes:   vulnMaxOutputBytes,
		VulnMaxPackages:      vulnMaxPackages,
		VulnHostRoot:         vulnHostRoot,
		VulnEmitSummaryEvent: vulnEmitSummaryEvent,

		AuthLogPath:         logPath,
		AuthIncludeAccepted: includeAccepted,
		AuthDedupTTL:        authDedupTTL,

		ProcTCP4Path: procTCP4Path,
		ProcTCP6Path: procTCP6Path,

		SkipLoopback:         skipLoopback,
		SkipLinkLocal:        skipLinkLocal,
		SkipPrivateToPrivate: skipPrivate,

		ProcDropLikelyOutbound: procDropOutbound,
		EphemeralPortMin:       ephemeralMin,

		DedupTTL:       dedupTTL,
		EstablishedTTL: establishedTTL,

		DenyCIDRs:    denyCIDRs,
		DenyDstPorts: denyDstPorts,
		DenySrcPorts: denySrcPorts,

		LateralMode:               lateralMode,
		LateralIface:              lateralIface,
		LateralPorts:              lateralPorts,
		LateralIncludeEstablished: lateralIncludeEstablished,
		LateralDedupTTL:           lateralDedup,
		LateralMaxBatch:           lateralMaxBatch,

		ScanIface:    scanIface,
		ScanDedupTTL: scanDedup,
		ScanMaxBatch: scanMaxBatch,

		ScanMode: scanMode,

		DDoSIface:                   ddosIface,
		DDoSWindow:                  ddosWindow,
		DDoSEvalEvery:               ddosEvalEvery,
		DDoSCooldown:                ddosCooldown,
		DDoSSustainWindows:          ddosSustain,
		DDoSBaselineWarmupWindows:   ddosWarmup,
		DDoSBaselineAlpha:           ddosAlpha,
		DDoSBaselineFactor:          ddosFactor,
		DDoSMinPPS:                  ddosMinPPS,
		DDoSMinBPS:                  ddosMinBPS,
		DDoSMinPackets:              ddosMinPackets,
		DDoSMinRequests:             ddosMinRequests,
		DDoSMinConfidence:           ddosMinConf,
		DDoSMinSynRatio:             ddosMinSynRatio,
		DDoSMinSrcIPs:               ddosMinSrcIPs,
		DDoSMinSrcEntropyNorm:       ddosMinSrcEntropy,
		DDoSEnableL7:                ddosEnableL7,
		DDoSMinHTTPRPS:              ddosMinHTTPRPS,
		DDoSMinTLSHSRPS:             ddosMinTLS,
		DDoSMinL7Ratio:              ddosMinL7Ratio,
		DDoSEnableEntropy:           ddosEnableEntropy,
		DDoSMinSrcEntropyNormSignal: ddosMinSrcEntropySig,
		DDoSMinPortEntropyNorm:      ddosMinPortEntropy,
		DDoSPortEntropyTopN:         ddosPortTopN,
		DDoSCardinalityMode:         ddosCardMode,
		DDoSHLLPrecision:            ddosHLLP,
		DDoSBloomBits:               ddosBloomBits,
		DDoSMaxUniqueSrc:            ddosMaxUnique,
		DDoSTopSrc:                  ddosTopSrc,
		DDoSMaxBatch:                ddosMaxBatch,
		DDoSBackpressureHighWM:      ddosBpHighWM,
		DDoSBackpressureSampleEvery: ddosBpSampleEvery,

		LogLevel:          logLevel,
		LogSummaryEvery:   logSummaryEvery,
		LogHeartbeatEvery: logHeartbeatEvery,
		LogMinEvents:      logMinEvents,
	}
}

func waitForHealth(ctx context.Context, baseURL string, httpClient *http.Client) error {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/health"

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
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

func getSecretEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	if filePath, ok := os.LookupEnv(k + "_FILE"); ok && strings.TrimSpace(filePath) != "" {
		return readTextFile(filePath)
	}

	return def
}

func splitCSVLower(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
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

func parseFloat(s string, def float64) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
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

func applyAgentRuntimeOverrides(cfg *Config, raw map[string]interface{}) {
	if cfg == nil {
		return
	}
	modules := asMap(raw["modules"])
	if modules == nil {
		return
	}
	dd := asMap(modules["ddos"])
	if dd == nil {
		return
	}

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

func readTextFile(path string) string {
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
