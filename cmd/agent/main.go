package main

import (
	"context"
	"encoding/json"
	"errors"
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

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/ddos"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/fim"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/l7"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/lateral"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/proc"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/procexec"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/scan"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/ssh"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/netutil"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/responseactions"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/sender"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

const (
	defaultL7Sources         = "authlog,proc,proc_exec,fim,scan,ddos,l7"
	defaultL7DedupTTL        = 20 * time.Second
	defaultL7MaxBatch        = 400
	defaultL7MaxPayloadBytes = 512
	maxL7MaxBatch            = 2000
	maxL7MaxPayloadBytes     = 4096
)

type Config struct {
	AgentID        string
	APIURL         string
	Sources        []string
	Interval       time.Duration
	HTTPTimeout    time.Duration
	SenderMaxBatch int

	AgentConfigFile               string
	AgentIdentityStateFile        string
	BootstrapToken                string
	BootstrapTokenFile            string
	AgentCredential               string
	AgentCredentialExpiresAt      string
	CredentialFile                string
	RenewalToken                  string
	RenewalTokenExpiresAt         string
	PreviousRenewalToken          string
	PreviousRenewalTokenExpiresAt string

	TLSCAFile     string
	TLSCertFile   string
	TLSKeyFile    string
	TLSServerName string

	ControlHeartbeatEvery     time.Duration
	ControlHeartbeatJitter    time.Duration
	ControlConfigEvery        time.Duration
	ControlConfigJitter       time.Duration
	ControlResponsePollEvery  time.Duration
	ControlResponsePollJitter time.Duration
	ControlEnrollTimeout      time.Duration
	ForceEnrollOnStart        bool
	CredentialRotateEvery     time.Duration
	CredentialRotateBefore    time.Duration
	ResponseActionStageMax    int

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

	ProcExecEvery             time.Duration
	ProcExecMaxBatch          int
	ProcExecHashEnabled       bool
	ProcExecHashMaxBytes      int64
	ProcExecEmitInitial       bool
	ProcExecIgnoreExeNames    map[string]bool
	ProcExecIgnoreCmdContains []string

	FIMEvery        time.Duration
	FIMMaxBatch     int
	FIMMaxDepth     int
	FIMHashEnabled  bool
	FIMHashMaxBytes int64
	FIMEmitInitial  bool
	FIMWatchPaths   []string
	FIMExcludePaths []string

	L7Iface           string
	L7DedupTTL        time.Duration
	L7MaxBatch        int
	L7MaxPayloadBytes int
	L7IncludePayload  bool

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

	SendAttemptsTotal             int
	SendErrorsTotal               int
	ResponseActionPollErrorsTotal int
	ResponseActionsStagedTotal    int

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

	sender               *sender.Sender
	cp                   *controlplane.Client
	runtime              *RuntimeConfig
	credMu               sync.RWMutex
	cred                 string
	credExp              time.Time
	renewalToken         string
	renewalExp           time.Time
	previousRenewalToken string
	previousRenewalExp   time.Time
	lastRecoveryMethod   string

	sysMu     sync.RWMutex
	sysStatus SyscollectorStatus

	procCapturer     *proc.Capturer
	procExecCapturer *procexec.Capturer
	fimCapturer      *fim.Capturer
	l7Capturer       *l7.PcapL7Capturer
	authCapturer     *ssh.AuthLogCapturer
	lateralProc      *lateral.ProcLateralCapturer
	lateralPcap      *lateral.PcapLateralCapturer
	scanCapturer     *scan.PcapScanCapturer
	ddosCapturer     *ddos.PcapDDoSCapturer

	vulnMu     sync.RWMutex
	vulnStatus VulnScannerStatus

	responseStage *responseactions.Stage

	state SummaryState

	enrollMu          sync.Mutex
	recoveryInFlight  bool
	recoveryFailures  int
	nextEnrollRetryAt time.Time
}

func main() {
	cfg := loadConfig()
	httpClient, err := netutil.NewHTTPClient(cfg.HTTPTimeout, netutil.TLSOptions{
		CAFile:     strings.TrimSpace(cfg.TLSCAFile),
		CertFile:   strings.TrimSpace(cfg.TLSCertFile),
		KeyFile:    strings.TrimSpace(cfg.TLSKeyFile),
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

	a, err := newAgent(cfg, rootCtx, stop, httpClient)
	if err != nil {
		log.Fatalf("[AGENT] init error: %v", err)
	}
	a.ensureInitialIdentity(rootCtx)

	a.startControlPlane(rootCtx)
	a.startSyscollector(rootCtx)
	a.startVulnScanner(rootCtx)

	a.loop(rootCtx)
}

func newAgent(cfg Config, rootCtx context.Context, stop context.CancelFunc, httpClient *http.Client) (*Agent, error) {
	now := time.Now().UTC()

	a := &Agent{
		cfg:                  cfg,
		cred:                 strings.TrimSpace(cfg.AgentCredential),
		renewalToken:         strings.TrimSpace(cfg.RenewalToken),
		previousRenewalToken: strings.TrimSpace(cfg.PreviousRenewalToken),
		lastRecoveryMethod:   "startup",
		responseStage:        responseactions.NewStage(cfg.ResponseActionStageMax),
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
	a.credExp = parseOptionalRFC3339(cfg.AgentCredentialExpiresAt)
	a.renewalExp = parseOptionalRFC3339(cfg.RenewalTokenExpiresAt)
	a.previousRenewalExp = parseOptionalRFC3339(cfg.PreviousRenewalTokenExpiresAt)

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

	if contains(cfg.Sources, "proc_exec") {
		a.procExecCapturer = procexec.New(cfg.AgentID, procexec.Options{
			MinInterval:       cfg.ProcExecEvery,
			MaxBatchSize:      cfg.ProcExecMaxBatch,
			HashExecutables:   cfg.ProcExecHashEnabled,
			HashMaxBytes:      cfg.ProcExecHashMaxBytes,
			EmitInitialState:  cfg.ProcExecEmitInitial,
			IgnoreExeNames:    cfg.ProcExecIgnoreExeNames,
			IgnoreCmdContains: cfg.ProcExecIgnoreCmdContains,
			ProcRoot:          "/proc",
			CmdlineMaxBytes:   2048,
			HashCacheTTL:      6 * time.Hour,
			HashCacheMaxItems: 4096,
			UsernameCacheTTL:  10 * time.Minute,
		})
	}

	if contains(cfg.Sources, "fim") {
		a.fimCapturer = fim.New(cfg.AgentID, fim.Options{
			WatchPaths:        cfg.FIMWatchPaths,
			Exclude:           cfg.FIMExcludePaths,
			MinInterval:       cfg.FIMEvery,
			MaxBatchSize:      cfg.FIMMaxBatch,
			MaxDepth:          cfg.FIMMaxDepth,
			EmitInitialState:  cfg.FIMEmitInitial,
			HashEnabled:       cfg.FIMHashEnabled,
			HashMaxBytes:      cfg.FIMHashMaxBytes,
			HashCacheTTL:      6 * time.Hour,
			HashCacheMaxItems: 4096,
		})
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

	if contains(cfg.Sources, "l7") {
		l7c, err := l7.NewPcapL7Capturer(cfg.AgentID, l7.PcapL7Options{
			Interface:       cfg.L7Iface,
			DedupTTL:        cfg.L7DedupTTL,
			MaxBatchSize:    cfg.L7MaxBatch,
			MaxPayloadBytes: cfg.L7MaxPayloadBytes,
			IncludePayload:  cfg.L7IncludePayload,
			SkipLoopback:    cfg.SkipLoopback,
			SkipLinkLocal:   cfg.SkipLinkLocal,
		})
		if err != nil {
			logJSON(LevelWarn, "l7_capture_disabled", map[string]interface{}{
				"agent_id":              cfg.AgentID,
				"interface":             cfg.L7Iface,
				"include_payload":       cfg.L7IncludePayload,
				"max_batch":             cfg.L7MaxBatch,
				"max_payload_bytes":     cfg.L7MaxPayloadBytes,
				"error":                 err.Error(),
				"continuing_without_l7": true,
			})
		} else {
			a.l7Capturer = l7c
			go func() {
				if err := a.l7Capturer.Start(rootCtx); err != nil {
					logJSON(LevelWarn, "l7_capture_stopped", map[string]interface{}{
						"agent_id":              cfg.AgentID,
						"interface":             cfg.L7Iface,
						"error":                 err.Error(),
						"continuing_without_l7": true,
					})
				}
			}()
		}
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

func (a *Agent) currentRenewalToken() string {
	a.credMu.RLock()
	defer a.credMu.RUnlock()
	return strings.TrimSpace(a.renewalToken)
}

func (a *Agent) recoveryTokenSnapshot() (string, time.Time, string, time.Time) {
	a.credMu.RLock()
	defer a.credMu.RUnlock()
	return strings.TrimSpace(a.renewalToken), a.renewalExp, strings.TrimSpace(a.previousRenewalToken), a.previousRenewalExp
}

func (a *Agent) currentBootstrapToken() string {
	if tokenFile := strings.TrimSpace(a.cfg.BootstrapTokenFile); tokenFile != "" {
		return strings.TrimSpace(readTextFile(tokenFile))
	}
	return strings.TrimSpace(a.cfg.BootstrapToken)
}

func (a *Agent) authStateSnapshot() (time.Time, time.Time, string, int, time.Time) {
	a.credMu.RLock()
	credExp := a.credExp
	renewalExp := a.renewalExp
	recoveryMethod := a.lastRecoveryMethod
	a.credMu.RUnlock()
	a.enrollMu.Lock()
	recoveryFailures := a.recoveryFailures
	nextRetryAt := a.nextEnrollRetryAt
	a.enrollMu.Unlock()
	return credExp, renewalExp, recoveryMethod, recoveryFailures, nextRetryAt
}

func (a *Agent) applyCredentialUpdate(update controlplane.Credential, recoveryMethod string) error {
	cred := strings.TrimSpace(update.Credential)
	if cred == "" {
		return fmt.Errorf("empty credential update")
	}
	currentRenewal, currentRenewalExp, previousRenewal, previousRenewalExp := a.recoveryTokenSnapshot()
	renewalToken := strings.TrimSpace(update.RenewalToken)
	renewalExpiresAt := strings.TrimSpace(update.RenewalTokenExpiresAt)
	if renewalToken == "" {
		renewalToken = currentRenewal
		if renewalExpiresAt == "" && !currentRenewalExp.IsZero() {
			renewalExpiresAt = currentRenewalExp.Format(time.RFC3339)
		}
	}
	previousRenewalToken := previousRenewal
	previousRenewalTokenExpiresAt := formatOptionalTime(previousRenewalExp)
	if renewalToken != "" && renewalToken != currentRenewal {
		previousRenewalToken = currentRenewal
		previousRenewalTokenExpiresAt = formatOptionalTime(currentRenewalExp)
	}

	state := PersistedIdentityState{
		AgentID:                       a.cfg.AgentID,
		Credential:                    cred,
		CredentialExpiresAt:           strings.TrimSpace(update.ExpiresAt),
		RenewalToken:                  renewalToken,
		RenewalTokenExpiresAt:         renewalExpiresAt,
		PreviousRenewalToken:          previousRenewalToken,
		PreviousRenewalTokenExpiresAt: previousRenewalTokenExpiresAt,
		LastRecoveryMethod:            strings.TrimSpace(recoveryMethod),
	}
	if err := saveIdentityState(a.cfg.AgentIdentityStateFile, state); err != nil {
		return err
	}
	if a.cfg.CredentialFile != "" {
		if err := atomicWriteFile(a.cfg.CredentialFile, []byte(cred+"\n"), 0o600); err != nil {
			logJSON(LevelWarn, "agent_credential_compat_write_failed", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"path":     a.cfg.CredentialFile,
				"error":    err.Error(),
			})
		}
	}

	a.credMu.Lock()
	a.cred = cred
	a.credExp = parseOptionalRFC3339(update.ExpiresAt)
	a.renewalToken = renewalToken
	a.renewalExp = parseOptionalRFC3339(renewalExpiresAt)
	a.previousRenewalToken = previousRenewalToken
	a.previousRenewalExp = parseOptionalRFC3339(previousRenewalTokenExpiresAt)
	a.lastRecoveryMethod = strings.TrimSpace(recoveryMethod)
	a.credMu.Unlock()
	a.enrollMu.Lock()
	a.recoveryFailures = 0
	a.nextEnrollRetryAt = time.Time{}
	a.enrollMu.Unlock()
	return nil
}

func (a *Agent) persistRemoteConfig(cfg map[string]interface{}) {
	if a.cfg.AgentConfigFile == "" || len(cfg) == 0 {
		return
	}
	if b, err := json.Marshal(cfg); err == nil {
		_ = atomicWriteFile(a.cfg.AgentConfigFile, b, 0o600)
	}
}

func (a *Agent) ensureInitialIdentity(rootCtx context.Context) {
	cred := a.currentCredential()
	if cred != "" {
		if a.cfg.CredentialFile != "" {
			_ = atomicWriteFile(a.cfg.CredentialFile, []byte(cred+"\n"), 0o600)
		}
		credExp, renewalExp, _, _, _ := a.authStateSnapshot()
		logJSON(LevelInfo, "agent_identity_loaded", map[string]interface{}{
			"agent_id":                a.cfg.AgentID,
			"identity_state_file":     a.cfg.AgentIdentityStateFile,
			"credential_file":         a.cfg.CredentialFile,
			"credential_expires_at":   formatOptionalTime(credExp),
			"renewal_token_present":   strings.TrimSpace(a.currentRenewalToken()) != "",
			"renewal_expires_at":      formatOptionalTime(renewalExp),
			"bootstrap_token_present": strings.TrimSpace(a.currentBootstrapToken()) != "",
		})
		return
	}
	if !a.cfg.ForceEnrollOnStart {
		return
	}
	if err := a.recoverIdentity(rootCtx, "startup_missing_identity", false); err != nil {
		logJSON(LevelWarn, "agent_identity_bootstrap_failed", map[string]interface{}{
			"agent_id": a.cfg.AgentID,
			"error":    err.Error(),
		})
	}
}

func (a *Agent) stageResponseActions(actions []controlplane.ResponseAction) responseactions.StageResult {
	if a.responseStage == nil {
		a.responseStage = responseactions.NewStage(a.cfg.ResponseActionStageMax)
	}
	out := a.responseStage.Stage(time.Now().UTC(), actions, a.cfg.AgentID)
	a.state.ResponseActionsStagedTotal += out.Added
	return out
}

func (a *Agent) pendingResponseActions() int {
	if a.responseStage == nil {
		return 0
	}
	return a.responseStage.PendingCount()
}

func (a *Agent) startResponseActionExecutor(rootCtx context.Context) {
	if a.responseStage == nil || a.cp == nil {
		return
	}
	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				for i := 0; i < 8; i++ {
					staged, ok := a.responseStage.Next(time.Now().UTC(), a.cfg.AgentID)
					if !ok {
						break
					}

					now := time.Now().UTC()
					runningResult := controlplane.ResponseActionExecutionResult{
						ResponseActionID: staged.Action.ID,
						AgentID:          a.cfg.AgentID,
						Status:           "running",
						StartedAt:        &now,
					}
					{
						ctx, cancel := context.WithTimeout(rootCtx, a.cfg.HTTPTimeout)
						err := a.cp.ReportResponseActionResult(ctx, runningResult)
						cancel()
						if err != nil {
							logJSON(LevelWarn, "response_action_running_report_failed", map[string]interface{}{
								"agent_id":  a.cfg.AgentID,
								"action_id": staged.Action.ID,
								"error":     err.Error(),
							})
							a.maybeRecoverIdentity(rootCtx, "response_action_running_report", err.Error(), 0)
							continue
						}
					}

					modules := map[string]interface{}{}
					for _, src := range a.cfg.Sources {
						modules[strings.TrimSpace(src)] = true
					}
					execRes := responseactions.Execute(staged.Action, responseactions.ExecuteOptions{
						ExpectedAgentID: a.cfg.AgentID,
						AgentID:         a.cfg.AgentID,
						BuildVersion:    "0.1.0",
						EffectiveConfig: a.runtime.Raw(),
						ModuleStates:    modules,
						RefreshRuntimeConfig: func() (bool, int, string, error) {
							ctxCfg, cancelCfg := context.WithTimeout(rootCtx, a.cfg.HTTPTimeout)
							cfg, err := a.cp.GetConfig(ctxCfg)
							cancelCfg()
							if err != nil {
								return false, 0, "", err
							}
							if a.runtime == nil {
								return false, len(cfg), "", nil
							}
							changed, _ := a.runtime.Apply(cfg)
							return changed, len(cfg), a.runtime.Hash(), nil
						},
						AgentStartedAt: a.state.StartedAt,
						Now:            now,
					})
					a.responseStage.MarkHandled(staged.Action.ID)

					result := controlplane.ResponseActionExecutionResult{
						ResponseActionID: staged.Action.ID,
						AgentID:          a.cfg.AgentID,
						Status:           execRes.Status,
						ResultPayload:    execRes.Result,
						Error:            execRes.Error,
						StartedAt:        &execRes.StartedAt,
						FinishedAt:       &execRes.FinishedAt,
					}
					ctx, cancel := context.WithTimeout(rootCtx, a.cfg.HTTPTimeout)
					err := a.cp.ReportResponseActionResult(ctx, result)
					cancel()
					if err != nil {
						logJSON(LevelWarn, "response_action_report_failed", map[string]interface{}{
							"agent_id":  a.cfg.AgentID,
							"action_id": staged.Action.ID,
							"status":    execRes.Status,
							"error":     err.Error(),
						})
						a.maybeRecoverIdentity(rootCtx, "response_action_report", err.Error(), 0)
						continue
					}
					logJSON(LevelInfo, "response_action_executed", map[string]interface{}{
						"agent_id":  a.cfg.AgentID,
						"action_id": staged.Action.ID,
						"type":      staged.Action.ActionType,
						"status":    execRes.Status,
					})
				}
			}
		}
	}()
}

func (a *Agent) startControlPlane(rootCtx context.Context) {
	if a.cp == nil {
		return
	}

	// One-time identity refresh for upgraded agents that only have the legacy credential file.
	go func() {
		delay := stableJitter(a.cfg.AgentID, "control.identity_refresh", 90*time.Second)
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-rootCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		if strings.TrimSpace(a.currentCredential()) == "" {
			return
		}
		credExp, renewalExp, _, _, _ := a.authStateSnapshot()
		if !credExp.IsZero() && !renewalExp.IsZero() {
			return
		}

		ctx, cancel := context.WithTimeout(rootCtx, a.cfg.ControlEnrollTimeout)
		rot, err := a.cp.RotateCredential(ctx)
		cancel()
		if err != nil {
			logJSON(LevelWarn, "agent_identity_refresh_failed", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
			a.maybeRecoverIdentity(rootCtx, "startup_identity_refresh", err.Error(), 0)
			return
		}
		if err := a.applyCredentialUpdate(rot, "startup_refresh"); err != nil {
			logJSON(LevelWarn, "agent_identity_refresh_persist_failed", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
			return
		}
		logJSON(LevelInfo, "agent_identity_refreshed", map[string]interface{}{
			"agent_id":              a.cfg.AgentID,
			"credential_expires_at": strings.TrimSpace(rot.ExpiresAt),
			"renewal_expires_at":    strings.TrimSpace(rot.RenewalTokenExpiresAt),
		})
	}()

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
				credExp, renewalExp, recoveryMethod, recoveryFailures, nextRetryAt := a.authStateSnapshot()
				metrics["auth_identity_state_file"] = a.cfg.AgentIdentityStateFile
				metrics["auth_has_credential"] = strings.TrimSpace(a.currentCredential()) != ""
				currentRenewal, _, previousRenewal, _ := a.recoveryTokenSnapshot()
				metrics["auth_has_renewal_token"] = strings.TrimSpace(currentRenewal) != ""
				metrics["auth_has_previous_renewal_token"] = strings.TrimSpace(previousRenewal) != ""
				metrics["auth_last_recovery_method"] = recoveryMethod
				metrics["auth_recovery_failures"] = recoveryFailures
				if !credExp.IsZero() {
					metrics["auth_credential_expires_at"] = credExp.Format(time.RFC3339)
					metrics["auth_credential_seconds_remaining"] = int64(time.Until(credExp).Seconds())
				}
				if !renewalExp.IsZero() {
					metrics["auth_renewal_expires_at"] = renewalExp.Format(time.RFC3339)
					metrics["auth_renewal_seconds_remaining"] = int64(time.Until(renewalExp).Seconds())
				}
				if !nextRetryAt.IsZero() {
					metrics["auth_next_recovery_retry_at"] = nextRetryAt.Format(time.RFC3339)
				}
				if a.runtime != nil {
					metrics["config_hash"] = a.runtime.Hash()
				}
				metrics["response_actions_pending"] = a.pendingResponseActions()
				metrics["response_actions_poll_errors_total"] = a.state.ResponseActionPollErrorsTotal
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
					a.maybeRecoverIdentity(rootCtx, "controlplane_heartbeat", err.Error(), 0)
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
					a.maybeRecoverIdentity(rootCtx, "controlplane_config", err.Error(), 0)
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

	responseactions.StartPolling(rootCtx, responseactions.PollerConfig{
		AgentID: a.cfg.AgentID,
		Every:   a.cfg.ControlResponsePollEvery,
		Jitter:  a.cfg.ControlResponsePollJitter,
		Timeout: a.cfg.HTTPTimeout,
	}, responseactions.PollerDeps{
		Fetch: func(ctx context.Context) ([]controlplane.ResponseAction, error) {
			return a.cp.ListPendingResponseActions(ctx)
		},
		Stage: a.stageResponseActions,
		OnError: func(err error) {
			a.state.ResponseActionPollErrorsTotal++
			logJSON(LevelWarn, "controlplane_response_actions_poll_error", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
			a.maybeRecoverIdentity(rootCtx, "response_actions_poll", err.Error(), 0)
		},
		OnStaged: func(fetched int, result responseactions.StageResult) {
			if result.Added > 0 || result.Dropped > 0 {
				logJSON(LevelInfo, "response_actions_staged", map[string]interface{}{
					"agent_id": a.cfg.AgentID,
					"fetched":  fetched,
					"added":    result.Added,
					"ignored":  result.Ignored,
					"dropped":  result.Dropped,
					"pending":  result.Pending,
				})
			}
		},
	})
	a.startResponseActionExecutor(rootCtx)

	// Credential rotation loop.
	go func() {
		t := time.NewTicker(a.cfg.CredentialRotateEvery)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				credExp, renewalExp, _, _, _ := a.authStateSnapshot()
				renewalRotateBefore := a.cfg.CredentialRotateBefore
				if renewalRotateBefore < 12*time.Hour {
					renewalRotateBefore = 12 * time.Hour
				}
				needsRotate := false
				if !credExp.IsZero() && time.Until(credExp) <= a.cfg.CredentialRotateBefore {
					needsRotate = true
				}
				if !renewalExp.IsZero() && time.Until(renewalExp) <= renewalRotateBefore {
					needsRotate = true
				}
				if !needsRotate {
					continue
				}
				if strings.TrimSpace(a.currentCredential()) == "" {
					_ = a.recoverIdentity(rootCtx, "rotation_missing_credential", false)
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
					a.maybeRecoverIdentity(rootCtx, "credential_rotate_failed", err.Error(), 0)
					continue
				}
				if err := a.applyCredentialUpdate(rot, "credential_rotation"); err != nil {
					logJSON(LevelWarn, "agent_credential_rotate_persist_failed", map[string]interface{}{
						"agent_id": a.cfg.AgentID,
						"error":    err.Error(),
					})
					continue
				}
				logJSON(LevelInfo, "agent_credential_rotated", map[string]interface{}{
					"agent_id":              a.cfg.AgentID,
					"credential_expires_at": strings.TrimSpace(rot.ExpiresAt),
					"renewal_expires_at":    strings.TrimSpace(rot.RenewalTokenExpiresAt),
				})
			}
		}
	}()
}

func (a *Agent) shouldAttemptIdentityRecovery(errText string, status int) bool {
	if !a.cfg.ForceEnrollOnStart {
		return false
	}
	et := strings.ToLower(strings.TrimSpace(errText))
	if status == 401 {
		return true
	}
	if strings.Contains(et, "status=401") {
		return true
	}
	return strings.Contains(et, "unknown or revoked agent") ||
		strings.Contains(et, "invalid agent credential") ||
		strings.Contains(et, "credential expired") ||
		strings.Contains(et, "credential exhausted")
}

func (a *Agent) nextRecoveryBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	wait := 5 * time.Second
	for i := 1; i < failures; i++ {
		wait *= 2
		if wait >= 5*time.Minute {
			wait = 5 * time.Minute
			break
		}
	}
	jitterMax := wait / 3
	if jitterMax > 30*time.Second {
		jitterMax = 30 * time.Second
	}
	return wait + stableJitter(a.cfg.AgentID, fmt.Sprintf("auth.recovery.%d", failures), jitterMax)
}

func (a *Agent) maybeRecoverIdentity(rootCtx context.Context, trigger string, errText string, status int) {
	if !a.shouldAttemptIdentityRecovery(errText, status) {
		return
	}
	_ = a.recoverIdentity(rootCtx, trigger, false)
}

func (a *Agent) recoverIdentity(rootCtx context.Context, trigger string, force bool) error {
	if !a.cfg.ForceEnrollOnStart {
		return fmt.Errorf("identity recovery disabled")
	}

	now := time.Now().UTC()
	a.enrollMu.Lock()
	if a.recoveryInFlight {
		a.enrollMu.Unlock()
		return fmt.Errorf("identity recovery already in progress")
	}
	if !force && !a.nextEnrollRetryAt.IsZero() && now.Before(a.nextEnrollRetryAt) {
		next := a.nextEnrollRetryAt
		a.enrollMu.Unlock()
		return fmt.Errorf("identity recovery backed off until %s", next.Format(time.RFC3339))
	}
	failures := a.recoveryFailures
	a.nextEnrollRetryAt = time.Time{}
	a.recoveryInFlight = true
	a.enrollMu.Unlock()
	defer func() {
		a.enrollMu.Lock()
		a.recoveryInFlight = false
		a.enrollMu.Unlock()
	}()

	bootstrapToken := strings.TrimSpace(a.currentBootstrapToken())
	currentRenewal, renewalExp, previousRenewal, previousRenewalExp := a.recoveryTokenSnapshot()
	renewalToken := strings.TrimSpace(currentRenewal)
	if !renewalExp.IsZero() && now.After(renewalExp) {
		renewalToken = ""
	}
	previousRenewalToken := strings.TrimSpace(previousRenewal)
	if previousRenewalToken == renewalToken {
		previousRenewalToken = ""
	}
	if !previousRenewalExp.IsZero() && now.After(previousRenewalExp) {
		previousRenewalToken = ""
	}

	hostname, _ := os.Hostname()
	type recoveryMethod struct {
		name            string
		token           string
		consumeFilePath string
	}
	methods := make([]recoveryMethod, 0, 2)
	if renewalToken != "" {
		methods = append(methods, recoveryMethod{name: "renewal", token: renewalToken})
	}
	if previousRenewalToken != "" {
		methods = append(methods, recoveryMethod{name: "renewal_previous", token: previousRenewalToken})
	}
	if bootstrapToken != "" {
		methods = append(methods, recoveryMethod{name: "bootstrap", token: bootstrapToken, consumeFilePath: a.cfg.BootstrapTokenFile})
	}
	if len(methods) == 0 {
		a.enrollMu.Lock()
		a.recoveryFailures = failures + 1
		a.nextEnrollRetryAt = now.Add(a.nextRecoveryBackoff(a.recoveryFailures))
		next := a.nextEnrollRetryAt
		a.enrollMu.Unlock()
		return fmt.Errorf("no recovery token or bootstrap token available; next retry at %s", next.Format(time.RFC3339))
	}

	var lastErr error
	for _, method := range methods {
		ctx, cancel := context.WithTimeout(rootCtx, a.cfg.ControlEnrollTimeout)
		resp, err := a.cp.Enroll(ctx, controlplane.EnrollRequest{
			AgentID:        a.cfg.AgentID,
			Hostname:       hostname,
			OS:             runtime.GOOS,
			Version:        "0.1.0",
			BootstrapToken: method.token,
		})
		cancel()
		if err != nil {
			lastErr = err
			logJSON(LevelWarn, "agent_identity_recovery_attempt_failed", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"trigger":  trigger,
				"method":   method.name,
				"error":    err.Error(),
			})
			continue
		}
		if err := a.applyCredentialUpdate(resp.Credential, method.name); err != nil {
			lastErr = err
			logJSON(LevelWarn, "agent_identity_recovery_persist_failed", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"trigger":  trigger,
				"method":   method.name,
				"error":    err.Error(),
			})
			continue
		}
		if a.runtime != nil && len(resp.Config) > 0 {
			changed, _ := a.runtime.Apply(resp.Config)
			if changed {
				logJSON(LevelInfo, "controlplane_config_applied", map[string]interface{}{
					"agent_id":    a.cfg.AgentID,
					"config_hash": a.runtime.Hash(),
					"config_keys": len(resp.Config),
				})
			}
		}
		a.persistRemoteConfig(resp.Config)
		if method.consumeFilePath != "" {
			consumeBootstrapTokenFile(method.consumeFilePath, a.cfg.AgentID)
		}
		logJSON(LevelInfo, "agent_identity_recovered", map[string]interface{}{
			"agent_id":              a.cfg.AgentID,
			"trigger":               trigger,
			"method":                method.name,
			"credential_expires_at": strings.TrimSpace(resp.Credential.ExpiresAt),
			"renewal_expires_at":    strings.TrimSpace(resp.Credential.RenewalTokenExpiresAt),
		})
		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("identity recovery failed")
	}
	a.enrollMu.Lock()
	a.recoveryFailures = failures + 1
	a.nextEnrollRetryAt = now.Add(a.nextRecoveryBackoff(a.recoveryFailures))
	next := a.nextEnrollRetryAt
	a.enrollMu.Unlock()
	return fmt.Errorf("%w; next retry at %s", lastErr, next.Format(time.RFC3339))
}

func (a *Agent) runAndLog(rootCtx context.Context) {
	res := a.runOnce(rootCtx)
	if res == nil {
		return
	}
	if res.SendAttempted {
		a.maybeRecoverIdentity(rootCtx, "event_ingest", res.Error, res.Status)
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

	if a.procExecCapturer != nil {
		evs, err := a.procExecCapturer.Capture(time.Now().UTC())
		if err != nil {
			logJSON(LevelWarn, "proc_exec_capture_error", map[string]interface{}{
				"agent_id": a.cfg.AgentID,
				"error":    err.Error(),
			})
		} else if len(evs) > 0 {
			events = append(events, evs...)
		}
	}

	if a.fimCapturer != nil {
		evs, err := a.fimCapturer.Capture(time.Now().UTC())
		if err != nil {
			logJSON(LevelWarn, "fim_capture_error", map[string]interface{}{
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

	if a.l7Capturer != nil {
		evs := a.l7Capturer.Drain()
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

		"send_attempts_total":                a.state.SendAttemptsTotal,
		"send_errors_total":                  a.state.SendErrorsTotal,
		"response_actions_staged_total":      a.state.ResponseActionsStagedTotal,
		"response_actions_poll_errors_total": a.state.ResponseActionPollErrorsTotal,
		"last_http_status":                   a.state.LastHTTPStatus,
		"last_error":                         a.state.LastError,
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
	agentID := getEnv("SEAGULL_AGENT_ID", "agent-unknown")
	apiURL := strings.TrimSpace(getEnv("SEAGULL_API_URL", ""))
	if apiURL == "" {
		log.Fatal("[AGENT] SEAGULL_API_URL is required")
	}
	sources := splitCSVLower(getEnv("SEAGULL_SOURCES", defaultL7Sources))

	interval := parseDuration(getEnv("SEAGULL_POLL_INTERVAL", "1s"), 1*time.Second)
	httpTimeout := parseDuration(getEnv("SEAGULL_HTTP_TIMEOUT", "10s"), 10*time.Second)
	senderMaxBatch := parseInt(getEnv("SEAGULL_SENDER_MAX_BATCH", "300"), 300)

	agentConfigFile := getEnv("SEAGULL_AGENT_CONFIG_FILE", "/var/lib/seagull/agent.config.json")
	agentIdentityStateFile := getEnv("SEAGULL_AGENT_IDENTITY_STATE_FILE", "/var/lib/seagull/agent.identity.json")
	credentialFile := strings.TrimSpace(getEnv("SEAGULL_AGENT_CREDENTIAL_FILE", "/var/lib/seagull/agent.credential"))
	agentCredential := strings.TrimSpace(getSecretEnv("SEAGULL_AGENT_CREDENTIAL", ""))
	agentCredentialExpiresAt := ""
	renewalToken := ""
	renewalTokenExpiresAt := ""
	previousRenewalToken := ""
	previousRenewalTokenExpiresAt := ""

	if state, err := loadIdentityState(agentIdentityStateFile, agentID); err != nil {
		logJSON(LevelWarn, "identity_state_load_failed", map[string]interface{}{
			"agent_id": agentID,
			"path":     agentIdentityStateFile,
			"error":    err.Error(),
		})
	} else {
		if agentCredential == "" {
			agentCredential = strings.TrimSpace(state.Credential)
		}
		if agentCredentialExpiresAt == "" {
			agentCredentialExpiresAt = strings.TrimSpace(state.CredentialExpiresAt)
		}
		renewalToken = strings.TrimSpace(state.RenewalToken)
		renewalTokenExpiresAt = strings.TrimSpace(state.RenewalTokenExpiresAt)
		previousRenewalToken = strings.TrimSpace(state.PreviousRenewalToken)
		previousRenewalTokenExpiresAt = strings.TrimSpace(state.PreviousRenewalTokenExpiresAt)
	}

	if agentCredential == "" && credentialFile != "" {
		agentCredential = strings.TrimSpace(readTextFile(credentialFile))
	}
	hasExistingIdentity := agentCredential != "" || renewalToken != "" || previousRenewalToken != ""
	bootstrapToken, bootstrapTokenFile, err := loadBootstrapTokenValue(hasExistingIdentity)
	if err != nil {
		log.Fatalf("[AGENT] bootstrap token config error: %v", err)
	}

	tlsCAFile := strings.TrimSpace(getEnv("SEAGULL_TLS_CA_FILE", ""))
	tlsCertFile := strings.TrimSpace(getEnv("SEAGULL_TLS_CERT_FILE", ""))
	tlsKeyFile := strings.TrimSpace(getEnv("SEAGULL_TLS_KEY_FILE", ""))
	tlsServerName := strings.TrimSpace(getEnv("SEAGULL_TLS_SERVER_NAME", ""))
	if (tlsCertFile == "") != (tlsKeyFile == "") {
		log.Fatal("[AGENT] SEAGULL_TLS_CERT_FILE and SEAGULL_TLS_KEY_FILE must be set together")
	}

	controlHeartbeatEvery := parseDuration(getEnv("SEAGULL_CONTROL_HEARTBEAT_EVERY", "30s"), 30*time.Second)
	controlHeartbeatJitter := parseDuration(getEnv("SEAGULL_CONTROL_HEARTBEAT_JITTER", "5s"), 5*time.Second)
	controlConfigEvery := parseDuration(getEnv("SEAGULL_CONTROL_CONFIG_EVERY", "5m"), 5*time.Minute)
	controlConfigJitter := parseDuration(getEnv("SEAGULL_CONTROL_CONFIG_JITTER", "30s"), 30*time.Second)
	controlResponsePollEvery := parseDuration(getEnv("SEAGULL_CONTROL_RESPONSE_ACTIONS_POLL_EVERY", "15s"), 15*time.Second)
	controlResponsePollJitter := parseDuration(getEnv("SEAGULL_CONTROL_RESPONSE_ACTIONS_POLL_JITTER", "5s"), 5*time.Second)
	controlEnrollTimeout := parseDuration(getEnv("SEAGULL_CONTROL_ENROLL_TIMEOUT", "10s"), 10*time.Second)
	forceEnrollOnStart := parseBool(getEnv("SEAGULL_FORCE_ENROLL_ON_START", "true"), true)
	credentialRotateEvery := parseDuration(getEnv("SEAGULL_CONTROL_CREDENTIAL_ROTATE_EVERY", "5m"), 5*time.Minute)
	credentialRotateBefore := parseDuration(getEnv("SEAGULL_CONTROL_CREDENTIAL_ROTATE_BEFORE", "24h"), 24*time.Hour)
	responseActionStageMax := parseInt(getEnv("SEAGULL_RESPONSE_ACTION_STAGE_MAX", "512"), 512)

	syscollectEvery := parseDuration(getEnv("SEAGULL_SYSCOLLECT_EVERY", "5m"), 5*time.Minute)
	syscollectStartupJitter := parseDuration(getEnv("SEAGULL_SYSCOLLECT_STARTUP_JITTER", "45s"), 45*time.Second)
	syscollectCmdTimeout := parseDuration(getEnv("SEAGULL_SYSCOLLECT_CMD_TIMEOUT", "10s"), 10*time.Second)
	syscollectMaxOutputBytes := int64(parseInt(getEnv("SEAGULL_SYSCOLLECT_MAX_OUTPUT_BYTES", "8388608"), 8388608))
	syscollectMaxPackages := parseInt(getEnv("SEAGULL_SYSCOLLECT_MAX_PACKAGES", "50000"), 50000)
	syscollectHostRoot := strings.TrimSpace(getEnv("SEAGULL_HOST_ROOT", ""))

	vulnEvery := parseDuration(getEnv("SEAGULL_VULN_SCAN_EVERY", "12h"), 12*time.Hour)
	vulnStartupJitter := parseDuration(getEnv("SEAGULL_VULN_STARTUP_JITTER", "2m"), 2*time.Minute)
	vulnOSVURL := strings.TrimSpace(getEnv("SEAGULL_VULN_OSV_URL", "https://api.osv.dev"))
	vulnMinSeverity := strings.ToLower(strings.TrimSpace(getEnv("SEAGULL_VULN_MIN_SEVERITY", "medium")))
	vulnAnalysisProfile := strings.TrimSpace(getEnv("SEAGULL_VULN_ANALYSIS_PROFILE", "wazuh_like_v1"))
	vulnExposureEnabled := parseBool(getEnv("SEAGULL_VULN_EXPOSURE_ENABLED", "true"), true)
	vulnBatch := parseInt(getEnv("SEAGULL_VULN_QUERY_BATCH_SIZE", "200"), 200)
	vulnCmdTimeout := parseDuration(getEnv("SEAGULL_VULN_CMD_TIMEOUT", "15s"), 15*time.Second)
	vulnHTTPTimeout := parseDuration(getEnv("SEAGULL_VULN_HTTP_TIMEOUT", "60s"), 60*time.Second)
	vulnMaxOutputBytes := int64(parseInt(getEnv("SEAGULL_VULN_MAX_OUTPUT_BYTES", "8388608"), 8388608))
	vulnMaxPackages := parseInt(getEnv("SEAGULL_VULN_MAX_PACKAGES", strconv.Itoa(syscollectMaxPackages)), syscollectMaxPackages)
	vulnHostRoot := strings.TrimSpace(getEnv("SEAGULL_VULN_HOST_ROOT", syscollectHostRoot))
	vulnEmitSummaryEvent := parseBool(getEnv("SEAGULL_VULN_EMIT_SUMMARY_EVENT", "true"), true)

	logPath := getEnv("SEAGULL_AUTHLOG_PATH", "/var/log/auth.log")
	includeAccepted := parseBool(getEnv("SEAGULL_AUTHLOG_INCLUDE_ACCEPTED", "false"), false)
	authDedupTTL := parseDuration(getEnv("SEAGULL_AUTHLOG_DEDUP_TTL", "30s"), 30*time.Second)

	procTCP4Path := getEnv("SEAGULL_PROC_TCP4_PATH", "/proc/net/tcp")
	procTCP6Path := getEnv("SEAGULL_PROC_TCP6_PATH", "/proc/net/tcp6")
	procExecEvery := parseDuration(getEnv("SEAGULL_PROC_EXEC_EVERY", "2s"), 2*time.Second)
	procExecMaxBatch := parseInt(getEnv("SEAGULL_PROC_EXEC_MAX_BATCH", "200"), 200)
	procExecHashEnabled := parseBool(getEnv("SEAGULL_PROC_EXEC_HASH_ENABLED", "true"), true)
	procExecHashMaxBytes := int64(parseInt(getEnv("SEAGULL_PROC_EXEC_HASH_MAX_BYTES", "26214400"), 26214400))
	procExecEmitInitial := parseBool(getEnv("SEAGULL_PROC_EXEC_EMIT_INITIAL", "false"), false)
	procExecIgnoreExeNames := parseStringSet(getEnv("SEAGULL_PROC_EXEC_IGNORE_EXE", "sleep"))
	procExecIgnoreCmdContains := splitCSVLower(getEnv("SEAGULL_PROC_EXEC_IGNORE_CMD_CONTAINS", "systemd --user"))

	fimEvery := parseDuration(getEnv("SEAGULL_FIM_EVERY", "30s"), 30*time.Second)
	fimMaxBatch := parseInt(getEnv("SEAGULL_FIM_MAX_BATCH", "200"), 200)
	fimMaxDepth := parseInt(getEnv("SEAGULL_FIM_MAX_DEPTH", "4"), 4)
	fimHashEnabled := parseBool(getEnv("SEAGULL_FIM_HASH_ENABLED", "true"), true)
	fimHashMaxBytes := int64(parseInt(getEnv("SEAGULL_FIM_HASH_MAX_BYTES", "2097152"), 2097152))
	fimEmitInitial := parseBool(getEnv("SEAGULL_FIM_EMIT_INITIAL", "false"), false)
	fimWatchPaths := splitCSV(getEnv("SEAGULL_FIM_PATHS", ""))
	fimExclude := splitCSV(getEnv("SEAGULL_FIM_EXCLUDE_PATHS", ""))

	skipLoopback := parseBool(getEnv("SEAGULL_SKIP_LOOPBACK", "true"), true)
	skipLinkLocal := parseBool(getEnv("SEAGULL_SKIP_LINK_LOCAL", "true"), true)
	skipPrivate := parseBool(getEnv("SEAGULL_SKIP_PRIVATE_TO_PRIVATE", "false"), false)

	procDropOutbound := parseBool(getEnv("SEAGULL_PROC_DROP_LIKELY_OUTBOUND", "true"), true)
	ephemeralMin := parseInt(getEnv("SEAGULL_EPHEMERAL_PORT_MIN", "49152"), 49152)

	dedupTTL := parseDuration(getEnv("SEAGULL_DEDUP_TTL", "30s"), 30*time.Second)
	establishedTTL := parseDuration(getEnv("SEAGULL_ESTABLISHED_TTL", "10m"), 10*time.Minute)

	denyCIDRs := parseCIDRs(getEnv("SEAGULL_DENY_CIDRS", ""))
	denyDstPorts := parseIntSet(getEnv("SEAGULL_DENY_DST_PORTS", ""))
	denySrcPorts := parseIntSet(getEnv("SEAGULL_DENY_SRC_PORTS", ""))

	lateralMode := strings.ToLower(strings.TrimSpace(getEnv("SEAGULL_LATERAL_MODE", "pcap")))
	lateralIface := getEnv("SEAGULL_LATERAL_PCAP_IFACE", getEnv("SEAGULL_PCAP_IFACE", "any"))
	lateralPorts := parseIntSet(getEnv("SEAGULL_LATERAL_PORTS", "22,445,3389,5985,5986,135,139"))
	lateralIncludeEstablished := parseBool(getEnv("SEAGULL_LATERAL_INCLUDE_ESTABLISHED", "true"), true)
	lateralDedup := parseDuration(getEnv("SEAGULL_LATERAL_DEDUP_TTL", "5s"), 5*time.Second)
	lateralMaxBatch := parseInt(getEnv("SEAGULL_LATERAL_MAX_BATCH", "500"), 500)

	scanIface := getEnv("SEAGULL_PCAP_IFACE", "any")
	scanDedup := parseDuration(getEnv("SEAGULL_SCAN_DEDUP_TTL", "2s"), 2*time.Second)
	scanMaxBatch := parseInt(getEnv("SEAGULL_SCAN_MAX_BATCH", "5000"), 5000)
	scanMode := getEnv("SEAGULL_SCAN_MODE", "summary")
	l7Iface := getEnvAlias("SEAGULL_L7_PCAP_IFACE", scanIface, "SEAGULL_L7_IFACE")
	l7Dedup := parseDuration(getEnvAlias("SEAGULL_L7_DEDUP_TTL", defaultL7DedupTTL.String()), defaultL7DedupTTL)
	l7MaxBatch := parseInt(getEnvAlias("SEAGULL_L7_MAX_BATCH", strconv.Itoa(defaultL7MaxBatch), "SEAGULL_L7_BATCH_SIZE"), defaultL7MaxBatch)
	l7MaxPayload := parseInt(getEnvAlias("SEAGULL_L7_MAX_PAYLOAD_BYTES", strconv.Itoa(defaultL7MaxPayloadBytes), "SEAGULL_L7_PAYLOAD_BYTES"), defaultL7MaxPayloadBytes)
	l7IncludePayload := parseBool(getEnvAlias("SEAGULL_L7_INCLUDE_PAYLOAD", "false"), false)

	ddosIface := getEnv("SEAGULL_DDOS_PCAP_IFACE", scanIface)
	ddosWindow := parseDuration(getEnv("SEAGULL_DDOS_WINDOW", "1s"), 1*time.Second)
	ddosEvalEvery := parseDuration(getEnv("SEAGULL_DDOS_EVAL_EVERY", "1s"), 1*time.Second)
	ddosCooldown := parseDuration(getEnv("SEAGULL_DDOS_COOLDOWN", "30s"), 30*time.Second)
	ddosSustain := parseInt(getEnv("SEAGULL_DDOS_SUSTAIN_WINDOWS", "3"), 3)
	ddosWarmup := parseInt(getEnv("SEAGULL_DDOS_BASELINE_WARMUP_WINDOWS", "20"), 20)
	ddosAlpha := parseFloat(getEnv("SEAGULL_DDOS_BASELINE_ALPHA", "0.08"), 0.08)
	ddosFactor := parseFloat(getEnv("SEAGULL_DDOS_BASELINE_FACTOR", "4.0"), 4.0)
	ddosMinPPS := parseFloat(getEnv("SEAGULL_DDOS_MIN_PPS", "3000"), 3000)
	ddosMinBPS := parseFloat(getEnv("SEAGULL_DDOS_MIN_BPS", "500000"), 500000)
	ddosMinPackets := parseInt(getEnv("SEAGULL_DDOS_MIN_PACKETS", "0"), 0)
	ddosMinRequests := parseInt(getEnv("SEAGULL_DDOS_MIN_REQUESTS", "0"), 0)
	ddosMinConf := parseInt(getEnv("SEAGULL_DDOS_MIN_CONFIDENCE", "70"), 70)
	ddosMinSynRatio := parseFloat(getEnv("SEAGULL_DDOS_MIN_SYN_RATIO", "0.70"), 0.70)
	ddosMinSrcIPs := parseInt(getEnv("SEAGULL_DDOS_MIN_SRC_IPS", "30"), 30)
	ddosMinSrcEntropy := parseFloat(getEnv("SEAGULL_DDOS_MIN_SRC_ENTROPY_NORM", "0.70"), 0.70)

	ddosEnableL7 := parseBool(getEnv("SEAGULL_DDOS_ENABLE_L7", "true"), true)
	ddosMinHTTPRPS := parseFloat(getEnv("SEAGULL_DDOS_MIN_HTTP_RPS", "200"), 200)
	ddosMinTLS := parseFloat(getEnv("SEAGULL_DDOS_MIN_TLS_HS_RPS", "200"), 200)
	ddosMinL7Ratio := parseFloat(getEnv("SEAGULL_DDOS_MIN_L7_RATIO", "0.15"), 0.15)

	ddosEnableEntropy := parseBool(getEnv("SEAGULL_DDOS_ENABLE_ENTROPY", "true"), true)
	ddosMinSrcEntropySig := parseFloat(getEnv("SEAGULL_DDOS_MIN_SRC_ENTROPY_NORM_SIGNAL", "0.75"), 0.75)
	ddosMinPortEntropy := parseFloat(getEnv("SEAGULL_DDOS_MIN_PORT_ENTROPY_NORM", "0.35"), 0.35)
	ddosPortTopN := parseInt(getEnv("SEAGULL_DDOS_PORT_ENTROPY_TOPN", "16"), 16)

	ddosCardMode := strings.ToLower(strings.TrimSpace(getEnv("SEAGULL_DDOS_CARDINALITY_MODE", "hll")))
	ddosHLLP := parseInt(getEnv("SEAGULL_DDOS_HLL_PRECISION", "14"), 14)
	ddosBloomBits := parseInt(getEnv("SEAGULL_DDOS_BLOOM_BITS", "1048576"), 1048576)
	ddosMaxUnique := parseInt(getEnv("SEAGULL_DDOS_MAX_UNIQUE_SRC", "500000"), 500000)
	ddosTopSrc := parseInt(getEnv("SEAGULL_DDOS_TOP_SRC", "20"), 20)
	ddosMaxBatch := parseInt(getEnv("SEAGULL_DDOS_MAX_BATCH", "200"), 200)
	ddosBpHighWM := parseInt(getEnv("SEAGULL_DDOS_BACKPRESSURE_HIGH_WATERMARK", "160"), 160)
	ddosBpSampleEvery := parseInt(getEnv("SEAGULL_DDOS_BACKPRESSURE_SAMPLE_EVERY", "4"), 4)

	levelStr := getEnv("SEAGULL_LOG_LEVEL", "info")
	logLevel := parseLogLevel(levelStr)

	logSummaryEvery := parseDuration(getEnv("SEAGULL_LOG_SUMMARY_EVERY", "10s"), 10*time.Second)
	logHeartbeatEvery := parseDuration(getEnv("SEAGULL_LOG_HEARTBEAT_EVERY", "60s"), 60*time.Second)
	logMinEvents := parseInt(getEnv("SEAGULL_LOG_MIN_EVENTS", "50"), 50)

	cfg := Config{
		AgentID:        agentID,
		APIURL:         apiURL,
		Sources:        sources,
		Interval:       interval,
		HTTPTimeout:    httpTimeout,
		SenderMaxBatch: senderMaxBatch,

		AgentConfigFile:               agentConfigFile,
		AgentIdentityStateFile:        agentIdentityStateFile,
		BootstrapToken:                bootstrapToken,
		BootstrapTokenFile:            bootstrapTokenFile,
		AgentCredential:               agentCredential,
		AgentCredentialExpiresAt:      agentCredentialExpiresAt,
		CredentialFile:                credentialFile,
		RenewalToken:                  renewalToken,
		RenewalTokenExpiresAt:         renewalTokenExpiresAt,
		PreviousRenewalToken:          previousRenewalToken,
		PreviousRenewalTokenExpiresAt: previousRenewalTokenExpiresAt,

		TLSCAFile:     tlsCAFile,
		TLSCertFile:   tlsCertFile,
		TLSKeyFile:    tlsKeyFile,
		TLSServerName: tlsServerName,

		ControlHeartbeatEvery:     controlHeartbeatEvery,
		ControlHeartbeatJitter:    controlHeartbeatJitter,
		ControlConfigEvery:        controlConfigEvery,
		ControlConfigJitter:       controlConfigJitter,
		ControlResponsePollEvery:  controlResponsePollEvery,
		ControlResponsePollJitter: controlResponsePollJitter,
		ControlEnrollTimeout:      controlEnrollTimeout,
		ForceEnrollOnStart:        forceEnrollOnStart,
		CredentialRotateEvery:     credentialRotateEvery,
		CredentialRotateBefore:    credentialRotateBefore,
		ResponseActionStageMax:    responseActionStageMax,

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

		ProcExecEvery:             procExecEvery,
		ProcExecMaxBatch:          procExecMaxBatch,
		ProcExecHashEnabled:       procExecHashEnabled,
		ProcExecHashMaxBytes:      procExecHashMaxBytes,
		ProcExecEmitInitial:       procExecEmitInitial,
		ProcExecIgnoreExeNames:    procExecIgnoreExeNames,
		ProcExecIgnoreCmdContains: procExecIgnoreCmdContains,

		FIMEvery:        fimEvery,
		FIMMaxBatch:     fimMaxBatch,
		FIMMaxDepth:     fimMaxDepth,
		FIMHashEnabled:  fimHashEnabled,
		FIMHashMaxBytes: fimHashMaxBytes,
		FIMEmitInitial:  fimEmitInitial,
		FIMWatchPaths:   fimWatchPaths,
		FIMExcludePaths: fimExclude,

		L7Iface:           l7Iface,
		L7DedupTTL:        l7Dedup,
		L7MaxBatch:        l7MaxBatch,
		L7MaxPayloadBytes: l7MaxPayload,
		L7IncludePayload:  l7IncludePayload,

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
	sanitizeL7Config(&cfg)
	return cfg
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
	if strings.HasPrefix(k, "SEAGULL_") {
		legacyKey := "NETWATCH_" + strings.TrimPrefix(k, "SEAGULL_")
		if v, ok := os.LookupEnv(legacyKey); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return def
}

func getEnvAlias(k, def string, aliases ...string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if strings.HasPrefix(k, "SEAGULL_") {
		legacyKey := "NETWATCH_" + strings.TrimPrefix(k, "SEAGULL_")
		if v, ok := os.LookupEnv(legacyKey); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	for _, alias := range aliases {
		if v := getEnv(alias, ""); strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
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

	if strings.HasPrefix(k, "SEAGULL_") {
		legacyKey := "NETWATCH_" + strings.TrimPrefix(k, "SEAGULL_")
		if v, ok := os.LookupEnv(legacyKey); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		if filePath, ok := os.LookupEnv(legacyKey + "_FILE"); ok && strings.TrimSpace(filePath) != "" {
			return readTextFile(filePath)
		}
	}

	return def
}

func loadBootstrapTokenValue(hasExistingIdentity bool) (string, string, error) {
	token := strings.TrimSpace(getSecretEnv("SEAGULL_AGENT_BOOTSTRAP_TOKEN", ""))
	tokenFile := strings.TrimSpace(getEnv("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE", ""))
	if tokenFile == "" {
		return token, "", nil
	}

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if hasExistingIdentity && os.IsNotExist(err) {
			return token, tokenFile, nil
		}
		return "", tokenFile, fmt.Errorf("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE=%q: %w", tokenFile, err)
	}
	fileToken := strings.TrimSpace(string(data))
	if fileToken == "" {
		if hasExistingIdentity {
			return token, tokenFile, nil
		}
		return "", tokenFile, fmt.Errorf("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE=%q: file is empty", tokenFile)
	}
	return fileToken, tokenFile, nil
}

func consumeBootstrapTokenFile(path string, agentID string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if errors.Is(err, syscall.EROFS) || os.IsPermission(err) {
			logJSON(LevelInfo, "agent_bootstrap_token_file_preserved", map[string]interface{}{
				"agent_id": agentID,
				"path":     path,
				"reason":   "externally_managed_or_read_only",
			})
			return
		}
		logJSON(LevelWarn, "agent_bootstrap_token_file_delete_failed", map[string]interface{}{
			"agent_id": agentID,
			"path":     path,
			"error":    err.Error(),
		})
		return
	}
	logJSON(LevelInfo, "agent_bootstrap_token_file_deleted", map[string]interface{}{
		"agent_id": agentID,
		"path":     path,
	})
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

func clampInt(v, minValue, maxValue int) int {
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

func sanitizeL7Config(cfg *Config) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(cfg.L7Iface) == "" {
		cfg.L7Iface = "any"
	}
	if cfg.L7DedupTTL <= 0 {
		cfg.L7DedupTTL = defaultL7DedupTTL
	}
	cfg.L7MaxBatch = clampInt(cfg.L7MaxBatch, 1, maxL7MaxBatch)
	cfg.L7MaxPayloadBytes = clampInt(cfg.L7MaxPayloadBytes, 1, maxL7MaxPayloadBytes)
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

func parseStringSet(csv string) map[string]bool {
	parts := strings.Split(csv, ",")
	out := make(map[string]bool, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out[p] = true
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
