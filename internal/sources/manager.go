package sources

import (
	"context"
	"strings"
	"sync"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/ddos"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/fim"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/l7"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/lateral"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/proc"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/procexec"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/scan"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/ssh"
	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/sender"
)

type Manager struct {
	cfg agentcfg.Config

	sender  *sender.Sender
	runtime *RuntimeConfig

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

	topoMu     sync.RWMutex
	topoStatus TopologyDiscoveryStatus
}

func NewManager(cfg agentcfg.Config, rootCtx context.Context, stop context.CancelFunc, sender *sender.Sender, runtimeCfg *RuntimeConfig) (*Manager, error) {
	m := &Manager{
		cfg:     cfg,
		sender:  sender,
		runtime: runtimeCfg,
	}

	if agentcfg.Contains(cfg.Sources, "proc") {
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
		m.procCapturer = proc.New(cfg.AgentID, cfg.ProcTCP4Path, cfg.ProcTCP6Path, opts)
	}

	if agentcfg.Contains(cfg.Sources, "proc_exec") {
		m.procExecCapturer = procexec.New(cfg.AgentID, procexec.Options{
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

	if agentcfg.Contains(cfg.Sources, "fim") {
		m.fimCapturer = fim.New(cfg.AgentID, fim.Options{
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

	if agentcfg.Contains(cfg.Sources, "authlog") {
		resolvedPath, err := ssh.ResolveAuthLogPath(cfg.AuthLogPath)
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "authlog_source_disabled", map[string]interface{}{
				"agent_id": cfg.AgentID,
				"path":     cfg.AuthLogPath,
				"error":    err.Error(),
			})
		} else {
			if resolvedPath != cfg.AuthLogPath {
				agentcfg.LogJSON(agentcfg.LevelInfo, "authlog_path_resolved", map[string]interface{}{
					"agent_id":   cfg.AgentID,
					"configured": cfg.AuthLogPath,
					"resolved":   resolvedPath,
				})
			}
			m.authCapturer = ssh.NewAuthLogCapturer(cfg.AgentID, ssh.AuthLogOptions{
				Path:            resolvedPath,
				MaxBatchSize:    200,
				DedupTTL:        cfg.AuthDedupTTL,
				IncludeAccepted: cfg.AuthIncludeAccepted,
			})
		}
	}

	if agentcfg.Contains(cfg.Sources, "lateral") {
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
			m.lateralProc = lateral.NewProcLateralCapturer(
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
			m.lateralPcap = lc

			go func() {
				if err := m.lateralPcap.Start(rootCtx); err != nil {
					agentcfg.LogJSON(agentcfg.LevelError, "lateral_capture_stopped", map[string]interface{}{
						"agent_id": cfg.AgentID,
						"error":    err.Error(),
					})
					stop()
				}
			}()
		}
	}

	if agentcfg.Contains(cfg.Sources, "scan") {
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
		m.scanCapturer = sc

		go func() {
			if err := m.scanCapturer.Start(rootCtx); err != nil {
				agentcfg.LogJSON(agentcfg.LevelError, "scan_capture_stopped", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
				stop()
			}
		}()
	}

	if agentcfg.Contains(cfg.Sources, "l7") {
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
			agentcfg.LogJSON(agentcfg.LevelWarn, "l7_capture_disabled", map[string]interface{}{
				"agent_id":              cfg.AgentID,
				"interface":             cfg.L7Iface,
				"include_payload":       cfg.L7IncludePayload,
				"max_batch":             cfg.L7MaxBatch,
				"max_payload_bytes":     cfg.L7MaxPayloadBytes,
				"error":                 err.Error(),
				"continuing_without_l7": true,
			})
		} else {
			m.l7Capturer = l7c
			go func() {
				if err := m.l7Capturer.Start(rootCtx); err != nil {
					agentcfg.LogJSON(agentcfg.LevelWarn, "l7_capture_stopped", map[string]interface{}{
						"agent_id":              cfg.AgentID,
						"interface":             cfg.L7Iface,
						"error":                 err.Error(),
						"continuing_without_l7": true,
					})
				}
			}()
		}
	}

	if agentcfg.Contains(cfg.Sources, "ddos") {
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
		m.ddosCapturer = dc

		go func() {
			if err := m.ddosCapturer.Start(rootCtx); err != nil {
				agentcfg.LogJSON(agentcfg.LevelError, "ddos_capture_stopped", map[string]interface{}{
					"agent_id": cfg.AgentID,
					"error":    err.Error(),
				})
				stop()
			}
		}()
	}

	return m, nil
}

func (m *Manager) RuntimeConfig() *RuntimeConfig {
	return m.runtime
}

func (m *Manager) SyscollectorStatus() SyscollectorStatus {
	m.sysMu.RLock()
	defer m.sysMu.RUnlock()
	return m.sysStatus
}

func (m *Manager) VulnScannerStatus() VulnScannerStatus {
	m.vulnMu.RLock()
	defer m.vulnMu.RUnlock()
	return m.vulnStatus
}

func (m *Manager) TopologyDiscoveryStatus() TopologyDiscoveryStatus {
	m.topoMu.RLock()
	defer m.topoMu.RUnlock()
	return m.topoStatus.Clone()
}
