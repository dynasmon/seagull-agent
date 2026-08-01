package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/controlplane"
	"github.com/dynasmon/seagull-agent/internal/enrollment"
	"github.com/dynasmon/seagull-agent/internal/responseactions"
	"github.com/dynasmon/seagull-agent/internal/sender"
	"github.com/dynasmon/seagull-agent/internal/sources"
	"github.com/dynasmon/seagull-agent/internal/spool"
	"github.com/dynasmon/seagull-agent/internal/transport"
	"github.com/dynasmon/seagull-agent/protocol"
)

type SummaryState struct {
	StartedAt time.Time

	Cycles int

	EventsSentTotal      int
	EventsAttemptedTotal int
	EventsDurableTotal   int

	SSHAuthEventsTotal int

	ScanProbesTotal     int
	ScanProbesEffective int

	MaxSentCycle  int
	MaxScanCycle  int
	MaxPortsCycle int

	SendAttemptsTotal                   int
	SendErrorsTotal                     int
	ResponseActionPollErrorsTotal       int
	ResponseActionsStagedTotal          int
	ResponseActionsExecutedTotal        int
	ResponseActionResultsDeliveredTotal int
	ResponseActionReportErrorsTotal     int

	CertRenewalsTotal    int
	CertRenewErrorsTotal int
	CertLastRenewError   string

	SpoolDeliveredTotal int
	SpoolLastError      string

	LastHTTPStatus int
	LastError      string

	LastSummaryAt            time.Time
	LastSummaryEventsSent    int
	LastSummaryScanTotal     int
	LastSummaryScanEffective int
	LastHeartbeatAt          time.Time
}

type Service struct {
	cfg             agentcfg.Config
	httpClient      *http.Client
	cp              *controlplane.Client
	sender          *sender.Sender
	runtimeConfig   *sources.RuntimeConfig
	enrollment      *enrollment.Manager
	sources         *sources.Manager
	responseStage   *responseactions.Stage
	responseJournal *responseactions.Journal
	firewallTool    string
	state           SummaryState
	stateMu         sync.RWMutex
	stop            context.CancelFunc
	fatal           chan error
	failOnce        sync.Once
}

func New(ctx context.Context, cfg agentcfg.Config, stop context.CancelFunc, httpClient *http.Client) (*Service, error) {
	now := time.Now().UTC()

	runtimeConfig := sources.NewRuntimeConfig(
		cfg.AgentConfigFile,
		sources.SyscollectorConfig{
			Enabled:        true,
			Every:          cfg.SyscollectEvery,
			CmdTimeout:     cfg.SyscollectCmdTimeout,
			MaxOutputBytes: cfg.SyscollectMaxOutputBytes,
			MaxPackages:    cfg.SyscollectMaxPackages,
			HostRoot:       cfg.SyscollectHostRoot,

			NetCtxMaxIfaces:    cfg.NetCtxMaxInterfaces,
			NetCtxMaxNeighbors: cfg.NetCtxMaxNeighbors,
			NetCtxMaxRoutes:    cfg.NetCtxMaxRoutes,
			NetCtxMaxResolvers: cfg.NetCtxMaxResolvers,
		},
		sources.VulnScannerConfig{
			Enabled:         agentcfg.Contains(cfg.Sources, "vuln"),
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
		sources.TopologyDiscoveryConfig{
			Enabled:     cfg.TopologyActiveDiscoveryEnabled,
			CIDRs:       cfg.TopologyActiveDiscoveryCIDRs,
			AllowPublic: cfg.TopologyActiveDiscoveryAllowPublic,
			Every:       cfg.TopologyActiveDiscoveryInterval,
			MaxHosts:    cfg.TopologyActiveDiscoveryMaxHosts,
			RateLimit:   cfg.TopologyActiveDiscoveryRateLimit,
			Timeout:     cfg.TopologyActiveDiscoveryTimeout,
		},
	)
	if err := runtimeConfig.LoadError(); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "persisted_runtime_config_rejected", map[string]interface{}{
			"agent_id": cfg.AgentID,
			"path":     cfg.AgentConfigFile,
			"error":    err.Error(),
		})
	}

	enrollMgr := enrollment.NewManager(cfg, runtimeConfig)
	eventSender := sender.New(cfg.APIURL, cfg.HTTPTimeout, cfg.SenderMaxBatch, cfg.AgentID, enrollMgr.CurrentCredential, httpClient)
	diskSpool, err := spool.New(spool.Options{
		Dir:      cfg.SpoolDir,
		MaxBytes: cfg.SpoolMaxBytes,
		MaxAge:   cfg.SpoolMaxAge,
		MaxItems: cfg.SpoolMaxItems,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize durable spool: %w", err)
	}
	if diskSpool != nil {
		eventSender.SetSpool(diskSpool)
	}
	cp := controlplane.New(cfg.APIURL, cfg.HTTPTimeout, cfg.AgentID, enrollMgr.CurrentCredential, httpClient)
	cp.SetEnrollBaseURL(cfg.EnrollURL)
	enrollMgr.SetClient(cp)

	agentcfg.ApplyAgentRuntimeOverrides(&cfg, runtimeConfig.Raw())

	responseStage := responseactions.NewStage(cfg.ResponseActionStageMax)
	var responseJournal *responseactions.Journal
	if protocol.ProfileAllowsResponseActions(cfg.Profile) {
		responseJournal, err = responseactions.NewJournal(
			cfg.ResponseActionJournalDir,
			cfg.ResponseActionJournalMax,
			cfg.ResponseActionJournalSize,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize response action journal: %w", err)
		}
		ids, err := responseJournal.IDs()
		if err != nil {
			return nil, fmt.Errorf("load response action journal: %w", err)
		}
		for _, actionID := range ids {
			responseStage.MarkHandled(actionID)
		}
	}

	return &Service{
		cfg:             cfg,
		httpClient:      httpClient,
		cp:              cp,
		sender:          eventSender,
		runtimeConfig:   runtimeConfig,
		enrollment:      enrollMgr,
		responseStage:   responseStage,
		responseJournal: responseJournal,
		firewallTool:    responseactions.DetectFirewallTool(),
		state: SummaryState{
			StartedAt:                now,
			LastSummaryAt:            now,
			LastHeartbeatAt:          now,
			LastSummaryEventsSent:    0,
			LastSummaryScanTotal:     0,
			LastSummaryScanEffective: 0,
		},
		stop:  stop,
		fatal: make(chan error, 1),
	}, nil
}

func (s *Service) Run(rootCtx context.Context) error {
	if s.enrollment.HasUsableIdentity() {
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
		if err := transport.WaitForHealth(ctx, s.cfg.APIURL, s.httpClient); err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "backend_not_ready", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    err.Error(),
			})
		}
		cancel()
	}

	if err := s.enrollment.EnsureInitialIdentity(rootCtx); err != nil {
		return fmt.Errorf("establish agent identity: %w", err)
	}
	if s.httpClient != nil {
		s.httpClient.CloseIdleConnections()
	}
	if err := s.verifyCompatibility(rootCtx); err != nil {
		return err
	}
	if err := s.initializeSources(rootCtx); err != nil {
		return err
	}
	s.startControlPlane(rootCtx)
	s.sources.StartSyscollector(rootCtx)
	s.sources.StartVulnScanner(rootCtx)
	s.sources.StartTopologyActiveDiscovery(rootCtx)
	return s.loop(rootCtx)
}

func (s *Service) initializeSources(rootCtx context.Context) error {
	ctx, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
	remoteConfig, err := s.cp.GetConfig(ctx)
	cancel()
	if err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "startup_config_unavailable", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"error":    err.Error(),
		})
	} else if len(remoteConfig) > 0 {
		changed, applyErr := s.runtimeConfig.Apply(remoteConfig)
		if applyErr != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "startup_config_rejected", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    applyErr.Error(),
				"revision": s.runtimeConfig.Revision(),
			})
		} else if changed {
			agentcfg.LogJSON(agentcfg.LevelInfo, "startup_config_applied", map[string]interface{}{
				"agent_id":    s.cfg.AgentID,
				"config_hash": s.runtimeConfig.Hash(),
				"revision":    s.runtimeConfig.Revision(),
			})
		}
	}

	agentcfg.ApplyAgentRuntimeOverrides(&s.cfg, s.runtimeConfig.Raw())
	manager, err := sources.NewManager(s.cfg, rootCtx, s.stop, s.sender, s.runtimeConfig)
	if err != nil {
		return fmt.Errorf("initialize collectors: %w", err)
	}
	s.sources = manager
	return nil
}

func (s *Service) verifyCompatibility(rootCtx context.Context) error {
	send := func() (protocol.Negotiation, error) {
		ctx, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
		defer cancel()
		return s.cp.Heartbeat(ctx, s.buildHeartbeatRequest())
	}

	before := strings.TrimSpace(s.enrollment.CurrentCredential())
	negotiated, err := send()
	if err != nil {
		var incompatible *protocol.Incompatibility
		if errors.As(err, &incompatible) {
			return incompatible
		}
		s.enrollment.MaybeRecoverIdentity(rootCtx, "startup_compatibility", err.Error(), 0)
		after := strings.TrimSpace(s.enrollment.CurrentCredential())
		if after != "" && after != before {
			negotiated, err = send()
			if err == nil {
				s.logCompatibility(negotiated)
				return nil
			}
			if errors.As(err, &incompatible) {
				return incompatible
			}
		}
		agentcfg.LogJSON(agentcfg.LevelWarn, "protocol_compatibility_unverified", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"error":    err.Error(),
		})
		return nil
	}
	s.logCompatibility(negotiated)
	return nil
}

func (s *Service) logCompatibility(negotiated protocol.Negotiation) {
	agentcfg.LogJSON(agentcfg.LevelInfo, "protocol_compatibility_verified", map[string]interface{}{
		"agent_id":             s.cfg.AgentID,
		"protocol_version":     negotiated.ProtocolVersion,
		"event_schema_version": negotiated.EventSchemaVersion,
		"degraded":             negotiated.Degraded,
		"notes":                negotiated.Notes,
	})
}

func (s *Service) fail(err error) {
	if err == nil {
		return
	}
	s.failOnce.Do(func() {
		s.fatal <- err
		if s.stop != nil {
			s.stop()
		}
	})
}

func (s *Service) stateSnapshot() SummaryState {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

func (s *Service) updateState(update func(*SummaryState)) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	update(&s.state)
}
