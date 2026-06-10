package runtime

import (
	"context"
	"net/http"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/enrollment"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/responseactions"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/sender"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/sources"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/transport"
)

const buildVersion = "0.1.0"

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

	CertRenewalsTotal    int
	CertRenewErrorsTotal int
	CertLastRenewError   string

	LastHTTPStatus int
	LastError      string

	LastSummaryAt            time.Time
	LastSummaryEventsSent    int
	LastSummaryScanTotal     int
	LastSummaryScanEffective int
	LastHeartbeatAt          time.Time
}

type Service struct {
	cfg           agentcfg.Config
	httpClient    *http.Client
	cp            *controlplane.Client
	sender        *sender.Sender
	runtimeConfig *sources.RuntimeConfig
	enrollment    *enrollment.Manager
	sources       *sources.Manager
	responseStage *responseactions.Stage
	state         SummaryState
	stop          context.CancelFunc
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

	enrollMgr := enrollment.NewManager(cfg, runtimeConfig)
	eventSender := sender.New(cfg.APIURL, cfg.HTTPTimeout, cfg.SenderMaxBatch, cfg.AgentID, enrollMgr.CurrentCredential, httpClient)
	cp := controlplane.New(cfg.APIURL, cfg.HTTPTimeout, cfg.AgentID, enrollMgr.CurrentCredential, httpClient)
	enrollMgr.SetClient(cp)

	cfgCtx, cancel := context.WithTimeout(ctx, cfg.ControlEnrollTimeout)
	if remoteCfg, err := cp.GetConfig(cfgCtx); err == nil && len(remoteCfg) > 0 {
		_, _ = runtimeConfig.Apply(remoteCfg)
	}
	cancel()

	agentcfg.ApplyAgentRuntimeOverrides(&cfg, runtimeConfig.Raw())

	sourceMgr, err := sources.NewManager(cfg, ctx, stop, eventSender, runtimeConfig)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:           cfg,
		httpClient:    httpClient,
		cp:            cp,
		sender:        eventSender,
		runtimeConfig: runtimeConfig,
		enrollment:    enrollMgr,
		sources:       sourceMgr,
		responseStage: responseactions.NewStage(cfg.ResponseActionStageMax),
		state: SummaryState{
			StartedAt:                now,
			LastSummaryAt:            now,
			LastHeartbeatAt:          now,
			LastSummaryEventsSent:    0,
			LastSummaryScanTotal:     0,
			LastSummaryScanEffective: 0,
		},
		stop: stop,
	}, nil
}

func (s *Service) Run(rootCtx context.Context) error {
	ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
	if err := transport.WaitForHealth(ctx, s.cfg.APIURL, s.httpClient); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "backend_not_ready", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"error":    err.Error(),
		})
	}
	cancel()

	s.enrollment.EnsureInitialIdentity(rootCtx)
	s.startControlPlane(rootCtx)
	s.sources.StartSyscollector(rootCtx)
	s.sources.StartVulnScanner(rootCtx)
	s.sources.StartTopologyActiveDiscovery(rootCtx)
	s.loop(rootCtx)
	return nil
}
