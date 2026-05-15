package sources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/syscollector"
	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/netcontext"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/topologydiscovery"
)

type TopologyDiscoveryStatus struct {
	LastRunAt          time.Time
	LastSentAt         time.Time
	LastError          string
	LastWarnings       []string
	LastAllowedCIDRs   []string
	LastDiscoveredIPs  []string
	LastObservedIPs    []string
	LastTargetCount    int
	LastAttemptedHosts int
	LastTrigger        string
}

func (s TopologyDiscoveryStatus) Clone() TopologyDiscoveryStatus {
	s.LastWarnings = append([]string(nil), s.LastWarnings...)
	s.LastAllowedCIDRs = append([]string(nil), s.LastAllowedCIDRs...)
	s.LastDiscoveredIPs = append([]string(nil), s.LastDiscoveredIPs...)
	s.LastObservedIPs = append([]string(nil), s.LastObservedIPs...)
	return s
}

func (m *Manager) StartTopologyActiveDiscovery(ctx context.Context) {
	if m == nil || m.runtime == nil || m.sender == nil {
		return
	}

	go func() {
		for {
			cfg, cfgErr := m.runtime.TopologyDiscovery()
			m.topoMu.RLock()
			lastRun := m.topoStatus.LastRunAt
			m.topoMu.RUnlock()

			nextIn := 30 * time.Second
			if cfgErr != nil {
				m.updateTopologyDiscoveryStatus(func(status *TopologyDiscoveryStatus) {
					status.LastError = cfgErr.Error()
				})
			} else if cfg.Enabled {
				if lastRun.IsZero() {
					nextIn = cfg.Every
				} else {
					nextIn = cfg.Every - time.Since(lastRun)
					if nextIn < 0 {
						nextIn = 0
					}
				}
			}

			t := time.NewTimer(nextIn)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-m.runtime.Changed():
				t.Stop()
				continue
			case <-t.C:
			}

			if cfgErr != nil || !cfg.Enabled {
				continue
			}
			ctxRun, cancel := context.WithTimeout(ctx, cfg.Timeout+10*time.Second)
			_, _ = m.runTopologyDiscoveryOnce(ctxRun, cfg, "scheduled")
			cancel()
		}
	}()
}

func (m *Manager) RunTopologyDiscoveryNow(ctx context.Context) (map[string]interface{}, error) {
	if m == nil || m.runtime == nil {
		return nil, fmt.Errorf("topology active discovery is not available")
	}
	cfg, err := m.runtime.TopologyDiscovery()
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("topology active discovery is disabled")
	}
	ctxRun, cancel := context.WithTimeout(ctx, cfg.Timeout+10*time.Second)
	defer cancel()
	return m.runTopologyDiscoveryOnce(ctxRun, cfg, "manual")
}

func (m *Manager) runTopologyDiscoveryOnce(
	ctx context.Context,
	cfg TopologyDiscoveryConfig,
	trigger string,
) (map[string]interface{}, error) {
	startedAt := time.Now().UTC()
	beforeNC, err := netcontext.Collect(netcontext.Caps{
		MaxInterfaces: m.cfg.NetCtxMaxInterfaces,
		MaxNeighbors:  m.cfg.NetCtxMaxNeighbors,
		MaxRoutes:     m.cfg.NetCtxMaxRoutes,
		MaxResolvers:  m.cfg.NetCtxMaxResolvers,
	})
	if err != nil {
		m.recordTopologyDiscoveryFailure(startedAt, trigger, err)
		return nil, err
	}

	plan, err := topologydiscovery.BuildPlan(topologydiscovery.PlanOptions{
		ConfiguredCIDRs: cfg.CIDRs,
		LocalCIDRs:      beforeNC.LocalCIDRs,
		LocalIPs:        beforeNC.LocalIPs,
		DenyCIDRs:       m.cfg.DenyCIDRs,
		MaxHosts:        cfg.MaxHosts,
		AllowPublic:     cfg.AllowPublic,
	})
	if err != nil {
		m.recordTopologyDiscoveryFailure(startedAt, trigger, err)
		return nil, err
	}

	warnings := append([]string(nil), plan.Warnings...)
	probe, probeTool := topologydiscovery.NewPingProbe(cfg.Timeout)
	probeStats := topologydiscovery.ProbeStats{}
	if probe == nil {
		warnings = append(warnings, "ping command unavailable; passive neighbor observation only")
	} else {
		ctxProbe, cancel := context.WithTimeout(ctx, cfg.Timeout)
		probeStats = topologydiscovery.RunProbes(ctxProbe, plan.Targets, cfg.RateLimit, topologydiscovery.ProbeDeps{
			Probe: probe,
		})
		cancel()
	}

	afterNC, afterErr := netcontext.Collect(netcontext.Caps{
		MaxInterfaces: m.cfg.NetCtxMaxInterfaces,
		MaxNeighbors:  m.cfg.NetCtxMaxNeighbors,
		MaxRoutes:     m.cfg.NetCtxMaxRoutes,
		MaxResolvers:  m.cfg.NetCtxMaxResolvers,
	})
	if afterErr != nil {
		m.recordTopologyDiscoveryFailure(startedAt, trigger, afterErr)
		return nil, afterErr
	}

	beforeNeighbors := toDiscoveryNeighbors(beforeNC.Neighbors)
	afterNeighbors := toDiscoveryNeighbors(afterNC.Neighbors)
	discoveredIPs := capStrings(topologydiscovery.NewNeighborIPs(beforeNeighbors, afterNeighbors), 50)
	observedIPs := capStrings(topologydiscovery.NeighborIPs(afterNeighbors), 50)

	collectCtx, cancel := context.WithTimeout(ctx, maxDuration(cfg.Timeout, 10*time.Second))
	res, collectErr := syscollector.Collect(collectCtx, syscollector.Options{
		CmdTimeout:     minDuration(cfg.Timeout, m.cfg.SyscollectCmdTimeout),
		MaxOutputBytes: m.cfg.SyscollectMaxOutputBytes,
		MaxPackages:    m.cfg.SyscollectMaxPackages,
		HostRoot:       m.cfg.SyscollectHostRoot,
		NetCtxCaps: netcontext.Caps{
			MaxInterfaces: m.cfg.NetCtxMaxInterfaces,
			MaxNeighbors:  m.cfg.NetCtxMaxNeighbors,
			MaxRoutes:     m.cfg.NetCtxMaxRoutes,
			MaxResolvers:  m.cfg.NetCtxMaxResolvers,
		},
	})
	cancel()
	if collectErr != nil {
		m.recordTopologyDiscoveryFailure(startedAt, trigger, collectErr)
		return nil, collectErr
	}
	res.Snapshot.Extra["network_context"] = afterNC.ToInventoryMap()
	res.Snapshot.Extra["topology_active_discovery"] = map[string]interface{}{
		"trigger":             trigger,
		"allowed_cidrs":       plan.AllowedCIDRs,
		"target_count":        len(plan.Targets),
		"attempted_hosts":     probeStats.Attempted,
		"successful_probes":   probeStats.Succeeded,
		"failed_probes":       probeStats.Failed,
		"discovered_hosts":    discoveredIPs,
		"observed_hosts":      observedIPs,
		"skipped_denied":      plan.SkippedDenied,
		"skipped_local":       plan.SkippedLocal,
		"probe_tool":          probeTool,
		"warnings":            warnings,
		"deny_ports_enforced": true,
	}

	ctxSend, cancel := context.WithTimeout(ctx, m.cfg.HTTPTimeout)
	_, sendErr := m.sender.SendInventorySnapshot(ctxSend, res.Snapshot)
	cancel()
	if sendErr != nil {
		m.recordTopologyDiscoveryFailure(startedAt, trigger, sendErr)
		return nil, sendErr
	}

	m.updateTopologyDiscoveryStatus(func(status *TopologyDiscoveryStatus) {
		status.LastRunAt = startedAt
		status.LastSentAt = time.Now().UTC()
		status.LastError = ""
		status.LastWarnings = append([]string(nil), warnings...)
		status.LastAllowedCIDRs = append([]string(nil), plan.AllowedCIDRs...)
		status.LastDiscoveredIPs = append([]string(nil), discoveredIPs...)
		status.LastObservedIPs = append([]string(nil), observedIPs...)
		status.LastTargetCount = len(plan.Targets)
		status.LastAttemptedHosts = probeStats.Attempted
		status.LastTrigger = trigger
	})

	return map[string]interface{}{
		"schema_version":      "v1",
		"mode":                "active_discovery",
		"trigger":             trigger,
		"allowed_cidrs":       plan.AllowedCIDRs,
		"target_count":        len(plan.Targets),
		"attempted_hosts":     probeStats.Attempted,
		"successful_probes":   probeStats.Succeeded,
		"failed_probes":       probeStats.Failed,
		"discovered_hosts":    discoveredIPs,
		"observed_hosts":      observedIPs,
		"skipped_denied":      plan.SkippedDenied,
		"skipped_local":       plan.SkippedLocal,
		"probe_tool":          probeTool,
		"warnings":            warnings,
		"deny_ports_enforced": true,
		"completed_at":        time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (m *Manager) recordTopologyDiscoveryFailure(startedAt time.Time, trigger string, err error) {
	m.updateTopologyDiscoveryStatus(func(status *TopologyDiscoveryStatus) {
		status.LastRunAt = startedAt
		status.LastError = err.Error()
		status.LastTrigger = trigger
	})
}

func (m *Manager) updateTopologyDiscoveryStatus(fn func(*TopologyDiscoveryStatus)) {
	m.topoMu.Lock()
	defer m.topoMu.Unlock()
	fn(&m.topoStatus)
}

func toDiscoveryNeighbors(entries []netcontext.NeighborEntry) []topologydiscovery.Neighbor {
	out := make([]topologydiscovery.Neighbor, 0, len(entries))
	for _, entry := range entries {
		out = append(out, topologydiscovery.Neighbor{IP: entry.IP})
	}
	return out
}

func capStrings(values []string, max int) []string {
	if max <= 0 || len(values) <= max {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:max]...)
}

func minDuration(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func TopologyDiscoveryMode(enabled bool) string {
	if enabled {
		return "active_enabled"
	}
	return "passive_only"
}

func TopologyDiscoveryCIDRs(cfg TopologyDiscoveryConfig, status TopologyDiscoveryStatus) []string {
	if len(cfg.CIDRs) > 0 {
		return agentcfg.CIDRStrings(cfg.CIDRs)
	}
	if len(status.LastAllowedCIDRs) > 0 {
		return append([]string(nil), status.LastAllowedCIDRs...)
	}
	return []string{}
}

func TopologyDiscoveryWarningText(warnings []string) string {
	return strings.Join(warnings, "; ")
}
