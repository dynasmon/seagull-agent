package sources

import (
	"context"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/syscollector"
	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/jitter"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/netcontext"
)

type SyscollectorStatus struct {
	LastRunAt    time.Time
	LastSentAt   time.Time
	LastError    string
	LastHash     string
	LastPkgCount int
}

func (m *Manager) StartSyscollector(ctx context.Context) {
	if m == nil || m.runtime == nil {
		return
	}
	if !agentcfg.Contains(m.cfg.Sources, "syscollector") {
		return
	}

	go func() {
		startupDelayed := false
		for {
			cfg := m.runtime.Syscollector()
			m.sysMu.RLock()
			lastRun := m.sysStatus.LastRunAt
			m.sysMu.RUnlock()

			nextIn := 30 * time.Second
			if cfg.Enabled {
				if lastRun.IsZero() {
					nextIn = 0
					if !startupDelayed {
						nextIn = jitter.Stable(m.cfg.AgentID, "syscollector.startup", m.cfg.SyscollectStartupJitter)
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
			case <-m.runtime.Changed():
				t.Stop()
				continue
			case <-t.C:
				// proceed
			}

			if !cfg.Enabled {
				continue
			}
			if m.sender == nil {
				continue
			}

			ctxRun, cancel := context.WithTimeout(ctx, cfg.CmdTimeout+5*time.Second)
			m.runSyscollectorOnce(ctxRun, cfg)
			cancel()
		}
	}()
}

func (m *Manager) runSyscollectorOnce(ctx context.Context, cfg SyscollectorConfig) {
	res, err := syscollector.Collect(ctx, syscollector.Options{
		CmdTimeout:     cfg.CmdTimeout,
		MaxOutputBytes: cfg.MaxOutputBytes,
		MaxPackages:    cfg.MaxPackages,
		HostRoot:       cfg.HostRoot,
		NetCtxCaps: netcontext.Caps{
			MaxInterfaces: cfg.NetCtxMaxIfaces,
			MaxNeighbors:  cfg.NetCtxMaxNeighbors,
			MaxRoutes:     cfg.NetCtxMaxRoutes,
			MaxResolvers:  cfg.NetCtxMaxResolvers,
		},
	})

	m.sysMu.Lock()
	m.sysStatus.LastRunAt = time.Now().UTC()
	m.sysMu.Unlock()
	if err != nil {
		m.sysMu.Lock()
		m.sysStatus.LastError = err.Error()
		m.sysMu.Unlock()
		return
	}

	// Best-effort: avoid emitting identical snapshots.
	m.sysMu.RLock()
	lastHash := m.sysStatus.LastHash
	m.sysMu.RUnlock()
	if res.Snapshot.PackagesHash != "" && res.Snapshot.PackagesHash == lastHash {
		m.sysMu.Lock()
		m.sysStatus.LastError = ""
		m.sysMu.Unlock()
		return
	}

	ctxSend, cancel := context.WithTimeout(ctx, m.cfg.HTTPTimeout)
	status, sendErr := m.sender.SendInventorySnapshot(ctxSend, res.Snapshot)
	cancel()

	if sendErr != nil {
		m.sysMu.Lock()
		m.sysStatus.LastError = sendErr.Error()
		m.sysStatus.LastSentAt = time.Time{}
		m.sysMu.Unlock()
		_ = status
		return
	}

	m.sysMu.Lock()
	m.sysStatus.LastError = ""
	m.sysStatus.LastSentAt = time.Now().UTC()
	m.sysStatus.LastHash = res.Snapshot.PackagesHash
	m.sysStatus.LastPkgCount = res.Snapshot.PackagesCount
	m.sysMu.Unlock()
}
