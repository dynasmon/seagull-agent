package main

import (
	"context"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/syscollector"
)

type SyscollectorStatus struct {
	LastRunAt    time.Time
	LastSentAt   time.Time
	LastError    string
	LastHash     string
	LastPkgCount int
}

func (a *Agent) startSyscollector(ctx context.Context) {
	if a == nil || a.runtime == nil {
		return
	}
	if !contains(a.cfg.Sources, "syscollector") {
		return
	}

	go func() {
		for {
			cfg := a.runtime.Syscollector()
			a.sysMu.RLock()
			lastRun := a.sysStatus.LastRunAt
			a.sysMu.RUnlock()

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
			if a.sender == nil {
				continue
			}

			ctxRun, cancel := context.WithTimeout(ctx, cfg.CmdTimeout+5*time.Second)
			a.runSyscollectorOnce(ctxRun, cfg)
			cancel()
		}
	}()
}

func (a *Agent) runSyscollectorOnce(ctx context.Context, cfg SyscollectorConfig) {
	res, err := syscollector.Collect(ctx, syscollector.Options{
		CmdTimeout:     cfg.CmdTimeout,
		MaxOutputBytes: cfg.MaxOutputBytes,
		MaxPackages:    cfg.MaxPackages,
		HostRoot:       cfg.HostRoot,
	})

	a.sysMu.Lock()
	a.sysStatus.LastRunAt = time.Now().UTC()
	a.sysMu.Unlock()
	if err != nil {
		a.sysMu.Lock()
		a.sysStatus.LastError = err.Error()
		a.sysMu.Unlock()
		return
	}

	// Best-effort: avoid emitting identical snapshots.
	a.sysMu.RLock()
	lastHash := a.sysStatus.LastHash
	a.sysMu.RUnlock()
	if res.Snapshot.PackagesHash != "" && res.Snapshot.PackagesHash == lastHash {
		a.sysMu.Lock()
		a.sysStatus.LastError = ""
		a.sysMu.Unlock()
		return
	}

	ctxSend, cancel := context.WithTimeout(ctx, a.cfg.HTTPTimeout)
	status, sendErr := a.sender.SendInventorySnapshot(ctxSend, res.Snapshot)
	cancel()

	if sendErr != nil {
		a.sysMu.Lock()
		a.sysStatus.LastError = sendErr.Error()
		a.sysStatus.LastSentAt = time.Time{}
		a.sysMu.Unlock()
		_ = status
		return
	}

	a.sysMu.Lock()
	a.sysStatus.LastError = ""
	a.sysStatus.LastSentAt = time.Now().UTC()
	a.sysStatus.LastHash = res.Snapshot.PackagesHash
	a.sysStatus.LastPkgCount = res.Snapshot.PackagesCount
	a.sysMu.Unlock()
}
