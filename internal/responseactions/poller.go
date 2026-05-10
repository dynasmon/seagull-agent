package responseactions

import (
	"context"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/jitter"
)

type PollerConfig struct {
	AgentID string
	Every   time.Duration
	Jitter  time.Duration
	Timeout time.Duration
}

type PollerDeps struct {
	Fetch    func(context.Context) ([]controlplane.ResponseAction, error)
	Stage    func([]controlplane.ResponseAction) StageResult
	OnError  func(error)
	OnStaged func(fetched int, result StageResult)
}

func StartPolling(ctx context.Context, cfg PollerConfig, deps PollerDeps) {
	if deps.Fetch == nil || deps.Stage == nil {
		return
	}
	every := cfg.Every
	if every <= 0 {
		every = 15 * time.Second
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	go func() {
		initialDelay := jitter.Stable(cfg.AgentID, "control.response_actions", cfg.Jitter)
		if initialDelay > 0 {
			t := time.NewTimer(initialDelay)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		t := time.NewTicker(every)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reqCtx, cancel := context.WithTimeout(ctx, timeout)
				actions, err := deps.Fetch(reqCtx)
				cancel()
				if err != nil {
					if deps.OnError != nil {
						deps.OnError(err)
					}
					continue
				}
				if len(actions) == 0 {
					continue
				}

				result := deps.Stage(actions)
				if deps.OnStaged != nil {
					deps.OnStaged(len(actions), result)
				}
			}
		}
	}()
}
