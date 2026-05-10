package heartbeat

import (
	"context"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/jitter"
)

type Config struct {
	AgentID string
	Every   time.Duration
	Jitter  time.Duration
	Timeout time.Duration
}

type Deps struct {
	Build   func() controlplane.HeartbeatRequest
	Send    func(context.Context, controlplane.HeartbeatRequest) error
	OnError func(error)
}

func Start(ctx context.Context, cfg Config, deps Deps) {
	if deps.Build == nil || deps.Send == nil {
		return
	}

	every := cfg.Every
	if every <= 0 {
		every = 30 * time.Second
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	go func() {
		initialDelay := jitter.Stable(cfg.AgentID, "control.heartbeat", cfg.Jitter)
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
				err := deps.Send(reqCtx, deps.Build())
				cancel()
				if err != nil && deps.OnError != nil {
					deps.OnError(err)
				}
			}
		}
	}()
}
