package responseactions

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
)

func TestStartPollingStagesActions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var staged atomic.Int64
	var calls atomic.Int64

	StartPolling(ctx, PollerConfig{
		AgentID: "agent-1",
		Every:   10 * time.Millisecond,
		Jitter:  0,
		Timeout: 100 * time.Millisecond,
	}, PollerDeps{
		Fetch: func(_ context.Context) ([]controlplane.ResponseAction, error) {
			calls.Add(1)
			return []controlplane.ResponseAction{
				{ID: 1, ActionType: "block_ip", AgentID: "agent-1", Status: "pending", RequestedAt: time.Now().UTC()},
			}, nil
		},
		Stage: func(_ []controlplane.ResponseAction) StageResult {
			staged.Add(1)
			return StageResult{Added: 1, Pending: 1}
		},
	})

	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if staged.Load() > 0 && calls.Load() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("poller did not fetch and stage actions")
}

func TestStartPollingErrorCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errorsSeen atomic.Int64
	StartPolling(ctx, PollerConfig{
		AgentID: "agent-1",
		Every:   10 * time.Millisecond,
		Jitter:  0,
		Timeout: 100 * time.Millisecond,
	}, PollerDeps{
		Fetch: func(_ context.Context) ([]controlplane.ResponseAction, error) {
			return nil, context.DeadlineExceeded
		},
		Stage: func(_ []controlplane.ResponseAction) StageResult {
			return StageResult{}
		},
		OnError: func(error) {
			errorsSeen.Add(1)
		},
	})

	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if errorsSeen.Load() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("poller did not trigger error callback")
}
