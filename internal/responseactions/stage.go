package responseactions

import (
	"sync"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/controlplane"
)

type StagedAction struct {
	Action   controlplane.ResponseAction
	StagedAt time.Time
}

type StageResult struct {
	Added   int
	Ignored int
	Dropped int
	Pending int
}

type Stage struct {
	mu    sync.Mutex
	max   int
	order []int64
	items map[int64]StagedAction
}

func NewStage(max int) *Stage {
	if max <= 0 {
		max = 256
	}
	return &Stage{
		max:   max,
		order: make([]int64, 0, max),
		items: make(map[int64]StagedAction, max),
	}
}

func (s *Stage) Stage(now time.Time, actions []controlplane.ResponseAction, expectedAgentID string) StageResult {
	if s == nil || len(actions) == 0 {
		return StageResult{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	out := StageResult{}
	for i := range actions {
		a := actions[i]
		if a.ID <= 0 || a.ActionType == "" {
			out.Ignored++
			continue
		}
		if expectedAgentID != "" && a.AgentID != expectedAgentID {
			out.Ignored++
			continue
		}
		if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
			out.Ignored++
			continue
		}
		if _, ok := s.items[a.ID]; ok {
			out.Ignored++
			continue
		}

		for len(s.items) >= s.max && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			if _, ok := s.items[oldest]; ok {
				delete(s.items, oldest)
				out.Dropped++
			}
		}

		s.items[a.ID] = StagedAction{
			Action:   a,
			StagedAt: now,
		}
		s.order = append(s.order, a.ID)
		out.Added++
	}
	out.Pending = len(s.items)
	return out
}

func (s *Stage) PendingCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}
