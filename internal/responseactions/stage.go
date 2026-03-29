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
	mu           sync.Mutex
	max          int
	handledMax   int
	order        []int64
	items        map[int64]StagedAction
	handledOrder []int64
	handledSet   map[int64]struct{}
}

func NewStage(max int) *Stage {
	if max <= 0 {
		max = 256
	}
	handledMax := max * 8
	if handledMax < 512 {
		handledMax = 512
	}
	return &Stage{
		max:          max,
		handledMax:   handledMax,
		order:        make([]int64, 0, max),
		items:        make(map[int64]StagedAction, max),
		handledOrder: make([]int64, 0, handledMax),
		handledSet:   make(map[int64]struct{}, handledMax),
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
		if _, ok := s.handledSet[a.ID]; ok {
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

func (s *Stage) Next(now time.Time, expectedAgentID string) (StagedAction, bool) {
	if s == nil {
		return StagedAction{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.order) > 0 {
		id := s.order[0]
		s.order = s.order[1:]
		item, ok := s.items[id]
		if !ok {
			continue
		}
		delete(s.items, id)
		if expectedAgentID != "" && item.Action.AgentID != expectedAgentID {
			s.markHandledLocked(id)
			continue
		}
		if item.Action.ExpiresAt != nil && !item.Action.ExpiresAt.After(now) {
			s.markHandledLocked(id)
			continue
		}
		return item, true
	}
	return StagedAction{}, false
}

func (s *Stage) MarkHandled(actionID int64) {
	if s == nil || actionID <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, actionID)
	s.markHandledLocked(actionID)
}

func (s *Stage) markHandledLocked(actionID int64) {
	if actionID <= 0 {
		return
	}
	if _, ok := s.handledSet[actionID]; ok {
		return
	}
	s.handledSet[actionID] = struct{}{}
	s.handledOrder = append(s.handledOrder, actionID)
	for len(s.handledOrder) > s.handledMax && len(s.handledOrder) > 0 {
		oldest := s.handledOrder[0]
		s.handledOrder = s.handledOrder[1:]
		delete(s.handledSet, oldest)
	}
}
