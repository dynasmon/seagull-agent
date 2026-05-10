package jitter

import (
	"hash/fnv"
	"time"
)

func Stable(agentID, scope string, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(agentID))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(scope))
	return time.Duration(h.Sum64() % uint64(max))
}
