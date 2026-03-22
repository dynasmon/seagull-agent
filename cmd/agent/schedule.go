package main

import (
	"hash/fnv"
	"time"
)

func stableJitter(agentID, scope string, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(agentID))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(scope))
	n := h.Sum64()
	return time.Duration(n % uint64(max))
}
