package pcapx

import (
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent/internal/protocol"
)

type Buffer struct {
	mu          sync.Mutex
	buf         []protocol.NetEvent
	cache       map[string]time.Time
	lastCleanup time.Time
	ttl         time.Duration
	maxBatch    int
}

func NewBuffer(ttl time.Duration, maxBatch int) *Buffer {
	return &Buffer{
		buf:         make([]protocol.NetEvent, 0, 2048),
		cache:       make(map[string]time.Time, 8192),
		lastCleanup: time.Now().UTC(),
		ttl:         ttl,
		maxBatch:    maxBatch,
	}
}

func (b *Buffer) Push(key string, ev protocol.NetEvent) bool {
	now := time.Now().UTC()

	b.mu.Lock()
	defer b.mu.Unlock()

	if t, ok := b.cache[key]; ok && now.Sub(t) < b.ttl {
		return false
	}
	if len(b.buf) >= b.maxBatch {
		return false
	}

	b.cache[key] = now
	b.buf = append(b.buf, ev)
	b.cleanupLocked(now)
	return true
}

func (b *Buffer) cleanupLocked(now time.Time) {
	if now.Sub(b.lastCleanup) < b.ttl {
		return
	}
	cutoff := now.Add(-2 * b.ttl)
	for k, t := range b.cache {
		if t.Before(cutoff) {
			delete(b.cache, k)
		}
	}
	b.lastCleanup = now
}

func (b *Buffer) Drain() []protocol.NetEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.buf) == 0 {
		return nil
	}
	out := make([]protocol.NetEvent, len(b.buf))
	copy(out, b.buf)
	b.buf = b.buf[:0]
	return out
}
