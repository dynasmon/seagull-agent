package spool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fileSuffix = ".spool.json"
	tempSuffix = ".tmp"
	dirMode    = 0o700
	fileMode   = 0o600
)

type Envelope struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	CreatedAt time.Time       `json:"created_at"`
	Attempts  int             `json:"attempts"`
	Payload   json.RawMessage `json:"payload"`
}

type Options struct {
	Dir      string
	MaxBytes int64
	MaxAge   time.Duration
	MaxItems int
}

type Stats struct {
	Pending        int   `json:"pending"`
	Bytes          int64 `json:"bytes"`
	EnqueuedTotal  int64 `json:"enqueued_total"`
	DeliveredTotal int64 `json:"delivered_total"`
	DroppedTotal   int64 `json:"dropped_total"`
}

type Spool struct {
	mu   sync.Mutex
	opts Options

	pending   int
	bytes     int64
	enqueued  int64
	delivered int64
	dropped   int64
}

func New(opts Options) (*Spool, error) {
	dir := strings.TrimSpace(opts.Dir)
	if dir == "" {
		return nil, nil
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 256 << 20
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = 24 * time.Hour
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = 10000
	}
	opts.Dir = dir

	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create spool dir: %w", err)
	}
	_ = os.Chmod(dir, dirMode)

	s := &Spool{opts: opts}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rescanLocked()
	return s, nil
}

func (s *Spool) Enabled() bool {
	return s != nil && strings.TrimSpace(s.opts.Dir) != ""
}

func (s *Spool) Pending() int {
	if !s.Enabled() {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

func (s *Spool) Stats() Stats {
	if !s.Enabled() {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{
		Pending:        s.pending,
		Bytes:          s.bytes,
		EnqueuedTotal:  s.enqueued,
		DeliveredTotal: s.delivered,
		DroppedTotal:   s.dropped,
	}
}

func (s *Spool) Enqueue(id string, kind string, payload []byte) (Envelope, error) {
	env := Envelope{}
	if !s.Enabled() {
		return env, fmt.Errorf("spool disabled")
	}
	if len(payload) == 0 {
		return env, fmt.Errorf("empty payload")
	}

	id = strings.TrimSpace(id)
	if id == "" {
		id = NewID()
	}
	env = Envelope{
		ID:        id,
		Kind:      strings.TrimSpace(kind),
		CreatedAt: time.Now().UTC(),
		Payload:   json.RawMessage(append([]byte(nil), payload...)),
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return env, fmt.Errorf("marshal spool envelope: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	name := fmt.Sprintf("%020d-%s%s", env.CreatedAt.UnixNano(), env.ID, fileSuffix)
	path := filepath.Join(s.opts.Dir, name)
	tmp := path + tempSuffix
	if err := os.WriteFile(tmp, encoded, fileMode); err != nil {
		return env, fmt.Errorf("write spool entry: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return env, fmt.Errorf("commit spool entry: %w", err)
	}

	s.pending++
	s.bytes += int64(len(encoded))
	s.enqueued++
	s.enforceRetentionLocked()
	return env, nil
}

func (s *Spool) Drain(ctx context.Context, limit int, deliver func(Envelope) error) (int, error) {
	if !s.Enabled() || deliver == nil {
		return 0, nil
	}
	if limit <= 0 {
		limit = 64
	}

	entries, err := s.snapshot()
	if err != nil {
		return 0, err
	}

	delivered := 0
	for _, name := range entries {
		if delivered >= limit {
			break
		}
		if ctx != nil && ctx.Err() != nil {
			return delivered, ctx.Err()
		}

		path := filepath.Join(s.opts.Dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			s.discard(path, int64(len(raw)))
			continue
		}

		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			s.discard(path, int64(len(raw)))
			continue
		}
		if s.opts.MaxAge > 0 && time.Since(env.CreatedAt) > s.opts.MaxAge {
			s.discard(path, int64(len(raw)))
			continue
		}

		if err := deliver(env); err != nil {
			return delivered, err
		}

		s.mu.Lock()
		if removeErr := os.Remove(path); removeErr == nil {
			s.pending--
			s.bytes -= int64(len(raw))
			s.delivered++
			if s.pending < 0 {
				s.pending = 0
			}
			if s.bytes < 0 {
				s.bytes = 0
			}
		}
		s.mu.Unlock()
		delivered++
	}

	return delivered, nil
}

func (s *Spool) snapshot() ([]string, error) {
	dirEntries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("read spool dir: %w", err)
	}
	names := make([]string, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (s *Spool) discard(path string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil {
		return
	}
	s.pending--
	s.bytes -= size
	s.dropped++
	if s.pending < 0 {
		s.pending = 0
	}
	if s.bytes < 0 {
		s.bytes = 0
	}
}

func (s *Spool) rescanLocked() {
	dirEntries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return
	}
	pending := 0
	var total int64
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, tempSuffix) {
			_ = os.Remove(filepath.Join(s.opts.Dir, name))
			continue
		}
		if !strings.HasSuffix(name, fileSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		pending++
		total += info.Size()
	}
	s.pending = pending
	s.bytes = total
	s.enforceRetentionLocked()
}

func (s *Spool) enforceRetentionLocked() {
	dirEntries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return
	}

	type record struct {
		name string
		size int64
		mod  time.Time
	}
	records := make([]record, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		records = append(records, record{name: entry.Name(), size: info.Size(), mod: info.ModTime()})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].name < records[j].name })

	cutoff := time.Now().Add(-s.opts.MaxAge)
	kept := make([]record, 0, len(records))
	for _, rec := range records {
		if s.opts.MaxAge > 0 && rec.mod.Before(cutoff) {
			if err := os.Remove(filepath.Join(s.opts.Dir, rec.name)); err == nil {
				s.pending--
				s.bytes -= rec.size
				s.dropped++
			}
			continue
		}
		kept = append(kept, rec)
	}

	idx := 0
	for idx < len(kept) && (s.bytes > s.opts.MaxBytes || len(kept)-idx > s.opts.MaxItems) {
		rec := kept[idx]
		if err := os.Remove(filepath.Join(s.opts.Dir, rec.name)); err == nil {
			s.pending--
			s.bytes -= rec.size
			s.dropped++
		}
		idx++
	}

	if s.pending < 0 {
		s.pending = 0
	}
	if s.bytes < 0 {
		s.bytes = 0
	}
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString(b[:])
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
