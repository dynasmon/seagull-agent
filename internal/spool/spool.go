package spool

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fileSuffix   = ".spool.json"
	tempSuffix   = ".tmp"
	statsFile    = ".spool-stats.json"
	dirMode      = 0o700
	fileMode     = 0o600
	statsVersion = 1
)

type Envelope struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Priority  int             `json:"priority"`
	CreatedAt time.Time       `json:"created_at"`
	Attempts  int             `json:"attempts"`
	Payload   json.RawMessage `json:"payload"`
	receipt   string
}

type Options struct {
	Dir      string
	MaxBytes int64
	MaxAge   time.Duration
	MaxItems int
}

type Stats struct {
	Pending            int   `json:"pending"`
	Bytes              int64 `json:"bytes"`
	EnqueuedTotal      int64 `json:"enqueued_total"`
	DeliveredTotal     int64 `json:"delivered_total"`
	DroppedTotal       int64 `json:"dropped_total"`
	ExpiredTotal       int64 `json:"expired_total"`
	CapacityTotal      int64 `json:"capacity_total"`
	CorruptTotal       int64 `json:"corrupt_total"`
	PermanentTotal     int64 `json:"permanent_total"`
	RetryTotal         int64 `json:"retry_total"`
	EnqueueErrorsTotal int64 `json:"enqueue_errors_total"`
}

type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string {
	if e == nil || e.Err == nil {
		return "permanent delivery error"
	}
	return e.Err.Error()
}

func (e *PermanentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

type Spool struct {
	mu       sync.Mutex
	drainMu  sync.Mutex
	opts     Options
	inflight map[string]struct{}

	pending       int
	bytes         int64
	enqueued      int64
	delivered     int64
	dropped       int64
	expired       int64
	capacity      int64
	corrupt       int64
	permanent     int64
	retries       int64
	enqueueErrors int64
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
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("secure spool dir: %w", err)
	}

	s := &Spool{opts: opts, inflight: make(map[string]struct{})}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadStatsLocked()
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
		Pending:            s.pending,
		Bytes:              s.bytes,
		EnqueuedTotal:      s.enqueued,
		DeliveredTotal:     s.delivered,
		DroppedTotal:       s.dropped,
		ExpiredTotal:       s.expired,
		CapacityTotal:      s.capacity,
		CorruptTotal:       s.corrupt,
		PermanentTotal:     s.permanent,
		RetryTotal:         s.retries,
		EnqueueErrorsTotal: s.enqueueErrors,
	}
}

func (s *Spool) Enqueue(id string, kind string, payload []byte) (Envelope, error) {
	return s.EnqueuePriority(id, kind, 0, payload)
}

func (s *Spool) EnqueuePriority(id string, kind string, priority int, payload []byte) (Envelope, error) {
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
		Priority:  priority,
		CreatedAt: time.Now().UTC(),
		Payload:   json.RawMessage(append([]byte(nil), payload...)),
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return env, fmt.Errorf("marshal spool envelope: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	name := fmt.Sprintf("%020d-%s-%s%s", env.CreatedAt.UnixNano(), filenameID(env.ID), filenameID(NewID()), fileSuffix)
	env.receipt = name
	path := filepath.Join(s.opts.Dir, name)
	if err := writeAtomic(path, encoded); err != nil {
		s.enqueueErrors++
		_ = s.persistStatsLocked()
		return env, fmt.Errorf("write spool entry: %w", err)
	}

	s.pending++
	s.bytes += int64(len(encoded))
	s.enqueued++
	s.enforceRetentionLocked()
	_ = s.persistStatsLocked()
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return env, fmt.Errorf("spool entry exceeded the retention budget")
		}
		return env, fmt.Errorf("inspect queued spool entry: %w", err)
	}
	return env, nil
}

func (s *Spool) Acknowledge(env Envelope) error {
	return s.removeEnvelope(env, "delivered")
}

func (s *Spool) Reject(env Envelope) error {
	return s.removeEnvelope(env, "permanent")
}

func (s *Spool) removeEnvelope(env Envelope, reason string) error {
	if !s.Enabled() {
		return fmt.Errorf("spool disabled")
	}
	name := strings.TrimSpace(env.receipt)
	if name == "" || filepath.Base(name) != name || !strings.HasSuffix(name, fileSuffix) {
		return fmt.Errorf("invalid spool receipt")
	}

	s.drainMu.Lock()
	defer s.drainMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.opts.Dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read queued spool entry: %w", err)
	}
	var stored Envelope
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("decode queued spool entry: %w", err)
	}
	if strings.TrimSpace(stored.ID) != strings.TrimSpace(env.ID) {
		return fmt.Errorf("spool receipt does not match the batch")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove queued spool entry: %w", err)
	}
	s.recordRemovalLocked(int64(len(raw)), reason)
	if err := syncDir(s.opts.Dir); err != nil {
		return fmt.Errorf("sync queued spool removal: %w", err)
	}
	_ = s.persistStatsLocked()
	return nil
}

func (s *Spool) Drain(ctx context.Context, limit int, deliver func(Envelope) error) (int, error) {
	if !s.Enabled() || deliver == nil {
		return 0, nil
	}
	if limit <= 0 {
		limit = 64
	}

	s.drainMu.Lock()
	defer s.drainMu.Unlock()

	entries, err := s.snapshot()
	if err != nil {
		return 0, err
	}

	delivered := 0
	processed := 0
	for _, name := range entries {
		if processed >= limit {
			break
		}
		if ctx != nil && ctx.Err() != nil {
			return delivered, ctx.Err()
		}
		processed++

		path := filepath.Join(s.opts.Dir, name)
		s.mu.Lock()
		s.inflight[name] = struct{}{}
		raw, err := os.ReadFile(path)
		if err != nil {
			delete(s.inflight, name)
			s.mu.Unlock()
			if os.IsNotExist(err) {
				continue
			}
			return delivered, fmt.Errorf("read spool entry: %w", err)
		}
		s.mu.Unlock()

		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			s.discard(name, path, int64(len(raw)), "corrupt")
			continue
		}
		if s.opts.MaxAge > 0 && time.Since(env.CreatedAt) > s.opts.MaxAge {
			s.discard(name, path, int64(len(raw)), "expired")
			continue
		}

		deliveryErr := deliver(env)
		if deliveryErr != nil {
			var permanent *PermanentError
			if errors.As(deliveryErr, &permanent) {
				s.discard(name, path, int64(len(raw)), "permanent")
				continue
			}
			env.Attempts++
			updated, marshalErr := json.Marshal(env)
			if marshalErr != nil {
				s.release(name)
				return delivered, errors.Join(deliveryErr, fmt.Errorf("marshal spool retry state: %w", marshalErr))
			}
			s.mu.Lock()
			writeErr := writeAtomic(path, updated)
			if writeErr == nil {
				s.bytes += int64(len(updated) - len(raw))
				s.retries++
				_ = s.persistStatsLocked()
			}
			delete(s.inflight, name)
			s.mu.Unlock()
			if writeErr != nil {
				return delivered, errors.Join(deliveryErr, fmt.Errorf("persist spool retry state: %w", writeErr))
			}
			return delivered, deliveryErr
		}

		s.mu.Lock()
		removeErr := os.Remove(path)
		if removeErr == nil {
			s.recordRemovalLocked(int64(len(raw)), "delivered")
			_ = syncDir(s.opts.Dir)
			_ = s.persistStatsLocked()
		}
		delete(s.inflight, name)
		s.mu.Unlock()
		if removeErr != nil {
			return delivered, fmt.Errorf("remove delivered spool entry: %w", removeErr)
		}
		delivered++
	}

	return delivered, nil
}

func (s *Spool) snapshot() ([]string, error) {
	dirEntries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("read spool dir: %w", err)
	}
	type record struct {
		name      string
		priority  int
		createdAt time.Time
		valid     bool
	}
	records := make([]record, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		item := record{name: entry.Name()}
		raw, readErr := os.ReadFile(filepath.Join(s.opts.Dir, entry.Name()))
		if readErr == nil {
			var env Envelope
			if json.Unmarshal(raw, &env) == nil {
				item.priority = env.Priority
				item.createdAt = env.CreatedAt
				item.valid = true
			}
		}
		records = append(records, item)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].valid != records[j].valid {
			return !records[i].valid
		}
		if records[i].priority != records[j].priority {
			return records[i].priority > records[j].priority
		}
		if !records[i].createdAt.Equal(records[j].createdAt) {
			return records[i].createdAt.Before(records[j].createdAt)
		}
		return records[i].name < records[j].name
	})
	names := make([]string, 0, len(records))
	for _, item := range records {
		names = append(names, item.name)
	}
	return names, nil
}

func (s *Spool) discard(name string, path string, size int64, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer delete(s.inflight, name)
	if err := os.Remove(path); err != nil {
		return
	}
	s.recordRemovalLocked(size, reason)
	_ = syncDir(s.opts.Dir)
	_ = s.persistStatsLocked()
}

func (s *Spool) release(name string) {
	s.mu.Lock()
	delete(s.inflight, name)
	s.mu.Unlock()
}

func (s *Spool) recordRemovalLocked(size int64, reason string) {
	s.pending--
	s.bytes -= size
	switch reason {
	case "delivered":
		s.delivered++
	case "expired":
		s.dropped++
		s.expired++
	case "capacity":
		s.dropped++
		s.capacity++
	case "corrupt":
		s.dropped++
		s.corrupt++
	case "permanent":
		s.dropped++
		s.permanent++
	}
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
	if s.enqueued < int64(s.pending) {
		s.enqueued = int64(s.pending)
	}
	s.enforceRetentionLocked()
	_ = s.persistStatsLocked()
}

func (s *Spool) enforceRetentionLocked() {
	dirEntries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return
	}

	type record struct {
		name     string
		size     int64
		created  time.Time
		priority int
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
		priority := 0
		created := info.ModTime()
		if raw, readErr := os.ReadFile(filepath.Join(s.opts.Dir, entry.Name())); readErr == nil {
			var env Envelope
			if json.Unmarshal(raw, &env) == nil {
				priority = env.Priority
				if !env.CreatedAt.IsZero() {
					created = env.CreatedAt
				}
			}
		}
		records = append(records, record{name: entry.Name(), size: info.Size(), created: created, priority: priority})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].name < records[j].name })

	cutoff := time.Now().Add(-s.opts.MaxAge)
	kept := make([]record, 0, len(records))
	for _, rec := range records {
		if _, ok := s.inflight[rec.name]; ok {
			kept = append(kept, rec)
			continue
		}
		if s.opts.MaxAge > 0 && rec.created.Before(cutoff) {
			if err := os.Remove(filepath.Join(s.opts.Dir, rec.name)); err == nil {
				s.recordRemovalLocked(rec.size, "expired")
			}
			continue
		}
		kept = append(kept, rec)
	}

	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].priority != kept[j].priority {
			return kept[i].priority < kept[j].priority
		}
		return kept[i].name < kept[j].name
	})
	remaining := len(kept)
	for _, rec := range kept {
		if s.bytes <= s.opts.MaxBytes && remaining <= s.opts.MaxItems {
			break
		}
		if _, ok := s.inflight[rec.name]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(s.opts.Dir, rec.name)); err == nil {
			s.recordRemovalLocked(rec.size, "capacity")
			remaining--
		}
	}

	if s.pending < 0 {
		s.pending = 0
	}
	if s.bytes < 0 {
		s.bytes = 0
	}
	_ = syncDir(s.opts.Dir)
}

func (s *Spool) loadStatsLocked() {
	raw, err := os.ReadFile(filepath.Join(s.opts.Dir, statsFile))
	if err != nil {
		return
	}
	var state struct {
		Version int   `json:"version"`
		Stats   Stats `json:"stats"`
	}
	if json.Unmarshal(raw, &state) != nil || state.Version != statsVersion {
		return
	}
	s.enqueued = maxInt64(state.Stats.EnqueuedTotal, 0)
	s.delivered = maxInt64(state.Stats.DeliveredTotal, 0)
	s.dropped = maxInt64(state.Stats.DroppedTotal, 0)
	s.expired = maxInt64(state.Stats.ExpiredTotal, 0)
	s.capacity = maxInt64(state.Stats.CapacityTotal, 0)
	s.corrupt = maxInt64(state.Stats.CorruptTotal, 0)
	s.permanent = maxInt64(state.Stats.PermanentTotal, 0)
	s.retries = maxInt64(state.Stats.RetryTotal, 0)
	s.enqueueErrors = maxInt64(state.Stats.EnqueueErrorsTotal, 0)
}

func (s *Spool) persistStatsLocked() error {
	state := struct {
		Version int   `json:"version"`
		Stats   Stats `json:"stats"`
	}{
		Version: statsVersion,
		Stats: Stats{
			Pending:            s.pending,
			Bytes:              s.bytes,
			EnqueuedTotal:      s.enqueued,
			DeliveredTotal:     s.delivered,
			DroppedTotal:       s.dropped,
			ExpiredTotal:       s.expired,
			CapacityTotal:      s.capacity,
			CorruptTotal:       s.corrupt,
			PermanentTotal:     s.permanent,
			RetryTotal:         s.retries,
			EnqueueErrorsTotal: s.enqueueErrors,
		},
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.opts.Dir, statsFile), raw)
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", time.Now().UnixNano(), os.Getpid())))
		copy(b[:], sum[:16])
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func filenameID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

func writeAtomic(path string, payload []byte) error {
	token := filenameID(fmt.Sprintf("%s:%d:%d", path, os.Getpid(), time.Now().UnixNano()))
	tmp := path + "." + token + tempSuffix
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(tmp)
		return writeErr
	}
	if syncErr != nil {
		_ = os.Remove(tmp)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func maxInt64(value int64, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
