package responseactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dynasmon/seagull-agent/protocol"
)

const (
	journalVersion        = 1
	maxJournalRecordSize  = int64(8 << 20)
	maxResultPayloadSize  = 2 << 20
	terminalGrowthReserve = int64(3 << 20)
)

var (
	ErrJournalEntryExists = errors.New("response action journal entry already exists")
	ErrJournalCapacity    = errors.New("response action journal capacity exceeded")
)

type JournalPhase string

const (
	JournalAccepted  JournalPhase = "accepted"
	JournalExecuting JournalPhase = "executing"
	JournalTerminal  JournalPhase = "terminal"
)

type JournalRecord struct {
	Version   int                                     `json:"version"`
	Action    protocol.ResponseAction                 `json:"action"`
	Phase     JournalPhase                            `json:"phase"`
	Result    *protocol.ResponseActionExecutionResult `json:"result,omitempty"`
	StartedAt time.Time                               `json:"started_at"`
	UpdatedAt time.Time                               `json:"updated_at"`
}

type Journal struct {
	mu         sync.Mutex
	dir        string
	maxRecords int
	maxBytes   int64
}

func NewJournal(dir string, maxRecords int, maxBytes int64) (*Journal, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("response action journal directory is required")
	}
	if maxRecords <= 0 {
		maxRecords = 2048
	}
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create response action journal: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure response action journal: %w", err)
	}

	journal := &Journal{
		dir:        dir,
		maxRecords: maxRecords,
		maxBytes:   maxBytes,
	}
	if err := journal.recover(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (j *Journal) Begin(action protocol.ResponseAction, startedAt time.Time) (JournalRecord, error) {
	if j == nil {
		return JournalRecord{}, fmt.Errorf("response action journal is unavailable")
	}
	if err := action.Normalize(); err != nil {
		return JournalRecord{}, err
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	startedAt = startedAt.UTC()
	record := JournalRecord{
		Version:   journalVersion,
		Action:    action,
		Phase:     JournalAccepted,
		StartedAt: startedAt,
		UpdatedAt: startedAt,
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := os.Lstat(j.path(action.ID)); err == nil {
		return JournalRecord{}, ErrJournalEntryExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return JournalRecord{}, fmt.Errorf("inspect response action journal entry: %w", err)
	}
	if err := j.ensureCapacityLocked(record); err != nil {
		return JournalRecord{}, err
	}
	if err := j.writeLocked(record); err != nil {
		return JournalRecord{}, err
	}
	return record, nil
}

func (j *Journal) MarkExecuting(actionID int64, now time.Time) (JournalRecord, error) {
	if j == nil {
		return JournalRecord{}, fmt.Errorf("response action journal is unavailable")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	record, err := j.readLocked(actionID)
	if err != nil {
		return JournalRecord{}, err
	}
	if record.Phase != JournalAccepted {
		return JournalRecord{}, fmt.Errorf("response action %d is in phase %s", actionID, record.Phase)
	}
	record.Phase = JournalExecuting
	record.UpdatedAt = now.UTC()
	if err := j.writeLocked(record); err != nil {
		return JournalRecord{}, err
	}
	return record, nil
}

func (j *Journal) Complete(actionID int64, result protocol.ResponseActionExecutionResult, now time.Time) (JournalRecord, error) {
	if j == nil {
		return JournalRecord{}, fmt.Errorf("response action journal is unavailable")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	record, err := j.readLocked(actionID)
	if err != nil {
		return JournalRecord{}, err
	}
	if record.Phase != JournalExecuting {
		return JournalRecord{}, fmt.Errorf("response action %d is in phase %s", actionID, record.Phase)
	}
	result.ResponseActionID = actionID
	result.AgentID = record.Action.AgentID
	result.Status = strings.ToLower(strings.TrimSpace(result.Status))
	if result.Status != "success" && result.Status != "failed" {
		return JournalRecord{}, fmt.Errorf("response action %d has invalid terminal status %q", actionID, result.Status)
	}
	result = boundedResult(result)
	record.Phase = JournalTerminal
	record.Result = &result
	record.UpdatedAt = now.UTC()
	if err := j.writeLocked(record); err != nil {
		return JournalRecord{}, err
	}
	return record, nil
}

func (j *Journal) Accepted(limit int) ([]JournalRecord, error) {
	return j.records(JournalAccepted, limit)
}

func (j *Journal) Terminal(limit int) ([]JournalRecord, error) {
	return j.records(JournalTerminal, limit)
}

func (j *Journal) IDs() ([]int64, error) {
	if j == nil {
		return []int64{}, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	records, _, err := j.loadLocked()
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.Action.ID)
	}
	return ids, nil
}

func (j *Journal) Pending() (int, error) {
	if j == nil {
		return 0, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	records, _, err := j.loadLocked()
	if err != nil {
		return 0, err
	}
	return len(records), nil
}

func (j *Journal) Delete(actionID int64) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	path := j.path(actionID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove response action journal entry: %w", err)
	}
	return syncDirectory(j.dir)
}

func (j *Journal) records(phase JournalPhase, limit int) ([]JournalRecord, error) {
	if j == nil {
		return []JournalRecord{}, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	records, _, err := j.loadLocked()
	if err != nil {
		return nil, err
	}
	filtered := make([]JournalRecord, 0, len(records))
	for _, record := range records {
		if record.Phase == phase {
			filtered = append(filtered, record)
			if limit > 0 && len(filtered) >= limit {
				break
			}
		}
	}
	return filtered, nil
}

func (j *Journal) recover() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return fmt.Errorf("read response action journal: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") && entry.Type().IsRegular() {
			if err := os.Remove(filepath.Join(j.dir, entry.Name())); err != nil {
				return fmt.Errorf("remove incomplete response action journal entry: %w", err)
			}
		}
	}
	records, _, err := j.loadLocked()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, record := range records {
		if record.Phase != JournalExecuting {
			continue
		}
		result := protocol.ResponseActionExecutionResult{
			ResponseActionID: record.Action.ID,
			AgentID:          record.Action.AgentID,
			Status:           "failed",
			Error:            "agent restarted while action execution outcome was indeterminate",
			StartedAt:        timePointer(record.StartedAt),
			FinishedAt:       timePointer(now),
		}
		record.Phase = JournalTerminal
		record.Result = &result
		record.UpdatedAt = now
		if err := j.writeLocked(record); err != nil {
			return fmt.Errorf("recover response action %d: %w", record.Action.ID, err)
		}
	}
	return syncDirectory(j.dir)
}

func (j *Journal) ensureCapacityLocked(record JournalRecord) error {
	records, totalBytes, err := j.loadLocked()
	if err != nil {
		return err
	}
	if len(records) >= j.maxRecords {
		return ErrJournalCapacity
	}
	for _, existing := range records {
		if existing.Phase != JournalTerminal {
			totalBytes += terminalGrowthReserve
		}
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal response action journal entry: %w", err)
	}
	if int64(len(payload)) > maxJournalRecordSize || totalBytes+int64(len(payload))+terminalGrowthReserve > j.maxBytes {
		return ErrJournalCapacity
	}
	return nil
}

func (j *Journal) loadLocked() ([]JournalRecord, int64, error) {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, 0, fmt.Errorf("read response action journal: %w", err)
	}
	records := make([]JournalRecord, 0, len(entries))
	var totalBytes int64
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return nil, 0, fmt.Errorf("unexpected response action journal entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, 0, fmt.Errorf("inspect response action journal entry %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxJournalRecordSize {
			return nil, 0, fmt.Errorf("invalid response action journal entry %q", entry.Name())
		}
		record, err := j.readPathLocked(filepath.Join(j.dir, entry.Name()))
		if err != nil {
			return nil, 0, err
		}
		if entry.Name() != filepath.Base(j.path(record.Action.ID)) {
			return nil, 0, fmt.Errorf("response action journal filename does not match action %d", record.Action.ID)
		}
		records = append(records, record)
		totalBytes += info.Size()
	}
	sort.Slice(records, func(a, b int) bool {
		if records[a].StartedAt.Equal(records[b].StartedAt) {
			return records[a].Action.ID < records[b].Action.ID
		}
		return records[a].StartedAt.Before(records[b].StartedAt)
	})
	return records, totalBytes, nil
}

func (j *Journal) readLocked(actionID int64) (JournalRecord, error) {
	return j.readPathLocked(j.path(actionID))
}

func (j *Journal) readPathLocked(path string) (JournalRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return JournalRecord{}, fmt.Errorf("open response action journal entry: %w", err)
	}
	defer file.Close()
	var record JournalRecord
	decoder := json.NewDecoder(io.LimitReader(file, maxJournalRecordSize+1))
	if err := decoder.Decode(&record); err != nil {
		return JournalRecord{}, fmt.Errorf("decode response action journal entry %q: %w", filepath.Base(path), err)
	}
	if err := validateJournalRecord(record); err != nil {
		return JournalRecord{}, fmt.Errorf("validate response action journal entry %q: %w", filepath.Base(path), err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return JournalRecord{}, fmt.Errorf("response action journal entry %q has trailing data", filepath.Base(path))
		}
		return JournalRecord{}, fmt.Errorf("decode response action journal entry %q: %w", filepath.Base(path), err)
	}
	return record, nil
}

func (j *Journal) writeLocked(record JournalRecord) error {
	if err := validateJournalRecord(record); err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal response action journal entry: %w", err)
	}
	if int64(len(payload)) > maxJournalRecordSize {
		return fmt.Errorf("response action journal entry exceeds %d bytes", maxJournalRecordSize)
	}
	temp, err := os.CreateTemp(j.dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("create response action journal entry: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("secure response action journal entry: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return fmt.Errorf("write response action journal entry: %w", err)
	}
	if _, err := temp.Write([]byte{'\n'}); err != nil {
		temp.Close()
		return fmt.Errorf("write response action journal entry: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync response action journal entry: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close response action journal entry: %w", err)
	}
	if err := os.Rename(tempPath, j.path(record.Action.ID)); err != nil {
		return fmt.Errorf("activate response action journal entry: %w", err)
	}
	return syncDirectory(j.dir)
}

func (j *Journal) path(actionID int64) string {
	return filepath.Join(j.dir, fmt.Sprintf("%020d.json", actionID))
}

func validateJournalRecord(record JournalRecord) error {
	if record.Version != journalVersion {
		return fmt.Errorf("unsupported response action journal version %d", record.Version)
	}
	action := record.Action
	if err := action.Normalize(); err != nil {
		return err
	}
	if record.StartedAt.IsZero() || record.UpdatedAt.IsZero() {
		return fmt.Errorf("response action journal timestamps are required")
	}
	switch record.Phase {
	case JournalAccepted, JournalExecuting:
		if record.Result != nil {
			return fmt.Errorf("non-terminal response action has a result")
		}
	case JournalTerminal:
		if record.Result == nil {
			return fmt.Errorf("terminal response action is missing its result")
		}
		if record.Result.ResponseActionID != record.Action.ID {
			return fmt.Errorf("response action result id does not match the journal action")
		}
		status := strings.ToLower(strings.TrimSpace(record.Result.Status))
		if status != "success" && status != "failed" {
			return fmt.Errorf("invalid response action result status %q", record.Result.Status)
		}
	default:
		return fmt.Errorf("invalid response action journal phase %q", record.Phase)
	}
	return nil
}

func boundedResult(result protocol.ResponseActionExecutionResult) protocol.ResponseActionExecutionResult {
	if result.ResultPayload == nil {
		return result
	}
	payload, err := json.Marshal(result.ResultPayload)
	if err == nil && len(payload) <= maxResultPayloadSize {
		return result
	}
	result.ResultPayload = nil
	message := "result payload omitted because it exceeded the durable result limit"
	if err != nil {
		message = "result payload omitted because it could not be encoded"
	}
	if strings.TrimSpace(result.Error) == "" {
		result.Error = message
	} else {
		result.Error = strings.TrimSpace(result.Error) + "; " + message
	}
	return result
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open response action journal directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync response action journal directory: %w", err)
	}
	return nil
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}
