package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"syscall"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/agentauth"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/spool"
)

const (
	batchIDHeader = "X-Seagull-Batch-Id"

	KindEvents    = "events"
	KindInventory = "inventory"
	KindVuln      = "vuln"
)

type Sender struct {
	baseURL        string
	client         *http.Client
	maxBatch       int
	retries        int
	agentID        string
	credentialFunc func() string
	spool          *spool.Spool
}

func New(baseURL string, timeout time.Duration, maxBatch int, agentID string, credentialFunc func() string, httpClient *http.Client) *Sender {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if maxBatch <= 0 {
		maxBatch = 300
	}

	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	httpClient.Timeout = timeout

	return &Sender{
		baseURL:        baseURL,
		client:         httpClient,
		maxBatch:       maxBatch,
		retries:        3,
		agentID:        strings.TrimSpace(agentID),
		credentialFunc: credentialFunc,
	}
}

func (s *Sender) SetSpool(sp *spool.Spool) {
	if sp != nil && sp.Enabled() {
		s.spool = sp
	}
}

func (s *Sender) SpoolStats() spool.Stats {
	if s.spool == nil {
		return spool.Stats{}
	}
	return s.spool.Stats()
}

func (s *Sender) SendEvents(ctx context.Context, events []model.NetEvent) (int, error) {
	if s.baseURL == "" {
		return 0, fmt.Errorf("sender baseURL is empty")
	}
	if len(events) == 0 {
		return 0, nil
	}

	lastStatus := 0

	for i := 0; i < len(events); i += s.maxBatch {
		j := i + s.maxBatch
		if j > len(events) {
			j = len(events)
		}

		payload, err := json.Marshal(events[i:j])
		if err != nil {
			return lastStatus, fmt.Errorf("marshal events: %w", err)
		}

		status, _, err := s.deliver(ctx, KindEvents, "", payload)
		lastStatus = status
		if err != nil {
			return lastStatus, err
		}
	}

	return lastStatus, nil
}

func (s *Sender) Flush(ctx context.Context) (int, error) {
	if s.spool == nil || s.spool.Pending() == 0 {
		return 0, nil
	}
	return s.spool.Drain(ctx, s.spoolDrainLimit(), func(env spool.Envelope) error {
		endpoint := s.endpointFor(env.Kind)
		if endpoint == "" {
			return nil
		}
		_, _, err := s.postWithRetry(ctx, endpoint, env.ID, env.Payload)
		return err
	})
}

func (s *Sender) spoolDrainLimit() int {
	limit := s.maxBatch / 10
	if limit < 8 {
		limit = 8
	}
	if limit > 64 {
		limit = 64
	}
	return limit
}

func (s *Sender) endpointFor(kind string) string {
	switch strings.TrimSpace(kind) {
	case KindEvents:
		return s.baseURL + "/ingest/events"
	case KindInventory:
		return s.baseURL + "/inventory"
	case KindVuln:
		return s.baseURL + "/vuln/ingest"
	default:
		return ""
	}
}

func (s *Sender) deliver(ctx context.Context, kind string, batchID string, payload []byte) (int, []byte, error) {
	if strings.TrimSpace(batchID) == "" {
		batchID = spool.NewID()
	}
	endpoint := s.endpointFor(kind)
	if endpoint == "" {
		return 0, nil, fmt.Errorf("unknown delivery kind: %s", kind)
	}

	status, body, err := s.postWithRetry(ctx, endpoint, batchID, payload)
	if err != nil && s.spool != nil && isSpoolable(err, status) {
		if _, spoolErr := s.spool.Enqueue(batchID, kind, payload); spoolErr == nil {
			return status, body, err
		}
	}
	return status, body, err
}

func (s *Sender) postWithRetry(ctx context.Context, url string, batchID string, payload []byte) (int, []byte, error) {
	var lastErr error
	lastStatus := 0
	var lastBody []byte

	for attempt := 0; attempt <= s.retries; attempt++ {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt); err != nil {
				return lastStatus, lastBody, err
			}
		}

		status, body, err := s.postOnce(ctx, url, batchID, payload)
		lastStatus = status
		lastBody = body

		if err == nil {
			return status, body, nil
		}

		lastErr = err
		if !isRetryable(err, status) {
			return status, body, err
		}
	}

	return lastStatus, lastBody, lastErr
}

func (s *Sender) postOnce(ctx context.Context, url string, batchID string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(batchID) != "" {
		req.Header.Set(batchIDHeader, batchID)
	}
	agentauth.ApplyCredentialHeaders(req, s.agentID, s.credentialFunc)

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("post ingest: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, body, fmt.Errorf("ingest returned status=%d", resp.StatusCode)
	}

	return resp.StatusCode, body, nil
}

func (s *Sender) SendInventorySnapshot(ctx context.Context, snap model.InventorySnapshot) (int, error) {
	if s.baseURL == "" {
		return 0, fmt.Errorf("sender baseURL is empty")
	}

	// Ensure required fields match backend schema expectations.
	if snap.SchemaVersion <= 0 {
		snap.SchemaVersion = 1
	}
	if snap.OS == nil {
		snap.OS = map[string]interface{}{}
	}
	if snap.Packages == nil {
		snap.Packages = []model.PackageEntry{}
	}
	if snap.Extra == nil {
		snap.Extra = map[string]interface{}{}
	}

	payload, err := json.Marshal(snap)
	if err != nil {
		return 0, fmt.Errorf("marshal inventory snapshot: %w", err)
	}

	status, _, err := s.deliver(ctx, KindInventory, "", payload)
	return status, err
}

func (s *Sender) SendVulnIngest(ctx context.Context, payload []byte) (int, []byte, error) {
	if s.baseURL == "" {
		return 0, nil, fmt.Errorf("sender baseURL is empty")
	}
	if len(payload) == 0 {
		return 0, nil, nil
	}

	return s.deliver(ctx, KindVuln, "", payload)
}

func isRetryable(err error, status int) bool {
	if status == 0 {
		return isRetryableNetErr(err)
	}
	// Respect server backpressure: retrying 429 immediately amplifies overload.
	if status >= 500 {
		return true
	}
	return false
}

func isSpoolable(err error, status int) bool {
	if err == nil {
		return false
	}
	if status == 0 {
		return true
	}
	return status == http.StatusTooManyRequests || status >= 500
}

func isRetryableNetErr(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.ECONNREFUSED)
}

func sleepBackoff(ctx context.Context, attempt int) error {
	// 200ms, 400ms, 800ms... + jitter (max ~200ms)
	base := 200 * time.Millisecond
	d := base * time.Duration(1<<min(attempt, 4))
	jitter := time.Duration(rand.Intn(200)) * time.Millisecond
	wait := d + jitter

	t := time.NewTimer(wait)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
