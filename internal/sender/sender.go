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

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type Sender struct {
	baseURL         string
	client          *http.Client
	maxBatch        int
	retries         int
	agentID         string
	credentialFunc  func() string
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

func (s *Sender) applyAuthHeaders(req *http.Request) {
	if s.agentID != "" {
		req.Header.Set("X-Agent-ID", s.agentID)
	}
	if s.credentialFunc == nil {
		return
	}
	if cred := strings.TrimSpace(s.credentialFunc()); cred != "" {
		req.Header.Set("X-Agent-Credential", cred)
	}
}

func (s *Sender) SendEvents(ctx context.Context, events []model.NetEvent) (int, error) {
	if s.baseURL == "" {
		return 0, fmt.Errorf("sender baseURL is empty")
	}
	if len(events) == 0 {
		return 0, nil
	}

	endpoint := s.baseURL + "/ingest/events"
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

		status, err := s.postWithRetry(ctx, endpoint, payload)
		lastStatus = status
		if err != nil {
			return lastStatus, err
		}
	}

	return lastStatus, nil
}

func (s *Sender) postWithRetry(ctx context.Context, url string, payload []byte) (int, error) {
	var lastErr error
	lastStatus := 0

	for attempt := 0; attempt <= s.retries; attempt++ {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt); err != nil {
				return lastStatus, err
			}
		}

		status, err := s.postOnce(ctx, url, payload)
		lastStatus = status

		if err == nil {
			return status, nil
		}

		lastErr = err
		if !isRetryable(err, status) {
			return status, err
		}
	}

	return lastStatus, lastErr
}

func (s *Sender) postWithRetryRead(ctx context.Context, url string, payload []byte) (int, []byte, error) {
	var lastErr error
	lastStatus := 0
	var lastBody []byte

	for attempt := 0; attempt <= s.retries; attempt++ {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt); err != nil {
				return lastStatus, lastBody, err
			}
		}

		status, body, err := s.postOnceRead(ctx, url, payload)
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

func (s *Sender) postOnce(ctx context.Context, url string, payload []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	s.applyAuthHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post ingest: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("ingest returned status=%d", resp.StatusCode)
	}

	return resp.StatusCode, nil
}

func (s *Sender) postOnceRead(ctx context.Context, url string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	s.applyAuthHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("post ingest: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
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

	endpoint := s.baseURL + "/inventory"
	return s.postWithRetry(ctx, endpoint, payload)
}

func (s *Sender) SendVulnIngest(ctx context.Context, payload []byte) (int, []byte, error) {
	if s.baseURL == "" {
		return 0, nil, fmt.Errorf("sender baseURL is empty")
	}
	if len(payload) == 0 {
		return 0, nil, nil
	}

	endpoint := s.baseURL + "/vuln/ingest"
	return s.postWithRetryRead(ctx, endpoint, payload)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
