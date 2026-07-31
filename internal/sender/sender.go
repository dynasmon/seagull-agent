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
	"sync"
	"time"

	"github.com/dynasmon/seagull-agent/internal/agentauth"
	"github.com/dynasmon/seagull-agent/internal/spool"
	"github.com/dynasmon/seagull-agent/protocol"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	batchIDHeader = "X-Seagull-Batch-Id"

	KindEvents    = "events"
	KindInventory = "inventory"
	KindVuln      = "vuln"
)

var (
	ErrUnconfirmedDelivery    = errors.New("server did not confirm durable delivery")
	ErrInvalidDeliveryPayload = errors.New("invalid delivery payload")
)

type EventDeliveryResult struct {
	Status    int
	Attempted int
	Delivered int
	Durable   int
}

type DurableQueueError struct {
	Err error
}

func (e *DurableQueueError) Error() string {
	if e == nil || e.Err == nil {
		return "delivery retained in the durable queue"
	}
	return e.Err.Error()
}

func (e *DurableQueueError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func IsDurablyQueued(err error) bool {
	var queued *DurableQueueError
	return errors.As(err, &queued)
}

type Sender struct {
	baseURL        string
	client         *http.Client
	maxBatch       int
	retries        int
	agentID        string
	credentialFunc func() string
	spool          *spool.Spool
	deliveryMu     sync.Mutex
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

func (s *Sender) SendEvents(ctx context.Context, events []protocol.NetEvent) (EventDeliveryResult, error) {
	result := EventDeliveryResult{Attempted: len(events)}
	if s.baseURL == "" {
		return result, fmt.Errorf("sender baseURL is empty")
	}
	if len(events) == 0 {
		return result, nil
	}

	for i := 0; i < len(events); i += s.maxBatch {
		j := i + s.maxBatch
		if j > len(events) {
			j = len(events)
		}
		for index := i; index < j; index++ {
			ensureEventIdentity(&events[index])
		}

		payload, err := json.Marshal(events[i:j])
		if err != nil {
			return result, fmt.Errorf("marshal events: %w", err)
		}

		status, _, err := s.deliver(ctx, KindEvents, "", payload)
		result.Status = status
		if err != nil {
			if IsDurablyQueued(err) {
				result.Durable += j - i
			}
			return result, err
		}
		result.Delivered += j - i
		result.Durable += j - i
	}

	return result, nil
}

func ensureEventIdentity(event *protocol.NetEvent) {
	if event.Extra == nil {
		event.Extra = map[string]interface{}{}
	}
	eventID := strings.TrimSpace(event.EventID)
	if eventID == "" {
		if existing, ok := event.Extra["event_id"].(string); ok {
			eventID = strings.TrimSpace(existing)
		}
	}
	parsed, err := uuid.Parse(eventID)
	if err != nil {
		parsed = uuid.New()
	}
	event.EventID = parsed.String()
	event.Extra["event_id"] = event.EventID
}

func (s *Sender) Flush(ctx context.Context) (int, error) {
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	if s.spool == nil || s.spool.Pending() == 0 {
		return 0, nil
	}
	return s.spool.Drain(ctx, s.spoolDrainLimit(), func(env spool.Envelope) error {
		endpoint := s.endpointFor(env.Kind)
		if endpoint == "" {
			return spool.Permanent(fmt.Errorf("unknown delivery kind: %s", env.Kind))
		}
		status, _, err := s.postWithRetry(ctx, env.Kind, endpoint, env.ID, env.Payload)
		if err != nil && (isPermanentDeliveryStatus(status) || errors.Is(err, ErrInvalidDeliveryPayload)) {
			return spool.Permanent(err)
		}
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
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	if strings.TrimSpace(batchID) == "" {
		batchID = spool.NewID()
	}
	endpoint := s.endpointFor(kind)
	if endpoint == "" {
		return 0, nil, fmt.Errorf("unknown delivery kind: %s", kind)
	}

	if s.spool == nil {
		return s.postWithRetry(ctx, kind, endpoint, batchID, payload)
	}

	envelope, enqueueErr := s.spool.EnqueuePriority(batchID, kind, deliveryPriority(kind), payload)
	if enqueueErr != nil {
		status, body, err := s.postWithRetry(ctx, kind, endpoint, batchID, payload)
		if err != nil {
			return status, body, errors.Join(fmt.Errorf("persist delivery backlog: %w", enqueueErr), err)
		}
		return status, body, nil
	}

	status, body, err := s.postWithRetry(ctx, kind, endpoint, batchID, payload)
	if err == nil {
		if acknowledgeErr := s.spool.Acknowledge(envelope); acknowledgeErr != nil {
			return status, body, fmt.Errorf("commit confirmed delivery: %w", acknowledgeErr)
		}
		return status, body, nil
	}
	if !isSpoolable(err, status) {
		if rejectErr := s.spool.Reject(envelope); rejectErr != nil {
			return status, body, errors.Join(err, fmt.Errorf("discard rejected delivery: %w", rejectErr))
		}
		return status, body, err
	}
	return status, body, &DurableQueueError{Err: err}
}

func deliveryPriority(kind string) int {
	switch strings.TrimSpace(kind) {
	case KindInventory, KindVuln:
		return 100
	case KindEvents:
		return 10
	default:
		return 0
	}
}

func (s *Sender) postWithRetry(ctx context.Context, kind string, url string, batchID string, payload []byte) (int, []byte, error) {
	var lastErr error
	lastStatus := 0
	var lastBody []byte

	for attempt := 0; attempt <= s.retries; attempt++ {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt); err != nil {
				return lastStatus, lastBody, err
			}
		}

		status, body, err := s.postOnce(ctx, kind, url, batchID, payload)
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

func (s *Sender) postOnce(ctx context.Context, kind string, url string, batchID string, payload []byte) (int, []byte, error) {
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
		if deliveryErr := decodePermanentDeliveryError(resp.StatusCode, body); deliveryErr != nil {
			return resp.StatusCode, body, deliveryErr
		}
		return resp.StatusCode, body, fmt.Errorf("ingest returned status=%d", resp.StatusCode)
	}
	if err := validateAcknowledgement(kind, payload, body); err != nil {
		return resp.StatusCode, body, err
	}

	return resp.StatusCode, body, nil
}

func (s *Sender) SendInventorySnapshot(ctx context.Context, snap protocol.InventorySnapshot) (int, error) {
	if s.baseURL == "" {
		return 0, fmt.Errorf("sender baseURL is empty")
	}

	if snap.SchemaVersion <= 0 {
		snap.SchemaVersion = 1
	}
	if snap.OS == nil {
		snap.OS = map[string]interface{}{}
	}
	if snap.Packages == nil {
		snap.Packages = []protocol.PackageEntry{}
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
	if errors.Is(err, ErrUnconfirmedDelivery) {
		return true
	}
	if status == 0 {
		return isRetryableNetErr(err)
	}
	if status >= 500 {
		return true
	}
	return false
}

func isSpoolable(err error, status int) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrInvalidDeliveryPayload) {
		return false
	}
	var incompatible *protocol.Incompatibility
	if errors.As(err, &incompatible) {
		return false
	}
	if errors.Is(err, ErrUnconfirmedDelivery) {
		return true
	}
	if status == 0 {
		return true
	}
	switch status {
	case http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusRequestTimeout,
		http.StatusConflict,
		http.StatusLocked,
		http.StatusTooEarly,
		http.StatusUpgradeRequired,
		http.StatusTooManyRequests:
		return true
	default:
		return status >= 500
	}
}

func decodePermanentDeliveryError(status int, body []byte) error {
	if incompatible, ok := protocol.DecodeIncompatibility(status, body); ok {
		return incompatible
	}
	if status != http.StatusConflict {
		return nil
	}
	var envelope struct {
		Error  string `json:"error"`
		Detail struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		} `json:"detail"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil
	}
	errorCode := strings.TrimSpace(envelope.Error)
	message := ""
	if errorCode == "" {
		errorCode = strings.TrimSpace(envelope.Detail.Error)
		message = strings.TrimSpace(envelope.Detail.Message)
	}
	if errorCode != "batch_payload_conflict" {
		return nil
	}
	if message == "" {
		message = "batch id was reused with different content"
	}
	return fmt.Errorf("%w: %s", ErrInvalidDeliveryPayload, message)
}

func validateAcknowledgement(kind string, payload []byte, body []byte) error {
	switch strings.TrimSpace(kind) {
	case KindEvents:
		var events []json.RawMessage
		if err := json.Unmarshal(payload, &events); err != nil {
			return fmt.Errorf("%w: events: %v", ErrInvalidDeliveryPayload, err)
		}
		var acknowledgement protocol.EventIngestAcknowledgement
		if err := json.Unmarshal(body, &acknowledgement); err != nil {
			return fmt.Errorf("%w: decode event acknowledgement: %v", ErrUnconfirmedDelivery, err)
		}
		if explicitAcknowledgement(acknowledgement.Accepted, acknowledgement.Durable) &&
			acknowledgement.Received != nil &&
			*acknowledgement.Received == len(events) {
			return nil
		}
		return fmt.Errorf("%w: event batch was not fully accepted", ErrUnconfirmedDelivery)
	case KindInventory:
		var snapshot map[string]interface{}
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return fmt.Errorf("%w: inventory: %v", ErrInvalidDeliveryPayload, err)
		}
		var acknowledgement protocol.InventoryAcknowledgement
		if err := json.Unmarshal(body, &acknowledgement); err != nil {
			return fmt.Errorf("%w: decode inventory acknowledgement: %v", ErrUnconfirmedDelivery, err)
		}
		if explicitAcknowledgement(acknowledgement.Accepted, acknowledgement.Durable) {
			return nil
		}
		return fmt.Errorf("%w: inventory snapshot was not durably stored", ErrUnconfirmedDelivery)
	case KindVuln:
		var batch struct {
			Findings []json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal(payload, &batch); err != nil {
			return fmt.Errorf("%w: vulnerability batch: %v", ErrInvalidDeliveryPayload, err)
		}
		var acknowledgement protocol.VulnerabilityAcknowledgement
		if err := json.Unmarshal(body, &acknowledgement); err != nil {
			return fmt.Errorf("%w: decode vulnerability acknowledgement: %v", ErrUnconfirmedDelivery, err)
		}
		if explicitAcknowledgement(acknowledgement.Accepted, acknowledgement.Durable) &&
			acknowledgement.ReceivedFindings != nil &&
			*acknowledgement.ReceivedFindings == len(batch.Findings) {
			return nil
		}
		return fmt.Errorf("%w: vulnerability batch was not fully accepted", ErrUnconfirmedDelivery)
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidDeliveryPayload, kind)
	}
}

func explicitAcknowledgement(accepted *bool, durable *bool) bool {
	return accepted != nil && durable != nil && *accepted && *durable
}

func isPermanentDeliveryStatus(status int) bool {
	switch status {
	case http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusGone,
		http.StatusRequestEntityTooLarge,
		http.StatusRequestURITooLong,
		http.StatusUnsupportedMediaType,
		http.StatusUnprocessableEntity,
		http.StatusUpgradeRequired,
		http.StatusRequestHeaderFieldsTooLarge:
		return true
	default:
		return false
	}
}

func isRetryableNetErr(err error) bool {
	return errors.Is(err, unix.ECONNRESET) ||
		errors.Is(err, unix.EPIPE) ||
		errors.Is(err, unix.ETIMEDOUT) ||
		errors.Is(err, unix.ECONNREFUSED)
}

func sleepBackoff(ctx context.Context, attempt int) error {
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
