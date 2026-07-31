package sender

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dynasmon/seagull-agent/internal/spool"
	"github.com/dynasmon/seagull-agent/protocol"
	"github.com/google/uuid"
)

func newTestSender(t *testing.T, baseURL string) (*Sender, *spool.Spool) {
	t.Helper()
	sp, err := spool.New(spool.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	s := New(baseURL, 2*time.Second, 100, "agent-test-1", func() string { return "cred" }, nil)
	s.retries = 0
	s.SetSpool(sp)
	return s, sp
}

func TestSendEventsSpoolsBatchWhenBackendIsUnavailable(t *testing.T) {
	var mu sync.Mutex
	var batchIDs []string
	failing := true
	var observedSpool atomic.Pointer[spool.Spool]
	pendingDuringRequest := make(chan int, 2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if currentSpool := observedSpool.Load(); currentSpool != nil {
			pendingDuringRequest <- currentSpool.Pending()
		}
		mu.Lock()
		batchIDs = append(batchIDs, r.Header.Get(batchIDHeader))
		down := failing
		mu.Unlock()
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": true,
			"durable":  true,
			"received": 1,
		})
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	observedSpool.Store(sp)
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	result, err := s.SendEvents(context.Background(), events)
	if err == nil {
		t.Fatal("expected send failure while backend is down")
	}
	if !IsDurablyQueued(err) || result.Delivered != 0 || result.Durable != 1 {
		t.Fatalf("unexpected queued delivery result=%+v err=%v", result, err)
	}
	if pending := <-pendingDuringRequest; pending != 1 {
		t.Fatalf("batch was not durable before the request, pending=%d", pending)
	}
	if sp.Pending() != 1 {
		t.Fatalf("expected batch spooled, pending=%d", sp.Pending())
	}

	mu.Lock()
	failing = false
	mu.Unlock()

	delivered, err := s.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if delivered != 1 {
		t.Fatalf("expected 1 delivered batch, got %d", delivered)
	}
	if sp.Pending() != 0 {
		t.Fatalf("expected spool drained, pending=%d", sp.Pending())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(batchIDs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(batchIDs))
	}
	if batchIDs[0] == "" {
		t.Fatal("expected batch id header on first attempt")
	}
	if batchIDs[0] != batchIDs[1] {
		t.Fatalf("expected replay to reuse batch id %q, got %q", batchIDs[0], batchIDs[1])
	}
}

func TestSpoolPersistenceFailureSurfacesToTheRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	parent := t.TempDir()
	spoolDir := filepath.Join(parent, "spool")
	sp, err := spool.New(spool.Options{Dir: spoolDir})
	if err != nil {
		t.Fatalf("new spool: %v", err)
	}
	if err := os.Rename(spoolDir, filepath.Join(parent, "spool-moved")); err != nil {
		t.Fatalf("move spool directory: %v", err)
	}
	if err := os.WriteFile(spoolDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace spool directory: %v", err)
	}
	s := New(server.URL, 2*time.Second, 100, "agent-test-1", func() string { return "cred" }, nil)
	s.retries = 0
	s.SetSpool(sp)

	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}
	_, err = s.SendEvents(context.Background(), events)
	if err == nil || !strings.Contains(err.Error(), "persist delivery backlog") {
		t.Fatalf("expected durable backlog error, got %v", err)
	}
	if sp.Stats().EnqueueErrorsTotal != 1 {
		t.Fatalf("enqueue errors=%d want 1", sp.Stats().EnqueueErrorsTotal)
	}
}

func TestSuccessfulStatusWithoutDurableAcknowledgementIsSpooled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}
	if _, err := s.SendEvents(context.Background(), events); !errors.Is(err, ErrUnconfirmedDelivery) {
		t.Fatalf("expected unconfirmed delivery error, got %v", err)
	}
	if sp.Pending() != 1 {
		t.Fatalf("unconfirmed delivery was not retained, pending=%d", sp.Pending())
	}
}

func TestPartialEventAcknowledgementIsSpooled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": true,
			"durable":  true,
			"received": 1,
		})
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []protocol.NetEvent{
		{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()},
		{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()},
	}
	if _, err := s.SendEvents(context.Background(), events); !errors.Is(err, ErrUnconfirmedDelivery) {
		t.Fatalf("expected partial acknowledgement error, got %v", err)
	}
	if sp.Pending() != 1 {
		t.Fatalf("partially acknowledged delivery was not retained, pending=%d", sp.Pending())
	}
}

func TestLegacyEventAcknowledgementIsRejected(t *testing.T) {
	legacy := []byte(`{"received":2,"enqueued":1}`)
	payload := []byte(`[{"agent_id":"a"},{"agent_id":"a"}]`)
	if err := validateAcknowledgement(KindEvents, payload, legacy); !errors.Is(err, ErrUnconfirmedDelivery) {
		t.Fatalf("legacy acknowledgement accepted: %v", err)
	}
}

func TestLegacyVulnerabilityAcknowledgementIsRejected(t *testing.T) {
	payload := []byte(`{"findings":[{"external_id":"CVE-1"},{"external_id":"CVE-2"}]}`)
	legacy := []byte(`{"received_findings":2,"stored_findings":2}`)
	if err := validateAcknowledgement(KindVuln, payload, legacy); !errors.Is(err, ErrUnconfirmedDelivery) {
		t.Fatalf("legacy acknowledgement accepted: %v", err)
	}
}

func TestEventIdentityIsStableAcrossRetry(t *testing.T) {
	var received []protocol.NetEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []protocol.NetEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received = append(received, events...)
		if len(received) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		accepted := true
		durable := true
		count := len(events)
		_ = json.NewEncoder(w).Encode(protocol.EventIngestAcknowledgement{
			Accepted: &accepted,
			Durable:  &durable,
			Received: &count,
		})
	}))
	defer server.Close()

	s := New(server.URL, 2*time.Second, 100, "agent-test-1", func() string { return "cred" }, nil)
	s.retries = 1
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}
	if result, err := s.SendEvents(context.Background(), events); err != nil {
		t.Fatalf("send events: %v", err)
	} else if result.Delivered != 1 || result.Durable != 1 {
		t.Fatalf("unexpected delivery result: %+v", result)
	}
	if len(received) != 2 {
		t.Fatalf("received=%d want 2", len(received))
	}
	if received[0].EventID == "" || received[0].EventID != received[1].EventID {
		t.Fatalf("event identity changed across retry: %#v", received)
	}
	if _, err := uuid.Parse(received[0].EventID); err != nil {
		t.Fatalf("invalid event identity: %v", err)
	}
	if received[0].Extra["event_id"] != received[0].EventID {
		t.Fatalf("event identity was not preserved in extra: %#v", received[0].Extra)
	}
}

func TestAuthenticationErrorsAreSpooledForRecovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	if _, err := s.SendEvents(context.Background(), events); err == nil {
		t.Fatal("expected 401 to surface as error")
	}
	if sp.Pending() != 1 {
		t.Fatalf("expected auth failure to retain telemetry, pending=%d", sp.Pending())
	}
}

func TestPermanentSchemaErrorsAreNotSpooled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	if _, err := s.SendEvents(context.Background(), events); err == nil {
		t.Fatal("expected schema error")
	}
	if sp.Pending() != 0 {
		t.Fatalf("expected schema error not to be spooled, pending=%d", sp.Pending())
	}
}

func TestProtocolIncompatibilityIsNotSpooled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = w.Write([]byte(`{"detail":{"error":"unsupported_protocol","kind":"protocol_version_too_old","agent_protocol_version":1,"server_protocol_version":2,"min_supported":2,"max_supported":2,"message":"upgrade the agent"}}`))
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	_, err := s.SendEvents(context.Background(), events)
	var incompatible *protocol.Incompatibility
	if !errors.As(err, &incompatible) {
		t.Fatalf("expected structured incompatibility, got %v", err)
	}
	if sp.Pending() != 0 {
		t.Fatalf("protocol incompatibility must not be spooled, pending=%d", sp.Pending())
	}
}

func TestBatchPayloadConflictIsNotSpooled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"detail":{"error":"batch_payload_conflict","message":"batch id was reused with different content"}}`))
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []protocol.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	if _, err := s.SendEvents(context.Background(), events); !errors.Is(err, ErrInvalidDeliveryPayload) {
		t.Fatalf("expected invalid delivery payload, got %v", err)
	}
	if sp.Pending() != 0 {
		t.Fatalf("batch payload conflict must not be spooled, pending=%d", sp.Pending())
	}
}

func TestFlushIsNoopWhenSpoolIsEmpty(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := newTestSender(t, server.URL)
	delivered, err := s.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if delivered != 0 || calls != 0 {
		t.Fatalf("expected inert flush, delivered=%d calls=%d", delivered, calls)
	}
}
