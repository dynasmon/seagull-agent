package sender

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/spool"
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		batchIDs = append(batchIDs, r.Header.Get(batchIDHeader))
		down := failing
		mu.Unlock()
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []model.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	if _, err := s.SendEvents(context.Background(), events); err == nil {
		t.Fatal("expected send failure while backend is down")
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

func TestClientErrorsAreNotSpooled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	s, sp := newTestSender(t, server.URL)
	events := []model.NetEvent{{AgentID: "agent-test-1", EventType: "flow", Timestamp: time.Now().UTC()}}

	if _, err := s.SendEvents(context.Background(), events); err == nil {
		t.Fatal("expected 401 to surface as error")
	}
	if sp.Pending() != 0 {
		t.Fatalf("expected auth failures not to be spooled, pending=%d", sp.Pending())
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
