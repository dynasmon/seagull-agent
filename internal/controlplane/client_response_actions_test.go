package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListPendingResponseActionsOK(t *testing.T) {
	reqAt := time.Now().UTC().Truncate(time.Second)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/response-actions/pending" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := strings.TrimSpace(r.Header.Get("X-Agent-ID")); got != "agent-1" {
			t.Fatalf("unexpected X-Agent-ID: %q", got)
		}
		if got := strings.TrimSpace(r.Header.Get("X-Agent-Credential")); got != "cred-1" {
			t.Fatalf("unexpected X-Agent-Credential: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"action_type":"block_ip","agent_id":"agent-1","status":"pending","payload":{"ip":"1.1.1.1"},"requested_at":"` + reqAt.Format(time.RFC3339) + `","expires_at":null}]`))
	}))
	defer ts.Close()

	c := New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	out, err := c.ListPendingResponseActions(context.Background())
	if err != nil {
		t.Fatalf("ListPendingResponseActions error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 action, got %d", len(out))
	}
	if out[0].ID != 1 || out[0].AgentID != "agent-1" || out[0].ActionType != "block_ip" {
		t.Fatalf("unexpected action payload: %+v", out[0])
	}
	if out[0].RequestedAt.IsZero() {
		t.Fatalf("expected non-zero requested_at")
	}
}

func TestListPendingResponseActionsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agents/response-actions/pending" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := New(ts.URL, 5*time.Second, "agent-1", nil, ts.Client())
	out, err := c.ListPendingResponseActions(context.Background())
	if err != nil {
		t.Fatalf("ListPendingResponseActions error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no actions, got %d", len(out))
	}
}

func TestListPendingResponseActionsRejectsMalformedAction(t *testing.T) {
	reqAt := time.Now().UTC().Truncate(time.Second)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agents/response-actions/pending" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"id":0,"action_type":"block_ip","agent_id":"agent-1","status":"pending","requested_at":"` + reqAt.Format(time.RFC3339) + `"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := New(ts.URL, 5*time.Second, "agent-1", nil, ts.Client())
	_, err := c.ListPendingResponseActions(context.Background())
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestReportResponseActionResultOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/response-actions/results" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := strings.TrimSpace(r.Header.Get("X-Agent-ID")); got != "agent-1" {
			t.Fatalf("unexpected X-Agent-ID: %q", got)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	now := time.Now().UTC().Truncate(time.Second)
	err := c.ReportResponseActionResult(context.Background(), ResponseActionExecutionResult{
		ResponseActionID: 12,
		AgentID:          "agent-1",
		Status:           "success",
		ResultPayload:    map[string]interface{}{"ok": true},
		StartedAt:        &now,
		FinishedAt:       &now,
	})
	if err != nil {
		t.Fatalf("ReportResponseActionResult error: %v", err)
	}
}

func TestReportResponseActionResultFallbackPath(t *testing.T) {
	var firstPathSeen bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agents/response-actions/results" {
			firstPathSeen = true
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/agents/response/actions/results" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := New(ts.URL, 5*time.Second, "agent-1", nil, ts.Client())
	err := c.ReportResponseActionResult(context.Background(), ResponseActionExecutionResult{
		ResponseActionID: 13,
		Status:           "failed",
		Error:            "x",
	})
	if err != nil {
		t.Fatalf("ReportResponseActionResult error: %v", err)
	}
	if !firstPathSeen {
		t.Fatalf("expected primary path attempt before fallback")
	}
}
