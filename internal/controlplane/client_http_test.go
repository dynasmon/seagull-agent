package controlplane_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/seagull-agent/internal/agentauth"
	"github.com/dynasmon/seagull-agent/internal/controlplane"
	"github.com/dynasmon/seagull-agent/protocol"
)

func TestEnrollOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/enroll" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get(agentauth.HeaderAgentID); got != "agent-1" {
			t.Fatalf("unexpected agent id header: %q", got)
		}
		if got := r.Header.Get(agentauth.HeaderBootstrapToken); got != "boot-1" {
			t.Fatalf("unexpected bootstrap header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_id":"agent-1","credential":{"credential":"cred-1"}}`))
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", nil, ts.Client())
	out, err := c.Enroll(context.Background(), protocol.EnrollRequest{AgentID: "agent-1", BootstrapToken: "boot-1"})
	if err != nil {
		t.Fatalf("Enroll error: %v", err)
	}
	if out.AgentID != "agent-1" || out.Credential.Credential != "cred-1" {
		t.Fatalf("unexpected enroll response: %+v", out)
	}
}

func TestEnrollReturnsStructuredHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token consumed", http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := controlplane.New(ts.URL, time.Second, "agent-1", nil, ts.Client())
	_, err := client.Enroll(context.Background(), protocol.EnrollRequest{AgentID: "agent-1"})
	var httpErr *controlplane.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected HTTPError, got %v", err)
	}
	if httpErr.StatusCode != http.StatusUnauthorized || httpErr.Body != "token consumed" {
		t.Fatalf("unexpected HTTP error: %+v", httpErr)
	}
}

func TestHeartbeatAppliesCredentialsAndStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/heartbeat" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get(agentauth.HeaderAgentID); got != "agent-1" {
			t.Fatalf("missing agent id header: %q", got)
		}
		if got := r.Header.Get(agentauth.HeaderCredential); got != "cred-1" {
			t.Fatalf("missing credential header: %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("missing content type: %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var hb protocol.HeartbeatRequest
		if err := json.Unmarshal(body, &hb); err != nil {
			t.Fatalf("bad heartbeat body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	negotiated, err := c.Heartbeat(context.Background(), protocol.HeartbeatRequest{Status: "ok"})
	if err != nil {
		t.Fatalf("Heartbeat error: %v", err)
	}
	if !negotiated.Degraded {
		t.Fatalf("legacy heartbeat must be degraded: %+v", negotiated)
	}
}

func TestHeartbeatServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", nil, ts.Client())
	_, err := c.Heartbeat(context.Background(), protocol.HeartbeatRequest{Status: "ok"})
	if err == nil || !strings.Contains(err.Error(), "status=500") {
		t.Fatalf("expected status=500 error, got %v", err)
	}
}

func TestHeartbeatNegotiatesServerDescriptor(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, protocol.LocalDescriptor())
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	negotiated, err := c.Heartbeat(context.Background(), protocol.HeartbeatRequest{
		Status:          "ok",
		ProtocolVersion: protocol.Version,
	})
	if err != nil {
		t.Fatalf("Heartbeat error: %v", err)
	}
	if negotiated.Degraded || negotiated.ProtocolVersion != protocol.Version {
		t.Fatalf("unexpected negotiation: %+v", negotiated)
	}
}

func TestHeartbeatDecodesStructuredIncompatibility(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUpgradeRequired)
		_, _ = w.Write([]byte(`{"detail":{"kind":"protocol_version_too_old","agent_protocol_version":1,"server_protocol_version":2,"min_supported":2,"max_supported":2,"agent_event_schema_version":1,"event_schema_version":1,"min_event_schema":1,"max_event_schema":1,"message":"upgrade the agent"}}`))
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	_, err := c.Heartbeat(context.Background(), protocol.HeartbeatRequest{Status: "ok"})
	var incompatible *protocol.Incompatibility
	if !errors.As(err, &incompatible) {
		t.Fatalf("expected structured incompatibility, got %v", err)
	}
	if incompatible.Kind != protocol.IncompatibleProtocolTooOld || incompatible.ServerMin != 2 {
		t.Fatalf("unexpected incompatibility: %+v", incompatible)
	}
}

func TestGetConfigOKAndEmpty(t *testing.T) {
	mode := "json"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/config" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if mode == "json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"modules":{"vulnscanner":{"enabled":true}}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())

	out, err := c.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig error: %v", err)
	}
	if _, ok := out["modules"]; !ok {
		t.Fatalf("expected modules key, got %+v", out)
	}

	mode = "empty"
	out, err = c.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig empty error: %v", err)
	}
	if out == nil || len(out) != 0 {
		t.Fatalf("expected empty map, got %+v", out)
	}
}

func TestRotateCredentialOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/credential/rotate" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential":"cred-2","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	out, err := c.RotateCredential(context.Background())
	if err != nil {
		t.Fatalf("RotateCredential error: %v", err)
	}
	if out.Credential != "cred-2" {
		t.Fatalf("unexpected credential: %+v", out)
	}
}

func TestRenewCertificateMissingCert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/certificate/renew" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"serial_hex":"ab","not_after":"2030-01-01T00:00:00Z"}`))
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	_, err := c.RenewCertificate(context.Background(), "csr")
	if err == nil || !strings.Contains(err.Error(), "missing certificate") {
		t.Fatalf("expected missing certificate error, got %v", err)
	}
}

func TestEnrollRejectsOversizedResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), (4<<20)+1))
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, time.Second, "agent-1", nil, ts.Client())
	_, err := c.Enroll(context.Background(), protocol.EnrollRequest{AgentID: "agent-1"})
	if err == nil || !strings.Contains(err.Error(), "body exceeds") {
		t.Fatalf("expected oversized response rejection, got %v", err)
	}
}

func TestControlPlaneErrorsBoundAndNormalizeResponseBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(append(bytes.Repeat([]byte("x\n"), 4096), []byte("sensitive-tail")...))
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, time.Second, "agent-1", nil, ts.Client())
	_, err := c.GetConfig(context.Background())
	var httpErr *controlplane.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected HTTP error, got %v", err)
	}
	if strings.Contains(httpErr.Body, "\n") {
		t.Fatalf("expected normalized error body, got %q", httpErr.Body)
	}
	if strings.Contains(httpErr.Body, "sensitive-tail") {
		t.Fatalf("expected bounded error body, got %q", httpErr.Body)
	}
	if !strings.HasSuffix(httpErr.Body, "[truncated]") {
		t.Fatalf("expected truncation marker, got %q", httpErr.Body)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
}
