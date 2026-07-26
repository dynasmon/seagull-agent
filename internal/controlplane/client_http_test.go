package controlplane_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/agentauth"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
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
	out, err := c.Enroll(context.Background(), controlplane.EnrollRequest{AgentID: "agent-1", BootstrapToken: "boot-1"})
	if err != nil {
		t.Fatalf("Enroll error: %v", err)
	}
	if out.AgentID != "agent-1" || out.Credential.Credential != "cred-1" {
		t.Fatalf("unexpected enroll response: %+v", out)
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
		var hb controlplane.HeartbeatRequest
		if err := json.Unmarshal(body, &hb); err != nil {
			t.Fatalf("bad heartbeat body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", func() string { return "cred-1" }, ts.Client())
	if err := c.Heartbeat(context.Background(), controlplane.HeartbeatRequest{Status: "ok"}); err != nil {
		t.Fatalf("Heartbeat error: %v", err)
	}
}

func TestHeartbeatServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := controlplane.New(ts.URL, 5*time.Second, "agent-1", nil, ts.Client())
	err := c.Heartbeat(context.Background(), controlplane.HeartbeatRequest{Status: "ok"})
	if err == nil || !strings.Contains(err.Error(), "status=500") {
		t.Fatalf("expected status=500 error, got %v", err)
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
