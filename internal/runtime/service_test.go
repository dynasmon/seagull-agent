package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/transport"
	"github.com/dynasmon/seagull-agent/protocol"
)

func runtimeTestConfig(baseURL string, dir string) agentcfg.Config {
	return agentcfg.Config{
		AgentID:                          "agent-runtime-1",
		APIURL:                           baseURL + "/agent",
		Sources:                          []string{},
		Interval:                         10 * time.Millisecond,
		HTTPTimeout:                      time.Second,
		SenderMaxBatch:                   100,
		Profile:                          protocol.ProfileSensor,
		SpoolDir:                         filepath.Join(dir, "spool"),
		SpoolMaxBytes:                    1 << 20,
		SpoolMaxAge:                      time.Hour,
		SpoolMaxItems:                    100,
		AgentConfigFile:                  filepath.Join(dir, "config.json"),
		AgentIdentityStateFile:           filepath.Join(dir, "identity.json"),
		AgentCredential:                  "credential",
		CredentialFile:                   filepath.Join(dir, "credential"),
		ForceEnrollOnStart:               true,
		ControlEnrollTimeout:             time.Second,
		ControlHeartbeatEvery:            10 * time.Millisecond,
		ControlConfigEvery:               10 * time.Millisecond,
		ControlResponsePollEvery:         10 * time.Millisecond,
		CredentialRotateEvery:            time.Hour,
		CredentialRotateBefore:           time.Hour,
		CertRotateEvery:                  time.Hour,
		LogSummaryEvery:                  time.Hour,
		LogHeartbeatEvery:                time.Hour,
		SyscollectEvery:                  time.Hour,
		VulnScanEvery:                    time.Hour,
		TopologyActiveDiscoveryRateLimit: 1,
	}
}

func TestEffectiveCapabilitiesHonorLocalResponsePolicy(t *testing.T) {
	service := &Service{
		cfg: agentcfg.Config{
			Profile:            protocol.ProfileManaged,
			AllowShellExec:     false,
			ShellExecAllowlist: []string{"/usr/bin/true"},
		},
	}
	capabilities := service.effectiveCapabilities()
	actionTypes, ok := capabilities["response_action_types"].([]string)
	if !ok {
		t.Fatalf("unexpected response action capability type: %T", capabilities["response_action_types"])
	}
	for _, actionType := range actionTypes {
		if actionType == protocol.ActionRunShellCommand {
			t.Fatalf("shell execution reported while disabled")
		}
		if actionType == protocol.ActionBlockOutboundIP || actionType == protocol.ActionUnblockOutboundIP {
			t.Fatalf("firewall action reported without a firewall backend")
		}
	}
	if capabilities["shell_exec"] != false {
		t.Fatalf("shell execution capability should be false")
	}

	service.cfg.AllowShellExec = true
	service.firewallTool = "nft"
	capabilities = service.effectiveCapabilities()
	actionTypes = capabilities["response_action_types"].([]string)
	expected := map[string]bool{
		protocol.ActionRunShellCommand:   false,
		protocol.ActionBlockOutboundIP:   false,
		protocol.ActionUnblockOutboundIP: false,
	}
	for _, actionType := range actionTypes {
		if _, exists := expected[actionType]; exists {
			expected[actionType] = true
		}
	}
	for actionType, present := range expected {
		if !present {
			t.Fatalf("expected response action capability %s", actionType)
		}
	}
	if capabilities["shell_exec"] != true {
		t.Fatalf("shell execution capability should be true")
	}
}

func TestServiceRejectsUnsupportedServerBeforeStartingCollectors(t *testing.T) {
	var configCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/agent/health":
			w.WriteHeader(http.StatusNoContent)
		case "/agent/agents/heartbeat":
			json.NewEncoder(w).Encode(protocol.Descriptor{
				ProtocolVersion:    2,
				MinSupported:       2,
				MaxSupported:       2,
				EventSchemaVersion: 2,
				MinEventSchema:     2,
				MaxEventSchema:     2,
			})
		case "/agent/agents/config":
			configCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]interface{}{"revision": 1})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	cfg := runtimeTestConfig(server.URL, t.TempDir())
	httpClient, err := transport.NewHTTPClient(time.Second, transport.TLSOptions{})
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := New(ctx, cfg, cancel, httpClient)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	err = service.Run(ctx)
	var incompatible *protocol.Incompatibility
	if !errors.As(err, &incompatible) {
		t.Fatalf("expected protocol incompatibility, got %v", err)
	}
	if configCalls.Load() != 0 {
		t.Fatalf("remote config fetched before compatibility validation")
	}
	if service.sources != nil {
		t.Fatalf("collectors initialized for an incompatible server")
	}
}

func TestSensorServiceNeverPollsResponseActions(t *testing.T) {
	var responsePolls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/agent/health":
			w.WriteHeader(http.StatusNoContent)
		case "/agent/agents/heartbeat":
			json.NewEncoder(w).Encode(protocol.LocalDescriptor())
		case "/agent/agents/config":
			json.NewEncoder(w).Encode(map[string]interface{}{"revision": 1})
		case "/agent/agents/response-actions/pending", "/agent/agents/response/actions/pending":
			responsePolls.Add(1)
			json.NewEncoder(w).Encode(protocol.ResponseActionList{})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	cfg := runtimeTestConfig(server.URL, t.TempDir())
	httpClient, err := transport.NewHTTPClient(time.Second, transport.TLSOptions{})
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	service, err := New(ctx, cfg, cancel, httpClient)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		result <- service.Run(ctx)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("service run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("service did not stop")
	}
	if responsePolls.Load() != 0 {
		t.Fatalf("sensor profile polled response actions %d times", responsePolls.Load())
	}
}

func TestCompletedResponseActionIsRetriedWithoutReexecution(t *testing.T) {
	var terminalAttempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/agent/agents/response-actions/results" {
			http.NotFound(w, request)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read response action result: %v", err)
		}
		var result protocol.ResponseActionExecutionResult
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("decode response action result: %v", err)
		}
		if result.Status == "running" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if terminalAttempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	dir := t.TempDir()
	cfg := runtimeTestConfig(server.URL, dir)
	cfg.Profile = protocol.ProfileManaged
	cfg.ResponseActionJournalDir = filepath.Join(dir, "response-actions")
	cfg.ResponseActionJournalMax = 64
	cfg.ResponseActionJournalSize = 8 << 20
	httpClient, err := transport.NewHTTPClient(time.Second, transport.TLSOptions{})
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := New(ctx, cfg, cancel, httpClient)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	now := time.Now().UTC()
	staged := service.stageResponseActions([]protocol.ResponseAction{{
		ID:          701,
		ActionType:  protocol.ActionTriggerInventory,
		AgentID:     cfg.AgentID,
		Status:      "pending",
		Payload:     json.RawMessage(`{"limits":{"max_processes":1,"max_connections":1}}`),
		RequestedAt: now,
	}})
	if staged.Added != 1 {
		t.Fatalf("response action was not staged: %+v", staged)
	}
	if err := service.processResponseActions(ctx); err != nil {
		t.Fatalf("process response action: %v", err)
	}
	if pending, err := service.responseJournal.Pending(); err != nil || pending != 1 {
		t.Fatalf("terminal result was not retained, pending=%d err=%v", pending, err)
	}
	if state := service.stateSnapshot(); state.ResponseActionsExecutedTotal != 1 {
		t.Fatalf("unexpected execution count: %d", state.ResponseActionsExecutedTotal)
	}
	if err := service.processResponseActions(ctx); err != nil {
		t.Fatalf("retry response action result: %v", err)
	}
	if pending, err := service.responseJournal.Pending(); err != nil || pending != 0 {
		t.Fatalf("delivered result remained in the journal, pending=%d err=%v", pending, err)
	}
	state := service.stateSnapshot()
	if state.ResponseActionsExecutedTotal != 1 {
		t.Fatalf("response action executed more than once: %d", state.ResponseActionsExecutedTotal)
	}
	if state.ResponseActionResultsDeliveredTotal != 1 || terminalAttempts.Load() != 2 {
		t.Fatalf("unexpected delivery state=%+v attempts=%d", state, terminalAttempts.Load())
	}
}

func TestServiceProbesTheApiOnlyWithAnIdentity(t *testing.T) {
	t.Run("an enrolled agent waits for the api", func(t *testing.T) {
		var healthProbes atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/agent/health":
				healthProbes.Add(1)
				w.WriteHeader(http.StatusNoContent)
			case "/agent/agents/heartbeat":
				json.NewEncoder(w).Encode(protocol.LocalDescriptor())
			case "/agent/agents/config":
				json.NewEncoder(w).Encode(map[string]interface{}{"revision": 1})
			default:
				http.NotFound(w, request)
			}
		}))
		defer server.Close()

		cfg := runtimeTestConfig(server.URL, t.TempDir())
		httpClient, err := transport.NewHTTPClient(time.Second, transport.TLSOptions{})
		if err != nil {
			t.Fatalf("create HTTP client: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		service, err := New(ctx, cfg, cancel, httpClient)
		if err != nil {
			t.Fatalf("create service: %v", err)
		}
		result := make(chan error, 1)
		go func() {
			result <- service.Run(ctx)
		}()
		time.Sleep(80 * time.Millisecond)
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("service run: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("service did not stop")
		}
		if healthProbes.Load() == 0 {
			t.Fatalf("an enrolled agent skipped the readiness probe")
		}
	})

	t.Run("an unenrolled agent enrolls without probing the api", func(t *testing.T) {
		var healthProbes atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/agent/health" {
				healthProbes.Add(1)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.NotFound(w, request)
		}))
		defer server.Close()

		cfg := runtimeTestConfig(server.URL, t.TempDir())
		cfg.AgentCredential = ""
		cfg.EnrollURL = server.URL
		httpClient, err := transport.NewHTTPClient(time.Second, transport.TLSOptions{})
		if err != nil {
			t.Fatalf("create HTTP client: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		service, err := New(ctx, cfg, cancel, httpClient)
		if err != nil {
			t.Fatalf("create service: %v", err)
		}
		if err := service.Run(ctx); err == nil {
			t.Fatalf("expected the run to fail without an enrollment token")
		}
		if healthProbes.Load() != 0 {
			t.Fatalf("the agent probed the api %d times before holding an identity", healthProbes.Load())
		}
	})
}
