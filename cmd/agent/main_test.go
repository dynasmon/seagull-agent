package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
)

func TestLoadBootstrapTokenValueAllowsMissingFileWithExistingIdentity(t *testing.T) {
	t.Setenv("SEAGULL_AGENT_BOOTSTRAP_TOKEN", "")
	t.Setenv("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE", filepath.Join(t.TempDir(), "missing.token"))

	token, tokenFile, err := loadBootstrapTokenValue(true)
	if err != nil {
		t.Fatalf("loadBootstrapTokenValue returned error: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if tokenFile == "" {
		t.Fatalf("expected bootstrap token file path to be preserved")
	}
}

func TestRecoverIdentitySerializesConcurrentAttempts(t *testing.T) {
	var enrollCalls atomic.Int32
	firstEntered := make(chan struct{})
	release := make(chan struct{})

	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/enroll" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		call := enrollCalls.Add(1)
		if call == 1 {
			close(firstEntered)
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			w,
			`{"agent_id":"agent-1","config":{},"credential":{"credential":"cred-%d","expires_at":"%s","max_uses":1,"used_uses":0,"renewal_token":"renewed-token","renewal_token_expires_at":"%s"}}`,
			call,
			expiresAt,
			expiresAt,
		)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	a := &Agent{
		cfg: Config{
			AgentID:                "agent-1",
			ForceEnrollOnStart:     true,
			ControlEnrollTimeout:   time.Second,
			AgentIdentityStateFile: filepath.Join(tempDir, "agent.identity.json"),
		},
		cp:           controlplane.New(server.URL, time.Second, "agent-1", nil, server.Client()),
		renewalToken: "renewal-token",
		renewalExp:   time.Now().UTC().Add(time.Hour),
	}

	const workers = 5
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- a.recoverIdentity(context.Background(), "test", false)
		}()
	}

	close(start)
	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first recovery attempt")
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	successes := 0
	inFlightErrors := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if strings.Contains(err.Error(), "already in progress") {
			inFlightErrors++
			continue
		}
		t.Fatalf("unexpected recovery error: %v", err)
	}

	if got := enrollCalls.Load(); got != 1 {
		t.Fatalf("expected exactly one enroll request, got %d", got)
	}
	if successes != 1 {
		t.Fatalf("expected exactly one successful recovery, got %d", successes)
	}
	if inFlightErrors != workers-1 {
		t.Fatalf("expected %d in-flight rejections, got %d", workers-1, inFlightErrors)
	}
}
