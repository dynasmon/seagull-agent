package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dynasmon/seagull-agent/internal/collectors/ssh"
	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/sender"
)

func TestRunOnceCountsOnlyConfirmedEventsAsSent(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantSent    int
		wantDurable int
		wantError   bool
	}{
		{
			name:        "durable acknowledgement",
			status:      http.StatusCreated,
			body:        `{"accepted":true,"durable":true,"received":1}`,
			wantSent:    1,
			wantDurable: 1,
			wantError:   false,
		},
		{
			name:        "rejected delivery",
			status:      http.StatusBadRequest,
			body:        `{"error":"invalid_event"}`,
			wantSent:    0,
			wantDurable: 0,
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			authLog := filepath.Join(t.TempDir(), "auth.log")
			line := "Failed password for invalid user root from 203.0.113.10 port 51514 ssh2\n"
			if err := os.WriteFile(authLog, []byte(line), 0o600); err != nil {
				t.Fatalf("write auth log: %v", err)
			}

			cfg := agentcfg.Config{
				AgentID:     "agent-cycle-1",
				HTTPTimeout: time.Second,
				ScanMode:    "raw",
			}
			eventSender := sender.New(server.URL, time.Second, 300, cfg.AgentID, nil, server.Client())
			manager := &Manager{
				cfg:    cfg,
				sender: eventSender,
				authCapturer: ssh.NewAuthLogCapturer(cfg.AgentID, ssh.AuthLogOptions{
					Path:         authLog,
					MaxBatchSize: 10,
				}),
			}

			result := manager.RunOnce(context.Background())
			if result.Attempted != 1 {
				t.Fatalf("attempted=%d want 1", result.Attempted)
			}
			if result.Sent != tt.wantSent {
				t.Fatalf("sent=%d want %d", result.Sent, tt.wantSent)
			}
			if result.Durable != tt.wantDurable {
				t.Fatalf("durable=%d want %d", result.Durable, tt.wantDurable)
			}
			if (result.Error != "") != tt.wantError {
				t.Fatalf("error=%q wantError=%v", result.Error, tt.wantError)
			}
		})
	}
}
