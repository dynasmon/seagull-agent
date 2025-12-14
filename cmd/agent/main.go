package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/capture"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/sender"
)

func main() {
	agentID := getEnv("NETWATCH_AGENT_ID", "agent-unknown")
	apiURL := getEnv("NETWATCH_API_URL", "http://localhost:8000")

	sources := splitCSVLower(getEnv("NETWATCH_SOURCES", "authlog,proc"))

	interval := parseDuration(getEnv("NETWATCH_POLL_INTERVAL", "5s"), 5*time.Second)
	httpTimeout := parseDuration(getEnv("NETWATCH_HTTP_TIMEOUT", "10s"), 10*time.Second)
	senderMaxBatch := parseInt(getEnv("NETWATCH_SENDER_MAX_BATCH", "300"), 300)

	logPath := getEnv("NETWATCH_AUTHLOG_PATH", "/var/log/auth.log")
	includeAccepted := parseBool(getEnv("NETWATCH_AUTHLOG_INCLUDE_ACCEPTED", "false"), false)

	procTCP4Path := getEnv("NETWATCH_PROC_TCP4_PATH", "/proc/net/tcp")
	procTCP6Path := getEnv("NETWATCH_PROC_TCP6_PATH", "/proc/net/tcp6")

	log.Printf("[AGENT] id=%s api=%s sources=%v interval=%s", agentID, apiURL, sources, interval)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	{
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
		if err := waitForHealth(ctx, apiURL); err != nil {
			log.Printf("[AGENT] backend not ready: %v", err)
		}
		cancel()
	}

	s := sender.New(apiURL, httpTimeout, senderMaxBatch)

	var procCapturer *capture.Capturer
	if contains(sources, "proc") {
		opts := capture.Options{
			SkipLoopback:         true,
			SkipLinkLocal:        true,
			SkipPrivateToPrivate: true,
			IncludeIPv6:          true,
			MaxBatchSize:         300,
		}
		procCapturer = capture.New(agentID, procTCP4Path, procTCP6Path, opts)
	}

	var authCapturer *capture.AuthLogCapturer
	if contains(sources, "authlog") {
		authCapturer = capture.NewAuthLogCapturer(agentID, capture.AuthLogOptions{
			Path:            logPath,
			MaxBatchSize:    200,
			DedupTTL:        30 * time.Second,
			IncludeAccepted: includeAccepted,
		})
	}

	runOnce := func() {
		now := time.Now().UTC()
		events := make([]model.NetEvent, 0, 256)

		if authCapturer != nil {
			evs, err := authCapturer.Capture(now)
			if err != nil {
				log.Printf("[AGENT] authlog capture error: %v", err)
			} else if len(evs) > 0 {
				events = append(events, evs...)
			}
		}

		if procCapturer != nil {
			evs, err := procCapturer.Capture()
			if err != nil {
				log.Printf("[AGENT] proc capture error: %v", err)
			} else if len(evs) > 0 {
				events = append(events, evs...)
			}
		}

		if len(events) == 0 {
			return
		}

		sshRelated := 0
		for _, ev := range events {
			if ev.EventType == "ssh_auth" || ev.DstPort == 22 || ev.SrcPort == 22 {
				sshRelated++
			}
		}

		ctx, cancel := context.WithTimeout(rootCtx, httpTimeout)
		status, err := s.SendEvents(ctx, events)
		cancel()
		if err != nil {
			log.Printf("[AGENT] send error: %v", err)
			return
		}

		log.Printf("[AGENT] sent=%d ssh_related=%d status=%d", len(events), sshRelated, status)
	}

	runOnce()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rootCtx.Done():
			log.Printf("[AGENT] shutdown requested")
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

func waitForHealth(ctx context.Context, baseURL string) error {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/health"

	client := &http.Client{Timeout: 2 * time.Second}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("health check timeout: %w", ctx.Err())
		case <-t.C:
		}
	}
}

func getEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func splitCSVLower(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func parseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func parseInt(s string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func parseBool(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}
