package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/capture"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/sender"
)

func main() {
	agentID := getEnv("NETWATCH_AGENT_ID", "agent-unknown")
	apiURL := getEnv("NETWATCH_API_URL", "http://localhost:8000")

	mode := getEnv("NETWATCH_AGENT_MODE", "proc")
	if mode != "proc" {
		log.Fatalf("[AGENT] NETWATCH_AGENT_MODE must be 'proc' (no mock). got=%q", mode)
	}

	tcp4Path := getEnv("NETWATCH_PROC_TCP4_PATH", getEnv("NETWATCH_PROC_TCP_PATH", "/proc/net/tcp"))
	tcp6Path := getEnv("NETWATCH_PROC_TCP6_PATH", "/proc/net/tcp6")

	interval := getEnvDuration("NETWATCH_INTERVAL", 2*time.Second)
	dedupTTL := getEnvDuration("NETWATCH_DEDUP_TTL", 30*time.Second)
	estTTL := getEnvDuration("NETWATCH_ESTABLISHED_TTL", 10*time.Minute)
	httpTimeout := getEnvDuration("NETWATCH_HTTP_TIMEOUT", 10*time.Second)

	maxBatch := getEnvInt("NETWATCH_MAX_EVENTS_PER_BATCH", 500)
	includeIPv6 := getEnvBool("NETWATCH_INCLUDE_IPV6", true)
	skipLoopback := getEnvBool("NETWATCH_SKIP_LOOPBACK", true)
	skipLinkLocal := getEnvBool("NETWATCH_SKIP_LINK_LOCAL", true)
	skipPriv2Priv := getEnvBool("NETWATCH_SKIP_PRIVATE_TO_PRIVATE", false)

	denyCIDRs := mustParseCIDRs(getEnv("NETWATCH_DENY_CIDRS", ""))
	denyDstPorts := parsePortsSet(getEnv("NETWATCH_DENY_DST_PORTS", ""))
	denySrcPorts := parsePortsSet(getEnv("NETWATCH_DENY_SRC_PORTS", ""))

	log.Printf("[AGENT] starting id=%s api=%s interval=%s dedup=%s established_ttl=%s max_batch=%d ipv6=%t",
		agentID, apiURL, interval, dedupTTL, estTTL, maxBatch, includeIPv6)
	log.Printf("[AGENT] filters skip_loopback=%t skip_link_local=%t skip_priv2priv=%t deny_cidrs=%d deny_dst_ports=%d deny_src_ports=%d",
		skipLoopback, skipLinkLocal, skipPriv2Priv, len(denyCIDRs), len(denyDstPorts), len(denySrcPorts))

	capturer := capture.New(agentID, tcp4Path, tcp6Path, capture.Options{
		DedupTTL:             dedupTTL,
		EstablishedTTL:       estTTL,
		SkipLoopback:         skipLoopback,
		SkipLinkLocal:        skipLinkLocal,
		SkipPrivateToPrivate: skipPriv2Priv,
		DenyCIDRs:            denyCIDRs,
		DenyDstPorts:         denyDstPorts,
		DenySrcPorts:         denySrcPorts,
		MaxBatchSize:         maxBatch,
		IncludeIPv6:          includeIPv6,
	})

	s := sender.New(apiURL, httpTimeout)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		events, err := capturer.Capture()
		if err != nil {
			log.Printf("[AGENT] capture error: %v", err)
			continue
		}
		if len(events) == 0 {
			continue
		}

		sshCount := 0
		for _, ev := range events {
			if ev.SrcPort == 22 || ev.DstPort == 22 {
				sshCount++
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		status, err := s.SendEvents(ctx, events)
		cancel()

		if err != nil {
			log.Printf("[AGENT] send error: %v", err)
			continue
		}

		log.Printf("[AGENT] sent=%d ssh_port_events=%d status=%d", len(events), sshCount, status)
	}
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func getEnvBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	switch v {
	case "1", "true", "TRUE", "yes", "YES", "y", "Y":
		return true
	case "0", "false", "FALSE", "no", "NO", "n", "N":
		return false
	default:
		return def
	}
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func mustParseCIDRs(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			log.Fatalf("[AGENT] invalid CIDR in NETWATCH_DENY_CIDRS: %q: %v", p, err)
		}
		out = append(out, n)
	}
	return out
}

func parsePortsSet(raw string) map[int]bool {
	raw = strings.TrimSpace(raw)
	m := map[int]bool{}
	if raw == "" {
		return m
	}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			continue
		}
		m[n] = true
	}
	return m
}
