package topologydiscovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func mustCIDR(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, cidr, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", raw, err)
	}
	return cidr
}

func TestBuildPlanEnforcesDenyCIDRs(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{
		ConfiguredCIDRs: []*net.IPNet{mustCIDR(t, "10.0.0.0/29")},
		DenyCIDRs:       []*net.IPNet{mustCIDR(t, "10.0.0.2/31")},
		LocalIPs:        map[string]bool{"10.0.0.1": true},
		MaxHosts:        16,
	})
	if err != nil {
		t.Fatalf("BuildPlan error: %v", err)
	}
	if plan.SkippedDenied != 2 {
		t.Fatalf("expected 2 denied hosts, got %d", plan.SkippedDenied)
	}
	if plan.SkippedLocal != 1 {
		t.Fatalf("expected 1 local host, got %d", plan.SkippedLocal)
	}
	for _, ip := range plan.Targets {
		if ip.String() == "10.0.0.2" || ip.String() == "10.0.0.3" || ip.String() == "10.0.0.1" {
			t.Fatalf("unexpected denied/local target %s", ip)
		}
	}
}

func TestBuildPlanCapsTargets(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{
		ConfiguredCIDRs: []*net.IPNet{mustCIDR(t, "10.0.0.0/24")},
		MaxHosts:        3,
	})
	if err != nil {
		t.Fatalf("BuildPlan error: %v", err)
	}
	if len(plan.Targets) != 3 {
		t.Fatalf("expected target cap of 3, got %d", len(plan.Targets))
	}
	if len(plan.Warnings) == 0 {
		t.Fatalf("expected cap warning")
	}
}

func TestRunProbesAppliesRateLimit(t *testing.T) {
	var sleeps []time.Duration
	var attempted []string
	stats := RunProbes(context.Background(), []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		net.ParseIP("10.0.0.3"),
	}, 2, ProbeDeps{
		Probe: func(_ context.Context, ip net.IP) error {
			attempted = append(attempted, ip.String())
			return nil
		},
		Sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	})
	if stats.Attempted != 3 || stats.Succeeded != 3 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(sleeps) != 2 {
		t.Fatalf("expected 2 sleeps, got %d", len(sleeps))
	}
	for _, sleep := range sleeps {
		if sleep != 500*time.Millisecond {
			t.Fatalf("expected 500ms sleep, got %s", sleep)
		}
	}
	if len(attempted) != 3 {
		t.Fatalf("expected all targets to be attempted")
	}
}
