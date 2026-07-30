package topologydiscovery

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type PlanOptions struct {
	ConfiguredCIDRs []*net.IPNet
	LocalCIDRs      []*net.IPNet
	LocalIPs        map[string]bool
	DenyCIDRs       []*net.IPNet
	MaxHosts        int
	AllowPublic     bool
}

type Plan struct {
	AllowedCIDRs  []string
	Targets       []net.IP
	SkippedDenied int
	SkippedLocal  int
	Warnings      []string
}

type ProbeStats struct {
	Attempted int
	Succeeded int
	Failed    int
}

type ProbeFunc func(context.Context, net.IP) error
type SleepFunc func(context.Context, time.Duration) error

type ProbeDeps struct {
	Probe ProbeFunc
	Sleep SleepFunc
}

func BuildPlan(opts PlanOptions) (Plan, error) {
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 256
	}

	selected := opts.ConfiguredCIDRs
	if len(selected) == 0 {
		selected = privateLocalCIDRs(opts.LocalCIDRs)
	}
	if len(selected) == 0 {
		return Plan{Warnings: []string{"no eligible private or internal CIDRs available"}}, nil
	}

	allowed := make([]*net.IPNet, 0, len(selected))
	for _, cidr := range selected {
		if cidr == nil || cidr.IP == nil {
			continue
		}
		if cidr.IP.To4() == nil {
			return Plan{}, fmt.Errorf("active discovery currently supports IPv4 CIDRs only: %s", cidr.String())
		}
		if !opts.AllowPublic && !isPrivateOrInternalCIDR(cidr) {
			return Plan{}, fmt.Errorf("public CIDR is not allowed for active discovery: %s", cidr.String())
		}
		allowed = append(allowed, cidr)
	}

	plan := Plan{AllowedCIDRs: cidrStrings(allowed)}
	seen := make(map[string]struct{})
	for _, cidr := range allowed {
		for ip, ok := firstIPv4Host(cidr); ok && cidr.Contains(ip); ip, ok = nextIPv4Host(ip, cidr) {
			if len(plan.Targets) >= opts.MaxHosts {
				plan.Warnings = append(plan.Warnings, "target list capped by max_hosts")
				return plan, nil
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if opts.LocalIPs != nil && opts.LocalIPs[key] {
				plan.SkippedLocal++
				continue
			}
			if denied(ip, opts.DenyCIDRs) {
				plan.SkippedDenied++
				continue
			}
			plan.Targets = append(plan.Targets, ip)
		}
	}
	return plan, nil
}

func RunProbes(ctx context.Context, targets []net.IP, rateLimit int, deps ProbeDeps) ProbeStats {
	if deps.Probe == nil || len(targets) == 0 {
		return ProbeStats{}
	}
	if rateLimit <= 0 {
		rateLimit = 1
	}
	if deps.Sleep == nil {
		deps.Sleep = sleepContext
	}

	interval := time.Second / time.Duration(rateLimit)
	stats := ProbeStats{}
	for i, target := range targets {
		if i > 0 && interval > 0 {
			if err := deps.Sleep(ctx, interval); err != nil {
				return stats
			}
		}
		if ctx.Err() != nil {
			return stats
		}
		stats.Attempted++
		if err := deps.Probe(ctx, target); err != nil {
			stats.Failed++
			continue
		}
		stats.Succeeded++
	}
	return stats
}

func NewPingProbe(timeout time.Duration) (ProbeFunc, string) {
	path, err := exec.LookPath("ping")
	if err != nil || strings.TrimSpace(path) == "" {
		return nil, ""
	}
	if timeout <= 0 || timeout > time.Second {
		timeout = time.Second
	}
	return func(ctx context.Context, ip net.IP) error {
		ctxProbe, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctxProbe, path, "-n", "-c", "1", "-W", "1", ip.String())
		return cmd.Run()
	}, "ping"
}

func NeighborIPs(entries []Neighbor) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.IP) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(entry.IP))
	}
	sort.Strings(out)
	return out
}

type Neighbor struct {
	IP string
}

func NewNeighborIPs(before, after []Neighbor) []string {
	seen := make(map[string]struct{}, len(before))
	for _, entry := range before {
		ip := strings.TrimSpace(entry.IP)
		if ip != "" {
			seen[ip] = struct{}{}
		}
	}
	out := make([]string, 0, len(after))
	for _, entry := range after {
		ip := strings.TrimSpace(entry.IP)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func privateLocalCIDRs(cidrs []*net.IPNet) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	seen := map[string]struct{}{}
	for _, cidr := range cidrs {
		if cidr == nil || cidr.IP == nil || cidr.IP.To4() == nil || !isPrivateOrInternalCIDR(cidr) {
			continue
		}
		key := cidr.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cidr)
	}
	return out
}

func firstIPv4Host(cidr *net.IPNet) (net.IP, bool) {
	if cidr == nil || cidr.IP.To4() == nil {
		return nil, false
	}
	ones, bits := cidr.Mask.Size()
	if bits != 32 {
		return nil, false
	}

	start := cidr.IP.Mask(cidr.Mask).To4()
	if start == nil {
		return nil, false
	}
	if ones <= 30 {
		return incIPv4(start), true
	}
	return append(net.IP(nil), start...), true
}

func nextIPv4Host(ip net.IP, cidr *net.IPNet) (net.IP, bool) {
	next := incIPv4(ip)
	if !cidr.Contains(next) {
		return nil, false
	}
	ones, bits := cidr.Mask.Size()
	if bits != 32 {
		return nil, false
	}
	if ones <= 30 && isIPv4Broadcast(next, cidr) {
		return nil, false
	}
	return next, true
}

func incIPv4(ip net.IP) net.IP {
	out := append(net.IP(nil), ip.To4()...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func isIPv4Broadcast(ip net.IP, cidr *net.IPNet) bool {
	ip4 := ip.To4()
	base := cidr.IP.Mask(cidr.Mask).To4()
	if ip4 == nil || base == nil {
		return false
	}
	for i := range ip4 {
		if ip4[i] != base[i]|^cidr.Mask[i] {
			return false
		}
	}
	return true
}

func denied(ip net.IP, cidrs []*net.IPNet) bool {
	for _, cidr := range cidrs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func cidrStrings(cidrs []*net.IPNet) []string {
	out := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr != nil {
			out = append(out, cidr.String())
		}
	}
	sort.Strings(out)
	return out
}

func isPrivateOrInternalCIDR(cidr *net.IPNet) bool {
	if cidr == nil || cidr.IP == nil {
		return false
	}
	for _, raw := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	} {
		_, parent, err := net.ParseCIDR(raw)
		if err == nil && cidrContainedWithin(cidr, parent) {
			return true
		}
	}
	return false
}

func cidrContainedWithin(child, parent *net.IPNet) bool {
	if child == nil || parent == nil || child.IP == nil || parent.IP == nil {
		return false
	}
	childOnes, childBits := child.Mask.Size()
	parentOnes, parentBits := parent.Mask.Size()
	if childBits != parentBits || childOnes < parentOnes {
		return false
	}
	return parent.Contains(child.IP)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
