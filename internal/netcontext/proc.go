package netcontext

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Caps limits the number of entries collected per category.
// Zero values are replaced by safe defaults inside normalizeCaps.
type Caps struct {
	MaxInterfaces int
	MaxNeighbors  int
	MaxRoutes     int
	MaxResolvers  int
}

const (
	defaultMaxInterfaces = 64
	defaultMaxNeighbors  = 512
	defaultMaxRoutes     = 256
	defaultMaxResolvers  = 8
)

func normalizeCaps(c Caps) Caps {
	if c.MaxInterfaces <= 0 {
		c.MaxInterfaces = defaultMaxInterfaces
	}
	if c.MaxNeighbors <= 0 {
		c.MaxNeighbors = defaultMaxNeighbors
	}
	if c.MaxRoutes <= 0 {
		c.MaxRoutes = defaultMaxRoutes
	}
	if c.MaxResolvers <= 0 {
		c.MaxResolvers = defaultMaxResolvers
	}
	return c
}

// NeighborEntry represents a single ARP/neighbor cache entry from /proc/net/arp.
type NeighborEntry struct {
	IP        string
	MAC       string
	Interface string
	State     string
}

// RouteEntry represents a single routing table entry from /proc/net/route or /proc/net/ipv6_route.
type RouteEntry struct {
	Destination string
	Gateway     string
	Interface   string
	Metric      int
	Family      string // "ipv4" or "ipv6"
}

// ResolverInfo holds DNS resolver configuration parsed from /etc/resolv.conf.
type ResolverInfo struct {
	Nameservers   []string
	SearchDomains []string
	Options       []string
}

// HostIdentity holds the host's hostname and FQDN where determinable without
// network calls.
type HostIdentity struct {
	Hostname string
	FQDN     string
}

// collectARP parses /proc/net/arp. Returns best-effort results; errors from
// missing or unreadable files are returned but callers should treat them as
// non-fatal.
func collectARP(path string, max int) ([]NeighborEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []NeighborEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header line
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		flagStr := strings.TrimPrefix(fields[2], "0x")
		mac := fields[3]
		iface := fields[5]

		if mac == "00:00:00:00:00:00" {
			continue // incomplete/unresolved entry
		}
		if net.ParseIP(ip) == nil {
			continue
		}

		state := "incomplete"
		if fl, e := strconv.ParseUint(flagStr, 16, 32); e == nil && fl&0x02 != 0 {
			state = "reachable"
		}

		out = append(out, NeighborEntry{IP: ip, MAC: mac, Interface: iface, State: state})
		if len(out) >= max {
			break
		}
	}
	return out, scanner.Err()
}

// collectRoutes parses /proc/net/route (IPv4 kernel routing table).
func collectRoutes(path string, max int) ([]RouteEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []RouteEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header line
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		dest, err := hexIPv4LEtoCIDR(fields[1], fields[7])
		if err != nil {
			continue
		}
		gw, err := hexIPv4LEtoIP(fields[2])
		if err != nil {
			continue
		}
		metric := 0
		if m, e := strconv.ParseInt(fields[6], 10, 32); e == nil {
			metric = int(m)
		}

		out = append(out, RouteEntry{
			Destination: dest,
			Gateway:     gw,
			Interface:   fields[0],
			Metric:      metric,
			Family:      "ipv4",
		})
		if len(out) >= max {
			break
		}
	}
	return out, scanner.Err()
}

// collectIPv6Routes parses /proc/net/ipv6_route (IPv6 kernel routing table).
// Returns nil without error when the file does not exist or max is zero.
func collectIPv6Routes(path string, max int) ([]RouteEntry, error) {
	if max <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []RouteEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		prefixLen, err := strconv.ParseUint(fields[1], 16, 8)
		if err != nil {
			continue
		}
		destIP, err := hexIPv6(fields[0])
		if err != nil {
			continue
		}
		gw, err := hexIPv6(fields[4])
		if err != nil {
			continue
		}
		metric := 0
		if m, e := strconv.ParseInt(fields[5], 16, 32); e == nil {
			metric = int(m)
		}

		out = append(out, RouteEntry{
			Destination: fmt.Sprintf("%s/%d", destIP, prefixLen),
			Gateway:     gw,
			Interface:   fields[9],
			Metric:      metric,
			Family:      "ipv6",
		})
		if len(out) >= max {
			break
		}
	}
	return out, scanner.Err()
}

// collectResolvers parses /etc/resolv.conf.
func collectResolvers(path string, maxNS int) (ResolverInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return ResolverInfo{}, err
	}
	defer f.Close()

	var info ResolverInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(info.Nameservers) < maxNS && net.ParseIP(fields[1]) != nil {
				info.Nameservers = append(info.Nameservers, fields[1])
			}
		case "search":
			info.SearchDomains = append(info.SearchDomains, fields[1:]...)
		case "domain":
			// domain is like search with a single name; prepend so it takes precedence.
			info.SearchDomains = append([]string{fields[1]}, info.SearchDomains...)
		case "options":
			info.Options = append(info.Options, fields[1:]...)
		}
	}
	return info, scanner.Err()
}

// collectHostIdentity returns the host's hostname and FQDN where determinable
// without network calls.
func collectHostIdentity() (HostIdentity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return HostIdentity{}, err
	}
	id := HostIdentity{Hostname: hostname}
	if strings.Contains(hostname, ".") {
		id.FQDN = hostname
	}
	return id, nil
}

func hexIPv4LEtoCIDR(addrHex, maskHex string) (string, error) {
	ip, err := hexIPv4LE(addrHex)
	if err != nil {
		return "", err
	}
	mask, err := hexIPv4LE(maskHex)
	if err != nil {
		return "", err
	}
	m := net.IPMask(mask)
	return (&net.IPNet{IP: ip.Mask(m), Mask: m}).String(), nil
}

func hexIPv4LEtoIP(h string) (string, error) {
	ip, err := hexIPv4LE(h)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// hexIPv4LE decodes an 8-char little-endian hex IPv4 address as used in
// /proc/net/route on little-endian architectures.
func hexIPv4LE(h string) (net.IP, error) {
	if len(h) != 8 {
		return nil, fmt.Errorf("invalid hex IPv4: %q", h)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return net.IP{b[3], b[2], b[1], b[0]}, nil
}

// hexIPv6 decodes a 32-char big-endian hex IPv6 address as used in
// /proc/net/ipv6_route.
func hexIPv6(h string) (string, error) {
	if len(h) != 32 {
		return "", fmt.Errorf("invalid hex IPv6: %q", h)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	return net.IP(b).String(), nil
}
