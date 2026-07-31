package netcontext

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Source describes how confident the agent is about the origin of its network
// context (host interfaces vs. container overlay).
type Source string

const (
	SourceHostObserved      Source = "host_observed"
	SourceContainerObserved Source = "container_observed"
	SourceUnknown           Source = "unknown"
)

// InterfaceInfo holds per-interface network data.
type InterfaceInfo struct {
	Name        string
	MAC         string
	MTU         int
	IsUp        bool
	IsLoopback  bool
	IsLinkLocal bool
	IPs         []string
	CIDRs       []string
}

// NetworkContext holds the agent's local network state. It is collected once at
// startup and cached for the lifetime of a collector.
type NetworkContext struct {
	Interfaces []InterfaceInfo
	// LocalIPs is a set of all local IP strings for O(1) endpoint classification.
	LocalIPs map[string]bool
	// LocalCIDRs contains the subnet of every local interface address.
	LocalCIDRs   []*net.IPNet
	Source       Source
	Neighbors    []NeighborEntry
	Routes       []RouteEntry
	Resolvers    ResolverInfo
	HostIdentity HostIdentity
}

// Collect enumerates the host's network interfaces and enriches them with
// ARP neighbors, routing table entries, DNS resolver config, and host identity.
// All proc-level sources are best-effort; failure of any one does not abort.
func Collect(caps Caps) (*NetworkContext, error) {
	caps = normalizeCaps(caps)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	data := make([]ifaceData, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		data = append(data, ifaceData{
			name:         iface.Name,
			hardwareAddr: iface.HardwareAddr,
			mtu:          iface.MTU,
			flags:        iface.Flags,
			addrs:        addrs,
		})
	}
	if len(data) > caps.MaxInterfaces {
		data = data[:caps.MaxInterfaces]
	}

	nc := buildFromIfaceData(data, detectSource("/"))

	nc.Neighbors, _ = collectARP("/proc/net/arp", caps.MaxNeighbors)

	routes, _ := collectRoutes("/proc/net/route", caps.MaxRoutes)
	nc.Routes = routes
	if remaining := caps.MaxRoutes - len(nc.Routes); remaining > 0 {
		if routes6, err := collectIPv6Routes("/proc/net/ipv6_route", remaining); err == nil {
			nc.Routes = append(nc.Routes, routes6...)
		}
	}

	nc.Resolvers, _ = collectResolvers("/etc/resolv.conf", caps.MaxResolvers)
	nc.HostIdentity, _ = collectHostIdentity()

	return nc, nil
}

// PrimaryIPv4 returns the first non-loopback IPv4 address on an up interface.
func PrimaryIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := ipFromAddr(addr)
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			return ip4.String()
		}
	}
	return ""
}

// FindCIDR returns the network-prefix CIDR string (e.g. "192.168.1.0/24") for
// the first local CIDR that contains ip, or "" if none match.
func (nc *NetworkContext) FindCIDR(ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, cidr := range nc.LocalCIDRs {
		if cidr.Contains(ip) {
			masked := ip.Mask(cidr.Mask)
			if masked == nil {
				continue
			}
			return (&net.IPNet{IP: masked, Mask: cidr.Mask}).String()
		}
	}
	return ""
}

func ipFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

// ToInventoryMap serializes the context for embedding in inventory snapshots
// under extra.network_context. Schema version 2 adds neighbors, routes,
// resolvers, and host_identity alongside the existing interfaces and source keys.
func (nc *NetworkContext) ToInventoryMap() map[string]interface{} {
	ifaces := make([]map[string]interface{}, 0, len(nc.Interfaces))
	for _, iface := range nc.Interfaces {
		m := map[string]interface{}{
			"name":          iface.Name,
			"ips":           iface.IPs,
			"cidrs":         iface.CIDRs,
			"is_loopback":   iface.IsLoopback,
			"is_link_local": iface.IsLinkLocal,
			"is_up":         iface.IsUp,
		}
		if iface.MAC != "" {
			m["mac"] = iface.MAC
		}
		if iface.MTU > 0 {
			m["mtu"] = iface.MTU
		}
		ifaces = append(ifaces, m)
	}

	neighbors := make([]map[string]interface{}, 0, len(nc.Neighbors))
	for _, n := range nc.Neighbors {
		neighbors = append(neighbors, map[string]interface{}{
			"ip":        n.IP,
			"mac":       n.MAC,
			"interface": n.Interface,
			"state":     n.State,
		})
	}

	routes := make([]map[string]interface{}, 0, len(nc.Routes))
	for _, r := range nc.Routes {
		routes = append(routes, map[string]interface{}{
			"destination": r.Destination,
			"gateway":     r.Gateway,
			"interface":   r.Interface,
			"metric":      r.Metric,
			"family":      r.Family,
		})
	}

	ns := nc.Resolvers.Nameservers
	if ns == nil {
		ns = []string{}
	}
	sd := nc.Resolvers.SearchDomains
	if sd == nil {
		sd = []string{}
	}
	resolvers := map[string]interface{}{
		"nameservers":    ns,
		"search_domains": sd,
	}
	if len(nc.Resolvers.Options) > 0 {
		resolvers["options"] = nc.Resolvers.Options
	}

	hostIdentity := map[string]interface{}{
		"hostname": nc.HostIdentity.Hostname,
	}
	if nc.HostIdentity.FQDN != "" {
		hostIdentity["fqdn"] = nc.HostIdentity.FQDN
	}

	return map[string]interface{}{
		"schema_version": 2,
		"source":         string(nc.Source),
		"interfaces":     ifaces,
		"neighbors":      neighbors,
		"routes":         routes,
		"resolvers":      resolvers,
		"host_identity":  hostIdentity,
	}
}

// EnrichEndpoints adds endpoint locality hints to an event Extra map.
// srcIPStr and dstIPStr are the string forms of the packet's source and
// destination IPs. Either may be empty to signal "not applicable".
func (nc *NetworkContext) EnrichEndpoints(extra map[string]interface{}, srcIPStr, dstIPStr string) {
	srcIsLocal := srcIPStr != "" && nc.LocalIPs[srcIPStr]
	dstIsLocal := dstIPStr != "" && nc.LocalIPs[dstIPStr]

	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)

	extra["src_is_local_endpoint"] = srcIsLocal
	extra["dst_is_local_endpoint"] = dstIsLocal
	extra["src_in_agent_network"] = srcIP != nil && nc.FindCIDR(srcIP) != ""
	extra["dst_in_agent_network"] = dstIP != nil && nc.FindCIDR(dstIP) != ""
	extra["network_context_source"] = string(nc.Source)

	if nc.Source != SourceUnknown {
		var localCIDR string
		switch {
		case srcIsLocal && srcIP != nil:
			localCIDR = nc.FindCIDR(srcIP)
		case dstIsLocal && dstIP != nil:
			localCIDR = nc.FindCIDR(dstIP)
		}
		if localCIDR != "" {
			extra["local_network_cidr"] = localCIDR
		}
	}
}

// ifaceData is the internal representation of a single interface's data,
// used to separate OS calls from business logic for testability.
type ifaceData struct {
	name         string
	hardwareAddr net.HardwareAddr
	mtu          int
	flags        net.Flags
	addrs        []net.Addr
}

// buildFromIfaceData is the testable core of Collect.
func buildFromIfaceData(data []ifaceData, src Source) *NetworkContext {
	nc := &NetworkContext{
		Interfaces: make([]InterfaceInfo, 0, len(data)),
		LocalIPs:   make(map[string]bool, 64),
		LocalCIDRs: make([]*net.IPNet, 0, 16),
		Source:     src,
	}

	for _, d := range data {
		info := InterfaceInfo{
			Name: d.name,
			MTU:  d.mtu,
			IsUp: d.flags&net.FlagUp != 0,
		}
		if len(d.hardwareAddr) > 0 {
			info.MAC = d.hardwareAddr.String()
		}

		for _, addr := range d.addrs {
			var ipnet *net.IPNet
			ip := ipFromAddr(addr)

			switch v := addr.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				raw := v.IP
				if ip4 := raw.To4(); ip4 != nil {
					ip = ip4
					ipnet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
				} else {
					ip = raw
					ipnet = &net.IPNet{IP: raw, Mask: net.CIDRMask(128, 128)}
				}
			default:
				continue
			}

			if ip == nil {
				continue
			}

			ipStr := ip.String()
			nc.LocalIPs[ipStr] = true
			nc.LocalCIDRs = append(nc.LocalCIDRs, ipnet)

			info.IPs = append(info.IPs, ipStr)
			info.CIDRs = append(info.CIDRs, ipnet.String())

			if ip.IsLoopback() {
				info.IsLoopback = true
			}
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				info.IsLinkLocal = true
			}
		}

		if len(info.IPs) > 0 {
			nc.Interfaces = append(nc.Interfaces, info)
		}
	}

	return nc
}

// detectSource probes well-known locations to determine whether the agent is
// running inside a container.
func detectSource(root string) Source {
	if _, err := os.Stat(filepath.Join(root, ".dockerenv")); err == nil {
		return SourceContainerObserved
	}
	cgroupPath := filepath.Join(root, "proc", "1", "cgroup")
	if data, err := os.ReadFile(cgroupPath); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") ||
			strings.Contains(s, "kubepods") ||
			strings.Contains(s, "containerd") {
			return SourceContainerObserved
		}
	}
	return SourceHostObserved
}
