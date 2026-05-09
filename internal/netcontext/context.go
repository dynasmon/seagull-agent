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

// InterfaceInfo holds per-interface network data collected at startup.
type InterfaceInfo struct {
	Name        string
	IPs         []string
	CIDRs       []string
	IsLoopback  bool
	IsLinkLocal bool
}

// NetworkContext holds the agent's local network state. It is collected once at
// startup and cached for the lifetime of a collector.
type NetworkContext struct {
	Interfaces []InterfaceInfo
	// LocalIPs is a set of all local IP strings for O(1) endpoint classification.
	LocalIPs map[string]bool
	// LocalCIDRs contains the subnet of every local interface address.
	LocalCIDRs []*net.IPNet
	Source     Source
}

// Collect enumerates the host's network interfaces and returns a NetworkContext.
func Collect() (*NetworkContext, error) {
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
		data = append(data, ifaceData{name: iface.Name, addrs: addrs})
	}

	return buildFromIfaceData(data, detectSource("/")), nil
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

// ToInventoryMap serializes the context for embedding in inventory snapshots
// under extra.network_context.
func (nc *NetworkContext) ToInventoryMap() map[string]interface{} {
	ifaces := make([]map[string]interface{}, 0, len(nc.Interfaces))
	for _, iface := range nc.Interfaces {
		ifaces = append(ifaces, map[string]interface{}{
			"name":          iface.Name,
			"ips":           iface.IPs,
			"cidrs":         iface.CIDRs,
			"is_loopback":   iface.IsLoopback,
			"is_link_local": iface.IsLinkLocal,
		})
	}
	return map[string]interface{}{
		"interfaces": ifaces,
		"source":     string(nc.Source),
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

// ifaceData is the internal representation of a single interface's address
// list, used to separate OS calls from business logic for testability.
type ifaceData struct {
	name  string
	addrs []net.Addr
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
		info := InterfaceInfo{Name: d.name}

		for _, addr := range d.addrs {
			var ip net.IP
			var ipnet *net.IPNet

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipnet = v
			case *net.IPAddr:
				raw := v.IP
				// Normalise to the shortest canonical form so the mask length
				// is consistent with the IP byte length.
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
