package ddos

import "net"

func ipInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	if ip == nil || len(cidrs) == 0 {
		return false
	}
	for _, n := range cidrs {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func isSkippableIP(ip net.IP, skipLoopback, skipLinkLocal bool) bool {
	if ip == nil {
		return true
	}
	if skipLoopback && ip.IsLoopback() {
		return true
	}
	if skipLinkLocal && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return true
	}
	return false
}
