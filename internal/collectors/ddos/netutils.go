package ddos

import "net"

func collectLocalIPs() (map[string]bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, 64)
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if ip == nil {
			continue
		}
		out[ip.String()] = true
	}
	return out, nil
}

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
