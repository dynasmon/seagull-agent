package utils

import "net"

// CollectLocalIPs returns all IPs bound to local interfaces (IPv4/IPv6).
func CollectLocalIPs() (map[string]bool, error) {
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
