package pcapx

import (
	"net"
	"strings"

	"github.com/google/gopacket/layers"
)

func TCPFlags(t *layers.TCP) string {
	flags := make([]string, 0, 6)
	if t.SYN {
		flags = append(flags, "SYN")
	}
	if t.ACK {
		flags = append(flags, "ACK")
	}
	if t.FIN {
		flags = append(flags, "FIN")
	}
	if t.RST {
		flags = append(flags, "RST")
	}
	if t.PSH {
		flags = append(flags, "PSH")
	}
	if t.URG {
		flags = append(flags, "URG")
	}
	return strings.Join(flags, "|")
}

func DropByIP(srcIP, dstIP string, skipLoopback, skipLinkLocal, skipPrivateToPrivate bool, denyCIDRs []*net.IPNet) bool {
	sip := net.ParseIP(srcIP)
	dip := net.ParseIP(dstIP)
	if sip == nil || dip == nil {
		return true
	}
	if skipLoopback && (sip.IsLoopback() || dip.IsLoopback()) {
		return true
	}
	if skipLinkLocal && (sip.IsLinkLocalUnicast() || dip.IsLinkLocalUnicast()) {
		return true
	}
	if skipPrivateToPrivate && sip.IsPrivate() && dip.IsPrivate() {
		return true
	}
	for _, n := range denyCIDRs {
		if n.Contains(sip) || n.Contains(dip) {
			return true
		}
	}
	return false
}

func SkippableIP(ip net.IP, skipLoopback, skipLinkLocal bool) bool {
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

func IPInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
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
