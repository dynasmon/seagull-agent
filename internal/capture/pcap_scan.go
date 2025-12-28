package capture

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type PcapScanOptions struct {
	Interface   string
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration

	DedupTTL     time.Duration
	MaxBatchSize int

	SkipLoopback  bool
	SkipLinkLocal bool

	DenyCIDRs    []*net.IPNet
	DenyDstPorts map[int]bool
	DenySrcPorts map[int]bool

	ServicePorts map[int]bool
}

type PcapScanCapturer struct {
	agentID string
	opts    PcapScanOptions

	localIPs map[string]bool

	mu          sync.Mutex
	buf         []model.NetEvent
	cache       map[string]time.Time
	lastCleanup time.Time
}

func NewPcapScanCapturer(agentID string, opts PcapScanOptions) (*PcapScanCapturer, error) {
	applyPcapDefaults(&opts)

	localIPs, err := collectLocalIPs()
	if err != nil {
		return nil, err
	}
	if len(localIPs) == 0 {
		return nil, fmt.Errorf("no local IPs detected")
	}

	return &PcapScanCapturer{
		agentID:     agentID,
		opts:        opts,
		localIPs:    localIPs,
		buf:         make([]model.NetEvent, 0, 2048),
		cache:       make(map[string]time.Time, 8192),
		lastCleanup: time.Now(),
	}, nil
}

func applyPcapDefaults(o *PcapScanOptions) {
	if o.SnapLen <= 0 {
		o.SnapLen = 128
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 500 * time.Millisecond
	}
	if o.DedupTTL <= 0 {
		o.DedupTTL = 2 * time.Second
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = 2000
	}
	if o.DenyDstPorts == nil {
		o.DenyDstPorts = map[int]bool{}
	}
	if o.DenySrcPorts == nil {
		o.DenySrcPorts = map[int]bool{}
	}
	if o.ServicePorts == nil {
		o.ServicePorts = map[int]bool{22: true}
	}
}

func (c *PcapScanCapturer) Start(ctx context.Context) error {
	iface := strings.TrimSpace(c.opts.Interface)
	if iface == "" {
		iface = "any"
	}

	handle, err := pcap.OpenLive(iface, int32(c.opts.SnapLen), c.opts.Promisc, c.opts.ReadTimeout)
	if err != nil {
		return fmt.Errorf("pcap open iface=%s: %w", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp or udp or icmp or icmp6 or arp"); err != nil {
		return fmt.Errorf("pcap bpf set: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			pkt, err := src.NextPacket()
			if err != nil {
				continue
			}
			if ev := c.packetToEvent(pkt, iface); ev != nil {
				c.push(*ev)
			}
		}
	}
}

func (c *PcapScanCapturer) Drain() []model.NetEvent {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.buf) == 0 {
		return nil
	}
	out := make([]model.NetEvent, len(c.buf))
	copy(out, c.buf)
	c.buf = c.buf[:0]
	return out
}

func (c *PcapScanCapturer) push(ev model.NetEvent) {
	now := time.Now().UTC()

	scanType := ""
	if ev.Extra != nil {
		if v, ok := ev.Extra["scan_type"].(string); ok {
			scanType = v
		}
	}

	key := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s",
		ev.EventType, ev.Proto, ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, scanType,
	)

	c.mu.Lock()
	defer c.mu.Unlock()

	if t, ok := c.cache[key]; ok && now.Sub(t) < c.opts.DedupTTL {
		return
	}
	if len(c.buf) >= c.opts.MaxBatchSize {
		return
	}

	c.cache[key] = now
	c.buf = append(c.buf, ev)

	c.cleanupLocked(now)
}

func (c *PcapScanCapturer) cleanupLocked(now time.Time) {
	if now.Sub(c.lastCleanup) < c.opts.DedupTTL {
		return
	}
	cutoff := now.Add(-2 * c.opts.DedupTTL)
	for k, t := range c.cache {
		if t.Before(cutoff) {
			delete(c.cache, k)
		}
	}
	c.lastCleanup = now
}

func (c *PcapScanCapturer) packetToEvent(pkt gopacket.Packet, iface string) *model.NetEvent {
	ts := pkt.Metadata().Timestamp.UTC()

	var srcIP, dstIP string
	var ipVersion int

	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		l := ip4.(*layers.IPv4)
		srcIP, dstIP = l.SrcIP.String(), l.DstIP.String()
		ipVersion = 4
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		l := ip6.(*layers.IPv6)
		srcIP, dstIP = l.SrcIP.String(), l.DstIP.String()
		ipVersion = 6
	} else if arpL := pkt.Layer(layers.LayerTypeARP); arpL != nil {
		arp := arpL.(*layers.ARP)
		if arp.Operation != layers.ARPRequest {
			return nil
		}

		src := net.IP(arp.SourceProtAddress).String()
		dst := net.IP(arp.DstProtAddress).String()

		if !c.localIPs[dst] {
			return nil
		}
		if c.shouldDrop(src, dst, 0, 0) {
			return nil
		}

		return &model.NetEvent{
			AgentID:   c.agentID,
			EventType: "scan_probe",
			Timestamp: ts,
			SrcIP:     src,
			DstIP:     dst,
			Proto:     "arp",
			Bytes:     len(pkt.Data()),
			Extra: map[string]interface{}{
				"scan_type":  "arp_request",
				"iface":      iface,
				"ip_version": 0,
			},
		}
	} else {
		return nil
	}

	if !c.localIPs[dstIP] {
		return nil
	}
	if c.shouldDrop(srcIP, dstIP, 0, 0) {
		return nil
	}

	if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp := tcpL.(*layers.TCP)

		scanType := classifyTCP(tcp)
		if scanType == "" {
			return nil
		}

		srcPort := int(tcp.SrcPort)
		dstPort := int(tcp.DstPort)

		if c.shouldDrop(srcIP, dstIP, srcPort, dstPort) {
			return nil
		}

		eventType := "scan_probe"
		// SYN to service ports is treated as service probing to avoid scan false positives.
		if scanType == "tcp_syn" && c.opts.ServicePorts[dstPort] {
			eventType = "service_probe"
		}

		extra := map[string]interface{}{
			"scan_type":  scanType,
			"iface":      iface,
			"ip_version": ipVersion,
			"tcp_flags":  tcpFlagsString(tcp),
		}
		if eventType == "service_probe" {
			extra["service_port"] = dstPort
		}

		return &model.NetEvent{
			AgentID:   c.agentID,
			EventType: eventType,
			Timestamp: ts,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Proto:     "tcp",
			Bytes:     len(pkt.Data()),
			Extra:     extra,
		}
	}

	if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		srcPort := int(udp.SrcPort)
		dstPort := int(udp.DstPort)

		if c.shouldDrop(srcIP, dstIP, srcPort, dstPort) {
			return nil
		}

		return &model.NetEvent{
			AgentID:   c.agentID,
			EventType: "scan_probe",
			Timestamp: ts,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Proto:     "udp",
			Bytes:     len(pkt.Data()),
			Extra: map[string]interface{}{
				"scan_type":  "udp_probe",
				"iface":      iface,
				"ip_version": ipVersion,
			},
		}
	}

	if icmp4L := pkt.Layer(layers.LayerTypeICMPv4); icmp4L != nil {
		icmp := icmp4L.(*layers.ICMPv4)
		if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
			return nil
		}
		return &model.NetEvent{
			AgentID:   c.agentID,
			EventType: "scan_probe",
			Timestamp: ts,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Proto:     "icmp",
			Bytes:     len(pkt.Data()),
			Extra: map[string]interface{}{
				"scan_type":  "icmp_echo",
				"iface":      iface,
				"ip_version": ipVersion,
				"icmp_type":  int(icmp.TypeCode.Type()),
				"icmp_code":  int(icmp.TypeCode.Code()),
			},
		}
	}

	if icmp6L := pkt.Layer(layers.LayerTypeICMPv6); icmp6L != nil {
		icmp := icmp6L.(*layers.ICMPv6)
		if icmp.TypeCode.Type() != layers.ICMPv6TypeEchoRequest {
			return nil
		}
		return &model.NetEvent{
			AgentID:   c.agentID,
			EventType: "scan_probe",
			Timestamp: ts,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Proto:     "icmp6",
			Bytes:     len(pkt.Data()),
			Extra: map[string]interface{}{
				"scan_type":  "icmp6_echo",
				"iface":      iface,
				"ip_version": ipVersion,
				"icmp_type":  int(icmp.TypeCode.Type()),
				"icmp_code":  int(icmp.TypeCode.Code()),
			},
		}
	}

	return nil
}

func (c *PcapScanCapturer) shouldDrop(srcIP, dstIP string, srcPort, dstPort int) bool {
	if c.opts.DenySrcPorts[srcPort] {
		return true
	}
	if c.opts.DenyDstPorts[dstPort] {
		return true
	}

	sip := net.ParseIP(srcIP)
	dip := net.ParseIP(dstIP)
	if sip == nil || dip == nil {
		return true
	}

	if c.opts.SkipLoopback && (sip.IsLoopback() || dip.IsLoopback()) {
		return true
	}
	if c.opts.SkipLinkLocal && (sip.IsLinkLocalUnicast() || dip.IsLinkLocalUnicast()) {
		return true
	}

	for _, n := range c.opts.DenyCIDRs {
		if n.Contains(sip) || n.Contains(dip) {
			return true
		}
	}
	return false
}

func classifyTCP(t *layers.TCP) string {
	if t.SYN && !t.ACK {
		return "tcp_syn"
	}
	if t.FIN && !t.SYN && !t.RST && !t.ACK && !t.PSH && !t.URG {
		return "tcp_fin"
	}
	if !t.SYN && !t.ACK && !t.FIN && !t.RST && !t.PSH && !t.URG {
		return "tcp_null"
	}
	if t.FIN && t.PSH && t.URG {
		return "tcp_xmas"
	}
	if t.ACK && !t.SYN && !t.FIN && !t.RST {
		return "tcp_ack"
	}
	return ""
}

func tcpFlagsString(t *layers.TCP) string {
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
