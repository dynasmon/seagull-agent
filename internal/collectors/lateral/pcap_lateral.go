package lateral

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/pcapx"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/netcontext"
)

type PcapLateralOptions struct {
	Interface   string
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration

	DedupTTL     time.Duration
	MaxBatchSize int

	SkipLoopback  bool
	SkipLinkLocal bool

	DenyCIDRs []*net.IPNet

	Ports map[int]bool
}

type PcapLateralCapturer struct {
	agentID string
	opts    PcapLateralOptions

	netCtx *netcontext.NetworkContext

	buffer *pcapx.Buffer
}

func NewPcapLateralCapturer(agentID string, opts PcapLateralOptions) (*PcapLateralCapturer, error) {
	applyPcapLateralDefaults(&opts)

	if len(opts.Ports) == 0 {
		return nil, fmt.Errorf("lateral pcap: ports set is empty")
	}

	nc, err := netcontext.Collect(netcontext.Caps{})
	if err != nil {
		return nil, err
	}
	if len(nc.LocalIPs) == 0 {
		return nil, fmt.Errorf("lateral pcap: no local IPs detected")
	}

	return &PcapLateralCapturer{
		agentID: agentID,
		opts:    opts,
		netCtx:  nc,
		buffer:  pcapx.NewBuffer(opts.DedupTTL, opts.MaxBatchSize),
	}, nil
}

func applyPcapLateralDefaults(o *PcapLateralOptions) {
	if o.SnapLen <= 0 {
		o.SnapLen = 96
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
	if o.Ports == nil {
		o.Ports = map[int]bool{}
	}
}

func (c *PcapLateralCapturer) Start(ctx context.Context) error {
	iface := strings.TrimSpace(c.opts.Interface)
	if iface == "" {
		iface = "any"
	}

	handle, err := pcap.OpenLive(iface, int32(c.opts.SnapLen), c.opts.Promisc, c.opts.ReadTimeout)
	if err != nil {
		return fmt.Errorf("pcap open iface=%s: %w", iface, err)
	}
	defer handle.Close()

	bpf := c.buildBPF()
	if err := handle.SetBPFFilter(bpf); err != nil {
		return fmt.Errorf("pcap bpf set (%s): %w", bpf, err)
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

func (c *PcapLateralCapturer) buildBPF() string {
	ports := make([]int, 0, len(c.opts.Ports))
	for p := range c.opts.Ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	clauses := make([]string, 0, len(ports))
	for _, p := range ports {
		clauses = append(clauses, fmt.Sprintf("dst port %d", p))
	}

	// SYN-only (attempt): tcp[tcpflags] & (syn|ack) == syn
	// This catches inbound attempts even when the port is closed (RST will be sent, but SYN exists).
	return fmt.Sprintf("tcp and (%s) and (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)", strings.Join(clauses, " or "))
}

func (c *PcapLateralCapturer) Drain() []model.NetEvent {
	return c.buffer.Drain()
}

func (c *PcapLateralCapturer) push(ev model.NetEvent) {
	if ev.Extra == nil {
		ev.Extra = map[string]interface{}{}
	}
	c.netCtx.EnrichEndpoints(ev.Extra, ev.SrcIP, ev.DstIP)

	key := fmt.Sprintf("%s|%s|%s|%d",
		ev.Proto, ev.SrcIP, ev.DstIP, ev.DstPort,
	)

	c.buffer.Push(key, ev)
}

func (c *PcapLateralCapturer) packetToEvent(pkt gopacket.Packet, iface string) *model.NetEvent {
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
	} else {
		return nil
	}

	// Only inbound-to-host attempts
	if !c.netCtx.LocalIPs[dstIP] {
		return nil
	}
	if c.shouldDrop(srcIP, dstIP) {
		return nil
	}

	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if tcpL == nil {
		return nil
	}
	tcp := tcpL.(*layers.TCP)

	dstPort := int(tcp.DstPort)
	if dstPort <= 0 || !c.opts.Ports[dstPort] {
		return nil
	}
	synOnly := tcp.SYN && !tcp.ACK
	confidence := 62
	if synOnly {
		confidence = 78
	}
	switch dstPort {
	case 445, 3389:
		confidence += 10
	case 5985, 5986:
		confidence += 8
	case 135, 139:
		confidence += 6
	}
	if confidence > 95 {
		confidence = 95
	}

	return &model.NetEvent{
		AgentID:   c.agentID,
		EventType: "lateral_conn",
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   int(tcp.SrcPort),
		DstPort:   dstPort,
		Proto:     "tcp",
		Bytes:     len(pkt.Data()),
		Extra: map[string]interface{}{
			"lateral_kind":       "attempt",
			"iface":              iface,
			"ip_version":         ipVersion,
			"tcp_flags":          pcapx.TCPFlags(tcp),
			"collector":          "pcap_lateral",
			"signal_family":      "lateral",
			"syn_only":           synOnly,
			"lateral_confidence": confidence,
		},
	}
}

func (c *PcapLateralCapturer) shouldDrop(srcIP, dstIP string) bool {
	return pcapx.DropByIP(srcIP, dstIP, c.opts.SkipLoopback, c.opts.SkipLinkLocal, false, c.opts.DenyCIDRs)
}
