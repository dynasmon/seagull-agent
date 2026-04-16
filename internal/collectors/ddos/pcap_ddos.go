package ddos

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

type PcapDDoSOptions struct {
	Interface   string
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration

	Window         time.Duration
	EvalEvery      time.Duration
	Cooldown       time.Duration
	SustainWindows int

	BaselineWarmupWindows int
	BaselineAlpha         float64
	BaselineFactor        float64

	MinPPS        float64
	MinBPS        float64
	MinPackets    int
	MinRequests   int
	MinConfidence int

	MinSynRatio float64

	DDoSMinSrcIPs         int
	DDoSMinSrcEntropyNorm float64

	EnableL7    bool
	MinHTTPRPS  float64
	MinTLSHSRPS float64
	MinL7Ratio  float64

	EnableEntropy      bool
	MinSrcEntropyNorm  float64
	MinPortEntropyNorm float64
	PortEntropyTopN    int

	CardinalityMode string
	HLLPrecision    int
	BloomBits       int
	MaxUniqueSrc    int
	TopSrc          int

	MaxBatchSize int
	// When the output buffer reaches this size, packet processing is sampled down.
	BackpressureHighWatermark int
	// Process 1 out of N packets while backpressured.
	BackpressureSampleEvery int

	DropLikelyOutbound bool
	EphemeralPortMin   int

	SkipLoopback  bool
	SkipLinkLocal bool

	DenyCIDRs    []*net.IPNet
	DenyDstPorts map[int]bool
	DenySrcPorts map[int]bool
}

type PcapDDoSCapturer struct {
	agentID string
	opts    PcapDDoSOptions

	localIPs map[string]bool

	mu  sync.Mutex
	buf []model.NetEvent
	// bufLen mirrors len(buf) and is read on the hot path without lock contention.
	bufLen int64

	windowStart time.Time
	aggs        map[aggKey]*agg

	backpressureSeq     uint64
	backpressureDropped uint64
}

type aggKey struct {
	dst   string
	proto string
	dport int
}

type agg struct {
	key aggKey

	pkts  int
	bytes int

	tcpPkts        int
	tcpSynPkts     int
	tcpPayloadPkts int
	httpReqPkts    int
	tlsHelloPkts   int

	udpPkts    int
	udpAmpPkts int
	icmpPkts   int

	srcCard cardCounter
	topSrc  *TopKStr

	baselinePPS float64
	baselineBPS float64
	warmupOK    int

	sustain     int
	lastAlertAt time.Time
	lastSeenAt  time.Time
}

type hostKey struct {
	dst   string
	proto string
}

type hostPortState struct {
	totalPkts int
	ports     *TopKInt
}

func NewPcapDDoSCapturer(agentID string, opts PcapDDoSOptions) (*PcapDDoSCapturer, error) {
	applyDDoSDefaults(&opts)

	localIPs, err := collectLocalIPs()
	if err != nil {
		return nil, err
	}
	if len(localIPs) == 0 {
		return nil, fmt.Errorf("no local IPs detected")
	}

	return &PcapDDoSCapturer{
		agentID:     agentID,
		opts:        opts,
		localIPs:    localIPs,
		buf:         make([]model.NetEvent, 0, 1024),
		windowStart: time.Now().UTC(),
		aggs:        make(map[aggKey]*agg, 256),
	}, nil
}

func applyDDoSDefaults(o *PcapDDoSOptions) {
	if o.SnapLen <= 0 {
		o.SnapLen = 256
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 500 * time.Millisecond
	}
	if o.Window <= 0 {
		o.Window = 5 * time.Second
	}
	if o.EvalEvery <= 0 {
		o.EvalEvery = 1 * time.Second
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 30 * time.Second
	}
	if o.SustainWindows <= 0 {
		o.SustainWindows = 2
	}
	if o.BaselineWarmupWindows <= 0 {
		o.BaselineWarmupWindows = 6
	}
	if o.BaselineAlpha <= 0 || o.BaselineAlpha > 1 {
		o.BaselineAlpha = 0.2
	}
	if o.BaselineFactor <= 1 {
		o.BaselineFactor = 4.0
	}
	if o.MinPPS <= 0 {
		o.MinPPS = 300
	}
	if o.MinBPS <= 0 {
		o.MinBPS = 500_000
	}
	if o.MinPackets < 0 {
		o.MinPackets = 0
	}
	if o.MinRequests < 0 {
		o.MinRequests = 0
	}
	if o.MinConfidence <= 0 {
		o.MinConfidence = 75
	}
	if o.MinSynRatio <= 0 {
		o.MinSynRatio = 0.70
	}
	if o.DDoSMinSrcIPs <= 0 {
		o.DDoSMinSrcIPs = 2
	}
	if o.DDoSMinSrcEntropyNorm <= 0 {
		o.DDoSMinSrcEntropyNorm = 0.55
	}
	if o.MinHTTPRPS <= 0 {
		o.MinHTTPRPS = 60
	}
	if o.MinTLSHSRPS <= 0 {
		o.MinTLSHSRPS = 60
	}
	if o.MinL7Ratio <= 0 {
		o.MinL7Ratio = 0.25
	}
	if o.MinSrcEntropyNorm <= 0 {
		o.MinSrcEntropyNorm = 0.50
	}
	if o.MinPortEntropyNorm <= 0 {
		o.MinPortEntropyNorm = 0.70
	}
	if o.PortEntropyTopN <= 0 {
		o.PortEntropyTopN = 12
	}
	if o.CardinalityMode == "" {
		o.CardinalityMode = "hll"
	}
	if o.HLLPrecision <= 0 {
		o.HLLPrecision = 8
	}
	if o.BloomBits <= 0 {
		o.BloomBits = 2048
	}
	if o.MaxUniqueSrc <= 0 {
		o.MaxUniqueSrc = 4096
	}
	if o.TopSrc <= 0 {
		o.TopSrc = 10
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = 200
	}
	if o.BackpressureHighWatermark <= 0 {
		o.BackpressureHighWatermark = int(float64(o.MaxBatchSize) * 0.80)
	}
	if o.BackpressureHighWatermark > o.MaxBatchSize {
		o.BackpressureHighWatermark = o.MaxBatchSize
	}
	if o.BackpressureSampleEvery <= 0 {
		o.BackpressureSampleEvery = 4
	}
	if o.EphemeralPortMin <= 0 {
		o.EphemeralPortMin = 49152
	}
	if o.DenyDstPorts == nil {
		o.DenyDstPorts = map[int]bool{}
	}
	if o.DenySrcPorts == nil {
		o.DenySrcPorts = map[int]bool{}
	}
}

func (c *PcapDDoSCapturer) Start(ctx context.Context) error {
	iface := strings.TrimSpace(c.opts.Interface)
	if iface == "" {
		iface = "any"
	}

	handle, err := pcap.OpenLive(iface, int32(c.opts.SnapLen), c.opts.Promisc, c.opts.ReadTimeout)
	if err != nil {
		return fmt.Errorf("pcap open iface=%s: %w", iface, err)
	}
	defer handle.Close()

	bpf := "tcp or udp or icmp or icmp6"
	if err := handle.SetBPFFilter(bpf); err != nil {
		return fmt.Errorf("pcap bpf set (%s): %w", bpf, err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.Lazy = true
	src.NoCopy = true
	packetCh := src.Packets()
	ticker := time.NewTicker(c.opts.EvalEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.rotateIfNeeded(time.Now().UTC())
		case pkt, ok := <-packetCh:
			if !ok {
				return nil
			}
			if pkt == nil {
				continue
			}
			c.onPacket(pkt)
		}
	}
}

func (c *PcapDDoSCapturer) Drain() []model.NetEvent {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.buf) == 0 {
		return nil
	}
	out := make([]model.NetEvent, len(c.buf))
	copy(out, c.buf)
	c.buf = c.buf[:0]
	atomic.StoreInt64(&c.bufLen, 0)
	return out
}

func (c *PcapDDoSCapturer) push(ev model.NetEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) >= c.opts.MaxBatchSize {
		atomic.AddUint64(&c.backpressureDropped, 1)
		return
	}
	c.buf = append(c.buf, ev)
	atomic.StoreInt64(&c.bufLen, int64(len(c.buf)))
}

func (c *PcapDDoSCapturer) sampleWeight() int {
	if c.opts.BackpressureHighWatermark <= 0 {
		return 1
	}
	if int(atomic.LoadInt64(&c.bufLen)) < c.opts.BackpressureHighWatermark {
		return 1
	}

	n := atomic.AddUint64(&c.backpressureSeq, 1)
	every := c.opts.BackpressureSampleEvery
	if every <= 1 || n%uint64(every) == 0 {
		if every <= 1 {
			return 1
		}
		return every
	}
	atomic.AddUint64(&c.backpressureDropped, 1)
	return 0
}

func (c *PcapDDoSCapturer) onPacket(pkt gopacket.Packet) {
	weight := c.sampleWeight()
	if weight <= 0 {
		return
	}

	var srcIP, dstIP net.IP

	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		l := ip4.(*layers.IPv4)
		srcIP, dstIP = l.SrcIP, l.DstIP
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		l := ip6.(*layers.IPv6)
		srcIP, dstIP = l.SrcIP, l.DstIP
	} else {
		return
	}

	if isSkippableIP(srcIP, c.opts.SkipLoopback, c.opts.SkipLinkLocal) {
		return
	}
	if isSkippableIP(dstIP, c.opts.SkipLoopback, c.opts.SkipLinkLocal) {
		return
	}
	if ipInCIDRs(srcIP, c.opts.DenyCIDRs) || ipInCIDRs(dstIP, c.opts.DenyCIDRs) {
		return
	}

	srcS := srcIP.String()
	dstS := dstIP.String()

	if !c.localIPs[dstS] {
		return
	}
	if c.localIPs[srcS] {
		return
	}

	capLen := 0
	if pkt.Metadata() != nil {
		capLen = int(pkt.Metadata().CaptureLength)
	}
	if capLen <= 0 {
		capLen = len(pkt.Data())
	}
	if capLen <= 0 {
		capLen = 1
	}

	now := time.Now().UTC()

	if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp := tcpL.(*layers.TCP)
		sport := int(tcp.SrcPort)
		dport := int(tcp.DstPort)

		if c.opts.DenyDstPorts[dport] || c.opts.DenySrcPorts[sport] {
			return
		}

		if c.opts.DropLikelyOutbound && c.opts.EphemeralPortMin > 0 && dport >= c.opts.EphemeralPortMin {
			return
		}

		k := aggKey{dst: dstS, proto: "tcp", dport: dport}
		a := c.getAgg(k, now)
		a.pkts += weight
		a.bytes += capLen * weight
		a.tcpPkts += weight
		if tcp.SYN && !tcp.ACK {
			a.tcpSynPkts += weight
		}
		if len(tcp.Payload) > 0 {
			a.tcpPayloadPkts += weight
			if c.opts.EnableL7 {
				if isHTTPPort(dport) && isHTTPPayload(tcp.Payload) {
					a.httpReqPkts += weight
				}
				if isTLSPort(dport) && isTLSClientHello(tcp.Payload) {
					a.tlsHelloPkts += weight
				}
			}
		}
		a.srcCard.Add(srcS)
		a.topSrc.Add(srcS, weight)
		return
	}

	if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		sport := int(udp.SrcPort)
		dport := int(udp.DstPort)

		if c.opts.DenyDstPorts[dport] || c.opts.DenySrcPorts[sport] {
			return
		}

		if c.opts.DropLikelyOutbound && c.opts.EphemeralPortMin > 0 && dport >= c.opts.EphemeralPortMin {
			return
		}

		k := aggKey{dst: dstS, proto: "udp", dport: dport}
		a := c.getAgg(k, now)
		a.pkts += weight
		a.bytes += capLen * weight
		a.udpPkts += weight
		if isAmplificationSrcPort(sport) {
			a.udpAmpPkts += weight
		}
		a.srcCard.Add(srcS)
		a.topSrc.Add(srcS, weight)
		return
	}

	if pkt.Layer(layers.LayerTypeICMPv4) != nil {
		k := aggKey{dst: dstS, proto: "icmp", dport: 0}
		a := c.getAgg(k, now)
		a.pkts += weight
		a.bytes += capLen * weight
		a.icmpPkts += weight
		a.srcCard.Add(srcS)
		a.topSrc.Add(srcS, weight)
		return
	}
	if pkt.Layer(layers.LayerTypeICMPv6) != nil {
		k := aggKey{dst: dstS, proto: "icmp6", dport: 0}
		a := c.getAgg(k, now)
		a.pkts += weight
		a.bytes += capLen * weight
		a.icmpPkts += weight
		a.srcCard.Add(srcS)
		a.topSrc.Add(srcS, weight)
		return
	}
}

func (c *PcapDDoSCapturer) getAgg(k aggKey, now time.Time) *agg {
	a, ok := c.aggs[k]
	if ok {
		a.lastSeenAt = now
		return a
	}
	a = &agg{
		key:         k,
		srcCard:     newCardCounter(c.opts.CardinalityMode, c.opts.MaxUniqueSrc, c.opts.HLLPrecision, c.opts.BloomBits),
		topSrc:      NewTopKStr(c.opts.TopSrc),
		baselinePPS: 0,
		baselineBPS: 0,
		warmupOK:    0,
		lastSeenAt:  now,
	}
	c.aggs[k] = a
	return a
}

func (c *PcapDDoSCapturer) rotateIfNeeded(now time.Time) {
	if now.Sub(c.windowStart) < c.opts.Window {
		return
	}
	backpressureDropped := int(atomic.SwapUint64(&c.backpressureDropped, 0))
	sustainNeeded := c.opts.SustainWindows
	if backpressureDropped > 0 {
		sustainNeeded = max(1, sustainNeeded-1)
	}

	windowSec := c.opts.Window.Seconds()
	if windowSec <= 0 {
		windowSec = 1
	}

	hostPorts := make(map[hostKey]*hostPortState, 64)
	for _, a := range c.aggs {
		if a.pkts <= 0 {
			continue
		}
		hk := hostKey{dst: a.key.dst, proto: a.key.proto}
		hs, ok := hostPorts[hk]
		if !ok {
			hs = &hostPortState{ports: NewTopKInt(c.opts.PortEntropyTopN)}
			hostPorts[hk] = hs
		}
		hs.totalPkts += a.pkts
		hs.ports.Add(a.key.dport, a.pkts)
	}

	portMetrics := make(map[hostKey]PortEntropy, len(hostPorts))
	for hk, hs := range hostPorts {
		portMetrics[hk] = portEntropy(hs.totalPkts, hs.ports.ItemsSorted())
	}

	staleCutoff := now.Add(-10 * c.opts.Window)
	for k, a := range c.aggs {
		if a.lastSeenAt.Before(staleCutoff) {
			delete(c.aggs, k)
			continue
		}
		if a.pkts <= 0 {
			continue
		}

		pps := float64(a.pkts) / windowSec
		bps := float64(a.bytes) / windowSec
		uniqueSrc := a.srcCard.Estimate()
		uniqueCapped := a.srcCard.Capped()
		cardMode := a.srcCard.Kind()

		topSrc := a.topSrc.ItemsSorted()
		srcEnt := 0.0
		if c.opts.EnableEntropy {
			srcEnt = srcEntropyNorm(a.pkts, topSrc)
		}

		hk := hostKey{dst: a.key.dst, proto: a.key.proto}
		pm := portMetrics[hk]

		synRatio := 0.0
		if a.tcpPkts > 0 {
			synRatio = float64(a.tcpSynPkts) / float64(a.tcpPkts)
		}

		httpRPS := float64(a.httpReqPkts) / windowSec
		tlsRPS := float64(a.tlsHelloPkts) / windowSec
		l7Ratio := 0.0
		if a.tcpPayloadPkts > 0 {
			l7Ratio = float64(a.httpReqPkts+a.tlsHelloPkts) / float64(a.tcpPayloadPkts)
		}

		reqCount := a.httpReqPkts + a.tlsHelloPkts
		packetsOK := (c.opts.MinPackets <= 0) || (a.pkts >= c.opts.MinPackets)
		requestsOK := (c.opts.MinRequests <= 0) || (reqCount >= c.opts.MinRequests)

		volOver := packetsOK && ((pps >= c.opts.MinPPS) || (bps >= c.opts.MinBPS))
		l7Over := c.opts.EnableL7 && packetsOK && requestsOK && l7Ratio >= c.opts.MinL7Ratio && (httpRPS >= c.opts.MinHTTPRPS || tlsRPS >= c.opts.MinTLSHSRPS)
		absOver := volOver || l7Over

		baselineReady := a.warmupOK >= c.opts.BaselineWarmupWindows && a.baselinePPS > 0 && a.baselineBPS > 0
		relOver := baselineReady && (pps >= a.baselinePPS*c.opts.BaselineFactor || bps >= a.baselineBPS*c.opts.BaselineFactor)

		trigger := absOver && (l7Over || !baselineReady || relOver)
		if trigger {
			a.sustain++
		} else {
			a.sustain = 0
		}
		if !trigger {
			if a.warmupOK == 0 {
				a.baselinePPS = pps
				a.baselineBPS = bps
			} else {
				alpha := c.opts.BaselineAlpha
				a.baselinePPS = (1-alpha)*a.baselinePPS + alpha*pps
				a.baselineBPS = (1-alpha)*a.baselineBPS + alpha*bps
			}
			a.warmupOK++
		}

		vector, ampRatio := classifyVector(c.opts, a, synRatio, httpRPS, tlsRPS, l7Ratio)

		distributed := uniqueSrc >= c.opts.DDoSMinSrcIPs
		if c.opts.EnableEntropy {
			distributed = distributed && (srcEnt >= c.opts.DDoSMinSrcEntropyNorm)
		}
		attack := "dos"
		if distributed {
			attack = "ddos"
		}

		srcEntropySignal := c.opts.EnableEntropy && srcEnt >= c.opts.MinSrcEntropyNorm
		portEntropySignal := c.opts.EnableEntropy && pm.EntropyNorm >= c.opts.MinPortEntropyNorm

		conf := computeConfidence(trigger, baselineReady, relOver, distributed, vector, pps, bps, synRatio, httpRPS, tlsRPS, l7Ratio, ampRatio, srcEnt, pm)
		sev := severityFrom(conf, pps, bps, distributed)

		shouldEmit := trigger && a.sustain >= sustainNeeded && conf >= c.opts.MinConfidence
		if shouldEmit {
			if !a.lastAlertAt.IsZero() && now.Sub(a.lastAlertAt) < c.opts.Cooldown {
				shouldEmit = false
			}
		}

		if shouldEmit {
			ev := model.NetEvent{
				AgentID:   c.agentID,
				EventType: "dos_attack",
				Timestamp: now,
				DstIP:     a.key.dst,
				DstPort:   a.key.dport,
				Proto:     a.key.proto,
				Bytes:     a.bytes,
				Extra: map[string]interface{}{
					"attack":              attack,
					"distributed":         distributed,
					"vector":              vector,
					"severity":            sev,
					"confidence":          conf,
					"window_seconds":      int(c.opts.Window.Seconds()),
					"packets":             a.pkts,
					"requests":            reqCount,
					"pps":                 round2(pps),
					"bps":                 round2(bps),
					"unique_src_ips":      uniqueSrc,
					"unique_src_capped":   uniqueCapped,
					"cardinality_mode":    cardMode,
					"src_entropy_norm":    round2(srcEnt),
					"src_entropy_signal":  srcEntropySignal,
					"port_entropy_signal": portEntropySignal,
					"port_entropy_norm":   round2(pm.EntropyNorm),
					"port_distinct":       pm.Distinct,
					"port_top":            pm.TopPort,
					"port_top_share":      round2(pm.TopShare),
					"tcp_syn_ratio":       round2(synRatio),
					"http_rps":            round2(httpRPS),
					"tls_handshake_rps":   round2(tlsRPS),
					"l7_ratio":            round2(l7Ratio),
					"udp_amp_ratio":       round2(ampRatio),
					"baseline_pps":        round2(a.baselinePPS),
					"baseline_bps":        round2(a.baselineBPS),
					"baseline_ready":      baselineReady,
					"baseline_factor":     round2(c.opts.BaselineFactor),
					"top_src":             topSrc,
					"collector_bp_compensated":     backpressureDropped > 0,
					"collector_bp_sample_every":    c.opts.BackpressureSampleEvery,
					"collector_sustain_windows":    c.opts.SustainWindows,
					"collector_sustain_effective":  sustainNeeded,
					"collector_bp_dropped_packets": backpressureDropped,
				},
			}
			c.push(ev)
			a.lastAlertAt = now
		}

		a.pkts = 0
		a.bytes = 0
		a.tcpPkts = 0
		a.tcpSynPkts = 0
		a.tcpPayloadPkts = 0
		a.httpReqPkts = 0
		a.tlsHelloPkts = 0
		a.udpPkts = 0
		a.udpAmpPkts = 0
		a.icmpPkts = 0
		a.srcCard.Reset()
		a.topSrc.Reset()
	}

	c.windowStart = now
}

func classifyVector(opts PcapDDoSOptions, a *agg, synRatio float64, httpRPS float64, tlsRPS float64, l7Ratio float64) (string, float64) {
	switch a.key.proto {
	case "tcp":
		if opts.EnableL7 && httpRPS >= opts.MinHTTPRPS && l7Ratio >= opts.MinL7Ratio && isHTTPPort(a.key.dport) {
			return "http_flood", 0
		}
		if opts.EnableL7 && tlsRPS >= opts.MinTLSHSRPS && l7Ratio >= opts.MinL7Ratio && isTLSPort(a.key.dport) {
			return "tls_handshake_flood", 0
		}
		if synRatio >= opts.MinSynRatio && a.tcpPkts >= 50 {
			return "tcp_syn_flood", 0
		}
		return "tcp_flood", 0
	case "udp":
		ampRatio := 0.0
		if a.udpPkts > 0 {
			ampRatio = float64(a.udpAmpPkts) / float64(a.udpPkts)
		}
		if ampRatio >= 0.60 && a.udpPkts >= 50 {
			return "udp_amp_flood", ampRatio
		}
		return "udp_flood", ampRatio
	case "icmp", "icmp6":
		return "icmp_flood", 0
	default:
		return "flood", 0
	}
}

func computeConfidence(trigger bool, baselineReady bool, relOver bool, distributed bool, vector string, pps float64, bps float64, synRatio float64, httpRPS float64, tlsRPS float64, l7Ratio float64, ampRatio float64, srcEnt float64, pm PortEntropy) int {
	conf := 0

	if trigger {
		conf += 25
	}
	if baselineReady && relOver {
		conf += 15
	}

	if pps >= 1000 {
		conf += 10
	}
	if bps >= 2_000_000 {
		conf += 10
	}

	if distributed {
		conf += 20
	} else {
		conf += 8
	}
	if srcEnt >= 0.75 {
		conf += 10
	} else if srcEnt >= 0.55 {
		conf += 6
	}

	switch vector {
	case "tcp_syn_flood":
		if synRatio >= 0.85 {
			conf += 12
		} else {
			conf += 8
		}
	case "http_flood":
		if httpRPS >= 200 {
			conf += 15
		} else {
			conf += 10
		}
		if l7Ratio >= 0.60 {
			conf += 5
		}
	case "tls_handshake_flood":
		if tlsRPS >= 200 {
			conf += 15
		} else {
			conf += 10
		}
		if l7Ratio >= 0.60 {
			conf += 5
		}
	case "udp_amp_flood":
		if ampRatio >= 0.80 {
			conf += 15
		} else {
			conf += 10
		}
	}

	if pm.TopShare >= 0.85 && pm.EntropyNorm <= 0.35 {
		conf += 5
	}

	if conf < 0 {
		conf = 0
	}
	if conf > 100 {
		conf = 100
	}
	return conf
}

func severityFrom(conf int, pps float64, bps float64, distributed bool) string {
	if conf >= 90 {
		return "critical"
	}
	if conf >= 80 {
		return "high"
	}
	if conf >= 70 {
		if distributed && (pps >= 1500 || bps >= 5_000_000) {
			return "high"
		}
		return "medium"
	}
	return "low"
}

func isAmplificationSrcPort(port int) bool {
	switch port {
	case 53, 123, 1900, 11211, 389, 19, 161, 520, 69, 5353:
		return true
	default:
		return false
	}
}

func round2(v float64) float64 {
	if v != v {
		return 0
	}
	return float64(int(v*100+0.5)) / 100
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
