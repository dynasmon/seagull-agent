package l7

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

type PcapL7Options struct {
	Interface   string
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration

	DedupTTL     time.Duration
	MaxBatchSize int

	MaxPayloadBytes int
	IncludePayload  bool

	SkipLoopback  bool
	SkipLinkLocal bool
}

type dedupEntry struct {
	at time.Time
}

type PcapL7Capturer struct {
	agentID string
	opts    PcapL7Options

	localIPs map[string]bool

	mu          sync.Mutex
	buf         []model.NetEvent
	cache       map[string]dedupEntry
	lastCleanup time.Time
}

func NewPcapL7Capturer(agentID string, opts PcapL7Options) (*PcapL7Capturer, error) {
	applyDefaults(&opts)

	localIPs, err := collectLocalIPs()
	if err != nil {
		return nil, err
	}
	if len(localIPs) == 0 {
		return nil, fmt.Errorf("l7 pcap: no local IPs detected")
	}

	return &PcapL7Capturer{
		agentID:     strings.TrimSpace(agentID),
		opts:        opts,
		localIPs:    localIPs,
		buf:         make([]model.NetEvent, 0, opts.MaxBatchSize),
		cache:       make(map[string]dedupEntry, 4096),
		lastCleanup: time.Now().UTC(),
	}, nil
}

func applyDefaults(o *PcapL7Options) {
	if strings.TrimSpace(o.Interface) == "" {
		o.Interface = "any"
	}
	if o.SnapLen <= 0 {
		o.SnapLen = 768
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 500 * time.Millisecond
	}
	if o.DedupTTL <= 0 {
		o.DedupTTL = 20 * time.Second
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = 400
	}
	if o.MaxPayloadBytes <= 0 {
		o.MaxPayloadBytes = 768
	}
}

func (c *PcapL7Capturer) Start(ctx context.Context) error {
	handle, err := pcap.OpenLive(c.opts.Interface, int32(c.opts.SnapLen), c.opts.Promisc, c.opts.ReadTimeout)
	if err != nil {
		return fmt.Errorf("pcap open iface=%s: %w", c.opts.Interface, err)
	}
	defer handle.Close()

	filter := "(tcp or udp) and (port 53 or port 80 or port 8080 or port 8000 or port 8888 or port 443 or port 8443 or port 9443)"
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("pcap bpf set (%s): %w", filter, err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.Lazy = true
	src.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			pkt, err := src.NextPacket()
			if err != nil || pkt == nil {
				continue
			}
			if ev := c.packetToEvent(pkt); ev != nil {
				c.push(*ev)
			}
		}
	}
}

func (c *PcapL7Capturer) Drain() []model.NetEvent {
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

func (c *PcapL7Capturer) push(ev model.NetEvent) {
	now := time.Now().UTC()
	key := c.dedupKey(ev)

	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.cache[key]; ok && now.Sub(old.at) < c.opts.DedupTTL {
		return
	}
	if len(c.buf) >= c.opts.MaxBatchSize {
		return
	}
	c.cache[key] = dedupEntry{at: now}
	c.buf = append(c.buf, ev)
	c.cleanupLocked(now)
}

func (c *PcapL7Capturer) cleanupLocked(now time.Time) {
	if now.Sub(c.lastCleanup) < c.opts.DedupTTL {
		return
	}
	cut := now.Add(-2 * c.opts.DedupTTL)
	for k, v := range c.cache {
		if v.at.Before(cut) {
			delete(c.cache, k)
		}
	}
	c.lastCleanup = now
}

func (c *PcapL7Capturer) dedupKey(ev model.NetEvent) string {
	extra := ev.Extra
	if extra == nil {
		extra = map[string]interface{}{}
	}
	var kind string
	kind = strings.ToLower(strings.TrimSpace(toString(extra["l7_protocol"])))
	return fmt.Sprintf("%s|%s|%d|%s|%d|%s|%s",
		ev.Proto, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort, kind, strings.TrimSpace(toString(extra["flow_direction"])),
	)
}

func (c *PcapL7Capturer) packetToEvent(pkt gopacket.Packet) *model.NetEvent {
	ts := time.Now().UTC()
	if meta := pkt.Metadata(); meta != nil && !meta.Timestamp.IsZero() {
		ts = meta.Timestamp.UTC()
	}

	var srcIP, dstIP net.IP
	var ipVersion int
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		l := ip4.(*layers.IPv4)
		srcIP = l.SrcIP
		dstIP = l.DstIP
		ipVersion = 4
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		l := ip6.(*layers.IPv6)
		srcIP = l.SrcIP
		dstIP = l.DstIP
		ipVersion = 6
	} else {
		return nil
	}

	if srcIP == nil || dstIP == nil {
		return nil
	}
	if c.opts.SkipLoopback && (srcIP.IsLoopback() || dstIP.IsLoopback()) {
		return nil
	}
	if c.opts.SkipLinkLocal && (srcIP.IsLinkLocalUnicast() || dstIP.IsLinkLocalUnicast()) {
		return nil
	}

	srcS := srcIP.String()
	dstS := dstIP.String()
	srcLocal := c.localIPs[srcS]
	dstLocal := c.localIPs[dstS]
	if srcLocal == dstLocal {
		// Keep only local<->remote traffic.
		return nil
	}

	flowDirection := "inbound_to_local"
	if srcLocal {
		flowDirection = "outbound_from_local"
	}

	var sport, dport int
	var proto string
	var payload []byte

	if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
		t := tcpL.(*layers.TCP)
		sport = int(t.SrcPort)
		dport = int(t.DstPort)
		proto = "tcp"
		payload = t.Payload
	} else if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
		u := udpL.(*layers.UDP)
		sport = int(u.SrcPort)
		dport = int(u.DstPort)
		proto = "udp"
		payload = u.Payload
	} else {
		return nil
	}

	if sport <= 0 || dport <= 0 {
		return nil
	}
	if len(payload) == 0 {
		return nil
	}

	kind, evidence := classifyPayload(proto, sport, dport, payload)
	if kind == "" {
		return nil
	}

	trimmed := payload
	if len(trimmed) > c.opts.MaxPayloadBytes {
		trimmed = trimmed[:c.opts.MaxPayloadBytes]
	}
	if c.opts.IncludePayload && len(trimmed) > 0 {
		l7 := asMap(evidence["l7"])
		if l7 == nil {
			l7 = map[string]interface{}{}
		}
		l7["payload_b64"] = base64.StdEncoding.EncodeToString(trimmed)
		l7["payload_size"] = len(trimmed)
		evidence["l7"] = l7
	}

	evidence["collector"] = "pcap_l7"
	evidence["collection_method"] = "pcap_sample"
	evidence["signal_family"] = "protocol_intel"
	evidence["flow_direction"] = flowDirection
	evidence["ip_version"] = ipVersion
	evidence["l7_protocol"] = kind
	evidence["app_proto"] = kind

	return &model.NetEvent{
		AgentID:   c.agentID,
		EventType: "l7_flow",
		Timestamp: ts,
		SrcIP:     srcS,
		DstIP:     dstS,
		SrcPort:   sport,
		DstPort:   dport,
		Proto:     proto,
		Bytes:     len(payload),
		Extra:     evidence,
	}
}

func classifyPayload(proto string, sport, dport int, payload []byte) (string, map[string]interface{}) {
	kind := ""
	extra := map[string]interface{}{}

	dnsPayload := payload
	if proto == "tcp" && (sport == 53 || dport == 53) && len(payload) > 2 {
		declared := int(payload[0])<<8 | int(payload[1])
		if declared > 0 && declared <= len(payload)-2 {
			dnsPayload = payload[2 : 2+declared]
		}
	}

	if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 {
		if dns := parseDNSMetadata(dnsPayload); dns != nil {
			kind = "dns"
			extra["l7"] = map[string]interface{}{"protocol": "dns", "dns": dns}
			extra["dns_evidence"] = dns
			return kind, extra
		}
	}

	if proto == "tcp" && isHTTPPort(sport, dport) {
		if h := parseHTTPMetadata(payload); h != nil {
			kind = "http"
			extra["l7"] = map[string]interface{}{"protocol": "http", "http": h}
			extra["http_evidence"] = h
			return kind, extra
		}
	}

	if isDTLS(payload) {
		kind = "dtls"
		extra["is_dtls"] = true
		extra["ja4_ptype"] = "d"
		extra["l7"] = map[string]interface{}{"protocol": "dtls"}
		return kind, extra
	}
	if looksLikeQUICInitial(payload) && proto == "udp" && (sport == 443 || dport == 443) {
		kind = "quic"
		extra["is_quic"] = true
		extra["ja4_ptype"] = "q"
		extra["l7"] = map[string]interface{}{"protocol": "quic"}
		return kind, extra
	}

	if isTLSClientHello(payload) {
		kind = "tls"
		l7 := map[string]interface{}{"protocol": "tls", "tls": parseTLSMetadata(payload)}
		extra["l7"] = l7
		return kind, extra
	}
	return "", nil
}

func parseDNSMetadata(payload []byte) map[string]interface{} {
	if len(payload) < 12 {
		return nil
	}
	id := int(payload[0])<<8 | int(payload[1])
	flags := int(payload[2])<<8 | int(payload[3])
	qd := int(payload[4])<<8 | int(payload[5])
	an := int(payload[6])<<8 | int(payload[7])
	rcode := flags & 0xF
	qr := (flags >> 15) & 0x1

	out := map[string]interface{}{
		"id":          id,
		"is_response": qr == 1,
		"rcode":       rcode,
		"qdcount":     qd,
		"ancount":     an,
	}

	if qd <= 0 {
		return out
	}
	name, offset := decodeDNSName(payload, 12, 0)
	if name != "" {
		out["qname"] = name
	}
	if offset+4 <= len(payload) {
		qtype := int(payload[offset])<<8 | int(payload[offset+1])
		out["qtype"] = qtype
		offset += 4
	}

	if an <= 0 || offset <= 0 || offset >= len(payload) {
		return out
	}
	answers := make([]string, 0, min(an, 6))
	for i := 0; i < an && i < 6; i++ {
		_, next := decodeDNSName(payload, offset, 0)
		offset = next
		if offset+10 > len(payload) {
			break
		}
		rtype := int(payload[offset])<<8 | int(payload[offset+1])
		rdlen := int(payload[offset+8])<<8 | int(payload[offset+9])
		offset += 10
		if rdlen <= 0 || offset+rdlen > len(payload) {
			break
		}
		rdata := payload[offset : offset+rdlen]
		switch rtype {
		case 1: // A
			if len(rdata) == 4 {
				answers = append(answers, net.IP(rdata).String())
			}
		case 28: // AAAA
			if len(rdata) == 16 {
				answers = append(answers, net.IP(rdata).String())
			}
		case 5, 2: // CNAME / NS
			if nm, _ := decodeDNSName(payload, offset, 0); nm != "" {
				answers = append(answers, nm)
			}
		}
		offset += rdlen
	}
	if len(answers) > 0 {
		out["answers"] = answers
	}
	return out
}

func decodeDNSName(payload []byte, off int, depth int) (string, int) {
	if depth > 8 || off < 0 || off >= len(payload) {
		return "", off
	}
	labels := make([]string, 0, 6)
	i := off
	for i < len(payload) {
		l := int(payload[i])
		if l == 0 {
			i++
			break
		}
		// pointer
		if (l & 0xC0) == 0xC0 {
			if i+1 >= len(payload) {
				return strings.Join(labels, "."), i + 1
			}
			ptr := (l&0x3F)<<8 | int(payload[i+1])
			ref, _ := decodeDNSName(payload, ptr, depth+1)
			if ref != "" {
				labels = append(labels, ref)
			}
			i += 2
			break
		}
		i++
		if i+l > len(payload) {
			break
		}
		labels = append(labels, strings.ToLower(string(payload[i:i+l])))
		i += l
	}
	return strings.Trim(strings.Join(labels, "."), "."), i
}

func parseHTTPMetadata(payload []byte) map[string]interface{} {
	if len(payload) < 8 {
		return nil
	}
	text := string(payload)
	if len(text) > 4096 {
		text = text[:4096]
	}
	head := text
	if idx := strings.Index(head, "\r\n\r\n"); idx > 0 {
		head = head[:idx]
	}
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 {
		return nil
	}
	first := strings.TrimSpace(lines[0])
	if first == "" {
		return nil
	}
	out := map[string]interface{}{}
	if strings.HasPrefix(first, "HTTP/") {
		parts := strings.Fields(first)
		if len(parts) < 2 {
			return nil
		}
		out["direction"] = "response"
		out["status"] = parts[1]
		out["version"] = parts[0]
	} else {
		parts := strings.Fields(first)
		if len(parts) < 2 {
			return nil
		}
		method := strings.ToUpper(parts[0])
		if !isHTTPMethod(method) {
			return nil
		}
		out["direction"] = "request"
		out["method"] = method
		out["path"] = trimString(parts[1], 1024)
		if len(parts) >= 3 {
			out["version"] = parts[2]
		}
	}

	for _, ln := range lines[1:] {
		i := strings.IndexByte(ln, ':')
		if i <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(ln[:i]))
		v := trimString(strings.TrimSpace(ln[i+1:]), 1024)
		switch k {
		case "host":
			out["host"] = strings.ToLower(v)
		case "user-agent":
			out["user_agent"] = v
		}
	}
	return out
}

func trimString(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

func parseTLSMetadata(payload []byte) map[string]interface{} {
	out := map[string]interface{}{}
	if len(payload) >= 3 {
		ver := uint16(payload[1])<<8 | uint16(payload[2])
		out["record_version"] = tlsVersionHint(ver)
	}
	if len(payload) < 9 || payload[0] != 0x16 {
		return out
	}
	recLen := int(payload[3])<<8 | int(payload[4])
	if recLen <= 0 {
		return out
	}
	end := 5 + recLen
	if end > len(payload) {
		end = len(payload)
	}
	rec := payload[5:end]
	if len(rec) < 4 || rec[0] != 0x01 {
		return out
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if hsLen <= 0 {
		return out
	}
	bodyEnd := 4 + hsLen
	if bodyEnd > len(rec) {
		bodyEnd = len(rec)
	}
	body := rec[4:bodyEnd]
	if len(body) < 42 {
		return out
	}
	i := 0
	chVer := uint16(body[i])<<8 | uint16(body[i+1])
	out["version"] = tlsVersionHint(chVer)
	i += 2 + 32
	if i >= len(body) {
		return out
	}
	sidLen := int(body[i])
	i++
	if i+sidLen > len(body) {
		return out
	}
	i += sidLen
	if i+2 > len(body) {
		return out
	}
	csLen := int(body[i])<<8 | int(body[i+1])
	i += 2
	if i+csLen > len(body) {
		return out
	}
	i += csLen
	if i >= len(body) {
		return out
	}
	compLen := int(body[i])
	i++
	if i+compLen > len(body) {
		return out
	}
	i += compLen
	if i+2 > len(body) {
		return out
	}
	extLen := int(body[i])<<8 | int(body[i+1])
	i += 2
	extEnd := i + extLen
	if extEnd > len(body) {
		extEnd = len(body)
	}
	for i+4 <= extEnd {
		etype := int(body[i])<<8 | int(body[i+1])
		elen := int(body[i+2])<<8 | int(body[i+3])
		i += 4
		if elen <= 0 || i+elen > extEnd {
			break
		}
		ext := body[i : i+elen]
		switch etype {
		case 0x0000:
			if sni := parseTLSSNI(ext); sni != "" {
				out["sni"] = sni
			}
		case 0x0010:
			if alpn := parseTLSALPN(ext); alpn != "" {
				out["alpn"] = alpn
			}
		}
		i += elen
	}
	return out
}

func parseTLSSNI(ext []byte) string {
	if len(ext) < 5 {
		return ""
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	i := 2
	end := i + listLen
	if end > len(ext) {
		end = len(ext)
	}
	for i+3 <= end {
		nameType := ext[i]
		nameLen := int(ext[i+1])<<8 | int(ext[i+2])
		i += 3
		if nameLen <= 0 || i+nameLen > end {
			break
		}
		if nameType == 0 {
			return strings.ToLower(strings.Trim(strings.TrimSpace(string(ext[i:i+nameLen])), "."))
		}
		i += nameLen
	}
	return ""
}

func parseTLSALPN(ext []byte) string {
	if len(ext) < 3 {
		return ""
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	i := 2
	end := i + listLen
	if end > len(ext) {
		end = len(ext)
	}
	if i >= end {
		return ""
	}
	firstLen := int(ext[i])
	i++
	if firstLen <= 0 || i+firstLen > end {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(ext[i : i+firstLen])))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func tlsVersionHint(v uint16) string {
	switch v {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func isHTTPPort(srcPort, dstPort int) bool {
	ports := []int{srcPort, dstPort}
	for _, p := range ports {
		switch p {
		case 80, 8000, 8080, 8888:
			return true
		}
	}
	return false
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func isTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	return payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

func isDTLS(payload []byte) bool {
	if len(payload) < 13 {
		return false
	}
	if payload[0] != 0x16 {
		return false
	}
	ver := uint16(payload[1])<<8 | uint16(payload[2])
	return ver == 0xFEFF || ver == 0xFEFD || ver == 0xFEFC
}

func looksLikeQUICInitial(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	// Long header bit set and fixed bit set (RFC 9000).
	first := payload[0]
	return (first&0x80) == 0x80 && (first&0x40) == 0x40
}

func collectLocalIPs() (map[string]bool, error) {
	out := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip = ip.To16()
			if ip == nil {
				continue
			}
			out[ip.String()] = true
		}
	}
	return out, nil
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}
