package proc

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type Options struct {
	AllowStates map[string]bool

	DedupTTL       time.Duration
	EstablishedTTL time.Duration

	SkipLoopback         bool
	SkipLinkLocal        bool
	SkipPrivateToPrivate bool

	// Drops flows that are very likely outbound: remote well-known port -> local ephemeral port.
	DropLikelyOutbound bool
	EphemeralPortMin   int

	DenyCIDRs    []*net.IPNet
	DenyDstPorts map[int]bool
	DenySrcPorts map[int]bool

	MaxBatchSize int
	IncludeIPv6  bool
}

type dedupEntry struct {
	lastState string
	lastSent  time.Time
}

type Capturer struct {
	agentID     string
	tcp4Path    string
	tcp6Path    string
	opts        Options
	cache       map[string]dedupEntry
	lastCleanup time.Time
}

func New(agentID, tcp4Path, tcp6Path string, opts Options) *Capturer {
	applyDefaults(&opts)
	return &Capturer{
		agentID:     agentID,
		tcp4Path:    tcp4Path,
		tcp6Path:    tcp6Path,
		opts:        opts,
		cache:       make(map[string]dedupEntry, 4096),
		lastCleanup: time.Now(),
	}
}

func applyDefaults(o *Options) {
	if o.DedupTTL <= 0 {
		o.DedupTTL = 30 * time.Second
	}
	if o.EstablishedTTL <= 0 {
		o.EstablishedTTL = 10 * time.Minute
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = 500
	}
	if o.EphemeralPortMin <= 0 {
		o.EphemeralPortMin = 49152
	}
	if o.AllowStates == nil {
		o.AllowStates = map[string]bool{
			"01": true, // ESTABLISHED
			"02": true, // SYN_SENT
			"03": true, // SYN_RECV
			"04": true, // FIN_WAIT1
			"05": true, // FIN_WAIT2
			"08": true, // CLOSE_WAIT
			"09": true, // LAST_ACK
			"0B": true, // CLOSING
		}
	}
	if o.DenyDstPorts == nil {
		o.DenyDstPorts = map[int]bool{}
	}
	if o.DenySrcPorts == nil {
		o.DenySrcPorts = map[int]bool{}
	}
}

func (c *Capturer) Capture() ([]model.NetEvent, error) {
	now := time.Now().UTC()

	var out []model.NetEvent

	ev4, err := c.captureProc4(now)
	if err != nil {
		return nil, err
	}
	out = append(out, ev4...)

	if c.opts.IncludeIPv6 {
		ev6, err := c.captureProc6(now)
		if err == nil {
			out = append(out, ev6...)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	out = c.dedupAndLimit(now, out)
	c.cleanup(now)

	return out, nil
}

// Standardized (host-centric) semantics:
//   src_* = remote (client/attacker)
//   dst_* = local (monitored host/target port)
func (c *Capturer) captureProc4(ts time.Time) ([]model.NetEvent, error) {
	f, err := os.Open(c.tcp4Path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", c.tcp4Path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	events := make([]model.NetEvent, 0, 256)

	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if firstLine {
			firstLine = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localAddr := fields[1]
		remAddr := fields[2]
		stateHex := strings.ToUpper(fields[3])

		if !c.opts.AllowStates[stateHex] {
			continue
		}

		localIP, localPort, err := parseHexIPPort4(localAddr)
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseHexIPPort4(remAddr)
		if err != nil {
			continue
		}

		// Invalid/zero remote endpoint.
		if remotePort == 0 || remoteIP == "0.0.0.0" {
			continue
		}

		// shouldDrop expects (src=remote, dst=local).
		if c.shouldDrop(remoteIP, localIP, remotePort, localPort) {
			continue
		}

		extra := map[string]interface{}{
			"flow_id":       uuid.NewString(),
			"tcp_state_hex": stateHex,
			"ip_version":    4,

			"local_ip":    localIP,
			"local_port":  localPort,
			"remote_ip":   remoteIP,
			"remote_port": remotePort,
		}

		// Best-effort parsing for optional fields.
		if len(fields) > 9 {
			if uid, e := strconv.Atoi(fields[7]); e == nil {
				extra["uid"] = uid
			}
			if inode, e := strconv.ParseUint(fields[9], 10, 64); e == nil {
				extra["inode"] = inode
			}
		}

		events = append(events, model.NetEvent{
			AgentID:   c.agentID,
			EventType: "flow",
			Timestamp: ts,

			SrcIP:   remoteIP,
			SrcPort: remotePort,
			DstIP:   localIP,
			DstPort: localPort,

			Proto: "tcp",
			Bytes: 0,
			Extra: extra,
		})
	}

	if err := scanner.Err(); err != nil {
		return events, fmt.Errorf("scan %s: %w", c.tcp4Path, err)
	}

	return events, nil
}

func (c *Capturer) captureProc6(ts time.Time) ([]model.NetEvent, error) {
	f, err := os.Open(c.tcp6Path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", c.tcp6Path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	events := make([]model.NetEvent, 0, 256)

	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if firstLine {
			firstLine = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localAddr := fields[1]
		remAddr := fields[2]
		stateHex := strings.ToUpper(fields[3])

		if !c.opts.AllowStates[stateHex] {
			continue
		}

		localIP, localPort, err := parseHexIPPort6(localAddr)
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseHexIPPort6(remAddr)
		if err != nil {
			continue
		}

		if remotePort == 0 || remoteIP == "::" {
			continue
		}

		if c.shouldDrop(remoteIP, localIP, remotePort, localPort) {
			continue
		}

		extra := map[string]interface{}{
			"flow_id":       uuid.NewString(),
			"tcp_state_hex": stateHex,
			"ip_version":    6,

			"local_ip":    localIP,
			"local_port":  localPort,
			"remote_ip":   remoteIP,
			"remote_port": remotePort,
		}

		if len(fields) > 9 {
			if uid, e := strconv.Atoi(fields[7]); e == nil {
				extra["uid"] = uid
			}
			if inode, e := strconv.ParseUint(fields[9], 10, 64); e == nil {
				extra["inode"] = inode
			}
		}

		events = append(events, model.NetEvent{
			AgentID:   c.agentID,
			EventType: "flow",
			Timestamp: ts,

			SrcIP:   remoteIP,
			SrcPort: remotePort,
			DstIP:   localIP,
			DstPort: localPort,

			Proto: "tcp6",
			Bytes: 0,
			Extra: extra,
		})
	}

	if err := scanner.Err(); err != nil {
		return events, fmt.Errorf("scan %s: %w", c.tcp6Path, err)
	}

	return events, nil
}

func (c *Capturer) shouldDrop(srcIP, dstIP string, srcPort, dstPort int) bool {
	// Drop flows that are very likely outbound (remote well-known port -> local ephemeral port).
	if c.opts.DropLikelyOutbound {
		ephMin := c.opts.EphemeralPortMin
		if ephMin <= 0 {
			ephMin = 49152
		}
		if dstPort >= ephMin && srcPort > 0 && srcPort < ephMin {
			return true
		}
	}

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
	if c.opts.SkipPrivateToPrivate && sip.IsPrivate() && dip.IsPrivate() {
		return true
	}

	for _, n := range c.opts.DenyCIDRs {
		if n.Contains(sip) || n.Contains(dip) {
			return true
		}
	}

	return false
}

func (c *Capturer) stateTTL(stateHex string) time.Duration {
	if stateHex == "01" {
		return c.opts.EstablishedTTL
	}
	return c.opts.DedupTTL
}

func (c *Capturer) dedupAndLimit(now time.Time, in []model.NetEvent) []model.NetEvent {
	if len(in) == 0 {
		return in
	}

	out := make([]model.NetEvent, 0, min(len(in), c.opts.MaxBatchSize))

	for _, ev := range in {
		if len(out) >= c.opts.MaxBatchSize {
			break
		}

		key := fmt.Sprintf("%s|%s|%d|%s|%d", ev.Proto, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
		stateHex, _ := ev.Extra["tcp_state_hex"].(string)
		ttl := c.stateTTL(stateHex)

		if entry, ok := c.cache[key]; ok {
			if entry.lastState == stateHex && now.Sub(entry.lastSent) < ttl {
				continue
			}
		}

		c.cache[key] = dedupEntry{lastState: stateHex, lastSent: now}
		out = append(out, ev)
	}

	return out
}

func (c *Capturer) cleanup(now time.Time) {
	if now.Sub(c.lastCleanup) < c.opts.DedupTTL {
		return
	}

	cutoff := now.Add(-2 * c.opts.EstablishedTTL)
	for k, v := range c.cache {
		if v.lastSent.Before(cutoff) {
			delete(c.cache, k)
		}
	}
	c.lastCleanup = now
}

func parseHexIPPort4(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %s", s)
	}

	ipHex := parts[0]
	portHex := parts[1]
	if len(ipHex) != 8 {
		return "", 0, fmt.Errorf("invalid ipv4 hex: %s", ipHex)
	}

	ipBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b, err := strconv.ParseUint(ipHex[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", 0, err
		}
		// IPv4 in /proc/net/tcp is little-endian.
		ipBytes[3-i] = byte(b)
	}

	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, err
	}

	ip := fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	return ip, int(port64), nil
}

func parseHexIPPort6(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %s", s)
	}

	ipHex := parts[0]
	portHex := parts[1]
	if len(ipHex) != 32 {
		return "", 0, fmt.Errorf("invalid ipv6 hex: %s", ipHex)
	}

	// /proc/net/tcp6 uses 32-bit words in little-endian order.
	var b strings.Builder
	b.Grow(32)
	for i := 0; i < 4; i++ {
		w := ipHex[i*8 : (i+1)*8]
		b.WriteString(w[6:8])
		b.WriteString(w[4:6])
		b.WriteString(w[2:4])
		b.WriteString(w[0:2])
	}

	ipBytes, err := hex.DecodeString(b.String())
	if err != nil {
		return "", 0, err
	}

	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, err
	}

	return net.IP(ipBytes).String(), int(port64), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
