package capture

import "time"

type probeKey struct {
	src   string
	dst   string
	proto string
}

type probeState struct {
	lastSeen time.Time
	total    int
	sshHits  int
	ports    map[int]time.Time
}

type ProbeClassifier struct {
	window time.Duration
	states map[probeKey]*probeState
}

func NewProbeClassifier(window time.Duration) *ProbeClassifier {
	if window <= 0 {
		window = 8 * time.Second
	}
	return &ProbeClassifier{
		window: window,
		states: make(map[probeKey]*probeState, 4096),
	}
}

// Classify returns: "scan_probe" or "ssh_probe"
func (c *ProbeClassifier) Classify(srcIP, dstIP, proto string, dstPort int) string {
	// Only classify TCP/22 as ssh_probe when not looking like a scan.
	// All other probes remain scan_probe.
	if proto != "tcp" {
		return "scan_probe"
	}

	now := time.Now()
	c.gc(now)

	k := probeKey{src: srcIP, dst: dstIP, proto: proto}
	st, ok := c.states[k]
	if !ok {
		st = &probeState{
			lastSeen: now,
			ports:    make(map[int]time.Time, 64),
		}
		c.states[k] = st
	}

	st.lastSeen = now
	st.total++
	st.ports[dstPort] = now
	if dstPort == 22 {
		st.sshHits++
	}

	c.gcPorts(st, now)
	uniquePorts := len(st.ports)

	// Scan dominance: many ports in short window.
	// When this triggers, even port 22 stays as scan_probe.
	if uniquePorts >= 8 || (uniquePorts >= 5 && st.total >= 25) {
		return "scan_probe"
	}

	// If not scan-like and hitting SSH, keep separated as ssh_probe.
	if dstPort == 22 {
		return "ssh_probe"
	}

	return "scan_probe"
}

func (c *ProbeClassifier) gc(now time.Time) {
	if len(c.states) == 0 {
		return
	}
	for k, st := range c.states {
		if now.Sub(st.lastSeen) > c.window {
			delete(c.states, k)
		}
	}
}

func (c *ProbeClassifier) gcPorts(st *probeState, now time.Time) {
	for p, t := range st.ports {
		if now.Sub(t) > c.window {
			delete(st.ports, p)
		}
	}
}
