package capture

import (
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

// ScanCapturer emits SYN-only probe events derived from /proc/net/tcp*.
// It reuses the proc capturer logic (dedup + filtering) but normalizes
// the event_type to "scan_probe".
type ScanCapturer struct {
	inner *Capturer
}

func NewScanCapturer(agentID, tcp4Path, tcp6Path string, opts Options) *ScanCapturer {
	// Force SYN states (best-effort for port-scan detection).
	opts.AllowStates = map[string]bool{
		"02": true, // SYN_SENT
		"03": true, // SYN_RECV
	}

	// Keep a tighter default for probes.
	if opts.DedupTTL <= 0 {
		opts.DedupTTL = 5 * time.Second
	}

	return &ScanCapturer{inner: New(agentID, tcp4Path, tcp6Path, opts)}
}

func (c *ScanCapturer) Capture() ([]model.NetEvent, error) {
	ev, err := c.inner.Capture()
	if err != nil {
		return nil, err
	}

	for i := range ev {
		ev[i].EventType = "scan_probe"
		if ev[i].Extra == nil {
			ev[i].Extra = map[string]interface{}{}
		}
		ev[i].Extra["classification"] = "syn_probe"
	}

	return ev, nil
}
