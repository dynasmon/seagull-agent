package scan

import (
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/proc"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

func scanConfidenceFromProcState(stateHex string) int {
	switch stateHex {
	case "02", "03": // SYN_SENT / SYN_RECV
		return 82
	case "01": // ESTABLISHED tends to be less scan-like
		return 55
	default:
		return 45
	}
}

// ProcScanCapturer emits SYN-only probe events derived from /proc/net/tcp*.
type ProcScanCapturer struct {
	inner *proc.Capturer
}

func NewProcScanCapturer(agentID, tcp4Path, tcp6Path string, opts proc.Options) *ProcScanCapturer {
	opts.AllowStates = map[string]bool{
		"02": true, // SYN_SENT
		"03": true, // SYN_RECV
	}

	if opts.DedupTTL <= 0 {
		opts.DedupTTL = 5 * time.Second
	}

	return &ProcScanCapturer{
		inner: proc.New(agentID, tcp4Path, tcp6Path, opts),
	}
}

func (c *ProcScanCapturer) Capture() ([]model.NetEvent, error) {
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
		ev[i].Extra["scan_type"] = "tcp_syn"
		ev[i].Extra["collector"] = "proc_scan"
		ev[i].Extra["signal_family"] = "scan"
		stateHex, _ := ev[i].Extra["tcp_state_hex"].(string)
		ev[i].Extra["scan_confidence"] = scanConfidenceFromProcState(stateHex)
		ev[i].Extra["syn_only"] = true
	}

	return ev, nil
}
