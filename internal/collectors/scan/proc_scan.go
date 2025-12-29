package scan

import (
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/collectors/proc"
	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

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
	}

	return ev, nil
}
