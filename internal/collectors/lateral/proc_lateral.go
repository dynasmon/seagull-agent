package lateral

import (
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/proc"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

func lateralConfidence(kind string, dstPort int, stateHex string) int {
	conf := 55
	if kind == "attempt" {
		conf = 72
	}
	switch dstPort {
	case 445, 3389:
		conf += 8
	case 5985, 5986:
		conf += 6
	case 135, 139:
		conf += 5
	}
	if stateHex == "03" { // SYN_RECV
		conf += 6
	}
	if conf > 95 {
		conf = 95
	}
	return conf
}

type Options struct {
	Ports              map[int]bool
	IncludeEstablished bool
	MaxBatchSize       int
}

type ProcLateralCapturer struct {
	inner              *proc.Capturer
	ports              map[int]bool
	includeEstablished bool
	maxBatch           int
}

func NewProcLateralCapturer(agentID, tcp4Path, tcp6Path string, procOpts proc.Options, o Options) *ProcLateralCapturer {
	if o.Ports == nil || len(o.Ports) == 0 {
		o.Ports = defaultPorts()
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = 500
	}

	procOpts.AllowStates = map[string]bool{
		"03": true, // SYN_RECV (inbound attempt)
	}
	if o.IncludeEstablished {
		procOpts.AllowStates["01"] = true // ESTABLISHED (session)
	}

	if procOpts.DedupTTL <= 0 {
		procOpts.DedupTTL = 5 * time.Second
	}
	if procOpts.MaxBatchSize <= 0 {
		procOpts.MaxBatchSize = o.MaxBatchSize * 4
	}

	return &ProcLateralCapturer{
		inner:              proc.New(agentID, tcp4Path, tcp6Path, procOpts),
		ports:              o.Ports,
		includeEstablished: o.IncludeEstablished,
		maxBatch:           o.MaxBatchSize,
	}
}

func (c *ProcLateralCapturer) Capture() ([]model.NetEvent, error) {
	evs, err := c.inner.Capture()
	if err != nil || len(evs) == 0 {
		return evs, err
	}

	out := make([]model.NetEvent, 0, min(c.maxBatch, len(evs)))

	for i := range evs {
		if len(out) >= c.maxBatch {
			break
		}

		if evs[i].DstPort <= 0 || !c.ports[evs[i].DstPort] {
			continue
		}

		if evs[i].Extra == nil {
			evs[i].Extra = map[string]interface{}{}
		}

		state, _ := evs[i].Extra["tcp_state_hex"].(string)
		kind := "attempt"
		if state == "01" {
			if !c.includeEstablished {
				continue
			}
			kind = "session"
		}

		evs[i].EventType = "lateral_conn"
		evs[i].Extra["lateral_kind"] = kind
		evs[i].Extra["lateral_service"] = serviceForPort(evs[i].DstPort)
		evs[i].Extra["collector"] = "proc_lateral"
		evs[i].Extra["signal_family"] = "lateral"
		stateHex, _ := evs[i].Extra["tcp_state_hex"].(string)
		evs[i].Extra["lateral_confidence"] = lateralConfidence(kind, evs[i].DstPort, stateHex)

		out = append(out, evs[i])
	}

	return out, nil
}

func defaultPorts() map[int]bool {
	return map[int]bool{
		445:  true, // SMB
		3389: true, // RDP
		5985: true, // WinRM
		5986: true, // WinRM TLS
		135:  true, // RPC
		139:  true, // NetBIOS SSN
	}
}

func serviceForPort(p int) string {
	switch p {
	case 445:
		return "smb"
	case 3389:
		return "rdp"
	case 5985:
		return "winrm"
	case 5986:
		return "winrm_tls"
	case 135:
		return "rpc"
	case 139:
		return "netbios_ssn"
	default:
		return "admin"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
