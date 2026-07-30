package protocol

type HeartbeatRequest struct {
	Status          string                 `json:"status"`
	UptimeSeconds   int64                  `json:"uptime_seconds,omitempty"`
	AgentVersion    string                 `json:"agent_version,omitempty"`
	ProtocolVersion int                    `json:"protocol_version,omitempty"`
	Profile         string                 `json:"profile,omitempty"`
	Capabilities    map[string]interface{} `json:"capabilities,omitempty"`
	Modules         map[string]interface{} `json:"modules,omitempty"`
	Metrics         map[string]interface{} `json:"metrics,omitempty"`
}
