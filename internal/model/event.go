package model

import "time"

type NetEvent struct {
	AgentID       string    `json:"agent_id"`
	EventType     string    `json:"event_type"`
	SchemaVersion int       `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`

	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`

	Extra map[string]interface{} `json:"extra"`
}
