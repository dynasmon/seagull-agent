package protocol

type EventIngestAcknowledgement struct {
	Accepted       *bool  `json:"accepted,omitempty"`
	Durable        *bool  `json:"durable,omitempty"`
	Received       *int   `json:"received,omitempty"`
	Enqueued       *int   `json:"enqueued,omitempty"`
	Stored         *int   `json:"stored,omitempty"`
	Duplicate      bool   `json:"duplicate,omitempty"`
	Mode           string `json:"mode,omitempty"`
	RollupsWritten *bool  `json:"rollups_written,omitempty"`
}

type InventoryAcknowledgement struct {
	Accepted  *bool `json:"accepted,omitempty"`
	Durable   *bool `json:"durable,omitempty"`
	Duplicate bool  `json:"duplicate,omitempty"`
	ID        int64 `json:"id,omitempty"`
	Stored    *bool `json:"stored,omitempty"`
}

type VulnerabilityAcknowledgement struct {
	Accepted         *bool  `json:"accepted,omitempty"`
	Durable          *bool  `json:"durable,omitempty"`
	Duplicate        bool   `json:"duplicate,omitempty"`
	ScanID           *int64 `json:"scan_id,omitempty"`
	ScanUUID         string `json:"scan_uuid,omitempty"`
	LifecycleState   string `json:"lifecycle_state,omitempty"`
	CurrentPhase     string `json:"current_phase,omitempty"`
	ReceivedFindings *int   `json:"received_findings,omitempty"`
	StoredFindings   *int   `json:"stored_findings,omitempty"`
}
