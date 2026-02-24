package vuln

import "time"

type ScanMeta struct {
	ScanUUID    string                 `json:"scan_uuid,omitempty"`
	Target      string                 `json:"target,omitempty"`
	Tool        string                 `json:"tool"`
	ToolVersion string                 `json:"tool_version,omitempty"`
	Status      string                 `json:"status"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	FinishedAt  *time.Time             `json:"finished_at,omitempty"`
	Scope       map[string]interface{} `json:"scope,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Stats       map[string]interface{} `json:"stats,omitempty"`
}

type Finding struct {
	AssetKey     string                 `json:"asset_key"`
	AssetAgentID string                 `json:"asset_agent_id,omitempty"`
	Target       string                 `json:"target,omitempty"`
	Asset        map[string]interface{} `json:"asset,omitempty"`

	Source      string `json:"source"`
	ExternalID  string `json:"external_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"`

	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`

	CVE  string `json:"cve,omitempty"`
	CWE  string `json:"cwe,omitempty"`
	CVSS string `json:"cvss,omitempty"`

	Location string                 `json:"location,omitempty"`
	Tags     []string               `json:"tags,omitempty"`
	Evidence map[string]interface{} `json:"evidence,omitempty"`

	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

type IngestBatch struct {
	Scan     *ScanMeta `json:"scan,omitempty"`
	Findings []Finding `json:"findings"`
}
