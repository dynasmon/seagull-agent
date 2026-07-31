package protocol

type EnrollRequest struct {
	AgentID         string `json:"agent_id"`
	Hostname        string `json:"hostname,omitempty"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	Profile         string `json:"profile,omitempty"`
	CSRPEM          string `json:"csr_pem,omitempty"`
	BootstrapToken  string `json:"-"`
}

type EnrollResponse struct {
	AgentID     string                 `json:"agent_id"`
	Config      map[string]interface{} `json:"config"`
	Credential  Credential             `json:"credential"`
	Certificate *CertificateRenewal    `json:"certificate,omitempty"`
	Protocol    *Descriptor            `json:"protocol,omitempty"`
}

type Credential struct {
	Credential            string `json:"credential"`
	ExpiresAt             string `json:"expires_at"`
	MaxUses               int    `json:"max_uses"`
	UsedUses              int    `json:"used_uses"`
	RenewalToken          string `json:"renewal_token"`
	RenewalTokenExpiresAt string `json:"renewal_token_expires_at"`
}

type CertificateRenewal struct {
	AgentID        string `json:"agent_id"`
	CertificatePEM string `json:"certificate_pem"`
	CAPEM          string `json:"ca_pem"`
	ServerCAPEM    string `json:"server_ca_pem,omitempty"`
	SerialHex      string `json:"serial_hex"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

type CertificateRenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}
