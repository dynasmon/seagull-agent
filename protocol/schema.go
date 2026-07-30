package protocol

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed schema/protocol-v1.json
var contractDocument []byte

//go:embed schema/compatibility.json
var compatibilityDocument []byte

type Contract struct {
	ProtocolVersion    int                         `json:"protocol_version"`
	EventSchemaVersion int                         `json:"event_schema_version"`
	Endpoints          map[string]ContractEndpoint `json:"endpoints"`
	Headers            map[string]string           `json:"headers"`
	Profiles           map[string]ContractProfile  `json:"profiles"`
	ResponseActions    ContractResponseActions     `json:"response_actions"`
	Defs               map[string]json.RawMessage  `json:"$defs"`
}

type ContractEndpoint struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Listener string `json:"listener"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
}

type ContractProfile struct {
	ResponseActions bool `json:"response_actions"`
	Default         bool `json:"default"`
}

type ContractResponseActions struct {
	Orchestration []string `json:"orchestration"`
	Privileged    []string `json:"privileged"`
}

type CompatibilityWindow struct {
	ProtocolVersion    int `json:"protocol_version"`
	EventSchemaVersion int `json:"event_schema_version"`
	Agent              struct {
		SpeaksProtocol        int `json:"speaks_protocol"`
		AcceptsServerProtocol struct {
			Min int `json:"min"`
			Max int `json:"max"`
		} `json:"accepts_server_protocol"`
		EmitsEventSchema int `json:"emits_event_schema"`
	} `json:"agent"`
	Server struct {
		OldestSupportedAgentProtocol int `json:"oldest_supported_agent_protocol"`
		NewestSupportedAgentProtocol int `json:"newest_supported_agent_protocol"`
		AcceptsEventSchema           struct {
			Min int `json:"min"`
			Max int `json:"max"`
		} `json:"accepts_event_schema"`
	} `json:"server"`
	Rules              map[string]string `json:"rules"`
	IndependentRelease struct {
		ServerUpgradeRequiresAgentUpgrade bool `json:"server_upgrade_requires_agent_upgrade"`
		AgentUpgradeRequiresServerUpgrade bool `json:"agent_upgrade_requires_server_upgrade"`
	} `json:"independent_release"`
}

var (
	contractOnce sync.Once
	contract     Contract
	contractErr  error

	compatibilityOnce sync.Once
	compatibility     CompatibilityWindow
	compatibilityErr  error
)

func ContractDocument() []byte {
	out := make([]byte, len(contractDocument))
	copy(out, contractDocument)
	return out
}

func CompatibilityDocument() []byte {
	out := make([]byte, len(compatibilityDocument))
	copy(out, compatibilityDocument)
	return out
}

func LoadContract() (Contract, error) {
	contractOnce.Do(func() {
		if err := json.Unmarshal(contractDocument, &contract); err != nil {
			contractErr = fmt.Errorf("parse protocol contract: %w", err)
		}
	})
	return contract, contractErr
}

func LoadCompatibility() (CompatibilityWindow, error) {
	compatibilityOnce.Do(func() {
		if err := json.Unmarshal(compatibilityDocument, &compatibility); err != nil {
			compatibilityErr = fmt.Errorf("parse compatibility window: %w", err)
		}
	})
	return compatibility, compatibilityErr
}
