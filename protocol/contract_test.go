package protocol

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestContractMatchesCompiledVersions(t *testing.T) {
	contract := loadContract(t)
	if contract.ProtocolVersion != Version {
		t.Fatalf("contract protocol_version=%d but code Version=%d", contract.ProtocolVersion, Version)
	}
	if contract.EventSchemaVersion != EventSchemaVersion {
		t.Fatalf("contract event_schema_version=%d but code EventSchemaVersion=%d", contract.EventSchemaVersion, EventSchemaVersion)
	}
	if contract.MinEventSchema != MinEventSchema || contract.MaxEventSchema != MaxEventSchema {
		t.Fatalf(
			"contract event schema range=%d..%d but code range=%d..%d",
			contract.MinEventSchema,
			contract.MaxEventSchema,
			MinEventSchema,
			MaxEventSchema,
		)
	}
}

func TestCompatibilityWindowMatchesCompiledVersions(t *testing.T) {
	window := loadCompatibility(t)
	if window.Agent.SpeaksProtocol != Version {
		t.Fatalf("compatibility agent.speaks_protocol=%d but Version=%d", window.Agent.SpeaksProtocol, Version)
	}
	if window.Agent.AcceptsServerProtocol.Min != MinSupportedServer {
		t.Fatalf("compatibility min=%d but MinSupportedServer=%d", window.Agent.AcceptsServerProtocol.Min, MinSupportedServer)
	}
	if window.Agent.AcceptsServerProtocol.Max != MaxSupportedServer {
		t.Fatalf("compatibility max=%d but MaxSupportedServer=%d", window.Agent.AcceptsServerProtocol.Max, MaxSupportedServer)
	}
	if window.Agent.EmitsEventSchema != EventSchemaVersion {
		t.Fatalf("compatibility emits_event_schema=%d but EventSchemaVersion=%d", window.Agent.EmitsEventSchema, EventSchemaVersion)
	}
	if window.Agent.SupportsEventSchema.Min != MinEventSchema ||
		window.Agent.SupportsEventSchema.Max != MaxEventSchema {
		t.Fatalf(
			"compatibility agent event range=%d..%d but code range=%d..%d",
			window.Agent.SupportsEventSchema.Min,
			window.Agent.SupportsEventSchema.Max,
			MinEventSchema,
			MaxEventSchema,
		)
	}
	if window.IndependentRelease.ServerUpgradeRequiresAgentUpgrade {
		t.Fatal("the compatibility window must not require agent upgrades alongside server upgrades")
	}
	if window.IndependentRelease.AgentUpgradeRequiresServerUpgrade {
		t.Fatal("the compatibility window must not require server upgrades alongside agent upgrades")
	}
}

func TestContractResponseActionsMatchCode(t *testing.T) {
	contract := loadContract(t)
	assertSameSet(t, "orchestration", contract.ResponseActions.Orchestration, OrchestrationActions())
	assertSameSet(t, "privileged", contract.ResponseActions.Privileged, PrivilegedActions())
}

func TestContractProfilesMatchCode(t *testing.T) {
	contract := loadContract(t)
	sensor, ok := contract.Profiles[ProfileSensor]
	if !ok {
		t.Fatal("contract does not declare the sensor profile")
	}
	if sensor.ResponseActions {
		t.Fatal("contract declares response actions for the sensor profile")
	}
	if !sensor.Default {
		t.Fatal("sensor must be the default profile in the contract")
	}
	managed, ok := contract.Profiles[ProfileManaged]
	if !ok {
		t.Fatal("contract does not declare the managed profile")
	}
	if !managed.ResponseActions {
		t.Fatal("contract must allow response actions for the managed profile")
	}
	if ProfileAllowsResponseActions(ProfileSensor) != sensor.ResponseActions {
		t.Fatal("sensor profile behaviour diverges from the contract")
	}
	if ProfileAllowsResponseActions(ProfileManaged) != managed.ResponseActions {
		t.Fatal("managed profile behaviour diverges from the contract")
	}
}

func TestContractCoversEveryMessageTypeTheAgentSends(t *testing.T) {
	contract := loadContract(t)
	for _, name := range []string{
		"EnrollRequest", "EnrollResponse", "Credential", "Descriptor",
		"CertificateRenewRequest", "CertificateRenewal", "HeartbeatRequest",
		"NetEvent", "NetEventBatch", "InventorySnapshot", "PackageEntry",
		"EventIngestAcknowledgement", "InventoryAcknowledgement",
		"ResponseAction", "ResponseActionList", "ResponseActionExecutionResult",
		"ErrorResponse", "RemoteConfig", "VulnerabilityScan",
		"VulnerabilityFinding", "VulnerabilityBatch", "VulnerabilityAcknowledgement",
	} {
		if _, ok := contract.Defs[name]; !ok {
			t.Fatalf("contract is missing a definition for %s", name)
		}
	}
}

func TestEveryContractPropertyExistsOnItsGoType(t *testing.T) {
	contract := loadContract(t)

	cases := map[string]interface{}{
		"EnrollRequest":                 EnrollRequest{},
		"EnrollResponse":                EnrollResponse{},
		"Credential":                    Credential{},
		"Descriptor":                    Descriptor{},
		"CertificateRenewRequest":       CertificateRenewRequest{},
		"CertificateRenewal":            CertificateRenewal{},
		"HeartbeatRequest":              HeartbeatRequest{},
		"NetEvent":                      NetEvent{},
		"EventIngestAcknowledgement":    EventIngestAcknowledgement{},
		"InventorySnapshot":             InventorySnapshot{},
		"InventoryAcknowledgement":      InventoryAcknowledgement{},
		"PackageEntry":                  PackageEntry{},
		"ResponseAction":                ResponseAction{},
		"ResponseActionList":            ResponseActionList{},
		"ResponseActionExecutionResult": ResponseActionExecutionResult{},
		"ErrorResponse":                 ErrorResponse{},
		"VulnerabilityScan":             VulnerabilityScan{},
		"VulnerabilityFinding":          VulnerabilityFinding{},
		"VulnerabilityBatch":            VulnerabilityBatch{},
		"VulnerabilityAcknowledgement":  VulnerabilityAcknowledgement{},
	}

	for name, value := range cases {
		raw, ok := contract.Defs[name]
		if !ok {
			t.Fatalf("contract is missing a definition for %s", name)
		}
		var def struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			t.Fatalf("parse %s definition: %v", name, err)
		}
		fields := jsonFieldNames(value)
		for property := range def.Properties {
			if _, ok := fields[property]; !ok {
				t.Fatalf("contract %s declares property %q that %T does not carry", name, property, value)
			}
		}
		for field := range fields {
			if _, ok := def.Properties[field]; !ok {
				t.Fatalf("%T carries field %q that the contract %s does not declare", value, field, name)
			}
		}
	}
}

func TestContractEndpointsCoverTheClientSurface(t *testing.T) {
	contract := loadContract(t)
	for name, want := range map[string]string{
		"enroll":                   "/enroll",
		"heartbeat":                "/agents/heartbeat",
		"config":                   "/agents/config",
		"credential_rotate":        "/agents/credential/rotate",
		"certificate_renew":        "/agents/certificate/renew",
		"response_actions_pending": "/agents/response-actions/pending",
		"response_actions_results": "/agents/response-actions/results",
		"ingest_events":            "/ingest/events",
		"ingest_inventory":         "/inventory",
		"ingest_vuln":              "/vuln/ingest",
	} {
		endpoint, ok := contract.Endpoints[name]
		if !ok {
			t.Fatalf("contract is missing endpoint %s", name)
		}
		if endpoint.Path != want {
			t.Fatalf("contract endpoint %s path=%q want %q", name, endpoint.Path, want)
		}
	}
}

func TestContractDefinesResponseActionCapabilityNegotiation(t *testing.T) {
	contract := loadContract(t)
	heartbeatRaw, ok := contract.Defs["HeartbeatRequest"]
	if !ok {
		t.Fatal("contract is missing HeartbeatRequest")
	}
	var heartbeat struct {
		Properties map[string]struct {
			Ref string `json:"$ref"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(heartbeatRaw, &heartbeat); err != nil {
		t.Fatalf("parse HeartbeatRequest: %v", err)
	}
	if heartbeat.Properties["capabilities"].Ref != "#/$defs/AgentCapabilities" {
		t.Fatalf("heartbeat capabilities do not reference AgentCapabilities")
	}
	capabilitiesRaw, ok := contract.Defs["AgentCapabilities"]
	if !ok {
		t.Fatal("contract is missing AgentCapabilities")
	}
	var capabilities struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}
	if err := json.Unmarshal(capabilitiesRaw, &capabilities); err != nil {
		t.Fatalf("parse AgentCapabilities: %v", err)
	}
	for _, field := range []string{"profile", "response_actions", "response_action_types", "shell_exec"} {
		if _, ok := capabilities.Properties[field]; !ok {
			t.Fatalf("AgentCapabilities is missing %s", field)
		}
	}
	if !capabilities.AdditionalProperties {
		t.Fatal("AgentCapabilities must allow future optional capabilities")
	}
}

func TestAgentMessagesRoundTripThroughTheContractShape(t *testing.T) {
	now := time.Now().UTC()
	event := NetEvent{
		AgentID:       "agent-1",
		EventType:     "net.flow",
		SchemaVersion: EventSchemaVersion,
		Timestamp:     now,
		Extra:         map[string]interface{}{},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	for _, required := range []string{"agent_id", "event_type", "schema_version", "timestamp", "extra"} {
		if _, ok := decoded[required]; !ok {
			t.Fatalf("serialized event is missing required field %q", required)
		}
	}
	if got := decoded["schema_version"]; got != float64(EventSchemaVersion) {
		t.Fatalf("event schema_version=%v want %d", got, EventSchemaVersion)
	}
}

func TestUnknownFieldsAreIgnoredOnDecode(t *testing.T) {
	body := []byte(`{
		"agent_id": "agent-1",
		"credential": {"credential": "agc.agent-1.value", "expires_at": "2030-01-01T00:00:00Z"},
		"protocol": {"protocol_version": 1, "min_supported": 1, "max_supported": 1, "event_schema_version": 1, "future_field": true},
		"config": {},
		"unknown_top_level": {"nested": [1,2,3]}
	}`)
	var out EnrollResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("an enroll response with unknown fields must decode: %v", err)
	}
	if out.Protocol == nil || out.Protocol.ProtocolVersion != 1 {
		t.Fatal("known protocol fields must survive an unknown-field payload")
	}
}

func jsonFieldNames(value interface{}) map[string]struct{} {
	out := make(map[string]struct{})
	rt := reflect.TypeOf(value)
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := tag
		if idx := indexByte(tag, ','); idx >= 0 {
			name = tag[:idx]
		}
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func assertSameSet(t *testing.T, label string, want, got []string) {
	t.Helper()
	a := append([]string(nil), want...)
	b := append([]string(nil), got...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		t.Fatalf("%s action set mismatch: contract=%v code=%v", label, a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%s action set mismatch: contract=%v code=%v", label, a, b)
		}
	}
}

func loadContract(t *testing.T) Contract {
	t.Helper()
	document, err := os.ReadFile("schema/protocol-v1.json")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	contract, err := ParseContract(document)
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	return contract
}

func loadCompatibility(t *testing.T) CompatibilityWindow {
	t.Helper()
	document, err := os.ReadFile("schema/compatibility.json")
	if err != nil {
		t.Fatalf("read compatibility: %v", err)
	}
	window, err := ParseCompatibility(document)
	if err != nil {
		t.Fatalf("load compatibility: %v", err)
	}
	return window
}
