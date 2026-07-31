package protocol

import (
	"fmt"
	"sort"
	"strings"
)

const (
	Version            = 1
	MinSupportedServer = 1
	MaxSupportedServer = 1
	EventSchemaVersion = 1
	MinEventSchema     = 1
	MaxEventSchema     = 1
)

type Descriptor struct {
	ProtocolVersion    int    `json:"protocol_version"`
	MinSupported       int    `json:"min_supported"`
	MaxSupported       int    `json:"max_supported"`
	EventSchemaVersion int    `json:"event_schema_version"`
	MinEventSchema     int    `json:"min_event_schema,omitempty"`
	MaxEventSchema     int    `json:"max_event_schema,omitempty"`
	ServerTime         string `json:"server_time,omitempty"`
}

type IncompatibilityKind string

const (
	IncompatibleProtocolTooOld  IncompatibilityKind = "protocol_version_too_old"
	IncompatibleProtocolTooNew  IncompatibilityKind = "protocol_version_too_new"
	IncompatibleEventSchema     IncompatibilityKind = "event_schema_unsupported"
	IncompatibleServerAdvertise IncompatibilityKind = "server_descriptor_invalid"
)

type Incompatibility struct {
	Kind              IncompatibilityKind `json:"kind"`
	AgentProtocol     int                 `json:"agent_protocol"`
	ServerProtocol    int                 `json:"server_protocol"`
	ServerMin         int                 `json:"server_min_supported"`
	ServerMax         int                 `json:"server_max_supported"`
	AgentEventSchema  int                 `json:"agent_event_schema"`
	ServerEventSchema int                 `json:"server_event_schema"`
	ServerMinEvent    int                 `json:"server_min_event_schema"`
	ServerMaxEvent    int                 `json:"server_max_event_schema"`
	HTTPStatus        int                 `json:"http_status,omitempty"`
	Detail            string              `json:"detail"`
	ServerResponse    string              `json:"server_response,omitempty"`
}

func (i *Incompatibility) Error() string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("protocol incompatibility: %s: %s", i.Kind, i.Detail)
}

type Negotiation struct {
	ProtocolVersion    int
	EventSchemaVersion int
	Degraded           bool
	Notes              []string
}

func LocalDescriptor() Descriptor {
	return Descriptor{
		ProtocolVersion:    Version,
		MinSupported:       MinSupportedServer,
		MaxSupported:       MaxSupportedServer,
		EventSchemaVersion: EventSchemaVersion,
		MinEventSchema:     MinEventSchema,
		MaxEventSchema:     MaxEventSchema,
	}
}

func Negotiate(server *Descriptor) (Negotiation, *Incompatibility) {
	local := LocalDescriptor()
	if server == nil {
		return Negotiation{
			ProtocolVersion:    local.ProtocolVersion,
			EventSchemaVersion: local.EventSchemaVersion,
			Degraded:           true,
			Notes:              []string{"server did not advertise a protocol descriptor; assuming protocol 1"},
		}, nil
	}

	serverMin := server.MinSupported
	serverMax := server.MaxSupported
	if serverMin <= 0 && serverMax <= 0 && server.ProtocolVersion > 0 {
		serverMin = server.ProtocolVersion
		serverMax = server.ProtocolVersion
	}
	if serverMin <= 0 || serverMax <= 0 || serverMin > serverMax {
		return Negotiation{}, &Incompatibility{
			Kind:             IncompatibleServerAdvertise,
			AgentProtocol:    local.ProtocolVersion,
			ServerProtocol:   server.ProtocolVersion,
			ServerMin:        server.MinSupported,
			ServerMax:        server.MaxSupported,
			AgentEventSchema: local.EventSchemaVersion,
			Detail:           "server advertised an unusable supported protocol range",
		}
	}

	if local.ProtocolVersion < serverMin {
		return Negotiation{}, &Incompatibility{
			Kind:             IncompatibleProtocolTooOld,
			AgentProtocol:    local.ProtocolVersion,
			ServerProtocol:   server.ProtocolVersion,
			ServerMin:        serverMin,
			ServerMax:        serverMax,
			AgentEventSchema: local.EventSchemaVersion,
			Detail: fmt.Sprintf(
				"agent speaks protocol %d but the server requires at least %d; upgrade the agent",
				local.ProtocolVersion, serverMin,
			),
		}
	}
	if local.ProtocolVersion > serverMax {
		return Negotiation{}, &Incompatibility{
			Kind:             IncompatibleProtocolTooNew,
			AgentProtocol:    local.ProtocolVersion,
			ServerProtocol:   server.ProtocolVersion,
			ServerMin:        serverMin,
			ServerMax:        serverMax,
			AgentEventSchema: local.EventSchemaVersion,
			Detail: fmt.Sprintf(
				"agent speaks protocol %d but the server supports at most %d; upgrade the server",
				local.ProtocolVersion, serverMax,
			),
		}
	}

	serverEventSchema := server.EventSchemaVersion
	serverMinEvent := server.MinEventSchema
	serverMaxEvent := server.MaxEventSchema
	if serverMinEvent <= 0 && serverMaxEvent <= 0 {
		if serverEventSchema <= 0 {
			serverEventSchema = EventSchemaVersion
		}
		serverMinEvent = serverEventSchema
		serverMaxEvent = serverEventSchema
	}
	if serverMinEvent <= 0 || serverMaxEvent <= 0 || serverMinEvent > serverMaxEvent {
		return Negotiation{}, &Incompatibility{
			Kind:              IncompatibleServerAdvertise,
			AgentProtocol:     local.ProtocolVersion,
			ServerProtocol:    server.ProtocolVersion,
			ServerMin:         serverMin,
			ServerMax:         serverMax,
			AgentEventSchema:  local.EventSchemaVersion,
			ServerEventSchema: serverEventSchema,
			ServerMinEvent:    server.MinEventSchema,
			ServerMaxEvent:    server.MaxEventSchema,
			Detail:            "server advertised an unusable supported event schema range",
		}
	}
	if serverEventSchema > 0 && (serverEventSchema < serverMinEvent || serverEventSchema > serverMaxEvent) {
		return Negotiation{}, &Incompatibility{
			Kind:              IncompatibleServerAdvertise,
			AgentProtocol:     local.ProtocolVersion,
			ServerProtocol:    server.ProtocolVersion,
			ServerMin:         serverMin,
			ServerMax:         serverMax,
			AgentEventSchema:  local.EventSchemaVersion,
			ServerEventSchema: serverEventSchema,
			ServerMinEvent:    serverMinEvent,
			ServerMaxEvent:    serverMaxEvent,
			Detail:            "server event schema version is outside its advertised supported range",
		}
	}
	if MaxEventSchema < serverMinEvent || MinEventSchema > serverMaxEvent {
		return Negotiation{}, &Incompatibility{
			Kind:              IncompatibleEventSchema,
			AgentProtocol:     local.ProtocolVersion,
			ServerProtocol:    server.ProtocolVersion,
			ServerMin:         serverMin,
			ServerMax:         serverMax,
			AgentEventSchema:  local.EventSchemaVersion,
			ServerEventSchema: serverEventSchema,
			ServerMinEvent:    serverMinEvent,
			ServerMaxEvent:    serverMaxEvent,
			Detail: fmt.Sprintf(
				"agent supports event schemas %d..%d but the server accepts %d..%d",
				MinEventSchema, MaxEventSchema, serverMinEvent, serverMaxEvent,
			),
		}
	}

	negotiatedEventSchema := local.EventSchemaVersion
	if negotiatedEventSchema > serverMaxEvent {
		negotiatedEventSchema = serverMaxEvent
	}
	negotiated := Negotiation{
		ProtocolVersion:    local.ProtocolVersion,
		EventSchemaVersion: negotiatedEventSchema,
	}
	if negotiatedEventSchema < local.EventSchemaVersion {
		negotiated.Degraded = true
		negotiated.Notes = append(negotiated.Notes, fmt.Sprintf(
			"emitting event schema %d because the server accepts at most %d",
			negotiatedEventSchema, serverMaxEvent,
		))
	}
	return negotiated, nil
}

func UnknownCapabilities(reported map[string]interface{}, known []string) []string {
	index := make(map[string]struct{}, len(known))
	for _, name := range known {
		index[name] = struct{}{}
	}
	out := make([]string, 0)
	for name := range reported {
		if _, ok := index[strings.TrimSpace(name)]; !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
