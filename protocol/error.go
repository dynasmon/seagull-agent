package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type ErrorResponse struct {
	Error                   string `json:"error"`
	Kind                    string `json:"kind"`
	AgentProtocolVersion    int    `json:"agent_protocol_version"`
	ServerProtocolVersion   int    `json:"server_protocol_version"`
	MinSupported            int    `json:"min_supported"`
	MaxSupported            int    `json:"max_supported"`
	AgentEventSchemaVersion int    `json:"agent_event_schema_version"`
	EventSchemaVersion      int    `json:"event_schema_version"`
	MinEventSchema          int    `json:"min_event_schema"`
	MaxEventSchema          int    `json:"max_event_schema"`
	Message                 string `json:"message"`
}

type errorEnvelope struct {
	ErrorResponse
	Detail json.RawMessage `json:"detail"`
}

func DecodeIncompatibility(status int, body []byte) (*Incompatibility, bool) {
	if status != http.StatusUpgradeRequired {
		return nil, false
	}

	var envelope errorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &Incompatibility{
			Kind:           IncompatibleServerAdvertise,
			AgentProtocol:  Version,
			HTTPStatus:     status,
			Detail:         "server rejected the agent protocol without a valid structured response",
			ServerResponse: strings.TrimSpace(string(body)),
		}, true
	}

	response := envelope.ErrorResponse
	if len(envelope.Detail) > 0 {
		var nested ErrorResponse
		if json.Unmarshal(envelope.Detail, &nested) == nil {
			response = nested
		} else {
			var message string
			if json.Unmarshal(envelope.Detail, &message) == nil {
				response.Message = message
			}
		}
	}

	agentProtocol := response.AgentProtocolVersion
	if agentProtocol <= 0 {
		agentProtocol = Version
	}
	agentEventSchema := response.AgentEventSchemaVersion
	if agentEventSchema <= 0 {
		agentEventSchema = response.EventSchemaVersion
	}
	if agentEventSchema <= 0 {
		agentEventSchema = EventSchemaVersion
	}

	kind := parseIncompatibilityKind(response.Kind)
	if kind == "" && response.MinSupported > 0 && agentProtocol < response.MinSupported {
		kind = IncompatibleProtocolTooOld
	} else if kind == "" && response.MaxSupported > 0 && agentProtocol > response.MaxSupported {
		kind = IncompatibleProtocolTooNew
	} else if kind == "" && response.MinEventSchema > 0 && agentEventSchema < response.MinEventSchema {
		kind = IncompatibleEventSchema
	} else if kind == "" && response.MaxEventSchema > 0 && agentEventSchema > response.MaxEventSchema {
		kind = IncompatibleEventSchema
	}
	if kind == "" {
		kind = IncompatibleServerAdvertise
	}

	detail := strings.TrimSpace(response.Message)
	if detail == "" {
		detail = fmt.Sprintf(
			"server rejected protocol %d; supported protocol range is %d..%d",
			agentProtocol,
			response.MinSupported,
			response.MaxSupported,
		)
	}

	return &Incompatibility{
		Kind:              kind,
		AgentProtocol:     agentProtocol,
		ServerProtocol:    response.ServerProtocolVersion,
		ServerMin:         response.MinSupported,
		ServerMax:         response.MaxSupported,
		AgentEventSchema:  agentEventSchema,
		ServerEventSchema: response.EventSchemaVersion,
		ServerMinEvent:    response.MinEventSchema,
		ServerMaxEvent:    response.MaxEventSchema,
		HTTPStatus:        status,
		Detail:            detail,
		ServerResponse:    strings.TrimSpace(string(body)),
	}, true
}

func parseIncompatibilityKind(value string) IncompatibilityKind {
	switch IncompatibilityKind(strings.TrimSpace(value)) {
	case IncompatibleProtocolTooOld:
		return IncompatibleProtocolTooOld
	case IncompatibleProtocolTooNew:
		return IncompatibleProtocolTooNew
	case IncompatibleEventSchema:
		return IncompatibleEventSchema
	case IncompatibleServerAdvertise:
		return IncompatibleServerAdvertise
	default:
		return ""
	}
}
