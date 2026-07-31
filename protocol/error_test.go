package protocol

import (
	"net/http"
	"testing"
)

func TestDecodeNestedIncompatibility(t *testing.T) {
	body := []byte(`{"detail":{"error":"incompatible_protocol","kind":"protocol_version_too_old","agent_protocol_version":1,"server_protocol_version":2,"min_supported":2,"max_supported":3,"agent_event_schema_version":1,"event_schema_version":2,"min_event_schema":1,"max_event_schema":2,"message":"upgrade required"}}`)
	incompatible, ok := DecodeIncompatibility(http.StatusUpgradeRequired, body)
	if !ok || incompatible == nil {
		t.Fatal("structured incompatibility was not decoded")
	}
	if incompatible.Kind != IncompatibleProtocolTooOld {
		t.Fatalf("kind=%s want %s", incompatible.Kind, IncompatibleProtocolTooOld)
	}
	if incompatible.ServerProtocol != 2 || incompatible.ServerMin != 2 || incompatible.ServerMax != 3 {
		t.Fatalf("unexpected protocol range: %+v", incompatible)
	}
	if incompatible.ServerMinEvent != 1 || incompatible.ServerMaxEvent != 2 {
		t.Fatalf("unexpected event schema range: %+v", incompatible)
	}
}

func TestDecodeMalformedUpgradeResponseFailsClosed(t *testing.T) {
	incompatible, ok := DecodeIncompatibility(http.StatusUpgradeRequired, []byte(`not-json`))
	if !ok || incompatible == nil {
		t.Fatal("HTTP 426 must be treated as incompatible")
	}
	if incompatible.Kind != IncompatibleServerAdvertise {
		t.Fatalf("kind=%s want %s", incompatible.Kind, IncompatibleServerAdvertise)
	}
}

func TestDecodeIgnoresOtherStatuses(t *testing.T) {
	if incompatible, ok := DecodeIncompatibility(http.StatusUnauthorized, []byte(`{}`)); ok || incompatible != nil {
		t.Fatalf("unexpected decode: %+v", incompatible)
	}
}
