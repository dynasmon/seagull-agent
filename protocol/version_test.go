package protocol

import "testing"

func TestNegotiateLegacyServerIsDegraded(t *testing.T) {
	negotiated, incompatible := Negotiate(nil)
	if incompatible != nil {
		t.Fatalf("legacy server rejected: %v", incompatible)
	}
	if !negotiated.Degraded || negotiated.ProtocolVersion != Version {
		t.Fatalf("unexpected negotiation: %+v", negotiated)
	}
}

func TestNegotiateCompatibleRanges(t *testing.T) {
	negotiated, incompatible := Negotiate(&Descriptor{
		ProtocolVersion:    Version,
		MinSupported:       MinSupportedServer,
		MaxSupported:       MaxSupportedServer,
		EventSchemaVersion: EventSchemaVersion,
		MinEventSchema:     MinEventSchema,
		MaxEventSchema:     MaxEventSchema,
	})
	if incompatible != nil {
		t.Fatalf("compatible server rejected: %v", incompatible)
	}
	if negotiated.Degraded || negotiated.EventSchemaVersion != EventSchemaVersion {
		t.Fatalf("unexpected negotiation: %+v", negotiated)
	}
}

func TestNegotiateRejectsUnsupportedProtocolRanges(t *testing.T) {
	cases := []struct {
		name       string
		descriptor Descriptor
		kind       IncompatibilityKind
	}{
		{
			name: "agent too old",
			descriptor: Descriptor{
				ProtocolVersion:    Version + 1,
				MinSupported:       Version + 1,
				MaxSupported:       Version + 1,
				EventSchemaVersion: EventSchemaVersion,
				MinEventSchema:     MinEventSchema,
				MaxEventSchema:     MaxEventSchema,
			},
			kind: IncompatibleProtocolTooOld,
		},
		{
			name: "event schema",
			descriptor: Descriptor{
				ProtocolVersion:    Version,
				MinSupported:       MinSupportedServer,
				MaxSupported:       MaxSupportedServer,
				EventSchemaVersion: EventSchemaVersion + 1,
				MinEventSchema:     EventSchemaVersion + 1,
				MaxEventSchema:     EventSchemaVersion + 1,
			},
			kind: IncompatibleEventSchema,
		},
		{
			name: "invalid event range",
			descriptor: Descriptor{
				ProtocolVersion:    Version,
				MinSupported:       MinSupportedServer,
				MaxSupported:       MaxSupportedServer,
				EventSchemaVersion: EventSchemaVersion,
				MinEventSchema:     EventSchemaVersion + 1,
				MaxEventSchema:     EventSchemaVersion,
			},
			kind: IncompatibleServerAdvertise,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			negotiated, incompatible := Negotiate(&tc.descriptor)
			if incompatible == nil {
				t.Fatalf("expected incompatibility, got %+v", negotiated)
			}
			if incompatible.Kind != tc.kind {
				t.Fatalf("kind=%s want %s", incompatible.Kind, tc.kind)
			}
		})
	}
}
