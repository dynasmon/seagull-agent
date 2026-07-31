package agentcfg

import "testing"

func TestParseOptionalRFC3339AcceptsUTCAndNaiveBackendTimestamps(t *testing.T) {
	cases := []string{
		"2026-05-14T18:03:22Z",
		"2026-05-14T18:03:22.085942Z",
		"2026-05-14T18:03:22",
		"2026-05-14T18:03:22.085942",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			got := ParseOptionalRFC3339(tc)
			if got.IsZero() {
				t.Fatalf("expected parsed timestamp")
			}
			if got.Location().String() != "UTC" {
				t.Fatalf("expected UTC timestamp, got %s", got.Location())
			}
		})
	}
}
