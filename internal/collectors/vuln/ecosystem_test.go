package vuln

import "testing"

func TestInferEcosystem(t *testing.T) {
	if got := InferEcosystem("apk", map[string]interface{}{"id": "alpine"}); got != "Alpine" {
		t.Fatalf("expected Alpine, got %q", got)
	}
	if got := InferEcosystem("dpkg", map[string]interface{}{"id": "ubuntu"}); got != "Ubuntu" {
		t.Fatalf("expected Ubuntu, got %q", got)
	}
	if got := InferEcosystem("rpm", map[string]interface{}{"id_like": "rhel fedora"}); got != "Red Hat" {
		t.Fatalf("expected Red Hat, got %q", got)
	}
}
