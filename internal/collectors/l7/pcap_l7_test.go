package l7

import (
	"encoding/hex"
	"testing"
)

func TestParseHTTPMetadataRequest(t *testing.T) {
	p := []byte("GET /index.html HTTP/1.1\r\nHost: EXAMPLE.org\r\nUser-Agent: curl/8.5\r\n\r\n")
	out := parseHTTPMetadata(p)
	if out == nil {
		t.Fatalf("expected parsed metadata")
	}
	if out["method"] != "GET" {
		t.Fatalf("method mismatch: %v", out["method"])
	}
	if out["host"] != "example.org" {
		t.Fatalf("host mismatch: %v", out["host"])
	}
}

func TestParseHTTPMetadataResponse(t *testing.T) {
	p := []byte("HTTP/1.1 204 No Content\r\nServer: nginx\r\n\r\n")
	out := parseHTTPMetadata(p)
	if out == nil {
		t.Fatalf("expected parsed response")
	}
	if out["status"] != "204" {
		t.Fatalf("status mismatch: %v", out["status"])
	}
}

func TestParseDNSMetadata(t *testing.T) {
	// DNS query for example.org A
	rawHex := "f00d01000001000000000000076578616d706c65036f72670000010001"
	b, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode dns payload: %v", err)
	}
	out := parseDNSMetadata(b)
	if out == nil {
		t.Fatalf("expected dns metadata")
	}
	if out["qname"] != "example.org" {
		t.Fatalf("qname mismatch: %v", out["qname"])
	}
	if int(out["qtype"].(int)) != 1 {
		t.Fatalf("qtype mismatch: %v", out["qtype"])
	}
}

func TestParseDNSMetadataResponseAnswers(t *testing.T) {
	// DNS response example.org A -> 93.184.216.34
	rawHex := "f00d81800001000100000000076578616d706c65036f72670000010001c00c000100010000003c00045db8d822"
	b, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode dns payload: %v", err)
	}
	out := parseDNSMetadata(b)
	if out == nil {
		t.Fatalf("expected dns metadata")
	}
	ans, ok := out["answers"].([]string)
	if !ok || len(ans) == 0 {
		t.Fatalf("expected answers, got: %#v", out["answers"])
	}
	if ans[0] != "93.184.216.34" {
		t.Fatalf("answer mismatch: %v", ans[0])
	}
}

func TestApplyDefaultsPreservesIncludePayloadFalse(t *testing.T) {
	opts := PcapL7Options{
		Interface:      "any",
		IncludePayload: false,
	}
	applyDefaults(&opts)
	if opts.IncludePayload {
		t.Fatalf("include payload should remain false when explicitly disabled")
	}
}

func TestClassifyPayloadTLSHello(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b}
	kind, extra := classifyPayload("tcp", 43000, 443, payload)
	if kind != "tls" {
		t.Fatalf("expected tls got=%s", kind)
	}
	if extra == nil {
		t.Fatalf("expected extra")
	}
}
