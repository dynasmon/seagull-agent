package certrenew

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustSelfSigned(t *testing.T, cn string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestNewKeyAndCSR(t *testing.T) {
	keyPEM, csrPEM, err := NewKeyAndCSR("agent-core-1")
	if err != nil {
		t.Fatalf("NewKeyAndCSR: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatalf("key PEM type = %v, want EC PRIVATE KEY", keyBlock)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", key.Curve.Params().Name)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csr PEM type = %v, want CERTIFICATE REQUEST", csrBlock)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature: %v", err)
	}
	if csr.Subject.CommonName != "agent-core-1" {
		t.Fatalf("csr CN = %q, want agent-core-1", csr.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "Seagull Agents" {
		t.Fatalf("csr O = %v, want [Seagull Agents]", csr.Subject.Organization)
	}
}

func TestInspect(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPEM, _ := mustSelfSigned(t, "agent-core-1", notAfter)
	certFile := filepath.Join(t.TempDir(), "client.crt")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	status, err := Inspect(certFile)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if status.SerialHex != big.NewInt(4242).Text(16) {
		t.Fatalf("serial = %q", status.SerialHex)
	}
	if !status.NotAfter.Equal(notAfter.UTC()) {
		t.Fatalf("notAfter = %v, want %v", status.NotAfter, notAfter.UTC())
	}
}

func TestInspectMissingFile(t *testing.T) {
	if _, err := Inspect(filepath.Join(t.TempDir(), "absent.crt")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	certPEM, _ := mustSelfSigned(t, "agent-core-1", now.Add(100*time.Hour))
	certFile := filepath.Join(t.TempDir(), "client.crt")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	needed, _, err := NeedsRenewal(certFile, 30*time.Hour, now)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if needed {
		t.Fatal("renewal should not be needed with 70h margin")
	}

	needed, status, err := NeedsRenewal(certFile, 200*time.Hour, now)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if !needed {
		t.Fatal("renewal should be needed inside the renew window")
	}
	if status.SerialHex == "" {
		t.Fatal("status should carry the current serial")
	}
}

func TestPersistPair(t *testing.T) {
	certPEM, keyPEM := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")

	if err := PersistPair(certPEM, keyPEM, certFile, keyFile); err != nil {
		t.Fatalf("PersistPair: %v", err)
	}

	certInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Fatalf("cert mode = %v, want 0644", certInfo.Mode().Perm())
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", keyInfo.Mode().Perm())
	}

	gotCert, _ := os.ReadFile(certFile)
	if string(gotCert) != string(certPEM) {
		t.Fatal("persisted certificate differs from issued certificate")
	}
}

func TestPersistPairRejectsMismatch(t *testing.T) {
	certPEM, _ := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	_, otherKeyPEM := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	dir := t.TempDir()

	err := PersistPair(certPEM, otherKeyPEM, filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "client.key")); !os.IsNotExist(statErr) {
		t.Fatal("no files should be written on mismatch")
	}
}
