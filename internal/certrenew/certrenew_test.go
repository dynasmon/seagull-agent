package certrenew

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	return mustSelfSignedCertificate(t, cn, notAfter, false)
}

func mustSelfSignedCA(t *testing.T, cn string, notAfter time.Time) ([]byte, []byte) {
	return mustSelfSignedCertificate(t, cn, notAfter, true)
}

func mustSelfSignedCertificate(t *testing.T, cn string, notAfter time.Time, isCA bool) ([]byte, []byte) {
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
		IsCA:         isCA,
	}
	if isCA {
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
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

func TestValidateIssuedPairRejectsInvalidIdentityAndValidity(t *testing.T) {
	tests := []struct {
		name       string
		commonName string
		notAfter   time.Time
	}{
		{
			name:       "wrong identity",
			commonName: "agent-other-1",
			notAfter:   time.Now().Add(time.Hour),
		},
		{
			name:       "expired certificate",
			commonName: "agent-core-1",
			notAfter:   time.Now().Add(-time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, keyPEM := mustSelfSigned(t, tt.commonName, tt.notAfter)
			if _, err := ValidateIssuedPair(certPEM, keyPEM, "agent-core-1", time.Now().UTC()); err == nil {
				t.Fatal("expected issued certificate validation failure")
			}
		})
	}
}

func TestPersistPair(t *testing.T) {
	certPEM, keyPEM := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")

	if err := PersistPair(certPEM, keyPEM, "agent-core-1", certFile, keyFile); err != nil {
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

	err := PersistPair(certPEM, otherKeyPEM, "agent-core-1", filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "client.key")); !os.IsNotExist(statErr) {
		t.Fatal("no files should be written on mismatch")
	}
}

func TestPersistPairSerializesConcurrentUpdates(t *testing.T) {
	firstCert, firstKey := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	secondCert, secondKey := mustSelfSigned(t, "agent-core-1", time.Now().Add(2*time.Hour))
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	start := make(chan struct{})
	errs := make(chan error, 2)

	go func() {
		<-start
		errs <- PersistPair(firstCert, firstKey, "agent-core-1", certFile, keyFile)
	}()
	go func() {
		<-start
		errs <- PersistPair(secondCert, secondKey, "agent-core-1", certFile, keyFile)
	}()
	close(start)

	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent PersistPair: %v", err)
		}
	}
	assertPair(t, certFile, keyFile)
	for _, suffix := range []string{".next", ".previous", ".pair-transaction"} {
		if _, err := os.Stat(certFile + suffix); !os.IsNotExist(err) {
			t.Fatalf("certificate transaction artifact remains: %s", suffix)
		}
	}
	for _, suffix := range []string{".next", ".previous"} {
		if _, err := os.Stat(keyFile + suffix); !os.IsNotExist(err) {
			t.Fatalf("key transaction artifact remains: %s", suffix)
		}
	}
}

func TestPersistServerCABundle(t *testing.T) {
	firstCert, _ := mustSelfSignedCA(t, "seagull-root-1", time.Now().Add(24*time.Hour))
	secondCert, _ := mustSelfSignedCA(t, "seagull-root-2", time.Now().Add(48*time.Hour))
	caFile := filepath.Join(t.TempDir(), "server-ca.crt")
	bundle := string(firstCert) + string(secondCert)

	changed, err := PersistServerCA(bundle, caFile)
	if err != nil {
		t.Fatalf("PersistServerCA: %v", err)
	}
	if !changed {
		t.Fatal("first CA persistence must report a change")
	}
	persisted, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read CA bundle: %v", err)
	}
	if string(persisted) != bundle {
		t.Fatal("persisted CA bundle differs from the supplied bundle")
	}

	changed, err = PersistServerCA(bundle, caFile)
	if err != nil {
		t.Fatalf("PersistServerCA idempotent call: %v", err)
	}
	if changed {
		t.Fatal("unchanged CA persistence must not report a change")
	}
}

func TestPersistServerCARejectsTrailingMaterial(t *testing.T) {
	certPEM, _ := mustSelfSignedCA(t, "seagull-root", time.Now().Add(24*time.Hour))
	caFile := filepath.Join(t.TempDir(), "server-ca.crt")

	if _, err := PersistServerCA(string(certPEM)+"invalid", caFile); err == nil {
		t.Fatal("expected invalid trailing material to be rejected")
	}
	if _, err := os.Stat(caFile); !os.IsNotExist(err) {
		t.Fatal("invalid CA bundle must not be persisted")
	}
}

func TestRecoverPairRestoresInterruptedBackup(t *testing.T) {
	certPEM, keyPEM := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	if err := PersistPair(certPEM, keyPEM, "agent-core-1", certFile, keyFile); err != nil {
		t.Fatalf("persist pair: %v", err)
	}
	if err := os.Rename(keyFile, keyFile+".previous"); err != nil {
		t.Fatalf("interrupt key backup: %v", err)
	}
	if err := os.WriteFile(certFile+".pair-transaction", []byte("active"), 0o600); err != nil {
		t.Fatalf("write transaction: %v", err)
	}

	if err := RecoverPair(certFile, keyFile); err != nil {
		t.Fatalf("recover pair: %v", err)
	}
	assertPair(t, certFile, keyFile)
	if _, err := os.Stat(keyFile + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("backup was not cleaned: %v", err)
	}
}

func TestRecoverPairCompletesFreshInterruptedInstall(t *testing.T) {
	certPEM, keyPEM := mustSelfSigned(t, "agent-core-1", time.Now().Add(time.Hour))
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write current key: %v", err)
	}
	if err := os.WriteFile(certFile+".next", certPEM, 0o644); err != nil {
		t.Fatalf("write next certificate: %v", err)
	}
	if err := os.WriteFile(certFile+".pair-transaction", []byte("active"), 0o600); err != nil {
		t.Fatalf("write transaction: %v", err)
	}

	if err := RecoverPair(certFile, keyFile); err != nil {
		t.Fatalf("recover pair: %v", err)
	}
	assertPair(t, certFile, keyFile)
}

func TestRecoverPairRejectsUnrecoverableMaterial(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, []byte("invalid"), 0o644); err != nil {
		t.Fatalf("write invalid certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("invalid"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	if err := RecoverPair(certFile, keyFile); err == nil {
		t.Fatal("expected unrecoverable pair error")
	}
}

func assertPair(t *testing.T, certFile string, keyFile string) {
	t.Helper()
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("load recovered pair: %v", err)
	}
}
