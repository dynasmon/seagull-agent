package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testAuthority struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	pem         []byte
}

func newTestAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return testAuthority{
		certificate: certificate,
		privateKey:  privateKey,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func issueTestCertificate(t *testing.T, authority testAuthority, commonName string, serverName string, server bool) (tls.Certificate, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{serverName}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, publicKey, authority.privateKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf pair: %v", err)
	}
	return pair, certPEM, keyPEM
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 120)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return value
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestHTTPClientVerifiesCustomCAAndServerName(t *testing.T) {
	authority := newTestAuthority(t, "test-root")
	serverPair, _, _ := issueTestCertificate(t, authority, "agent.test", "agent.test", true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	writeTestFile(t, caFile, authority.pem, 0o600)
	client, err := NewHTTPClient(2*time.Second, TLSOptions{CAFile: caFile, ServerName: "agent.test"})
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("trusted request failed: %v", err)
	}
	response.Body.Close()

	wrongName, err := NewHTTPClient(2*time.Second, TLSOptions{CAFile: caFile, ServerName: "wrong.test"})
	if err != nil {
		t.Fatalf("create wrong-name client: %v", err)
	}
	if _, err := wrongName.Get(server.URL); err == nil {
		t.Fatalf("expected hostname verification failure")
	}
}

func TestHTTPClientPinsExplicitCA(t *testing.T) {
	trusted := newTestAuthority(t, "trusted-root")
	untrusted := newTestAuthority(t, "untrusted-root")
	serverPair, _, _ := issueTestCertificate(t, untrusted, "agent.test", "agent.test", true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	writeTestFile(t, caFile, trusted.pem, 0o600)
	client, err := NewHTTPClient(2*time.Second, TLSOptions{CAFile: caFile, ServerName: "agent.test"})
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	if _, err := client.Get(server.URL); err == nil {
		t.Fatalf("expected untrusted CA rejection")
	}
}

func TestHTTPClientReloadsClientCertificate(t *testing.T) {
	authority := newTestAuthority(t, "shared-root")
	serverPair, _, _ := issueTestCertificate(t, authority, "agent.test", "agent.test", true)
	_, firstCert, firstKey := issueTestCertificate(t, authority, "client-one", "", false)
	_, secondCert, secondKey := issueTestCertificate(t, authority, "client-second-long", "", false)
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(authority.pem)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		io.WriteString(w, request.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "server-ca.pem")
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	writeTestFile(t, caFile, authority.pem, 0o600)
	writeTestFile(t, certFile, firstCert, 0o600)
	writeTestFile(t, keyFile, firstKey, 0o600)
	client, err := NewHTTPClient(2*time.Second, TLSOptions{
		CAFile:     caFile,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ServerName: "agent.test",
	})
	if err != nil {
		t.Fatalf("create mTLS client: %v", err)
	}

	readIdentity := func() string {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("mTLS request failed: %v", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read mTLS response: %v", err)
		}
		return string(body)
	}
	if identity := readIdentity(); identity != "client-one" {
		t.Fatalf("unexpected initial client identity: %s", identity)
	}

	writeTestFile(t, certFile, secondCert, 0o600)
	writeTestFile(t, keyFile, secondKey, 0o600)
	client.CloseIdleConnections()
	if identity := readIdentity(); identity != "client-second-long" {
		t.Fatalf("client certificate was not reloaded: %s", identity)
	}
}

func TestHTTPClientRequiresServerNameForCustomCA(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	writeTestFile(t, caFile, newTestAuthority(t, "test-root").pem, 0o600)
	if _, err := NewHTTPClient(time.Second, TLSOptions{CAFile: caFile}); err == nil {
		t.Fatalf("expected missing server name rejection")
	}
}
