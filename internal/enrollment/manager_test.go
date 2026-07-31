package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/controlplane"
	"github.com/dynasmon/seagull-agent/internal/sources"
	"github.com/dynasmon/seagull-agent/protocol"
)

func TestRecoverIdentitySerializesConcurrentAttempts(t *testing.T) {
	var enrollCalls atomic.Int32
	firstEntered := make(chan struct{})
	release := make(chan struct{})

	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/enroll" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		call := enrollCalls.Add(1)
		if call == 1 {
			close(firstEntered)
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			w,
			`{"agent_id":"agent-1","config":{},"credential":{"credential":"cred-%d","expires_at":"%s","max_uses":1,"used_uses":0,"renewal_token":"renewed-token","renewal_token_expires_at":"%s"}}`,
			call,
			expiresAt,
			expiresAt,
		)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	runtimeConfig := sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{})
	mgr := NewManager(agentcfg.Config{
		AgentID:                "agent-1",
		ForceEnrollOnStart:     true,
		ControlEnrollTimeout:   time.Second,
		AgentIdentityStateFile: filepath.Join(tempDir, "agent.identity.json"),
	}, runtimeConfig)
	mgr.renewalToken = "renewal-token"
	mgr.renewalExp = time.Now().UTC().Add(time.Hour)
	mgr.SetClient(controlplane.New(server.URL, time.Second, "agent-1", mgr.CurrentCredential, server.Client()))

	const workers = 5
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- mgr.RecoverIdentity(context.Background(), "test", false)
		}()
	}

	close(start)
	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first recovery attempt")
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	successes := 0
	inFlightErrors := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if strings.Contains(err.Error(), "already in progress") {
			inFlightErrors++
			continue
		}
		t.Fatalf("unexpected recovery error: %v", err)
	}

	if got := enrollCalls.Load(); got != 1 {
		t.Fatalf("expected exactly one enroll request, got %d", got)
	}
	if successes != 1 {
		t.Fatalf("expected exactly one successful recovery, got %d", successes)
	}
	if inFlightErrors != workers-1 {
		t.Fatalf("expected %d in-flight rejections, got %d", workers-1, inFlightErrors)
	}
}

func TestRecoverIdentityEnrollsWithCSRAndPersistsCertificate(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "client.crt")
	keyFile := filepath.Join(tempDir, "client.key")
	caFile := filepath.Join(tempDir, "root_ca.crt")

	caKeyPEM, caCertPEM := newTestCA(t)
	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

	var gotCSR atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req struct {
			AgentID string `json:"agent_id"`
			CSRPEM  string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode enroll request: %v", err)
		}
		gotCSR.Store(req.CSRPEM)
		certPEM := signTestCSR(t, caKeyPEM, caCertPEM, req.CSRPEM, req.AgentID)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"agent_id": req.AgentID,
			"config":   map[string]interface{}{},
			"credential": map[string]interface{}{
				"credential":               "cred-1",
				"expires_at":               expiresAt,
				"max_uses":                 1,
				"used_uses":                0,
				"renewal_token":            "renewed-token",
				"renewal_token_expires_at": expiresAt,
			},
			"certificate": map[string]interface{}{
				"agent_id":        req.AgentID,
				"certificate_pem": certPEM,
				"ca_pem":          string(caCertPEM),
				"server_ca_pem":   string(caCertPEM),
				"serial_hex":      "1a",
				"not_before":      expiresAt,
				"not_after":       expiresAt,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	runtimeConfig := sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{})
	mgr := NewManager(agentcfg.Config{
		AgentID:                "agent-1",
		ForceEnrollOnStart:     true,
		ControlEnrollTimeout:   time.Second,
		AgentIdentityStateFile: filepath.Join(tempDir, "agent.identity.json"),
		TLSCertFile:            certFile,
		TLSKeyFile:             keyFile,
		TLSCAFile:              caFile,
		BootstrapToken:         "abt.agent-1.token",
	}, runtimeConfig)
	cp := controlplane.New("", time.Second, "agent-1", mgr.CurrentCredential, server.Client())
	cp.SetEnrollBaseURL(server.URL)
	mgr.SetClient(cp)

	if err := mgr.RecoverIdentity(context.Background(), "test", true); err != nil {
		t.Fatalf("recover identity: %v", err)
	}

	csr, _ := gotCSR.Load().(string)
	if !strings.Contains(csr, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("expected CSR in enroll request, got: %q", csr)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("persisted pair invalid: %v", err)
	}
	if got := mgr.CurrentCredential(); got != "cred-1" {
		t.Fatalf("credential not applied: %q", got)
	}
	persistedCA, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("server CA not persisted: %v", err)
	}
	if !strings.Contains(string(persistedCA), "BEGIN CERTIFICATE") {
		t.Fatalf("persisted server CA is not a certificate: %q", string(persistedCA))
	}
}

func TestEnsureInitialIdentityResumesPendingEnrollment(t *testing.T) {
	dir := t.TempDir()
	cfg := agentcfg.Config{
		AgentID:                "agent-1",
		ForceEnrollOnStart:     true,
		AgentIdentityStateFile: filepath.Join(dir, "agent.identity.json"),
		BootstrapToken:         "abt.agent-1.token",
	}
	manager := NewManager(cfg, sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{}))
	response := protocol.EnrollResponse{
		AgentID: "agent-1",
		Config:  map[string]interface{}{"revision": float64(1)},
		Credential: protocol.Credential{
			Credential:            "cred-pending",
			ExpiresAt:             time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			RenewalToken:          "renew-pending",
			RenewalTokenExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		},
		Protocol: descriptorPointer(protocol.LocalDescriptor()),
	}
	pending := pendingEnrollment{
		Method:   "bootstrap",
		Request:  protocol.EnrollRequest{EnrollmentID: "11111111-1111-4111-8111-111111111111"},
		Response: &response,
	}
	if err := manager.savePendingEnrollment(&pending); err != nil {
		t.Fatalf("save pending enrollment: %v", err)
	}

	restarted := NewManager(cfg, sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{}))
	if err := restarted.EnsureInitialIdentity(context.Background()); err != nil {
		t.Fatalf("resume pending enrollment: %v", err)
	}
	if restarted.CurrentCredential() != "cred-pending" {
		t.Fatalf("credential=%q want cred-pending", restarted.CurrentCredential())
	}
	if restarted.CurrentBootstrapToken() != "" {
		t.Fatal("consumed bootstrap token remained available")
	}
	state, err := agentcfg.LoadIdentityState(cfg.AgentIdentityStateFile, cfg.AgentID)
	if err != nil {
		t.Fatalf("load identity state: %v", err)
	}
	if !state.BootstrapTokenConsumed {
		t.Fatal("identity state did not record bootstrap token consumption")
	}
	if _, err := os.Stat(cfg.AgentIdentityStateFile + ".pending-enrollment"); !os.IsNotExist(err) {
		t.Fatalf("pending enrollment was not cleared: %v", err)
	}
}

func TestPendingEnrollmentRejectsIncompatibleDescriptor(t *testing.T) {
	dir := t.TempDir()
	cfg := agentcfg.Config{
		AgentID:                "agent-1",
		ForceEnrollOnStart:     true,
		AgentIdentityStateFile: filepath.Join(dir, "agent.identity.json"),
	}
	manager := NewManager(cfg, sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{}))
	future := protocol.Descriptor{
		ProtocolVersion:    protocol.Version + 1,
		MinSupported:       protocol.Version + 1,
		MaxSupported:       protocol.Version + 1,
		EventSchemaVersion: protocol.EventSchemaVersion,
		MinEventSchema:     protocol.MinEventSchema,
		MaxEventSchema:     protocol.MaxEventSchema,
	}
	response := protocol.EnrollResponse{
		AgentID:    cfg.AgentID,
		Credential: protocol.Credential{Credential: "must-not-apply"},
		Protocol:   &future,
	}
	pending := pendingEnrollment{
		Method:   "renewal",
		Request:  protocol.EnrollRequest{EnrollmentID: "22222222-2222-4222-8222-222222222222"},
		Response: &response,
	}
	if err := manager.savePendingEnrollment(&pending); err != nil {
		t.Fatalf("save pending enrollment: %v", err)
	}
	if err := manager.EnsureInitialIdentity(context.Background()); err == nil {
		t.Fatal("expected incompatible pending enrollment rejection")
	}
	if manager.CurrentCredential() != "" {
		t.Fatal("incompatible credential was applied")
	}
}

func TestRecoverIdentityReplaysDurableEnrollmentAfterResponseLoss(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "client.crt")
	keyFile := filepath.Join(tempDir, "client.key")
	caFile := filepath.Join(tempDir, "root_ca.crt")
	caKeyPEM, caCertPEM := newTestCA(t)
	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

	var mu sync.Mutex
	requests := make([]protocol.EnrollRequest, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request protocol.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode enroll request: %v", err)
			return
		}
		mu.Lock()
		requests = append(requests, request)
		call := len(requests)
		mu.Unlock()
		if call == 1 {
			panic(http.ErrAbortHandler)
		}
		certPEM := signTestCSR(t, caKeyPEM, caCertPEM, request.CSRPEM, request.AgentID)
		response := protocol.EnrollResponse{
			AgentID: request.AgentID,
			Config:  map[string]interface{}{},
			Credential: protocol.Credential{
				Credential:            "cred-replayed",
				ExpiresAt:             expiresAt,
				MaxUses:               1,
				RenewalToken:          "renew-replayed",
				RenewalTokenExpiresAt: expiresAt,
			},
			Certificate: &protocol.CertificateRenewal{
				AgentID:        request.AgentID,
				CertificatePEM: certPEM,
				CAPEM:          string(caCertPEM),
				ServerCAPEM:    string(caCertPEM),
				SerialHex:      "2a",
				NotBefore:      expiresAt,
				NotAfter:       expiresAt,
			},
			Protocol: descriptorPointer(protocol.LocalDescriptor()),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode enroll response: %v", err)
		}
	}))
	defer server.Close()

	cfg := agentcfg.Config{
		AgentID:                "agent-1",
		ForceEnrollOnStart:     true,
		ControlEnrollTimeout:   time.Second,
		AgentIdentityStateFile: filepath.Join(tempDir, "agent.identity.json"),
		TLSCertFile:            certFile,
		TLSKeyFile:             keyFile,
		TLSCAFile:              caFile,
		BootstrapToken:         "abt.agent-1.response-loss",
	}
	manager := NewManager(cfg, sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{}))
	client := controlplane.New("", time.Second, cfg.AgentID, manager.CurrentCredential, server.Client())
	client.SetEnrollBaseURL(server.URL)
	manager.SetClient(client)

	if err := manager.RecoverIdentity(context.Background(), "response_loss", true); err == nil {
		t.Fatal("expected the interrupted enrollment to fail")
	}
	pendingBytes, err := os.ReadFile(cfg.AgentIdentityStateFile + ".pending-enrollment")
	if err != nil {
		t.Fatalf("read pending enrollment: %v", err)
	}
	if bytes.Contains(pendingBytes, []byte(cfg.BootstrapToken)) {
		t.Fatal("pending enrollment persisted the bootstrap token")
	}
	if err := manager.RecoverIdentity(context.Background(), "response_loss_retry", true); err != nil {
		t.Fatalf("replay durable enrollment: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("enroll requests=%d want 2", len(requests))
	}
	if requests[0].EnrollmentID == "" || requests[0].EnrollmentID != requests[1].EnrollmentID {
		t.Fatalf("enrollment IDs differ: %q and %q", requests[0].EnrollmentID, requests[1].EnrollmentID)
	}
	if requests[0].CSRPEM == "" || requests[0].CSRPEM != requests[1].CSRPEM {
		t.Fatal("enrollment CSR changed during replay")
	}
	if manager.CurrentCredential() != "cred-replayed" {
		t.Fatalf("credential=%q want cred-replayed", manager.CurrentCredential())
	}
	if _, err := os.Stat(cfg.AgentIdentityStateFile + ".pending-enrollment"); !os.IsNotExist(err) {
		t.Fatalf("pending enrollment was not cleared: %v", err)
	}
}

func descriptorPointer(descriptor protocol.Descriptor) *protocol.Descriptor {
	return &descriptor
}

func newTestCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM
}

func signTestCSR(t *testing.T, caKeyPEM, caCertPEM []byte, csrPEM, agentID string) string {
	t.Helper()
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA key: %v", err)
	}
	certBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		t.Fatalf("decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(26),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
