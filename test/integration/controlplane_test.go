//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent/internal/certrenew"
	agentcfg "github.com/dynasmon/Seagull-agent/internal/config"
	"github.com/dynasmon/Seagull-agent/internal/controlplane"
	"github.com/dynasmon/Seagull-agent/internal/enrollment"
	"github.com/dynasmon/Seagull-agent/internal/sources"
	"github.com/dynasmon/Seagull-agent/protocol"
)

func TestFreshEnrollmentPersistsIdentityCertificateAndTrustAnchor(t *testing.T) {
	server := newFakeControlPlane(t)
	defer server.Close()

	dir := t.TempDir()
	cfg := baseConfig(dir, server.URL)
	writeFile(t, cfg.BootstrapTokenFile, "abt.agent-1.first-token")

	manager := enrollment.NewManager(cfg, sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{}))
	client := controlplane.New(server.URL, 5*time.Second, cfg.AgentID, manager.CurrentCredential, server.Client())
	client.SetEnrollBaseURL(server.URL)
	manager.SetClient(client)

	if err := manager.RecoverIdentity(context.Background(), "test", true); err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}

	if got := manager.CurrentCredential(); got == "" {
		t.Fatal("enrollment did not produce a credential")
	}
	if manager.CurrentRenewalToken() == "" {
		t.Fatal("enrollment did not produce a renewal token")
	}
	requireFile(t, cfg.AgentIdentityStateFile)
	requireFile(t, cfg.CredentialFile)
	requireFile(t, cfg.TLSCertFile)
	requireFile(t, cfg.TLSKeyFile)
	requireFile(t, cfg.TLSCAFile)

	if _, err := certrenew.Inspect(cfg.TLSCertFile); err != nil {
		t.Fatalf("issued certificate is unusable: %v", err)
	}
	if server.enrollCSRs() == 0 {
		t.Fatal("the agent enrolled without sending a CSR")
	}
	assertPerm(t, cfg.TLSKeyFile, 0o600)
	assertPerm(t, cfg.CredentialFile, 0o600)
	assertPerm(t, cfg.AgentIdentityStateFile, 0o600)
}

func TestEnrollmentConsumesTheBootstrapTokenExactlyOnce(t *testing.T) {
	server := newFakeControlPlane(t)
	defer server.Close()

	dir := t.TempDir()
	cfg := baseConfig(dir, server.URL)
	writeFile(t, cfg.BootstrapTokenFile, "abt.agent-1.single-use")

	manager, _ := newEnrolledManager(t, cfg, server)

	if server.tokenUses("abt.agent-1.single-use") != 1 {
		t.Fatalf("bootstrap token used %d times, want 1", server.tokenUses("abt.agent-1.single-use"))
	}
	if data, err := os.ReadFile(cfg.BootstrapTokenFile); err == nil && len(data) > 0 {
		t.Fatalf("the bootstrap token file was not consumed: %q", string(data))
	}

	server.rejectToken("abt.agent-1.single-use")
	if err := manager.RecoverIdentity(context.Background(), "replay", true); err != nil {
		t.Fatalf("recovery should succeed through the renewal token: %v", err)
	}
	if server.replayAttempts() > 0 {
		t.Fatal("the agent replayed a consumed bootstrap token")
	}
}

func TestCredentialRotationPreservesTheRecoveryChain(t *testing.T) {
	server := newFakeControlPlane(t)
	defer server.Close()

	dir := t.TempDir()
	cfg := baseConfig(dir, server.URL)
	writeFile(t, cfg.BootstrapTokenFile, "abt.agent-1.token")

	manager, client := newEnrolledManager(t, cfg, server)
	first := manager.CurrentCredential()
	firstRenewal := manager.CurrentRenewalToken()

	rotated, err := client.RotateCredential(context.Background())
	if err != nil {
		t.Fatalf("rotate credential: %v", err)
	}
	if err := manager.ApplyCredentialUpdate(rotated, "rotate"); err != nil {
		t.Fatalf("apply rotated credential: %v", err)
	}

	if manager.CurrentCredential() == first {
		t.Fatal("rotation did not change the credential")
	}
	current, _, previous, _ := manager.RecoveryTokenSnapshot()
	if current == firstRenewal {
		t.Fatal("rotation did not issue a new renewal token")
	}
	if previous != firstRenewal {
		t.Fatalf("rotation lost the previous renewal token: got %q want %q", previous, firstRenewal)
	}

	state, err := agentcfg.LoadIdentityState(cfg.AgentIdentityStateFile, cfg.AgentID)
	if err != nil {
		t.Fatalf("load identity state: %v", err)
	}
	if state.Credential != manager.CurrentCredential() {
		t.Fatal("the rotated credential was not persisted atomically")
	}
}

func TestCertificateRenewalRotatesTheServerTrustAnchor(t *testing.T) {
	server := newFakeControlPlane(t)
	defer server.Close()

	dir := t.TempDir()
	cfg := baseConfig(dir, server.URL)
	writeFile(t, cfg.BootstrapTokenFile, "abt.agent-1.token")

	manager, client := newEnrolledManager(t, cfg, server)
	_ = manager

	before, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		t.Fatalf("read trust anchor: %v", err)
	}

	server.rotateServerCA()
	_, csrPEM, err := certrenew.NewKeyAndCSR(cfg.AgentID)
	if err != nil {
		t.Fatalf("build CSR: %v", err)
	}
	renewed, err := client.RenewCertificate(context.Background(), string(csrPEM))
	if err != nil {
		t.Fatalf("renew certificate: %v", err)
	}
	changed, err := certrenew.PersistServerCA(renewed.ServerCAPEM, cfg.TLSCAFile)
	if err != nil {
		t.Fatalf("persist rotated server CA: %v", err)
	}
	if !changed {
		t.Fatal("certificate renewal did not rotate the server trust anchor")
	}
	after, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		t.Fatalf("read rotated trust anchor: %v", err)
	}
	if string(before) == string(after) {
		t.Fatal("the trust anchor on disk did not change")
	}
}

func TestRevokedCredentialRecoversThroughTheRenewalToken(t *testing.T) {
	server := newFakeControlPlane(t)
	defer server.Close()

	dir := t.TempDir()
	cfg := baseConfig(dir, server.URL)
	writeFile(t, cfg.BootstrapTokenFile, "abt.agent-1.token")

	manager, _ := newEnrolledManager(t, cfg, server)
	revoked := manager.CurrentCredential()

	server.revokeCredential(revoked)
	manager.MaybeRecoverIdentity(context.Background(), "heartbeat", "heartbeat failed status=401", 401)

	if manager.CurrentCredential() == revoked {
		t.Fatal("the agent kept using a revoked credential")
	}
	if manager.CurrentCredential() == "" {
		t.Fatal("recovery did not produce a new credential")
	}
}

func TestUnsupportedProtocolIsReportedStructurally(t *testing.T) {
	negotiated, incompatible := protocol.Negotiate(&protocol.Descriptor{
		ProtocolVersion:    9,
		MinSupported:       9,
		MaxSupported:       9,
		EventSchemaVersion: 9,
	})
	if incompatible == nil {
		t.Fatal("a future-only server must be reported as incompatible")
	}
	if incompatible.Kind != protocol.IncompatibleProtocolTooOld {
		t.Fatalf("kind=%s want %s", incompatible.Kind, protocol.IncompatibleProtocolTooOld)
	}
	if negotiated.ProtocolVersion != 0 {
		t.Fatal("an incompatible negotiation must not yield a usable protocol version")
	}

	if _, err := protocol.Negotiate(&protocol.Descriptor{
		ProtocolVersion: 1, MinSupported: 1, MaxSupported: 1, EventSchemaVersion: 1,
	}); err != nil {
		t.Fatalf("the current server must be compatible: %v", err)
	}
	if _, err := protocol.Negotiate(nil); err != nil {
		t.Fatalf("a server that omits the descriptor must stay compatible: %v", err)
	}
}

func newEnrolledManager(t *testing.T, cfg agentcfg.Config, server *fakeControlPlane) (*enrollment.Manager, *controlplane.Client) {
	t.Helper()
	manager := enrollment.NewManager(cfg, sources.NewRuntimeConfig("", sources.SyscollectorConfig{}, sources.VulnScannerConfig{}, sources.TopologyDiscoveryConfig{}))
	client := controlplane.New(server.URL, 5*time.Second, cfg.AgentID, manager.CurrentCredential, server.Client())
	client.SetEnrollBaseURL(server.URL)
	manager.SetClient(client)
	if err := manager.RecoverIdentity(context.Background(), "test", true); err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}
	return manager, client
}

func baseConfig(dir string, apiURL string) agentcfg.Config {
	return agentcfg.Config{
		AgentID:                "agent-1",
		APIURL:                 apiURL,
		EnrollURL:              apiURL,
		Profile:                protocol.ProfileSensor,
		ForceEnrollOnStart:     true,
		ControlEnrollTimeout:   5 * time.Second,
		AgentIdentityStateFile: filepath.Join(dir, "agent.identity.json"),
		CredentialFile:         filepath.Join(dir, "agent.credential"),
		BootstrapTokenFile:     filepath.Join(dir, "bootstrap.token"),
		TLSCAFile:              filepath.Join(dir, "root_ca.crt"),
		TLSCertFile:            filepath.Join(dir, "client.crt"),
		TLSKeyFile:             filepath.Join(dir, "client.key"),
	}
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func requireFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("expected %s to be non-empty", path)
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode=%o want %o", path, got, want)
	}
}

type fakeControlPlane struct {
	*httptest.Server

	mu           sync.Mutex
	authority    *testCA
	tokens       map[string]int
	rejected     map[string]bool
	revoked      map[string]bool
	credentials  map[string]bool
	csrCount     int
	replayCount  int
	issuedSerial int64
}

func newFakeControlPlane(t *testing.T) *fakeControlPlane {
	t.Helper()
	f := &fakeControlPlane{
		authority:   newTestCA(t),
		tokens:      map[string]int{},
		rejected:    map[string]bool{},
		revoked:     map[string]bool{},
		credentials: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", f.handleEnroll)
	mux.HandleFunc("/agents/enroll", f.handleEnroll)
	mux.HandleFunc("/agents/credential/rotate", f.handleRotate)
	mux.HandleFunc("/agents/certificate/renew", f.handleRenew)
	mux.HandleFunc("/agents/heartbeat", f.handleHeartbeat)
	f.Server = httptest.NewServer(mux)
	return f
}

func (f *fakeControlPlane) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	token := r.Header.Get("X-Agent-Bootstrap-Token")

	f.mu.Lock()
	if f.rejected[token] {
		f.replayCount++
		f.mu.Unlock()
		http.Error(w, "Bootstrap token already consumed", http.StatusUnauthorized)
		return
	}
	f.tokens[token]++
	if req.CSRPEM != "" {
		f.csrCount++
	}
	f.issuedSerial++
	serial := f.issuedSerial
	authority := f.authority
	f.mu.Unlock()

	certPEM := ""
	if req.CSRPEM != "" {
		certPEM = authority.sign(req.CSRPEM, serial)
	}

	credential := f.mintCredential()
	response := protocol.EnrollResponse{
		AgentID: req.AgentID,
		Config:  map[string]interface{}{},
		Credential: protocol.Credential{
			Credential:            credential,
			ExpiresAt:             time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
			MaxUses:               100000,
			RenewalToken:          "renew." + credential,
			RenewalTokenExpiresAt: time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		},
		Protocol: &protocol.Descriptor{
			ProtocolVersion:    protocol.Version,
			MinSupported:       protocol.MinSupportedServer,
			MaxSupported:       protocol.MaxSupportedServer,
			EventSchemaVersion: protocol.EventSchemaVersion,
		},
	}
	if certPEM != "" {
		response.Certificate = &protocol.CertificateRenewal{
			AgentID:        req.AgentID,
			CertificatePEM: certPEM,
			CAPEM:          authority.certPEM(),
			ServerCAPEM:    authority.serverCAPEM(),
			SerialHex:      "0a",
			NotBefore:      time.Now().UTC().Format(time.RFC3339),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusCreated, response)
}

func (f *fakeControlPlane) handleRotate(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(r) {
		http.Error(w, "invalid agent credential", http.StatusUnauthorized)
		return
	}
	credential := f.mintCredential()
	writeJSON(w, http.StatusOK, protocol.Credential{
		Credential:            credential,
		ExpiresAt:             time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		MaxUses:               100000,
		RenewalToken:          "renew." + credential,
		RenewalTokenExpiresAt: time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
}

func (f *fakeControlPlane) handleRenew(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(r) {
		http.Error(w, "invalid agent credential", http.StatusUnauthorized)
		return
	}
	var req protocol.CertificateRenewRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	f.mu.Lock()
	f.issuedSerial++
	serial := f.issuedSerial
	authority := f.authority
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, protocol.CertificateRenewal{
		AgentID:        "agent-1",
		CertificatePEM: authority.sign(req.CSRPEM, serial),
		CAPEM:          authority.certPEM(),
		ServerCAPEM:    authority.serverCAPEM(),
		SerialHex:      "0b",
		NotBefore:      time.Now().UTC().Format(time.RFC3339),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
}

func (f *fakeControlPlane) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(r) {
		http.Error(w, "invalid agent credential", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeControlPlane) authorized(r *http.Request) bool {
	credential := r.Header.Get("X-Agent-Credential")
	f.mu.Lock()
	defer f.mu.Unlock()
	return credential != "" && f.credentials[credential] && !f.revoked[credential]
}

func (f *fakeControlPlane) mintCredential() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	credential := "agc.agent-1." + time.Now().UTC().Format("150405.000000000")
	f.credentials[credential] = true
	return credential
}

func (f *fakeControlPlane) rejectToken(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected[token] = true
}

func (f *fakeControlPlane) revokeCredential(credential string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[credential] = true
}

func (f *fakeControlPlane) rotateServerCA() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authority.rotateServer()
}

func (f *fakeControlPlane) tokenUses(token string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[token]
}

func (f *fakeControlPlane) replayAttempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.replayCount
}

func (f *fakeControlPlane) enrollCSRs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.csrCount
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
