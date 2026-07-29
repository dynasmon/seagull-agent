package enrollment

import (
	"context"
	"fmt"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/buildinfo"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/certrenew"
	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/sources"
)

type Manager struct {
	cfg     agentcfg.Config
	runtime *sources.RuntimeConfig
	cp      *controlplane.Client

	credMu               sync.RWMutex
	cred                 string
	credExp              time.Time
	renewalToken         string
	renewalExp           time.Time
	previousRenewalToken string
	previousRenewalExp   time.Time
	lastRecoveryMethod   string

	enrollMu          sync.Mutex
	recoveryInFlight  bool
	recoveryFailures  int
	nextEnrollRetryAt time.Time
}

func NewManager(cfg agentcfg.Config, runtimeCfg *sources.RuntimeConfig) *Manager {
	return &Manager{
		cfg:                  cfg,
		runtime:              runtimeCfg,
		cred:                 strings.TrimSpace(cfg.AgentCredential),
		credExp:              agentcfg.ParseOptionalRFC3339(cfg.AgentCredentialExpiresAt),
		renewalToken:         strings.TrimSpace(cfg.RenewalToken),
		renewalExp:           agentcfg.ParseOptionalRFC3339(cfg.RenewalTokenExpiresAt),
		previousRenewalToken: strings.TrimSpace(cfg.PreviousRenewalToken),
		previousRenewalExp:   agentcfg.ParseOptionalRFC3339(cfg.PreviousRenewalTokenExpiresAt),
		lastRecoveryMethod:   "startup",
	}
}

func (m *Manager) SetClient(cp *controlplane.Client) {
	m.cp = cp
}

func (m *Manager) CurrentCredential() string {
	m.credMu.RLock()
	defer m.credMu.RUnlock()
	return strings.TrimSpace(m.cred)
}

func (m *Manager) CurrentRenewalToken() string {
	m.credMu.RLock()
	defer m.credMu.RUnlock()
	return strings.TrimSpace(m.renewalToken)
}

func (m *Manager) RecoveryTokenSnapshot() (string, time.Time, string, time.Time) {
	m.credMu.RLock()
	defer m.credMu.RUnlock()
	return strings.TrimSpace(m.renewalToken), m.renewalExp, strings.TrimSpace(m.previousRenewalToken), m.previousRenewalExp
}

func (m *Manager) AuthStateSnapshot() (time.Time, time.Time, string, int, time.Time) {
	m.credMu.RLock()
	credExp := m.credExp
	renewalExp := m.renewalExp
	recoveryMethod := m.lastRecoveryMethod
	m.credMu.RUnlock()

	m.enrollMu.Lock()
	recoveryFailures := m.recoveryFailures
	nextRetryAt := m.nextEnrollRetryAt
	m.enrollMu.Unlock()

	return credExp, renewalExp, recoveryMethod, recoveryFailures, nextRetryAt
}

func (m *Manager) CurrentBootstrapToken() string {
	if tokenFile := strings.TrimSpace(m.cfg.BootstrapTokenFile); tokenFile != "" {
		return strings.TrimSpace(agentcfg.ReadTextFile(tokenFile))
	}
	return strings.TrimSpace(m.cfg.BootstrapToken)
}

func (m *Manager) ApplyCredentialUpdate(update controlplane.Credential, recoveryMethod string) error {
	cred := strings.TrimSpace(update.Credential)
	if cred == "" {
		return fmt.Errorf("empty credential update")
	}

	currentRenewal, currentRenewalExp, previousRenewal, previousRenewalExp := m.RecoveryTokenSnapshot()
	renewalToken := strings.TrimSpace(update.RenewalToken)
	renewalExpiresAt := strings.TrimSpace(update.RenewalTokenExpiresAt)
	if renewalToken == "" {
		renewalToken = currentRenewal
		if renewalExpiresAt == "" && !currentRenewalExp.IsZero() {
			renewalExpiresAt = currentRenewalExp.Format(time.RFC3339)
		}
	}

	previousRenewalToken := previousRenewal
	previousRenewalTokenExpiresAt := agentcfg.FormatOptionalTime(previousRenewalExp)
	if renewalToken != "" && renewalToken != currentRenewal {
		previousRenewalToken = currentRenewal
		previousRenewalTokenExpiresAt = agentcfg.FormatOptionalTime(currentRenewalExp)
	}

	state := agentcfg.PersistedIdentityState{
		AgentID:                       m.cfg.AgentID,
		Credential:                    cred,
		CredentialExpiresAt:           strings.TrimSpace(update.ExpiresAt),
		RenewalToken:                  renewalToken,
		RenewalTokenExpiresAt:         renewalExpiresAt,
		PreviousRenewalToken:          previousRenewalToken,
		PreviousRenewalTokenExpiresAt: previousRenewalTokenExpiresAt,
		LastRecoveryMethod:            strings.TrimSpace(recoveryMethod),
	}
	if err := agentcfg.SaveIdentityState(m.cfg.AgentIdentityStateFile, state); err != nil {
		return err
	}
	if m.cfg.CredentialFile != "" {
		if err := agentcfg.AtomicWriteFile(m.cfg.CredentialFile, []byte(cred+"\n"), 0o600); err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "agent_credential_compat_write_failed", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"path":     m.cfg.CredentialFile,
				"error":    err.Error(),
			})
		}
	}

	m.credMu.Lock()
	m.cred = cred
	m.credExp = agentcfg.ParseOptionalRFC3339(update.ExpiresAt)
	m.renewalToken = renewalToken
	m.renewalExp = agentcfg.ParseOptionalRFC3339(renewalExpiresAt)
	m.previousRenewalToken = previousRenewalToken
	m.previousRenewalExp = agentcfg.ParseOptionalRFC3339(previousRenewalTokenExpiresAt)
	m.lastRecoveryMethod = strings.TrimSpace(recoveryMethod)
	m.credMu.Unlock()

	m.enrollMu.Lock()
	m.recoveryFailures = 0
	m.nextEnrollRetryAt = time.Time{}
	m.enrollMu.Unlock()

	return nil
}

func (m *Manager) EnsureInitialIdentity(rootCtx context.Context) {
	cred := m.CurrentCredential()
	if cred != "" {
		if m.cfg.CredentialFile != "" {
			_ = agentcfg.AtomicWriteFile(m.cfg.CredentialFile, []byte(cred+"\n"), 0o600)
		}
		credExp, renewalExp, _, _, _ := m.AuthStateSnapshot()
		agentcfg.LogJSON(agentcfg.LevelInfo, "agent_identity_loaded", map[string]interface{}{
			"agent_id":                m.cfg.AgentID,
			"identity_state_file":     m.cfg.AgentIdentityStateFile,
			"credential_file":         m.cfg.CredentialFile,
			"credential_expires_at":   agentcfg.FormatOptionalTime(credExp),
			"renewal_token_present":   strings.TrimSpace(m.CurrentRenewalToken()) != "",
			"renewal_expires_at":      agentcfg.FormatOptionalTime(renewalExp),
			"bootstrap_token_present": strings.TrimSpace(m.CurrentBootstrapToken()) != "",
		})
		return
	}
	if !m.cfg.ForceEnrollOnStart {
		return
	}
	if err := m.RecoverIdentity(rootCtx, "startup_missing_identity", false); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_bootstrap_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"error":    err.Error(),
		})
	}
}

func (m *Manager) shouldAttemptIdentityRecovery(errText string, status int) bool {
	if !m.cfg.ForceEnrollOnStart {
		return false
	}
	et := strings.ToLower(strings.TrimSpace(errText))
	if status == 401 {
		return true
	}
	if strings.Contains(et, "status=401") {
		return true
	}
	if strings.Contains(et, "remote error: tls:") {
		return strings.Contains(et, "certificate required") ||
			strings.Contains(et, "bad certificate") ||
			strings.Contains(et, "expired certificate") ||
			strings.Contains(et, "unknown certificate authority")
	}
	return strings.Contains(et, "unknown or revoked agent") ||
		strings.Contains(et, "invalid agent credential") ||
		strings.Contains(et, "credential expired") ||
		strings.Contains(et, "credential exhausted")
}

func (m *Manager) nextRecoveryBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	wait := 5 * time.Second
	for i := 1; i < failures; i++ {
		wait *= 2
		if wait >= 5*time.Minute {
			wait = 5 * time.Minute
			break
		}
	}
	jitterMax := wait / 3
	if jitterMax > 30*time.Second {
		jitterMax = 30 * time.Second
	}
	return wait + stableJitter(m.cfg.AgentID, fmt.Sprintf("auth.recovery.%d", failures), jitterMax)
}

func (m *Manager) MaybeRecoverIdentity(rootCtx context.Context, trigger string, errText string, status int) {
	if !m.shouldAttemptIdentityRecovery(errText, status) {
		return
	}
	_ = m.RecoverIdentity(rootCtx, trigger, false)
}

func (m *Manager) RecoverIdentity(rootCtx context.Context, trigger string, force bool) error {
	if !m.cfg.ForceEnrollOnStart {
		return fmt.Errorf("identity recovery disabled")
	}
	if m.cp == nil {
		return fmt.Errorf("controlplane client not initialized")
	}

	now := time.Now().UTC()
	m.enrollMu.Lock()
	if m.recoveryInFlight {
		m.enrollMu.Unlock()
		return fmt.Errorf("identity recovery already in progress")
	}
	if !force && !m.nextEnrollRetryAt.IsZero() && now.Before(m.nextEnrollRetryAt) {
		next := m.nextEnrollRetryAt
		m.enrollMu.Unlock()
		return fmt.Errorf("identity recovery backed off until %s", next.Format(time.RFC3339))
	}
	failures := m.recoveryFailures
	m.nextEnrollRetryAt = time.Time{}
	m.recoveryInFlight = true
	m.enrollMu.Unlock()
	defer func() {
		m.enrollMu.Lock()
		m.recoveryInFlight = false
		m.enrollMu.Unlock()
	}()

	bootstrapToken := strings.TrimSpace(m.CurrentBootstrapToken())
	currentRenewal, renewalExp, previousRenewal, previousRenewalExp := m.RecoveryTokenSnapshot()
	renewalToken := strings.TrimSpace(currentRenewal)
	if !renewalExp.IsZero() && now.After(renewalExp) {
		renewalToken = ""
	}
	previousRenewalToken := strings.TrimSpace(previousRenewal)
	if previousRenewalToken == renewalToken {
		previousRenewalToken = ""
	}
	if !previousRenewalExp.IsZero() && now.After(previousRenewalExp) {
		previousRenewalToken = ""
	}

	hostname, _ := os.Hostname()
	keyPEM, csrPEM := m.prepareEnrollmentCSR()
	type recoveryMethod struct {
		name            string
		token           string
		consumeFilePath string
	}
	methods := make([]recoveryMethod, 0, 3)
	if renewalToken != "" {
		methods = append(methods, recoveryMethod{name: "renewal", token: renewalToken})
	}
	if previousRenewalToken != "" {
		methods = append(methods, recoveryMethod{name: "renewal_previous", token: previousRenewalToken})
	}
	if bootstrapToken != "" {
		methods = append(methods, recoveryMethod{name: "bootstrap", token: bootstrapToken, consumeFilePath: m.cfg.BootstrapTokenFile})
	}
	if len(methods) == 0 {
		m.enrollMu.Lock()
		m.recoveryFailures = failures + 1
		m.nextEnrollRetryAt = now.Add(m.nextRecoveryBackoff(m.recoveryFailures))
		next := m.nextEnrollRetryAt
		m.enrollMu.Unlock()
		return fmt.Errorf("no recovery token or bootstrap token available; next retry at %s", next.Format(time.RFC3339))
	}

	var lastErr error
	for _, method := range methods {
		ctx, cancel := context.WithTimeout(rootCtx, m.cfg.ControlEnrollTimeout)
		resp, err := m.cp.Enroll(ctx, controlplane.EnrollRequest{
			AgentID:         m.cfg.AgentID,
			Hostname:        hostname,
			OS:              goruntime.GOOS,
			Arch:            goruntime.GOARCH,
			Version:         buildinfo.Version,
			ProtocolVersion: buildinfo.ProtocolVersion,
			Profile:         agentcfg.NormalizeProfile(m.cfg.Profile),
			CSRPEM:          string(csrPEM),
			BootstrapToken:  method.token,
		})
		cancel()
		if err != nil {
			lastErr = err
			agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_recovery_attempt_failed", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"trigger":  trigger,
				"method":   method.name,
				"error":    err.Error(),
			})
			continue
		}
		m.persistEnrollmentServerCA(resp.Certificate)
		m.persistEnrollmentCertificate(resp.Certificate, keyPEM, method.name)
		if err := m.ApplyCredentialUpdate(resp.Credential, method.name); err != nil {
			lastErr = err
			agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_recovery_persist_failed", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"trigger":  trigger,
				"method":   method.name,
				"error":    err.Error(),
			})
			continue
		}
		if m.runtime != nil && len(resp.Config) > 0 {
			changed, _ := m.runtime.Apply(resp.Config)
			if changed {
				agentcfg.LogJSON(agentcfg.LevelInfo, "controlplane_config_applied", map[string]interface{}{
					"agent_id":    m.cfg.AgentID,
					"config_hash": m.runtime.Hash(),
					"config_keys": len(resp.Config),
				})
			}
		}
		if method.consumeFilePath != "" {
			agentcfg.ConsumeBootstrapTokenFile(method.consumeFilePath, m.cfg.AgentID)
		}
		agentcfg.LogJSON(agentcfg.LevelInfo, "agent_identity_recovered", map[string]interface{}{
			"agent_id":              m.cfg.AgentID,
			"trigger":               trigger,
			"method":                method.name,
			"credential_expires_at": strings.TrimSpace(resp.Credential.ExpiresAt),
			"renewal_expires_at":    strings.TrimSpace(resp.Credential.RenewalTokenExpiresAt),
		})
		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("identity recovery failed")
	}
	m.enrollMu.Lock()
	m.recoveryFailures = failures + 1
	m.nextEnrollRetryAt = now.Add(m.nextRecoveryBackoff(m.recoveryFailures))
	next := m.nextEnrollRetryAt
	m.enrollMu.Unlock()
	return fmt.Errorf("%w; next retry at %s", lastErr, next.Format(time.RFC3339))
}

func (m *Manager) prepareEnrollmentCSR() ([]byte, []byte) {
	if strings.TrimSpace(m.cfg.TLSCertFile) == "" || strings.TrimSpace(m.cfg.TLSKeyFile) == "" {
		return nil, nil
	}
	keyPEM, csrPEM, err := certrenew.NewKeyAndCSR(m.cfg.AgentID)
	if err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_enroll_csr_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"error":    err.Error(),
		})
		return nil, nil
	}
	return keyPEM, csrPEM
}

func (m *Manager) persistEnrollmentServerCA(issued *controlplane.CertificateRenewal) {
	if issued == nil {
		return
	}
	bundle := strings.TrimSpace(issued.ServerCAPEM)
	caFile := strings.TrimSpace(m.cfg.TLSCAFile)
	if bundle == "" || caFile == "" {
		return
	}
	if existing, err := os.ReadFile(caFile); err == nil && strings.TrimSpace(string(existing)) == bundle {
		return
	}
	if err := agentcfg.AtomicWriteFile(caFile, []byte(bundle+"\n"), 0o644); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_enroll_server_ca_persist_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"path":     caFile,
			"error":    err.Error(),
		})
		return
	}
	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_enroll_server_ca_persisted", map[string]interface{}{
		"agent_id": m.cfg.AgentID,
		"path":     caFile,
	})
}

func (m *Manager) persistEnrollmentCertificate(issued *controlplane.CertificateRenewal, keyPEM []byte, method string) {
	if issued == nil || len(keyPEM) == 0 {
		return
	}
	if strings.TrimSpace(issued.CertificatePEM) == "" {
		return
	}
	if err := certrenew.PersistPair([]byte(issued.CertificatePEM), keyPEM, m.cfg.TLSCertFile, m.cfg.TLSKeyFile); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_enroll_certificate_persist_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"method":   method,
			"error":    err.Error(),
		})
		return
	}
	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_enroll_certificate_persisted", map[string]interface{}{
		"agent_id":  m.cfg.AgentID,
		"method":    method,
		"serial":    issued.SerialHex,
		"not_after": strings.TrimSpace(issued.NotAfter),
	})
}

func stableJitter(agentID, scope string, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var n uint64 = 1469598103934665603
	for _, b := range []byte(agentID + "|" + scope) {
		n ^= uint64(b)
		n *= 1099511628211
	}
	return time.Duration(n % uint64(max))
}
