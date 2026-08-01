package enrollment

import (
	"context"
	"errors"
	"fmt"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/dynasmon/seagull-agent/internal/buildinfo"
	"github.com/dynasmon/seagull-agent/internal/certrenew"
	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/controlplane"
	"github.com/dynasmon/seagull-agent/internal/sources"
	"github.com/dynasmon/seagull-agent/protocol"
	"github.com/google/uuid"
)

type recoveryMethod struct {
	name  string
	token string
}

type Manager struct {
	cfg     agentcfg.Config
	runtime *sources.RuntimeConfig
	cp      *controlplane.Client

	identityMu           sync.Mutex
	credMu               sync.RWMutex
	cred                 string
	credExp              time.Time
	renewalToken         string
	renewalExp           time.Time
	previousRenewalToken string
	previousRenewalExp   time.Time
	lastRecoveryMethod   string
	bootstrapConsumed    bool

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
		bootstrapConsumed:    cfg.BootstrapTokenConsumed,
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
	m.credMu.RLock()
	consumed := m.bootstrapConsumed
	m.credMu.RUnlock()
	if consumed {
		return ""
	}
	if tokenFile := strings.TrimSpace(m.cfg.BootstrapTokenFile); tokenFile != "" {
		return strings.TrimSpace(agentcfg.ReadTextFile(tokenFile))
	}
	return strings.TrimSpace(m.cfg.BootstrapToken)
}

func (m *Manager) ApplyCredentialUpdate(update protocol.Credential, recoveryMethod string) error {
	m.identityMu.Lock()
	defer m.identityMu.Unlock()

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
	m.credMu.RLock()
	bootstrapTokenConsumed := m.bootstrapConsumed
	m.credMu.RUnlock()
	if strings.TrimSpace(recoveryMethod) == "bootstrap" {
		bootstrapTokenConsumed = true
	}
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
		BootstrapTokenConsumed:        bootstrapTokenConsumed,
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
	m.bootstrapConsumed = bootstrapTokenConsumed
	m.credMu.Unlock()

	m.enrollMu.Lock()
	m.recoveryFailures = 0
	m.nextEnrollRetryAt = time.Time{}
	m.enrollMu.Unlock()

	return nil
}

func (m *Manager) HasUsableIdentity() bool {
	return m.CurrentCredential() != "" && m.certificateIdentityUsable()
}

func (m *Manager) EnsureInitialIdentity(rootCtx context.Context) error {
	if _, err := m.resumePendingEnrollment(); err != nil {
		return fmt.Errorf("resume pending enrollment: %w", err)
	}
	cred := m.CurrentCredential()
	if m.HasUsableIdentity() {
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
		return nil
	}
	if !m.cfg.ForceEnrollOnStart {
		return fmt.Errorf("agent identity is missing and enrollment on startup is disabled")
	}
	if err := m.RecoverIdentity(rootCtx, "startup_missing_identity", false); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_bootstrap_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"error":    err.Error(),
		})
		return err
	}
	return nil
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

	if resumed, err := m.resumePendingEnrollment(); err != nil {
		return fmt.Errorf("resume pending enrollment: %w", err)
	} else if resumed {
		return nil
	}

	methods := m.availableRecoveryMethods(now)
	pending, hasPending, err := m.loadPendingEnrollment()
	if err != nil {
		return fmt.Errorf("load pending enrollment: %w", err)
	}
	if hasPending {
		token := recoveryMethodToken(methods, pending.Method)
		if token == "" {
			return m.recordRecoveryFailure(
				now,
				failures,
				fmt.Errorf("pending %s enrollment token is unavailable", pending.Method),
			)
		}
		_, err = m.attemptPendingEnrollment(rootCtx, trigger, pending, token)
		if err == nil {
			return nil
		}
		var httpErr *controlplane.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == 401 {
			if clearErr := m.clearPendingEnrollment(); clearErr != nil {
				return clearErr
			}
			methods = removeRecoveryMethod(methods, pending.Method)
		} else {
			var incompatible *protocol.Incompatibility
			if errors.As(err, &incompatible) && incompatible.HTTPStatus != 0 {
				if clearErr := m.clearPendingEnrollment(); clearErr != nil {
					return clearErr
				}
			}
			return m.recordRecoveryFailure(now, failures, err)
		}
	}

	if len(methods) == 0 {
		return m.recordRecoveryFailure(now, failures, errors.New("no recovery token or bootstrap token available"))
	}

	hostname, _ := os.Hostname()
	keyPEM, csrPEM, err := m.prepareEnrollmentCSR()
	if err != nil {
		return err
	}

	var lastErr error
	for _, method := range methods {
		pending := pendingEnrollment{
			Method: method.name,
			Request: protocol.EnrollRequest{
				EnrollmentID:    uuid.NewString(),
				AgentID:         m.cfg.AgentID,
				Hostname:        hostname,
				OS:              goruntime.GOOS,
				Arch:            goruntime.GOARCH,
				Version:         buildinfo.Release(),
				ProtocolVersion: protocol.Version,
				Profile:         protocol.NormalizeProfile(m.cfg.Profile),
				CSRPEM:          string(csrPEM),
			},
			KeyPEM: string(keyPEM),
		}
		if err := m.savePendingEnrollment(&pending); err != nil {
			return err
		}
		_, err := m.attemptPendingEnrollment(rootCtx, trigger, pending, method.token)
		if err == nil {
			return nil
		}
		lastErr = err
		var httpErr *controlplane.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == 401 {
			if clearErr := m.clearPendingEnrollment(); clearErr != nil {
				return clearErr
			}
			continue
		}
		var incompatible *protocol.Incompatibility
		if errors.As(err, &incompatible) && incompatible.HTTPStatus != 0 {
			if clearErr := m.clearPendingEnrollment(); clearErr != nil {
				return clearErr
			}
		}
		return m.recordRecoveryFailure(now, failures, err)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("identity recovery failed")
	}
	return m.recordRecoveryFailure(now, failures, lastErr)
}

func (m *Manager) availableRecoveryMethods(now time.Time) []recoveryMethod {
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
	methods := make([]recoveryMethod, 0, 3)
	if renewalToken != "" {
		methods = append(methods, recoveryMethod{name: "renewal", token: renewalToken})
	}
	if previousRenewalToken != "" {
		methods = append(methods, recoveryMethod{name: "renewal_previous", token: previousRenewalToken})
	}
	if bootstrapToken != "" {
		methods = append(methods, recoveryMethod{name: "bootstrap", token: bootstrapToken})
	}
	return methods
}

func recoveryMethodToken(methods []recoveryMethod, name string) string {
	for _, method := range methods {
		if method.name == strings.TrimSpace(name) {
			return method.token
		}
	}
	return ""
}

func removeRecoveryMethod(methods []recoveryMethod, name string) []recoveryMethod {
	out := make([]recoveryMethod, 0, len(methods))
	for _, method := range methods {
		if method.name != strings.TrimSpace(name) {
			out = append(out, method)
		}
	}
	return out
}

func (m *Manager) attemptPendingEnrollment(
	rootCtx context.Context,
	trigger string,
	pending pendingEnrollment,
	token string,
) (protocol.EnrollResponse, error) {
	request := pending.Request
	request.BootstrapToken = strings.TrimSpace(token)
	ctx, cancel := context.WithTimeout(rootCtx, m.cfg.ControlEnrollTimeout)
	response, err := m.cp.Enroll(ctx, request)
	cancel()
	if err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_recovery_attempt_failed", map[string]interface{}{
			"agent_id":      m.cfg.AgentID,
			"enrollment_id": pending.Request.EnrollmentID,
			"trigger":       trigger,
			"method":        pending.Method,
			"error":         err.Error(),
		})
		return protocol.EnrollResponse{}, err
	}
	if _, incompatible := protocol.Negotiate(response.Protocol); incompatible != nil {
		return protocol.EnrollResponse{}, incompatible
	}
	pending.Response = &response
	if err := m.savePendingEnrollment(&pending); err != nil {
		return protocol.EnrollResponse{}, err
	}
	if err := m.finalizePendingEnrollment(pending); err != nil {
		return protocol.EnrollResponse{}, fmt.Errorf("finalize enrollment: %w", err)
	}
	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_identity_recovered", map[string]interface{}{
		"agent_id":              m.cfg.AgentID,
		"enrollment_id":         pending.Request.EnrollmentID,
		"trigger":               trigger,
		"method":                pending.Method,
		"credential_expires_at": strings.TrimSpace(response.Credential.ExpiresAt),
		"renewal_expires_at":    strings.TrimSpace(response.Credential.RenewalTokenExpiresAt),
	})
	return response, nil
}

func (m *Manager) recordRecoveryFailure(now time.Time, failures int, recoveryErr error) error {
	m.enrollMu.Lock()
	m.recoveryFailures = failures + 1
	m.nextEnrollRetryAt = now.Add(m.nextRecoveryBackoff(m.recoveryFailures))
	next := m.nextEnrollRetryAt
	m.enrollMu.Unlock()
	return fmt.Errorf("%w; next retry at %s", recoveryErr, next.Format(time.RFC3339))
}

func (m *Manager) prepareEnrollmentCSR() ([]byte, []byte, error) {
	if strings.TrimSpace(m.cfg.TLSCertFile) == "" || strings.TrimSpace(m.cfg.TLSKeyFile) == "" {
		return nil, nil, nil
	}
	keyPEM, csrPEM, err := certrenew.NewKeyAndCSR(m.cfg.AgentID)
	if err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_enroll_csr_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"error":    err.Error(),
		})
		return nil, nil, fmt.Errorf("create enrollment CSR: %w", err)
	}
	return keyPEM, csrPEM, nil
}

func (m *Manager) persistEnrollmentServerCA(issued *protocol.CertificateRenewal) error {
	if issued == nil {
		return nil
	}
	changed, err := certrenew.PersistServerCA(issued.ServerCAPEM, m.cfg.TLSCAFile)
	if err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_enroll_server_ca_persist_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"path":     m.cfg.TLSCAFile,
			"error":    err.Error(),
		})
		return err
	}
	if changed {
		agentcfg.LogJSON(agentcfg.LevelInfo, "agent_enroll_server_ca_persisted", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"path":     m.cfg.TLSCAFile,
		})
	}
	return nil
}

func (m *Manager) persistEnrollmentCertificate(issued *protocol.CertificateRenewal, keyPEM []byte, method string) error {
	tlsConfigured := strings.TrimSpace(m.cfg.TLSCertFile) != "" || strings.TrimSpace(m.cfg.TLSKeyFile) != ""
	if !tlsConfigured {
		return nil
	}
	if issued == nil || len(keyPEM) == 0 {
		return errors.New("enrollment response is missing client certificate material")
	}
	if strings.TrimSpace(issued.CertificatePEM) == "" {
		return errors.New("enrollment response client certificate is empty")
	}
	if err := certrenew.PersistPair([]byte(issued.CertificatePEM), keyPEM, m.cfg.AgentID, m.cfg.TLSCertFile, m.cfg.TLSKeyFile); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_enroll_certificate_persist_failed", map[string]interface{}{
			"agent_id": m.cfg.AgentID,
			"method":   method,
			"error":    err.Error(),
		})
		return err
	}
	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_enroll_certificate_persisted", map[string]interface{}{
		"agent_id":  m.cfg.AgentID,
		"method":    method,
		"serial":    issued.SerialHex,
		"not_after": strings.TrimSpace(issued.NotAfter),
	})
	return nil
}

func (m *Manager) certificateIdentityUsable() bool {
	certFile := strings.TrimSpace(m.cfg.TLSCertFile)
	keyFile := strings.TrimSpace(m.cfg.TLSKeyFile)
	if certFile == "" && keyFile == "" {
		return true
	}
	if certFile == "" || keyFile == "" {
		return false
	}
	if err := certrenew.RecoverPair(certFile, keyFile); err != nil {
		return false
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return false
	}
	_, err = certrenew.ValidateIssuedPair(certPEM, keyPEM, m.cfg.AgentID, time.Now().UTC())
	return err == nil
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
