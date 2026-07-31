package enrollment

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dynasmon/seagull-agent/internal/certrenew"
	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/protocol"
	"github.com/google/uuid"
)

const pendingEnrollmentVersion = 2

type pendingEnrollment struct {
	Version   int                      `json:"version"`
	AgentID   string                   `json:"agent_id"`
	Method    string                   `json:"method"`
	Request   protocol.EnrollRequest   `json:"request"`
	Response  *protocol.EnrollResponse `json:"response,omitempty"`
	KeyPEM    string                   `json:"key_pem,omitempty"`
	CreatedAt string                   `json:"created_at"`
	UpdatedAt string                   `json:"updated_at"`
}

func (m *Manager) pendingEnrollmentPath() string {
	if path := strings.TrimSpace(m.cfg.AgentIdentityStateFile); path != "" {
		return path + ".pending-enrollment"
	}
	if path := strings.TrimSpace(m.cfg.CredentialFile); path != "" {
		return path + ".pending-enrollment"
	}
	return ""
}

func (m *Manager) savePendingEnrollment(pending *pendingEnrollment) error {
	if pending == nil {
		return errors.New("pending enrollment is required")
	}
	path := m.pendingEnrollmentPath()
	if path == "" {
		return errors.New("identity state path is required for durable enrollment")
	}
	pending.Version = pendingEnrollmentVersion
	pending.AgentID = strings.TrimSpace(m.cfg.AgentID)
	pending.Method = strings.TrimSpace(pending.Method)
	pending.Request.AgentID = pending.AgentID
	switch pending.Method {
	case "bootstrap", "renewal", "renewal_previous":
	default:
		return errors.New("pending enrollment recovery method is invalid")
	}
	if _, err := uuid.Parse(strings.TrimSpace(pending.Request.EnrollmentID)); err != nil {
		return errors.New("pending enrollment transaction ID is invalid")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if strings.TrimSpace(pending.CreatedAt) == "" {
		pending.CreatedAt = now
	}
	pending.UpdatedAt = now
	payload, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("marshal pending enrollment: %w", err)
	}
	if err := agentcfg.AtomicWriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("persist pending enrollment: %w", err)
	}
	return nil
}

func (m *Manager) loadPendingEnrollment() (pendingEnrollment, bool, error) {
	path := m.pendingEnrollmentPath()
	if path == "" {
		return pendingEnrollment{}, false, nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingEnrollment{}, false, nil
		}
		return pendingEnrollment{}, false, fmt.Errorf("read pending enrollment: %w", err)
	}
	var pending pendingEnrollment
	if err := json.Unmarshal(payload, &pending); err != nil {
		return pendingEnrollment{}, false, fmt.Errorf("parse pending enrollment: %w", err)
	}
	if pending.Version != pendingEnrollmentVersion {
		return pendingEnrollment{}, false, fmt.Errorf("unsupported pending enrollment version: %d", pending.Version)
	}
	if strings.TrimSpace(pending.AgentID) != strings.TrimSpace(m.cfg.AgentID) {
		return pendingEnrollment{}, false, errors.New("pending enrollment agent ID mismatch")
	}
	switch strings.TrimSpace(pending.Method) {
	case "bootstrap", "renewal", "renewal_previous":
	default:
		return pendingEnrollment{}, false, errors.New("pending enrollment recovery method is invalid")
	}
	if strings.TrimSpace(pending.Request.AgentID) != strings.TrimSpace(m.cfg.AgentID) {
		return pendingEnrollment{}, false, errors.New("pending enrollment request agent ID mismatch")
	}
	if _, err := uuid.Parse(strings.TrimSpace(pending.Request.EnrollmentID)); err != nil {
		return pendingEnrollment{}, false, errors.New("pending enrollment transaction ID is invalid")
	}
	return pending, true, nil
}

func (m *Manager) clearPendingEnrollment() error {
	path := m.pendingEnrollmentPath()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pending enrollment: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open pending enrollment directory: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("sync pending enrollment directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close pending enrollment directory: %w", closeErr)
	}
	return nil
}

func (m *Manager) resumePendingEnrollment() (bool, error) {
	pending, ok, err := m.loadPendingEnrollment()
	if err != nil || !ok {
		return ok, err
	}
	if pending.Response == nil {
		return false, nil
	}
	if err := m.finalizePendingEnrollment(pending); err != nil {
		return true, err
	}
	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_pending_enrollment_recovered", map[string]interface{}{
		"agent_id": m.cfg.AgentID,
		"method":   pending.Method,
	})
	return true, nil
}

func (m *Manager) finalizePendingEnrollment(pending pendingEnrollment) error {
	if pending.Response == nil {
		return errors.New("pending enrollment response is unavailable")
	}
	response := *pending.Response
	if strings.TrimSpace(response.AgentID) != strings.TrimSpace(m.cfg.AgentID) {
		return errors.New("enrollment response agent ID mismatch")
	}
	if _, incompatible := protocol.Negotiate(response.Protocol); incompatible != nil {
		return incompatible
	}
	if strings.TrimSpace(response.Credential.Credential) == "" {
		return errors.New("enrollment response credential is empty")
	}
	if response.Certificate != nil && len(pending.KeyPEM) > 0 {
		if _, err := certrenew.ValidateIssuedPair(
			[]byte(response.Certificate.CertificatePEM),
			[]byte(pending.KeyPEM),
			m.cfg.AgentID,
			time.Now().UTC(),
		); err != nil {
			return err
		}
	}
	if err := m.persistEnrollmentServerCA(response.Certificate); err != nil {
		return err
	}
	if err := m.persistEnrollmentCertificate(response.Certificate, []byte(pending.KeyPEM), pending.Method); err != nil {
		return err
	}
	if err := m.ApplyCredentialUpdate(response.Credential, pending.Method); err != nil {
		return err
	}
	if m.runtime != nil && len(response.Config) > 0 {
		changed, applyErr := m.runtime.Apply(response.Config)
		if applyErr != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "controlplane_config_rejected", map[string]interface{}{
				"agent_id": m.cfg.AgentID,
				"error":    applyErr.Error(),
				"revision": m.runtime.Revision(),
			})
		}
		if changed {
			agentcfg.LogJSON(agentcfg.LevelInfo, "controlplane_config_applied", map[string]interface{}{
				"agent_id":    m.cfg.AgentID,
				"config_hash": m.runtime.Hash(),
				"config_keys": len(response.Config),
				"revision":    m.runtime.Revision(),
			})
		}
	}
	if err := m.clearPendingEnrollment(); err != nil {
		return err
	}
	if pending.Method == "bootstrap" {
		agentcfg.ConsumeBootstrapTokenFile(m.cfg.BootstrapTokenFile, m.cfg.AgentID)
	}
	return nil
}
