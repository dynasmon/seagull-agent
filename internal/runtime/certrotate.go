package runtime

import (
	"context"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent/internal/certrenew"
	agentcfg "github.com/dynasmon/Seagull-agent/internal/config"
	"github.com/dynasmon/Seagull-agent/internal/jitter"
)

func (s *Service) startCertificateRotation(rootCtx context.Context) {
	if s.cp == nil {
		return
	}
	if strings.TrimSpace(s.cfg.TLSCertFile) == "" || strings.TrimSpace(s.cfg.TLSKeyFile) == "" {
		return
	}

	go func() {
		initialDelay := jitter.Stable(s.cfg.AgentID, "control.cert_rotate", 2*time.Minute)
		if initialDelay > 0 {
			t := time.NewTimer(initialDelay)
			select {
			case <-rootCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		s.maybeRenewCertificate(rootCtx)

		t := time.NewTicker(s.cfg.CertRotateEvery)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				s.maybeRenewCertificate(rootCtx)
			}
		}
	}()
}

func (s *Service) maybeRenewCertificate(rootCtx context.Context) {
	needed, current, err := certrenew.NeedsRenewal(s.cfg.TLSCertFile, s.cfg.CertRotateBefore, time.Now().UTC())
	if err != nil {
		s.state.CertRenewErrorsTotal++
		s.state.CertLastRenewError = err.Error()
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_certificate_inspect_failed", map[string]interface{}{
			"agent_id":  s.cfg.AgentID,
			"cert_file": s.cfg.TLSCertFile,
			"error":     err.Error(),
		})
		return
	}
	if !needed {
		return
	}

	keyPEM, csrPEM, err := certrenew.NewKeyAndCSR(s.cfg.AgentID)
	if err != nil {
		s.state.CertRenewErrorsTotal++
		s.state.CertLastRenewError = err.Error()
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_certificate_csr_failed", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"error":    err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(rootCtx, s.cfg.ControlEnrollTimeout)
	renewed, err := s.cp.RenewCertificate(ctx, string(csrPEM))
	cancel()
	if err != nil {
		s.state.CertRenewErrorsTotal++
		s.state.CertLastRenewError = err.Error()
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_certificate_renew_failed", map[string]interface{}{
			"agent_id":       s.cfg.AgentID,
			"current_serial": current.SerialHex,
			"not_after":      current.NotAfter.Format(time.RFC3339),
			"error":          err.Error(),
		})
		s.enrollment.MaybeRecoverIdentity(rootCtx, "certificate_renew", err.Error(), 0)
		return
	}

	if err := certrenew.PersistPair([]byte(renewed.CertificatePEM), keyPEM, s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil {
		s.state.CertRenewErrorsTotal++
		s.state.CertLastRenewError = err.Error()
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_certificate_persist_failed", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"error":    err.Error(),
		})
		return
	}

	if changed, err := certrenew.PersistServerCA(renewed.ServerCAPEM, s.cfg.TLSCAFile); err != nil {
		agentcfg.LogJSON(agentcfg.LevelWarn, "agent_server_ca_persist_failed", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"path":     s.cfg.TLSCAFile,
			"error":    err.Error(),
		})
	} else if changed {
		agentcfg.LogJSON(agentcfg.LevelInfo, "agent_server_ca_rotated", map[string]interface{}{
			"agent_id": s.cfg.AgentID,
			"path":     s.cfg.TLSCAFile,
		})
	}

	s.state.CertRenewalsTotal++
	s.state.CertLastRenewError = ""
	agentcfg.LogJSON(agentcfg.LevelInfo, "agent_certificate_renewed", map[string]interface{}{
		"agent_id":        s.cfg.AgentID,
		"previous_serial": current.SerialHex,
		"serial":          renewed.SerialHex,
		"not_after":       strings.TrimSpace(renewed.NotAfter),
	})
}
