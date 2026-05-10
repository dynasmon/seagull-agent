package runtime

import (
	"context"
	"strings"
	"time"

	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/controlplane"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/heartbeat"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/jitter"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/responseactions"
)

func (s *Service) stageResponseActions(actions []controlplane.ResponseAction) responseactions.StageResult {
	if s.responseStage == nil {
		s.responseStage = responseactions.NewStage(s.cfg.ResponseActionStageMax)
	}
	out := s.responseStage.Stage(time.Now().UTC(), actions, s.cfg.AgentID)
	s.state.ResponseActionsStagedTotal += out.Added
	return out
}

func (s *Service) pendingResponseActions() int {
	if s.responseStage == nil {
		return 0
	}
	return s.responseStage.PendingCount()
}

func (s *Service) refreshRuntimeConfig(rootCtx context.Context) (bool, int, string, error) {
	ctxCfg, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
	cfg, err := s.cp.GetConfig(ctxCfg)
	cancel()
	if err != nil {
		return false, 0, "", err
	}
	if s.runtimeConfig == nil {
		return false, len(cfg), "", nil
	}
	changed, _ := s.runtimeConfig.Apply(cfg)
	return changed, len(cfg), s.runtimeConfig.Hash(), nil
}

func (s *Service) startResponseActionExecutor(rootCtx context.Context) {
	if s.responseStage == nil || s.cp == nil {
		return
	}

	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				for i := 0; i < 8; i++ {
					staged, ok := s.responseStage.Next(time.Now().UTC(), s.cfg.AgentID)
					if !ok {
						break
					}

					now := time.Now().UTC()
					runningResult := controlplane.ResponseActionExecutionResult{
						ResponseActionID: staged.Action.ID,
						AgentID:          s.cfg.AgentID,
						Status:           "running",
						StartedAt:        &now,
					}

					ctx, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
					err := s.cp.ReportResponseActionResult(ctx, runningResult)
					cancel()
					if err != nil {
						agentcfg.LogJSON(agentcfg.LevelWarn, "response_action_running_report_failed", map[string]interface{}{
							"agent_id":  s.cfg.AgentID,
							"action_id": staged.Action.ID,
							"error":     err.Error(),
						})
						s.enrollment.MaybeRecoverIdentity(rootCtx, "response_action_running_report", err.Error(), 0)
						continue
					}

					modules := map[string]interface{}{}
					for _, src := range s.cfg.Sources {
						modules[strings.TrimSpace(src)] = true
					}
					effectiveConfig := map[string]interface{}{}
					if s.runtimeConfig != nil {
						effectiveConfig = s.runtimeConfig.Raw()
					}
					execRes := responseactions.Execute(staged.Action, responseactions.ExecuteOptions{
						ExpectedAgentID: s.cfg.AgentID,
						AgentID:         s.cfg.AgentID,
						BuildVersion:    buildVersion,
						EffectiveConfig: effectiveConfig,
						ModuleStates:    modules,
						RefreshRuntimeConfig: func() (bool, int, string, error) {
							return s.refreshRuntimeConfig(rootCtx)
						},
						AgentStartedAt: s.state.StartedAt,
						Now:            now,
					})
					s.responseStage.MarkHandled(staged.Action.ID)

					result := controlplane.ResponseActionExecutionResult{
						ResponseActionID: staged.Action.ID,
						AgentID:          s.cfg.AgentID,
						Status:           execRes.Status,
						ResultPayload:    execRes.Result,
						Error:            execRes.Error,
						StartedAt:        &execRes.StartedAt,
						FinishedAt:       &execRes.FinishedAt,
					}
					ctx, cancel = context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
					err = s.cp.ReportResponseActionResult(ctx, result)
					cancel()
					if err != nil {
						agentcfg.LogJSON(agentcfg.LevelWarn, "response_action_report_failed", map[string]interface{}{
							"agent_id":  s.cfg.AgentID,
							"action_id": staged.Action.ID,
							"status":    execRes.Status,
							"error":     err.Error(),
						})
						s.enrollment.MaybeRecoverIdentity(rootCtx, "response_action_report", err.Error(), 0)
						continue
					}
					agentcfg.LogJSON(agentcfg.LevelInfo, "response_action_executed", map[string]interface{}{
						"agent_id":  s.cfg.AgentID,
						"action_id": staged.Action.ID,
						"type":      staged.Action.ActionType,
						"status":    execRes.Status,
					})
				}
			}
		}
	}()
}

func (s *Service) startControlPlane(rootCtx context.Context) {
	if s.cp == nil {
		return
	}

	go func() {
		delay := jitter.Stable(s.cfg.AgentID, "control.identity_refresh", 90*time.Second)
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-rootCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		if strings.TrimSpace(s.enrollment.CurrentCredential()) == "" {
			return
		}
		credExp, renewalExp, _, _, _ := s.enrollment.AuthStateSnapshot()
		if !credExp.IsZero() && !renewalExp.IsZero() {
			return
		}

		ctx, cancel := context.WithTimeout(rootCtx, s.cfg.ControlEnrollTimeout)
		rot, err := s.cp.RotateCredential(ctx)
		cancel()
		if err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_refresh_failed", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    err.Error(),
			})
			s.enrollment.MaybeRecoverIdentity(rootCtx, "startup_identity_refresh", err.Error(), 0)
			return
		}
		if err := s.enrollment.ApplyCredentialUpdate(rot, "startup_refresh"); err != nil {
			agentcfg.LogJSON(agentcfg.LevelWarn, "agent_identity_refresh_persist_failed", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    err.Error(),
			})
			return
		}
		agentcfg.LogJSON(agentcfg.LevelInfo, "agent_identity_refreshed", map[string]interface{}{
			"agent_id":              s.cfg.AgentID,
			"credential_expires_at": strings.TrimSpace(rot.ExpiresAt),
			"renewal_expires_at":    strings.TrimSpace(rot.RenewalTokenExpiresAt),
		})
	}()

	heartbeat.Start(rootCtx, heartbeat.Config{
		AgentID: s.cfg.AgentID,
		Every:   s.cfg.ControlHeartbeatEvery,
		Jitter:  s.cfg.ControlHeartbeatJitter,
		Timeout: s.cfg.HTTPTimeout,
	}, heartbeat.Deps{
		Build: s.buildHeartbeatRequest,
		Send: func(ctx context.Context, hb controlplane.HeartbeatRequest) error {
			return s.cp.Heartbeat(ctx, hb)
		},
		OnError: func(err error) {
			agentcfg.LogJSON(agentcfg.LevelWarn, "controlplane_heartbeat_error", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    err.Error(),
			})
			s.enrollment.MaybeRecoverIdentity(rootCtx, "controlplane_heartbeat", err.Error(), 0)
		},
	})

	go func() {
		initialDelay := jitter.Stable(s.cfg.AgentID, "control.config", s.cfg.ControlConfigJitter)
		if initialDelay > 0 {
			t := time.NewTimer(initialDelay)
			select {
			case <-rootCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}

		t := time.NewTicker(s.cfg.ControlConfigEvery)
		defer t.Stop()

		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
				cfg, err := s.cp.GetConfig(ctx)
				cancel()
				if err != nil {
					agentcfg.LogJSON(agentcfg.LevelWarn, "controlplane_config_error", map[string]interface{}{
						"agent_id": s.cfg.AgentID,
						"error":    err.Error(),
					})
					s.enrollment.MaybeRecoverIdentity(rootCtx, "controlplane_config", err.Error(), 0)
					continue
				}
				if s.runtimeConfig != nil && len(cfg) > 0 {
					changed, _ := s.runtimeConfig.Apply(cfg)
					if changed {
						agentcfg.LogJSON(agentcfg.LevelInfo, "controlplane_config_applied", map[string]interface{}{
							"agent_id":    s.cfg.AgentID,
							"config_hash": s.runtimeConfig.Hash(),
							"config_keys": len(cfg),
						})
					}
				}
			}
		}
	}()

	responseactions.StartPolling(rootCtx, responseactions.PollerConfig{
		AgentID: s.cfg.AgentID,
		Every:   s.cfg.ControlResponsePollEvery,
		Jitter:  s.cfg.ControlResponsePollJitter,
		Timeout: s.cfg.HTTPTimeout,
	}, responseactions.PollerDeps{
		Fetch: func(ctx context.Context) ([]controlplane.ResponseAction, error) {
			return s.cp.ListPendingResponseActions(ctx)
		},
		Stage: s.stageResponseActions,
		OnError: func(err error) {
			s.state.ResponseActionPollErrorsTotal++
			agentcfg.LogJSON(agentcfg.LevelWarn, "controlplane_response_actions_poll_error", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    err.Error(),
			})
			s.enrollment.MaybeRecoverIdentity(rootCtx, "response_actions_poll", err.Error(), 0)
		},
		OnStaged: func(fetched int, result responseactions.StageResult) {
			if result.Added > 0 || result.Dropped > 0 {
				agentcfg.LogJSON(agentcfg.LevelInfo, "response_actions_staged", map[string]interface{}{
					"agent_id": s.cfg.AgentID,
					"fetched":  fetched,
					"added":    result.Added,
					"ignored":  result.Ignored,
					"dropped":  result.Dropped,
					"pending":  result.Pending,
				})
			}
		},
	})
	s.startResponseActionExecutor(rootCtx)

	go func() {
		t := time.NewTicker(s.cfg.CredentialRotateEvery)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				credExp, renewalExp, _, _, _ := s.enrollment.AuthStateSnapshot()
				renewalRotateBefore := s.cfg.CredentialRotateBefore
				if renewalRotateBefore < 12*time.Hour {
					renewalRotateBefore = 12 * time.Hour
				}

				needsRotate := false
				if !credExp.IsZero() && time.Until(credExp) <= s.cfg.CredentialRotateBefore {
					needsRotate = true
				}
				if !renewalExp.IsZero() && time.Until(renewalExp) <= renewalRotateBefore {
					needsRotate = true
				}
				if !needsRotate {
					continue
				}

				if strings.TrimSpace(s.enrollment.CurrentCredential()) == "" {
					_ = s.enrollment.RecoverIdentity(rootCtx, "rotation_missing_credential", false)
					continue
				}

				ctx, cancel := context.WithTimeout(rootCtx, s.cfg.ControlEnrollTimeout)
				rot, err := s.cp.RotateCredential(ctx)
				cancel()
				if err != nil {
					agentcfg.LogJSON(agentcfg.LevelWarn, "agent_credential_rotate_failed", map[string]interface{}{
						"agent_id": s.cfg.AgentID,
						"error":    err.Error(),
					})
					s.enrollment.MaybeRecoverIdentity(rootCtx, "credential_rotate_failed", err.Error(), 0)
					continue
				}
				if err := s.enrollment.ApplyCredentialUpdate(rot, "credential_rotation"); err != nil {
					agentcfg.LogJSON(agentcfg.LevelWarn, "agent_credential_rotate_persist_failed", map[string]interface{}{
						"agent_id": s.cfg.AgentID,
						"error":    err.Error(),
					})
					continue
				}
				agentcfg.LogJSON(agentcfg.LevelInfo, "agent_credential_rotated", map[string]interface{}{
					"agent_id":              s.cfg.AgentID,
					"credential_expires_at": strings.TrimSpace(rot.ExpiresAt),
					"renewal_expires_at":    strings.TrimSpace(rot.RenewalTokenExpiresAt),
				})
			}
		}
	}()
}

func (s *Service) buildHeartbeatRequest() controlplane.HeartbeatRequest {
	metrics := map[string]interface{}{
		"events_sent_total":   s.state.EventsSentTotal,
		"send_errors_total":   s.state.SendErrorsTotal,
		"last_http_status":    s.state.LastHTTPStatus,
		"last_error":          s.state.LastError,
		"send_attempts_total": s.state.SendAttemptsTotal,
	}

	credExp, renewalExp, recoveryMethod, recoveryFailures, nextRetryAt := s.enrollment.AuthStateSnapshot()
	metrics["auth_identity_state_file"] = s.cfg.AgentIdentityStateFile
	metrics["auth_has_credential"] = strings.TrimSpace(s.enrollment.CurrentCredential()) != ""
	currentRenewal, _, previousRenewal, _ := s.enrollment.RecoveryTokenSnapshot()
	metrics["auth_has_renewal_token"] = strings.TrimSpace(currentRenewal) != ""
	metrics["auth_has_previous_renewal_token"] = strings.TrimSpace(previousRenewal) != ""
	metrics["auth_last_recovery_method"] = recoveryMethod
	metrics["auth_recovery_failures"] = recoveryFailures

	if !credExp.IsZero() {
		metrics["auth_credential_expires_at"] = credExp.Format(time.RFC3339)
		metrics["auth_credential_seconds_remaining"] = int64(time.Until(credExp).Seconds())
	}
	if !renewalExp.IsZero() {
		metrics["auth_renewal_expires_at"] = renewalExp.Format(time.RFC3339)
		metrics["auth_renewal_seconds_remaining"] = int64(time.Until(renewalExp).Seconds())
	}
	if !nextRetryAt.IsZero() {
		metrics["auth_next_recovery_retry_at"] = nextRetryAt.Format(time.RFC3339)
	}
	if s.runtimeConfig != nil {
		metrics["config_hash"] = s.runtimeConfig.Hash()
	}
	metrics["response_actions_pending"] = s.pendingResponseActions()
	metrics["response_actions_poll_errors_total"] = s.state.ResponseActionPollErrorsTotal

	if agentcfg.Contains(s.cfg.Sources, "syscollector") {
		sysCfg := s.runtimeConfig.Syscollector()
		status := s.sources.SyscollectorStatus()
		metrics["syscollector_enabled"] = sysCfg.Enabled
		metrics["syscollector_last_run_at"] = status.LastRunAt
		metrics["syscollector_last_sent_at"] = status.LastSentAt
		metrics["syscollector_last_error"] = status.LastError
		metrics["syscollector_last_hash"] = status.LastHash
		metrics["syscollector_last_packages_count"] = status.LastPkgCount
	}

	return controlplane.HeartbeatRequest{
		Status:        "ok",
		UptimeSeconds: int64(time.Since(s.state.StartedAt).Seconds()),
		Modules: map[string]interface{}{
			"sources": s.cfg.Sources,
		},
		Metrics: metrics,
	}
}
