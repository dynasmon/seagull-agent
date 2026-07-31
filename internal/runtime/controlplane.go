package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dynasmon/seagull-agent/internal/buildinfo"
	"github.com/dynasmon/seagull-agent/internal/certrenew"
	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/heartbeat"
	"github.com/dynasmon/seagull-agent/internal/jitter"
	"github.com/dynasmon/seagull-agent/internal/responseactions"
	"github.com/dynasmon/seagull-agent/internal/sources"
	"github.com/dynasmon/seagull-agent/protocol"
)

func (s *Service) stageResponseActions(actions []protocol.ResponseAction) responseactions.StageResult {
	if s.responseStage == nil {
		return responseactions.StageResult{}
	}
	out := s.responseStage.Stage(time.Now().UTC(), actions, s.cfg.AgentID)
	s.updateState(func(state *SummaryState) {
		state.ResponseActionsStagedTotal += out.Added
	})
	return out
}

func (s *Service) pendingResponseActions() int {
	pending := 0
	if s.responseStage != nil {
		pending += s.responseStage.PendingCount()
	}
	if s.responseJournal != nil {
		count, err := s.responseJournal.Pending()
		if err == nil {
			pending += count
		}
	}
	return pending
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
	changed, err := s.runtimeConfig.Apply(cfg)
	if err != nil {
		return false, len(cfg), s.runtimeConfig.Hash(), err
	}
	return changed, len(cfg), s.runtimeConfig.Hash(), nil
}

func (s *Service) startResponseActionExecutor(rootCtx context.Context) {
	if s.responseStage == nil || s.responseJournal == nil || s.cp == nil {
		return
	}

	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()

		for {
			if err := s.processResponseActions(rootCtx); err != nil {
				s.fail(fmt.Errorf("process response actions: %w", err))
				return
			}
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (s *Service) processResponseActions(rootCtx context.Context) error {
	terminal, err := s.responseJournal.Terminal(8)
	if err != nil {
		return err
	}
	for _, record := range terminal {
		delivered, err := s.reportTerminalResponseAction(rootCtx, record)
		if err != nil {
			return err
		}
		if !delivered {
			return nil
		}
	}

	accepted, err := s.responseJournal.Accepted(8)
	if err != nil {
		return err
	}
	for _, record := range accepted {
		if err := s.executeAcceptedResponseAction(rootCtx, record); err != nil {
			return err
		}
	}

	for i := 0; i < 8; i++ {
		staged, ok := s.responseStage.Next(time.Now().UTC(), s.cfg.AgentID)
		if !ok {
			return nil
		}
		record, err := s.responseJournal.Begin(staged.Action, time.Now().UTC())
		if errors.Is(err, responseactions.ErrJournalEntryExists) {
			s.responseStage.MarkHandled(staged.Action.ID)
			continue
		}
		if errors.Is(err, responseactions.ErrJournalCapacity) {
			agentcfg.LogJSON(agentcfg.LevelWarn, "response_action_journal_capacity", map[string]interface{}{
				"agent_id":  s.cfg.AgentID,
				"action_id": staged.Action.ID,
				"error":     err.Error(),
			})
			return nil
		}
		if err != nil {
			return err
		}
		s.responseStage.MarkHandled(staged.Action.ID)
		if err := s.executeAcceptedResponseAction(rootCtx, record); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) executeAcceptedResponseAction(rootCtx context.Context, record responseactions.JournalRecord) error {
	runningResult := protocol.ResponseActionExecutionResult{
		ResponseActionID: record.Action.ID,
		AgentID:          s.cfg.AgentID,
		Status:           "running",
		StartedAt:        timePointer(record.StartedAt),
	}
	ctx, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
	err := s.cp.ReportResponseActionResult(ctx, runningResult)
	cancel()
	if err != nil {
		s.recordResponseActionReportError(rootCtx, record.Action.ID, "running", err)
		return nil
	}
	if _, err := s.responseJournal.MarkExecuting(record.Action.ID, time.Now().UTC()); err != nil {
		return err
	}

	modules := map[string]interface{}{}
	for _, src := range s.cfg.Sources {
		modules[strings.TrimSpace(src)] = true
	}
	effectiveConfig := map[string]interface{}{}
	if s.runtimeConfig != nil {
		effectiveConfig = s.runtimeConfig.Raw()
	}
	state := s.stateSnapshot()
	execRes := responseactions.Execute(record.Action, responseactions.ExecuteOptions{
		ExpectedAgentID: s.cfg.AgentID,
		AgentID:         s.cfg.AgentID,
		Profile:         s.cfg.Profile,
		BuildVersion:    buildinfo.Release(),
		EffectiveConfig: effectiveConfig,
		ModuleStates:    modules,
		RefreshRuntimeConfig: func() (bool, int, string, error) {
			return s.refreshRuntimeConfig(rootCtx)
		},
		RunTopologyDiscovery: func() (map[string]interface{}, error) {
			return s.sources.RunTopologyDiscoveryNow(rootCtx)
		},
		AgentStartedAt:     state.StartedAt,
		Now:                record.StartedAt,
		FirewallTool:       s.firewallTool,
		QuarantineDir:      s.cfg.ResponseQuarantineDir,
		AllowShellExec:     s.cfg.AllowShellExec,
		ShellExecAllowlist: s.cfg.ShellExecAllowlist,
	})
	result := protocol.ResponseActionExecutionResult{
		ResponseActionID: record.Action.ID,
		AgentID:          s.cfg.AgentID,
		Status:           execRes.Status,
		ResultPayload:    execRes.Result,
		Error:            execRes.Error,
		StartedAt:        timePointer(execRes.StartedAt),
		FinishedAt:       timePointer(execRes.FinishedAt),
	}
	terminal, err := s.responseJournal.Complete(record.Action.ID, result, time.Now().UTC())
	if err != nil {
		return err
	}
	s.updateState(func(state *SummaryState) {
		state.ResponseActionsExecutedTotal++
	})
	_, err = s.reportTerminalResponseAction(rootCtx, terminal)
	return err
}

func (s *Service) reportTerminalResponseAction(rootCtx context.Context, record responseactions.JournalRecord) (bool, error) {
	if record.Result == nil {
		return false, fmt.Errorf("response action %d terminal journal entry has no result", record.Action.ID)
	}
	ctx, cancel := context.WithTimeout(rootCtx, s.cfg.HTTPTimeout)
	err := s.cp.ReportResponseActionResult(ctx, *record.Result)
	cancel()
	if err != nil {
		s.recordResponseActionReportError(rootCtx, record.Action.ID, record.Result.Status, err)
		return false, nil
	}
	if err := s.responseJournal.Delete(record.Action.ID); err != nil {
		return false, err
	}
	s.updateState(func(state *SummaryState) {
		state.ResponseActionResultsDeliveredTotal++
	})
	agentcfg.LogJSON(agentcfg.LevelInfo, "response_action_result_delivered", map[string]interface{}{
		"agent_id":  s.cfg.AgentID,
		"action_id": record.Action.ID,
		"type":      record.Action.ActionType,
		"status":    record.Result.Status,
	})
	return true, nil
}

func (s *Service) recordResponseActionReportError(rootCtx context.Context, actionID int64, status string, err error) {
	s.updateState(func(state *SummaryState) {
		state.ResponseActionReportErrorsTotal++
	})
	agentcfg.LogJSON(agentcfg.LevelWarn, "response_action_report_failed", map[string]interface{}{
		"agent_id":  s.cfg.AgentID,
		"action_id": actionID,
		"status":    status,
		"error":     err.Error(),
	})
	s.enrollment.MaybeRecoverIdentity(rootCtx, "response_action_report", err.Error(), 0)
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
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
		Send: func(ctx context.Context, hb protocol.HeartbeatRequest) error {
			_, err := s.cp.Heartbeat(ctx, hb)
			return err
		},
		OnError: func(err error) {
			agentcfg.LogJSON(agentcfg.LevelWarn, "controlplane_heartbeat_error", map[string]interface{}{
				"agent_id": s.cfg.AgentID,
				"error":    err.Error(),
			})
			var incompatible *protocol.Incompatibility
			if errors.As(err, &incompatible) {
				s.fail(incompatible)
				return
			}
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
					changed, applyErr := s.runtimeConfig.Apply(cfg)
					if applyErr != nil {
						agentcfg.LogJSON(agentcfg.LevelWarn, "controlplane_config_rejected", map[string]interface{}{
							"agent_id": s.cfg.AgentID,
							"error":    applyErr.Error(),
							"revision": s.runtimeConfig.Revision(),
						})
						continue
					}
					if changed {
						agentcfg.LogJSON(agentcfg.LevelInfo, "controlplane_config_applied", map[string]interface{}{
							"agent_id":    s.cfg.AgentID,
							"config_hash": s.runtimeConfig.Hash(),
							"config_keys": len(cfg),
							"revision":    s.runtimeConfig.Revision(),
						})
					}
				}
			}
		}
	}()

	s.startCertificateRotation(rootCtx)

	if protocol.ProfileAllowsResponseActions(s.cfg.Profile) {
		responseactions.StartPolling(rootCtx, responseactions.PollerConfig{
			AgentID: s.cfg.AgentID,
			Every:   s.cfg.ControlResponsePollEvery,
			Jitter:  s.cfg.ControlResponsePollJitter,
			Timeout: s.cfg.HTTPTimeout,
		}, responseactions.PollerDeps{
			Fetch: func(ctx context.Context) ([]protocol.ResponseAction, error) {
				return s.cp.ListPendingResponseActions(ctx)
			},
			Stage: s.stageResponseActions,
			OnError: func(err error) {
				s.updateState(func(state *SummaryState) {
					state.ResponseActionPollErrorsTotal++
				})
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
	}

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

func (s *Service) buildHeartbeatRequest() protocol.HeartbeatRequest {
	state := s.stateSnapshot()
	metrics := map[string]interface{}{
		"events_sent_total":      state.EventsSentTotal,
		"events_attempted_total": state.EventsAttemptedTotal,
		"events_durable_total":   state.EventsDurableTotal,
		"send_errors_total":      state.SendErrorsTotal,
		"last_http_status":       state.LastHTTPStatus,
		"last_error":             state.LastError,
		"send_attempts_total":    state.SendAttemptsTotal,
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
	if strings.TrimSpace(s.cfg.TLSCertFile) != "" {
		metrics["tls_client_cert_renewals_total"] = state.CertRenewalsTotal
		metrics["tls_client_cert_renew_errors_total"] = state.CertRenewErrorsTotal
		if state.CertLastRenewError != "" {
			metrics["tls_client_cert_last_renew_error"] = state.CertLastRenewError
		}
		if certStatus, err := certrenew.Inspect(s.cfg.TLSCertFile); err == nil {
			metrics["tls_client_cert_serial"] = certStatus.SerialHex
			metrics["tls_client_cert_not_after"] = certStatus.NotAfter.Format(time.RFC3339)
			metrics["tls_client_cert_seconds_remaining"] = int64(time.Until(certStatus.NotAfter).Seconds())
		}
	}
	if s.runtimeConfig != nil {
		metrics["config_hash"] = s.runtimeConfig.Hash()
	}
	metrics["response_actions_pending"] = s.pendingResponseActions()
	metrics["response_actions_poll_errors_total"] = state.ResponseActionPollErrorsTotal
	metrics["response_actions_executed_total"] = state.ResponseActionsExecutedTotal
	metrics["response_action_results_delivered_total"] = state.ResponseActionResultsDeliveredTotal
	metrics["response_action_report_errors_total"] = state.ResponseActionReportErrorsTotal

	spoolStats := s.sender.SpoolStats()
	metrics["spool_pending"] = spoolStats.Pending
	metrics["spool_bytes"] = spoolStats.Bytes
	metrics["spool_enqueued_total"] = spoolStats.EnqueuedTotal
	metrics["spool_delivered_total"] = spoolStats.DeliveredTotal
	metrics["spool_dropped_total"] = spoolStats.DroppedTotal
	metrics["spool_expired_total"] = spoolStats.ExpiredTotal
	metrics["spool_capacity_total"] = spoolStats.CapacityTotal
	metrics["spool_corrupt_total"] = spoolStats.CorruptTotal
	metrics["spool_permanent_total"] = spoolStats.PermanentTotal
	metrics["spool_retry_total"] = spoolStats.RetryTotal
	metrics["spool_enqueue_errors_total"] = spoolStats.EnqueueErrorsTotal
	if state.SpoolLastError != "" {
		metrics["spool_last_error"] = state.SpoolLastError
	}

	if s.sources != nil && s.runtimeConfig != nil && agentcfg.Contains(s.cfg.Sources, "syscollector") {
		sysCfg := s.runtimeConfig.Syscollector()
		status := s.sources.SyscollectorStatus()
		metrics["syscollector_enabled"] = sysCfg.Enabled
		metrics["syscollector_last_run_at"] = status.LastRunAt
		metrics["syscollector_last_sent_at"] = status.LastSentAt
		metrics["syscollector_last_error"] = status.LastError
		metrics["syscollector_last_hash"] = status.LastHash
		metrics["syscollector_last_packages_count"] = status.LastPkgCount
	}

	if s.sources != nil && s.runtimeConfig != nil {
		discCfg, discErr := s.runtimeConfig.TopologyDiscovery()
		discStatus := s.sources.TopologyDiscoveryStatus()
		metrics["topology_active_discovery_mode"] = "passive_only"
		metrics["topology_active_discovery_enabled"] = false
		if discErr != nil {
			metrics["topology_active_discovery_config_error"] = discErr.Error()
		} else {
			metrics["topology_active_discovery_mode"] = sources.TopologyDiscoveryMode(discCfg.Enabled)
			metrics["topology_active_discovery_enabled"] = discCfg.Enabled
			metrics["topology_active_discovery_allowed_cidrs"] = sources.TopologyDiscoveryCIDRs(discCfg, discStatus)
		}
		metrics["topology_active_discovery_last_run_at"] = discStatus.LastRunAt
		metrics["topology_active_discovery_last_sent_at"] = discStatus.LastSentAt
		metrics["topology_active_discovery_last_error"] = discStatus.LastError
		metrics["topology_active_discovery_last_warnings"] = discStatus.LastWarnings
		metrics["topology_active_discovery_last_warning_text"] = sources.TopologyDiscoveryWarningText(discStatus.LastWarnings)
		metrics["topology_active_discovery_last_discovered_hosts"] = discStatus.LastDiscoveredIPs
		metrics["topology_active_discovery_last_observed_hosts"] = discStatus.LastObservedIPs
		metrics["topology_active_discovery_last_target_count"] = discStatus.LastTargetCount
		metrics["topology_active_discovery_last_attempted_hosts"] = discStatus.LastAttemptedHosts
		metrics["topology_active_discovery_last_trigger"] = discStatus.LastTrigger
	}

	return protocol.HeartbeatRequest{
		Status:          "ok",
		UptimeSeconds:   int64(time.Since(state.StartedAt).Seconds()),
		AgentVersion:    buildinfo.Release(),
		ProtocolVersion: protocol.Version,
		Profile:         protocol.NormalizeProfile(s.cfg.Profile),
		Capabilities:    s.effectiveCapabilities(),
		Modules: map[string]interface{}{
			"sources": s.cfg.Sources,
		},
		Metrics: metrics,
	}
}

func (s *Service) effectiveCapabilities() map[string]interface{} {
	profile := protocol.NormalizeProfile(s.cfg.Profile)
	responseActionTypes := make([]string, 0)
	for _, actionType := range protocol.SupportedActions(profile) {
		switch actionType {
		case protocol.ActionRunShellCommand:
			if !s.cfg.AllowShellExec || len(s.cfg.ShellExecAllowlist) == 0 {
				continue
			}
		case protocol.ActionBlockOutboundIP, protocol.ActionUnblockOutboundIP:
			if strings.TrimSpace(s.firewallTool) == "" {
				continue
			}
		}
		responseActionTypes = append(responseActionTypes, actionType)
	}
	build := buildinfo.Summary()
	build["sources"] = s.cfg.Sources
	build["profile"] = profile
	build["response_actions"] = protocol.ProfileAllowsResponseActions(profile)
	build["response_action_types"] = responseActionTypes
	build["shell_exec"] = protocol.ProfileAllowsResponseActions(profile) &&
		s.cfg.AllowShellExec &&
		len(s.cfg.ShellExecAllowlist) > 0
	return build
}
