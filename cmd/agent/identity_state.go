package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type PersistedIdentityState struct {
	AgentID                       string `json:"agent_id,omitempty"`
	Credential                    string `json:"credential,omitempty"`
	CredentialExpiresAt           string `json:"credential_expires_at,omitempty"`
	RenewalToken                  string `json:"renewal_token,omitempty"`
	RenewalTokenExpiresAt         string `json:"renewal_token_expires_at,omitempty"`
	PreviousRenewalToken          string `json:"previous_renewal_token,omitempty"`
	PreviousRenewalTokenExpiresAt string `json:"previous_renewal_token_expires_at,omitempty"`
	LastRecoveryMethod            string `json:"last_recovery_method,omitempty"`
	UpdatedAt                     string `json:"updated_at,omitempty"`
}

func loadIdentityState(path string, agentID string) (PersistedIdentityState, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return PersistedIdentityState{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return PersistedIdentityState{}, nil
		}
		return PersistedIdentityState{}, fmt.Errorf("read identity state: %w", err)
	}

	var state PersistedIdentityState
	if err := json.Unmarshal(data, &state); err != nil {
		return PersistedIdentityState{}, fmt.Errorf("parse identity state: %w", err)
	}

	state.AgentID = strings.TrimSpace(state.AgentID)
	if state.AgentID != "" && strings.TrimSpace(agentID) != "" && state.AgentID != strings.TrimSpace(agentID) {
		return PersistedIdentityState{}, fmt.Errorf("identity state agent_id mismatch: %s", state.AgentID)
	}
	if state.AgentID == "" {
		state.AgentID = strings.TrimSpace(agentID)
	}
	state.Credential = strings.TrimSpace(state.Credential)
	state.CredentialExpiresAt = strings.TrimSpace(state.CredentialExpiresAt)
	state.RenewalToken = strings.TrimSpace(state.RenewalToken)
	state.RenewalTokenExpiresAt = strings.TrimSpace(state.RenewalTokenExpiresAt)
	state.PreviousRenewalToken = strings.TrimSpace(state.PreviousRenewalToken)
	state.PreviousRenewalTokenExpiresAt = strings.TrimSpace(state.PreviousRenewalTokenExpiresAt)
	state.LastRecoveryMethod = strings.TrimSpace(state.LastRecoveryMethod)
	state.UpdatedAt = strings.TrimSpace(state.UpdatedAt)
	return state, nil
}

func saveIdentityState(path string, state PersistedIdentityState) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	state.AgentID = strings.TrimSpace(state.AgentID)
	state.Credential = strings.TrimSpace(state.Credential)
	state.CredentialExpiresAt = strings.TrimSpace(state.CredentialExpiresAt)
	state.RenewalToken = strings.TrimSpace(state.RenewalToken)
	state.RenewalTokenExpiresAt = strings.TrimSpace(state.RenewalTokenExpiresAt)
	state.PreviousRenewalToken = strings.TrimSpace(state.PreviousRenewalToken)
	state.PreviousRenewalTokenExpiresAt = strings.TrimSpace(state.PreviousRenewalTokenExpiresAt)
	state.LastRecoveryMethod = strings.TrimSpace(state.LastRecoveryMethod)
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal identity state: %w", err)
	}
	return atomicWriteFile(path, append(payload, '\n'), 0o600)
}

func parseOptionalRFC3339(raw string) time.Time {
	text := strings.TrimSpace(raw)
	if text == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}
	}
	return ts.UTC()
}

func formatOptionalTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}
