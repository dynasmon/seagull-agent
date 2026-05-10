package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/agentauth"
)

type Client struct {
	baseURL        string
	http           *http.Client
	agentID        string
	credentialFunc func() string
}

func New(baseURL string, timeout time.Duration, agentID string, credentialFunc func() string, httpClient *http.Client) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	httpClient.Timeout = timeout
	return &Client{
		baseURL:        baseURL,
		http:           httpClient,
		agentID:        strings.TrimSpace(agentID),
		credentialFunc: credentialFunc,
	}
}

type EnrollRequest struct {
	AgentID        string `json:"agent_id"`
	Hostname       string `json:"hostname,omitempty"`
	OS             string `json:"os,omitempty"`
	Version        string `json:"version,omitempty"`
	BootstrapToken string `json:"-"`
}

type Credential struct {
	Credential            string `json:"credential"`
	ExpiresAt             string `json:"expires_at"`
	MaxUses               int    `json:"max_uses"`
	UsedUses              int    `json:"used_uses"`
	RenewalToken          string `json:"renewal_token"`
	RenewalTokenExpiresAt string `json:"renewal_token_expires_at"`
}

type EnrollResponse struct {
	AgentID    string                 `json:"agent_id"`
	Config     map[string]interface{} `json:"config"`
	Credential Credential             `json:"credential"`
}

func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	if c.baseURL == "" {
		return out, fmt.Errorf("controlplane baseURL is empty")
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return out, fmt.Errorf("marshal enroll request: %w", err)
	}

	u := c.baseURL + "/agents/enroll"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return out, fmt.Errorf("new enroll request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(agentauth.HeaderAgentID, strings.TrimSpace(req.AgentID))
	if bootstrapToken := strings.TrimSpace(req.BootstrapToken); bootstrapToken != "" {
		httpReq.Header.Set(agentauth.HeaderBootstrapToken, bootstrapToken)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("enroll failed status=%d body=%s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal enroll response: %w", err)
	}

	return out, nil
}

type HeartbeatRequest struct {
	Status        string                 `json:"status"`
	UptimeSeconds int64                  `json:"uptime_seconds,omitempty"`
	Modules       map[string]interface{} `json:"modules,omitempty"`
	Metrics       map[string]interface{} `json:"metrics,omitempty"`
}

func (c *Client) Heartbeat(ctx context.Context, hb HeartbeatRequest) error {
	if c.baseURL == "" {
		return fmt.Errorf("controlplane baseURL is empty")
	}

	payload, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	u := c.baseURL + "/agents/heartbeat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("new heartbeat request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	agentauth.ApplyCredentialHeaders(httpReq, c.agentID, c.credentialFunc)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("heartbeat request: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat failed status=%d", resp.StatusCode)
	}
	return nil
}

func (c *Client) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("controlplane baseURL is empty")
	}

	u := c.baseURL + "/agents/config"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("new config request: %w", err)
	}
	agentauth.ApplyCredentialHeaders(httpReq, c.agentID, c.credentialFunc)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("config request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("config failed status=%d body=%s", resp.StatusCode, string(body))
	}

	var out map[string]interface{}
	if len(body) == 0 {
		return map[string]interface{}{}, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out, nil
}

func (c *Client) RotateCredential(ctx context.Context) (Credential, error) {
	var out Credential
	if c.baseURL == "" {
		return out, fmt.Errorf("controlplane baseURL is empty")
	}

	u := c.baseURL + "/agents/credential/rotate"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return out, fmt.Errorf("new rotate request: %w", err)
	}
	agentauth.ApplyCredentialHeaders(httpReq, c.agentID, c.credentialFunc)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("rotate credential request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("rotate credential failed status=%d body=%s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal rotate response: %w", err)
	}
	return out, nil
}

var ErrInvalidResponseAction = errors.New("invalid response action")

type ResponseAction struct {
	ID          int64           `json:"id"`
	ActionType  string          `json:"action_type"`
	AgentID     string          `json:"agent_id"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	RequestedAt time.Time       `json:"requested_at"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

type responseActionListEnvelope struct {
	Items   []ResponseAction `json:"items"`
	Actions []ResponseAction `json:"actions"`
}

type ResponseActionExecutionResult struct {
	ResponseActionID int64                  `json:"response_action_id"`
	AgentID          string                 `json:"agent_id,omitempty"`
	Status           string                 `json:"status"`
	ResultPayload    map[string]interface{} `json:"result_payload,omitempty"`
	Error            string                 `json:"error,omitempty"`
	StartedAt        *time.Time             `json:"started_at,omitempty"`
	FinishedAt       *time.Time             `json:"finished_at,omitempty"`
}

func (c *Client) ListPendingResponseActions(ctx context.Context) ([]ResponseAction, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("controlplane baseURL is empty")
	}
	paths := []string{
		"/agents/response-actions/pending",
		"/agents/response/actions/pending",
	}

	var lastErr error
	for _, path := range paths {
		out, err := c.listPendingResponseActionsPath(ctx, path)
		if err == nil {
			return out, nil
		}
		if strings.Contains(err.Error(), "status=404") {
			lastErr = err
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return []ResponseAction{}, nil
}

func (c *Client) listPendingResponseActionsPath(ctx context.Context, path string) ([]ResponseAction, error) {
	u := c.baseURL + path
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("new response actions request: %w", err)
	}
	agentauth.ApplyCredentialHeaders(httpReq, c.agentID, c.credentialFunc)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("response actions request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNoContent {
		return []ResponseAction{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("response actions failed status=%d body=%s", resp.StatusCode, string(body))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return []ResponseAction{}, nil
	}

	actions, err := decodeResponseActions(body)
	if err != nil {
		return nil, err
	}
	for i := range actions {
		if err := normalizeResponseAction(&actions[i]); err != nil {
			return nil, fmt.Errorf("decode response action: %w", err)
		}
	}
	return actions, nil
}

func decodeResponseActions(body []byte) ([]ResponseAction, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return []ResponseAction{}, nil
	}

	if trimmed[0] == '[' {
		var out []ResponseAction
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("unmarshal response actions array: %w", err)
		}
		if out == nil {
			out = []ResponseAction{}
		}
		return out, nil
	}

	var env responseActionListEnvelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, fmt.Errorf("unmarshal response actions envelope: %w", err)
	}
	if env.Items != nil {
		return env.Items, nil
	}
	if env.Actions != nil {
		return env.Actions, nil
	}
	return []ResponseAction{}, nil
}

func normalizeResponseAction(a *ResponseAction) error {
	if a == nil {
		return fmt.Errorf("%w: nil action", ErrInvalidResponseAction)
	}
	a.ActionType = strings.ToLower(strings.TrimSpace(a.ActionType))
	a.AgentID = strings.TrimSpace(a.AgentID)
	a.Status = strings.ToLower(strings.TrimSpace(a.Status))

	if a.ID <= 0 {
		return fmt.Errorf("%w: invalid id", ErrInvalidResponseAction)
	}
	if a.ActionType == "" {
		return fmt.Errorf("%w: empty action_type", ErrInvalidResponseAction)
	}
	if a.AgentID == "" {
		return fmt.Errorf("%w: empty agent_id", ErrInvalidResponseAction)
	}
	if a.Status == "" {
		return fmt.Errorf("%w: empty status", ErrInvalidResponseAction)
	}
	if a.RequestedAt.IsZero() {
		return fmt.Errorf("%w: empty requested_at", ErrInvalidResponseAction)
	}
	if len(bytes.TrimSpace(a.Payload)) == 0 {
		a.Payload = json.RawMessage(`{}`)
	}
	return nil
}

func (c *Client) ReportResponseActionResult(ctx context.Context, in ResponseActionExecutionResult) error {
	if c.baseURL == "" {
		return fmt.Errorf("controlplane baseURL is empty")
	}
	if in.ResponseActionID <= 0 {
		return fmt.Errorf("invalid response_action_id")
	}
	in.Status = strings.ToLower(strings.TrimSpace(in.Status))
	if in.Status == "" {
		return fmt.Errorf("status is required")
	}

	payload, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal response action result: %w", err)
	}

	paths := []string{
		"/agents/response-actions/results",
		"/agents/response/actions/results",
	}
	var lastErr error
	for _, path := range paths {
		u := c.baseURL + path
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("new response action result request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		agentauth.ApplyCredentialHeaders(httpReq, c.agentID, c.credentialFunc)

		resp, err := c.http.Do(httpReq)
		if err != nil {
			return fmt.Errorf("response action result request: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		err = fmt.Errorf("response action result failed status=%d body=%s", resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusNotFound {
			lastErr = err
			continue
		}
		return err
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("response action result failed")
}
