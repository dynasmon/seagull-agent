package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	Credential string `json:"credential"`
	ExpiresAt  string `json:"expires_at"`
	MaxUses    int    `json:"max_uses"`
	UsedUses   int    `json:"used_uses"`
}

type EnrollResponse struct {
	AgentID    string                 `json:"agent_id"`
	Config     map[string]interface{} `json:"config"`
	Credential Credential             `json:"credential"`
}

func (c *Client) applyAuthHeaders(req *http.Request) {
	if c.agentID != "" {
		req.Header.Set("X-Agent-ID", c.agentID)
	}
	if c.credentialFunc == nil {
		return
	}
	if cred := strings.TrimSpace(c.credentialFunc()); cred != "" {
		req.Header.Set("X-Agent-Credential", cred)
	}
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
	httpReq.Header.Set("X-Agent-ID", strings.TrimSpace(req.AgentID))
	if bootstrapToken := strings.TrimSpace(req.BootstrapToken); bootstrapToken != "" {
		httpReq.Header.Set("X-Agent-Bootstrap-Token", bootstrapToken)
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
	c.applyAuthHeaders(httpReq)

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
	c.applyAuthHeaders(httpReq)

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
	c.applyAuthHeaders(httpReq)

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
