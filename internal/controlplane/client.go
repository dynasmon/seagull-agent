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
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: timeout},
	}
}

func (c *Client) SetToken(token string) {
	c.token = strings.TrimSpace(token)
}

type EnrollRequest struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Version  string `json:"version,omitempty"`
	Token    string `json:"-"`
}

type EnrollResponse struct {
	AgentID    string                 `json:"agent_id"`
	AgentToken string                 `json:"agent_token"`
	Config     map[string]interface{} `json:"config"`
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
	if token := strings.TrimSpace(req.Token); token != "" {
		httpReq.Header.Set("X-Enroll-Token", token)
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

	if out.AgentToken == "" {
		return out, fmt.Errorf("enroll returned empty agent_token")
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
	if c.token == "" {
		return fmt.Errorf("controlplane token is empty")
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
	httpReq.Header.Set("Authorization", "Bearer "+c.token)

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
	if c.token == "" {
		return nil, fmt.Errorf("controlplane token is empty")
	}

	u := c.baseURL + "/agents/config"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("new config request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)

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
