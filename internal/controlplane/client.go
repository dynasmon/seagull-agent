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

	"github.com/dynasmon/seagull-agent/internal/agentauth"
	"github.com/dynasmon/seagull-agent/protocol"
)

var (
	responseActionListPaths = []string{
		"/agents/response-actions/pending",
		"/agents/response/actions/pending",
	}
	responseActionResultPaths = []string{
		"/agents/response-actions/results",
		"/agents/response/actions/results",
	}
)

const (
	maxResponseBytes  = 4 << 20
	maxErrorBodyBytes = 4 << 10
)

type HTTPError struct {
	Operation  string
	StatusCode int
	Body       string
}

func responseExcerpt(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	truncated := len(trimmed) > maxErrorBodyBytes
	if truncated {
		trimmed = trimmed[:maxErrorBodyBytes]
	}
	value := strings.ToValidUTF8(string(trimmed), "\uFFFD")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		value = "<empty>"
	}
	if truncated {
		value += " [truncated]"
	}
	return value
}

func newHTTPError(operation string, statusCode int, body []byte) *HTTPError {
	return &HTTPError{
		Operation:  operation,
		StatusCode: statusCode,
		Body:       responseExcerpt(body),
	}
}

func (e *HTTPError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s failed status=%d body=%s", e.Operation, e.StatusCode, e.Body)
}

type Client struct {
	baseURL        string
	enrollBaseURL  string
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

func (c *Client) SetEnrollBaseURL(url string) {
	c.enrollBaseURL = strings.TrimRight(strings.TrimSpace(url), "/")
}

func (c *Client) do(ctx context.Context, method, path, name string, body []byte) (int, []byte, error) {
	if c.baseURL == "" {
		return 0, nil, fmt.Errorf("controlplane baseURL is empty")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("new %s request: %w", name, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	agentauth.ApplyCredentialHeaders(req, c.agentID, c.credentialFunc)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s request: %w", name, err)
	}
	defer resp.Body.Close()

	respBody, err := readResponse(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s response: %w", name, err)
	}
	return resp.StatusCode, respBody, nil
}

func (c *Client) enrollEndpoint() string {
	if c.enrollBaseURL != "" {
		return c.enrollBaseURL + "/enroll"
	}
	if c.baseURL != "" {
		return c.baseURL + "/agents/enroll"
	}
	return ""
}

func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	u := c.enrollEndpoint()
	if u == "" {
		return out, fmt.Errorf("controlplane baseURL is empty")
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return out, fmt.Errorf("marshal enroll request: %w", err)
	}
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

	body, err := readResponse(resp.Body)
	if err != nil {
		return out, fmt.Errorf("enroll response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if incompatible, ok := protocol.DecodeIncompatibility(resp.StatusCode, body); ok {
			return out, incompatible
		}
		return out, newHTTPError("enroll", resp.StatusCode, body)
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal enroll response: %w", err)
	}

	return out, nil
}

func readResponse(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxResponseBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxResponseBytes)
	}
	return payload, nil
}

func (c *Client) Heartbeat(ctx context.Context, hb protocol.HeartbeatRequest) (protocol.Negotiation, error) {
	payload, err := json.Marshal(hb)
	if err != nil {
		return protocol.Negotiation{}, fmt.Errorf("marshal heartbeat: %w", err)
	}
	status, body, err := c.do(ctx, http.MethodPost, "/agents/heartbeat", "heartbeat", payload)
	if err != nil {
		return protocol.Negotiation{}, err
	}
	if status < 200 || status >= 300 {
		if incompatible, ok := protocol.DecodeIncompatibility(status, body); ok {
			return protocol.Negotiation{}, incompatible
		}
		return protocol.Negotiation{}, newHTTPError("heartbeat", status, body)
	}

	if len(bytes.TrimSpace(body)) == 0 {
		negotiated, incompatible := protocol.Negotiate(nil)
		if incompatible != nil {
			return protocol.Negotiation{}, incompatible
		}
		return negotiated, nil
	}

	var descriptor protocol.Descriptor
	if err := json.Unmarshal(body, &descriptor); err != nil || descriptor.ProtocolVersion <= 0 {
		negotiated, incompatible := protocol.Negotiate(nil)
		if incompatible != nil {
			return protocol.Negotiation{}, incompatible
		}
		return negotiated, nil
	}

	negotiated, incompatible := protocol.Negotiate(&descriptor)
	if incompatible != nil {
		return protocol.Negotiation{}, incompatible
	}
	return negotiated, nil
}

func (c *Client) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/agents/config", "config", nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, newHTTPError("config", status, body)
	}
	if len(body) == 0 {
		return map[string]interface{}{}, nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out, nil
}

func (c *Client) RotateCredential(ctx context.Context) (protocol.Credential, error) {
	var out protocol.Credential
	status, body, err := c.do(ctx, http.MethodPost, "/agents/credential/rotate", "rotate credential", nil)
	if err != nil {
		return out, err
	}
	if status < 200 || status >= 300 {
		return out, newHTTPError("rotate credential", status, body)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal rotate response: %w", err)
	}
	return out, nil
}

func (c *Client) RenewCertificate(ctx context.Context, csrPEM string) (protocol.CertificateRenewal, error) {
	var out protocol.CertificateRenewal
	payload, err := json.Marshal(protocol.CertificateRenewRequest{CSRPEM: csrPEM})
	if err != nil {
		return out, fmt.Errorf("marshal certificate renew request: %w", err)
	}
	status, body, err := c.do(ctx, http.MethodPost, "/agents/certificate/renew", "certificate renew", payload)
	if err != nil {
		return out, err
	}
	if status < 200 || status >= 300 {
		return out, newHTTPError("certificate renew", status, body)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal certificate renew response: %w", err)
	}
	if strings.TrimSpace(out.CertificatePEM) == "" {
		return out, fmt.Errorf("certificate renew response missing certificate")
	}
	return out, nil
}

func (c *Client) ListPendingResponseActions(ctx context.Context) ([]protocol.ResponseAction, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("controlplane baseURL is empty")
	}

	var lastErr error
	for _, path := range responseActionListPaths {
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
	return []protocol.ResponseAction{}, nil
}

func (c *Client) listPendingResponseActionsPath(ctx context.Context, path string) ([]protocol.ResponseAction, error) {
	status, body, err := c.do(ctx, http.MethodGet, path, "response actions", nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return []protocol.ResponseAction{}, nil
	}
	if status < 200 || status >= 300 {
		return nil, newHTTPError("response actions", status, body)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return []protocol.ResponseAction{}, nil
	}

	actions, err := decodeResponseActions(body)
	if err != nil {
		return nil, err
	}
	for i := range actions {
		if err := actions[i].Normalize(); err != nil {
			return nil, fmt.Errorf("decode response action: %w", err)
		}
	}
	return actions, nil
}

func decodeResponseActions(body []byte) ([]protocol.ResponseAction, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return []protocol.ResponseAction{}, nil
	}

	if trimmed[0] == '[' {
		var out []protocol.ResponseAction
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("unmarshal response actions array: %w", err)
		}
		if out == nil {
			out = []protocol.ResponseAction{}
		}
		return out, nil
	}

	var env protocol.ResponseActionList
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, fmt.Errorf("unmarshal response actions envelope: %w", err)
	}
	if env.Items != nil {
		return env.Items, nil
	}
	if env.Actions != nil {
		return env.Actions, nil
	}
	return []protocol.ResponseAction{}, nil
}

func (c *Client) ReportResponseActionResult(ctx context.Context, in protocol.ResponseActionExecutionResult) error {
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

	var lastErr error
	for _, path := range responseActionResultPaths {
		status, body, err := c.do(ctx, http.MethodPost, path, "response action result", payload)
		if err != nil {
			return err
		}
		if status >= 200 && status < 300 {
			return nil
		}
		err = newHTTPError("response action result", status, body)
		if status == http.StatusNotFound {
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
