package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type Client struct {
	baseURL string
	httpc   *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL: baseURL,
		httpc: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) SendEvents(ctx context.Context, events []model.NetEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	body, err := json.Marshal(events)
	if err != nil {
		return 0, fmt.Errorf("marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/ingest/events", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post ingest: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}
