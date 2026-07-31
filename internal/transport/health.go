package transport

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func WaitForHealth(ctx context.Context, baseURL string, httpClient *http.Client) error {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/health"

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("health check timeout: %w", ctx.Err())
		case <-t.C:
		}
	}
}
