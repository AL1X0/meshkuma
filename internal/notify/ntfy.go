package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"meshwatch/internal/config"
)

const defaultNotifyHTTPTimeout = 10 * time.Second

// NtfyNotifier sends MeshWatch alerts to an ntfy server via HTTP POST.
type NtfyNotifier struct {
	endpoint string
	token    string
	client   *http.Client
	backoffs []time.Duration
}

// NewNtfyNotifier constructs an NtfyNotifier from configuration.
func NewNtfyNotifier(cfg config.NtfyConfig) *NtfyNotifier {
	endpoint := strings.TrimSpace(cfg.URL)
	if topic := strings.TrimSpace(cfg.Topic); topic != "" {
		endpoint = strings.TrimRight(endpoint, "/") + "/" + strings.TrimLeft(topic, "/")
	}
	return &NtfyNotifier{
		endpoint: endpoint,
		token:    strings.TrimSpace(cfg.Token),
		client: &http.Client{
			Timeout:   defaultNotifyHTTPTimeout,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		backoffs: append([]time.Duration(nil), DefaultRetryBackoffs...),
	}
}

func (n *NtfyNotifier) Name() string { return "ntfy" }

func (n *NtfyNotifier) Send(ctx context.Context, alert Alert) error {
	priority := "urgent"
	tags := "rotating_light"
	if alert.State == StateResolved {
		priority = "default"
		tags = "white_check_mark"
	}

	title := alert.Title()
	body := alert.Body()

	return retryWithBackoff(ctx, n.backoffs, func(_ int) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, strings.NewReader(body))
		if err != nil {
			return false, fmt.Errorf("create ntfy request: %w", err)
		}
		req.Header.Set("Title", title)
		req.Header.Set("Priority", priority)
		req.Header.Set("Tags", tags)
		req.Header.Set("User-Agent", "MeshWatch/1.0")
		if n.token != "" {
			req.Header.Set("Authorization", "Bearer "+n.token)
		}

		resp, err := n.client.Do(req)
		if err != nil {
			return ctx.Err() == nil, fmt.Errorf("ntfy POST failed: %w", err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return false, nil
		}
		return isRetryableStatus(resp.StatusCode), fmt.Errorf("ntfy returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	})
}
