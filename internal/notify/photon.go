package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"meshwatch/internal/config"
)

// PhotonNotifier sends MeshWatch alerts through a Photon iMessage HTTP gateway
// with 3 exponential backoff retries (2s, 5s, 10s) on network/timeout/5xx errors.
type PhotonNotifier struct {
	endpoint       string
	token          string
	recipient      string
	recipientField string
	messageField   string
	client         *http.Client
	backoffs       []time.Duration
}

// NewPhotonNotifier constructs a PhotonNotifier from configuration.
func NewPhotonNotifier(cfg config.PhotonConfig) *PhotonNotifier {
	recField := strings.TrimSpace(cfg.RecipientField)
	if recField == "" {
		recField = "recipient"
	}
	msgField := strings.TrimSpace(cfg.MessageField)
	if msgField == "" {
		msgField = "message"
	}
	return &PhotonNotifier{
		endpoint:       strings.TrimSpace(cfg.URL),
		token:          strings.TrimSpace(cfg.Token),
		recipient:      strings.TrimSpace(cfg.Recipient),
		recipientField: recField,
		messageField:   msgField,
		client: &http.Client{
			Timeout:   defaultNotifyHTTPTimeout,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		backoffs: append([]time.Duration(nil), DefaultRetryBackoffs...),
	}
}

func (p *PhotonNotifier) Name() string { return "photon_imessage" }

func (p *PhotonNotifier) Send(ctx context.Context, alert Alert) error {
	payload := map[string]string{
		p.recipientField: p.recipient,
		p.messageField:   alert.Title() + "\n" + alert.Body(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal photon payload: %w", err)
	}

	return retryWithBackoff(ctx, p.backoffs, func(_ int) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(raw))
		if err != nil {
			return false, fmt.Errorf("create photon request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "MeshWatch/1.0")
		if p.token != "" {
			req.Header.Set("Authorization", "Bearer "+p.token)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			return ctx.Err() == nil, fmt.Errorf("photon POST failed: %w", err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return false, nil
		}
		return isRetryableStatus(resp.StatusCode), fmt.Errorf("photon returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	})
}
