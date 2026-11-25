package kuma

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshwatch/internal/transport"
)

const (
	defaultPushTimeout = 5 * time.Second
	maxMsgRunes        = 250
)

// Pusher bridges validated Nostr peer heartbeats to a local Uptime Kuma Push monitor.
// When a peer stops emitting heartbeats, MeshWatch stops pushing, letting Uptime Kuma's
// Dead Man's Switch mark the monitor DOWN automatically.
type Pusher struct {
	client *http.Client
}

// NewPusher creates a lightweight HTTP Push client for Uptime Kuma.
func NewPusher(timeout time.Duration) *Pusher {
	if timeout <= 0 {
		timeout = defaultPushTimeout
	}
	return &Pusher{
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
	}
}

// Push sends GET <pushURL>?status=<up|down>&msg=<summary>&ping=<ms> to Uptime Kuma.
func (p *Pusher) Push(ctx context.Context, pushURL string, hb *transport.HeartbeatPayload, pingMs int64) error {
	if strings.TrimSpace(pushURL) == "" || hb == nil {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(pushURL))
	if err != nil {
		return fmt.Errorf("parse kuma_push_url: %w", err)
	}

	status := "up"
	if !hb.OverallOK {
		status = "down"
	}
	if pingMs < 0 {
		pingMs = 0
	}

	q := u.Query()
	q.Set("status", status)
	q.Set("msg", formatHeartbeatMsg(hb))
	q.Set("ping", strconv.FormatInt(pingMs, 10))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create kuma push request: %w", err)
	}
	req.Header.Set("User-Agent", "MeshWatch/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("kuma push request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kuma push returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func formatHeartbeatMsg(hb *transport.HeartbeatPayload) string {
	if hb.OverallOK {
		if len(hb.Probes) == 0 {
			return "OK"
		}
		return fmt.Sprintf("OK (%d/%d probes)", len(hb.Probes), len(hb.Probes))
	}

	var failed []string
	for _, pr := range hb.Probes {
		if !pr.OK {
			detail := strings.TrimSpace(pr.Summary)
			if detail == "" {
				detail = "failed"
			}
			failed = append(failed, fmt.Sprintf("%s: %s", pr.ID, detail))
		}
	}
	if len(failed) == 0 {
		return "probe check failed"
	}
	msg := strings.Join(failed, "; ")
	runes := []rune(msg)
	if len(runes) > maxMsgRunes {
		return string(runes[:maxMsgRunes-3]) + "..."
	}
	return msg
}
