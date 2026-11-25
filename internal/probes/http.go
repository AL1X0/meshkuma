package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"meshwatch/internal/config"
)

const maxHTTPProbeBodyBytes = 1 << 20 // 1 MiB cap to keep RAM minimal

// HTTPProbe verifies HTTP status code, optional keyword match, latency, and TLS cert expiry.
type HTTPProbe struct {
	id                 string
	url                string
	expectedStatus     int
	contains           string
	tlsMinDays         int
	insecureSkipVerify bool
	client             *http.Client
	now                func() time.Time
}

// NewHTTPProbe creates an HTTPProbe from configuration.
func NewHTTPProbe(cfg config.ProbeConfig) *HTTPProbe {
	expected := cfg.ExpectedStatus
	if expected == 0 {
		expected = config.DefaultHTTPStatus
	}
	tlsMinDays := config.DefaultTLSMinDays
	if cfg.TLSMinDays != nil {
		tlsMinDays = *cfg.TLSMinDays
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // user-configurable for local self-signed LAN services
		},
		DisableKeepAlives: true,
	}

	return &HTTPProbe{
		id:                 cfg.ID,
		url:                cfg.URL,
		expectedStatus:     expected,
		contains:           cfg.Contains,
		tlsMinDays:         tlsMinDays,
		insecureSkipVerify: cfg.InsecureSkipVerify,
		client:             &http.Client{Transport: tr},
		now:                time.Now,
	}
}

func (p *HTTPProbe) ID() string   { return p.id }
func (p *HTTPProbe) Kind() string { return "http" }

func (p *HTTPProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("invalid HTTP request: %v", err),
		}
	}
	req.Header.Set("User-Agent", "MeshWatch/1.0")

	resp, err := p.client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("HTTP request failed: %v", err),
			Latency: latency,
		}
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPProbeBodyBytes))
	if readErr != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("HTTP %d read body error: %v", resp.StatusCode, readErr),
			Latency: latency,
		}
	}

	var issues []string
	if resp.StatusCode != p.expectedStatus {
		issues = append(issues, fmt.Sprintf("status %d (expected %d)", resp.StatusCode, p.expectedStatus))
	}

	if p.contains != "" && !strings.Contains(string(body), p.contains) {
		issues = append(issues, fmt.Sprintf("body missing %q", p.contains))
	}

	tlsNote := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		remaining := leaf.NotAfter.Sub(p.now())
		daysLeft := int(remaining.Hours() / 24)
		tlsNote = fmt.Sprintf(", TLS %dd", daysLeft)
		if p.tlsMinDays > 0 {
			if remaining <= 0 {
				issues = append(issues, fmt.Sprintf("TLS certificate expired (%s)", leaf.NotAfter.Format(time.RFC3339)))
			} else if daysLeft < p.tlsMinDays {
				issues = append(issues, fmt.Sprintf("TLS cert expires in %dd (< %dd)", daysLeft, p.tlsMinDays))
			}
		}
	}

	if len(issues) > 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: strings.Join(issues, "; "),
			Latency: latency,
		}
	}

	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      true,
		Summary: fmt.Sprintf("HTTP %d (%dms%s)", resp.StatusCode, latency, tlsNote),
		Latency: latency,
	}
}
