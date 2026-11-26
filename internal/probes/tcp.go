package probes

import (
	"context"
	"fmt"
	"net"
	"time"

	"meshwatch/internal/config"
)

// TCPProbe verifies basic TCP reachability to a host:port target.
type TCPProbe struct {
	id      string
	address string
}

// NewTCPProbe creates a TCPProbe from configuration.
func NewTCPProbe(cfg config.ProbeConfig) *TCPProbe {
	return &TCPProbe{
		id:      cfg.ID,
		address: cfg.TCPAddress(),
	}
}

func (p *TCPProbe) ID() string   { return p.id }
func (p *TCPProbe) Kind() string { return "tcp" }

func (p *TCPProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", p.address)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("TCP %s failed: %v", p.address, err),
			Latency: latency,
			Metrics: &ProbeMetrics{Target: p.address},
		}
	}
	_ = conn.Close()
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      true,
		Summary: fmt.Sprintf("TCP %s OK (%dms)", p.address, latency),
		Latency: latency,
		Metrics: &ProbeMetrics{Target: p.address},
	}
}
