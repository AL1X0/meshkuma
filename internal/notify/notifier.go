package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshwatch/internal/config"
)

// DefaultRetryBackoffs matches the spec's 3-retry exponential backoff (2s, 5s, 10s).
var DefaultRetryBackoffs = []time.Duration{
	2 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

// AlertState represents whether an alert is firing (DOWN) or recovered (RESOLVED).
type AlertState string

const (
	StateDown     AlertState = "DOWN"
	StateResolved AlertState = "RESOLVED"
)

// Alert contains structured details for an outbound MeshWatch alert.
type Alert struct {
	IncidentID   string
	State        AlertState
	NodeName     string
	TargetPubKey string
	ProbeID      string
	Reason       string
	Summary      string
	Timestamp    time.Time
	ReportedBy   string
}

// Title returns a concise human-readable alert title.
func (a Alert) Title() string {
	prefix := "DOWN"
	if a.State == StateResolved {
		prefix = "RESOLVED"
	}
	if a.ProbeID != "" {
		return fmt.Sprintf("[MeshWatch %s] %s / %s", prefix, a.NodeName, a.ProbeID)
	}
	return fmt.Sprintf("[MeshWatch %s] %s", prefix, a.NodeName)
}

// Body returns a readable multi-line alert message including node, probe, summary, and timestamp.
func (a Alert) Body() string {
	ts := a.Timestamp.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	probeLine := "all (peer unreachable)"
	if a.ProbeID != "" {
		probeLine = a.ProbeID
	}
	reporter := a.ReportedBy
	if reporter == "" {
		reporter = "meshwatch"
	}
	return fmt.Sprintf(
		"State: %s\nNode: %s\nProbe: %s\nSummary: %s\nReason: %s\nTime: %s\nReported by: %s",
		a.State,
		a.NodeName,
		probeLine,
		a.Summary,
		a.Reason,
		ts.Format(time.RFC3339),
		reporter,
	)
}

// Notifier sends an Alert to a downstream notification service.
type Notifier interface {
	Name() string
	Send(ctx context.Context, alert Alert) error
}

// MultiNotifier dispatches alerts to all configured notifiers and collects any errors.
type MultiNotifier struct {
	notifiers []Notifier
}

// NewMultiNotifier creates a MultiNotifier wrapping zero or more Notifiers.
func NewMultiNotifier(notifiers ...Notifier) *MultiNotifier {
	filtered := make([]Notifier, 0, len(notifiers))
	for _, n := range notifiers {
		if n != nil {
			filtered = append(filtered, n)
		}
	}
	return &MultiNotifier{notifiers: filtered}
}

// BuildFromConfig builds a MultiNotifier containing every enabled channel from configuration.
func BuildFromConfig(cfg config.NotificationsConfig) *MultiNotifier {
	var list []Notifier
	if cfg.Ntfy.Enabled {
		list = append(list, NewNtfyNotifier(cfg.Ntfy))
	}
	if cfg.PhotonIMessage.Enabled {
		list = append(list, NewPhotonNotifier(cfg.PhotonIMessage))
	}
	return NewMultiNotifier(list...)
}

func (m *MultiNotifier) Name() string { return "multi" }

func (m *MultiNotifier) Count() int { return len(m.notifiers) }

// Notifiers returns a shallow copy of the enabled notifiers.
func (m *MultiNotifier) Notifiers() []Notifier {
	out := make([]Notifier, len(m.notifiers))
	copy(out, m.notifiers)
	return out
}

func (m *MultiNotifier) Send(ctx context.Context, alert Alert) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Send(ctx, alert); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func retryWithBackoff(ctx context.Context, backoffs []time.Duration, fn func(attempt int) (retryable bool, err error)) error {
	var lastErr error
	for attempt := 0; attempt <= len(backoffs); attempt++ {
		if attempt > 0 {
			delay := backoffs[attempt-1]
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		retryable, err := fn(attempt)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable {
			return err
		}
	}
	return lastErr
}

func isRetryableStatus(statusCode int) bool {
	return statusCode >= 500 || statusCode == 429 || statusCode == 408
}
