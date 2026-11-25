package probes

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"meshwatch/internal/config"
)

// ProbeResult represents the outcome of a single local probe execution.
type ProbeResult struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	OK      bool   `json:"ok"`
	Summary string `json:"summary"`
	Latency int64  `json:"latency_ms,omitempty"`
}

// HistoryPoint records one check sample for the built-in availability history bar.
type HistoryPoint struct {
	TS        int64 `json:"ts"`
	OK        bool  `json:"ok"`
	LatencyMs int64 `json:"latency_ms,omitempty"`
}

// IncidentEvent records a state transition (outage or recovery) for the built-in activity timeline.
type IncidentEvent struct {
	TS      int64  `json:"ts"`
	Source  string `json:"source"` // "local" or "peer"
	Target  string `json:"target"`
	OK      bool   `json:"ok"`
	Summary string `json:"summary"`
}

const (
	maxHistoryPoints  = 36
	maxIncidentEvents = 40
)

// Probe is implemented by every local monitoring probe.
type Probe interface {
	ID() string
	Kind() string
	Check(ctx context.Context) ProbeResult
}

// ScheduledProbe pairs a Probe with its execution interval and per-check timeout.
type ScheduledProbe struct {
	Probe    Probe
	Interval time.Duration
	Timeout  time.Duration
}

// Scheduler executes each probe concurrently on its own ticker with an isolated timeout,
// ensuring slow or stuck probes never block heartbeats or other probes.
type Scheduler struct {
	probes []ScheduledProbe
	logger *slog.Logger

	mu        sync.RWMutex
	results   map[string]ProbeResult
	history   map[string][]HistoryPoint
	incidents []IncidentEvent
	ready     chan struct{}
	started   bool
	stopped   bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewScheduler creates a concurrent Scheduler for the given probes.
func NewScheduler(scheduled []ScheduledProbe, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	copied := make([]ScheduledProbe, len(scheduled))
	copy(copied, scheduled)
	return &Scheduler{
		probes:  copied,
		logger:  logger,
		results: make(map[string]ProbeResult, len(copied)),
		history: make(map[string][]HistoryPoint, len(copied)),
		ready:   make(chan struct{}),
	}
}

// BuildFromConfig instantiates all probes declared in configuration.
func BuildFromConfig(cfgs []config.ProbeConfig) ([]ScheduledProbe, error) {
	out := make([]ScheduledProbe, 0, len(cfgs))
	for _, pc := range cfgs {
		var (
			p   Probe
			err error
		)
		switch pc.Kind {
		case "http":
			p = NewHTTPProbe(pc)
		case "tcp":
			p = NewTCPProbe(pc)
		case "docker":
			p, err = NewDockerProbe(pc)
		case "synology":
			p, err = NewSynologyProbe(pc)
		case "snmp_oid":
			p, err = NewSNMPOIDProbe(pc)
		case "node_exporter":
			p = NewNodeExporterProbe(pc)
		case "windows_exporter":
			p = NewWindowsExporterProbe(pc)
		default:
			return nil, fmt.Errorf("probe %q: unsupported kind %q", pc.ID, pc.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("init probe %q (%s): %w", pc.ID, pc.Kind, err)
		}
		out = append(out, ScheduledProbe{
			Probe:    p,
			Interval: pc.Interval,
			Timeout:  pc.Timeout,
		})
	}
	return out, nil
}

// Start launches one goroutine per probe. Each probe runs immediately and then on its ticker.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	if len(s.probes) == 0 {
		close(s.ready)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	var initialWG sync.WaitGroup
	initialWG.Add(len(s.probes))
	go func() {
		initialWG.Wait()
		close(s.ready)
	}()

	for _, sp := range s.probes {
		s.wg.Add(1)
		go s.runProbeLoop(runCtx, sp, &initialWG)
	}
}

// Stop cancels all probe goroutines and waits for them to exit cleanly.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	cancel := s.cancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// WaitInitial blocks until every configured probe has completed its first check or ctx expires.
func (s *Scheduler) WaitInitial(ctx context.Context) error {
	select {
	case <-s.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Snapshot returns the latest ProbeResult for each probe in configuration order,
// along with overallOK (true if every probe with a result is OK).
func (s *Scheduler) Snapshot() (results []ProbeResult, overallOK bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results = make([]ProbeResult, 0, len(s.probes))
	overallOK = true
	for _, sp := range s.probes {
		res, ok := s.results[sp.Probe.ID()]
		if !ok {
			continue
		}
		results = append(results, res)
		if !res.OK {
			overallOK = false
		}
	}
	return results, overallOK
}

// RunNow executes all configured probes immediately in parallel, updates cached results
// and history, and returns the fresh snapshot.
func (s *Scheduler) RunNow(ctx context.Context) ([]ProbeResult, bool) {
	s.mu.RLock()
	list := make([]ScheduledProbe, len(s.probes))
	copy(list, s.probes)
	s.mu.RUnlock()

	var wg sync.WaitGroup
	for _, sp := range list {
		timeout := sp.Timeout
		if timeout <= 0 {
			timeout = config.DefaultProbeTimeout
		}
		wg.Add(1)
		go func(p Probe, to time.Duration) {
			defer wg.Done()
			s.execOnce(ctx, p, to)
		}(sp.Probe, timeout)
	}
	wg.Wait()
	return s.Snapshot()
}

// HistorySnapshot returns a copy of the recent check history for each probe.
func (s *Scheduler) HistorySnapshot() map[string][]HistoryPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string][]HistoryPoint, len(s.history))
	for id, pts := range s.history {
		cp := make([]HistoryPoint, len(pts))
		copy(cp, pts)
		out[id] = cp
	}
	return out
}

// Incidents returns recent local probe state transitions (newest first).
func (s *Scheduler) Incidents() []IncidentEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]IncidentEvent, len(s.incidents))
	for i := range s.incidents {
		out[i] = s.incidents[len(s.incidents)-1-i]
	}
	return out
}

func (s *Scheduler) runProbeLoop(ctx context.Context, sp ScheduledProbe, initialWG *sync.WaitGroup) {
	defer s.wg.Done()

	interval := sp.Interval
	if interval <= 0 {
		interval = config.DefaultProbeInterval
	}
	timeout := sp.Timeout
	if timeout <= 0 {
		timeout = config.DefaultProbeTimeout
	}

	s.execOnce(ctx, sp.Probe, timeout)
	initialWG.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.execOnce(ctx, sp.Probe, timeout)
		}
	}
}

func (s *Scheduler) execOnce(ctx context.Context, p Probe, timeout time.Duration) {
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := p.Check(checkCtx)
	if res.ID == "" {
		res.ID = p.ID()
	}
	if res.Kind == "" {
		res.Kind = p.Kind()
	}

	nowUnix := time.Now().Unix()

	s.mu.Lock()
	prev, existed := s.results[res.ID]
	s.results[res.ID] = res

	pts := append(s.history[res.ID], HistoryPoint{
		TS:        nowUnix,
		OK:        res.OK,
		LatencyMs: res.Latency,
	})
	if len(pts) > maxHistoryPoints {
		pts = pts[len(pts)-maxHistoryPoints:]
	}
	s.history[res.ID] = pts

	if (existed && prev.OK != res.OK) || (!existed && !res.OK) {
		s.incidents = append(s.incidents, IncidentEvent{
			TS:      nowUnix,
			Source:  "local",
			Target:  res.ID,
			OK:      res.OK,
			Summary: res.Summary,
		})
		if len(s.incidents) > maxIncidentEvents {
			s.incidents = s.incidents[len(s.incidents)-maxIncidentEvents:]
		}
	}
	s.mu.Unlock()

	if !existed || prev.OK != res.OK {
		level := slog.LevelInfo
		if !res.OK {
			level = slog.LevelWarn
		}
		s.logger.Log(ctx, level, "probe state update",
			"probe_id", res.ID,
			"kind", res.Kind,
			"ok", res.OK,
			"summary", res.Summary,
			"latency_ms", res.Latency,
		)
	}
}
