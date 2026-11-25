package quorum

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"meshwatch/internal/config"
	"meshwatch/internal/notify"
	"meshwatch/internal/probes"
	"meshwatch/internal/transport"
)

const (
	// DefaultRank1Delay is the failover wait duration for notifier rank 1 (15s per spec).
	DefaultRank1Delay = 15 * time.Second
	// DefaultRank2Delay is the failover wait duration for notifier rank >= 2 (30s per spec).
	DefaultRank2Delay = 30 * time.Second

	claimRetentionWindow = 3 * time.Minute
	claimMatchWindow     = 90 * time.Second
)

// ClaimPublisher publishes alert_claim messages onto the Nostr mesh.
type ClaimPublisher interface {
	PublishAlertClaim(ctx context.Context, claim transport.AlertClaimPayload) (string, error)
}

// DialFunc dials a TCP endpoint (injectable for Auto-Mute unit tests).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// PeerHistoryPoint records a single peer liveness/health sample for the built-in UI bar.
type PeerHistoryPoint struct {
	TS    int64  `json:"ts"`
	State string `json:"state"` // "ok", "warn", or "down"
}

const (
	maxPeerHistoryPoints = 36
	maxPeerIncidents     = 40
)

// EngineConfig configures the quorum, Auto-Mute, and notifier election engine.
type EngineConfig struct {
	SelfNodeName    string
	SelfPubKeyHex   string
	PeerTimeout     time.Duration
	Peers           []config.PeerConfig
	AutoMuteTargets []string
	AutoMuteTimeout time.Duration
	Rank1Delay      time.Duration
	Rank2Delay      time.Duration
	Publisher       ClaimPublisher
	Notifier        notify.Notifier
	Dial            DialFunc
	Now             func() time.Time
	Logger          *slog.Logger
}

type peerState struct {
	cfg         config.PeerConfig
	nodeName    string
	everSeen    bool
	online      bool
	timedOut    bool
	overallOK   bool
	uptimeSec   int64
	lastSeen    time.Time
	probeStates map[string]bool
	lastProbes  []probes.ProbeResult
	history     []PeerHistoryPoint
}

// PeerStatus is a thread-safe snapshot of a peer's liveness and latest reported probes.
type PeerStatus struct {
	Name      string               `json:"name"`
	NodeName  string               `json:"node_name"`
	PubKeyHex string               `json:"pubkey_hex"`
	EverSeen  bool                 `json:"ever_seen"`
	Online    bool                 `json:"online"`
	TimedOut  bool                 `json:"timed_out"`
	OverallOK bool                 `json:"overall_ok"`
	UptimeSec int64                `json:"uptime_sec"`
	LastSeen  *time.Time           `json:"last_seen,omitempty"`
	Probes    []probes.ProbeResult `json:"probes"`
	History   []PeerHistoryPoint   `json:"history,omitempty"`
}

type claimRecord struct {
	incidentID   string
	targetPubKey string
	reason       string
	state        string
	receivedAt   time.Time
}

type pendingElection struct {
	incidentID   string
	targetPubKey string
	reason       string
	state        string
	cancel       context.CancelFunc
}

// Engine tracks peer liveness and probe states, enforces Auto-Mute on local WAN loss,
// records peer availability history, and elects a single notifier per incident via alert_claim.
type Engine struct {
	selfName        string
	selfPubKey      string
	peerTimeout     time.Duration
	autoMuteTargets []string
	autoMuteTimeout time.Duration
	rank1Delay      time.Duration
	rank2Delay      time.Duration
	publisher       ClaimPublisher
	notifier        notify.Notifier
	dial            DialFunc
	now             func() time.Time
	logger          *slog.Logger

	mu        sync.Mutex
	peers     map[string]*peerState
	incidents []probes.IncidentEvent
	muted     bool
	claims    map[string]claimRecord
	pending   map[string]*pendingElection
	stopped   bool

	wg sync.WaitGroup
}

// NewEngine creates a new Quorum Engine.
func NewEngine(cfg EngineConfig) *Engine {
	peerTimeout := cfg.PeerTimeout
	if peerTimeout <= 0 {
		peerTimeout = config.DefaultPeerTimeout
	}
	amTimeout := cfg.AutoMuteTimeout
	if amTimeout <= 0 {
		amTimeout = config.DefaultAutoMuteTimeout
	}
	amTargets := append([]string(nil), cfg.AutoMuteTargets...)
	if len(amTargets) == 0 {
		amTargets = []string{"1.1.1.1:443", "9.9.9.9:443"}
	}
	rank1 := cfg.Rank1Delay
	if rank1 <= 0 {
		rank1 = DefaultRank1Delay
	}
	rank2 := cfg.Rank2Delay
	if rank2 <= 0 {
		rank2 = DefaultRank2Delay
	}
	dialFn := cfg.Dial
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	peers := make(map[string]*peerState, len(cfg.Peers))
	for _, p := range cfg.Peers {
		pk := strings.ToLower(strings.TrimSpace(p.PubKeyHex))
		p.PubKeyHex = pk
		peers[pk] = &peerState{
			cfg:         p,
			nodeName:    p.Name,
			probeStates: make(map[string]bool),
		}
	}

	return &Engine{
		selfName:        cfg.SelfNodeName,
		selfPubKey:      strings.ToLower(strings.TrimSpace(cfg.SelfPubKeyHex)),
		peerTimeout:     peerTimeout,
		autoMuteTargets: amTargets,
		autoMuteTimeout: amTimeout,
		rank1Delay:      rank1,
		rank2Delay:      rank2,
		publisher:       cfg.Publisher,
		notifier:        cfg.Notifier,
		dial:            dialFn,
		now:             nowFn,
		logger:          logger,
		peers:           peers,
		claims:          make(map[string]claimRecord),
		pending:         make(map[string]*pendingElection),
	}
}

// Stop cancels all pending failover election timers and waits for goroutines to exit.
func (e *Engine) Stop() {
	e.mu.Lock()
	e.stopped = true
	for key, p := range e.pending {
		p.cancel()
		delete(e.pending, key)
	}
	e.mu.Unlock()
	e.wg.Wait()
}

// IsMuted reports whether the local node is currently muted due to WAN connectivity loss.
func (e *Engine) IsMuted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.muted
}

// PeerStatuses returns a deterministic snapshot of all configured peers sorted by name.
func (e *Engine) PeerStatuses() []PeerStatus {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]PeerStatus, 0, len(e.peers))
	for _, p := range e.peers {
		var lastSeenPtr *time.Time
		if !p.lastSeen.IsZero() {
			t := p.lastSeen
			lastSeenPtr = &t
		}
		copiedProbes := make([]probes.ProbeResult, len(p.lastProbes))
		copy(copiedProbes, p.lastProbes)
		copiedHistory := make([]PeerHistoryPoint, len(p.history))
		copy(copiedHistory, p.history)
		out = append(out, PeerStatus{
			Name:      p.cfg.Name,
			NodeName:  p.nodeName,
			PubKeyHex: p.cfg.PubKeyHex,
			EverSeen:  p.everSeen,
			Online:    p.online,
			TimedOut:  p.timedOut,
			OverallOK: p.overallOK,
			UptimeSec: p.uptimeSec,
			LastSeen:  lastSeenPtr,
			Probes:    copiedProbes,
			History:   copiedHistory,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].PubKeyHex < out[j].PubKeyHex
	})
	return out
}

// Incidents returns recent peer outages and recoveries (newest first).
func (e *Engine) Incidents() []probes.IncidentEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]probes.IncidentEvent, len(e.incidents))
	for i := range e.incidents {
		out[i] = e.incidents[len(e.incidents)-1-i]
	}
	return out
}

func (e *Engine) recordIncidentLocked(ts int64, target string, ok bool, summary string) {
	e.incidents = append(e.incidents, probes.IncidentEvent{
		TS:      ts,
		Source:  "peer",
		Target:  target,
		OK:      ok,
		Summary: summary,
	})
	if len(e.incidents) > maxPeerIncidents {
		e.incidents = e.incidents[len(e.incidents)-maxPeerIncidents:]
	}
}

func appendPeerHistoryLocked(p *peerState, ts int64, state string) {
	p.history = append(p.history, PeerHistoryPoint{TS: ts, State: state})
	if len(p.history) > maxPeerHistoryPoints {
		p.history = p.history[len(p.history)-maxPeerHistoryPoints:]
	}
}

// CheckAutoMute verifies outbound WAN connectivity via TCP Dial (default 3s timeout)
// against configured external targets. If all targets fail, the node enters muted=true
// to prevent false alerts during a local fiber/internet outage.
func (e *Engine) CheckAutoMute(ctx context.Context) bool {
	if len(e.autoMuteTargets) == 0 {
		e.setMuted(false)
		return false
	}

	dialCtx, cancel := context.WithTimeout(ctx, e.autoMuteTimeout)
	defer cancel()

	results := make(chan bool, len(e.autoMuteTargets))
	for _, target := range e.autoMuteTargets {
		go func(addr string) {
			conn, err := e.dial(dialCtx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				results <- true
				return
			}
			results <- false
		}(target)
	}

	reachable := false
	for range e.autoMuteTargets {
		if <-results {
			reachable = true
			cancel() // Cancel remaining dials once WAN reachability is proven.
		}
	}

	muted := !reachable
	e.setMuted(muted)
	return muted
}

func (e *Engine) setMuted(muted bool) {
	e.mu.Lock()
	prev := e.muted
	e.muted = muted
	if muted {
		// Suspend any pending outbound alert elections while WAN is down.
		for k, p := range e.pending {
			p.cancel()
			delete(e.pending, k)
		}
	}
	e.mu.Unlock()

	if prev != muted {
		if muted {
			e.logger.Warn("local WAN connectivity lost: Auto-Mute enabled, outbound alerts suspended")
		} else {
			e.logger.Info("local WAN connectivity restored: Auto-Mute disabled")
		}
	}
}

// HandleMessage processes a verified, decrypted Nostr message (heartbeat or alert_claim).
func (e *Engine) HandleMessage(ctx context.Context, msg transport.IncomingMessage) {
	switch msg.Type {
	case transport.TypeHeartbeat:
		if msg.Heartbeat != nil {
			e.handleHeartbeat(ctx, msg)
		}
	case transport.TypeAlertClaim:
		if msg.AlertClaim != nil {
			e.handleAlertClaim(msg)
		}
	}
}

func (e *Engine) handleHeartbeat(ctx context.Context, msg transport.IncomingMessage) {
	pk := strings.ToLower(strings.TrimSpace(msg.PubKey))
	hb := msg.Heartbeat
	now := e.now()

	e.mu.Lock()
	peer, ok := e.peers[pk]
	if !ok {
		e.mu.Unlock()
		return
	}

	if strings.TrimSpace(hb.NodeName) != "" {
		peer.nodeName = strings.TrimSpace(hb.NodeName)
	}
	wasTimedOut := peer.timedOut
	peer.everSeen = true
	peer.online = true
	peer.timedOut = false
	peer.overallOK = hb.OverallOK
	peer.uptimeSec = hb.UptimeSec
	peer.lastSeen = now
	peer.lastProbes = append([]probes.ProbeResult(nil), hb.Probes...)

	histState := "ok"
	if !hb.OverallOK {
		histState = "warn"
	}
	appendPeerHistoryLocked(peer, now.Unix(), histState)

	var alertsToSchedule []notify.Alert

	// Peer recovered from a timeout.
	if wasTimedOut {
		e.recordIncidentLocked(now.Unix(), peer.cfg.Name, true, "Connexion rétablie")
		bucket := timestampBucket60(now)
		alertsToSchedule = append(alertsToSchedule, notify.Alert{
			IncidentID:   fmt.Sprintf("resolved:%s:%d", pk, bucket),
			State:        notify.StateResolved,
			NodeName:     peer.nodeName,
			TargetPubKey: pk,
			Reason:       "peer_recovered",
			Summary:      "Peer heartbeat restored",
			Timestamp:    now,
			ReportedBy:   e.selfName,
		})
	}

	// Track per-probe state transitions (true -> false => DOWN, false -> true => RESOLVED).
	for _, pr := range hb.Probes {
		prevOK, seen := peer.probeStates[pr.ID]
		peer.probeStates[pr.ID] = pr.OK
		if !seen {
			continue
		}
		bucket := timestampBucket60(now)
		if prevOK && !pr.OK {
			summary := pr.Summary
			if summary == "" {
				summary = "probe check failed"
			}
			e.recordIncidentLocked(now.Unix(), peer.cfg.Name+" · "+pr.ID, false, summary)
			alertsToSchedule = append(alertsToSchedule, notify.Alert{
				IncidentID:   fmt.Sprintf("%s:%s:%d", pk, pr.ID, bucket),
				State:        notify.StateDown,
				NodeName:     peer.nodeName,
				TargetPubKey: pk,
				ProbeID:      pr.ID,
				Reason:       "probe_failed:" + pr.ID,
				Summary:      summary,
				Timestamp:    now,
				ReportedBy:   e.selfName,
			})
		} else if !prevOK && pr.OK {
			summary := pr.Summary
			if summary == "" {
				summary = "probe check OK"
			}
			e.recordIncidentLocked(now.Unix(), peer.cfg.Name+" · "+pr.ID, true, summary)
			alertsToSchedule = append(alertsToSchedule, notify.Alert{
				IncidentID:   fmt.Sprintf("resolved:%s:%s:%d", pk, pr.ID, bucket),
				State:        notify.StateResolved,
				NodeName:     peer.nodeName,
				TargetPubKey: pk,
				ProbeID:      pr.ID,
				Reason:       "probe_recovered:" + pr.ID,
				Summary:      summary,
				Timestamp:    now,
				ReportedBy:   e.selfName,
			})
		}
	}

	e.mu.Unlock()

	// Schedule elected alerts (checking Auto-Mute before alerting).
	if len(alertsToSchedule) > 0 {
		if e.CheckAutoMute(ctx) {
			return
		}
		for _, alert := range alertsToSchedule {
			e.scheduleAlert(ctx, alert)
		}
	}
}

func (e *Engine) handleAlertClaim(msg transport.IncomingMessage) {
	claim := msg.AlertClaim
	now := e.now()
	target := strings.ToLower(strings.TrimSpace(claim.TargetPubKey))
	state := normalizeClaimState(claim.State, claim.IncidentID)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.pruneExpiredClaimsLocked(now)
	e.claims[claim.IncidentID] = claimRecord{
		incidentID:   claim.IncidentID,
		targetPubKey: target,
		reason:       claim.Reason,
		state:        state,
		receivedAt:   now,
	}

	// Cancel any matching pending failover alert so only one node notifies.
	for key, pend := range e.pending {
		if pend.incidentID == claim.IncidentID ||
			(pend.targetPubKey == target && pend.reason == claim.Reason && pend.state == state) {
			e.logger.Info("alert already claimed by peer, suppressing local fallback notification",
				"claimed_by", msg.PubKey,
				"incident_id", claim.IncidentID,
				"target", target,
				"reason", claim.Reason,
			)
			pend.cancel()
			delete(e.pending, key)
		}
	}
}

// CheckTimeouts scans peers for missing heartbeats exceeding peer_timeout.
// Before declaring any peer DOWN, it executes CheckAutoMute to protect against local WAN loss.
func (e *Engine) CheckTimeouts(ctx context.Context) {
	now := e.now()

	// First check whether any currently-online peer has exceeded peer_timeout.
	e.mu.Lock()
	var expiredPubKeys []string
	for pk, peer := range e.peers {
		if peer.online && now.Sub(peer.lastSeen) > e.peerTimeout {
			expiredPubKeys = append(expiredPubKeys, pk)
		}
	}
	e.mu.Unlock()

	if len(expiredPubKeys) == 0 {
		return
	}

	// Mandatory Auto-Mute guard BEFORE marking any peer down or firing alerts.
	if e.CheckAutoMute(ctx) {
		return
	}

	// Re-check under lock and transition timed-out peers to offline.
	now = e.now()
	var alerts []notify.Alert

	e.mu.Lock()
	for _, pk := range expiredPubKeys {
		peer := e.peers[pk]
		if peer == nil || !peer.online || now.Sub(peer.lastSeen) <= e.peerTimeout {
			continue
		}
		peer.online = false
		peer.timedOut = true
		silentFor := now.Sub(peer.lastSeen).Round(time.Second)
		appendPeerHistoryLocked(peer, now.Unix(), "down")
		e.recordIncidentLocked(now.Unix(), peer.cfg.Name, false, fmt.Sprintf("Hors ligne depuis %s", silentFor))
		bucket := timestampBucket60(now)
		alerts = append(alerts, notify.Alert{
			IncidentID:   fmt.Sprintf("%s:%d", pk, bucket),
			State:        notify.StateDown,
			NodeName:     peer.nodeName,
			TargetPubKey: pk,
			Reason:       "peer_timeout",
			Summary:      fmt.Sprintf("No heartbeat received for %s (timeout %s)", silentFor, e.peerTimeout),
			Timestamp:    now,
			ReportedBy:   e.selfName,
		})
	}
	e.mu.Unlock()

	for _, alert := range alerts {
		e.scheduleAlert(ctx, alert)
	}
}

// ComputeNotifierRank returns this node's 0-based lexicographical rank among all
// currently online observer nodes (self + online peers excluding targetPubKey).
func (e *Engine) ComputeNotifierRank(targetPubKey string) (rank int, candidates []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.computeRankLocked(strings.ToLower(strings.TrimSpace(targetPubKey)))
}

func (e *Engine) computeRankLocked(targetPubKey string) (int, []string) {
	candidates := make([]string, 0, len(e.peers)+1)
	if e.selfPubKey != "" && e.selfPubKey != targetPubKey {
		candidates = append(candidates, e.selfPubKey)
	}
	for pk, peer := range e.peers {
		if peer.online && pk != targetPubKey && pk != e.selfPubKey {
			candidates = append(candidates, pk)
		}
	}
	sort.Strings(candidates)
	for i, pk := range candidates {
		if pk == e.selfPubKey {
			return i, candidates
		}
	}
	return len(candidates), candidates
}

// DelayForRank returns the election wait duration for a given lexicographical rank:
// Rank 0 -> 0s (immediate), Rank 1 -> 15s (default), Rank >= 2 -> 30s (default).
func (e *Engine) DelayForRank(rank int) time.Duration {
	switch {
	case rank <= 0:
		return 0
	case rank == 1:
		return e.rank1Delay
	default:
		return e.rank2Delay
	}
}

func (e *Engine) scheduleAlert(ctx context.Context, alert notify.Alert) {
	now := e.now()
	stateStr := strings.ToLower(string(alert.State))

	e.mu.Lock()
	if e.stopped || e.muted {
		e.mu.Unlock()
		return
	}
	e.pruneExpiredClaimsLocked(now)
	if e.isAlreadyClaimedLocked(alert.IncidentID, alert.TargetPubKey, alert.Reason, stateStr, now) {
		e.mu.Unlock()
		return
	}

	rank, candidates := e.computeRankLocked(alert.TargetPubKey)
	delay := e.DelayForRank(rank)

	// Avoid scheduling duplicate pending alerts for the same (target, reason, state).
	pendingKey := fmt.Sprintf("%s|%s|%s", alert.TargetPubKey, alert.Reason, stateStr)
	if _, exists := e.pending[pendingKey]; exists {
		e.mu.Unlock()
		return
	}

	if delay == 0 {
		// Record our own claim locally so we don't duplicate if triggered twice.
		e.claims[alert.IncidentID] = claimRecord{
			incidentID:   alert.IncidentID,
			targetPubKey: alert.TargetPubKey,
			reason:       alert.Reason,
			state:        stateStr,
			receivedAt:   now,
		}
		e.mu.Unlock()

		e.logger.Info("elected as rank 0 notifier: claiming and sending alert immediately",
			"incident_id", alert.IncidentID,
			"target", alert.NodeName,
			"state", alert.State,
			"candidates", len(candidates),
		)
		e.claimAndNotify(ctx, alert)
		return
	}

	waitCtx, cancel := context.WithCancel(ctx)
	e.pending[pendingKey] = &pendingElection{
		incidentID:   alert.IncidentID,
		targetPubKey: alert.TargetPubKey,
		reason:       alert.Reason,
		state:        stateStr,
		cancel:       cancel,
	}
	e.wg.Add(1)
	e.mu.Unlock()

	e.logger.Info("elected as backup notifier: waiting for rank-0 alert_claim",
		"rank", rank,
		"delay", delay,
		"incident_id", alert.IncidentID,
		"target", alert.NodeName,
		"state", alert.State,
	)

	go func() {
		defer e.wg.Done()
		defer cancel()

		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-waitCtx.Done():
			return
		case <-timer.C:
		}

		// Re-check WAN reachability before taking over.
		if e.CheckAutoMute(waitCtx) {
			e.removePending(pendingKey)
			return
		}

		e.mu.Lock()
		if e.stopped || e.muted {
			delete(e.pending, pendingKey)
			e.mu.Unlock()
			return
		}
		nowCheck := e.now()
		if _, stillPending := e.pending[pendingKey]; !stillPending {
			e.mu.Unlock()
			return
		}
		delete(e.pending, pendingKey)
		if e.isAlreadyClaimedLocked(alert.IncidentID, alert.TargetPubKey, alert.Reason, stateStr, nowCheck) {
			e.mu.Unlock()
			return
		}
		e.claims[alert.IncidentID] = claimRecord{
			incidentID:   alert.IncidentID,
			targetPubKey: alert.TargetPubKey,
			reason:       alert.Reason,
			state:        stateStr,
			receivedAt:   nowCheck,
		}
		e.mu.Unlock()

		e.logger.Warn("no alert_claim received from higher-rank peer: taking over notification",
			"rank", rank,
			"incident_id", alert.IncidentID,
			"target", alert.NodeName,
			"state", alert.State,
		)
		e.claimAndNotify(waitCtx, alert)
	}()
}

func (e *Engine) removePending(key string) {
	e.mu.Lock()
	delete(e.pending, key)
	e.mu.Unlock()
}

func (e *Engine) claimAndNotify(ctx context.Context, alert notify.Alert) {
	if e.publisher != nil {
		claim := transport.AlertClaimPayload{
			Type:         transport.TypeAlertClaim,
			TargetPubKey: alert.TargetPubKey,
			IncidentID:   alert.IncidentID,
			Reason:       alert.Reason,
			State:        strings.ToLower(string(alert.State)),
		}
		if _, err := e.publisher.PublishAlertClaim(ctx, claim); err != nil {
			e.logger.Warn("failed to publish alert_claim to nostr", "incident_id", alert.IncidentID, "err", err)
		}
	}

	if e.notifier != nil {
		if err := e.notifier.Send(ctx, alert); err != nil {
			e.logger.Error("failed to send notification", "incident_id", alert.IncidentID, "err", err)
		}
	}
}

func (e *Engine) isAlreadyClaimedLocked(incidentID, targetPubKey, reason, state string, now time.Time) bool {
	if rec, ok := e.claims[incidentID]; ok && now.Sub(rec.receivedAt) <= claimMatchWindow {
		return true
	}
	for _, rec := range e.claims {
		if now.Sub(rec.receivedAt) <= claimMatchWindow &&
			rec.targetPubKey == targetPubKey &&
			rec.reason == reason &&
			rec.state == state {
			return true
		}
	}
	return false
}

func (e *Engine) pruneExpiredClaimsLocked(now time.Time) {
	for id, rec := range e.claims {
		if now.Sub(rec.receivedAt) > claimRetentionWindow {
			delete(e.claims, id)
		}
	}
}

func timestampBucket60(t time.Time) int64 {
	return (t.Unix() / 60) * 60
}

func normalizeClaimState(state, incidentID string) string {
	s := strings.ToLower(strings.TrimSpace(state))
	if s != "" {
		return s
	}
	if strings.HasPrefix(incidentID, "resolved:") {
		return "resolved"
	}
	return "down"
}
