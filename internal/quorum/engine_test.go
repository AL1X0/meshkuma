package quorum

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"meshwatch/internal/config"
	"meshwatch/internal/notify"
	"meshwatch/internal/probes"
	"meshwatch/internal/transport"
)

type recordingNotifier struct {
	mu     sync.Mutex
	alerts []notify.Alert
	notify chan notify.Alert
}

func newRecordingNotifier() *recordingNotifier {
	return &recordingNotifier{notify: make(chan notify.Alert, 16)}
}

func (r *recordingNotifier) Name() string { return "recorder" }

func (r *recordingNotifier) Send(_ context.Context, alert notify.Alert) error {
	r.mu.Lock()
	r.alerts = append(r.alerts, alert)
	r.mu.Unlock()
	select {
	case r.notify <- alert:
	default:
	}
	return nil
}

func (r *recordingNotifier) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.alerts)
}

func (r *recordingNotifier) Snapshot() []notify.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]notify.Alert, len(r.alerts))
	copy(out, r.alerts)
	return out
}

type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

func dialAlwaysOK(_ context.Context, _, _ string) (net.Conn, error) {
	return fakeConn{}, nil
}

func dialAlwaysFail(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("network unreachable")
}

// meshBus routes published alert_claims between simulated in-memory engines.
type meshBus struct {
	mu      sync.Mutex
	engines map[string]*Engine
	dropped map[string]bool // pubkeys whose outbound claims are dropped (simulates crashed rank 0)
}

func newMeshBus() *meshBus {
	return &meshBus{
		engines: make(map[string]*Engine),
		dropped: make(map[string]bool),
	}
}

type busPublisher struct {
	bus        *meshBus
	fromPubKey string
	now        func() time.Time
}

func (p *busPublisher) PublishAlertClaim(ctx context.Context, claim transport.AlertClaimPayload) (string, error) {
	p.bus.mu.Lock()
	if p.bus.dropped[p.fromPubKey] {
		p.bus.mu.Unlock()
		return "", errors.New("simulated rank-0 loss")
	}
	targets := make([]*Engine, 0, len(p.bus.engines))
	for pk, eng := range p.bus.engines {
		if pk != p.fromPubKey {
			targets = append(targets, eng)
		}
	}
	p.bus.mu.Unlock()

	msg := transport.IncomingMessage{
		EventID:    "evt-" + claim.IncidentID,
		PubKey:     p.fromPubKey,
		CreatedAt:  p.now(),
		ReceivedAt: p.now(),
		Type:       transport.TypeAlertClaim,
		AlertClaim: &claim,
	}
	for _, eng := range targets {
		eng.HandleMessage(ctx, msg)
	}
	return msg.EventID, nil
}

type simClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *simClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *simClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestDefaultElectionDelays(t *testing.T) {
	eng := NewEngine(EngineConfig{SelfPubKeyHex: strings.Repeat("a", 64)})
	if eng.DelayForRank(0) != 0 {
		t.Fatalf("rank 0 delay = %v, want 0", eng.DelayForRank(0))
	}
	if eng.DelayForRank(1) != 15*time.Second {
		t.Fatalf("rank 1 delay = %v, want 15s", eng.DelayForRank(1))
	}
	if eng.DelayForRank(2) != 30*time.Second {
		t.Fatalf("rank 2 delay = %v, want 30s", eng.DelayForRank(2))
	}
	if eng.DelayForRank(5) != 30*time.Second {
		t.Fatalf("rank 5 delay = %v, want 30s", eng.DelayForRank(5))
	}
}

// TestThreeNodeSingleNotifierAndProbeRecovery proves that in a 3-node mesh (A < B < C),
// when C goes down, ONLY Rank 0 (A) notifies and B suppresses its notification via alert_claim.
func TestThreeNodeSingleNotifierAndRecovery(t *testing.T) {
	pkA := strings.Repeat("1", 64) // Rank 0
	pkB := strings.Repeat("2", 64) // Rank 1
	pkC := strings.Repeat("3", 64) // Target node going down

	clock := &simClock{now: time.Unix(1764060000, 0)}
	bus := newMeshBus()
	notA := newRecordingNotifier()
	notB := newRecordingNotifier()

	engA := NewEngine(EngineConfig{
		SelfNodeName: "node-a",
		SelfPubKeyHex: pkA,
		PeerTimeout:  90 * time.Second,
		Peers: []config.PeerConfig{
			{Name: "node-b", PubKeyHex: pkB},
			{Name: "node-c", PubKeyHex: pkC},
		},
		Rank1Delay: 120 * time.Millisecond,
		Rank2Delay: 240 * time.Millisecond,
		Publisher:  &busPublisher{bus: bus, fromPubKey: pkA, now: clock.Now},
		Notifier:   notA,
		Dial:       dialAlwaysOK,
		Now:        clock.Now,
	})
	engB := NewEngine(EngineConfig{
		SelfNodeName: "node-b",
		SelfPubKeyHex: pkB,
		PeerTimeout:  90 * time.Second,
		Peers: []config.PeerConfig{
			{Name: "node-a", PubKeyHex: pkA},
			{Name: "node-c", PubKeyHex: pkC},
		},
		Rank1Delay: 120 * time.Millisecond,
		Rank2Delay: 240 * time.Millisecond,
		Publisher:  &busPublisher{bus: bus, fromPubKey: pkB, now: clock.Now},
		Notifier:   notB,
		Dial:       dialAlwaysOK,
		Now:        clock.Now,
	})
	defer engA.Stop()
	defer engB.Stop()

	bus.engines[pkA] = engA
	bus.engines[pkB] = engB

	ctx := context.Background()

	// All 3 nodes are initially ONLINE.
	sendHB := func(eng *Engine, fromPK, fromName string, ok bool) {
		eng.HandleMessage(ctx, transport.IncomingMessage{
			PubKey:     fromPK,
			CreatedAt:  clock.Now(),
			ReceivedAt: clock.Now(),
			Type:       transport.TypeHeartbeat,
			Heartbeat: &transport.HeartbeatPayload{
				Type:      transport.TypeHeartbeat,
				NodeName:  fromName,
				TS:        clock.Now().Unix(),
				OverallOK: ok,
				Probes:    []probes.ProbeResult{{ID: "syno", Kind: "synology", OK: ok, Summary: "check"}},
			},
		})
	}
	sendHB(engA, pkB, "node-b", true)
	sendHB(engA, pkC, "node-c", true)
	sendHB(engB, pkA, "node-a", true)
	sendHB(engB, pkC, "node-c", true)

	// Advance time by 95s: A and B keep exchanging heartbeats, C goes silent!
	clock.Advance(60 * time.Second)
	sendHB(engA, pkB, "node-b", true)
	sendHB(engB, pkA, "node-a", true)
	clock.Advance(35 * time.Second) // C is now 95s silent (> 90s peer_timeout), A and B are 35s (< 90s).

	// Both B (Rank 1) and A (Rank 0) detect C's timeout.
	engB.CheckTimeouts(ctx)
	engA.CheckTimeouts(ctx)

	// Wait longer than Rank1Delay (120ms) to confirm B stays suppressed.
	time.Sleep(220 * time.Millisecond)

	if notA.Count() != 1 {
		t.Fatalf("Rank 0 (A) notifications = %d, want 1", notA.Count())
	}
	if notB.Count() != 0 {
		t.Fatalf("Rank 1 (B) notifications = %d, want 0 (should be suppressed by A's alert_claim)", notB.Count())
	}
	gotDown := notA.Snapshot()[0]
	if gotDown.State != notify.StateDown || gotDown.Reason != "peer_timeout" || gotDown.TargetPubKey != pkC {
		t.Fatalf("unexpected DOWN alert from A: %+v", gotDown)
	}

	// Now C comes back online -> only Rank 0 (A) sends RESOLVED notification.
	clock.Advance(5 * time.Second)
	sendHB(engB, pkC, "node-c", true)
	sendHB(engA, pkC, "node-c", true)
	time.Sleep(220 * time.Millisecond)

	if notA.Count() != 2 {
		t.Fatalf("Rank 0 (A) notifications after recovery = %d, want 2", notA.Count())
	}
	if notB.Count() != 0 {
		t.Fatalf("Rank 1 (B) notifications after recovery = %d, want 0", notB.Count())
	}
	gotResolved := notA.Snapshot()[1]
	if gotResolved.State != notify.StateResolved || gotResolved.Reason != "peer_recovered" {
		t.Fatalf("unexpected RESOLVED alert from A: %+v", gotResolved)
	}
}

// TestRank1FailoverWhenRank0Lost proves that when Rank 0 fails to emit an alert_claim,
// Rank 1 automatically takes over after the configured Rank1Delay (15s in production).
func TestRank1FailoverWhenRank0Lost(t *testing.T) {
	pkA := strings.Repeat("1", 64) // Rank 0 (will silently fail)
	pkB := strings.Repeat("2", 64) // Rank 1 (must take over after Rank1Delay)
	pkC := strings.Repeat("3", 64) // Target node going down

	clock := &simClock{now: time.Unix(1764060000, 0)}
	bus := newMeshBus()
	notB := newRecordingNotifier()

	rank1Delay := 120 * time.Millisecond
	engB := NewEngine(EngineConfig{
		SelfNodeName:  "node-b",
		SelfPubKeyHex: pkB,
		PeerTimeout:   90 * time.Second,
		Peers: []config.PeerConfig{
			{Name: "node-a", PubKeyHex: pkA},
			{Name: "node-c", PubKeyHex: pkC},
		},
		Rank1Delay: rank1Delay,
		Rank2Delay: 240 * time.Millisecond,
		Publisher:  &busPublisher{bus: bus, fromPubKey: pkB, now: clock.Now},
		Notifier:   notB,
		Dial:       dialAlwaysOK,
		Now:        clock.Now,
	})
	defer engB.Stop()
	bus.engines[pkB] = engB

	ctx := context.Background()
	hb := func(fromPK, name string) transport.IncomingMessage {
		return transport.IncomingMessage{
			PubKey:     fromPK,
			CreatedAt:  clock.Now(),
			ReceivedAt: clock.Now(),
			Type:       transport.TypeHeartbeat,
			Heartbeat:  &transport.HeartbeatPayload{Type: transport.TypeHeartbeat, NodeName: name, OverallOK: true},
		}
	}

	// B sees both A (rank 0) and C online.
	engB.HandleMessage(ctx, hb(pkA, "node-a"))
	engB.HandleMessage(ctx, hb(pkC, "node-c"))

	// A stays fresh enough that B still considers A rank 0, while C times out.
	// Meanwhile A is lost / cannot publish alert_claim.
	clock.Advance(60 * time.Second)
	engB.HandleMessage(ctx, hb(pkA, "node-a"))
	clock.Advance(35 * time.Second)

	rank, _ := engB.ComputeNotifierRank(pkC)
	if rank != 1 {
		t.Fatalf("expected B to have rank 1, got %d", rank)
	}

	start := time.Now()
	engB.CheckTimeouts(ctx)

	// Immediately after timeout detection, B must NOT have notified yet.
	if notB.Count() != 0 {
		t.Fatal("Rank 1 notified immediately instead of waiting for Rank1Delay")
	}

	// After Rank1Delay with no alert_claim from A, B MUST take over and notify!
	select {
	case alert := <-notB.notify:
		elapsed := time.Since(start)
		if elapsed < rank1Delay-20*time.Millisecond {
			t.Fatalf("Rank 1 fired too early: %v < %v", elapsed, rank1Delay)
		}
		if alert.State != notify.StateDown || alert.TargetPubKey != pkC {
			t.Fatalf("unexpected failover alert: %+v", alert)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for Rank 1 failover notification")
	}
}

// TestProbeTransitionAlerts verifies that a peer's internal probe transitioning
// ok:true -> ok:false fires DOWN, and ok:false -> ok:true fires RESOLVED.
func TestProbeTransitionAlerts(t *testing.T) {
	pkA := strings.Repeat("1", 64)
	pkB := strings.Repeat("2", 64)

	clock := &simClock{now: time.Unix(1764060000, 0)}
	notA := newRecordingNotifier()

	engA := NewEngine(EngineConfig{
		SelfNodeName:  "node-a",
		SelfPubKeyHex: pkA,
		PeerTimeout:   90 * time.Second,
		Peers:         []config.PeerConfig{{Name: "node-b", PubKeyHex: pkB}},
		Notifier:      notA,
		Dial:          dialAlwaysOK,
		Now:           clock.Now,
	})
	defer engA.Stop()

	ctx := context.Background()
	pushHB := func(ok bool, summary string) {
		engA.HandleMessage(ctx, transport.IncomingMessage{
			PubKey:     pkB,
			CreatedAt:  clock.Now(),
			ReceivedAt: clock.Now(),
			Type:       transport.TypeHeartbeat,
			Heartbeat: &transport.HeartbeatPayload{
				Type:      transport.TypeHeartbeat,
				NodeName:  "homelab-b",
				OverallOK: ok,
				Probes:    []probes.ProbeResult{{ID: "win-srv-01", Kind: "windows_exporter", OK: ok, Summary: summary}},
			},
		})
	}

	// Initial OK heartbeat -> no alert.
	pushHB(true, "Services 2/2 running")
	if notA.Count() != 0 {
		t.Fatalf("unexpected alert on initial healthy heartbeat")
	}

	// Probe fails (true -> false) -> DOWN alert.
	clock.Advance(30 * time.Second)
	pushHB(false, "Service VeeamBackup stopped")
	if notA.Count() != 1 {
		t.Fatalf("expected 1 alert after probe failure, got %d", notA.Count())
	}
	a1 := notA.Snapshot()[0]
	if a1.State != notify.StateDown || a1.ProbeID != "win-srv-01" || a1.Summary != "Service VeeamBackup stopped" {
		t.Fatalf("unexpected probe DOWN alert: %+v", a1)
	}

	// Probe recovers (false -> true) -> RESOLVED alert.
	clock.Advance(30 * time.Second)
	pushHB(true, "Services 2/2 running")
	if notA.Count() != 2 {
		t.Fatalf("expected 2 alerts after probe recovery, got %d", notA.Count())
	}
	a2 := notA.Snapshot()[1]
	if a2.State != notify.StateResolved || a2.ProbeID != "win-srv-01" {
		t.Fatalf("unexpected probe RESOLVED alert: %+v", a2)
	}
}

// TestAutoMuteSuppressesAlertsOnLocalWANOutage verifies that when all WAN dial targets fail,
// muted=true is set, peers are not declared down, and zero alerts are sent.
func TestAutoMuteSuppressesAlertsOnLocalWANOutage(t *testing.T) {
	pkA := strings.Repeat("1", 64)
	pkB := strings.Repeat("2", 64)

	clock := &simClock{now: time.Unix(1764060000, 0)}
	notA := newRecordingNotifier()

	var wanUp sync.Mutex
	isWANUp := true
	dialFn := func(_ context.Context, _, _ string) (net.Conn, error) {
		wanUp.Lock()
		ok := isWANUp
		wanUp.Unlock()
		if ok {
			return fakeConn{}, nil
		}
		return nil, errors.New("fiber link down")
	}

	engA := NewEngine(EngineConfig{
		SelfNodeName:    "node-a",
		SelfPubKeyHex:   pkA,
		PeerTimeout:     90 * time.Second,
		Peers:           []config.PeerConfig{{Name: "node-b", PubKeyHex: pkB}},
		AutoMuteTargets: []string{"1.1.1.1:443", "9.9.9.9:443"},
		AutoMuteTimeout: 200 * time.Millisecond,
		Notifier:        notA,
		Dial:            dialFn,
		Now:             clock.Now,
	})
	defer engA.Stop()

	ctx := context.Background()
	engA.HandleMessage(ctx, transport.IncomingMessage{
		PubKey:     pkB,
		CreatedAt:  clock.Now(),
		ReceivedAt: clock.Now(),
		Type:       transport.TypeHeartbeat,
		Heartbeat:  &transport.HeartbeatPayload{Type: transport.TypeHeartbeat, NodeName: "node-b", OverallOK: true},
	})

	// Simulate local fiber cut: WAN targets fail AND peer B appears silent > 90s.
	wanUp.Lock()
	isWANUp = false
	wanUp.Unlock()

	clock.Advance(120 * time.Second)
	engA.CheckTimeouts(ctx)

	if !engA.IsMuted() {
		t.Fatal("expected IsMuted() == true when all Auto-Mute targets fail")
	}
	if notA.Count() != 0 {
		t.Fatalf("expected 0 alerts while Auto-Muted, got %d", notA.Count())
	}

	// Verify partial WAN connectivity (1 of 2 targets succeeds) unmutes properly.
	partialEng := NewEngine(EngineConfig{
		SelfNodeName:    "partial",
		SelfPubKeyHex:   pkA,
		AutoMuteTargets: []string{"1.1.1.1:443", "9.9.9.9:443"},
		AutoMuteTimeout: 200 * time.Millisecond,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			if addr == "9.9.9.9:443" {
				return fakeConn{}, nil
			}
			return nil, errors.New("target 1 down")
		},
	})
	if partialEng.CheckAutoMute(ctx) {
		t.Fatal("expected CheckAutoMute() == false when at least 1 WAN target is reachable")
	}
}
