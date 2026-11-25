package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr"

	mwcrypto "meshwatch/internal/crypto"
	"meshwatch/internal/probes"
)

// mockNostrRelay is an in-memory NIP-01 ephemeral Nostr relay for integration tests.
type mockNostrRelay struct {
	server *httptest.Server

	mu          sync.Mutex
	subscribers map[*mockClient]map[string]nostr.Filters
	events      []nostr.Event
}

type mockClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (c *mockClient) sendJSON(ctx context.Context, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Write(ctx, websocket.MessageText, raw)
}

func newMockNostrRelay(t *testing.T) *mockNostrRelay {
	t.Helper()
	r := &mockNostrRelay{
		subscribers: make(map[*mockClient]map[string]nostr.Filters),
	}
	r.server = httptest.NewServer(http.HandlerFunc(r.handleWS))
	t.Cleanup(r.Close)
	return r
}

func (r *mockNostrRelay) URL() string {
	return "ws" + strings.TrimPrefix(r.server.URL, "http")
}

func (r *mockNostrRelay) Close() {
	r.dropAllClients()
	r.server.Close()
}

func (r *mockNostrRelay) dropAllClients() {
	r.mu.Lock()
	clients := make([]*mockClient, 0, len(r.subscribers))
	for c := range r.subscribers {
		clients = append(clients, c)
	}
	r.subscribers = make(map[*mockClient]map[string]nostr.Filters)
	r.mu.Unlock()

	for _, c := range clients {
		_ = c.conn.Close(websocket.StatusGoingAway, "simulated disconnect")
	}
}

func (r *mockNostrRelay) injectEvent(ev nostr.Event) {
	r.mu.Lock()
	type target struct {
		client *mockClient
		subID  string
	}
	var targets []target
	for client, subs := range r.subscribers {
		for subID, filters := range subs {
			if filters.Match(&ev) {
				targets = append(targets, target{client: client, subID: subID})
			}
		}
	}
	r.mu.Unlock()

	for _, tg := range targets {
		_ = tg.client.sendJSON(context.Background(), []any{"EVENT", tg.subID, ev})
	}
}

func (r *mockNostrRelay) handleWS(w http.ResponseWriter, req *http.Request) {
	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	client := &mockClient{conn: conn}

	r.mu.Lock()
	r.subscribers[client] = make(map[string]nostr.Filters)
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.subscribers, client)
		r.mu.Unlock()
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}()

	ctx := req.Context()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var raw []json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil || len(raw) < 2 {
			continue
		}
		var cmd string
		if err := json.Unmarshal(raw[0], &cmd); err != nil {
			continue
		}

		switch cmd {
		case "REQ":
			var subID string
			if err := json.Unmarshal(raw[1], &subID); err != nil {
				continue
			}
			var filters nostr.Filters
			for _, fRaw := range raw[2:] {
				var f nostr.Filter
				if err := json.Unmarshal(fRaw, &f); err == nil {
					filters = append(filters, f)
				}
			}
			r.mu.Lock()
			if subs, ok := r.subscribers[client]; ok {
				subs[subID] = filters
			}
			r.mu.Unlock()
			_ = client.sendJSON(ctx, []any{"EOSE", subID})

		case "CLOSE":
			var subID string
			if err := json.Unmarshal(raw[1], &subID); err == nil {
				r.mu.Lock()
				if subs, ok := r.subscribers[client]; ok {
					delete(subs, subID)
				}
				r.mu.Unlock()
			}

		case "EVENT":
			var ev nostr.Event
			if err := json.Unmarshal(raw[1], &ev); err != nil {
				continue
			}
			r.mu.Lock()
			r.events = append(r.events, ev)
			r.mu.Unlock()

			_ = client.sendJSON(ctx, []any{"OK", ev.ID, true, ""})
			r.injectEvent(ev)
		}
	}
}

func TestMultiRelayEncryptedExchangeAndDeduplication(t *testing.T) {
	relay1 := newMockNostrRelay(t)
	relay2 := newMockNostrRelay(t)
	relay3 := newMockNostrRelay(t)
	relayURLs := []string{relay1.URL(), relay2.URL(), relay3.URL()}

	privA, pubA, _ := mwcrypto.GenerateNostrKeypair()
	privB, pubB, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()
	cipherA, _ := mwcrypto.NewCipherFromString(psk)
	cipherB, _ := mwcrypto.NewCipherFromString(psk)

	poolA, err := NewPool(PoolConfig{
		PrivateKeyHex:  privA,
		PublicKeyHex:   pubA,
		Relays:         relayURLs,
		AllowedPeers:   map[string]struct{}{pubB: {}},
		Cipher:         cipherA,
		InitialBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPool A: %v", err)
	}
	poolB, err := NewPool(PoolConfig{
		PrivateKeyHex:  privB,
		PublicKeyHex:   pubB,
		Relays:         relayURLs,
		AllowedPeers:   map[string]struct{}{pubA: {}},
		Cipher:         cipherB,
		InitialBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPool B: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolA.Start(ctx)
	defer poolA.Stop()
	poolB.Start(ctx)
	defer poolB.Stop()

	if err := poolA.WaitConnected(ctx, 3); err != nil {
		t.Fatalf("poolA WaitConnected(3): %v", err)
	}
	if err := poolB.WaitConnected(ctx, 3); err != nil {
		t.Fatalf("poolB WaitConnected(3): %v", err)
	}

	// Node A publishes a heartbeat across all 3 relays.
	sentHB := HeartbeatPayload{
		NodeName:  "mon-homelab",
		UptimeSec: 84210,
		OverallOK: true,
		Probes: []probes.ProbeResult{
			{ID: "syno-ds920", Kind: "synology", OK: true, Summary: "RAID OK, 36°C"},
			{ID: "docker-core", Kind: "docker", OK: true, Summary: "18/18 up"},
		},
	}
	evID, err := poolA.PublishHeartbeat(ctx, sentHB)
	if err != nil {
		t.Fatalf("PublishHeartbeat: %v", err)
	}

	// Node B must receive the decrypted heartbeat exactly once despite 3 relays delivering it.
	select {
	case msg := <-poolB.Messages():
		if msg.EventID != evID {
			t.Fatalf("EventID = %q, want %q", msg.EventID, evID)
		}
		if msg.PubKey != pubA {
			t.Fatalf("PubKey = %q, want %q", msg.PubKey, pubA)
		}
		if msg.Type != TypeHeartbeat || msg.Heartbeat == nil {
			t.Fatalf("expected heartbeat message, got %+v", msg)
		}
		if msg.Heartbeat.NodeName != "mon-homelab" || !msg.Heartbeat.OverallOK || len(msg.Heartbeat.Probes) != 2 {
			t.Fatalf("unexpected heartbeat payload: %+v", msg.Heartbeat)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for heartbeat on poolB")
	}

	// Verify no duplicate delivery arrives from the other 2 relays.
	select {
	case dup := <-poolB.Messages():
		t.Fatalf("received duplicate event from multi-relay fanout: %+v", dup)
	case <-time.After(200 * time.Millisecond):
	}

	// Verify Node B can also publish an alert_claim back to Node A.
	claimID, err := poolB.PublishAlertClaim(ctx, AlertClaimPayload{
		TargetPubKey: pubA,
		IncidentID:   pubA + ":1764060000",
		Reason:       "peer_timeout",
	})
	if err != nil {
		t.Fatalf("PublishAlertClaim: %v", err)
	}

	select {
	case msg := <-poolA.Messages():
		if msg.EventID != claimID || msg.Type != TypeAlertClaim || msg.AlertClaim == nil {
			t.Fatalf("unexpected alert_claim message: %+v", msg)
		}
		if msg.AlertClaim.Reason != "peer_timeout" || msg.AlertClaim.TargetPubKey != pubA {
			t.Fatalf("unexpected alert_claim payload: %+v", msg.AlertClaim)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for alert_claim on poolA")
	}
}

func TestRelayAutoReconnect(t *testing.T) {
	relay := newMockNostrRelay(t)

	privA, pubA, _ := mwcrypto.GenerateNostrKeypair()
	privB, pubB, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()
	cA, _ := mwcrypto.NewCipherFromString(psk)
	cB, _ := mwcrypto.NewCipherFromString(psk)

	poolA, _ := NewPool(PoolConfig{
		PrivateKeyHex:  privA,
		PublicKeyHex:   pubA,
		Relays:         []string{relay.URL()},
		AllowedPeers:   map[string]struct{}{pubB: {}},
		Cipher:         cA,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
	})
	poolB, _ := NewPool(PoolConfig{
		PrivateKeyHex:  privB,
		PublicKeyHex:   pubB,
		Relays:         []string{relay.URL()},
		AllowedPeers:   map[string]struct{}{pubA: {}},
		Cipher:         cB,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolA.Start(ctx)
	defer poolA.Stop()
	poolB.Start(ctx)
	defer poolB.Stop()

	if err := poolA.WaitConnected(ctx, 1); err != nil {
		t.Fatalf("poolA initial connect: %v", err)
	}
	if err := poolB.WaitConnected(ctx, 1); err != nil {
		t.Fatalf("poolB initial connect: %v", err)
	}

	// Forcibly drop all WebSocket clients from the relay.
	relay.dropAllClients()

	// Wait briefly for disconnects to be noticed, then wait for automatic reconnection.
	time.Sleep(150 * time.Millisecond)
	if err := poolA.WaitConnected(ctx, 1); err != nil {
		t.Fatalf("poolA reconnect: %v", err)
	}
	if err := poolB.WaitConnected(ctx, 1); err != nil {
		t.Fatalf("poolB reconnect: %v", err)
	}

	// Confirm heartbeat flows again after reconnection.
	if _, err := poolA.PublishHeartbeat(ctx, HeartbeatPayload{NodeName: "after-reconnect", OverallOK: true}); err != nil {
		t.Fatalf("PublishHeartbeat after reconnect: %v", err)
	}
	select {
	case msg := <-poolB.Messages():
		if msg.Heartbeat == nil || msg.Heartbeat.NodeName != "after-reconnect" {
			t.Fatalf("unexpected post-reconnect message: %+v", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for heartbeat after relay reconnect")
	}
}

func TestValidationSecurityGuards(t *testing.T) {
	fixedNow := time.Unix(1764060000, 0)

	privPeer, pubPeer, _ := mwcrypto.GenerateNostrKeypair()
	privRogue, pubRogue, _ := mwcrypto.GenerateNostrKeypair()
	privSelf, pubSelf, _ := mwcrypto.GenerateNostrKeypair()

	pskGood, _ := mwcrypto.GeneratePSK()
	pskWrong, _ := mwcrypto.GeneratePSK()
	cGood, _ := mwcrypto.NewCipherFromString(pskGood)
	cWrong, _ := mwcrypto.NewCipherFromString(pskWrong)

	pool, err := NewPool(PoolConfig{
		PrivateKeyHex: privSelf,
		PublicKeyHex:  pubSelf,
		Relays:        []string{"ws://127.0.0.1:1"},
		AllowedPeers:  map[string]struct{}{pubPeer: {}},
		Cipher:        cGood,
		Now:           func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	makeSignedEvent := func(priv, pub string, kind int, ts time.Time, c *mwcrypto.Cipher, payload any) *nostr.Event {
		content, err := c.EncryptJSON(payload)
		if err != nil {
			t.Fatalf("EncryptJSON: %v", err)
		}
		ev := &nostr.Event{
			PubKey:    pub,
			CreatedAt: nostr.Timestamp(ts.Unix()),
			Kind:      kind,
			Tags:      nostr.Tags{{"t", cGood.TopicTag()}},
			Content:   content,
		}
		if err := ev.Sign(priv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return ev
	}

	hb := HeartbeatPayload{Type: TypeHeartbeat, NodeName: "peer-1", TS: fixedNow.Unix(), OverallOK: true}

	// 1. Unauthorized pubkey rejected
	evRogue := makeSignedEvent(privRogue, pubRogue, EventKind, fixedNow, cGood, hb)
	if _, ok := pool.validateAndDecodeEvent(evRogue, "ws://mock"); ok {
		t.Fatal("expected event from unauthorized pubkey to be rejected")
	}

	// 2. Wrong kind rejected
	evWrongKind := makeSignedEvent(privPeer, pubPeer, 1, fixedNow, cGood, hb)
	if _, ok := pool.validateAndDecodeEvent(evWrongKind, "ws://mock"); ok {
		t.Fatal("expected event with wrong kind to be rejected")
	}

	// 3. Invalid Schnorr signature rejected
	evBadSig := makeSignedEvent(privPeer, pubPeer, EventKind, fixedNow, cGood, hb)
	evBadSig.Sig = strings.Repeat("0", 128)
	if _, ok := pool.validateAndDecodeEvent(evBadSig, "ws://mock"); ok {
		t.Fatal("expected event with bad signature to be rejected")
	}

	// 4. Tampered content (ID mismatch) rejected
	evTampered := makeSignedEvent(privPeer, pubPeer, EventKind, fixedNow, cGood, hb)
	evTampered.Content = evTampered.Content + "A"
	if _, ok := pool.validateAndDecodeEvent(evTampered, "ws://mock"); ok {
		t.Fatal("expected tampered event to be rejected")
	}

	// 5. Anti-replay: >60s old rejected
	evOld := makeSignedEvent(privPeer, pubPeer, EventKind, fixedNow.Add(-61*time.Second), cGood, hb)
	if _, ok := pool.validateAndDecodeEvent(evOld, "ws://mock"); ok {
		t.Fatal("expected event older than 60s to be rejected")
	}

	// 6. Anti-replay: >60s in the future rejected
	evFuture := makeSignedEvent(privPeer, pubPeer, EventKind, fixedNow.Add(61*time.Second), cGood, hb)
	if _, ok := pool.validateAndDecodeEvent(evFuture, "ws://mock"); ok {
		t.Fatal("expected event >60s in the future to be rejected")
	}

	// 7. Wrong PSK silently rejected
	evWrongPSK := makeSignedEvent(privPeer, pubPeer, EventKind, fixedNow, cWrong, hb)
	if _, ok := pool.validateAndDecodeEvent(evWrongPSK, "ws://mock"); ok {
		t.Fatal("expected event encrypted with wrong PSK to be rejected")
	}

	// 8. Valid event within 60s skew accepted once, then deduplicated
	evValid := makeSignedEvent(privPeer, pubPeer, EventKind, fixedNow.Add(-30*time.Second), cGood, hb)
	msg, ok := pool.validateAndDecodeEvent(evValid, "ws://mock")
	if !ok {
		t.Fatal("expected valid event to be accepted")
	}
	if msg.Heartbeat == nil || msg.Heartbeat.NodeName != "peer-1" {
		t.Fatalf("unexpected decoded message: %+v", msg)
	}
	if _, dupOk := pool.validateAndDecodeEvent(evValid, "ws://mock-2"); dupOk {
		t.Fatal("expected duplicate event ID to be rejected")
	}
}
