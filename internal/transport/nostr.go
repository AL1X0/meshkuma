package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr"

	mwcrypto "meshwatch/internal/crypto"
	"meshwatch/internal/probes"
)

const (
	// EventKind is the ephemeral NIP-01/NIP-16 kind used for MeshWatch messages.
	EventKind = 24242
	// MaxEventSkew is the maximum allowed clock skew for anti-replay protection.
	MaxEventSkew = 60 * time.Second

	// TypeHeartbeat identifies periodic node health heartbeats.
	TypeHeartbeat = "heartbeat"
	// TypeAlertClaim identifies anti-alert-storm alert claims.
	TypeAlertClaim = "alert_claim"

	defaultDedupeTTL      = 5 * time.Minute
	defaultDedupeMaxSize  = 10000
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 60 * time.Second
	defaultConnectTimeout = 10 * time.Second
	defaultPublishTimeout = 5 * time.Second
	defaultPingInterval   = 25 * time.Second
	defaultMessageBufSize = 256
	maxWebSocketMsgBytes  = 1 << 20 // 1 MiB
)

var (
	ErrNoConnectedRelays = errors.New("no connected Nostr relays available")
	ErrInvalidConfig     = errors.New("invalid Nostr transport config")
)

var subSeq atomic.Int64

// HeartbeatPayload is the decrypted JSON payload for periodic node heartbeats.
type HeartbeatPayload struct {
	Type      string               `json:"type"`
	NodeName  string               `json:"node_name"`
	TS        int64                `json:"ts"`
	UptimeSec int64                `json:"uptime_sec"`
	OverallOK bool                 `json:"overall_ok"`
	Probes    []probes.ProbeResult `json:"probes"`
}

// AlertClaimPayload is the decrypted JSON payload for quorum alert claims.
type AlertClaimPayload struct {
	Type         string `json:"type"`
	TargetPubKey string `json:"target_pubkey"`
	IncidentID   string `json:"incident_id"`
	Reason       string `json:"reason"`
	State        string `json:"state,omitempty"`
}

// IncomingMessage represents a verified, deduplicated, decrypted message from a peer.
type IncomingMessage struct {
	EventID    string
	PubKey     string
	CreatedAt  time.Time
	ReceivedAt time.Time
	RelayURL   string
	Type       string
	Heartbeat  *HeartbeatPayload
	AlertClaim *AlertClaimPayload
	RawJSON    []byte
}

// PoolConfig configures a multi-relay Nostr transport pool.
type PoolConfig struct {
	PrivateKeyHex  string
	PublicKeyHex   string
	Relays         []string
	AllowedPeers   map[string]struct{}
	Cipher         *mwcrypto.Cipher
	Logger         *slog.Logger
	Now            func() time.Time
	MaxEventSkew   time.Duration
	DedupeTTL      time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	ConnectTimeout time.Duration
	PublishTimeout time.Duration
}

// Pool manages concurrent WebSocket connections to multiple Nostr relays,
// automatic reconnection, event signing/encryption, and strict receive validation.
type Pool struct {
	privKey        string
	pubKey         string
	relays         []string
	allowedPeers   map[string]struct{}
	cipher         *mwcrypto.Cipher
	logger         *slog.Logger
	now            func() time.Time
	maxSkew        time.Duration
	initialBackoff time.Duration
	maxBackoff     time.Duration
	connectTimeout time.Duration
	publishTimeout time.Duration

	dedupe   *dedupeCache
	messages chan IncomingMessage

	stateMu     sync.RWMutex
	active      map[string]*relayConn
	stateSignal chan struct{}
	started     bool
	stopped     bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewPool creates a new multi-relay Nostr transport Pool.
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.PrivateKeyHex == "" || cfg.Cipher == nil || len(cfg.Relays) == 0 {
		return nil, ErrInvalidConfig
	}

	pubKey := strings.ToLower(strings.TrimSpace(cfg.PublicKeyHex))
	if pubKey == "" {
		derived, err := nostr.GetPublicKey(cfg.PrivateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("%w: derive public key: %v", ErrInvalidConfig, err)
		}
		pubKey = strings.ToLower(derived)
	}

	allowed := make(map[string]struct{}, len(cfg.AllowedPeers))
	for pk := range cfg.AllowedPeers {
		allowed[strings.ToLower(strings.TrimSpace(pk))] = struct{}{}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	maxSkew := cfg.MaxEventSkew
	if maxSkew <= 0 {
		maxSkew = MaxEventSkew
	}
	dedupeTTL := cfg.DedupeTTL
	if dedupeTTL <= 0 {
		dedupeTTL = defaultDedupeTTL
	}
	initBackoff := cfg.InitialBackoff
	if initBackoff <= 0 {
		initBackoff = defaultInitialBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultMaxBackoff
	}
	connectTimeout := cfg.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultConnectTimeout
	}
	publishTimeout := cfg.PublishTimeout
	if publishTimeout <= 0 {
		publishTimeout = defaultPublishTimeout
	}

	relays := make([]string, 0, len(cfg.Relays))
	seenRelays := make(map[string]struct{}, len(cfg.Relays))
	for _, r := range cfg.Relays {
		u := strings.TrimSpace(r)
		if u == "" {
			continue
		}
		if _, dup := seenRelays[u]; dup {
			continue
		}
		seenRelays[u] = struct{}{}
		relays = append(relays, u)
	}
	if len(relays) == 0 {
		return nil, ErrInvalidConfig
	}

	return &Pool{
		privKey:        strings.ToLower(strings.TrimSpace(cfg.PrivateKeyHex)),
		pubKey:         pubKey,
		relays:         relays,
		allowedPeers:   allowed,
		cipher:         cfg.Cipher,
		logger:         logger,
		now:            nowFn,
		maxSkew:        maxSkew,
		initialBackoff: initBackoff,
		maxBackoff:     maxBackoff,
		connectTimeout: connectTimeout,
		publishTimeout: publishTimeout,
		dedupe:         newDedupeCache(dedupeTTL, defaultDedupeMaxSize),
		messages:       make(chan IncomingMessage, defaultMessageBufSize),
		active:         make(map[string]*relayConn, len(relays)),
		stateSignal:    make(chan struct{}),
	}, nil
}

// Start launches one background worker per configured relay.
func (p *Pool) Start(ctx context.Context) {
	p.stateMu.Lock()
	if p.started {
		p.stateMu.Unlock()
		return
	}
	p.started = true
	poolCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.stateMu.Unlock()

	for _, relayURL := range p.relays {
		p.wg.Add(1)
		go p.runRelayWorker(poolCtx, relayURL)
	}
}

// Stop disconnects all relays and waits for all workers to terminate cleanly.
func (p *Pool) Stop() {
	p.stateMu.Lock()
	if !p.started || p.stopped {
		p.stateMu.Unlock()
		return
	}
	p.stopped = true
	cancel := p.cancel
	p.stateMu.Unlock()

	if cancel != nil {
		cancel()
	}
	p.wg.Wait()
	close(p.messages)
}

// Messages returns the channel of validated, deduplicated, decrypted peer messages.
func (p *Pool) Messages() <-chan IncomingMessage {
	return p.messages
}

// RelayStatus describes the live connection state of a single configured Nostr relay.
type RelayStatus struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
}

// ConnectedRelays returns the number of currently connected and subscribed relays.
func (p *Pool) ConnectedRelays() int {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return len(p.active)
}

// RelayStatuses returns the ordered connection state of every configured relay.
func (p *Pool) RelayStatuses() []RelayStatus {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()

	out := make([]RelayStatus, 0, len(p.relays))
	for _, u := range p.relays {
		_, connected := p.active[u]
		out = append(out, RelayStatus{
			URL:       u,
			Connected: connected,
		})
	}
	return out
}

// WaitConnected blocks until at least minRelays are connected and subscribed, or ctx ends.
func (p *Pool) WaitConnected(ctx context.Context, minRelays int) error {
	if minRelays <= 0 {
		return nil
	}
	for {
		p.stateMu.RLock()
		count := len(p.active)
		sig := p.stateSignal
		p.stateMu.RUnlock()

		if count >= minRelays {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sig:
		}
	}
}

// PublishHeartbeat encrypts, signs, and publishes a HeartbeatPayload to connected relays.
func (p *Pool) PublishHeartbeat(ctx context.Context, hb HeartbeatPayload) (string, error) {
	hb.Type = TypeHeartbeat
	if hb.TS == 0 {
		hb.TS = p.now().Unix()
	}
	return p.PublishPayload(ctx, hb)
}

// PublishAlertClaim encrypts, signs, and publishes an AlertClaimPayload to connected relays.
func (p *Pool) PublishAlertClaim(ctx context.Context, claim AlertClaimPayload) (string, error) {
	claim.Type = TypeAlertClaim
	return p.PublishPayload(ctx, claim)
}

// PublishPayload encrypts an arbitrary JSON payload, wraps it in a signed kind 24242
// Nostr event tagged with #t, and fans it out concurrently across all connected relays.
func (p *Pool) PublishPayload(ctx context.Context, payload any) (string, error) {
	ciphertext, err := p.cipher.EncryptJSON(payload)
	if err != nil {
		return "", fmt.Errorf("encrypt payload: %w", err)
	}

	ev := nostr.Event{
		PubKey:    p.pubKey,
		CreatedAt: nostr.Timestamp(p.now().Unix()),
		Kind:      EventKind,
		Tags:      nostr.Tags{{"t", p.cipher.TopicTag()}},
		Content:   ciphertext,
	}
	if err := ev.Sign(p.privKey); err != nil {
		return "", fmt.Errorf("sign nostr event: %w", err)
	}

	return p.PublishEvent(ctx, ev)
}

// PublishEvent fans out a signed Nostr event to all currently connected relays.
// It succeeds if at least one relay accepts the event.
func (p *Pool) PublishEvent(ctx context.Context, ev nostr.Event) (string, error) {
	p.stateMu.RLock()
	relays := make([]*relayConn, 0, len(p.active))
	for _, r := range p.active {
		relays = append(relays, r)
	}
	p.stateMu.RUnlock()

	if len(relays) == 0 {
		return "", ErrNoConnectedRelays
	}

	type pubResult struct {
		url string
		err error
	}
	resCh := make(chan pubResult, len(relays))
	var wg sync.WaitGroup
	for _, relay := range relays {
		wg.Add(1)
		go func(r *relayConn) {
			defer wg.Done()
			pubCtx, cancel := context.WithTimeout(ctx, p.publishTimeout)
			defer cancel()
			err := r.publish(pubCtx, ev)
			resCh <- pubResult{url: r.url, err: err}
		}(relay)
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var errs []error
	succeeded := 0
	for res := range resCh {
		if res.err == nil {
			succeeded++
		} else {
			p.logger.Debug("relay publish failed", "relay", res.url, "event_id", ev.ID, "err", res.err)
			errs = append(errs, fmt.Errorf("%s: %w", res.url, res.err))
		}
	}

	if succeeded == 0 {
		return "", fmt.Errorf("publish failed on all %d connected relays: %w", len(relays), errors.Join(errs...))
	}
	return ev.ID, nil
}

func (p *Pool) runRelayWorker(ctx context.Context, relayURL string) {
	defer p.wg.Done()

	backoff := p.initialBackoff
	for {
		if ctx.Err() != nil {
			return
		}

		connectedAt, err := p.connectAndConsume(ctx, relayURL)
		if ctx.Err() != nil {
			return
		}

		if !connectedAt.IsZero() && time.Since(connectedAt) > 10*time.Second {
			backoff = p.initialBackoff
		}

		p.logger.Warn("nostr relay disconnected, scheduling reconnect",
			"relay", relayURL,
			"backoff", backoff,
			"err", err,
		)

		jitter := time.Duration(0)
		if backoff >= 5*time.Millisecond {
			jitter = time.Duration(rand.Int64N(int64(backoff / 5)))
		}
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		backoff *= 2
		if backoff > p.maxBackoff {
			backoff = p.maxBackoff
		}
	}
}

func (p *Pool) connectAndConsume(ctx context.Context, relayURL string) (time.Time, error) {
	dialCtx, dialCancel := context.WithTimeout(ctx, p.connectTimeout)
	wsConn, _, err := websocket.Dial(dialCtx, relayURL, nil)
	dialCancel()
	if err != nil {
		return time.Time{}, fmt.Errorf("dial websocket: %w", err)
	}
	wsConn.SetReadLimit(maxWebSocketMsgBytes)

	connCtx, connCancel := context.WithCancel(ctx)
	rc := newRelayConn(relayURL, wsConn, connCtx, connCancel)
	defer func() {
		rc.close()
	}()

	subID := fmt.Sprintf("mw-%d", subSeq.Add(1))
	filter := nostr.Filter{
		Kinds: []int{EventKind},
		Tags:  nostr.TagMap{"t": {p.cipher.TopicTag()}},
	}
	reqBytes, err := (nostr.ReqEnvelope{SubscriptionID: subID, Filters: nostr.Filters{filter}}).MarshalJSON()
	if err != nil {
		return time.Time{}, fmt.Errorf("marshal REQ: %w", err)
	}
	if err := rc.writeText(connCtx, reqBytes); err != nil {
		return time.Time{}, fmt.Errorf("send REQ: %w", err)
	}

	connectedAt := time.Now()
	p.setActiveRelay(relayURL, rc)
	p.logger.Info("connected to nostr relay", "relay", relayURL, "topic_tag", p.cipher.TopicTag())
	defer p.clearActiveRelay(relayURL, rc)

	// Start periodic WebSocket ping keepalive to detect dead half-open sockets.
	var pingWG sync.WaitGroup
	pingWG.Add(1)
	go func() {
		defer pingWG.Done()
		ticker := time.NewTicker(defaultPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(connCtx, 10*time.Second)
				err := wsConn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					if connCtx.Err() == nil {
						p.logger.Debug("nostr relay ping failed", "relay", relayURL, "err", err)
						connCancel()
					}
					return
				}
			}
		}
	}()
	defer func() {
		connCancel()
		pingWG.Wait()
	}()

	for {
		_, data, err := wsConn.Read(connCtx)
		if err != nil {
			return connectedAt, err
		}

		env := nostr.ParseMessage(string(data))
		if env == nil {
			continue
		}

		switch msg := env.(type) {
		case *nostr.EventEnvelope:
			if msg.SubscriptionID != nil && *msg.SubscriptionID != subID {
				continue
			}
			ev := msg.Event
			p.handleEvent(ctx, &ev, relayURL)

		case *nostr.OKEnvelope:
			rc.resolveOK(msg.EventID, msg.OK, msg.Reason)

		case *nostr.ClosedEnvelope:
			if msg.SubscriptionID == subID {
				return connectedAt, fmt.Errorf("subscription closed by relay: %s", msg.Reason)
			}

		case *nostr.NoticeEnvelope:
			p.logger.Debug("nostr relay notice", "relay", relayURL, "notice", string(*msg))

		case *nostr.EOSEEnvelope:
			p.logger.Debug("nostr relay EOSE", "relay", relayURL, "sub", string(*msg))
		}
	}
}

func (p *Pool) setActiveRelay(url string, rc *relayConn) {
	p.stateMu.Lock()
	p.active[url] = rc
	close(p.stateSignal)
	p.stateSignal = make(chan struct{})
	p.stateMu.Unlock()
}

func (p *Pool) clearActiveRelay(url string, rc *relayConn) {
	p.stateMu.Lock()
	if cur, ok := p.active[url]; ok && cur == rc {
		delete(p.active, url)
		close(p.stateSignal)
		p.stateSignal = make(chan struct{})
	}
	p.stateMu.Unlock()
}

func (p *Pool) handleEvent(ctx context.Context, ev *nostr.Event, relayURL string) {
	msg, ok := p.validateAndDecodeEvent(ev, relayURL)
	if !ok {
		return
	}

	select {
	case p.messages <- msg:
	case <-ctx.Done():
	default:
		p.logger.Warn("dropping incoming message because consumer buffer is full",
			"event_id", msg.EventID,
			"pubkey", msg.PubKey,
			"type", msg.Type,
		)
	}
}

// validateAndDecodeEvent enforces every mandatory Nostr & MeshWatch security rule:
// 1. Kind == 24242
// 2. Valid event ID & Schnorr signature
// 3. PubKey is in allowed_peers
// 4. abs(now - CreatedAt) <= 60s (anti-replay)
// 5. Event ID deduplication across relays
// 6. AES-256-GCM decryption (silent reject on failure)
// 7. JSON payload decoding
func (p *Pool) validateAndDecodeEvent(ev *nostr.Event, relayURL string) (IncomingMessage, bool) {
	if ev == nil || ev.Kind != EventKind {
		return IncomingMessage{}, false
	}

	if !ev.CheckID() {
		p.logger.Debug("rejected event with mismatched ID", "event_id", ev.ID, "relay", relayURL)
		return IncomingMessage{}, false
	}
	validSig, err := ev.CheckSignature()
	if err != nil || !validSig {
		p.logger.Debug("rejected event with invalid Schnorr signature", "event_id", ev.ID, "relay", relayURL)
		return IncomingMessage{}, false
	}

	pubKey := strings.ToLower(ev.PubKey)
	if _, allowed := p.allowedPeers[pubKey]; !allowed {
		p.logger.Debug("rejected event from unauthorized pubkey", "pubkey", pubKey, "event_id", ev.ID)
		return IncomingMessage{}, false
	}

	now := p.now()
	createdAt := ev.CreatedAt.Time()
	skew := now.Sub(createdAt)
	if skew < 0 {
		skew = -skew
	}
	if skew > p.maxSkew {
		p.logger.Debug("rejected event outside anti-replay window",
			"event_id", ev.ID,
			"pubkey", pubKey,
			"skew", skew,
		)
		return IncomingMessage{}, false
	}

	if p.dedupe.SeenOrAdd(ev.ID, now) {
		return IncomingMessage{}, false
	}

	plaintext, err := p.cipher.Decrypt(ev.Content)
	if err != nil {
		// Silent reject per spec on AES-GCM failure.
		p.logger.Debug("silently rejected undecryptable event", "event_id", ev.ID, "pubkey", pubKey)
		return IncomingMessage{}, false
	}

	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(plaintext, &envelope); err != nil {
		p.logger.Debug("rejected event with invalid JSON payload", "event_id", ev.ID, "err", err)
		return IncomingMessage{}, false
	}

	msg := IncomingMessage{
		EventID:    ev.ID,
		PubKey:     pubKey,
		CreatedAt:  createdAt,
		ReceivedAt: now,
		RelayURL:   relayURL,
		Type:       envelope.Type,
		RawJSON:    plaintext,
	}

	switch envelope.Type {
	case TypeHeartbeat:
		var hb HeartbeatPayload
		if err := json.Unmarshal(plaintext, &hb); err != nil {
			p.logger.Debug("rejected malformed heartbeat payload", "event_id", ev.ID, "err", err)
			return IncomingMessage{}, false
		}
		msg.Heartbeat = &hb
	case TypeAlertClaim:
		var claim AlertClaimPayload
		if err := json.Unmarshal(plaintext, &claim); err != nil {
			p.logger.Debug("rejected malformed alert_claim payload", "event_id", ev.ID, "err", err)
			return IncomingMessage{}, false
		}
		claim.TargetPubKey = strings.ToLower(strings.TrimSpace(claim.TargetPubKey))
		msg.AlertClaim = &claim
	default:
		p.logger.Debug("rejected event with unknown payload type", "event_id", ev.ID, "type", envelope.Type)
		return IncomingMessage{}, false
	}

	return msg, true
}

// relayConn wraps a single NIP-01 WebSocket connection with race-free writes and OK tracking.
type relayConn struct {
	url    string
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex

	okMu      sync.Mutex
	pendingOK map[string]chan okResult

	closeOnce sync.Once
}

type okResult struct {
	ok     bool
	reason string
}

func newRelayConn(url string, conn *websocket.Conn, ctx context.Context, cancel context.CancelFunc) *relayConn {
	return &relayConn{
		url:       url,
		conn:      conn,
		ctx:       ctx,
		cancel:    cancel,
		pendingOK: make(map[string]chan okResult),
	}
}

func (rc *relayConn) writeText(ctx context.Context, payload []byte) error {
	rc.writeMu.Lock()
	defer rc.writeMu.Unlock()
	return rc.conn.Write(ctx, websocket.MessageText, payload)
}

func (rc *relayConn) publish(ctx context.Context, ev nostr.Event) error {
	envBytes, err := (&nostr.EventEnvelope{Event: ev}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal EVENT: %w", err)
	}

	ch := make(chan okResult, 1)
	rc.okMu.Lock()
	rc.pendingOK[ev.ID] = ch
	rc.okMu.Unlock()
	defer func() {
		rc.okMu.Lock()
		delete(rc.pendingOK, ev.ID)
		rc.okMu.Unlock()
	}()

	if err := rc.writeText(ctx, envBytes); err != nil {
		return err
	}

	select {
	case res := <-ch:
		if !res.ok {
			return fmt.Errorf("relay rejected event: %s", res.reason)
		}
		return nil
	case <-rc.ctx.Done():
		return errors.New("relay connection closed while awaiting OK")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rc *relayConn) resolveOK(eventID string, ok bool, reason string) {
	rc.okMu.Lock()
	ch, exists := rc.pendingOK[eventID]
	rc.okMu.Unlock()
	if exists {
		select {
		case ch <- okResult{ok: ok, reason: reason}:
		default:
		}
	}
}

func (rc *relayConn) close() {
	rc.closeOnce.Do(func() {
		rc.cancel()
		_ = rc.conn.Close(websocket.StatusNormalClosure, "shutdown")
	})
}

// dedupeCache keeps recently seen Nostr event IDs with bounded memory and TTL eviction.
type dedupeCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	seen       map[string]time.Time
}

func newDedupeCache(ttl time.Duration, maxEntries int) *dedupeCache {
	return &dedupeCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		seen:       make(map[string]time.Time),
	}
}

// SeenOrAdd returns true if id was already recorded and not yet expired.
// Otherwise it records id and returns false.
func (d *dedupeCache) SeenOrAdd(id string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if exp, ok := d.seen[id]; ok {
		if now.Before(exp) {
			return true
		}
		delete(d.seen, id)
	}

	if len(d.seen) >= d.maxEntries {
		for k, exp := range d.seen {
			if !now.Before(exp) {
				delete(d.seen, k)
			}
		}
		if len(d.seen) >= d.maxEntries {
			target := d.maxEntries / 2
			for k := range d.seen {
				delete(d.seen, k)
				if len(d.seen) <= target {
					break
				}
			}
		}
	}

	d.seen[id] = now.Add(d.ttl)
	return false
}
