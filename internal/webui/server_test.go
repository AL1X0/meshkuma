package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"meshwatch/internal/config"
	mwcrypto "meshwatch/internal/crypto"
	"meshwatch/internal/probes"
	"meshwatch/internal/quorum"
	"meshwatch/internal/transport"
)

type mockController struct {
	mu      sync.Mutex
	cfg     *config.Config
	rawYAML string
	muted   bool
	applied int
}

func (m *mockController) Status() RuntimeStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := ""
	pub := ""
	if m.cfg != nil {
		name = m.cfg.Node.Name
		pub = m.cfg.Node.PublicKeyHex
	}
	hbAt := time.Now().Add(-10 * time.Second).UTC()
	return RuntimeStatus{
		Mode:             "running",
		NodeName:         name,
		PublicKeyHex:     pub,
		TopicTag:         "abcdef0123456789",
		StartedAt:        time.Now().Add(-time.Hour),
		LastHeartbeatAt:  &hbAt,
		UptimeSec:        3600,
		HeartbeatSec:     30,
		PeerTimeoutSec:   90,
		OverallOK:        true,
		Muted:            m.muted,
		ProtectedByCount: 1,
		AutoMuteTargets:  []string{"1.1.1.1:443", "9.9.9.9:443"},
		Relays:           []transport.RelayStatus{{URL: "wss://nos.lol", Connected: true}},
		Probes:           []probes.ProbeResult{{ID: "web", Kind: "http", OK: true, Summary: "HTTP 200", Latency: 18}},
		Peers:            []quorum.PeerStatus{{Name: "pote", NodeName: "pote-box", Online: true, EverSeen: true, OverallOK: true}},
	}
}

func (m *mockController) RunProbesNow(_ context.Context) ([]probes.ProbeResult, bool, error) {
	return []probes.ProbeResult{{ID: "web", Kind: "http", OK: true, Summary: "HTTP 200", Latency: 12}}, true, nil
}

func (m *mockController) CurrentConfig() (*config.Config, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg, m.rawYAML
}

func (m *mockController) ApplyConfig(_ context.Context, rawYAML []byte, parsed *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = parsed
	m.rawYAML = string(rawYAML)
	m.applied++
	return nil
}

func (m *mockController) CheckAutoMute(_ context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.muted, nil
}

func TestWebUIServerEndpointsAndAuth(t *testing.T) {
	priv, _, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()
	initialYAML := "node:\n  name: \"homelab-ui\"\n  private_key_hex: \"" + priv + "\"\n  group_psk_hex: \"" + psk + "\"\nnostr:\n  relays:\n    - \"wss://nos.lol\"\n"
	parsed, err := config.Parse([]byte(initialYAML))
	if err != nil {
		t.Fatalf("Parse initial: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	ctrl := &mockController{cfg: parsed, rawYAML: initialYAML}
	srv, err := NewServer(ServerConfig{
		Addr:       "127.0.0.1:0",
		AuthToken:  "super-secret-token",
		ConfigPath: cfgPath,
		Controller: ctrl,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()

	// 1. Unauthorized GET /api/status must fail with 401
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status code = %d, want 401", rec.Code)
	}

	// 2. Authorized GET /api/status returns live snapshot
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth status code = %d, want 200", rec.Code)
	}
	var st RuntimeStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.NodeName != "homelab-ui" || len(st.Probes) != 1 || len(st.Peers) != 1 {
		t.Fatalf("unexpected status: %+v", st)
	}

	// 3. POST /api/keygen without application/json fails with 415 (CSRF guard)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/keygen", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-json POST code = %d, want 415", rec.Code)
	}

	// 4. POST /api/keygen returns valid keys
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/keygen", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("keygen code = %d, want 200", rec.Code)
	}
	var keys map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys["private_key_hex"]) != 64 || len(keys["pubkey_hex"]) != 64 || len(keys["group_psk_hex"]) != 64 || len(keys["topic_tag"]) != 16 {
		t.Fatalf("unexpected keygen response: %+v", keys)
	}

	// 5. PUT /api/config saves to disk and triggers controller reload
	dto := configToDTO(parsed)
	dto.Node.Name = "homelab-renamed"
	payload, _ := json.Marshal(map[string]any{"config": dto})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ctrl.applied != 1 {
		t.Fatalf("expected controller ApplyConfig called once, got %d", ctrl.applied)
	}
	diskBytes, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(diskBytes), "homelab-renamed") {
		t.Fatalf("expected updated config written to %s, err=%v", cfgPath, err)
	}

	// 6. POST /api/test-notify delivers to mock ntfy endpoint
	var ntfyCalled bool
	ntfyMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ntfyCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ntfyMock.Close()

	testPayload, _ := json.Marshal(map[string]any{
		"node_name": "homelab-renamed",
		"notifications": map[string]any{
			"ntfy": map[string]any{"enabled": true, "url": ntfyMock.URL + "/topic"},
		},
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/test-notify", bytes.NewReader(testPayload))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !ntfyCalled {
		t.Fatalf("test-notify failed: code=%d ntfyCalled=%v body=%s", rec.Code, ntfyCalled, rec.Body.String())
	}

	// 6b. POST /api/probes/test verifies a single probe live
	probeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer probeSrv.Close()

	probePayload, _ := json.Marshal(map[string]any{
		"probe": map[string]any{
			"id":              "live-http",
			"kind":            "http",
			"url":             probeSrv.URL,
			"expected_status": 200,
		},
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/probes/test", bytes.NewReader(probePayload))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("probes/test status = %d body=%s", rec.Code, rec.Body.String())
	}
	var pRes probes.ProbeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &pRes); err != nil || !pRes.OK {
		t.Fatalf("probes/test unexpected result: %+v err=%v", pRes, err)
	}

	// 6b-proxmox. POST /api/probes/test verifies Proxmox API probe DTO/validation/check
	pveSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/cluster/resources" && r.Header.Get("Authorization") == "PVEAPIToken=root@pam!mw=sec" {
			_, _ = w.Write([]byte(`{"data":[{"type":"node","node":"pve","status":"online","cpu":0.15,"maxcpu":4,"mem":4,"maxmem":10,"disk":2,"maxdisk":10}]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer pveSrv.Close()

	pvePayload, _ := json.Marshal(map[string]any{
		"probe": map[string]any{
			"id":                   "pve-test",
			"kind":                 "proxmox",
			"url":                  pveSrv.URL,
			"token_id":             "root@pam!mw",
			"token_secret":         "sec",
			"insecure_skip_verify": true,
			"max_cpu_percent":      90,
		},
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/probes/test", bytes.NewReader(pvePayload))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxmox probes/test status = %d body=%s", rec.Code, rec.Body.String())
	}
	var pveRes probes.ProbeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &pveRes); err != nil || !pveRes.OK || !strings.Contains(pveRes.Summary, "pve en ligne") {
		t.Fatalf("proxmox probes/test unexpected result: %+v err=%v", pveRes, err)
	}

	// 6c. POST /api/probes/run triggers immediate refresh
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/probes/run", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("probes/run status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 7. Embedded static assets serve cleanly with security headers
	for _, tc := range []struct {
		path    string
		wantSub string
	}{
		{"/", "<title>MeshWatch</title>"},
		{"/styles.css", "--accent:"},
		{"/app.js", "runDockerScan"},
	} {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, tc.path, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s code = %d, want 200", tc.path, rec.Code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("missing security headers on %s", tc.path)
		}
		if !strings.Contains(rec.Body.String(), tc.wantSub) {
			t.Fatalf("GET %s body missing %q", tc.path, tc.wantSub)
		}
	}
}

func TestIsNonLoopback(t *testing.T) {
	if IsNonLoopback("127.0.0.1:8080") || IsNonLoopback("localhost:8080") || IsNonLoopback("[::1]:8080") {
		t.Fatal("loopback address reported as non-loopback")
	}
	if !IsNonLoopback("0.0.0.0:8080") || !IsNonLoopback(":8080") || !IsNonLoopback("192.168.1.10:8080") {
		t.Fatal("non-loopback address not detected")
	}
}
