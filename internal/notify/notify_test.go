package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshwatch/internal/config"
)

func TestNtfyNotifierHeadersAndStates(t *testing.T) {
	var (
		gotPath     string
		gotTitle    string
		gotPriority string
		gotTags     string
		gotAuth     string
		gotBody     string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotTitle = r.Header.Get("Title")
		gotPriority = r.Header.Get("Priority")
		gotTags = r.Header.Get("Tags")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNtfyNotifier(config.NtfyConfig{
		Enabled: true,
		URL:     srv.URL,
		Topic:   "meshwatch-alerts",
		Token:   "tk_secret123",
	})
	n.backoffs = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}

	ts := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	downAlert := Alert{
		IncidentID: "abc:123",
		State:      StateDown,
		NodeName:   "pote-thomas",
		ProbeID:    "win-srv-01",
		Reason:     "probe_failed:win-srv-01",
		Summary:    "Service VeeamBackup stopped",
		Timestamp:  ts,
		ReportedBy: "homelab-alix",
	}

	if err := n.Send(context.Background(), downAlert); err != nil {
		t.Fatalf("Ntfy Send(DOWN) error = %v", err)
	}
	if gotPath != "/meshwatch-alerts" {
		t.Fatalf("path = %q, want /meshwatch-alerts", gotPath)
	}
	if gotPriority != "urgent" || gotTags != "rotating_light" || gotAuth != "Bearer tk_secret123" {
		t.Fatalf("unexpected headers: priority=%q tags=%q auth=%q", gotPriority, gotTags, gotAuth)
	}
	if !strings.Contains(gotTitle, "DOWN") || !strings.Contains(gotTitle, "pote-thomas") {
		t.Fatalf("unexpected title: %q", gotTitle)
	}
	if !strings.Contains(gotBody, "Service VeeamBackup stopped") || !strings.Contains(gotBody, "2026-11-25T12:00:00Z") {
		t.Fatalf("unexpected body: %q", gotBody)
	}

	resolvedAlert := downAlert
	resolvedAlert.State = StateResolved
	resolvedAlert.Summary = "Services 2/2 running"
	if err := n.Send(context.Background(), resolvedAlert); err != nil {
		t.Fatalf("Ntfy Send(RESOLVED) error = %v", err)
	}
	if gotPriority != "default" || gotTags != "white_check_mark" {
		t.Fatalf("unexpected RESOLVED headers: priority=%q tags=%q", gotPriority, gotTags)
	}
}

func TestPhotonNotifierPayloadHeadersAndRetries(t *testing.T) {
	// Verify default backoff matches spec: 2s, 5s, 10s.
	def := NewPhotonNotifier(config.PhotonConfig{URL: "https://example.test", Recipient: "+33600000000"})
	wantBackoffs := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}
	if len(def.backoffs) != len(wantBackoffs) {
		t.Fatalf("default backoffs = %v, want %v", def.backoffs, wantBackoffs)
	}
	for i := range wantBackoffs {
		if def.backoffs[i] != wantBackoffs[i] {
			t.Fatalf("default backoff[%d] = %v, want %v", i, def.backoffs[i], wantBackoffs[i])
		}
	}

	var attempts atomic.Int32
	var gotAuth string
	var gotPayload map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		gotAuth = r.Header.Get("Authorization")
		if n < 3 {
			// Simulate transient 502/503 errors on attempts 1 and 2.
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("gateway temporarily unavailable"))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotPayload)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sent":true}`))
	}))
	defer srv.Close()

	p := NewPhotonNotifier(config.PhotonConfig{
		Enabled:   true,
		URL:       srv.URL + "/api/v1/message",
		Token:     "photon_api_key",
		Recipient: "+33600000000",
	})
	p.backoffs = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}

	alert := Alert{
		State:      StateDown,
		NodeName:   "homelab-thomas",
		ProbeID:    "syno-nas",
		Reason:     "probe_failed:syno-nas",
		Summary:    "RAID#1 Degraded (11)",
		Timestamp:  time.Now().UTC(),
		ReportedBy: "homelab-alix",
	}

	if err := p.Send(context.Background(), alert); err != nil {
		t.Fatalf("Photon Send() expected success on retry 3, got err = %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
	if gotAuth != "Bearer photon_api_key" {
		t.Fatalf("Authorization = %q, want Bearer photon_api_key", gotAuth)
	}
	if gotPayload["recipient"] != "+33600000000" {
		t.Fatalf("recipient = %q, want +33600000000", gotPayload["recipient"])
	}
	if !strings.Contains(gotPayload["message"], "RAID#1 Degraded (11)") || !strings.Contains(gotPayload["message"], "homelab-thomas") {
		t.Fatalf("unexpected message payload: %q", gotPayload["message"])
	}

	// Verify 4xx does NOT retry (fails immediately after 1 attempt).
	var badReqAttempts atomic.Int32
	srv400 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badReqAttempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv400.Close()

	p400 := NewPhotonNotifier(config.PhotonConfig{URL: srv400.URL, Recipient: "+33600000000"})
	p400.backoffs = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}
	if err := p400.Send(context.Background(), alert); err == nil {
		t.Fatal("expected error on HTTP 401")
	}
	if badReqAttempts.Load() != 1 {
		t.Fatalf("401 attempts = %d, want 1 (must not retry 4xx)", badReqAttempts.Load())
	}

	// Verify persistent 500 exhausts all 3 retries (4 total attempts) and returns error.
	var failAttempts atomic.Int32
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failAttempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()

	p500 := NewPhotonNotifier(config.PhotonConfig{URL: srv500.URL, Recipient: "+33600000000"})
	p500.backoffs = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 15 * time.Millisecond}
	if err := p500.Send(context.Background(), alert); err == nil {
		t.Fatal("expected error after exhausting retries on HTTP 500")
	}
	if failAttempts.Load() != 4 {
		t.Fatalf("500 attempts = %d, want 4 (1 initial + 3 retries)", failAttempts.Load())
	}
}
