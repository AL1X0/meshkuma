package kuma

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshwatch/internal/probes"
	"meshwatch/internal/transport"
)

func TestPusherUpAndDown(t *testing.T) {
	var (
		gotStatus string
		gotMsg    string
		gotPing   string
		reqCount  int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		gotStatus = r.URL.Query().Get("status")
		gotMsg = r.URL.Query().Get("msg")
		gotPing = r.URL.Query().Get("ping")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pusher := NewPusher(2 * time.Second)
	pushURL := srv.URL + "/api/push/ABCDEF"

	// 1. Healthy heartbeat -> status=up
	hbUp := &transport.HeartbeatPayload{
		NodeName:  "pote-thomas",
		OverallOK: true,
		Probes: []probes.ProbeResult{
			{ID: "syno", Kind: "synology", OK: true, Summary: "RAID OK"},
			{ID: "dock", Kind: "docker", OK: true, Summary: "5/5 up"},
		},
	}
	if err := pusher.Push(context.Background(), pushURL, hbUp, 42); err != nil {
		t.Fatalf("Push(up) error = %v", err)
	}
	if gotStatus != "up" || gotPing != "42" || !strings.Contains(gotMsg, "2/2") {
		t.Fatalf("unexpected Kuma UP params: status=%q msg=%q ping=%q", gotStatus, gotMsg, gotPing)
	}

	// 2. Failing internal probe -> status=down with failing probe detail in msg
	hbDown := &transport.HeartbeatPayload{
		NodeName:  "pote-thomas",
		OverallOK: false,
		Probes: []probes.ProbeResult{
			{ID: "syno", Kind: "synology", OK: true, Summary: "RAID OK"},
			{ID: "win-srv-01", Kind: "windows_exporter", OK: false, Summary: "Service VeeamBackup stopped"},
		},
	}
	if err := pusher.Push(context.Background(), pushURL, hbDown, -5); err != nil {
		t.Fatalf("Push(down) error = %v", err)
	}
	if gotStatus != "down" || gotPing != "0" || !strings.Contains(gotMsg, "win-srv-01: Service VeeamBackup stopped") {
		t.Fatalf("unexpected Kuma DOWN params: status=%q msg=%q ping=%q", gotStatus, gotMsg, gotPing)
	}
	if reqCount != 2 {
		t.Fatalf("reqCount = %d, want 2", reqCount)
	}
}

func TestPusherReturnsErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pusher := NewPusher(2 * time.Second)
	err := pusher.Push(context.Background(), srv.URL+"/api/push/XYZ", &transport.HeartbeatPayload{OverallOK: true}, 10)
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}
