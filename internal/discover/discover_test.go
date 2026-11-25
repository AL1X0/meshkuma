package discover

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanDockerOverUnixSocket(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "mw-disc-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "docker.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Id":     "111111222222333333",
				"Names":  []string{"/stopped-app"},
				"Image":  "nginx:alpine",
				"State":  "exited",
				"Status": "Exited (0) 2 hours ago",
			},
			{
				"Id":     "aaaaaa111111222222",
				"Names":  []string{"/jellyfin"},
				"Image":  "jellyfin/jellyfin:latest",
				"State":  "running",
				"Status": "Up 5 hours (healthy)",
				"Ports":  []map[string]any{{"PrivatePort": 8096, "PublicPort": 8096}},
			},
		})
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	containers, err := ScanDocker(context.Background(), sockPath)
	if err != nil {
		t.Fatalf("ScanDocker error = %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("len(containers) = %d, want 2", len(containers))
	}
	// Running containers must sort before stopped ones.
	if containers[0].Name != "jellyfin" || !containers[0].Running || containers[0].Health != "healthy" {
		t.Fatalf("unexpected first container: %+v", containers[0])
	}
	if containers[1].Name != "stopped-app" || containers[1].Running {
		t.Fatalf("unexpected second container: %+v", containers[1])
	}
}

func TestParsePrivateCIDRGuards(t *testing.T) {
	ips, norm, err := ParsePrivateCIDR("192.168.1.42/24")
	if err != nil {
		t.Fatalf("ParsePrivateCIDR valid error = %v", err)
	}
	if norm != "192.168.1.0/24" || len(ips) != 254 {
		t.Fatalf("got norm=%q len=%d, want 192.168.1.0/24 len=254", norm, len(ips))
	}

	// Reject public internet CIDR.
	if _, _, err := ParsePrivateCIDR("8.8.8.0/24"); err == nil {
		t.Fatal("expected public CIDR to be rejected")
	}

	// Reject overly wide subnet (/16).
	if _, _, err := ParsePrivateCIDR("192.168.0.0/16"); err == nil {
		t.Fatal("expected /16 CIDR to be rejected")
	}
}

func TestScanLANDiscoversLocalHTTPService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Jellyfin Media</title></head><body>OK</body></html>"))
	}))
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	var port int
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}

	res, err := ScanLAN(context.Background(), "127.0.0.1/32", ScanOptions{
		DialTimeout: 500 * time.Millisecond,
		HTTPTimeout: 1 * time.Second,
		Workers:     4,
		Ports:       []int{port},
	})
	if err != nil {
		t.Fatalf("ScanLAN error = %v", err)
	}
	if res.ScannedIPs != 1 || len(res.Items) != 1 {
		t.Fatalf("unexpected scan result: %+v", res)
	}
	item := res.Items[0]
	if item.Name != "Jellyfin Media" || item.SuggestedProbe.Kind != "http" || item.SuggestedProbe.ExpectedStatus != 200 {
		t.Fatalf("unexpected discovered item: %+v", item)
	}
}
