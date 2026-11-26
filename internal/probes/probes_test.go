package probes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshwatch/internal/config"
)

type stubProbe struct {
	id    string
	kind  string
	delay time.Duration
	fn    func(ctx context.Context) ProbeResult
}

func (s *stubProbe) ID() string   { return s.id }
func (s *stubProbe) Kind() string { return s.kind }
func (s *stubProbe) Check(ctx context.Context) ProbeResult {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ProbeResult{ID: s.id, Kind: s.kind, OK: false, Summary: "timeout: " + ctx.Err().Error()}
		}
	}
	return s.fn(ctx)
}

func TestSchedulerConcurrencyAndTimeoutIsolation(t *testing.T) {
	var toggle atomic.Bool
	toggle.Store(true)

	fast := &stubProbe{
		id:   "fast",
		kind: "tcp",
		fn: func(ctx context.Context) ProbeResult {
			return ProbeResult{ID: "fast", Kind: "tcp", OK: toggle.Load(), Summary: "fast ok"}
		},
	}
	slow := &stubProbe{
		id:    "slow",
		kind:  "http",
		delay: 2 * time.Second, // exceeds per-probe timeout
		fn: func(ctx context.Context) ProbeResult {
			return ProbeResult{ID: "slow", Kind: "http", OK: true, Summary: "should have timed out"}
		},
	}

	sched := NewScheduler([]ScheduledProbe{
		{Probe: fast, Interval: 50 * time.Millisecond, Timeout: 500 * time.Millisecond},
		{Probe: slow, Interval: 500 * time.Millisecond, Timeout: 80 * time.Millisecond},
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sched.Start(ctx)
	defer sched.Stop()

	if err := sched.WaitInitial(ctx); err != nil {
		t.Fatalf("WaitInitial: %v", err)
	}

	results, overallOK := sched.Snapshot()
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if results[0].ID != "fast" || !results[0].OK {
		t.Fatalf("expected fast probe OK, got %+v", results[0])
	}
	if results[1].ID != "slow" || results[1].OK || !strings.Contains(results[1].Summary, "timeout") {
		t.Fatalf("expected slow probe timeout failure, got %+v", results[1])
	}
	if overallOK {
		t.Fatal("expected overallOK = false when slow probe timed out")
	}
}

func TestSchedulerRunNow(t *testing.T) {
	var okState atomic.Bool
	okState.Store(true)

	p := &stubProbe{
		id:   "instant",
		kind: "http",
		fn: func(ctx context.Context) ProbeResult {
			return ProbeResult{ID: "instant", Kind: "http", OK: okState.Load(), Summary: "instant check"}
		},
	}

	sched := NewScheduler([]ScheduledProbe{
		{Probe: p, Interval: time.Minute, Timeout: 2 * time.Second},
	}, nil)

	results, overallOK := sched.RunNow(context.Background())
	if !overallOK || len(results) != 1 || !results[0].OK {
		t.Fatalf("expected immediate RunNow OK, got overall=%v results=%+v", overallOK, results)
	}

	okState.Store(false)
	results, overallOK = sched.RunNow(context.Background())
	if overallOK || len(results) != 1 || results[0].OK {
		t.Fatalf("expected updated false state after RunNow, got overall=%v results=%+v", overallOK, results)
	}
	hist := sched.HistorySnapshot()["instant"]
	if len(hist) < 2 {
		t.Fatalf("expected >= 2 history points recorded, got %d", len(hist))
	}
}

func makeSelfSignedCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestHTTPProbeStatusContainsAndTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("MeshWatch service healthy"))
		case "/bad-status":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("unexpected content"))
		}
	}))
	defer srv.Close()

	minDays := 0
	pOK := NewHTTPProbe(config.ProbeConfig{
		ID: "web-ok", Kind: "http", URL: srv.URL + "/ok", ExpectedStatus: 200, Contains: "healthy", TLSMinDays: &minDays,
	})
	res := pOK.Check(context.Background())
	if !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}

	pBadStatus := NewHTTPProbe(config.ProbeConfig{
		ID: "web-503", Kind: "http", URL: srv.URL + "/bad-status", ExpectedStatus: 200, TLSMinDays: &minDays,
	})
	res = pBadStatus.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "503") {
		t.Fatalf("expected 503 failure, got %+v", res)
	}

	pMissingKeyword := NewHTTPProbe(config.ProbeConfig{
		ID: "web-kw", Kind: "http", URL: srv.URL + "/other", ExpectedStatus: 200, Contains: "healthy", TLSMinDays: &minDays,
	})
	res = pMissingKeyword.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "missing") {
		t.Fatalf("expected keyword failure, got %+v", res)
	}

	// TLS certificate expiration check (valid for 10 days from now).
	now := time.Now()
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tlsSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{makeSelfSignedCert(t, now.Add(-time.Hour), now.Add(10*24*time.Hour))},
	}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()

	// Require 14 days -> must FAIL (only ~9-10 days left).
	req14 := 14
	pTLSFail := NewHTTPProbe(config.ProbeConfig{
		ID: "tls-fail", Kind: "http", URL: tlsSrv.URL, ExpectedStatus: 200, TLSMinDays: &req14, InsecureSkipVerify: true,
	})
	pTLSFail.now = func() time.Time { return now }
	res = pTLSFail.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "TLS cert expires") {
		t.Fatalf("expected TLS expiry failure, got %+v", res)
	}

	// Require 5 days -> must PASS.
	req5 := 5
	pTLSOK := NewHTTPProbe(config.ProbeConfig{
		ID: "tls-ok", Kind: "http", URL: tlsSrv.URL, ExpectedStatus: 200, TLSMinDays: &req5, InsecureSkipVerify: true,
	})
	pTLSOK.now = func() time.Time { return now }
	res = pTLSOK.Check(context.Background())
	if !res.OK || !strings.Contains(res.Summary, "TLS") {
		t.Fatalf("expected TLS OK, got %+v", res)
	}
}

func TestTCPProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	p := NewTCPProbe(config.ProbeConfig{ID: "tcp-ok", Kind: "tcp", Address: addr})
	if res := p.Check(context.Background()); !res.OK {
		t.Fatalf("expected TCP OK, got %+v", res)
	}

	_ = ln.Close()
	if res := p.Check(context.Background()); res.OK {
		t.Fatalf("expected TCP failure after listener closed, got %+v", res)
	}
}

func TestDockerProbeUnixSocketAndTCPProxy(t *testing.T) {
	containersPayload := []dockerContainerSummary{
		{
			ID:     "aaa111222333",
			Names:  []string{"/jellyfin"},
			State:  "running",
			Status: "Up 3 hours (healthy)",
			Labels: map[string]string{"meshwatch.enable": "true"},
		},
		{
			ID:     "bbb111222333",
			Names:  []string{"/traefik"},
			State:  "running",
			Status: "Up 2 hours (unhealthy)",
			Labels: map[string]string{"meshwatch.enable": "true"},
		},
		{
			ID:     "ccc111222333",
			Names:  []string{"/homeassistant"},
			State:  "exited",
			Status: "Exited (1) 2 minutes ago",
			Labels: map[string]string{"meshwatch.enable": "false"},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/containers/json":
			_ = json.NewEncoder(w).Encode(containersPayload)
		case r.URL.Path == "/containers/aaa111222333/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"RestartCount": 5,
				"State":        map[string]any{"Status": "running"},
			})
		default:
			http.NotFound(w, r)
		}
	})

	// 1. Test over a real Unix domain socket (short path under /tmp for AF_UNIX 108-byte sun_path limit).
	sockDir, err := os.MkdirTemp("/tmp", "mw-dock-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "d.sock")
	unixLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	unixSrv := &http.Server{Handler: handler}
	go func() { _ = unixSrv.Serve(unixLn) }()
	defer unixSrv.Close()

	pOK, err := NewDockerProbe(config.ProbeConfig{
		ID: "dock-ok", Kind: "docker", Socket: sockPath, Containers: []string{"jellyfin"},
	})
	if err != nil {
		t.Fatalf("NewDockerProbe: %v", err)
	}
	res := pOK.Check(context.Background())
	if !res.OK || res.Summary != "1/1 up" {
		t.Fatalf("expected 1/1 up, got %+v", res)
	}

	// Check MaxRestarts failure on jellyfin (RestartCount = 5 > 3).
	pRestarts, _ := NewDockerProbe(config.ProbeConfig{
		ID: "dock-restarts", Kind: "docker", Socket: sockPath, Containers: []string{"jellyfin"}, MaxRestarts: 3,
	})
	res = pRestarts.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "restarts=5") {
		t.Fatalf("expected restart threshold failure, got %+v", res)
	}

	// 2. Test over tcp:// socket-proxy with unhealthy, exited, and missing containers.
	tcpSrv := httptest.NewServer(handler)
	defer tcpSrv.Close()
	tcpAddr := "tcp://" + strings.TrimPrefix(tcpSrv.URL, "http://")

	pIssues, err := NewDockerProbe(config.ProbeConfig{
		ID: "dock-fail", Kind: "docker", Socket: tcpAddr, Containers: []string{"jellyfin", "traefik", "homeassistant", "ghost"},
	})
	if err != nil {
		t.Fatalf("NewDockerProbe tcp: %v", err)
	}
	res = pIssues.Check(context.Background())
	if res.OK {
		t.Fatalf("expected failure, got %+v", res)
	}
	for _, want := range []string{"1/4 up", "traefik (unhealthy)", "homeassistant (exited)", "ghost (missing)"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary %q missing %q", res.Summary, want)
		}
	}

	// 3. Test label-based selection (meshwatch.enable=true matches jellyfin & traefik -> traefik unhealthy).
	pLabel, _ := NewDockerProbe(config.ProbeConfig{
		ID: "dock-label", Kind: "docker", Socket: tcpAddr, Label: "meshwatch.enable=true",
	})
	res = pLabel.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "1/2 up") || !strings.Contains(res.Summary, "traefik (unhealthy)") {
		t.Fatalf("unexpected label probe result: %+v", res)
	}
}

type mockSNMPClient struct {
	getVars  []SNMPVariable
	walkVars map[string][]SNMPVariable
	getErr   error
	walkErr  error
}

func (m *mockSNMPClient) Get(_ context.Context, _ []string) ([]SNMPVariable, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getVars, nil
}

func (m *mockSNMPClient) Walk(_ context.Context, rootOID string) ([]SNMPVariable, error) {
	if m.walkErr != nil {
		return nil, m.walkErr
	}
	return m.walkVars[rootOID], nil
}

func TestSynologySNMPProbe(t *testing.T) {
	healthyMock := &mockSNMPClient{
		getVars: []SNMPVariable{
			{OID: synoOIDSystemStatus, Value: 1},
			{OID: synoOIDTemperature, Value: 36},
			{OID: synoOIDSystemFan, Value: 1},
			{OID: synoOIDPowerFan, Value: 1},
		},
		walkVars: map[string][]SNMPVariable{
			synoOIDRAIDStatus: {
				{OID: synoOIDRAIDStatus + ".0", Value: 1},
			},
			synoOIDDiskStatus: {
				{OID: synoOIDDiskStatus + ".0", Value: 1},
				{OID: synoOIDDiskStatus + ".1", Value: 1},
			},
		},
	}

	pOK := NewSynologyProbeWithClient(config.ProbeConfig{ID: "syno-ds920", MaxTempC: 55}, healthyMock)
	res := pOK.Check(context.Background())
	if !res.OK || !strings.Contains(res.Summary, "RAID OK") || !strings.Contains(res.Summary, "36°C") {
		t.Fatalf("expected healthy Synology result, got %+v", res)
	}

	degradedMock := &mockSNMPClient{
		getVars: []SNMPVariable{
			{OID: synoOIDSystemStatus, Value: 2},
			{OID: synoOIDTemperature, Value: 64},
			{OID: synoOIDSystemFan, Value: 2},
			{OID: synoOIDPowerFan, Value: 1},
		},
		walkVars: map[string][]SNMPVariable{
			synoOIDRAIDStatus: {
				{OID: synoOIDRAIDStatus + ".0", Value: 11},
			},
			synoOIDDiskStatus: {
				{OID: synoOIDDiskStatus + ".0", Value: 1},
				{OID: synoOIDDiskStatus + ".1", Value: 5},
			},
		},
	}

	pFail := NewSynologyProbeWithClient(config.ProbeConfig{ID: "syno-ds920", MaxTempC: 55}, degradedMock)
	res = pFail.Check(context.Background())
	if res.OK {
		t.Fatalf("expected failed Synology result, got %+v", res)
	}
	for _, want := range []string{"System failed", "64°C > 55°C", "System fan failed", "RAID#1 Degraded", "Disk#2 Crashed"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary %q missing %q", res.Summary, want)
		}
	}

	errMock := &mockSNMPClient{getErr: errors.New("udp timeout")}
	pErr := NewSynologyProbeWithClient(config.ProbeConfig{ID: "syno-err", MaxTempC: 55}, errMock)
	res = pErr.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "udp timeout") {
		t.Fatalf("expected SNMP error failure, got %+v", res)
	}
}

func TestSNMPOIDProbe(t *testing.T) {
	maxVal := 80.0
	minVal := 10.0

	pRangeOK := NewSNMPOIDProbeWithClient(config.ProbeConfig{
		ID: "ups-load", OID: ".1.3.6.1.2.1.33.1.4.4.1.5.1", MinValue: &minVal, MaxValue: &maxVal,
	}, &mockSNMPClient{getVars: []SNMPVariable{{OID: ".1.3.6.1.2.1.33.1.4.4.1.5.1", Value: 42}}})
	if res := pRangeOK.Check(context.Background()); !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}

	pRangeHigh := NewSNMPOIDProbeWithClient(config.ProbeConfig{
		ID: "ups-load", OID: ".1.3.6.1.2.1.33.1.4.4.1.5.1", MaxValue: &maxVal,
	}, &mockSNMPClient{getVars: []SNMPVariable{{OID: ".1.3.6.1.2.1.33.1.4.4.1.5.1", Value: 95}}})
	if res := pRangeHigh.Check(context.Background()); res.OK || !strings.Contains(res.Summary, "> max") {
		t.Fatalf("expected max threshold failure, got %+v", res)
	}

	pExact := NewSNMPOIDProbeWithClient(config.ProbeConfig{
		ID: "status-oid", OID: ".1.3.6.1.4.1.9999.1.0", ExpectedValue: "online",
	}, &mockSNMPClient{getVars: []SNMPVariable{{OID: ".1.3.6.1.4.1.9999.1.0", Value: "offline"}}})
	if res := pExact.Check(context.Background()); res.OK || !strings.Contains(res.Summary, "expected") {
		t.Fatalf("expected exact mismatch failure, got %+v", res)
	}
}

func TestNodeExporterProbe(t *testing.T) {
	metricsOK := `
# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 1.6e+10
node_memory_MemAvailable_bytes 8.0e+09
node_filesystem_size_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 100000000000
node_filesystem_avail_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 40000000000
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1000000000
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 10000000
`
	metricsHigh := `
node_memory_MemTotal_bytes 10000000000
node_memory_MemAvailable_bytes 500000000
node_filesystem_size_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 100000000000
node_filesystem_avail_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 5000000000
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/high" {
			_, _ = w.Write([]byte(metricsHigh))
			return
		}
		_, _ = w.Write([]byte(metricsOK))
	}))
	defer srv.Close()

	pOK := NewNodeExporterProbe(config.ProbeConfig{
		ID: "srv-linux", URL: srv.URL + "/ok", MaxRAMPercent: 92, MaxDiskPercent: 90,
	})
	res := pOK.Check(context.Background())
	if !res.OK || !strings.Contains(res.Summary, "RAM 50%") || !strings.Contains(res.Summary, "Disk / 60%") {
		t.Fatalf("expected healthy node_exporter result, got %+v", res)
	}

	pFail := NewNodeExporterProbe(config.ProbeConfig{
		ID: "srv-linux", URL: srv.URL + "/high", MaxRAMPercent: 92, MaxDiskPercent: 90,
	})
	res = pFail.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "RAM 95.0%") || !strings.Contains(res.Summary, "Disk / 95.0%") {
		t.Fatalf("expected RAM+Disk threshold failure, got %+v", res)
	}
}

func TestWindowsExporterProbe(t *testing.T) {
	metricsOK := `
# TYPE windows_memory_physical_total_bytes gauge
windows_memory_physical_total_bytes 34359738368
windows_memory_physical_free_bytes 17179869184
windows_logical_disk_size_bytes{volume="C:"} 500000000000
windows_logical_disk_free_bytes{volume="C:"} 200000000000
windows_logical_disk_size_bytes{volume="HarddiskVolume1"} 500000000
windows_logical_disk_free_bytes{volume="HarddiskVolume1"} 1000000
windows_service_state{name="w32time",state="running"} 1
windows_service_state{name="w32time",state="stopped"} 0
windows_service_state{name="veeambackupsvc",state="running"} 1
windows_service_state{name="veeambackupsvc",state="stopped"} 0
`
	metricsStopped := `
windows_memory_physical_total_bytes 34359738368
windows_memory_physical_free_bytes 17179869184
windows_logical_disk_size_bytes{volume="C:"} 500000000000
windows_logical_disk_free_bytes{volume="C:"} 20000000000
windows_service_state{name="w32time",state="running"} 1
windows_service_state{name="veeambackupsvc",state="running"} 0
windows_service_state{name="veeambackupsvc",state="stopped"} 1
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			_, _ = w.Write([]byte(metricsStopped))
			return
		}
		_, _ = w.Write([]byte(metricsOK))
	}))
	defer srv.Close()

	pOK := NewWindowsExporterProbe(config.ProbeConfig{
		ID:             "srv-windows",
		URL:            srv.URL + "/ok",
		Services:       []string{"W32Time", "VeeamBackupSvc"},
		MaxDiskPercent: 90,
		MaxRAMPercent:  90,
	})
	res := pOK.Check(context.Background())
	if !res.OK || !strings.Contains(res.Summary, "Services 2/2 running") {
		t.Fatalf("expected healthy windows_exporter result, got %+v", res)
	}

	pFail := NewWindowsExporterProbe(config.ProbeConfig{
		ID:             "srv-windows",
		URL:            srv.URL + "/fail",
		Services:       []string{"W32Time", "VeeamBackupSvc"},
		MaxDiskPercent: 90,
	})
	res = pFail.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "Service VeeamBackupSvc stopped") || !strings.Contains(res.Summary, "Disk C: 96.0%") {
		t.Fatalf("expected stopped service + full disk failure, got %+v", res)
	}
}

func TestProxmoxProbe(t *testing.T) {
	healthyResources := `{
  "data": [
    {"type": "node", "node": "pve", "status": "online", "cpu": 0.24, "maxcpu": 8, "mem": 8589934592, "maxmem": 17179869184, "disk": 10000000000, "maxdisk": 50000000000, "uptime": 123456},
    {"type": "storage", "node": "pve", "storage": "local", "status": "available", "disk": 20000000000, "maxdisk": 100000000000, "shared": 0},
    {"type": "storage", "node": "pve", "storage": "local-lvm", "status": "available", "disk": 250000000000, "maxdisk": 500000000000, "shared": 0},
    {"type": "qemu", "node": "pve", "vmid": 100, "name": "homeassistant", "status": "running", "template": 0},
    {"type": "lxc", "node": "pve", "vmid": 102, "name": "reverse-proxy", "status": "running", "template": 0},
    {"type": "qemu", "node": "pve", "vmid": 9000, "name": "ubuntu-tpl", "status": "stopped", "template": 1}
  ]
}`

	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			switch r.Header.Get("Authorization") {
			case "PVEAPIToken=root@pam!meshwatch=secret-uuid":
				_, _ = w.Write([]byte(healthyResources))
			case "PVEAPIToken=monitor@pve!ro=abc-123":
				_, _ = w.Write([]byte(healthyResources))
			case "PVEAPIToken=root@pam!bad=wrong":
				w.WriteHeader(http.StatusUnauthorized)
			case "PVEAPIToken=root@pam!empty=nodata":
				_, _ = w.Write([]byte(`{"data":[]}`))
			case "PVEAPIToken=root@pam!nodesonly=fb":
				_, _ = w.Write([]byte(`{"data":[]}`))
			case "PVEAPIToken=root@pam!noperm=stub":
				_, _ = w.Write([]byte(`{"data":[{"type":"node","node":"pve","status":"online"}]}`))
			case "PVEAPIToken=root@pam!fail=cases":
				_, _ = w.Write([]byte(`{
  "data": [
    {"type": "node", "node": "pve1", "status": "offline", "cpu": 0, "maxcpu": 8, "mem": 0, "maxmem": 100, "disk": 0, "maxdisk": 100},
    {"type": "node", "node": "pve2", "status": "online", "cpu": 0.95, "maxcpu": 8, "mem": 95, "maxmem": 100, "disk": 20, "maxdisk": 100},
    {"type": "storage", "node": "pve2", "storage": "nas-nfs", "status": "unknown", "disk": 96, "maxdisk": 100, "shared": 1},
    {"type": "qemu", "node": "pve2", "vmid": 100, "name": "homeassistant", "status": "stopped", "template": 0}
  ]
}`))
			default:
				w.WriteHeader(http.StatusForbidden)
			}
		case "/api2/json/nodes":
			if r.Header.Get("Authorization") == "PVEAPIToken=root@pam!nodesonly=fb" {
				_, _ = w.Write([]byte(`{"data":[{"node":"pve-fb","status":"online","cpu":0.18,"maxcpu":4,"mem":20,"maxmem":100,"disk":30,"maxdisk":100}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// 1. Healthy cluster/resources + VMID and name matching + template excluded
	pOK := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-main",
		URL:                srv.URL,
		TokenID:            "root@pam!meshwatch",
		TokenSecret:        "secret-uuid",
		InsecureSkipVerify: true,
		MaxCPUPercent:      90,
		MaxRAMPercent:      90,
		MaxDiskPercent:     90,
		VMs:                []string{"100", "reverse-proxy"},
	})
	res := pOK.Check(context.Background())
	if !res.OK {
		t.Fatalf("expected Proxmox healthy OK, got %+v", res)
	}
	if gotAuth != "PVEAPIToken=root@pam!meshwatch=secret-uuid" {
		t.Fatalf("Authorization = %q, want PVEAPIToken=root@pam!meshwatch=secret-uuid", gotAuth)
	}
	for _, want := range []string{"pve en ligne", "CPU 24%", "RAM 50%", "Stockage local-lvm 50%", "2/2 VM/LXC actives"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary %q missing %q", res.Summary, want)
		}
	}

	// 2. Combined token string + trailing /api2/json URL
	pCombined := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-combined",
		URL:                srv.URL + "/api2/json/",
		TokenID:            "PVEAPIToken=monitor@pve!ro=abc-123",
		InsecureSkipVerify: true,
		MaxCPUPercent:      90,
	})
	res = pCombined.Check(context.Background())
	if !res.OK || gotAuth != "PVEAPIToken=monitor@pve!ro=abc-123" {
		t.Fatalf("combined token probe failed: res=%+v auth=%q", res, gotAuth)
	}

	// 3. Failure conditions: offline node, CPU > max, RAM > max, storage unavailable + > max, VM stopped, missing VM
	pFail := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-fail",
		URL:                srv.URL,
		TokenID:            "root@pam!fail",
		TokenSecret:        "cases",
		InsecureSkipVerify: true,
		MaxCPUPercent:      90,
		MaxRAMPercent:      90,
		MaxDiskPercent:     90,
		VMs:                []string{"100", "999"},
	})
	res = pFail.Check(context.Background())
	if res.OK {
		t.Fatalf("expected Proxmox failures, got OK: %+v", res)
	}
	for _, want := range []string{
		"Node pve1 offline",
		"CPU (pve2) 95.0% > 90%",
		"RAM (pve2) 95.0% > 90%",
		"Stockage nas-nfs (pve2) unknown",
		"Stockage nas-nfs 96.0% > 90%",
		"VM/LXC homeassistant (100) stopped",
		"VM/LXC 999 introuvable",
	} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("failure summary %q missing %q", res.Summary, want)
		}
	}

	// 4a. HTTP 401 auth error
	pUnauth := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-unauth",
		URL:                srv.URL,
		TokenID:            "root@pam!bad",
		TokenSecret:        "wrong",
		InsecureSkipVerify: true,
	})
	res = pUnauth.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "HTTP 401") || !strings.Contains(res.Summary, "PVEAuditor") {
		t.Fatalf("expected HTTP 401 guidance, got %+v", res)
	}

	// 4b. Empty /cluster/resources falls back to /nodes when /nodes returns data
	pNodesFB := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-nodes-fb",
		URL:                srv.URL,
		TokenID:            "root@pam!nodesonly",
		TokenSecret:        "fb",
		InsecureSkipVerify: true,
		MaxCPUPercent:      90,
		MaxRAMPercent:      90,
		MaxDiskPercent:     90,
	})
	res = pNodesFB.Check(context.Background())
	if !res.OK || !strings.Contains(res.Summary, "pve-fb en ligne") || !strings.Contains(res.Summary, "Disque root 30%") {
		t.Fatalf("expected /nodes fallback OK, got %+v", res)
	}

	// 4c. Empty /cluster/resources AND empty /nodes returns Privilege Separation guidance
	pEmpty := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-empty",
		URL:                srv.URL,
		TokenID:            "root@pam!empty",
		TokenSecret:        "nodata",
		InsecureSkipVerify: true,
	})
	res = pEmpty.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "Privilege Separation") || !strings.Contains(res.Summary, "PVEAuditor") {
		t.Fatalf("expected Privilege Separation guidance, got %+v", res)
	}

	// 4d. Unprivileged token stub (Privilege Separation without ACL role: only {"type":"node","status":"online"})
	pStub := NewProxmoxProbe(config.ProbeConfig{
		ID:                 "pve-stub",
		URL:                srv.URL,
		TokenID:            "root@pam!noperm",
		TokenSecret:        "stub",
		InsecureSkipVerify: true,
		VMs:                []string{"100", "101"},
	})
	res = pStub.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "PVEAuditor") || !strings.Contains(res.Summary, "Séparation des privilèges") {
		t.Fatalf("expected unprivileged token guidance, got %+v", res)
	}
}

func TestWindowsWinRMProbeWithAndWithoutHyperV(t *testing.T) {
	baseQuery := func(_ context.Context, ns, wql string) ([]map[string]string, error) {
		switch {
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_OperatingSystem"):
			return []map[string]string{{
				"csname":                 "SRV-WIN-LAB",
				"caption":                "Microsoft Windows Server 2022 Standard",
				"totalvisiblememorysize": "16777216",
				"freephysicalmemory":     "8388608",
			}}, nil
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_Processor"):
			return []map[string]string{
				{"loadpercentage": "20"},
				{"loadpercentage": "30"},
			}, nil
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_LogicalDisk"):
			return []map[string]string{
				{"deviceid": "C:", "size": "100000000000", "freespace": "60000000000"},
				{"deviceid": "D:", "size": "500000000000", "freespace": "250000000000"},
			}, nil
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_Service"):
			return []map[string]string{
				{"name": "W32Time", "state": "Running"},
				{"name": "vmms", "state": "Running"},
			}, nil
		case ns == "root/virtualization/v2" && strings.Contains(wql, "Msvm_ComputerSystem"):
			return []map[string]string{
				{"name": "SRV-WIN-LAB", "elementname": "SRV-WIN-LAB", "caption": "Système ordinateur", "enabledstate": "2", "healthstate": "5"},
				{"name": "11111111-2222-3333-4444-555555555555", "elementname": "VM-AD", "caption": "Ordinateur virtuel", "enabledstate": "2", "healthstate": "5"},
				{"name": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "elementname": "VM-TEST", "caption": "Ordinateur virtuel", "enabledstate": "3", "healthstate": "5"},
			}, nil
		}
		return nil, nil
	}

	// 1. Healthy Windows + Hyper-V (critical VM running; another stopped VM does not fail unless in VMs)
	p := NewWindowsWinRMProbe(config.ProbeConfig{
		ID:             "win-hv",
		Kind:           "windows_winrm",
		Host:           "192.168.1.40",
		Port:           5985,
		User:           `CORP\Administrator`,
		Password:       "pw",
		MaxCPUPercent:  90,
		MaxRAMPercent:  90,
		MaxDiskPercent: 90,
		Services:       []string{"w32time", "vmms"},
		VMs:            []string{"vm-ad"},
	})
	p.queryFn = baseQuery
	res := p.Check(context.Background())
	if !res.OK {
		t.Fatalf("expected Windows+Hyper-V OK, got %+v", res)
	}
	for _, want := range []string{"SRV-WIN-LAB", "CPU 25%", "RAM 50%", "Disque D: 50%", "1/2 VM Hyper-V actives", "2/2 services OK"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary %q missing %q", res.Summary, want)
		}
	}

	// 2. Plain Windows without Hyper-V (French or English InvalidNamespace ignored when no VMs required)
	plainQuery := func(ctx context.Context, ns, wql string) ([]map[string]string, error) {
		if ns == "root/virtualization/v2" {
			return nil, errWMIInvalidNamespace
		}
		return baseQuery(ctx, ns, wql)
	}
	pPlain := NewWindowsWinRMProbe(config.ProbeConfig{
		ID:             "win-plain",
		Host:           "192.168.1.41",
		User:           "Administrator",
		Password:       "pw",
		MaxCPUPercent:  90,
		MaxRAMPercent:  90,
		MaxDiskPercent: 90,
	})
	pPlain.queryFn = plainQuery
	res = pPlain.Check(context.Background())
	if !res.OK || strings.Contains(res.Summary, "Hyper-V") {
		t.Fatalf("expected plain Windows OK without Hyper-V mention, got %+v", res)
	}

	// 3. Plain Windows when critical Hyper-V VMs WERE requested -> explicit failure
	pMissingHV := NewWindowsWinRMProbe(config.ProbeConfig{
		ID:       "win-no-hv",
		Host:     "192.168.1.41",
		User:     "Administrator",
		Password: "pw",
		VMs:      []string{"VM-AD"},
	})
	pMissingHV.queryFn = plainQuery
	res = pMissingHV.Check(context.Background())
	if res.OK || !strings.Contains(res.Summary, "Hyper-V non installé") {
		t.Fatalf("expected missing Hyper-V role error, got %+v", res)
	}

	// 4. Threshold breaches, stopped service, stopped/missing Hyper-V VM
	pFail := NewWindowsWinRMProbe(config.ProbeConfig{
		ID:             "win-fail",
		Host:           "192.168.1.40",
		User:           "Administrator",
		Password:       "pw",
		MaxCPUPercent:  20,
		MaxRAMPercent:  40,
		MaxDiskPercent: 45,
		Disks:          []string{"C"},
		Services:       []string{"W32Time", "Spooler"},
		VMs:            []string{"VM-TEST", "VM-MISSING"},
	})
	pFail.queryFn = baseQuery
	res = pFail.Check(context.Background())
	if res.OK {
		t.Fatalf("expected Windows failure result, got OK: %+v", res)
	}
	for _, want := range []string{
		"CPU 25.0% > 20%",
		"RAM 50.0% > 40%",
		"Service Spooler introuvable",
		"VM Hyper-V VM-TEST (arrêtée)",
		"VM Hyper-V VM-MISSING introuvable",
	} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("failure summary %q missing %q", res.Summary, want)
		}
	}
}

func TestWSManXMLParsingAndCredentials(t *testing.T) {
	dom, usr := splitWindowsCredentials(`CONTOSO\admin`, "")
	if dom != "CONTOSO" || usr != "admin" {
		t.Fatalf("splitWindowsCredentials backslash = (%q, %q)", dom, usr)
	}
	dom, usr = splitWindowsCredentials("admin@contoso.local", "")
	if dom != "" || usr != "admin@contoso.local" {
		t.Fatalf("splitWindowsCredentials UPN = (%q, %q)", dom, usr)
	}

	sampleXML := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:n1="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_LogicalDisk">
  <s:Body>
    <n1:EnumerateResponse>
      <w:Items>
        <p:Win32_LogicalDisk>
          <p:DeviceID>C:</p:DeviceID>
          <p:FreeSpace>53687091200</p:FreeSpace>
          <p:Size>107374182400</p:Size>
        </p:Win32_LogicalDisk>
      </w:Items>
      <w:EndOfSequence/>
    </n1:EnumerateResponse>
  </s:Body>
</s:Envelope>`
	parsed, err := parseWSManResponse([]byte(sampleXML))
	if err != nil {
		t.Fatalf("parseWSManResponse: %v", err)
	}
	if !parsed.endOfSequence || len(parsed.rows) != 1 || parsed.rows[0]["deviceid"] != "C:" || parsed.rows[0]["size"] != "107374182400" {
		t.Fatalf("unexpected parsed WS-Man response: %+v", parsed)
	}

	faultXML := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Reason><s:Text xml:lang="fr-FR">Espace de noms non valide</s:Text></s:Reason><s:Detail><f:WSManFault Code="2150858770"><f:Message>L'espace de noms n'est pas valide.</f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>`
	fParsed, err := parseWSManResponse([]byte(faultXML))
	if err != nil {
		t.Fatalf("parseWSManResponse fault: %v", err)
	}
	if !isInvalidNamespaceFault(fParsed.fault, fParsed.faultCode, "root/virtualization/v2") {
		t.Fatalf("expected InvalidNamespace detection for French fault: %+v", fParsed)
	}
}

func TestWindowsWinRMProbeMockHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "":
			w.Header().Add("WWW-Authenticate", "Basic realm=\"WinRM\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		case "Basic QWxpY2U6YmFk": // Alice:bad
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		var bodyBuf [16384]byte
		n, _ := r.Body.Read(bodyBuf[:])
		reqXML := string(bodyBuf[:n])
		switch {
		case strings.Contains(reqXML, "Win32_OperatingSystem"):
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><EnumerateResponse><w:Items><Win32_OperatingSystem><CSName>MOCK-WIN</CSName><TotalVisibleMemorySize>1000</TotalVisibleMemorySize><FreePhysicalMemory>400</FreePhysicalMemory></Win32_OperatingSystem></w:Items><w:EndOfSequence/></EnumerateResponse></s:Body></s:Envelope>`))
		case strings.Contains(reqXML, "Win32_Processor"):
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><EnumerateResponse><w:Items><Win32_Processor><LoadPercentage>15</LoadPercentage></Win32_Processor></w:Items><w:EndOfSequence/></EnumerateResponse></s:Body></s:Envelope>`))
		case strings.Contains(reqXML, "Win32_LogicalDisk"):
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><EnumerateResponse><w:Items><Win32_LogicalDisk><DeviceID>C:</DeviceID><Size>1000</Size><FreeSpace>700</FreeSpace></Win32_LogicalDisk></w:Items><w:EndOfSequence/></EnumerateResponse></s:Body></s:Envelope>`))
		case strings.Contains(reqXML, "Msvm_ComputerSystem"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Detail><WSManFault Code="2147749902"><Message>InvalidNamespace</Message></WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
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

	built, err := BuildFromConfig([]config.ProbeConfig{
		{
			ID:             "win-mock",
			Kind:           "windows_winrm",
			Host:           "127.0.0.1",
			Port:           port,
			User:           "Administrator",
			Password:       "okpass",
			MaxCPUPercent:  90,
			MaxRAMPercent:  90,
			MaxDiskPercent: 90,
		},
		{
			ID:       "win-bad-auth",
			Kind:     "windows_winrm",
			Host:     "127.0.0.1",
			Port:     port,
			User:     "Alice",
			Password: "bad",
		},
	})
	if err != nil {
		t.Fatalf("BuildFromConfig: %v", err)
	}
	res := built[0].Probe.Check(context.Background())
	if !res.OK || !strings.Contains(res.Summary, "MOCK-WIN") || !strings.Contains(res.Summary, "CPU 15%") || !strings.Contains(res.Summary, "RAM 60%") {
		t.Fatalf("unexpected WinRM HTTP mock result: %+v", res)
	}
	resAuth := built[1].Probe.Check(context.Background())
	if resAuth.OK || !strings.Contains(resAuth.Summary, "HTTP 401") {
		t.Fatalf("expected 401 failure, got %+v", resAuth)
	}
}

func TestLinuxSSHProbe(t *testing.T) {
	healthyOutput := strings.Join([]string{
		"HOST=srv-linux-01",
		"STAT1=cpu  1000 0 500 8500 0 0 0 0 0 0",
		"STAT2=cpu  1200 0 600 9200 0 0 0 0 0 0",
		"MEM_MemTotal=1000000",
		"MEM_MemAvailable=400000",
		"DISK=tmpfs tmpfs 102400 1024 101376 1% /run",
		"DISK=overlay overlay 10485760 4000000 6485760 39% /var/lib/docker/overlay2/abc/merged",
		"DISK=/dev/sda1 ext4 104857600 40000000 60000000 40% /",
		"DISK=/dev/sdb1 ext4 209715200 100000000 100000000 50% /data",
		"SVC=docker\tactive",
		"SVC=ssh\tactive",
	}, "\n")

	built, err := BuildFromConfig([]config.ProbeConfig{{
		ID:             "lin-ok",
		Kind:           "linux_ssh",
		Host:           "192.168.1.45",
		Port:           22,
		User:           "monitor",
		Password:       "secret",
		MaxCPUPercent:  90,
		MaxRAMPercent:  90,
		MaxDiskPercent: 90,
		Services:       []string{"docker", "ssh"},
	}})
	if err != nil {
		t.Fatalf("BuildFromConfig(linux_ssh): %v", err)
	}
	p := built[0].Probe.(*LinuxSSHProbe)
	p.runFn = func(_ context.Context, _ string) (string, error) {
		return healthyOutput, nil
	}

	res := p.Check(context.Background())
	if !res.OK {
		t.Fatalf("expected healthy linux_ssh result, got %+v", res)
	}
	for _, want := range []string{"srv-linux-01", "CPU 30%", "RAM 60%", "Disque /data 50%", "2/2 services OK"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary %q missing %q", res.Summary, want)
		}
	}

	// Thresholds + missing disk + inactive service
	pFail := NewLinuxSSHProbe(config.ProbeConfig{
		ID:             "lin-fail",
		Host:           "192.168.1.45",
		User:           "monitor",
		Password:       "secret",
		MaxCPUPercent:  25,
		MaxRAMPercent:  50,
		MaxDiskPercent: 35,
		Disks:          []string{"/", "/mnt/missing"},
		Services:       []string{"docker", "nginx"},
	})
	pFail.runFn = func(_ context.Context, _ string) (string, error) {
		return healthyOutput + "\nSVC=nginx\tinactive\n", nil
	}
	resFail := pFail.Check(context.Background())
	if resFail.OK {
		t.Fatalf("expected failure result, got OK: %+v", resFail)
	}
	for _, want := range []string{"CPU 30.0% > 25%", "RAM 60.0% > 50%", "Disque / 40.0% > 35%", "Disque /mnt/missing introuvable", "Service nginx (inactive)"} {
		if !strings.Contains(resFail.Summary, want) {
			t.Errorf("failure summary %q missing %q", resFail.Summary, want)
		}
	}

	// Auth failure
	pErr := NewLinuxSSHProbe(config.ProbeConfig{ID: "lin-err", Host: "192.168.1.45", User: "monitor", Password: "bad"})
	pErr.runFn = func(_ context.Context, _ string) (string, error) {
		return "", errors.New("ssh: unable to authenticate, attempted methods [none password]")
	}
	resErr := pErr.Check(context.Background())
	if resErr.OK || !strings.Contains(resErr.Summary, "authentification refusée") {
		t.Fatalf("expected French SSH auth error, got %+v", resErr)
	}
}

func TestProbeMetricsAndSchedulerHistory(t *testing.T) {
	// Verify WindowsWinRMProbe structured metrics + Hyper-V guests
	pWin := NewWindowsWinRMProbe(config.ProbeConfig{
		ID:       "win-metrics",
		Host:     "192.168.1.40",
		User:     "Administrator",
		Password: "pw",
		Services: []string{"W32Time"},
	})
	pWin.queryFn = func(_ context.Context, ns, wql string) ([]map[string]string, error) {
		switch {
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_OperatingSystem"):
			return []map[string]string{{"csname": "WIN-SRV", "caption": "Windows Server 2022", "totalvisiblememorysize": "8388608", "freephysicalmemory": "4194304"}}, nil
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_Processor"):
			return []map[string]string{{"loadpercentage": "32"}}, nil
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_LogicalDisk"):
			return []map[string]string{{"deviceid": "C:", "size": "107374182400", "freespace": "53687091200"}}, nil
		case ns == "root/cimv2" && strings.Contains(wql, "Win32_Service"):
			return []map[string]string{{"name": "W32Time", "state": "Running"}}, nil
		case ns == "root/virtualization/v2":
			return []map[string]string{{"name": "11111111-2222-3333-4444-555555555555", "elementname": "VM-AD", "enabledstate": "2", "healthstate": "5"}}, nil
		}
		return nil, nil
	}
	resWin := pWin.Check(context.Background())
	if resWin.Metrics == nil || resWin.Metrics.CPUPercent == nil || *resWin.Metrics.CPUPercent != 32 {
		t.Fatalf("expected Windows CPUPercent=32, got %+v", resWin.Metrics)
	}
	if len(resWin.Metrics.Disks) != 1 || len(resWin.Metrics.Guests) != 1 || len(resWin.Metrics.Services) != 1 {
		t.Fatalf("expected Windows Disks/Guests/Services populated, got %+v", resWin.Metrics)
	}

	// Verify ProbeResult.Metrics is excluded from JSON (Nostr heartbeat backwards-compatibility)
	wire, err := json.Marshal(resWin)
	if err != nil {
		t.Fatalf("json.Marshal(ProbeResult): %v", err)
	}
	if strings.Contains(string(wire), "VM-AD") || strings.Contains(string(wire), "Windows Server 2022") {
		t.Fatalf("ProbeResult JSON leaked Metrics into Nostr wire payload: %s", string(wire))
	}

	// Verify LinuxSSHProbe structured metrics (loadavg + uptime + disks + services)
	pLin := NewLinuxSSHProbe(config.ProbeConfig{
		ID:       "lin-metrics",
		Host:     "192.168.1.45",
		User:     "monitor",
		Password: "pw",
		Services: []string{"ssh"},
	})
	pLin.runFn = func(_ context.Context, _ string) (string, error) {
		return "HOST=lin-srv\nLOAD=0.42 0.35 0.30\nUPTIME=86400.4\nSTAT1=cpu 100 0 100 800 0 0 0 0\nSTAT2=cpu 120 0 120 860 0 0 0 0\nMEM_MemTotal=2048000\nMEM_MemAvailable=1024000\nDISK=/dev/sda1 ext4 104857600 52428800 52428800 50% /\nSVC=ssh\tactive\n", nil
	}
	resLin := pLin.Check(context.Background())
	if resLin.Metrics == nil || resLin.Metrics.LoadAvg != "0.42 0.35 0.30" || resLin.Metrics.UptimeSec != 86400 {
		t.Fatalf("expected Linux LoadAvg + UptimeSec, got %+v", resLin.Metrics)
	}

	// Verify Scheduler records MetricsSnapshot + numeric HistoryPoint metrics
	sched := NewScheduler([]ScheduledProbe{
		{Probe: pWin, Interval: time.Minute, Timeout: 2 * time.Second},
		{Probe: pLin, Interval: time.Minute, Timeout: 2 * time.Second},
	}, nil)
	sched.RunNow(context.Background())

	snap := sched.MetricsSnapshot()
	if snap["win-metrics"] == nil || snap["lin-metrics"] == nil {
		t.Fatalf("expected MetricsSnapshot for both probes, got %+v", snap)
	}
	histWin := sched.HistorySnapshot()["win-metrics"]
	if len(histWin) != 1 || histWin[0].CPUPct == nil || *histWin[0].CPUPct != 32 || histWin[0].RAMPct == nil {
		t.Fatalf("expected numeric CPU/RAM in HistoryPoint, got %+v", histWin)
	}
}
