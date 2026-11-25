package notify

import (
	"context"
	"encoding/base64"
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
		NodeName:   "ami-nord",
		ProbeID:    "win-srv-01",
		Reason:     "probe_failed:win-srv-01",
		Summary:    "Service VeeamBackup stopped",
		Timestamp:  ts,
		ReportedBy: "mon-homelab",
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
	if !strings.Contains(gotTitle, "DOWN") || !strings.Contains(gotTitle, "ami-nord") {
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
		NodeName:   "homelab-nord",
		ProbeID:    "syno-nas",
		Reason:     "probe_failed:syno-nas",
		Summary:    "RAID#1 Degraded (11)",
		Timestamp:  time.Now().UTC(),
		ReportedBy: "mon-homelab",
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
	if !strings.Contains(gotPayload["message"], "RAID#1 Degraded (11)") || !strings.Contains(gotPayload["message"], "homelab-nord") {
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

func TestPhotonProxyModeFormat(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"data":{}}`))
	}))
	defer srv.Close()

	p := NewPhotonNotifier(config.PhotonConfig{
		Enabled:   true,
		Mode:      "proxy",
		URL:       srv.URL,
		ServerURL: "https://mac.example.com",
		APIKey:    "secret-mac-key",
		Recipient: "+33612345678",
	})
	p.backoffs = []time.Duration{5 * time.Millisecond}

	err := p.Send(context.Background(), Alert{
		IncidentID: "inc-proxy-1",
		State:      StateDown,
		NodeName:   "homelab-nord",
		ProbeID:    "nas",
		Summary:    "Disk alert",
		Timestamp:  time.Now().UTC(),
		ReportedBy: "mon-homelab",
	})
	if err != nil {
		t.Fatalf("proxy Send() error = %v", err)
	}
	if gotPath != "/send" {
		t.Fatalf("path = %q, want /send", gotPath)
	}
	// base64("https://mac.example.com|secret-mac-key")
	wantAuth := "Bearer aHR0cHM6Ly9tYWMuZXhhbXBsZS5jb218c2VjcmV0LW1hYy1rZXk="
	if gotAuth != wantAuth {
		t.Fatalf("Authorization = %q, want %q", gotAuth, wantAuth)
	}
	if gotBody["to"] != "+33612345678" || !strings.Contains(gotBody["text"], "Disk alert") {
		t.Fatalf("unexpected proxy payload: %+v", gotBody)
	}
}

func TestPhotonCloudV1AutoResolveAndSend(t *testing.T) {
	var sentCount atomic.Int32
	var gotIdem, gotVer, gotAuth string
	var gotMsg map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/pho_prj_01test/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": "pho_usr_agent1", "kind": "agent", "platform": "imessage", "handle": "+14155550100"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/pho_prj_01test/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "pho_usr_peer1", "kind": "user", "platform": "imessage", "handle": "+33612345678",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/pho_prj_01test/spaces":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "pho_spc_direct1", "platform": "imessage",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/pho_prj_01test/messages":
			sentCount.Add(1)
			gotIdem = r.Header.Get("Idempotency-Key")
			gotVer = r.Header.Get("Photon-Version")
			_ = json.NewDecoder(r.Body).Decode(&gotMsg)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"pho_msg_1"}`))
		default:
			t.Errorf("unexpected Photon Cloud call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := NewPhotonNotifier(config.PhotonConfig{
		Enabled:   true,
		Mode:      "cloud",
		URL:       srv.URL + "/v1",
		ProjectID: "pho_prj_01test",
		APIKey:    "pho_sk_testkey",
		Recipient: "+33612345678",
	})
	p.backoffs = []time.Duration{5 * time.Millisecond}

	err := p.Send(context.Background(), Alert{
		IncidentID: "inc:cloud:42",
		State:      StateDown,
		NodeName:   "homelab-sud",
		ProbeID:    "syno",
		Summary:    "Temp 62C",
		Timestamp:  time.Now().UTC(),
		ReportedBy: "mon-homelab",
	})
	if err != nil {
		t.Fatalf("cloud Send() error = %v", err)
	}
	if sentCount.Load() != 1 {
		t.Fatalf("sentCount = %d, want 1", sentCount.Load())
	}
	if gotAuth != "Bearer pho_sk_testkey" || gotVer != photonAPIVersion || gotIdem != "mw:down:inc:cloud:42" {
		t.Fatalf("unexpected headers: auth=%q ver=%q idem=%q", gotAuth, gotVer, gotIdem)
	}
	if gotMsg["spaceId"] != "pho_spc_direct1" || gotMsg["senderId"] != "pho_usr_agent1" {
		t.Fatalf("unexpected cloud message target: %+v", gotMsg)
	}
	content, _ := gotMsg["content"].(map[string]any)
	if content["type"] != "text" || content["format"] != "plain" || !strings.Contains(content["text"].(string), "Temp 62C") {
		t.Fatalf("unexpected cloud content: %+v", content)
	}
}

func TestPhotonSpectrumSharedGRPCSend(t *testing.T) {
	projectUUID := "00000000-1111-4222-8333-444444444444"
	secret := "test_spectrum_secret_key"
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(projectUUID+":"+secret))

	var gotBasicAuth, gotTokenPath, gotGRPCAuth, gotIdem, gotChatGUID, gotText, gotClientMsgID string

	spectrumAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokenPath = r.URL.Path
		gotBasicAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"succeed": true,
			"data": map[string]any{
				"type":      "shared",
				"token":     "light_auth_tok_shared",
				"expiresIn": 3600,
			},
		})
	}))
	defer spectrumAPI.Close()

	grpcSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2 gRPC request, got HTTP/%d.%d", r.ProtoMajor, r.ProtoMinor)
		}
		if r.URL.Path != "/photon.imessage.v1.MessageService/SendTextMessage" {
			t.Errorf("unexpected gRPC path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotGRPCAuth = r.Header.Get("Authorization")
		gotIdem = r.Header.Get("x-idempotency-key")
		body, _ := io.ReadAll(r.Body)
		if msg, ok := unframeGRPC(body); ok {
			if b, ok := readProtoFieldBytes(msg, 1); ok {
				gotChatGUID = string(b)
			}
			if b, ok := readProtoFieldBytes(msg, 2); ok {
				gotText = string(b)
			}
			if b, ok := readProtoFieldBytes(msg, 100); ok {
				gotClientMsgID = string(b)
			}
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frameGRPC(nil))
		w.Header().Set("Grpc-Status", "0")
	}))
	grpcSrv.EnableHTTP2 = true
	grpcSrv.StartTLS()
	defer grpcSrv.Close()

	// Intentionally pass legacy Beta URL with UUID ProjectID to verify automatic Stable routing.
	p := NewPhotonNotifier(config.PhotonConfig{
		Enabled:   true,
		Mode:      "cloud",
		URL:       "https://api.photon.codes/v1",
		ProjectID: projectUUID,
		APIKey:    secret,
		Recipient: "+33600000001",
	})
	if p.isBeta2Cloud() {
		t.Fatal("UUID project with non-pho_sk secret must route to Stable/Spectrum even with legacy Beta URL")
	}
	p.endpoint = spectrumAPI.URL
	p.spectrumIMessageBaseURL = grpcSrv.URL
	p.grpcClient = grpcSrv.Client()
	p.backoffs = []time.Duration{5 * time.Millisecond}

	err := p.Send(context.Background(), Alert{
		IncidentID: "ui-test:123",
		State:      StateResolved,
		NodeName:   "mon-homelab",
		Summary:    "Test notification",
		Timestamp:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Spectrum shared Send() error = %v", err)
	}
	if gotTokenPath != "/projects/"+projectUUID+"/imessage/tokens" {
		t.Fatalf("token path = %q", gotTokenPath)
	}
	if gotBasicAuth != wantBasic {
		t.Fatalf("Basic auth = %q, want %q", gotBasicAuth, wantBasic)
	}
	if gotGRPCAuth != "Bearer light_auth_tok_shared" {
		t.Fatalf("gRPC auth = %q", gotGRPCAuth)
	}
	if gotChatGUID != "iMessage;-;+33600000001" {
		t.Fatalf("chat_guid = %q, want iMessage;-;+33600000001", gotChatGUID)
	}
	if !strings.Contains(gotText, "Test notification") || gotIdem != "mw:resolved:ui-test:123" || gotClientMsgID != gotIdem {
		t.Fatalf("unexpected gRPC payload text=%q idem=%q clientMsgID=%q", gotText, gotIdem, gotClientMsgID)
	}
}

func TestPhotonSpectrumDedicatedGRPCSend(t *testing.T) {
	projectUUID := "11111111-2222-4333-8444-555555555555"
	var sawCreateChat, sawSendText bool
	var gotChatGUID string

	spectrumAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"succeed": true,
			"data": map[string]any{
				"type":      "dedicated",
				"auth":      map[string]string{"inst-01": "light_tok_ded"},
				"numbers":   map[string]string{"inst-01": "+14155550199"},
				"expiresIn": 3600,
			},
		})
	}))
	defer spectrumAPI.Close()

	grpcSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		switch r.URL.Path {
		case "/photon.imessage.v1.ChatService/CreateChat":
			sawCreateChat = true
			// Build CreateChatResponse{chat: Chat{guid: "iMessage;-;test@icloud.com"}}
			chatMsg := appendProtoStringField(nil, 1, "iMessage;-;test@icloud.com")
			var respMsg []byte
			respMsg = appendProtoVarint(respMsg, (1<<3)|2)
			respMsg = appendProtoVarint(respMsg, uint64(len(chatMsg)))
			respMsg = append(respMsg, chatMsg...)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(frameGRPC(respMsg))
			w.Header().Set("Grpc-Status", "0")
		case "/photon.imessage.v1.MessageService/SendTextMessage":
			sawSendText = true
			if msg, ok := unframeGRPC(body); ok {
				if b, ok := readProtoFieldBytes(msg, 1); ok {
					gotChatGUID = string(b)
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(frameGRPC(nil))
			w.Header().Set("Grpc-Status", "0")
		default:
			t.Errorf("unexpected gRPC method: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	grpcSrv.EnableHTTP2 = true
	grpcSrv.StartTLS()
	defer grpcSrv.Close()

	p := NewPhotonNotifier(config.PhotonConfig{
		Enabled:   true,
		Mode:      "spectrum",
		URL:       spectrumAPI.URL,
		ProjectID: projectUUID,
		APIKey:    "ded_secret",
		Recipient: "test@icloud.com",
	})
	p.spectrumIMessageBaseURL = grpcSrv.URL
	p.grpcClient = grpcSrv.Client()
	p.backoffs = []time.Duration{5 * time.Millisecond}

	if err := p.Send(context.Background(), Alert{IncidentID: "ded-1", State: StateDown, Summary: "Alert"}); err != nil {
		t.Fatalf("dedicated Send() error = %v", err)
	}
	if !sawCreateChat || !sawSendText || gotChatGUID != "iMessage;-;test@icloud.com" {
		t.Fatalf("createChat=%v sendText=%v chatGUID=%q", sawCreateChat, sawSendText, gotChatGUID)
	}
}

func TestPhotonSpectrumGRPCErrorTrailer(t *testing.T) {
	spectrumAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"succeed": true,
			"data":    map[string]any{"type": "shared", "token": "tok", "expiresIn": 3600},
		})
	}))
	defer spectrumAPI.Close()

	grpcSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Grpc-Status", "7")
		w.Header().Set("Grpc-Message", "Send%20first%20message%20to%20shared%20line")
	}))
	grpcSrv.EnableHTTP2 = true
	grpcSrv.StartTLS()
	defer grpcSrv.Close()

	p := NewPhotonNotifier(config.PhotonConfig{
		Enabled:   true,
		Mode:      "cloud",
		URL:       spectrumAPI.URL,
		ProjectID: "22222222-3333-4444-8555-666666666666",
		APIKey:    "sec",
		Recipient: "+33600000001",
	})
	p.spectrumIMessageBaseURL = grpcSrv.URL
	p.grpcClient = grpcSrv.Client()
	p.backoffs = []time.Duration{5 * time.Millisecond}

	err := p.Send(context.Background(), Alert{IncidentID: "err-1", State: StateDown, Summary: "Test"})
	if err == nil || !strings.Contains(err.Error(), "gRPC 7") || !strings.Contains(err.Error(), "shared line") {
		t.Fatalf("expected decoded gRPC 7 error, got %v", err)
	}
}
