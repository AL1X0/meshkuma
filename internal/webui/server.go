package webui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"meshwatch/internal/config"
	mwcrypto "meshwatch/internal/crypto"
	"meshwatch/internal/discover"
	"meshwatch/internal/notify"
	"meshwatch/internal/probes"
	"meshwatch/internal/quorum"
	"meshwatch/internal/transport"
	"meshwatch/internal/updater"
	"meshwatch/internal/version"
)

//go:embed static/*
var staticFS embed.FS

const maxAPIBodyBytes = 1 << 20 // 1 MiB

// NotificationsStatus summarizes enabled outbound alert channels.
type NotificationsStatus struct {
	NtfyEnabled   bool `json:"ntfy_enabled"`
	PhotonEnabled bool `json:"photon_enabled"`
}

// RuntimeStatus is the live snapshot returned by GET /api/status.
type RuntimeStatus struct {
	Mode            string                  `json:"mode"`
	SetupError      string                  `json:"setup_error,omitempty"`
	Version         string                  `json:"version"`
	Commit          string                  `json:"commit"`
	ConfigPath      string                  `json:"config_path"`
	ConfigWritable  bool                    `json:"config_writable"`
	NodeName        string                  `json:"node_name"`
	PublicKeyHex    string                  `json:"pubkey_hex"`
	TopicTag        string                  `json:"topic_tag"`
	StartedAt       time.Time               `json:"started_at"`
	UptimeSec       int64                   `json:"uptime_sec"`
	HeartbeatSec    int64                   `json:"heartbeat_interval_sec"`
	PeerTimeoutSec  int64                   `json:"peer_timeout_sec"`
	OverallOK       bool                    `json:"overall_ok"`
	Muted           bool                    `json:"muted"`
	AutoMuteTargets []string                `json:"auto_mute_targets"`
	Relays          []transport.RelayStatus `json:"relays"`
	Probes          []probes.ProbeResult    `json:"probes"`
	Peers           []quorum.PeerStatus     `json:"peers"`
	Notifications   NotificationsStatus     `json:"notifications"`
}

// RuntimeController bridges the embedded HTTP UI to the running MeshWatch agent.
type RuntimeController interface {
	Status() RuntimeStatus
	CurrentConfig() (*config.Config, string)
	ApplyConfig(ctx context.Context, rawYAML []byte, parsed *config.Config) error
	CheckAutoMute(ctx context.Context) (bool, error)
}

// ServerConfig configures the opt-in local HTTP configuration UI.
type ServerConfig struct {
	Addr       string
	AuthToken  string
	ConfigPath string
	Controller RuntimeController
	Updater    *updater.Updater
	Logger     *slog.Logger
}

// Server serves the embedded single-page configuration and status console.
type Server struct {
	addr       string
	authToken  string
	configPath string
	controller RuntimeController
	updater    *updater.Updater
	logger     *slog.Logger
	handler    http.Handler
}

// NewServer constructs a web UI Server. It does not start listening until Serve is called.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Controller == nil {
		return nil, errors.New("webui server requires a RuntimeController")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	upd := cfg.Updater
	if upd == nil {
		upd = updater.New(updater.Config{})
	}

	s := &Server{
		addr:       cfg.Addr,
		authToken:  strings.TrimSpace(cfg.AuthToken),
		configPath: cfg.ConfigPath,
		controller: cfg.Controller,
		updater:    upd,
		logger:     logger,
	}

	subStatic, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("init embedded static fs: %w", err)
	}
	fileServer := http.FileServer(http.FS(subStatic))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/check", s.handleAuthCheck)
	mux.HandleFunc("GET /api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /api/config", s.requireAuth(s.handleGetConfig))
	mux.HandleFunc("PUT /api/config", s.requireAuth(s.requireJSON(s.handlePutConfig)))
	mux.HandleFunc("POST /api/validate", s.requireAuth(s.requireJSON(s.handleValidate)))
	mux.HandleFunc("POST /api/keygen", s.requireAuth(s.requireJSON(s.handleKeygen)))
	mux.HandleFunc("POST /api/test-notify", s.requireAuth(s.requireJSON(s.handleTestNotify)))
	mux.HandleFunc("POST /api/probes/test", s.requireAuth(s.requireJSON(s.handleTestProbe)))
	mux.HandleFunc("POST /api/check-automute", s.requireAuth(s.requireJSON(s.handleCheckAutoMute)))
	mux.HandleFunc("GET /api/discover/info", s.requireAuth(s.handleDiscoverInfo))
	mux.HandleFunc("POST /api/discover/docker", s.requireAuth(s.requireJSON(s.handleDiscoverDocker)))
	mux.HandleFunc("POST /api/discover/lan", s.requireAuth(s.requireJSON(s.handleDiscoverLAN)))
	mux.HandleFunc("GET /api/update/check", s.requireAuth(s.handleUpdateCheck))
	mux.HandleFunc("POST /api/update/apply", s.requireAuth(s.requireJSON(s.handleUpdateApply)))
	mux.Handle("/", s.serveStatic(fileServer))

	s.handler = s.withSecurityHeaders(mux)
	return s, nil
}

// Handler returns the HTTP handler (useful for httptest unit tests).
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Serve binds to cfg.Addr and serves until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	if IsNonLoopback(s.addr) && s.authToken == "" {
		s.logger.Warn("web UI is listening on a non-loopback address without --ui-token; consider setting --ui-token or binding to 127.0.0.1",
			"ui_addr", s.addr,
		)
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen web UI on %q: %w", s.addr, err)
	}

	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("MeshWatch local web UI listening",
			"url", "http://"+ln.Addr().String(),
			"auth_enabled", s.authToken != "",
		)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) serveStatic(fsHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, http.StatusNotFound, "unknown API endpoint")
			return
		}
		// Never cache embedded UI assets so browser picks up updates cleanly in a single reload.
		w.Header().Set("Cache-Control", "no-store")
		fsHandler.ServeHTTP(w, r)
	})
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) checkToken(r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	supplied := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		supplied = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	} else if hdr := r.Header.Get("X-MeshWatch-Token"); hdr != "" {
		supplied = strings.TrimSpace(hdr)
	}
	if len(supplied) != len(s.authToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(s.authToken)) == 1
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkToken(r) {
			writeJSONError(w, http.StatusUnauthorized, "authentication required: invalid or missing UI token")
			return
		}
		next(w, r)
	}
}

func (s *Server) requireJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
		if !strings.HasPrefix(ct, "application/json") {
			writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_required": s.authToken != "",
		"authenticated": s.checkToken(r),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	st := s.controller.Status()
	if st.Version == "" {
		st.Version = version.Version
	}
	if st.Commit == "" {
		st.Commit = version.ShortCommit()
	}
	if st.Relays == nil {
		st.Relays = []transport.RelayStatus{}
	}
	if st.Probes == nil {
		st.Probes = []probes.ProbeResult{}
	}
	if st.Peers == nil {
		st.Peers = []quorum.PeerStatus{}
	}
	if st.AutoMuteTargets == nil {
		st.AutoMuteTargets = []string{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	cfg, rawYAML := s.controller.CurrentConfig()
	dto := configToDTO(cfg)
	if strings.TrimSpace(rawYAML) == "" {
		if generated, err := dtoToYAML(dto); err == nil {
			rawYAML = string(generated)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":      dto,
		"yaml":        rawYAML,
		"config_path": s.configPath,
		"writable":    IsConfigPathWritable(s.configPath),
	})
}

type configMutationRequest struct {
	Config *ConfigDTO `json:"config,omitempty"`
	YAML   string     `json:"yaml,omitempty"`
}

func decodeConfigMutation(r *http.Request) ([]byte, *config.Config, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("read request body: %w", err)
	}
	var req configMutationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON payload: %w", err)
	}

	var rawYAML []byte
	switch {
	case req.Config != nil:
		rawYAML, err = dtoToYAML(*req.Config)
		if err != nil {
			return nil, nil, err
		}
	case strings.TrimSpace(req.YAML) != "":
		rawYAML = []byte(req.YAML)
	default:
		return nil, nil, errors.New("request must include either 'config' or 'yaml'")
	}

	parsed, err := config.Parse(rawYAML)
	if err != nil {
		return rawYAML, nil, err
	}
	return rawYAML, parsed, nil
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	rawYAML, parsed, err := decodeConfigMutation(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"valid":  false,
			"errors": splitErrors(err),
			"error":  err.Error(),
		})
		return
	}
	cipher, _ := mwcrypto.NewCipher(parsed.Node.PSKBytes)
	topicTag := ""
	if cipher != nil {
		topicTag = cipher.TopicTag()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":      true,
		"pubkey_hex": parsed.Node.PublicKeyHex,
		"topic_tag":  topicTag,
		"config":     configToDTO(parsed),
		"yaml":       string(rawYAML),
	})
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	rawYAML, parsed, err := decodeConfigMutation(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"saved":  false,
			"errors": splitErrors(err),
			"error":  err.Error(),
		})
		return
	}

	persisted := true
	persistErr := ""
	if s.configPath != "" {
		if err := WriteConfigFile(s.configPath, rawYAML); err != nil {
			persisted = false
			persistErr = err.Error()
		}
	}

	if err := s.controller.ApplyConfig(r.Context(), rawYAML, parsed); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("reload agent failed: %v", err))
		return
	}

	cipher, _ := mwcrypto.NewCipher(parsed.Node.PSKBytes)
	topicTag := ""
	if cipher != nil {
		topicTag = cipher.TopicTag()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"saved":         true,
		"persisted":     persisted,
		"persist_error": persistErr,
		"reloaded":      true,
		"pubkey_hex":    parsed.Node.PublicKeyHex,
		"topic_tag":     topicTag,
		"config":        configToDTO(parsed),
		"yaml":          string(rawYAML),
	})
}

func (s *Server) handleKeygen(w http.ResponseWriter, _ *http.Request) {
	privHex, pubHex, err := mwcrypto.GenerateNostrKeypair()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pskHex, err := mwcrypto.GeneratePSK()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c, err := mwcrypto.NewCipherFromString(pskHex)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"private_key_hex": privHex,
		"pubkey_hex":      pubHex,
		"group_psk_hex":   pskHex,
		"topic_tag":       c.TopicTag(),
	})
}

type testNotifyRequest struct {
	Notifications *NotificationsDTO `json:"notifications,omitempty"`
	NodeName      string            `json:"node_name,omitempty"`
}

type channelTestResult struct {
	Channel   string `json:"channel"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBodyBytes))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req testNotifyRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
	}

	curCfg, _ := s.controller.CurrentConfig()
	var notifCfg config.NotificationsConfig
	nodeName := "meshwatch"
	pubKey := ""

	if curCfg != nil {
		notifCfg = curCfg.Notifications
		nodeName = curCfg.Node.Name
		pubKey = curCfg.Node.PublicKeyHex
	}
	if req.NodeName != "" {
		nodeName = strings.TrimSpace(req.NodeName)
	}
	if req.Notifications != nil {
		notifCfg = config.NotificationsConfig{
			Ntfy: config.NtfyConfig{
				Enabled: req.Notifications.Ntfy.Enabled,
				URL:     strings.TrimSpace(req.Notifications.Ntfy.URL),
				Topic:   strings.TrimSpace(req.Notifications.Ntfy.Topic),
				Token:   strings.TrimSpace(req.Notifications.Ntfy.Token),
			},
			PhotonIMessage: config.PhotonConfig{
				Enabled:        req.Notifications.PhotonIMessage.Enabled,
				Mode:           strings.TrimSpace(req.Notifications.PhotonIMessage.Mode),
				URL:            strings.TrimSpace(req.Notifications.PhotonIMessage.URL),
				ProjectID:      strings.TrimSpace(req.Notifications.PhotonIMessage.ProjectID),
				APIKey:         strings.TrimSpace(req.Notifications.PhotonIMessage.APIKey),
				ServerURL:      strings.TrimSpace(req.Notifications.PhotonIMessage.ServerURL),
				SenderID:       strings.TrimSpace(req.Notifications.PhotonIMessage.SenderID),
				SpaceID:        strings.TrimSpace(req.Notifications.PhotonIMessage.SpaceID),
				Token:          strings.TrimSpace(req.Notifications.PhotonIMessage.Token),
				Recipient:      strings.TrimSpace(req.Notifications.PhotonIMessage.Recipient),
				RecipientField: strings.TrimSpace(req.Notifications.PhotonIMessage.RecipientField),
				MessageField:   strings.TrimSpace(req.Notifications.PhotonIMessage.MessageField),
			},
		}
	}

	multi := notify.BuildFromConfig(notifCfg)
	if multi.Count() == 0 {
		writeJSONError(w, http.StatusBadRequest, "aucun canal de notification activé (activez ntfy ou photon_imessage)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	alert := notify.Alert{
		IncidentID:   fmt.Sprintf("ui-test:%d", time.Now().Unix()),
		State:        notify.StateResolved,
		NodeName:     nodeName,
		TargetPubKey: pubKey,
		ProbeID:      "ui-test",
		Reason:       "manual_test",
		Summary:      "Test envoyé depuis l'interface locale MeshWatch",
		Timestamp:    time.Now().UTC(),
		ReportedBy:   nodeName,
	}

	results := make([]channelTestResult, 0, multi.Count())
	allOK := true
	for _, ch := range multi.Notifiers() {
		start := time.Now()
		err := ch.Send(ctx, alert)
		res := channelTestResult{
			Channel:   ch.Name(),
			OK:        err == nil,
			LatencyMs: time.Since(start).Milliseconds(),
		}
		if err != nil {
			allOK = false
			res.Error = err.Error()
		}
		results = append(results, res)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      allOK,
		"results": results,
	})
}

func (s *Server) handleTestProbe(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBodyBytes))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "impossible de lire la requête")
		return
	}
	var req struct {
		Probe *ProbeDTO `json:"probe"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Probe == nil {
		writeJSONError(w, http.StatusBadRequest, "paramètres du service invalides")
		return
	}
	p := *req.Probe
	if strings.TrimSpace(p.ID) == "" {
		p.ID = "test-service"
	}

	probeWrapper := ConfigDTO{
		Node: NodeDTO{
			Name:          "test-probe",
			PrivateKeyHex: "0000000000000000000000000000000000000000000000000000000000000001",
			GroupPSKHex:   "0000000000000000000000000000000000000000000000000000000000000002",
		},
		Nostr:  NostrDTO{Relays: []string{"wss://nos.lol"}},
		Probes: []ProbeDTO{p},
	}
	raw, err := dtoToYAML(probeWrapper)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := config.Parse(raw)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	built, err := probes.BuildFromConfig(parsed.Probes)
	if err != nil || len(built) == 0 {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("service invalide : %v", err))
		return
	}

	timeout := built[0].Timeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	res := built[0].Probe.Check(ctx)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCheckAutoMute(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	muted, err := s.controller.CheckAutoMute(ctx)
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	st := s.controller.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"muted":   muted,
		"targets": st.AutoMuteTargets,
	})
}

func (s *Server) preferredDockerSocket() string {
	cfg, _ := s.controller.CurrentConfig()
	if cfg != nil {
		for _, p := range cfg.Probes {
			if p.Kind == "docker" && strings.TrimSpace(p.Socket) != "" {
				return strings.TrimSpace(p.Socket)
			}
		}
	}
	return config.DefaultDockerSocket
}

func (s *Server) configuredProbeHosts() []string {
	cfg, _ := s.controller.CurrentConfig()
	if cfg == nil {
		return nil
	}
	var hosts []string
	for _, p := range cfg.Probes {
		if p.Host != "" {
			hosts = append(hosts, p.Host)
		}
		if p.URL != "" {
			hosts = append(hosts, p.URL)
		}
		if p.Address != "" {
			hosts = append(hosts, p.Address)
		}
	}
	return hosts
}

func (s *Server) handleDiscoverInfo(w http.ResponseWriter, _ *http.Request) {
	sock := s.preferredDockerSocket()
	dockerOK := false
	if strings.HasPrefix(sock, "tcp://") || strings.HasPrefix(sock, "http://") || strings.HasPrefix(sock, "https://") {
		dockerOK = true
	} else if _, err := os.Stat(strings.TrimPrefix(sock, "unix://")); err == nil {
		dockerOK = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"default_subnet":   discover.DetectDefaultSubnet(s.configuredProbeHosts()),
		"docker_socket":    sock,
		"docker_available": dockerOK,
	})
}

func (s *Server) handleDiscoverDocker(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Socket string `json:"socket,omitempty"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if len(strings.TrimSpace(string(body))) > 0 {
		_ = json.Unmarshal(body, &req)
	}
	sock := strings.TrimSpace(req.Socket)
	if sock == "" {
		sock = s.preferredDockerSocket()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	containers, err := discover.ScanDocker(ctx, sock)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	monitored := make(map[string]bool)
	if cfg, _ := s.controller.CurrentConfig(); cfg != nil {
		for _, p := range cfg.Probes {
			if p.Kind == "docker" {
				for _, name := range p.Containers {
					monitored[strings.TrimPrefix(strings.TrimSpace(name), "/")] = true
				}
			}
		}
	}

	type containerEntry struct {
		discover.DockerContainer
		Monitored bool `json:"monitored"`
	}
	items := make([]containerEntry, 0, len(containers))
	for _, c := range containers {
		items = append(items, containerEntry{
			DockerContainer: c,
			Monitored:       monitored[c.Name] || monitored[c.ID],
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"socket":     sock,
		"containers": items,
	})
}

func (s *Server) handleDiscoverLAN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subnet string `json:"subnet,omitempty"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "requête JSON invalide")
			return
		}
	}
	subnet := strings.TrimSpace(req.Subnet)
	if subnet == "" {
		subnet = discover.DetectDefaultSubnet(s.configuredProbeHosts())
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	res, err := discover.ScanLAN(ctx, subnet, discover.ScanOptions{})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	existingTargets := make(map[string]bool)
	if cfg, _ := s.controller.CurrentConfig(); cfg != nil {
		for _, p := range cfg.Probes {
			if p.URL != "" {
				existingTargets[strings.TrimRight(strings.ToLower(p.URL), "/")] = true
			}
			if p.Host != "" {
				existingTargets[fmt.Sprintf("%s:%s:%d", p.Kind, strings.ToLower(p.Host), p.Port)] = true
				if p.Kind == "synology" {
					existingTargets["synology:"+strings.ToLower(p.Host)] = true
				}
			}
		}
	}

	type lanEntry struct {
		discover.DiscoveredItem
		AlreadyMonitored bool `json:"already_monitored"`
	}
	out := make([]lanEntry, 0, len(res.Items))
	for _, item := range res.Items {
		sp := item.SuggestedProbe
		dup := false
		if sp.URL != "" && existingTargets[strings.TrimRight(strings.ToLower(sp.URL), "/")] {
			dup = true
		}
		if sp.Kind == "synology" && existingTargets["synology:"+strings.ToLower(sp.Host)] {
			dup = true
		}
		if sp.Host != "" && existingTargets[fmt.Sprintf("%s:%s:%d", sp.Kind, strings.ToLower(sp.Host), sp.Port)] {
			dup = true
		}
		out = append(out, lanEntry{
			DiscoveredItem:   item,
			AlreadyMonitored: dup,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"subnet":      res.Subnet,
		"scanned_ips": res.ScannedIPs,
		"duration_ms": res.DurationMs,
		"items":       out,
	})
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	res, err := s.updater.Check(ctx, force)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":           err.Error(),
			"current_version": res.CurrentVersion,
			"current_commit":  res.CurrentCommit,
			"can_auto_update": res.CanAutoUpdate,
		})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Image string `json:"image,omitempty"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if len(strings.TrimSpace(string(body))) > 0 {
		_ = json.Unmarshal(body, &req)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	if err := s.updater.ApplyDockerUpdate(ctx, req.Image); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"updating": true,
		"message":  "Mise à jour lancée : le conteneur va redémarrer automatiquement.",
	})
}

// WriteConfigFile saves YAML to path safely (0600 permissions).
// It attempts an atomic temp-file rename first, falling back to direct write
// when target is a Docker single-file bind mount (where rename returns EBUSY/EXDEV).
func WriteConfigFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, ".meshwatch-config-*.tmp")
	if err == nil {
		tmpName := tmp.Name()
		_, wErr := tmp.Write(data)
		cErr := tmp.Close()
		chErr := os.Chmod(tmpName, 0o600)
		if wErr == nil && cErr == nil && chErr == nil {
			if rErr := os.Rename(tmpName, path); rErr == nil {
				return nil
			}
		}
		_ = os.Remove(tmpName)
	}

	// Fallback for bind-mounted single files inside Docker containers.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

// IsConfigPathWritable checks if the config path can be created or opened for writing.
func IsConfigPathWritable(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return false
		}
		f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if openErr != nil {
			return false
		}
		_ = f.Close()
		return true
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mw-writecheck-*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(name)
	return true
}

// IsNonLoopback reports whether addr binds to a non-loopback network interface.
func IsNonLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func splitErrors(err error) []string {
	lines := strings.Split(err.Error(), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
