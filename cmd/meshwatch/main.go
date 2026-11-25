package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"meshwatch/internal/config"
	mwcrypto "meshwatch/internal/crypto"
	"meshwatch/internal/notify"
	"meshwatch/internal/probes"
	"meshwatch/internal/quorum"
	"meshwatch/internal/transport"
	"meshwatch/internal/updater"
	"meshwatch/internal/version"
	"meshwatch/internal/webui"
)

func main() {
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return fmt.Errorf("missing subcommand (expected: run, keygen, test-notify)")
	}

	switch args[0] {
	case "keygen":
		return cmdKeygen(stdout)
	case "run":
		return cmdRun(args[1:], stdout, stderr)
	case "test-notify":
		return cmdTestNotify(args[1:], stdout, stderr)
	case "self-update":
		return cmdSelfUpdate(args[1:], stderr)
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "meshwatch %s (%s)\n", version.Version, version.ShortCommit())
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "MeshWatch — Decentralized P2P Homelab Monitoring over Nostr")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  meshwatch keygen                                           Generate Nostr keypair and 32-byte group PSK")
	fmt.Fprintln(w, "  meshwatch run --config <path> [--ui 127.0.0.1:8080]        Start the MeshWatch monitoring daemon (UI opt-in)")
	fmt.Fprintln(w, "  meshwatch test-notify --config <path>                      Send a test alert to configured notifiers")
}

func cmdKeygen(w io.Writer) error {
	privHex, pubHex, err := mwcrypto.GenerateNostrKeypair()
	if err != nil {
		return err
	}
	pskHex, err := mwcrypto.GeneratePSK()
	if err != nil {
		return err
	}
	c, err := mwcrypto.NewCipherFromString(pskHex)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "# MeshWatch credentials — keep private_key_hex and group_psk_hex secret!")
	fmt.Fprintf(w, "private_key_hex: %q\n", privHex)
	fmt.Fprintf(w, "pubkey_hex:      %q  # Share this with your peers\n", pubHex)
	fmt.Fprintf(w, "group_psk_hex:   %q  # Share out-of-band with your group (one PSK per mesh)\n", pskHex)
	fmt.Fprintf(w, "topic_tag:       %q  # Derived Nostr #t tag\n", c.TopicTag())
	return nil
}

func cmdSelfUpdate(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("self-update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	containerID := fs.String("container", "", "target container ID or name to recreate")
	imageRef := fs.String("image", version.DefaultDockerImage, "updated Docker image reference")
	dockerSocket := fs.String("socket", "/var/run/docker.sock", "Docker Engine socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return updater.RunSelfUpdateHelper(ctx, *dockerSocket, *containerID, *imageRef)
}

func cmdTestNotify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("test-notify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.yaml", "path to MeshWatch YAML configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	multi := notify.BuildFromConfig(cfg.Notifications)
	if multi.Count() == 0 {
		return errors.New("no notification channels are enabled in config (enable ntfy and/or photon_imessage)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alert := notify.Alert{
		IncidentID:   fmt.Sprintf("test:%s:%d", cfg.Node.PublicKeyHex, time.Now().Unix()),
		State:        notify.StateResolved,
		NodeName:     cfg.Node.Name,
		TargetPubKey: cfg.Node.PublicKeyHex,
		ProbeID:      "test-notify",
		Reason:       "manual_test",
		Summary:      "MeshWatch test notification succeeded",
		Timestamp:    time.Now().UTC(),
		ReportedBy:   cfg.Node.Name,
	}

	var errs []error
	for _, ch := range multi.Notifiers() {
		fmt.Fprintf(stdout, "Testing notifier %q... ", ch.Name())
		if err := ch.Send(ctx, alert); err != nil {
			fmt.Fprintf(stdout, "FAILED (%v)\n", err)
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), err))
		} else {
			fmt.Fprintln(stdout, "OK")
		}
	}
	return errors.Join(errs...)
}

func cmdRun(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.yaml", "path to MeshWatch YAML configuration file")
	uiAddr := fs.String("ui", os.Getenv("MESHWATCH_UI_ADDR"), "opt-in local web UI bind address (e.g. 127.0.0.1:8080; empty disables UI)")
	uiToken := fs.String("ui-token", os.Getenv("MESHWATCH_UI_TOKEN"), "optional Bearer token required to access the local web UI")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// Strict CLI-only mode (default): zero HTTP server, fail fast on invalid config.
	if *uiAddr == "" {
		rawBytes, err := os.ReadFile(*configPath)
		if err != nil {
			return fmt.Errorf("read config %q: %w", *configPath, err)
		}
		cfg, err := config.Parse(rawBytes)
		if err != nil {
			return err
		}
		mgr := newAgentManager(ctx, *configPath, stdout)
		defer mgr.Stop()
		if err := mgr.ApplyConfig(ctx, rawBytes, cfg); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}

	// Opt-in local web UI mode: supports Setup Mode if config is missing/placeholder
	// and live hot-reload when saving configuration changes.
	mgr := newAgentManager(ctx, *configPath, stdout)
	defer mgr.Stop()

	rawBytes, readErr := os.ReadFile(*configPath)
	if readErr != nil {
		mgr.setSetupMode("", fmt.Sprintf("read config %q: %v", *configPath, readErr))
	} else {
		cfg, parseErr := config.Parse(rawBytes)
		if parseErr != nil {
			mgr.setSetupMode(string(rawBytes), parseErr.Error())
		} else if startErr := mgr.ApplyConfig(ctx, rawBytes, cfg); startErr != nil {
			mgr.setSetupMode(string(rawBytes), startErr.Error())
		}
	}

	srv, err := webui.NewServer(webui.ServerConfig{
		Addr:       *uiAddr,
		AuthToken:  *uiToken,
		ConfigPath: *configPath,
		Controller: mgr,
		Logger:     mgr.currentLogger(),
	})
	if err != nil {
		return err
	}

	return srv.Serve(ctx)
}

type runningInstance struct {
	cfg               *config.Config
	cipher            *mwcrypto.Cipher
	scheduler         *probes.Scheduler
	pool              *transport.Pool
	engine            *quorum.Engine
	startedAt         time.Time
	lastHeartbeatUnix atomic.Int64
	cancel            context.CancelFunc
	done              chan struct{}
}

type agentManager struct {
	parentCtx  context.Context
	configPath string
	stdout     io.Writer

	mu       sync.Mutex
	cfg      *config.Config
	rawYAML  string
	setupErr string
	inst     *runningInstance
	logger   *slog.Logger
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (sw *syncWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

func newAgentManager(parentCtx context.Context, configPath string, stdout io.Writer) *agentManager {
	sw := &syncWriter{w: stdout}
	return &agentManager{
		parentCtx:  parentCtx,
		configPath: configPath,
		stdout:     sw,
		logger:     newLogger(config.LoggingConfig{Level: "info", Format: "text"}, sw),
	}
}

func (m *agentManager) currentLogger() *slog.Logger {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logger
}

func (m *agentManager) setSetupMode(rawYAML, errMsg string) {
	m.mu.Lock()
	m.rawYAML = rawYAML
	m.setupErr = errMsg
	logger := m.logger
	m.mu.Unlock()
	logger.Warn("starting MeshWatch web UI in setup mode", "config_path", m.configPath, "reason", errMsg)
}

func (m *agentManager) Stop() {
	m.mu.Lock()
	inst := m.inst
	m.inst = nil
	m.mu.Unlock()

	if inst != nil {
		inst.cancel()
		<-inst.done
	}
}

func (m *agentManager) CurrentConfig() (*config.Config, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg, m.rawYAML
}

func (m *agentManager) ApplyConfig(_ context.Context, rawYAML []byte, cfg *config.Config) error {
	logger := newLogger(cfg.Logging, m.stdout)

	cipher, err := mwcrypto.NewCipher(cfg.Node.PSKBytes)
	if err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}

	scheduledProbes, err := probes.BuildFromConfig(cfg.Probes)
	if err != nil {
		return fmt.Errorf("init probes: %w", err)
	}

	allowed := make(map[string]struct{}, len(cfg.Peers))
	for _, p := range cfg.Peers {
		allowed[p.PubKeyHex] = struct{}{}
	}

	pool, err := transport.NewPool(transport.PoolConfig{
		PrivateKeyHex: cfg.Node.PrivateKeyHex,
		PublicKeyHex:  cfg.Node.PublicKeyHex,
		Relays:        cfg.Nostr.Relays,
		AllowedPeers:  allowed,
		Cipher:        cipher,
		Logger:        logger,
	})
	if err != nil {
		return fmt.Errorf("init nostr transport: %w", err)
	}

	notifiers := notify.BuildFromConfig(cfg.Notifications)

	engine := quorum.NewEngine(quorum.EngineConfig{
		SelfNodeName:    cfg.Node.Name,
		SelfPubKeyHex:   cfg.Node.PublicKeyHex,
		PeerTimeout:     cfg.Node.PeerTimeout,
		Peers:           cfg.Peers,
		AutoMuteTargets: cfg.AutoMute.Targets,
		AutoMuteTimeout: cfg.AutoMute.Timeout,
		Publisher:       pool,
		Notifier:        notifiers,
		Logger:          logger,
	})

	scheduler := probes.NewScheduler(scheduledProbes, logger)

	runCtx, cancel := context.WithCancel(m.parentCtx)
	inst := &runningInstance{
		cfg:       cfg,
		cipher:    cipher,
		scheduler: scheduler,
		pool:      pool,
		engine:    engine,
		startedAt: time.Now(),
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	// Swap out previous instance cleanly before starting the new runtime.
	m.mu.Lock()
	prev := m.inst
	m.inst = inst
	m.cfg = cfg
	m.rawYAML = string(rawYAML)
	m.setupErr = ""
	m.logger = logger
	m.mu.Unlock()

	if prev != nil {
		logger.Info("reloading MeshWatch agent with updated configuration")
		prev.cancel()
		<-prev.done
	}

	scheduler.Start(runCtx)
	pool.Start(runCtx)

	logger.Info("MeshWatch agent started",
		"node", cfg.Node.Name,
		"pubkey", cfg.Node.PublicKeyHex,
		"topic_tag", cipher.TopicTag(),
		"relays", len(cfg.Nostr.Relays),
		"peers", len(cfg.Peers),
		"probes", len(cfg.Probes),
		"notifiers", notifiers.Count(),
		"heartbeat_interval", cfg.Node.HeartbeatInterval,
		"peer_timeout", cfg.Node.PeerTimeout,
	)

	go runInstanceLoop(runCtx, inst, logger)
	return nil
}

func runInstanceLoop(ctx context.Context, inst *runningInstance, logger *slog.Logger) {
	defer close(inst.done)
	defer inst.pool.Stop()
	defer inst.scheduler.Stop()
	defer inst.engine.Stop()

	cfg := inst.cfg

	initCtx, initCancel := context.WithTimeout(ctx, 5*time.Second)
	_ = inst.scheduler.WaitInitial(initCtx)
	_ = inst.pool.WaitConnected(initCtx, 1)
	initCancel()

	publishHeartbeat := func() {
		inst.publishHeartbeatNow(ctx, logger)
	}

	if ctx.Err() == nil && inst.pool.ConnectedRelays() > 0 {
		publishHeartbeat()
	}

	hbTicker := time.NewTicker(cfg.Node.HeartbeatInterval)
	defer hbTicker.Stop()

	timeoutInterval := 5 * time.Second
	if cfg.Node.PeerTimeout/3 < timeoutInterval && cfg.Node.PeerTimeout/3 > 0 {
		timeoutInterval = cfg.Node.PeerTimeout / 3
	}
	timeoutTicker := time.NewTicker(timeoutInterval)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("stopping MeshWatch agent instance", "node", cfg.Node.Name)
			return
		case msg, ok := <-inst.pool.Messages():
			if !ok {
				return
			}
			inst.engine.HandleMessage(ctx, msg)
		case <-hbTicker.C:
			publishHeartbeat()
		case <-timeoutTicker.C:
			inst.engine.CheckTimeouts(ctx)
		}
	}
}

func (m *agentManager) Status() webui.RuntimeStatus {
	m.mu.Lock()
	inst := m.inst
	setupErr := m.setupErr
	m.mu.Unlock()

	if inst == nil {
		return webui.RuntimeStatus{
			Mode:           "setup",
			SetupError:     setupErr,
			ConfigPath:     m.configPath,
			ConfigWritable: webui.IsConfigPathWritable(m.configPath),
			OverallOK:      false,
		}
	}

	probeResults, overallOK := inst.scheduler.Snapshot()
	peers := inst.engine.PeerStatuses()
	protectedBy := 0
	for _, p := range peers {
		if p.Online {
			protectedBy++
		}
	}
	var lastHB *time.Time
	if ts := inst.lastHeartbeatUnix.Load(); ts > 0 {
		t := time.Unix(ts, 0).UTC()
		lastHB = &t
	}

	incidents := append(inst.scheduler.Incidents(), inst.engine.Incidents()...)
	sort.Slice(incidents, func(i, j int) bool {
		return incidents[i].TS > incidents[j].TS
	})
	if len(incidents) > 30 {
		incidents = incidents[:30]
	}

	return webui.RuntimeStatus{
		Mode:             "running",
		ConfigPath:       m.configPath,
		ConfigWritable:   webui.IsConfigPathWritable(m.configPath),
		NodeName:         inst.cfg.Node.Name,
		PublicKeyHex:     inst.cfg.Node.PublicKeyHex,
		TopicTag:         inst.cipher.TopicTag(),
		StartedAt:        inst.startedAt,
		LastHeartbeatAt:  lastHB,
		UptimeSec:        int64(time.Since(inst.startedAt).Seconds()),
		HeartbeatSec:     int64(inst.cfg.Node.HeartbeatInterval.Seconds()),
		PeerTimeoutSec:   int64(inst.cfg.Node.PeerTimeout.Seconds()),
		OverallOK:        overallOK,
		Muted:            inst.engine.IsMuted(),
		ProtectedByCount: protectedBy,
		AutoMuteTargets:  append([]string(nil), inst.cfg.AutoMute.Targets...),
		Relays:           inst.pool.RelayStatuses(),
		Probes:           probeResults,
		ProbeHistory:     inst.scheduler.HistorySnapshot(),
		Peers:            peers,
		Incidents:        incidents,
		Notifications: webui.NotificationsStatus{
			NtfyEnabled:   inst.cfg.Notifications.Ntfy.Enabled,
			PhotonEnabled: inst.cfg.Notifications.PhotonIMessage.Enabled,
		},
	}
}

func (inst *runningInstance) publishHeartbeatNow(ctx context.Context, logger *slog.Logger) {
	results, overallOK := inst.scheduler.Snapshot()
	hb := transport.HeartbeatPayload{
		Type:      transport.TypeHeartbeat,
		NodeName:  inst.cfg.Node.Name,
		TS:        time.Now().Unix(),
		UptimeSec: int64(time.Since(inst.startedAt).Seconds()),
		OverallOK: overallOK,
		Probes:    results,
	}
	pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if evID, err := inst.pool.PublishHeartbeat(pubCtx, hb); err != nil {
		if logger != nil {
			logger.Warn("failed to publish heartbeat", "err", err)
		}
	} else {
		inst.lastHeartbeatUnix.Store(time.Now().Unix())
		if logger != nil {
			logger.Debug("heartbeat published",
				"event_id", evID,
				"overall_ok", overallOK,
				"probes", len(results),
				"connected_relays", inst.pool.ConnectedRelays(),
			)
		}
	}
}

func (m *agentManager) RunProbesNow(ctx context.Context) ([]probes.ProbeResult, bool, error) {
	m.mu.Lock()
	inst := m.inst
	logger := m.logger
	m.mu.Unlock()

	if inst == nil {
		return nil, false, errors.New("agent en mode initialisation : enregistrez d'abord une configuration valide")
	}
	results, overallOK := inst.scheduler.RunNow(ctx)
	if inst.pool != nil && inst.pool.ConnectedRelays() > 0 {
		go inst.publishHeartbeatNow(m.parentCtx, logger)
	}
	return results, overallOK, nil
}

func (m *agentManager) CheckAutoMute(ctx context.Context) (bool, error) {
	m.mu.Lock()
	inst := m.inst
	m.mu.Unlock()

	if inst == nil {
		return false, errors.New("agent en mode initialisation : enregistrez d'abord une configuration valide")
	}
	return inst.engine.CheckAutoMute(ctx), nil
}

func newLogger(lc config.LoggingConfig, w io.Writer) *slog.Logger {
	var level slog.Level
	switch lc.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if lc.Format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
