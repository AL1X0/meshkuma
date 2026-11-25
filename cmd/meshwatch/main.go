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
	"syscall"
	"time"

	"meshwatch/internal/config"
	mwcrypto "meshwatch/internal/crypto"
	"meshwatch/internal/kuma"
	"meshwatch/internal/notify"
	"meshwatch/internal/probes"
	"meshwatch/internal/quorum"
	"meshwatch/internal/transport"
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
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "MeshWatch — Decentralized P2P Monitoring over Nostr + Uptime Kuma")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  meshwatch keygen                           Generate Nostr keypair and 32-byte group PSK")
	fmt.Fprintln(w, "  meshwatch run --config <config.yaml>       Start the MeshWatch monitoring daemon")
	fmt.Fprintln(w, "  meshwatch test-notify --config <path>      Send a test alert to configured notifiers")
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger := newLogger(cfg.Logging, stdout)
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	return runAgent(ctx, cfg, logger)
}

func runAgent(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	startedAt := time.Now()

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
	kumaPusher := kuma.NewPusher(5 * time.Second)

	engine := quorum.NewEngine(quorum.EngineConfig{
		SelfNodeName:    cfg.Node.Name,
		SelfPubKeyHex:   cfg.Node.PublicKeyHex,
		PeerTimeout:     cfg.Node.PeerTimeout,
		Peers:           cfg.Peers,
		AutoMuteTargets: cfg.AutoMute.Targets,
		AutoMuteTimeout: cfg.AutoMute.Timeout,
		Publisher:       pool,
		Kuma:            kumaPusher,
		Notifier:        notifiers,
		Logger:          logger,
	})
	defer engine.Stop()

	scheduler := probes.NewScheduler(scheduledProbes, logger)
	scheduler.Start(ctx)
	defer scheduler.Stop()

	pool.Start(ctx)
	defer pool.Stop()

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

	// Give probes & relays a brief startup window before sending the initial heartbeat.
	initCtx, initCancel := context.WithTimeout(ctx, 5*time.Second)
	_ = scheduler.WaitInitial(initCtx)
	_ = pool.WaitConnected(initCtx, 1)
	initCancel()

	publishHeartbeat := func() {
		results, overallOK := scheduler.Snapshot()
		hb := transport.HeartbeatPayload{
			Type:      transport.TypeHeartbeat,
			NodeName:  cfg.Node.Name,
			TS:        time.Now().Unix(),
			UptimeSec: int64(time.Since(startedAt).Seconds()),
			OverallOK: overallOK,
			Probes:    results,
		}
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if evID, err := pool.PublishHeartbeat(pubCtx, hb); err != nil {
			logger.Warn("failed to publish heartbeat", "err", err)
		} else {
			logger.Debug("heartbeat published",
				"event_id", evID,
				"overall_ok", overallOK,
				"probes", len(results),
				"connected_relays", pool.ConnectedRelays(),
			)
		}
	}

	if ctx.Err() == nil && pool.ConnectedRelays() > 0 {
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
			logger.Info("shutting down MeshWatch agent")
			return nil
		case msg, ok := <-pool.Messages():
			if !ok {
				return nil
			}
			engine.HandleMessage(ctx, msg)
		case <-hbTicker.C:
			publishHeartbeat()
		case <-timeoutTicker.C:
			engine.CheckTimeouts(ctx)
		}
	}
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
