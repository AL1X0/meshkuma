package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mwcrypto "meshwatch/internal/crypto"
)

func validTestYAML(t *testing.T) (string, string, string) {
	t.Helper()
	priv, pub, err := mwcrypto.GenerateNostrKeypair()
	if err != nil {
		t.Fatalf("GenerateNostrKeypair: %v", err)
	}
	_, peerPub, err := mwcrypto.GenerateNostrKeypair()
	if err != nil {
		t.Fatalf("GenerateNostrKeypair peer: %v", err)
	}
	psk, err := mwcrypto.GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK: %v", err)
	}

	yml := fmt.Sprintf(`
node:
  name: "mon-homelab"
  private_key_hex: "%s"
  group_psk_hex: "%s"
  heartbeat_interval: 30s
  peer_timeout: 90s

nostr:
  relays:
    - "wss://relay.damus.io"
    - "wss://nos.lol"

auto_mute:
  targets: ["1.1.1.1:443", "9.9.9.9:443"]

peers:
  - name: "ami-nord"
    pubkey_hex: "%s"

probes:
  - id: "syno-nas"
    kind: "synology"
    interval: 60s
    host: "192.168.1.20"
    snmp_version: "2c"
    community: "public"
    max_temp_c: 55
  - id: "docker-local"
    kind: "docker"
    interval: 30s
    socket: "/var/run/docker.sock"
    containers: ["jellyfin", "traefik"]
  - id: "srv-linux"
    kind: "node_exporter"
    interval: 60s
    url: "http://192.168.1.10:9100/metrics"
    max_disk_percent: 90
    max_ram_percent: 92
  - id: "srv-windows"
    kind: "windows_exporter"
    interval: 60s
    url: "http://192.168.1.15:9182/metrics"
    services: ["W32Time", "VeeamBackupSvc"]
    max_disk_percent: 90
  - id: "web-public"
    kind: "http"
    interval: 30s
    url: "https://mon-domaine.fr"
    expected_status: 200
    tls_min_days: 14
  - id: "ssh-check"
    kind: "tcp"
    host: "192.168.1.10"
    port: 22
  - id: "ups-load"
    kind: "snmp_oid"
    host: "192.168.1.50"
    snmp_version: "3"
    user: "monitor"
    auth_proto: "SHA256"
    auth_pass: "secretauth"
    priv_proto: "AES"
    priv_pass: "secretpriv"
    oid: ".1.3.6.1.2.1.33.1.4.4.1.5.1"
    max_value: 80

notifications:
  ntfy:
    enabled: true
    url: "https://ntfy.sh/mon-topic-secret-meshwatch"
    token: ""
  photon_imessage:
    enabled: true
    url: "https://ton-gateway-photon.example/send"
    token: "TON_TOKEN_PHOTON"
    recipient: "+33600000000"
`, priv, psk, peerPub)

	return yml, pub, peerPub
}

func TestParseValidConfig(t *testing.T) {
	yml, expectedPub, peerPub := validTestYAML(t)
	cfg, err := Parse([]byte(yml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Node.PublicKeyHex != expectedPub {
		t.Fatalf("Node.PublicKeyHex = %q, want %q", cfg.Node.PublicKeyHex, expectedPub)
	}
	if len(cfg.Node.PSKBytes) != mwcrypto.PSKSize {
		t.Fatalf("len(PSKBytes) = %d, want %d", len(cfg.Node.PSKBytes), mwcrypto.PSKSize)
	}
	if cfg.AutoMute.Timeout != DefaultAutoMuteTimeout {
		t.Fatalf("AutoMute.Timeout = %v, want %v", cfg.AutoMute.Timeout, DefaultAutoMuteTimeout)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "text" {
		t.Fatalf("unexpected default logging: %+v", cfg.Logging)
	}
	allowed := cfg.AllowedPeers()
	if _, ok := allowed[peerPub]; !ok {
		t.Fatalf("peer %s missing from AllowedPeers()", peerPub)
	}
	if len(cfg.Probes) != 7 {
		t.Fatalf("len(Probes) = %d, want 7", len(cfg.Probes))
	}
}

func TestParseDefaults(t *testing.T) {
	priv, _, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()
	yml := fmt.Sprintf(`
node:
  name: "minimal"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: ["wss://nos.lol"]
probes:
  - id: "http-default"
    kind: "http"
    url: "https://example.com"
  - id: "docker-default"
    kind: "docker"
`, priv, psk)

	cfg, err := Parse([]byte(yml))
	if err != nil {
		t.Fatalf("Parse(minimal) error = %v", err)
	}
	if cfg.Node.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 30s", cfg.Node.HeartbeatInterval)
	}
	if cfg.Node.PeerTimeout != 90*time.Second {
		t.Errorf("PeerTimeout = %v, want 90s", cfg.Node.PeerTimeout)
	}
	if len(cfg.AutoMute.Targets) != 2 {
		t.Errorf("AutoMute.Targets = %v, want 2 defaults", cfg.AutoMute.Targets)
	}
	if cfg.Probes[0].ExpectedStatus != 200 || cfg.Probes[0].TLSMinDays == nil || *cfg.Probes[0].TLSMinDays != 14 {
		t.Errorf("HTTP defaults not applied: %+v", cfg.Probes[0])
	}
	if cfg.Probes[1].Socket != DefaultDockerSocket || cfg.Probes[1].Label != DefaultDockerLabel {
		t.Errorf("Docker defaults not applied: %+v", cfg.Probes[1])
	}
}

func TestParseValidationErrors(t *testing.T) {
	priv, pub, _ := mwcrypto.GenerateNostrKeypair()
	_, peerPub, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()

	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "empty config",
			yaml:    "",
			wantSub: "empty",
		},
		{
			name:    "unknown field",
			yaml:    "node:\n  unknown_key: 1\n",
			wantSub: "unknown_key",
		},
		{
			name: "placeholder private key and PSK",
			yaml: `
node:
  name: "test"
  private_key_hex: "REMPLACER_VIA_KEYGEN"
  group_psk_hex: "REMPLACER_VIA_KEYGEN"
nostr:
  relays: ["wss://nos.lol"]
`,
			wantSub: "private_key_hex",
		},
		{
			name: "missing relays",
			yaml: fmt.Sprintf(`
node:
  name: "test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: []
`, priv, psk),
			wantSub: "nostr.relays",
		},
		{
			name: "invalid relay scheme",
			yaml: fmt.Sprintf(`
node:
  name: "test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: ["https://nos.lol"]
`, priv, psk),
			wantSub: "ws:// or wss://",
		},
		{
			name: "peer_timeout less than heartbeat_interval",
			yaml: fmt.Sprintf(`
node:
  name: "test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
  heartbeat_interval: 60s
  peer_timeout: 30s
nostr:
  relays: ["wss://nos.lol"]
`, priv, psk),
			wantSub: "peer_timeout",
		},
		{
			name: "duplicate peer and self peer",
			yaml: fmt.Sprintf(`
node:
  name: "test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: ["wss://nos.lol"]
peers:
  - name: "me"
    pubkey_hex: "%s"
  - name: "p1"
    pubkey_hex: "%s"
  - name: "p2"
    pubkey_hex: "%s"
`, priv, psk, pub, peerPub, peerPub),
			wantSub: "duplicated",
		},
		{
			name: "unsupported probe kind and duplicate probe id",
			yaml: fmt.Sprintf(`
node:
  name: "test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: ["wss://nos.lol"]
probes:
  - id: "p1"
    kind: "unknown_kind"
  - id: "p1"
    kind: "tcp"
`, priv, psk),
			wantSub: "unsupported kind",
		},
		{
			name: "invalid notifications",
			yaml: fmt.Sprintf(`
node:
  name: "test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: ["wss://nos.lol"]
notifications:
  ntfy:
    enabled: true
    url: "not-a-url"
  photon_imessage:
    enabled: true
    url: "https://photon.example/send"
    recipient: ""
`, priv, psk),
			wantSub: "photon_imessage.recipient",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("Parse() succeeded, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Parse() error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestConfigExampleYAMLSync(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read config.example.yaml: %v", err)
	}
	priv, _, _ := mwcrypto.GenerateNostrKeypair()
	_, peerPub, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()

	content := string(raw)
	content = strings.Replace(content, "REMPLACER_VIA_KEYGEN", priv, 1)
	content = strings.Replace(content, "REMPLACER_VIA_KEYGEN", psk, 1)
	content = strings.Replace(content, "PUBKEY_HEX_DU_POTE", peerPub, 1)

	cfg, err := Parse([]byte(content))
	if err != nil {
		t.Fatalf("config.example.yaml failed validation after replacing placeholders: %v", err)
	}
	if len(cfg.Probes) != 5 || len(cfg.Peers) != 1 {
		t.Fatalf("unexpected counts in config.example.yaml: probes=%d peers=%d", len(cfg.Probes), len(cfg.Peers))
	}
}
