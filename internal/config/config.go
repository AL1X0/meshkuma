package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"gopkg.in/yaml.v3"

	mwcrypto "meshwatch/internal/crypto"
)

const (
	DefaultHeartbeatInterval = 30 * time.Second
	DefaultPeerTimeout       = 90 * time.Second
	DefaultAutoMuteTimeout   = 3 * time.Second
	DefaultProbeInterval     = 60 * time.Second
	DefaultProbeTimeout      = 10 * time.Second
	DefaultHTTPStatus        = 200
	DefaultTLSMinDays        = 14
	DefaultDockerSocket      = "/var/run/docker.sock"
	DefaultDockerLabel       = "meshwatch.enable=true"
	DefaultSNMPPort          = 161
	DefaultSynologyMaxTempC  = 60
)

// Config holds the complete MeshWatch agent configuration.
type Config struct {
	Node          NodeConfig          `yaml:"node"`
	Nostr         NostrConfig         `yaml:"nostr"`
	AutoMute      AutoMuteConfig      `yaml:"auto_mute"`
	Peers         []PeerConfig        `yaml:"peers"`
	Probes        []ProbeConfig       `yaml:"probes"`
	Notifications NotificationsConfig `yaml:"notifications"`
	Logging       LoggingConfig       `yaml:"logging"`
}

// LoggingConfig controls slog level and output format.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// NodeConfig identifies the local MeshWatch node and timing parameters.
type NodeConfig struct {
	Name              string        `yaml:"name"`
	PrivateKeyHex     string        `yaml:"private_key_hex"`
	GroupPSKHex       string        `yaml:"group_psk_hex"`
	GroupPSK          string        `yaml:"group_psk"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	PeerTimeout       time.Duration `yaml:"peer_timeout"`

	// Derived values populated during validation.
	PublicKeyHex string `yaml:"-"`
	PSKBytes     []byte `yaml:"-"`
}

// NostrConfig specifies the public Nostr relays to connect to.
type NostrConfig struct {
	Relays []string `yaml:"relays"`
}

// AutoMuteConfig configures WAN connectivity checks before firing alerts.
type AutoMuteConfig struct {
	Targets []string      `yaml:"targets"`
	Timeout time.Duration `yaml:"timeout"`
}

// PeerConfig describes a trusted peer in the mesh.
type PeerConfig struct {
	Name        string `yaml:"name"`
	PubKeyHex   string `yaml:"pubkey_hex"`
	KumaPushURL string `yaml:"kuma_push_url"`
}

// ProbeConfig holds configuration for any supported local monitoring probe.
type ProbeConfig struct {
	ID       string        `yaml:"id"`
	Kind     string        `yaml:"kind"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`

	// HTTP / Exporter probes
	URL                string `yaml:"url"`
	ExpectedStatus     int    `yaml:"expected_status"`
	Contains           string `yaml:"contains"`
	TLSMinDays         *int   `yaml:"tls_min_days"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`

	// TCP & SNMP probes
	Address string `yaml:"address"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`

	// Docker probe
	Socket      string   `yaml:"socket"`
	Containers  []string `yaml:"containers"`
	Label       string   `yaml:"label"`
	MaxRestarts int      `yaml:"max_restarts"`

	// SNMP (Synology & generic snmp_oid)
	SNMPVersion   string   `yaml:"snmp_version"`
	Community     string   `yaml:"community"`
	User          string   `yaml:"user"`
	AuthProto     string   `yaml:"auth_proto"`
	AuthPass      string   `yaml:"auth_pass"`
	PrivProto     string   `yaml:"priv_proto"`
	PrivPass      string   `yaml:"priv_pass"`
	MaxTempC      int      `yaml:"max_temp_c"`
	OID           string   `yaml:"oid"`
	ExpectedValue string   `yaml:"expected_value"`
	MinValue      *float64 `yaml:"min_value"`
	MaxValue      *float64 `yaml:"max_value"`

	// node_exporter & windows_exporter
	MaxDiskPercent float64  `yaml:"max_disk_percent"`
	MaxRAMPercent  float64  `yaml:"max_ram_percent"`
	Disks          []string `yaml:"disks"`
	Services       []string `yaml:"services"`
}

// NotificationsConfig configures outbound alert channels.
type NotificationsConfig struct {
	Ntfy           NtfyConfig   `yaml:"ntfy"`
	PhotonIMessage PhotonConfig `yaml:"photon_imessage"`
}

// NtfyConfig configures the ntfy push notification connector.
type NtfyConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Topic   string `yaml:"topic"`
	Token   string `yaml:"token"`
}

// PhotonConfig configures the Photon iMessage notification connector.
// Supported modes:
//   - "cloud": Photon 2.0 Cloud API (https://api.photon.codes/v1) using project_id + api_key (pho_sk_...)
//   - "proxy": Photon Advanced iMessage HTTP Proxy (https://imessage-swagger.photon.codes/send) using server_url + api_key (or pre-encoded token)
//   - "custom": generic JSON webhook with configurable recipient_field / message_field
type PhotonConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Mode           string `yaml:"mode"`
	URL            string `yaml:"url"`
	ProjectID      string `yaml:"project_id"`
	APIKey         string `yaml:"api_key"`
	ServerURL      string `yaml:"server_url"`
	SenderID       string `yaml:"sender_id"`
	SpaceID        string `yaml:"space_id"`
	Token          string `yaml:"token"`
	Recipient      string `yaml:"recipient"`
	RecipientField string `yaml:"recipient_field"`
	MessageField   string `yaml:"message_field"`
}

// EffectiveMode infers the Photon transport mode ("cloud", "proxy", or "custom").
func (p PhotonConfig) EffectiveMode() string {
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case "cloud", "proxy", "custom":
		return strings.ToLower(strings.TrimSpace(p.Mode))
	}
	if strings.TrimSpace(p.ProjectID) != "" ||
		strings.HasPrefix(strings.TrimSpace(p.APIKey), "pho_") ||
		strings.Contains(strings.ToLower(p.URL), "api.photon.codes") {
		return "cloud"
	}
	if strings.TrimSpace(p.ServerURL) != "" ||
		strings.Contains(strings.ToLower(p.URL), "imessage-swagger.photon.codes") {
		return "proxy"
	}
	return "custom"
}

// Load reads, parses, and strictly validates a YAML config file from disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return Parse(data)
}

// Parse unmarshals YAML bytes into a Config, applies defaults, and validates all fields.
func Parse(data []byte) (*Config, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("config is empty")
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}

	if c.Node.HeartbeatInterval == 0 {
		c.Node.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if c.Node.PeerTimeout == 0 {
		c.Node.PeerTimeout = DefaultPeerTimeout
	}

	if len(c.AutoMute.Targets) == 0 {
		c.AutoMute.Targets = []string{"1.1.1.1:443", "9.9.9.9:443"}
	}
	if c.AutoMute.Timeout == 0 {
		c.AutoMute.Timeout = DefaultAutoMuteTimeout
	}

	for i := range c.Probes {
		p := &c.Probes[i]
		if p.Interval == 0 {
			p.Interval = DefaultProbeInterval
		}
		if p.Timeout == 0 {
			p.Timeout = DefaultProbeTimeout
		}
		switch p.Kind {
		case "http":
			if p.ExpectedStatus == 0 {
				p.ExpectedStatus = DefaultHTTPStatus
			}
			if p.TLSMinDays == nil {
				d := DefaultTLSMinDays
				p.TLSMinDays = &d
			}
		case "docker":
			if p.Socket == "" {
				p.Socket = DefaultDockerSocket
			}
			if len(p.Containers) == 0 && p.Label == "" {
				p.Label = DefaultDockerLabel
			}
		case "synology":
			if p.Port == 0 {
				p.Port = DefaultSNMPPort
			}
			if p.SNMPVersion == "" {
				p.SNMPVersion = "2c"
			}
			if p.MaxTempC == 0 {
				p.MaxTempC = DefaultSynologyMaxTempC
			}
		case "snmp_oid":
			if p.Port == 0 {
				p.Port = DefaultSNMPPort
			}
			if p.SNMPVersion == "" {
				p.SNMPVersion = "2c"
			}
		}
	}

	if c.Notifications.PhotonIMessage.RecipientField == "" {
		c.Notifications.PhotonIMessage.RecipientField = "recipient"
	}
	if c.Notifications.PhotonIMessage.MessageField == "" {
		c.Notifications.PhotonIMessage.MessageField = "message"
	}
}

// Validate checks every section of the configuration and populates derived fields.
func (c *Config) Validate() error {
	var errs []error

	// Logging
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
		c.Logging.Level = strings.ToLower(c.Logging.Level)
	default:
		errs = append(errs, fmt.Errorf("logging.level %q must be one of debug, info, warn, error", c.Logging.Level))
	}
	switch strings.ToLower(c.Logging.Format) {
	case "text", "json":
		c.Logging.Format = strings.ToLower(c.Logging.Format)
	default:
		errs = append(errs, fmt.Errorf("logging.format %q must be text or json", c.Logging.Format))
	}

	// Node
	c.Node.Name = strings.TrimSpace(c.Node.Name)
	if c.Node.Name == "" {
		errs = append(errs, errors.New("node.name is required"))
	}

	c.Node.PrivateKeyHex = strings.ToLower(strings.TrimSpace(c.Node.PrivateKeyHex))
	if !isValidHex32(c.Node.PrivateKeyHex) {
		errs = append(errs, errors.New("node.private_key_hex must be a 64-character hex string (run `meshwatch keygen`)"))
	} else {
		pub, err := nostr.GetPublicKey(c.Node.PrivateKeyHex)
		if err != nil {
			errs = append(errs, fmt.Errorf("node.private_key_hex is invalid: %w", err))
		} else {
			c.Node.PublicKeyHex = strings.ToLower(pub)
		}
	}

	pskRawStr := strings.TrimSpace(c.Node.GroupPSKHex)
	if pskRawStr == "" {
		pskRawStr = strings.TrimSpace(c.Node.GroupPSK)
	}
	pskBytes, err := mwcrypto.ParsePSK(pskRawStr)
	if err != nil {
		errs = append(errs, fmt.Errorf("node.group_psk_hex: %w", err))
	} else {
		c.Node.PSKBytes = pskBytes
	}

	if c.Node.HeartbeatInterval <= 0 {
		errs = append(errs, errors.New("node.heartbeat_interval must be > 0"))
	}
	if c.Node.PeerTimeout <= 0 {
		errs = append(errs, errors.New("node.peer_timeout must be > 0"))
	} else if c.Node.HeartbeatInterval > 0 && c.Node.PeerTimeout < c.Node.HeartbeatInterval {
		errs = append(errs, fmt.Errorf("node.peer_timeout (%s) must be >= node.heartbeat_interval (%s)", c.Node.PeerTimeout, c.Node.HeartbeatInterval))
	}

	// Nostr relays
	if len(c.Nostr.Relays) == 0 {
		errs = append(errs, errors.New("nostr.relays must contain at least one relay URL"))
	}
	for i, relay := range c.Nostr.Relays {
		u, err := url.Parse(strings.TrimSpace(relay))
		if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" {
			errs = append(errs, fmt.Errorf("nostr.relays[%d] (%q) must be a valid ws:// or wss:// URL", i, relay))
		}
	}

	// Auto-mute
	if c.AutoMute.Timeout <= 0 {
		errs = append(errs, errors.New("auto_mute.timeout must be > 0"))
	}
	for i, target := range c.AutoMute.Targets {
		host, port, err := net.SplitHostPort(strings.TrimSpace(target))
		if err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("auto_mute.targets[%d] (%q) must be host:port", i, target))
		}
	}

	// Peers
	seenPeers := make(map[string]struct{}, len(c.Peers))
	for i := range c.Peers {
		p := &c.Peers[i]
		p.Name = strings.TrimSpace(p.Name)
		p.PubKeyHex = strings.ToLower(strings.TrimSpace(p.PubKeyHex))
		p.KumaPushURL = strings.TrimSpace(p.KumaPushURL)

		if p.Name == "" {
			errs = append(errs, fmt.Errorf("peers[%d].name is required", i))
		}
		if !isValidHex32(p.PubKeyHex) {
			errs = append(errs, fmt.Errorf("peers[%d].pubkey_hex (%q) must be a 64-character hex string", i, p.PubKeyHex))
		} else {
			if c.Node.PublicKeyHex != "" && p.PubKeyHex == c.Node.PublicKeyHex {
				errs = append(errs, fmt.Errorf("peers[%d].pubkey_hex matches local node public key", i))
			}
			if _, dup := seenPeers[p.PubKeyHex]; dup {
				errs = append(errs, fmt.Errorf("peers[%d].pubkey_hex (%s) is duplicated", i, p.PubKeyHex))
			}
			seenPeers[p.PubKeyHex] = struct{}{}
		}
		if p.KumaPushURL != "" {
			if err := validateHTTPURL(p.KumaPushURL); err != nil {
				errs = append(errs, fmt.Errorf("peers[%d].kuma_push_url: %w", i, err))
			}
		}
	}

	// Probes
	seenProbes := make(map[string]struct{}, len(c.Probes))
	for i := range c.Probes {
		p := &c.Probes[i]
		p.ID = strings.TrimSpace(p.ID)
		p.Kind = strings.ToLower(strings.TrimSpace(p.Kind))

		if p.ID == "" {
			errs = append(errs, fmt.Errorf("probes[%d].id is required", i))
		} else {
			if _, dup := seenProbes[p.ID]; dup {
				errs = append(errs, fmt.Errorf("probes[%d].id (%q) is duplicated", i, p.ID))
			}
			seenProbes[p.ID] = struct{}{}
		}
		if p.Interval <= 0 {
			errs = append(errs, fmt.Errorf("probes[%d] (%s): interval must be > 0", i, p.ID))
		}
		if p.Timeout <= 0 {
			errs = append(errs, fmt.Errorf("probes[%d] (%s): timeout must be > 0", i, p.ID))
		}

		errs = append(errs, validateProbe(i, p)...)
	}

	// Notifications
	if c.Notifications.Ntfy.Enabled {
		if err := validateHTTPURL(c.Notifications.Ntfy.URL); err != nil {
			errs = append(errs, fmt.Errorf("notifications.ntfy.url: %w", err))
		}
	}
	if c.Notifications.PhotonIMessage.Enabled {
		ph := &c.Notifications.PhotonIMessage
		mode := ph.EffectiveMode()
		switch mode {
		case "cloud":
			if strings.TrimSpace(ph.URL) == "" {
				ph.URL = "https://api.photon.codes/v1"
			} else if err := validateHTTPURL(ph.URL); err != nil {
				errs = append(errs, fmt.Errorf("notifications.photon_imessage.url: %w", err))
			}
			if strings.TrimSpace(ph.ProjectID) == "" {
				errs = append(errs, errors.New("notifications.photon_imessage.project_id is required in cloud mode"))
			}
			if strings.TrimSpace(ph.APIKey) == "" && strings.TrimSpace(ph.Token) == "" {
				errs = append(errs, errors.New("notifications.photon_imessage.api_key is required in cloud mode"))
			}
			if strings.TrimSpace(ph.Recipient) == "" && (strings.TrimSpace(ph.SpaceID) == "" || strings.TrimSpace(ph.SenderID) == "") {
				errs = append(errs, errors.New("notifications.photon_imessage.recipient (or space_id + sender_id) is required in cloud mode"))
			}
		case "proxy":
			if strings.TrimSpace(ph.URL) == "" {
				ph.URL = "https://imessage-swagger.photon.codes"
			} else if err := validateHTTPURL(ph.URL); err != nil {
				errs = append(errs, fmt.Errorf("notifications.photon_imessage.url: %w", err))
			}
			if strings.TrimSpace(ph.Recipient) == "" {
				errs = append(errs, errors.New("notifications.photon_imessage.recipient is required in proxy mode"))
			}
			if strings.TrimSpace(ph.Token) == "" && (strings.TrimSpace(ph.ServerURL) == "" || strings.TrimSpace(ph.APIKey) == "") {
				errs = append(errs, errors.New("notifications.photon_imessage requires server_url + api_key (or token) in proxy mode"))
			}
		default:
			if err := validateHTTPURL(ph.URL); err != nil {
				errs = append(errs, fmt.Errorf("notifications.photon_imessage.url: %w", err))
			}
			if strings.TrimSpace(ph.Recipient) == "" {
				errs = append(errs, errors.New("notifications.photon_imessage.recipient is required when enabled"))
			}
		}
	}

	return errors.Join(errs...)
}

func validateProbe(idx int, p *ProbeConfig) []error {
	var errs []error
	prefix := fmt.Sprintf("probes[%d] (%s)", idx, p.ID)

	switch p.Kind {
	case "http":
		if err := validateHTTPURL(p.URL); err != nil {
			errs = append(errs, fmt.Errorf("%s: url: %w", prefix, err))
		}
		if p.ExpectedStatus < 100 || p.ExpectedStatus > 599 {
			errs = append(errs, fmt.Errorf("%s: expected_status (%d) must be 100..599", prefix, p.ExpectedStatus))
		}
		if p.TLSMinDays != nil && *p.TLSMinDays < 0 {
			errs = append(errs, fmt.Errorf("%s: tls_min_days must be >= 0", prefix))
		}
	case "tcp":
		addr := p.TCPAddress()
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("%s: tcp probe requires valid address (host:port) or host+port", prefix))
		}
	case "docker":
		if strings.TrimSpace(p.Socket) == "" {
			errs = append(errs, fmt.Errorf("%s: docker socket is required", prefix))
		}
		if p.MaxRestarts < 0 {
			errs = append(errs, fmt.Errorf("%s: max_restarts must be >= 0", prefix))
		}
	case "synology":
		errs = append(errs, validateSNMPCommon(prefix, p)...)
		if p.MaxTempC <= 0 {
			errs = append(errs, fmt.Errorf("%s: max_temp_c must be > 0", prefix))
		}
	case "snmp_oid":
		errs = append(errs, validateSNMPCommon(prefix, p)...)
		if strings.TrimSpace(p.OID) == "" {
			errs = append(errs, fmt.Errorf("%s: oid is required for snmp_oid probe", prefix))
		}
		if p.ExpectedValue == "" && p.MinValue == nil && p.MaxValue == nil {
			errs = append(errs, fmt.Errorf("%s: snmp_oid requires expected_value, min_value, or max_value", prefix))
		}
		if p.MinValue != nil && p.MaxValue != nil && *p.MinValue > *p.MaxValue {
			errs = append(errs, fmt.Errorf("%s: min_value (%v) > max_value (%v)", prefix, *p.MinValue, *p.MaxValue))
		}
	case "node_exporter", "windows_exporter":
		if err := validateHTTPURL(p.URL); err != nil {
			errs = append(errs, fmt.Errorf("%s: url: %w", prefix, err))
		}
		if p.MaxDiskPercent < 0 || p.MaxDiskPercent > 100 {
			errs = append(errs, fmt.Errorf("%s: max_disk_percent must be 0..100", prefix))
		}
		if p.MaxRAMPercent < 0 || p.MaxRAMPercent > 100 {
			errs = append(errs, fmt.Errorf("%s: max_ram_percent must be 0..100", prefix))
		}
	default:
		errs = append(errs, fmt.Errorf("%s: unsupported kind %q (supported: http, tcp, docker, synology, snmp_oid, node_exporter, windows_exporter)", prefix, p.Kind))
	}

	return errs
}

func validateSNMPCommon(prefix string, p *ProbeConfig) []error {
	var errs []error
	if strings.TrimSpace(p.Host) == "" {
		errs = append(errs, fmt.Errorf("%s: host is required", prefix))
	}
	if p.Port <= 0 || p.Port > 65535 {
		errs = append(errs, fmt.Errorf("%s: port (%d) must be 1..65535", prefix, p.Port))
	}
	switch strings.ToLower(strings.TrimSpace(p.SNMPVersion)) {
	case "2c":
		p.SNMPVersion = "2c"
		if strings.TrimSpace(p.Community) == "" {
			errs = append(errs, fmt.Errorf("%s: community is required for SNMPv2c", prefix))
		}
	case "3":
		p.SNMPVersion = "3"
		if strings.TrimSpace(p.User) == "" {
			errs = append(errs, fmt.Errorf("%s: user is required for SNMPv3", prefix))
		}
		switch strings.ToUpper(strings.TrimSpace(p.AuthProto)) {
		case "", "NONE", "NOAUTH", "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512":
		default:
			errs = append(errs, fmt.Errorf("%s: unsupported SNMPv3 auth_proto %q", prefix, p.AuthProto))
		}
		switch strings.ToUpper(strings.TrimSpace(p.PrivProto)) {
		case "", "NONE", "NOPRIV", "DES", "AES", "AES192", "AES256", "AES192C", "AES256C":
		default:
			errs = append(errs, fmt.Errorf("%s: unsupported SNMPv3 priv_proto %q", prefix, p.PrivProto))
		}
	default:
		errs = append(errs, fmt.Errorf("%s: snmp_version %q must be \"2c\" or \"3\"", prefix, p.SNMPVersion))
	}
	return errs
}

// TCPAddress resolves the host:port target for a tcp probe.
func (p ProbeConfig) TCPAddress() string {
	if strings.TrimSpace(p.Address) != "" {
		return strings.TrimSpace(p.Address)
	}
	if strings.TrimSpace(p.Host) != "" && p.Port > 0 {
		return net.JoinHostPort(strings.TrimSpace(p.Host), fmt.Sprintf("%d", p.Port))
	}
	return ""
}

// AllowedPeers returns a lookup map of trusted peer pubkeys -> PeerConfig.
func (c *Config) AllowedPeers() map[string]PeerConfig {
	out := make(map[string]PeerConfig, len(c.Peers))
	for _, p := range c.Peers {
		out[p.PubKeyHex] = p
	}
	return out
}

func isValidHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validateHTTPURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("URL %q must start with http:// or https:// and include a host", raw)
	}
	return nil
}
