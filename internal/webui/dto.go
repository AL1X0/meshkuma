package webui

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"meshwatch/internal/config"
)

// ConfigDTO is the JSON-friendly representation of MeshWatch YAML configuration
// exchanged between the embedded web UI and the Go backend.
type ConfigDTO struct {
	Node          NodeDTO          `json:"node" yaml:"node"`
	Logging       LoggingDTO       `json:"logging,omitempty" yaml:"logging,omitempty"`
	Nostr         NostrDTO         `json:"nostr" yaml:"nostr"`
	AutoMute      AutoMuteDTO      `json:"auto_mute,omitempty" yaml:"auto_mute,omitempty"`
	Peers         []PeerDTO        `json:"peers" yaml:"peers"`
	Probes        []ProbeDTO       `json:"probes" yaml:"probes"`
	Notifications NotificationsDTO `json:"notifications" yaml:"notifications"`
}

type NodeDTO struct {
	Name              string `json:"name" yaml:"name"`
	PrivateKeyHex     string `json:"private_key_hex" yaml:"private_key_hex"`
	GroupPSKHex       string `json:"group_psk_hex" yaml:"group_psk_hex"`
	HeartbeatInterval string `json:"heartbeat_interval,omitempty" yaml:"heartbeat_interval,omitempty"`
	PeerTimeout       string `json:"peer_timeout,omitempty" yaml:"peer_timeout,omitempty"`
	PublicKeyHex      string `json:"pubkey_hex,omitempty" yaml:"-"`
}

type LoggingDTO struct {
	Level  string `json:"level,omitempty" yaml:"level,omitempty"`
	Format string `json:"format,omitempty" yaml:"format,omitempty"`
}

type NostrDTO struct {
	Relays []string `json:"relays" yaml:"relays"`
}

type AutoMuteDTO struct {
	Targets []string `json:"targets,omitempty" yaml:"targets,omitempty"`
	Timeout string   `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

type PeerDTO struct {
	Name        string `json:"name" yaml:"name"`
	PubKeyHex   string `json:"pubkey_hex" yaml:"pubkey_hex"`
	KumaPushURL string `json:"kuma_push_url,omitempty" yaml:"kuma_push_url,omitempty"`
}

type ProbeDTO struct {
	ID       string `json:"id" yaml:"id"`
	Kind     string `json:"kind" yaml:"kind"`
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	URL                string `json:"url,omitempty" yaml:"url,omitempty"`
	ExpectedStatus     int    `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	Contains           string `json:"contains,omitempty" yaml:"contains,omitempty"`
	TLSMinDays         *int   `json:"tls_min_days,omitempty" yaml:"tls_min_days,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" yaml:"insecure_skip_verify,omitempty"`

	Address string `json:"address,omitempty" yaml:"address,omitempty"`
	Host    string `json:"host,omitempty" yaml:"host,omitempty"`
	Port    int    `json:"port,omitempty" yaml:"port,omitempty"`

	Socket      string   `json:"socket,omitempty" yaml:"socket,omitempty"`
	Containers  []string `json:"containers,omitempty" yaml:"containers,omitempty"`
	Label       string   `json:"label,omitempty" yaml:"label,omitempty"`
	MaxRestarts int      `json:"max_restarts,omitempty" yaml:"max_restarts,omitempty"`

	SNMPVersion   string   `json:"snmp_version,omitempty" yaml:"snmp_version,omitempty"`
	Community     string   `json:"community,omitempty" yaml:"community,omitempty"`
	User          string   `json:"user,omitempty" yaml:"user,omitempty"`
	AuthProto     string   `json:"auth_proto,omitempty" yaml:"auth_proto,omitempty"`
	AuthPass      string   `json:"auth_pass,omitempty" yaml:"auth_pass,omitempty"`
	PrivProto     string   `json:"priv_proto,omitempty" yaml:"priv_proto,omitempty"`
	PrivPass      string   `json:"priv_pass,omitempty" yaml:"priv_pass,omitempty"`
	MaxTempC      int      `json:"max_temp_c,omitempty" yaml:"max_temp_c,omitempty"`
	OID           string   `json:"oid,omitempty" yaml:"oid,omitempty"`
	ExpectedValue string   `json:"expected_value,omitempty" yaml:"expected_value,omitempty"`
	MinValue      *float64 `json:"min_value,omitempty" yaml:"min_value,omitempty"`
	MaxValue      *float64 `json:"max_value,omitempty" yaml:"max_value,omitempty"`

	MaxDiskPercent float64  `json:"max_disk_percent,omitempty" yaml:"max_disk_percent,omitempty"`
	MaxRAMPercent  float64  `json:"max_ram_percent,omitempty" yaml:"max_ram_percent,omitempty"`
	Disks          []string `json:"disks,omitempty" yaml:"disks,omitempty"`
	Services       []string `json:"services,omitempty" yaml:"services,omitempty"`
}

type NotificationsDTO struct {
	Ntfy           NtfyDTO   `json:"ntfy" yaml:"ntfy"`
	PhotonIMessage PhotonDTO `json:"photon_imessage" yaml:"photon_imessage"`
}

type NtfyDTO struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	URL     string `json:"url,omitempty" yaml:"url,omitempty"`
	Topic   string `json:"topic,omitempty" yaml:"topic,omitempty"`
	Token   string `json:"token,omitempty" yaml:"token,omitempty"`
}

type PhotonDTO struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	URL            string `json:"url,omitempty" yaml:"url,omitempty"`
	Token          string `json:"token,omitempty" yaml:"token,omitempty"`
	Recipient      string `json:"recipient,omitempty" yaml:"recipient,omitempty"`
	RecipientField string `json:"recipient_field,omitempty" yaml:"recipient_field,omitempty"`
	MessageField   string `json:"message_field,omitempty" yaml:"message_field,omitempty"`
}

func configToDTO(cfg *config.Config) ConfigDTO {
	if cfg == nil {
		return defaultTemplateDTO()
	}

	psk := cfg.Node.GroupPSKHex
	if psk == "" {
		psk = cfg.Node.GroupPSK
	}

	peers := make([]PeerDTO, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers = append(peers, PeerDTO{
			Name:        p.Name,
			PubKeyHex:   p.PubKeyHex,
			KumaPushURL: p.KumaPushURL,
		})
	}

	probesList := make([]ProbeDTO, 0, len(cfg.Probes))
	for _, p := range cfg.Probes {
		dto := ProbeDTO{
			ID:                 p.ID,
			Kind:               p.Kind,
			Interval:           formatDuration(p.Interval),
			Timeout:            formatDuration(p.Timeout),
			URL:                p.URL,
			ExpectedStatus:     p.ExpectedStatus,
			Contains:           p.Contains,
			TLSMinDays:         p.TLSMinDays,
			InsecureSkipVerify: p.InsecureSkipVerify,
			Address:            p.Address,
			Host:               p.Host,
			Port:               p.Port,
			Socket:             p.Socket,
			Containers:         append([]string(nil), p.Containers...),
			Label:              p.Label,
			MaxRestarts:        p.MaxRestarts,
			SNMPVersion:        p.SNMPVersion,
			Community:          p.Community,
			User:               p.User,
			AuthProto:          p.AuthProto,
			AuthPass:           p.AuthPass,
			PrivProto:          p.PrivProto,
			PrivPass:           p.PrivPass,
			MaxTempC:           p.MaxTempC,
			OID:                p.OID,
			ExpectedValue:      p.ExpectedValue,
			MinValue:           p.MinValue,
			MaxValue:           p.MaxValue,
			MaxDiskPercent:     p.MaxDiskPercent,
			MaxRAMPercent:      p.MaxRAMPercent,
			Disks:              append([]string(nil), p.Disks...),
			Services:           append([]string(nil), p.Services...),
		}
		probesList = append(probesList, dto)
	}

	return ConfigDTO{
		Node: NodeDTO{
			Name:              cfg.Node.Name,
			PrivateKeyHex:     cfg.Node.PrivateKeyHex,
			GroupPSKHex:       psk,
			HeartbeatInterval: formatDuration(cfg.Node.HeartbeatInterval),
			PeerTimeout:       formatDuration(cfg.Node.PeerTimeout),
			PublicKeyHex:      cfg.Node.PublicKeyHex,
		},
		Logging: LoggingDTO{
			Level:  cfg.Logging.Level,
			Format: cfg.Logging.Format,
		},
		Nostr: NostrDTO{
			Relays: append([]string(nil), cfg.Nostr.Relays...),
		},
		AutoMute: AutoMuteDTO{
			Targets: append([]string(nil), cfg.AutoMute.Targets...),
			Timeout: formatDuration(cfg.AutoMute.Timeout),
		},
		Peers:  peers,
		Probes: probesList,
		Notifications: NotificationsDTO{
			Ntfy: NtfyDTO{
				Enabled: cfg.Notifications.Ntfy.Enabled,
				URL:     cfg.Notifications.Ntfy.URL,
				Topic:   cfg.Notifications.Ntfy.Topic,
				Token:   cfg.Notifications.Ntfy.Token,
			},
			PhotonIMessage: PhotonDTO{
				Enabled:        cfg.Notifications.PhotonIMessage.Enabled,
				URL:            cfg.Notifications.PhotonIMessage.URL,
				Token:          cfg.Notifications.PhotonIMessage.Token,
				Recipient:      cfg.Notifications.PhotonIMessage.Recipient,
				RecipientField: cfg.Notifications.PhotonIMessage.RecipientField,
				MessageField:   cfg.Notifications.PhotonIMessage.MessageField,
			},
		},
	}
}

// cleanProbeForYAML strips irrelevant fields for each probe kind so generated YAML stays clean.
func cleanDTO(in ConfigDTO) ConfigDTO {
	out := in
	out.Node.Name = strings.TrimSpace(out.Node.Name)
	out.Node.PrivateKeyHex = strings.TrimSpace(out.Node.PrivateKeyHex)
	out.Node.GroupPSKHex = strings.TrimSpace(out.Node.GroupPSKHex)
	out.Node.PublicKeyHex = ""

	cleanedRelays := make([]string, 0, len(out.Nostr.Relays))
	for _, r := range out.Nostr.Relays {
		if s := strings.TrimSpace(r); s != "" {
			cleanedRelays = append(cleanedRelays, s)
		}
	}
	out.Nostr.Relays = cleanedRelays

	cleanedTargets := make([]string, 0, len(out.AutoMute.Targets))
	for _, t := range out.AutoMute.Targets {
		if s := strings.TrimSpace(t); s != "" {
			cleanedTargets = append(cleanedTargets, s)
		}
	}
	out.AutoMute.Targets = cleanedTargets

	cleanedPeers := make([]PeerDTO, 0, len(out.Peers))
	for _, p := range out.Peers {
		cleanedPeers = append(cleanedPeers, PeerDTO{
			Name:        strings.TrimSpace(p.Name),
			PubKeyHex:   strings.TrimSpace(p.PubKeyHex),
			KumaPushURL: strings.TrimSpace(p.KumaPushURL),
		})
	}
	out.Peers = cleanedPeers

	cleanedProbes := make([]ProbeDTO, 0, len(out.Probes))
	for _, p := range out.Probes {
		cp := ProbeDTO{
			ID:       strings.TrimSpace(p.ID),
			Kind:     strings.ToLower(strings.TrimSpace(p.Kind)),
			Interval: strings.TrimSpace(p.Interval),
			Timeout:  strings.TrimSpace(p.Timeout),
		}
		switch cp.Kind {
		case "http":
			cp.URL = strings.TrimSpace(p.URL)
			cp.ExpectedStatus = p.ExpectedStatus
			cp.Contains = p.Contains
			cp.TLSMinDays = p.TLSMinDays
			cp.InsecureSkipVerify = p.InsecureSkipVerify
		case "tcp":
			cp.Address = strings.TrimSpace(p.Address)
			cp.Host = strings.TrimSpace(p.Host)
			cp.Port = p.Port
		case "docker":
			cp.Socket = strings.TrimSpace(p.Socket)
			cp.Containers = trimSlice(p.Containers)
			cp.Label = strings.TrimSpace(p.Label)
			cp.MaxRestarts = p.MaxRestarts
		case "synology":
			cp.Host = strings.TrimSpace(p.Host)
			cp.Port = p.Port
			cp.SNMPVersion = strings.TrimSpace(p.SNMPVersion)
			cp.Community = p.Community
			cp.User = strings.TrimSpace(p.User)
			cp.AuthProto = strings.TrimSpace(p.AuthProto)
			cp.AuthPass = p.AuthPass
			cp.PrivProto = strings.TrimSpace(p.PrivProto)
			cp.PrivPass = p.PrivPass
			cp.MaxTempC = p.MaxTempC
		case "snmp_oid":
			cp.Host = strings.TrimSpace(p.Host)
			cp.Port = p.Port
			cp.SNMPVersion = strings.TrimSpace(p.SNMPVersion)
			cp.Community = p.Community
			cp.User = strings.TrimSpace(p.User)
			cp.AuthProto = strings.TrimSpace(p.AuthProto)
			cp.AuthPass = p.AuthPass
			cp.PrivProto = strings.TrimSpace(p.PrivProto)
			cp.PrivPass = p.PrivPass
			cp.OID = strings.TrimSpace(p.OID)
			cp.ExpectedValue = p.ExpectedValue
			cp.MinValue = p.MinValue
			cp.MaxValue = p.MaxValue
		case "node_exporter":
			cp.URL = strings.TrimSpace(p.URL)
			cp.MaxDiskPercent = p.MaxDiskPercent
			cp.MaxRAMPercent = p.MaxRAMPercent
			cp.Disks = trimSlice(p.Disks)
		case "windows_exporter":
			cp.URL = strings.TrimSpace(p.URL)
			cp.MaxDiskPercent = p.MaxDiskPercent
			cp.MaxRAMPercent = p.MaxRAMPercent
			cp.Disks = trimSlice(p.Disks)
			cp.Services = trimSlice(p.Services)
		default:
			cp = p
		}
		cleanedProbes = append(cleanedProbes, cp)
	}
	out.Probes = cleanedProbes

	return out
}

func dtoToYAML(dto ConfigDTO) ([]byte, error) {
	cleaned := cleanDTO(dto)
	raw, err := yaml.Marshal(&cleaned)
	if err != nil {
		return nil, fmt.Errorf("marshal YAML: %w", err)
	}
	return raw, nil
}

func defaultTemplateDTO() ConfigDTO {
	return ConfigDTO{
		Node: NodeDTO{
			Name:              "mon-homelab",
			HeartbeatInterval: "30s",
			PeerTimeout:       "90s",
		},
		Logging: LoggingDTO{
			Level:  "info",
			Format: "text",
		},
		Nostr: NostrDTO{
			Relays: []string{
				"wss://relay.damus.io",
				"wss://nos.lol",
				"wss://relay.primal.net",
				"wss://relay.nostr.band",
			},
		},
		AutoMute: AutoMuteDTO{
			Targets: []string{"1.1.1.1:443", "9.9.9.9:443"},
			Timeout: "3s",
		},
		Peers:  []PeerDTO{},
		Probes: []ProbeDTO{},
		Notifications: NotificationsDTO{
			PhotonIMessage: PhotonDTO{
				RecipientField: "recipient",
				MessageField:   "message",
			},
		},
	}
}

func trimSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}
