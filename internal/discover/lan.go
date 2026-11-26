package discover

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// SuggestedProbe describes a ready-to-add MeshWatch probe proposal from discovery.
type SuggestedProbe struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Interval           string   `json:"interval"`
	Timeout            string   `json:"timeout,omitempty"`
	URL                string   `json:"url,omitempty"`
	Host               string   `json:"host,omitempty"`
	Port               int      `json:"port,omitempty"`
	ExpectedStatus     int      `json:"expected_status,omitempty"`
	TLSMinDays         *int     `json:"tls_min_days,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
	SNMPVersion        string   `json:"snmp_version,omitempty"`
	Community          string   `json:"community,omitempty"`
	MaxTempC           int      `json:"max_temp_c,omitempty"`
	MaxCPUPercent      float64  `json:"max_cpu_percent,omitempty"`
	MaxDiskPercent     float64  `json:"max_disk_percent,omitempty"`
	MaxRAMPercent      float64  `json:"max_ram_percent,omitempty"`
	Services           []string `json:"services,omitempty"`
}

// DiscoveredItem represents a monitorable device or service detected on the local LAN.
type DiscoveredItem struct {
	Key            string         `json:"key"`
	IP             string         `json:"ip"`
	Hostname       string         `json:"hostname,omitempty"`
	Name           string         `json:"name"`
	Category       string         `json:"category"`       // synology, linux, windows, web, network
	CategoryLabel  string         `json:"category_label"` // Human French label
	Summary        string         `json:"summary"`
	Port           int            `json:"port"`
	OpenPorts      []int          `json:"open_ports"`
	SuggestedProbe SuggestedProbe `json:"suggested_probe"`
}

// LANScanResult summarizes a completed local network discovery pass.
type LANScanResult struct {
	Subnet     string           `json:"subnet"`
	ScannedIPs int              `json:"scanned_ips"`
	DurationMs int64            `json:"duration_ms"`
	Items      []DiscoveredItem `json:"items"`
}

// ScanOptions configures LAN scanning timing and concurrency (injectable for tests).
type ScanOptions struct {
	DialTimeout time.Duration
	HTTPTimeout time.Duration
	Workers     int
	Ports       []int
}

type portProfile struct {
	port       int
	https      bool
	hintName   string
	category   string
	skipTitle  bool
	isExporter string
}

var defaultPortProfiles = []portProfile{
	{port: 5000, https: false, hintName: "NAS Synology", category: "synology"},
	{port: 5001, https: true, hintName: "NAS Synology", category: "synology"},
	{port: 9100, https: false, hintName: "Serveur Linux", category: "linux", isExporter: "node_exporter"},
	{port: 9182, https: false, hintName: "Serveur Windows", category: "windows", isExporter: "windows_exporter"},
	{port: 8096, https: false, hintName: "Jellyfin", category: "web"},
	{port: 2283, https: false, hintName: "Immich", category: "web"},
	{port: 8123, https: false, hintName: "Home Assistant", category: "web"},
	{port: 8006, https: true, hintName: "Proxmox VE", category: "web"},
	{port: 3001, https: false, hintName: "Service Web", category: "web"},
	{port: 3002, https: false, hintName: "Uptime Kuma", category: "web"},
	{port: 9000, https: false, hintName: "Portainer", category: "web"},
	{port: 8080, https: false, hintName: "Service Web", category: "web"},
	{port: 8085, https: false, hintName: "Service Web", category: "web"},
	{port: 443, https: true, hintName: "Service HTTPS", category: "web"},
	{port: 80, https: false, hintName: "Service HTTP", category: "web"},
	{port: 22, skipTitle: true, hintName: "Serveur Linux (SSH)", category: "linux"},
	{port: 3389, skipTitle: true, hintName: "PC / Serveur Windows", category: "windows"},
}

var (
	htmlTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	nonSlugRe   = regexp.MustCompile(`[^a-z0-9]+`)
)

// DetectDefaultSubnet picks the best RFC1918 /24 subnet to suggest to the user.
func DetectDefaultSubnet(configuredHosts []string) string {
	if env := strings.TrimSpace(os.Getenv("MESHWATCH_LAN_SUBNET")); env != "" {
		if _, normalized, err := ParsePrivateCIDR(env); err == nil {
			return normalized
		}
	}

	// Prefer a private IP already referenced in configured probes.
	for _, raw := range configuredHosts {
		ip, ok := extractPrivateIPv4(raw)
		if ok && !isLikelyDockerBridge(ip) {
			return ipv4ToSlash24(ip)
		}
	}

	// Inspect local host interfaces, preferring 192.168.x.x / 10.x.x.x over Docker bridges.
	ifaces, err := net.Interfaces()
	if err == nil {
		var fallback netip.Addr
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				addr, ok := netip.AddrFromSlice(ipNet.IP.To4())
				if !ok || !isRFC1918(addr) {
					continue
				}
				if !isLikelyDockerBridge(addr) {
					return ipv4ToSlash24(addr)
				}
				if !fallback.IsValid() {
					fallback = addr
				}
			}
		}
		if fallback.IsValid() {
			return ipv4ToSlash24(fallback)
		}
	}

	return "192.168.1.0/24"
}

// ParsePrivateCIDR validates that cidr is a private RFC1918 IPv4 range of size /24../32
// (or a single private IPv4 address) and returns all target host IPs.
func ParsePrivateCIDR(raw string) ([]netip.Addr, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, "", errors.New("sous-réseau requis (ex. 192.168.1.0/24)")
	}
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			return nil, "", fmt.Errorf("adresse IPv4 invalide : %q", s)
		}
		if !isRFC1918(addr) && !addr.IsLoopback() {
			return nil, "", errors.New("seuls les réseaux privés locaux (192.168.x.x, 10.x.x.x, 172.16-31.x.x) sont autorisés")
		}
		return []netip.Addr{addr}, addr.String() + "/32", nil
	}

	pfx, err := netip.ParsePrefix(s)
	if err != nil || !pfx.Addr().Is4() {
		return nil, "", fmt.Errorf("plage CIDR invalide : %q (exemple : 192.168.1.0/24)", s)
	}
	pfx = pfx.Masked()
	if !isRFC1918(pfx.Addr()) && !pfx.Addr().IsLoopback() {
		return nil, "", errors.New("seuls les réseaux privés locaux (RFC1918) peuvent être scannés")
	}
	if pfx.Bits() < 24 {
		return nil, "", errors.New("le scan est limité à /24 maximum (254 appareils) pour rester rapide et léger")
	}

	var ips []netip.Addr
	for addr := pfx.Addr(); pfx.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}
	// Strip network and broadcast addresses for prefixes wider than /31.
	if pfx.Bits() <= 30 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, pfx.String(), nil
}

// ScanLAN performs a fast, non-intrusive local TCP discovery pass over a private RFC1918 subnet
// and returns user-friendly device/service monitoring suggestions.
func ScanLAN(ctx context.Context, cidr string, opts ScanOptions) (LANScanResult, error) {
	ips, normalized, err := ParsePrivateCIDR(cidr)
	if err != nil {
		return LANScanResult{}, err
	}

	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 280 * time.Millisecond
	}
	httpTimeout := opts.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = 700 * time.Millisecond
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 64
	}

	profiles := defaultPortProfiles
	if len(opts.Ports) > 0 {
		custom := make([]portProfile, 0, len(opts.Ports))
		byPort := make(map[int]portProfile, len(defaultPortProfiles))
		for _, pp := range defaultPortProfiles {
			byPort[pp.port] = pp
		}
		for _, pt := range opts.Ports {
			if known, ok := byPort[pt]; ok {
				custom = append(custom, known)
			} else {
				custom = append(custom, portProfile{port: pt, hintName: "Service réseau", category: "web"})
			}
		}
		profiles = custom
	}

	start := time.Now()

	// Phase 1: probe each (ip, port) pair via bounded worker pool.
	type scanTask struct {
		ip   string
		port int
	}
	tasks := make(chan scanTask, workers*2)
	var (
		openMu    sync.Mutex
		openByIP  = make(map[string][]int)
		workerWG  sync.WaitGroup
	)

	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for t := range tasks {
				if ctx.Err() != nil {
					return
				}
				dctx, cancel := context.WithTimeout(ctx, dialTimeout)
				var d net.Dialer
				conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(t.ip, fmt.Sprintf("%d", t.port)))
				cancel()
				if err == nil {
					_ = conn.Close()
					openMu.Lock()
					openByIP[t.ip] = append(openByIP[t.ip], t.port)
					openMu.Unlock()
				}
			}
		}()
	}

enqueueLoop:
	for _, addr := range ips {
		ipStr := addr.String()
		for _, pp := range profiles {
			select {
			case <-ctx.Done():
				break enqueueLoop
			case tasks <- scanTask{ip: ipStr, port: pp.port}:
			}
		}
	}
	close(tasks)
	workerWG.Wait()

	// Phase 2: classify and enrich responsive hosts concurrently.
	httpClient := &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local LAN banner discovery
		},
	}

	profileByPort := make(map[int]portProfile, len(profiles))
	for _, pp := range profiles {
		profileByPort[pp.port] = pp
	}

	var (
		itemsMu sync.Mutex
		items   []DiscoveredItem
		enrichWG sync.WaitGroup
	)
	sem := make(chan struct{}, 16)

	for ip, ports := range openByIP {
		sort.Ints(ports)
		enrichWG.Add(1)
		go func(hostIP string, openPorts []int) {
			defer enrichWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostItems := classifyHost(ctx, httpClient, hostIP, openPorts, profileByPort)
			if len(hostItems) > 0 {
				itemsMu.Lock()
				items = append(items, hostItems...)
				itemsMu.Unlock()
			}
		}(ip, ports)
	}
	enrichWG.Wait()

	sort.Slice(items, func(i, j int) bool {
		if items[i].Category != items[j].Category {
			return categoryOrder(items[i].Category) < categoryOrder(items[j].Category)
		}
		if items[i].IP != items[j].IP {
			return items[i].IP < items[j].IP
		}
		return items[i].Port < items[j].Port
	})

	return LANScanResult{
		Subnet:     normalized,
		ScannedIPs: len(ips),
		DurationMs: time.Since(start).Milliseconds(),
		Items:      items,
	}, nil
}

func classifyHost(ctx context.Context, client *http.Client, ip string, openPorts []int, profiles map[int]portProfile) []DiscoveredItem {
	hostname := lookupFriendlyHost(ctx, ip)
	portSet := make(map[int]bool, len(openPorts))
	for _, p := range openPorts {
		portSet[p] = true
	}

	var out []DiscoveredItem
	hasSpecific := false

	// 1. Synology NAS detection (DSM ports 5000 / 5001)
	if portSet[5000] || portSet[5001] {
		dsmPort := 5000
		scheme := "http"
		if portSet[5001] && !portSet[5000] {
			dsmPort = 5001
			scheme = "https"
		}
		title := fetchHTMLTitle(ctx, client, fmt.Sprintf("%s://%s:%d", scheme, ip, dsmPort))
		name := "NAS Synology"
		if title != "" && strings.Contains(strings.ToLower(title), "synology") {
			name = cleanTitle(title)
		} else if hostname != "" {
			name = "NAS " + hostname
		}
		out = append(out, DiscoveredItem{
			Key:           fmt.Sprintf("synology:%s", ip),
			IP:            ip,
			Hostname:      hostname,
			Name:          name,
			Category:      "synology",
			CategoryLabel: "NAS Synology",
			Summary:       fmt.Sprintf("Interface DSM détectée sur %s (port %d). Surveillance SNMP Disques, RAID et température.", ip, dsmPort),
			Port:          dsmPort,
			OpenPorts:     openPorts,
			SuggestedProbe: SuggestedProbe{
				ID:          makeProbeID("syno", hostname, ip),
				Kind:        "synology",
				Interval:    "60s",
				Timeout:     "10s",
				Host:        ip,
				Port:        161,
				SNMPVersion: "2c",
				Community:   "public",
				MaxTempC:    55,
			},
		})
		hasSpecific = true
	}

	// 1b. Proxmox VE API detection (port 8006)
	if portSet[8006] {
		title := fetchHTMLTitle(ctx, client, fmt.Sprintf("https://%s:8006", ip))
		name := "Proxmox VE"
		if title != "" && strings.Contains(strings.ToLower(title), "proxmox") {
			name = cleanTitle(title)
		} else if hostname != "" {
			name = "Proxmox VE (" + hostname + ")"
		}
		out = append(out, DiscoveredItem{
			Key:           fmt.Sprintf("proxmox:%s", ip),
			IP:            ip,
			Hostname:      hostname,
			Name:          name,
			Category:      "proxmox",
			CategoryLabel: "Hyperviseur Proxmox VE",
			Summary:       fmt.Sprintf("Proxmox VE détecté sur %s:8006. Surveillance via API (nœuds, CPU, RAM, stockages et VM/LXC).", ip),
			Port:          8006,
			OpenPorts:     openPorts,
			SuggestedProbe: SuggestedProbe{
				ID:                 makeProbeID("proxmox", hostname, ip),
				Kind:               "proxmox",
				Interval:           "60s",
				Timeout:            "10s",
				URL:                fmt.Sprintf("https://%s:8006", ip),
				InsecureSkipVerify: true,
				MaxCPUPercent:      90,
				MaxRAMPercent:      90,
				MaxDiskPercent:     90,
			},
		})
		hasSpecific = true
	}

	// 2. Linux node_exporter (port 9100)
	if portSet[9100] {
		metricsURL := fmt.Sprintf("http://%s:9100/metrics", ip)
		if snippet := fetchBodySnippet(ctx, client, metricsURL, 2048); strings.Contains(snippet, "node_") {
			name := "Serveur Linux"
			if hostname != "" {
				name = hostname + " (Linux)"
			}
			out = append(out, DiscoveredItem{
				Key:           fmt.Sprintf("node_exporter:%s", ip),
				IP:            ip,
				Hostname:      hostname,
				Name:          name,
				Category:      "linux",
				CategoryLabel: "Serveur Linux",
				Summary:       fmt.Sprintf("Agent node_exporter actif sur %s:9100 (RAM et disques).", ip),
				Port:          9100,
				OpenPorts:     openPorts,
				SuggestedProbe: SuggestedProbe{
					ID:             makeProbeID("linux", hostname, ip),
					Kind:           "node_exporter",
					Interval:       "60s",
					Timeout:        "10s",
					URL:            metricsURL,
					MaxDiskPercent: 90,
					MaxRAMPercent:  92,
				},
			})
			hasSpecific = true
		}
	}

	// 3. Windows windows_exporter (port 9182)
	if portSet[9182] {
		metricsURL := fmt.Sprintf("http://%s:9182/metrics", ip)
		if snippet := fetchBodySnippet(ctx, client, metricsURL, 2048); strings.Contains(snippet, "windows_") {
			name := "Serveur Windows"
			if hostname != "" {
				name = hostname + " (Windows)"
			}
			out = append(out, DiscoveredItem{
				Key:           fmt.Sprintf("windows_exporter:%s", ip),
				IP:            ip,
				Hostname:      hostname,
				Name:          name,
				Category:      "windows",
				CategoryLabel: "Serveur Windows",
				Summary:       fmt.Sprintf("Agent windows_exporter actif sur %s:9182 (services, RAM, disques).", ip),
				Port:          9182,
				OpenPorts:     openPorts,
				SuggestedProbe: SuggestedProbe{
					ID:             makeProbeID("win", hostname, ip),
					Kind:           "windows_exporter",
					Interval:       "60s",
					Timeout:        "10s",
					URL:            metricsURL,
					MaxDiskPercent: 90,
					MaxRAMPercent:  92,
				},
			})
			hasSpecific = true
		}
	}

	// 4. Web applications / dashboards on open HTTP/HTTPS ports
	skipWeb := map[int]bool{5000: true, 5001: true, 8006: true, 9100: true, 9182: true, 22: true, 3389: true}
	for _, port := range openPorts {
		if skipWeb[port] {
			continue
		}
		pp := profiles[port]
		scheme := "http"
		if pp.https {
			scheme = "https"
		}
		targetURL := fmt.Sprintf("%s://%s:%d", scheme, ip, port)
		if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
			targetURL = fmt.Sprintf("%s://%s", scheme, ip)
		}

		title := fetchHTMLTitle(ctx, client, targetURL)
		appName := identifyWebApp(port, title, hostname)
		tlsDays := 0
		if scheme == "https" {
			tlsDays = 14
		}

		out = append(out, DiscoveredItem{
			Key:           fmt.Sprintf("http:%s:%d", ip, port),
			IP:            ip,
			Hostname:      hostname,
			Name:          appName,
			Category:      "web",
			CategoryLabel: "Application web",
			Summary:       fmt.Sprintf("Service joignable sur %s", targetURL),
			Port:          port,
			OpenPorts:     openPorts,
			SuggestedProbe: SuggestedProbe{
				ID:                 makeProbeID(slugify(appName), "", fmt.Sprintf("%s-%d", ip, port)),
				Kind:               "http",
				Interval:           "30s",
				Timeout:            "10s",
				URL:                targetURL,
				ExpectedStatus:     200,
				TLSMinDays:         &tlsDays,
				InsecureSkipVerify: scheme == "https",
			},
		})
		hasSpecific = true
	}

	// 5. Fallback: SSH (22) or Windows RDP (3389) if no higher-level app/exporter was detected.
	if !hasSpecific {
		if portSet[3389] {
			name := "Poste ou serveur Windows"
			if hostname != "" {
				name = hostname
			}
			out = append(out, DiscoveredItem{
				Key:           fmt.Sprintf("tcp:%s:3389", ip),
				IP:            ip,
				Hostname:      hostname,
				Name:          name,
				Category:      "windows",
				CategoryLabel: "Appareil Windows",
				Summary:       fmt.Sprintf("Port RDP 3389 ouvert sur %s", ip),
				Port:          3389,
				OpenPorts:     openPorts,
				SuggestedProbe: SuggestedProbe{
					ID:       makeProbeID("win", hostname, ip),
					Kind:     "tcp",
					Interval: "60s",
					Timeout:  "5s",
					Host:     ip,
					Port:     3389,
				},
			})
		} else if portSet[22] {
			name := "Serveur Linux / SSH"
			if hostname != "" {
				name = hostname
			}
			out = append(out, DiscoveredItem{
				Key:           fmt.Sprintf("tcp:%s:22", ip),
				IP:            ip,
				Hostname:      hostname,
				Name:          name,
				Category:      "linux",
				CategoryLabel: "Serveur SSH",
				Summary:       fmt.Sprintf("Port SSH 22 ouvert sur %s", ip),
				Port:          22,
				OpenPorts:     openPorts,
				SuggestedProbe: SuggestedProbe{
					ID:       makeProbeID("ssh", hostname, ip),
					Kind:     "tcp",
					Interval: "60s",
					Timeout:  "5s",
					Host:     ip,
					Port:     22,
				},
			})
		}
	}

	return out
}

func identifyWebApp(port int, title, hostname string) string {
	cleaned := cleanTitle(title)
	if cleaned != "" {
		return cleaned
	}
	switch port {
	case 8096:
		return "Jellyfin"
	case 2283:
		return "Immich"
	case 8123:
		return "Home Assistant"
	case 8006:
		return "Proxmox VE"
	case 3002:
		return "Uptime Kuma"
	case 9000:
		return "Portainer"
	default:
		if hostname != "" {
			return fmt.Sprintf("%s (:%d)", hostname, port)
		}
		return fmt.Sprintf("Application web (:%d)", port)
	}
}

func fetchHTMLTitle(ctx context.Context, client *http.Client, targetURL string) string {
	snippet := fetchBodySnippet(ctx, client, targetURL, 8192)
	if snippet == "" {
		return ""
	}
	m := htmlTitleRe.FindStringSubmatch(snippet)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func fetchBodySnippet(ctx context.Context, client *http.Client, targetURL string, maxBytes int64) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "MeshWatch-Discovery/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return string(b)
}

func cleanTitle(raw string) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(raw)), " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&#39;", "'")
	if len(s) > 42 {
		s = s[:42]
	}
	return s
}

func lookupFriendlyHost(ctx context.Context, ip string) string {
	lctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.TrimSuffix(names[0], ".")
	if dot := strings.IndexByte(name, '.'); dot > 0 {
		name = name[:dot]
	}
	return name
}

func makeProbeID(prefix, hostname, fallback string) string {
	base := slugify(prefix)
	suffix := slugify(hostname)
	if suffix == "" {
		parts := strings.Split(fallback, ".")
		suffix = slugify(parts[len(parts)-1])
	}
	if base == "" {
		base = "service"
	}
	if suffix == "" || strings.Contains(base, suffix) {
		return base
	}
	id := base + "-" + suffix
	if len(id) > 32 {
		id = id[:32]
	}
	return strings.Trim(id, "-")
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonSlugRe.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

func categoryOrder(cat string) int {
	switch cat {
	case "synology":
		return 0
	case "proxmox":
		return 1
	case "web":
		return 2
	case "linux":
		return 3
	case "windows":
		return 4
	default:
		return 5
	}
}

func isRFC1918(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	if b[0] == 10 {
		return true
	}
	if b[0] == 172 && b[1] >= 16 && b[1] <= 31 {
		return true
	}
	if b[0] == 192 && b[1] == 168 {
		return true
	}
	return false
}

func isLikelyDockerBridge(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] == 172 && b[1] >= 16 && b[1] <= 31
}

func ipv4ToSlash24(addr netip.Addr) string {
	b := addr.As4()
	return fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
}

func extractPrivateIPv4(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if slash := strings.IndexByte(s, '/'); slash >= 0 {
		s = s[:slash]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !isRFC1918(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}
