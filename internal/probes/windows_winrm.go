package probes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bodgit/ntlmssp"

	"meshwatch/internal/config"
)

const (
	wsmvBoundary         = "Encrypted Boundary"
	wsmvProtocolSPNEGO   = "application/HTTP-SPNEGO-session-encrypted"
	wsmvSOAPContentType  = "application/soap+xml;charset=UTF-8"
	maxWinRMBodyBytes    = 8 << 20
	maxWinRMPullPages    = 10
	winrmEnumerateAction = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	winrmPullAction      = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
)

var (
	errWMIInvalidNamespace = errors.New("WMI namespace unavailable")
	guidPattern            = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// WindowsWinRMProbe monitors a Windows workstation/server and optional Hyper-V host
// agentlessly over WS-Management (WinRM port 5985 encrypted NTLM, or HTTPS port 5986).
type WindowsWinRMProbe struct {
	id                 string
	host               string
	port               int
	useHTTPS           bool
	insecureSkipVerify bool
	domain             string
	user               string
	password           string
	maxCPUPercent      float64
	maxRAMPercent      float64
	maxDiskPercent     float64
	disks              []string
	services           []string
	vms                []string

	// queryFn may be injected in tests to bypass network transport.
	queryFn func(ctx context.Context, namespace, wql string) ([]map[string]string, error)
}

// NewWindowsWinRMProbe creates a WindowsWinRMProbe from configuration.
func NewWindowsWinRMProbe(cfg config.ProbeConfig) *WindowsWinRMProbe {
	port := cfg.Port
	if port <= 0 {
		if cfg.UseHTTPS {
			port = config.DefaultWinRMHTTPSPort
		} else {
			port = config.DefaultWinRMPort
		}
	}
	return &WindowsWinRMProbe{
		id:                 cfg.ID,
		host:               strings.TrimSpace(cfg.Host),
		port:               port,
		useHTTPS:           cfg.UseHTTPS,
		insecureSkipVerify: cfg.InsecureSkipVerify,
		domain:             strings.TrimSpace(cfg.Domain),
		user:               strings.TrimSpace(cfg.User),
		password:           cfg.Password,
		maxCPUPercent:      cfg.MaxCPUPercent,
		maxRAMPercent:      cfg.MaxRAMPercent,
		maxDiskPercent:     cfg.MaxDiskPercent,
		disks:              append([]string(nil), cfg.Disks...),
		services:           append([]string(nil), cfg.Services...),
		vms:                append([]string(nil), cfg.VMs...),
	}
}

func (p *WindowsWinRMProbe) ID() string   { return p.id }
func (p *WindowsWinRMProbe) Kind() string { return "windows_winrm" }

func (p *WindowsWinRMProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	query := p.queryFn
	var sess *winrmSession
	if query == nil {
		sess = p.newSession()
		defer sess.close()
		query = sess.queryWQL
	}

	ok, summary, metrics, err := p.collectAndEvaluate(ctx, query)
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: humanizeWinRMError(err, p.host, p.port, p.useHTTPS),
			Latency: time.Since(start).Milliseconds(),
		}
	}
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      ok,
		Summary: summary,
		Latency: time.Since(start).Milliseconds(),
		Metrics: metrics,
	}
}

func (p *WindowsWinRMProbe) collectAndEvaluate(
	ctx context.Context,
	query func(ctx context.Context, namespace, wql string) ([]map[string]string, error),
) (bool, string, *ProbeMetrics, error) {
	osRows, err := query(ctx, "root/cimv2", "SELECT Caption, CSName, TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem")
	if err != nil {
		return false, "", nil, err
	}

	cpuRows, err := query(ctx, "root/cimv2", "SELECT LoadPercentage FROM Win32_Processor")
	if err != nil {
		return false, "", nil, err
	}

	diskRows, err := query(ctx, "root/cimv2", "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3")
	if err != nil {
		return false, "", nil, err
	}

	var svcRows []map[string]string
	if len(p.services) > 0 {
		svcRows, err = query(ctx, "root/cimv2", "SELECT Name, State FROM Win32_Service")
		if err != nil {
			return false, "", nil, err
		}
	}

	var hvRows []map[string]string
	hyperVUnavailable := false
	hvRows, hvErr := query(ctx, "root/virtualization/v2", "SELECT Name, ElementName, EnabledState, HealthState FROM Msvm_ComputerSystem")
	if hvErr != nil {
		if errors.Is(hvErr, errWMIInvalidNamespace) {
			hyperVUnavailable = true
		} else if len(p.vms) > 0 {
			return false, "", nil, hvErr
		}
	}

	ok, summary, metrics := evaluateWindowsSnapshotDetailed(
		osRows,
		cpuRows,
		diskRows,
		svcRows,
		hvRows,
		hyperVUnavailable,
		p.maxCPUPercent,
		p.maxRAMPercent,
		p.maxDiskPercent,
		p.disks,
		p.services,
		p.vms,
		p.host,
	)
	return ok, summary, metrics, nil
}

func evaluateWindowsSnapshot(
	osRows, cpuRows, diskRows, svcRows, hvRows []map[string]string,
	hyperVUnavailable bool,
	maxCPUPct, maxRAMPct, maxDiskPct float64,
	diskFilter, requiredServices, requiredVMs []string,
	fallbackHost string,
) (bool, string) {
	ok, summary, _ := evaluateWindowsSnapshotDetailed(
		osRows, cpuRows, diskRows, svcRows, hvRows, hyperVUnavailable,
		maxCPUPct, maxRAMPct, maxDiskPct, diskFilter, requiredServices, requiredVMs, fallbackHost,
	)
	return ok, summary
}

func evaluateWindowsSnapshotDetailed(
	osRows, cpuRows, diskRows, svcRows, hvRows []map[string]string,
	hyperVUnavailable bool,
	maxCPUPct, maxRAMPct, maxDiskPct float64,
	diskFilter, requiredServices, requiredVMs []string,
	fallbackHost string,
) (bool, string, *ProbeMetrics) {
	var issues []string
	m := &ProbeMetrics{}

	hostName := strings.TrimSpace(fallbackHost)
	ramPct := -1.0
	if len(osRows) > 0 {
		if cs := strings.TrimSpace(osRows[0]["csname"]); cs != "" {
			hostName = cs
		}
		m.OS = strings.TrimSpace(osRows[0]["caption"])
		totalKB, tOK := parseWMIUint(osRows[0]["totalvisiblememorysize"])
		freeKB, fOK := parseWMIUint(osRows[0]["freephysicalmemory"])
		if tOK && fOK && totalKB > 0 {
			usedKB := 0.0
			if totalKB > freeKB {
				usedKB = totalKB - freeKB
			}
			ramPct = (usedKB / totalKB) * 100.0
			m.RAMPercent = floatPtr(ramPct)
			m.RAMUsedMB = usedKB / 1024.0
			m.RAMTotalMB = totalKB / 1024.0
		}
	}
	if hostName == "" {
		hostName = "Windows"
	}
	m.Hostname = hostName

	cpuPct := -1.0
	var cpuSum float64
	var cpuCount int
	for _, r := range cpuRows {
		if v, ok := parseWMIUint(r["loadpercentage"]); ok {
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			cpuSum += v
			cpuCount++
		}
	}
	if cpuCount > 0 {
		cpuPct = cpuSum / float64(cpuCount)
		m.CPUPercent = floatPtr(cpuPct)
	}

	if maxCPUPct > 0 && cpuPct >= 0 && cpuPct > maxCPUPct {
		issues = append(issues, fmt.Sprintf("CPU %.1f%% > %.0f%%", cpuPct, maxCPUPct))
	}
	if maxRAMPct > 0 && ramPct >= 0 && ramPct > maxRAMPct {
		issues = append(issues, fmt.Sprintf("RAM %.1f%% > %.0f%%", ramPct, maxRAMPct))
	}

	// Disks
	wantedDisks := make(map[string]struct{}, len(diskFilter))
	for _, d := range diskFilter {
		if norm := normalizeDriveLetter(d); norm != "" {
			wantedDisks[norm] = struct{}{}
		}
	}
	seenDisks := make(map[string]bool)
	maxDisk := -1.0
	maxDiskName := ""

	sort.Slice(diskRows, func(i, j int) bool {
		return normalizeDriveLetter(diskRows[i]["deviceid"]) < normalizeDriveLetter(diskRows[j]["deviceid"])
	})
	for _, r := range diskRows {
		dev := normalizeDriveLetter(r["deviceid"])
		if dev == "" {
			continue
		}
		if len(wantedDisks) > 0 {
			if _, ok := wantedDisks[dev]; !ok {
				continue
			}
		}
		sizeBytes, sOK := parseWMIUint(r["size"])
		freeBytes, fOK := parseWMIUint(r["freespace"])
		if !sOK || !fOK || sizeBytes <= 0 {
			continue
		}
		seenDisks[dev] = true
		usedBytes := 0.0
		if sizeBytes > freeBytes {
			usedBytes = sizeBytes - freeBytes
		}
		usedPct := (usedBytes / sizeBytes) * 100.0
		diskStatus := "OK"
		if maxDiskPct > 0 && usedPct > maxDiskPct {
			diskStatus = "Saturé"
			issues = append(issues, fmt.Sprintf("Disque %s %.1f%% > %.0f%%", dev, usedPct, maxDiskPct))
		}
		m.Disks = append(m.Disks, DiskMetric{
			Name:        dev,
			Mount:       dev,
			UsedPercent: usedPct,
			UsedGB:      usedBytes / (1024 * 1024 * 1024),
			TotalGB:     sizeBytes / (1024 * 1024 * 1024),
			Status:      diskStatus,
		})
		if usedPct > maxDisk {
			maxDisk = usedPct
			maxDiskName = dev
		}
	}
	if maxDisk >= 0 {
		m.DiskMaxPct = floatPtr(maxDisk)
	}
	for _, rawWant := range diskFilter {
		norm := normalizeDriveLetter(rawWant)
		if norm != "" && !seenDisks[norm] {
			issues = append(issues, fmt.Sprintf("Disque %s introuvable", norm))
		}
	}

	// Windows services
	svcStates := make(map[string]string, len(svcRows))
	for _, r := range svcRows {
		if n := strings.ToLower(strings.TrimSpace(r["name"])); n != "" {
			svcStates[n] = strings.TrimSpace(r["state"])
		}
	}
	okSvc := 0
	for _, rawSvc := range requiredServices {
		want := strings.TrimSpace(rawSvc)
		if want == "" {
			continue
		}
		st, found := svcStates[strings.ToLower(want)]
		if !found {
			issues = append(issues, fmt.Sprintf("Service %s introuvable", want))
			m.Services = append(m.Services, ServiceMetric{Name: want, State: "introuvable", OK: false})
			continue
		}
		if !strings.EqualFold(st, "Running") {
			issues = append(issues, fmt.Sprintf("Service %s (%s)", want, fallbackStr(st, "stopped")))
			m.Services = append(m.Services, ServiceMetric{Name: want, State: fallbackStr(st, "stopped"), OK: false})
			continue
		}
		okSvc++
		m.Services = append(m.Services, ServiceMetric{Name: want, State: st, OK: true})
	}

	// Hyper-V VMs (Msvm_ComputerSystem: VM rows have a GUID in Name; the host row has the machine name).
	type hvVM struct {
		name         string
		guid         string
		enabledState string
		healthState  string
	}
	var vms []hvVM
	byName := make(map[string]hvVM)
	byGUID := make(map[string]hvVM)
	runningVMs := 0

	for _, r := range hvRows {
		rawName := strings.TrimSpace(r["name"])
		if !guidPattern.MatchString(rawName) {
			continue
		}
		vm := hvVM{
			name:         fallbackStr(strings.TrimSpace(r["elementname"]), rawName),
			guid:         rawName,
			enabledState: strings.TrimSpace(r["enabledstate"]),
			healthState:  strings.TrimSpace(r["healthstate"]),
		}
		vms = append(vms, vm)
		byName[strings.ToLower(vm.name)] = vm
		byGUID[strings.ToLower(vm.guid)] = vm
		if vm.enabledState == "2" {
			runningVMs++
		}
		m.Guests = append(m.Guests, GuestMetric{
			ID:     vm.guid,
			Name:   vm.name,
			Type:   "hyper-v",
			Status: hyperVStateLabel(vm.enabledState),
			Health: hyperVHealthLabel(vm.healthState),
		})
	}

	if hyperVUnavailable {
		for _, rawVM := range requiredVMs {
			if strings.TrimSpace(rawVM) != "" {
				issues = append(issues, "Hyper-V non installé sur cette machine (namespace root/virtualization/v2 absent)")
				break
			}
		}
	} else {
		for _, rawVM := range requiredVMs {
			want := strings.TrimSpace(rawVM)
			if want == "" {
				continue
			}
			vm, ok := byName[strings.ToLower(want)]
			if !ok {
				vm, ok = byGUID[strings.ToLower(want)]
			}
			if !ok {
				issues = append(issues, fmt.Sprintf("VM Hyper-V %s introuvable", want))
				continue
			}
			if vm.enabledState != "2" {
				issues = append(issues, fmt.Sprintf("VM Hyper-V %s (%s)", vm.name, hyperVStateLabel(vm.enabledState)))
				continue
			}
			if vm.healthState == "20" || vm.healthState == "25" {
				issues = append(issues, fmt.Sprintf("VM Hyper-V %s en erreur critique", vm.name))
			}
		}
	}

	if len(issues) > 0 {
		return false, strings.Join(issues, "; "), m
	}

	parts := []string{hostName}
	if cpuPct >= 0 {
		parts = append(parts, fmt.Sprintf("CPU %.0f%%", cpuPct))
	}
	if ramPct >= 0 {
		parts = append(parts, fmt.Sprintf("RAM %.0f%%", ramPct))
	}
	if maxDisk >= 0 {
		parts = append(parts, fmt.Sprintf("Disque %s %.0f%%", maxDiskName, maxDisk))
	}
	if !hyperVUnavailable && len(vms) > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d VM Hyper-V actives", runningVMs, len(vms)))
	}
	if len(requiredServices) > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d services OK", okSvc, countNonEmpty(requiredServices)))
	}
	return true, strings.Join(parts, ", "), m
}

func hyperVHealthLabel(code string) string {
	switch strings.TrimSpace(code) {
	case "5":
		return "sain"
	case "20":
		return "majeur"
	case "25":
		return "critique"
	default:
		return strings.TrimSpace(code)
	}
}

func hyperVStateLabel(code string) string {
	switch strings.TrimSpace(code) {
	case "2":
		return "active"
	case "3":
		return "arrêtée"
	case "6", "32769":
		return "enregistrée"
	case "9", "32768":
		return "en pause"
	case "32770":
		return "démarrage"
	case "32773":
		return "enregistrement"
	case "32774":
		return "arrêt en cours"
	default:
		if code == "" {
			return "inactive"
		}
		return "état " + code
	}
}

func normalizeDriveLetter(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimRight(s, `\/`)
	s = strings.ToUpper(s)
	if len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' {
		s += ":"
	}
	return s
}

func parseWMIUint(raw string) (float64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func countNonEmpty(items []string) int {
	n := 0
	for _, s := range items {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}

func splitWindowsCredentials(user, explicitDomain string) (domain, username string) {
	u := strings.TrimSpace(user)
	d := strings.TrimSpace(explicitDomain)
	if d != "" {
		if idx := strings.IndexByte(u, '\\'); idx > 0 {
			u = u[idx+1:]
		}
		return d, u
	}
	if idx := strings.IndexByte(u, '\\'); idx > 0 {
		return strings.TrimSpace(u[:idx]), strings.TrimSpace(u[idx+1:])
	}
	return "", u
}

func humanizeWinRMError(err error, host string, port int, useHTTPS bool) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	if strings.HasPrefix(msg, "WinRM") {
		return msg
	}
	if strings.Contains(low, "connection refused") {
		return fmt.Sprintf("WinRM inaccessible sur %s:%d (connexion refusée) — sur Windows 10/11 exécutez en PowerShell Admin : Enable-PSRemoting -Force", host, port)
	}
	if strings.Contains(low, "timeout") || strings.Contains(low, "deadline exceeded") {
		return fmt.Sprintf("WinRM ne répond pas sur %s:%d (délai dépassé) — vérifiez l'adresse IP et le pare-feu Windows", host, port)
	}
	if strings.Contains(low, "no such host") {
		return fmt.Sprintf("WinRM : hôte %q introuvable", host)
	}
	if useHTTPS && (strings.Contains(low, "tls:") || strings.Contains(low, "x509:") || strings.Contains(low, "certificate")) {
		return fmt.Sprintf("WinRM HTTPS : erreur de certificat TLS sur %s:%d (%s) — activez « Accepter le certificat auto-signé » dans les options avancées", host, port, msg)
	}
	return "WinRM : " + msg
}

type winrmSession struct {
	endpoint           string
	useHTTPS           bool
	insecureSkipVerify bool
	domain             string
	user               string
	password           string

	transport   *http.Transport
	client      *http.Client
	ntlm        *ntlmssp.Client
	encrypt     bool
	useBasic    bool
	authed      bool
	basicHeader string
}

func (p *WindowsWinRMProbe) newSession() *winrmSession {
	scheme := "http"
	if p.useHTTPS {
		scheme = "https"
	}
	endpoint := fmt.Sprintf("%s://%s/wsman", scheme, net.JoinHostPort(p.host, strconv.Itoa(p.port)))
	dom, usr := splitWindowsCredentials(p.user, p.domain)

	tr := &http.Transport{
		DisableKeepAlives:   false,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.insecureSkipVerify, //nolint:gosec // user-enabled for self-signed WinRM certificates
		},
	}
	jar, _ := cookiejar.New(nil)
	return &winrmSession{
		endpoint:           endpoint,
		useHTTPS:           p.useHTTPS,
		insecureSkipVerify: p.insecureSkipVerify,
		domain:             dom,
		user:               usr,
		password:           p.password,
		transport:          tr,
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		},
	}
}

func (s *winrmSession) close() {
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

func (s *winrmSession) resetAuth() {
	s.authed = false
	s.encrypt = false
	s.ntlm = nil
	s.useBasic = false
	s.basicHeader = ""
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

func (s *winrmSession) authenticate(ctx context.Context) error {
	// Step 1: initial blank POST to probe authentication schemes.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "MeshWatch/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		s.authed = true
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("HTTP %d inattendu lors de la connexion WinRM", resp.StatusCode)
	}

	scheme, _ := pickWinRMAuthScheme(resp.Header.Values("WWW-Authenticate"))
	switch scheme {
	case "Negotiate", "NTLM":
		// Proceed with NTLMv2 handshake.
	case "Basic":
		credUser := s.user
		if s.domain != "" {
			credUser = s.domain + `\` + s.user
		}
		s.basicHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(credUser+":"+s.password))
		s.useBasic = true
		s.authed = true
		return nil
	default:
		return fmt.Errorf("méthode d'authentification WinRM non supportée (%s)", strings.Join(resp.Header.Values("WWW-Authenticate"), ", "))
	}

	ntlmClient, err := ntlmssp.NewClient(
		ntlmssp.SetDomain(s.domain),
		ntlmssp.SetUserInfo(s.user, s.password),
		ntlmssp.SetWorkstation("MESHWATCH"),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return fmt.Errorf("initialisation NTLM : %w", err)
	}

	// Step 2: send NTLM Type 1 (Negotiate).
	type1, err := ntlmClient.Authenticate(nil, nil)
	if err != nil {
		return fmt.Errorf("NTLM Type 1 : %w", err)
	}
	req1, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, http.NoBody)
	if err != nil {
		return err
	}
	req1.Header.Set("User-Agent", "MeshWatch/1.0")
	req1.Header.Set("Accept-Encoding", "identity")
	req1.Header.Set("Connection", "Keep-Alive")
	req1.Header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString(type1))

	resp1, err := s.client.Do(req1)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp1.Body, 64*1024))
	_ = resp1.Body.Close()

	if resp1.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("réponse HTTP %d inattendue pendant NTLM Type 2", resp1.StatusCode)
	}

	matchedScheme, challenge := pickWinRMAuthScheme(resp1.Header.Values("WWW-Authenticate"))
	if len(challenge) == 0 {
		return errors.New("authentification NTLM refusée ou jeton Challenge absent")
	}
	if matchedScheme != "" {
		scheme = matchedScheme
	}

	var cbt *ntlmssp.ChannelBindings
	if resp1.TLS != nil && len(resp1.TLS.PeerCertificates) > 0 {
		cbt = generateWinRMChannelBindings(resp1.TLS.PeerCertificates[0])
	}

	// Step 3: send NTLM Type 3 (Authenticate).
	type3, err := ntlmClient.Authenticate(challenge, cbt)
	if err != nil {
		return fmt.Errorf("NTLM Type 3 : %w", err)
	}
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, http.NoBody)
	if err != nil {
		return err
	}
	req2.Header.Set("User-Agent", "MeshWatch/1.0")
	req2.Header.Set("Accept-Encoding", "identity")
	req2.Header.Set("Connection", "Keep-Alive")
	req2.Header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString(type3))

	resp2, err := s.client.Do(req2)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp2.Body, 64*1024))
	_ = resp2.Body.Close()

	if resp2.StatusCode == http.StatusUnauthorized || resp2.StatusCode == http.StatusForbidden {
		return fmt.Errorf("WinRM : authentification refusée (HTTP %d) — vérifiez identifiant/mot de passe (compte administrateur requis ; pour un compte local hors Administrateur intégré, activez LocalAccountTokenFilterPolicy)", resp2.StatusCode)
	}
	if resp2.StatusCode >= 400 && resp2.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("HTTP %d après authentification NTLM", resp2.StatusCode)
	}

	s.ntlm = ntlmClient
	s.encrypt = !s.useHTTPS && ntlmClient.SecuritySession() != nil
	s.authed = true
	return nil
}

func (s *winrmSession) postSOAP(ctx context.Context, soapXML []byte) ([]byte, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if !s.authed {
			if err := s.authenticate(ctx); err != nil {
				return nil, 0, err
			}
		}

		payload := soapXML
		contentType := wsmvSOAPContentType
		var encSession *ntlmssp.SecuritySession
		if s.ntlm != nil {
			encSession = s.ntlm.SecuritySession()
		}
		if s.encrypt && encSession != nil {
			var err error
			payload, contentType, err = wrapWSMV(encSession, soapXML)
			if err != nil {
				return nil, 0, fmt.Errorf("chiffrement WSMV : %w", err)
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, 0, err
		}
		req.ContentLength = int64(len(payload))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", "MeshWatch/1.0")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Connection", "Keep-Alive")
		if s.useBasic && s.basicHeader != "" {
			req.Header.Set("Authorization", s.basicHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxWinRMBodyBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}

		// Re-authenticate once if a keep-alive TCP socket was recycled.
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			s.resetAuth()
			continue
		}

		respCT := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
		if (strings.HasPrefix(respCT, "multipart/encrypted") || strings.HasPrefix(respCT, "multipart/x-multi-encrypted")) && encSession != nil {
			plain, err := unwrapWSMV(encSession, rawBody, resp.Header.Get("Content-Type"))
			if err != nil {
				return nil, resp.StatusCode, fmt.Errorf("déchiffrement WSMV : %w", err)
			}
			rawBody = plain
		}

		return rawBody, resp.StatusCode, nil
	}
	return nil, http.StatusUnauthorized, errors.New("WinRM : authentification refusée")
}

func (s *winrmSession) queryWQL(ctx context.Context, namespace, wql string) ([]map[string]string, error) {
	resourceURI := "http://schemas.microsoft.com/wbem/wsman/1/wmi/" + strings.TrimPrefix(namespace, "/") + "/*"
	enumEnv := buildWSManEnumerateEnvelope(s.endpoint, resourceURI, wql, 100)

	raw, code, err := s.postSOAP(ctx, enumEnv)
	if err != nil {
		return nil, err
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return nil, fmt.Errorf("WinRM : authentification refusée (HTTP %d) — vérifiez identifiant/mot de passe", code)
	}

	parsed, err := parseWSManResponse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.fault != "" {
		if isInvalidNamespaceFault(parsed.fault, parsed.faultCode, namespace) {
			return nil, errWMIInvalidNamespace
		}
		return nil, fmt.Errorf("WinRM WMI fault : %s", parsed.fault)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("WinRM HTTP %d", code)
	}

	rows := append([]map[string]string(nil), parsed.rows...)
	enumCtx := parsed.enumContext
	endOfSeq := parsed.endOfSequence

	for page := 0; !endOfSeq && enumCtx != "" && page < maxWinRMPullPages; page++ {
		pullEnv := buildWSManPullEnvelope(s.endpoint, resourceURI, enumCtx, 100)
		pRaw, pCode, pErr := s.postSOAP(ctx, pullEnv)
		if pErr != nil {
			return nil, pErr
		}
		pParsed, pParseErr := parseWSManResponse(pRaw)
		if pParseErr != nil {
			return nil, pParseErr
		}
		if pParsed.fault != "" {
			return nil, fmt.Errorf("WinRM WMI fault : %s", pParsed.fault)
		}
		if pCode != http.StatusOK {
			return nil, fmt.Errorf("WinRM HTTP %d", pCode)
		}
		rows = append(rows, pParsed.rows...)
		enumCtx = pParsed.enumContext
		endOfSeq = pParsed.endOfSequence
	}

	return rows, nil
}

func pickWinRMAuthScheme(headers []string) (string, []byte) {
	candidates := make(map[string][]byte)
	for _, rawHdr := range headers {
		for _, part := range strings.Split(rawHdr, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			fields := strings.Fields(part)
			scheme := fields[0]
			var token []byte
			if len(fields) > 1 {
				if decoded, err := base64.StdEncoding.DecodeString(fields[1]); err == nil {
					token = decoded
				}
			}
			switch {
			case strings.EqualFold(scheme, "Negotiate"):
				if _, exists := candidates["Negotiate"]; !exists || len(token) > 0 {
					candidates["Negotiate"] = token
				}
			case strings.EqualFold(scheme, "NTLM"):
				if _, exists := candidates["NTLM"]; !exists || len(token) > 0 {
					candidates["NTLM"] = token
				}
			case strings.EqualFold(scheme, "Basic"):
				if _, exists := candidates["Basic"]; !exists {
					candidates["Basic"] = nil
				}
			}
		}
	}
	for _, preferred := range []string{"Negotiate", "NTLM", "Basic"} {
		if tok, ok := candidates[preferred]; ok {
			return preferred, tok
		}
	}
	return "", nil
}

func generateWinRMChannelBindings(cert *x509.Certificate) *ntlmssp.ChannelBindings {
	if cert == nil {
		return nil
	}
	var h []byte
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA:
		return nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(cert.Raw)
		h = sum[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(cert.Raw)
		h = sum[:]
	default:
		// RFC 5929 section 4.1: MD5/SHA1/SHA256 certificates use SHA-256.
		sum := sha256.Sum256(cert.Raw)
		h = sum[:]
	}
	appData := make([]byte, 0, len(ntlmssp.TLSServerEndPoint)+1+len(h))
	appData = append(appData, ntlmssp.TLSServerEndPoint+":"...)
	appData = append(appData, h...)
	return &ntlmssp.ChannelBindings{ApplicationData: appData}
}

func wrapWSMV(session *ntlmssp.SecuritySession, plain []byte) ([]byte, string, error) {
	if session == nil {
		return nil, "", errors.New("missing NTLM security session")
	}
	sealed, sig, err := session.Wrap(plain)
	if err != nil {
		return nil, "", err
	}

	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(sig)))

	var buf bytes.Buffer
	buf.Grow(len(sealed) + len(sig) + 256)
	buf.WriteString("--" + wsmvBoundary + "\r\n")
	buf.WriteString("\tContent-Type: " + wsmvProtocolSPNEGO + "\r\n")
	fmt.Fprintf(&buf, "\tOriginalContent: type=%s;Length=%d\r\n", wsmvSOAPContentType, len(plain))
	buf.WriteString("--" + wsmvBoundary + "\r\n")
	buf.WriteString("\tContent-Type: application/octet-stream\r\n")
	buf.Write(lenBuf[:])
	buf.Write(sig)
	buf.Write(sealed)
	buf.WriteString("--" + wsmvBoundary + "--\r\n")

	ct := fmt.Sprintf("multipart/encrypted;protocol=%q;boundary=%q", wsmvProtocolSPNEGO, wsmvBoundary)
	return buf.Bytes(), ct, nil
}

func unwrapWSMV(session *ntlmssp.SecuritySession, body []byte, contentType string) ([]byte, error) {
	if session == nil {
		return nil, errors.New("missing NTLM security session")
	}
	boundary := wsmvBoundary
	if _, params, err := mime.ParseMediaType(contentType); err == nil && params["boundary"] != "" {
		boundary = params["boundary"]
	}

	splitRe := regexp.MustCompile(`--\s*` + regexp.QuoteMeta(boundary) + `\r?\n`)
	endRe := regexp.MustCompile(`--\s*` + regexp.QuoteMeta(boundary) + `--\r?\n?$`)
	octetHdrRe := regexp.MustCompile(`(?i)^[ \t]*Content-Type:\s*application/octet-stream\r?\n(?:\r?\n)?`)

	rawParts := splitRe.Split(string(body), -1)
	var nonEmpty [][]byte
	for _, p := range rawParts {
		if len(p) > 0 {
			nonEmpty = append(nonEmpty, []byte(p))
		}
	}
	if len(nonEmpty) < 2 || len(nonEmpty)%2 != 0 {
		return nil, fmt.Errorf("structure multipart WSMV invalide (%d parties)", len(nonEmpty))
	}

	var plainOut bytes.Buffer
	for i := 0; i < len(nonEmpty); i += 2 {
		payload := endRe.ReplaceAll(nonEmpty[i+1], nil)
		payload = octetHdrRe.ReplaceAll(payload, nil)
		if len(payload) < 4 {
			return nil, errors.New("bloc chiffré WSMV tronqué")
		}
		sigLen := int(binary.LittleEndian.Uint32(payload[:4]))
		if sigLen <= 0 || 4+sigLen > len(payload) {
			return nil, fmt.Errorf("longueur de signature WSMV invalide (%d)", sigLen)
		}
		sig := payload[4 : 4+sigLen]
		cipher := payload[4+sigLen:]
		chunk, err := session.Unwrap(cipher, sig)
		if err != nil {
			return nil, err
		}
		plainOut.Write(chunk)
	}
	return plainOut.Bytes(), nil
}

func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func xmlEscapeText(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func buildWSManEnumerateEnvelope(endpoint, resourceURI, wql string, maxElements int) []byte {
	msgID := "uuid:" + newUUIDv4()
	if maxElements <= 0 {
		maxElements = 100
	}
	s := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Header>
    <wsa:To s:mustUnderstand="true">%s</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">%s</wsman:ResourceURI>
    <wsa:ReplyTo><wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">%s</wsa:Action>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsman:OperationTimeout>PT10S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <wsen:Enumerate>
      <wsman:OptimizeEnumeration/>
      <wsman:MaxElements>%d</wsman:MaxElements>
      <wsman:Filter Dialect="http://schemas.microsoft.com/wbem/wsman/1/WQL">%s</wsman:Filter>
    </wsen:Enumerate>
  </s:Body>
</s:Envelope>`,
		xmlEscapeText(endpoint),
		xmlEscapeText(resourceURI),
		winrmEnumerateAction,
		msgID,
		maxElements,
		xmlEscapeText(wql),
	)
	return []byte(s)
}

func buildWSManPullEnvelope(endpoint, resourceURI, enumContext string, maxElements int) []byte {
	msgID := "uuid:" + newUUIDv4()
	if maxElements <= 0 {
		maxElements = 100
	}
	s := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Header>
    <wsa:To s:mustUnderstand="true">%s</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">%s</wsman:ResourceURI>
    <wsa:ReplyTo><wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">%s</wsa:Action>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsman:OperationTimeout>PT10S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <wsen:Pull>
      <wsen:EnumerationContext>%s</wsen:EnumerationContext>
      <wsen:MaxElements>%d</wsen:MaxElements>
    </wsen:Pull>
  </s:Body>
</s:Envelope>`,
		xmlEscapeText(endpoint),
		xmlEscapeText(resourceURI),
		winrmPullAction,
		msgID,
		xmlEscapeText(enumContext),
		maxElements,
	)
	return []byte(s)
}

type wsmanParsedResponse struct {
	rows          []map[string]string
	enumContext   string
	endOfSequence bool
	fault         string
	faultCode     string
}

func parseWSManResponse(raw []byte) (wsmanParsedResponse, error) {
	var out wsmanParsedResponse
	dec := xml.NewDecoder(bytes.NewReader(raw))

	var (
		stack       []string
		inItems     bool
		itemsDepth  int
		curRow      map[string]string
		inRow       bool
		rowDepth    int
		curPropName string
		propBuf     strings.Builder

		inFault    bool
		faultDepth int
		inReason   bool
		faultParts []string
		enumBuf    strings.Builder
		captureCtx bool
	)

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("réponse SOAP WinRM invalide : %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			local := t.Name.Local
			stack = append(stack, local)
			depth := len(stack)

			if local == "Fault" && !inFault {
				inFault = true
				faultDepth = depth
			} else if inFault {
				if local == "Reason" {
					inReason = true
				}
				if local == "WSManFault" {
					for _, attr := range t.Attr {
						if strings.EqualFold(attr.Name.Local, "Code") {
							out.faultCode = attr.Value
						}
					}
				}
			}

			if local == "EnumerationContext" {
				enumBuf.Reset()
				captureCtx = true
			}
			if local == "EndOfSequence" {
				out.endOfSequence = true
			}

			if local == "Items" && !inItems {
				inItems = true
				itemsDepth = depth
			} else if inItems && !inRow && depth == itemsDepth+1 {
				inRow = true
				rowDepth = depth
				curRow = make(map[string]string)
			} else if inRow && depth == rowDepth+1 {
				curPropName = strings.ToLower(local)
				propBuf.Reset()
			}

		case xml.CharData:
			text := string(t)
			if curPropName != "" && len(stack) == rowDepth+1 {
				propBuf.WriteString(text)
			}
			if captureCtx {
				enumBuf.WriteString(text)
			}
			if inFault && len(stack) > 0 {
				top := strings.ToLower(stack[len(stack)-1])
				if (inReason && top == "text") || top == "message" || top == "value" || top == "faultstring" {
					if trimmed := strings.TrimSpace(text); trimmed != "" {
						faultParts = append(faultParts, trimmed)
					}
				}
			}

		case xml.EndElement:
			local := t.Name.Local
			depth := len(stack)

			if captureCtx && local == "EnumerationContext" {
				out.enumContext = strings.TrimSpace(enumBuf.String())
				captureCtx = false
			}
			if inRow && depth == rowDepth+1 && curPropName != "" {
				curRow[curPropName] = strings.TrimSpace(propBuf.String())
				curPropName = ""
			} else if inRow && depth == rowDepth {
				out.rows = append(out.rows, curRow)
				curRow = nil
				inRow = false
			} else if inItems && depth == itemsDepth {
				inItems = false
			}

			if inFault && local == "Reason" {
				inReason = false
			}
			if inFault && depth == faultDepth {
				inFault = false
			}

			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}

	if len(faultParts) > 0 {
		out.fault = strings.Join(faultParts, " — ")
	} else if out.faultCode != "" {
		out.fault = "code " + out.faultCode
	}
	return out, nil
}

func isInvalidNamespaceFault(faultMsg, faultCode, namespace string) bool {
	low := strings.ToLower(faultMsg + " " + faultCode)
	return strings.Contains(low, "invalidnamespace") ||
		strings.Contains(low, "invalid namespace") ||
		strings.Contains(low, "espace de noms") ||
		strings.Contains(low, "0x8004100e") ||
		strings.Contains(low, "8004100e") ||
		strings.Contains(low, "2147749902") ||
		strings.Contains(low, "2150858770") ||
		(namespace != "" && strings.Contains(low, strings.ToLower(namespace)) && strings.Contains(low, "namespace"))
}
