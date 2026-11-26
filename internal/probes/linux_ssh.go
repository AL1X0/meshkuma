package probes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"meshwatch/internal/config"
)

const (
	maxSSHStdoutBytes = 1 << 20
	maxSSHStderrBytes = 64 << 10
)

// LinuxSSHProbe monitors any Linux host agentlessly over SSH (port 22 by default)
// without requiring node_exporter or any preinstalled monitoring daemon.
type LinuxSSHProbe struct {
	id             string
	host           string
	port           int
	user           string
	password       string
	sshKey         string
	maxCPUPercent  float64
	maxRAMPercent  float64
	maxDiskPercent float64
	disks          []string
	services       []string

	// runFn may be injected in unit tests to bypass live SSH dial/auth.
	runFn func(ctx context.Context, cmd string) (string, error)
}

// NewLinuxSSHProbe creates a LinuxSSHProbe from configuration.
func NewLinuxSSHProbe(cfg config.ProbeConfig) *LinuxSSHProbe {
	port := cfg.Port
	if port <= 0 {
		port = config.DefaultSSHPort
	}
	return &LinuxSSHProbe{
		id:             cfg.ID,
		host:           strings.TrimSpace(cfg.Host),
		port:           port,
		user:           strings.TrimSpace(cfg.User),
		password:       cfg.Password,
		sshKey:         cfg.SSHKey,
		maxCPUPercent:  cfg.MaxCPUPercent,
		maxRAMPercent:  cfg.MaxRAMPercent,
		maxDiskPercent: cfg.MaxDiskPercent,
		disks:          append([]string(nil), cfg.Disks...),
		services:       append([]string(nil), cfg.Services...),
	}
}

func (p *LinuxSSHProbe) ID() string   { return p.id }
func (p *LinuxSSHProbe) Kind() string { return "linux_ssh" }

func (p *LinuxSSHProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	cmd := buildLinuxProbeCommand(p.services)

	var (
		output string
		err    error
	)
	if p.runFn != nil {
		output, err = p.runFn(ctx, cmd)
	} else {
		output, err = p.runSSHCommand(ctx, cmd)
	}
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: humanizeSSHError(err, p.host, p.port),
			Latency: time.Since(start).Milliseconds(),
		}
	}

	ok, summary, metrics := evaluateLinuxSSHOutputDetailed(
		output,
		p.maxCPUPercent,
		p.maxRAMPercent,
		p.maxDiskPercent,
		p.disks,
		p.services,
		p.host,
	)
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      ok,
		Summary: summary,
		Latency: time.Since(start).Milliseconds(),
		Metrics: metrics,
	}
}

func (p *LinuxSSHProbe) runSSHCommand(ctx context.Context, cmd string) (string, error) {
	var authMethods []ssh.AuthMethod
	if keyPEM := strings.TrimSpace(p.sshKey); keyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
		if err != nil && p.password != "" {
			if passphraseErr := (*ssh.PassphraseMissingError)(nil); errors.As(err, &passphraseErr) {
				signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(keyPEM), []byte(p.password))
			}
		}
		if err != nil {
			return "", fmt.Errorf("SSH : clé privée PEM invalide (%w)", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if p.password != "" {
		pass := p.password
		authMethods = append(authMethods,
			ssh.Password(pass),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pass
				}
				return answers, nil
			}),
		)
	}
	if len(authMethods) == 0 {
		return "", errors.New("SSH : mot de passe ou clé privée requis")
	}

	timeout := 10 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 {
			timeout = rem
		}
	}

	addr := net.JoinHostPort(p.host, strconv.Itoa(p.port))
	var d net.Dialer
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = netConn.SetDeadline(dl)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = netConn.Close()
		case <-done:
		}
	}()

	sshCfg := &ssh.ClientConfig{
		User:            p.user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // local homelab agentless SSH probe
		Timeout:         timeout,
	}

	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, sshCfg)
	if err != nil {
		_ = netConn.Close()
		return "", err
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr cappedBuffer
	stdout.max = maxSSHStdoutBytes
	stderr.max = maxSSHStderrBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(cmd); err != nil {
		if outStr := strings.TrimSpace(stdout.String()); outStr != "" && strings.Contains(outStr, "HOST=") {
			return outStr, nil
		}
		errDetail := strings.TrimSpace(stderr.String())
		if errDetail != "" {
			return "", fmt.Errorf("%w (%s)", err, errDetail)
		}
		return "", err
	}
	return stdout.String(), nil
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	if c.max > 0 {
		rem := c.max - c.buf.Len()
		if rem <= 0 {
			return origLen, nil
		}
		if len(p) > rem {
			p = p[:rem]
		}
	}
	_, err := c.buf.Write(p)
	if err != nil {
		return 0, err
	}
	return origLen, nil
}

func (c *cappedBuffer) String() string {
	return c.buf.String()
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func buildLinuxProbeCommand(services []string) string {
	var b strings.Builder
	b.WriteString(`printf 'HOST=%s\n' "$(hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null)"; `)
	b.WriteString(`printf 'LOAD=%s\n' "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"; `)
	b.WriteString(`printf 'UPTIME=%s\n' "$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"; `)
	b.WriteString(`head -n 1 /proc/stat 2>/dev/null | sed 's/^/STAT1=/'; `)
	b.WriteString(`sleep 0.25 2>/dev/null || sleep 1; `)
	b.WriteString(`head -n 1 /proc/stat 2>/dev/null | sed 's/^/STAT2=/'; `)
	b.WriteString(`sed -n 's/^\(MemTotal\|MemAvailable\|MemFree\|Buffers\|Cached\|SReclaimable\):[[:space:]]*\([0-9]*\).*/MEM_\1=\2/p' /proc/meminfo 2>/dev/null; `)
	b.WriteString(`if df -P -T -k >/dev/null 2>&1; then df -P -T -k | awk 'NR>1 {print "DISK=" $0}'; else df -P -k | awk 'NR>1 {print "DISK=" $0}'; fi`)

	for _, rawSvc := range services {
		svc := strings.TrimSpace(rawSvc)
		if svc == "" {
			continue
		}
		q := shellSingleQuote(svc)
		fmt.Fprintf(&b, `; if command -v systemctl >/dev/null 2>&1 && { s=$(systemctl is-active %s 2>/dev/null | head -n 1) || [ -n "$s" ]; }; then :; elif command -v rc-service >/dev/null 2>&1; then if rc-service %s status >/dev/null 2>&1; then s=active; else s=inactive; fi; elif command -v service >/dev/null 2>&1; then if service %s status >/dev/null 2>&1; then s=active; else s=inactive; fi; else s=unknown; fi; [ -n "$s" ] || s=inactive; printf 'SVC=%%s\t%%s\n' %s "$s"`, q, q, q, q)
	}
	return b.String()
}

type linuxDiskEntry struct {
	device  string
	fsType  string
	blocks  float64
	usedKB  float64
	usedPct float64
	mount   string
}

var ignoredLinuxSSHExtraFSTypes = map[string]struct{}{
	"devpts": {}, "iso9660": {}, "efivarfs": {}, "bpf": {}, "configfs": {}, "binfmt_misc": {},
}

func evaluateLinuxSSHOutput(
	rawOutput string,
	maxCPUPct, maxRAMPct, maxDiskPct float64,
	diskFilter, requiredServices []string,
	fallbackHost string,
) (bool, string) {
	ok, summary, _ := evaluateLinuxSSHOutputDetailed(
		rawOutput, maxCPUPct, maxRAMPct, maxDiskPct, diskFilter, requiredServices, fallbackHost,
	)
	return ok, summary
}

func evaluateLinuxSSHOutputDetailed(
	rawOutput string,
	maxCPUPct, maxRAMPct, maxDiskPct float64,
	diskFilter, requiredServices []string,
	fallbackHost string,
) (bool, string, *ProbeMetrics) {
	var (
		hostName  = strings.TrimSpace(fallbackHost)
		loadAvg   string
		uptimeSec int64
		stat1     string
		stat2     string
		memKB     = make(map[string]float64)
		disks     []linuxDiskEntry
		svcState  = make(map[string]string)
	)

	for _, line := range strings.Split(strings.ReplaceAll(rawOutput, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, " \t")
		switch {
		case strings.HasPrefix(line, "HOST="):
			if v := strings.TrimSpace(strings.TrimPrefix(line, "HOST=")); v != "" {
				hostName = v
			}
		case strings.HasPrefix(line, "LOAD="):
			loadAvg = strings.TrimSpace(strings.TrimPrefix(line, "LOAD="))
		case strings.HasPrefix(line, "UPTIME="):
			if v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "UPTIME=")), 64); err == nil && v >= 0 {
				uptimeSec = int64(math.Round(v))
			}
		case strings.HasPrefix(line, "STAT1="):
			stat1 = strings.TrimSpace(strings.TrimPrefix(line, "STAT1="))
		case strings.HasPrefix(line, "STAT2="):
			stat2 = strings.TrimSpace(strings.TrimPrefix(line, "STAT2="))
		case strings.HasPrefix(line, "MEM_"):
			rest := strings.TrimPrefix(line, "MEM_")
			if eq := strings.IndexByte(rest, '='); eq > 0 {
				if val, err := strconv.ParseFloat(strings.TrimSpace(rest[eq+1:]), 64); err == nil {
					memKB[rest[:eq]] = val
				}
			}
		case strings.HasPrefix(line, "DISK="):
			if entry, ok := parseLinuxDFLine(strings.TrimPrefix(line, "DISK=")); ok {
				disks = append(disks, entry)
			}
		case strings.HasPrefix(line, "SVC="):
			rest := strings.TrimPrefix(line, "SVC=")
			parts := strings.SplitN(rest, "\t", 2)
			if len(parts) == 2 {
				svcState[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
			}
		}
	}

	if hostName == "" {
		hostName = "Linux"
	}

	m := &ProbeMetrics{
		Hostname:  hostName,
		LoadAvg:   loadAvg,
		UptimeSec: uptimeSec,
	}
	var issues []string

	cpuPct, cpuOK := computeProcStatCPU(stat1, stat2)
	if cpuOK {
		m.CPUPercent = floatPtr(cpuPct)
	}
	if maxCPUPct > 0 && cpuOK && cpuPct > maxCPUPct {
		issues = append(issues, fmt.Sprintf("CPU %.1f%% > %.0f%%", cpuPct, maxCPUPct))
	}

	ramPct, ramOK := computeMeminfoRAM(memKB)
	if ramOK {
		total := memKB["MemTotal"]
		avail, hasAvail := memKB["MemAvailable"]
		if !hasAvail {
			avail = memKB["MemFree"] + memKB["Buffers"] + memKB["Cached"] + memKB["SReclaimable"]
		}
		used := total - avail
		if used < 0 {
			used = 0
		}
		m.RAMPercent = floatPtr(ramPct)
		m.RAMTotalMB = total / 1024.0
		m.RAMUsedMB = used / 1024.0
	}
	if maxRAMPct > 0 && ramOK && ramPct > maxRAMPct {
		issues = append(issues, fmt.Sprintf("RAM %.1f%% > %.0f%%", ramPct, maxRAMPct))
	}

	// Filter & deduplicate physical/real filesystems by mount point.
	dedupByMount := make(map[string]linuxDiskEntry)
	for _, d := range disks {
		if !isRealLinuxDisk(d) {
			continue
		}
		if prev, exists := dedupByMount[d.mount]; !exists || prev.device == "rootfs" {
			dedupByMount[d.mount] = d
		}
	}

	wantedDisks := make(map[string]struct{}, len(diskFilter))
	for _, rawD := range diskFilter {
		if mnt := strings.TrimSpace(rawD); mnt != "" {
			wantedDisks[mnt] = struct{}{}
		}
	}
	seenDisks := make(map[string]bool)
	maxDisk := -1.0
	maxDiskMount := ""

	var filteredDisks []linuxDiskEntry
	for _, d := range dedupByMount {
		if len(wantedDisks) > 0 {
			if _, ok := wantedDisks[d.mount]; !ok {
				continue
			}
		}
		filteredDisks = append(filteredDisks, d)
	}
	if len(filteredDisks) == 0 && len(wantedDisks) == 0 && len(disks) > 0 {
		// Last-resort fallback: inspect raw non-zero root mount if all were filtered unexpectedly.
		for _, d := range disks {
			if d.mount == "/" && d.blocks > 0 {
				filteredDisks = append(filteredDisks, d)
				break
			}
		}
	}
	sort.Slice(filteredDisks, func(i, j int) bool {
		return filteredDisks[i].mount < filteredDisks[j].mount
	})

	for _, d := range filteredDisks {
		seenDisks[d.mount] = true
		diskStatus := "OK"
		if maxDiskPct > 0 && d.usedPct > maxDiskPct {
			diskStatus = "Saturé"
			issues = append(issues, fmt.Sprintf("Disque %s %.1f%% > %.0f%%", d.mount, d.usedPct, maxDiskPct))
		}
		m.Disks = append(m.Disks, DiskMetric{
			Name:        d.mount,
			Mount:       d.mount,
			FSType:      d.fsType,
			UsedPercent: d.usedPct,
			UsedGB:      d.usedKB / (1024 * 1024),
			TotalGB:     d.blocks / (1024 * 1024),
			Status:      diskStatus,
		})
		if d.usedPct > maxDisk {
			maxDisk = d.usedPct
			maxDiskMount = d.mount
		}
	}
	if maxDisk >= 0 {
		m.DiskMaxPct = floatPtr(maxDisk)
	}
	for _, rawWant := range diskFilter {
		want := strings.TrimSpace(rawWant)
		if want != "" && !seenDisks[want] {
			issues = append(issues, fmt.Sprintf("Disque %s introuvable", want))
		}
	}

	okSvc := 0
	for _, rawSvc := range requiredServices {
		want := strings.TrimSpace(rawSvc)
		if want == "" {
			continue
		}
		st, ok := svcState[strings.ToLower(want)]
		if !ok {
			issues = append(issues, fmt.Sprintf("Service %s introuvable", want))
			m.Services = append(m.Services, ServiceMetric{Name: want, State: "introuvable", OK: false})
			continue
		}
		if !strings.EqualFold(st, "active") {
			issues = append(issues, fmt.Sprintf("Service %s (%s)", want, fallbackStr(st, "inactive")))
			m.Services = append(m.Services, ServiceMetric{Name: want, State: fallbackStr(st, "inactive"), OK: false})
			continue
		}
		okSvc++
		m.Services = append(m.Services, ServiceMetric{Name: want, State: st, OK: true})
	}

	if len(issues) > 0 {
		return false, strings.Join(issues, "; "), m
	}

	parts := []string{hostName}
	if cpuOK {
		parts = append(parts, fmt.Sprintf("CPU %.0f%%", cpuPct))
	}
	if ramOK {
		parts = append(parts, fmt.Sprintf("RAM %.0f%%", ramPct))
	}
	if maxDisk >= 0 {
		parts = append(parts, fmt.Sprintf("Disque %s %.0f%%", maxDiskMount, maxDisk))
	}
	if len(requiredServices) > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d services OK", okSvc, countNonEmpty(requiredServices)))
	}
	if len(parts) == 1 && !cpuOK && !ramOK && maxDisk < 0 {
		return false, "SSH connecté mais impossible de lire /proc ou df", m
	}
	return true, strings.Join(parts, ", "), m
}

func computeProcStatCPU(stat1, stat2 string) (float64, bool) {
	t1, i1, ok1 := parseProcStatLine(stat1)
	t2, i2, ok2 := parseProcStatLine(stat2)
	if !ok1 || !ok2 {
		return 0, false
	}
	dTotal := t2 - t1
	dIdle := i2 - i1
	if dTotal <= 0 {
		return 0, false
	}
	pct := (1.0 - (float64(dIdle) / float64(dTotal))) * 100.0
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, true
}

func parseProcStatLine(line string) (total, idle uint64, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	// Columns 1..8 = user, nice, system, idle, iowait, irq, softirq, steal
	// (guest columns 9..10 are already accounted inside user/nice).
	limit := len(fields)
	if limit > 9 {
		limit = 9
	}
	var vals [8]uint64
	for i := 1; i < limit; i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		vals[i-1] = v
		total += v
	}
	idle = vals[3] + vals[4] // idle + iowait
	return total, idle, true
}

func computeMeminfoRAM(memKB map[string]float64) (float64, bool) {
	total, ok := memKB["MemTotal"]
	if !ok || total <= 0 {
		return 0, false
	}
	avail, hasAvail := memKB["MemAvailable"]
	if !hasAvail {
		avail = memKB["MemFree"] + memKB["Buffers"] + memKB["Cached"] + memKB["SReclaimable"]
	}
	used := total - avail
	if used < 0 {
		used = 0
	}
	if used > total {
		used = total
	}
	return (used / total) * 100.0, true
}

func parseLinuxDFLine(line string) (linuxDiskEntry, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 6 {
		return linuxDiskEntry{}, false
	}
	// Find capacity% column (supports both `df -P -T -k` with fstype and `df -P -k` without fstype).
	capIdx := -1
	for i := 3; i < len(fields)-1; i++ {
		if strings.HasSuffix(fields[i], "%") {
			capIdx = i
			break
		}
	}
	if capIdx < 4 {
		return linuxDiskEntry{}, false
	}
	blocks, bErr := strconv.ParseFloat(fields[capIdx-3], 64)
	used, uErr := strconv.ParseFloat(fields[capIdx-2], 64)
	avail, aErr := strconv.ParseFloat(fields[capIdx-1], 64)
	if bErr != nil || uErr != nil || aErr != nil {
		return linuxDiskEntry{}, false
	}
	fsType := ""
	if capIdx >= 5 {
		fsType = strings.ToLower(strings.TrimSpace(fields[1]))
	}
	usedPct := 0.0
	if used+avail > 0 {
		usedPct = (used / (used + avail)) * 100.0
	} else if capStr := strings.TrimSuffix(fields[capIdx], "%"); capStr != "" {
		if v, err := strconv.ParseFloat(capStr, 64); err == nil {
			usedPct = v
		}
	}

	// Preserve mount points even if they contain spaces by slicing past the cap% token.
	mount := fields[capIdx+1]
	if pctPos := strings.Index(line, fields[capIdx]); pctPos >= 0 {
		rest := strings.TrimSpace(line[pctPos+len(fields[capIdx]):])
		if rest != "" {
			mount = rest
		}
	}

	return linuxDiskEntry{
		device:  strings.TrimSpace(fields[0]),
		fsType:  fsType,
		blocks:  blocks,
		usedKB:  used,
		usedPct: usedPct,
		mount:   mount,
	}, true
}

func isRealLinuxDisk(d linuxDiskEntry) bool {
	if d.blocks <= 0 || d.mount == "" {
		return false
	}
	if d.fsType != "" {
		if _, ignored := ignoredLinuxFSTypes[d.fsType]; ignored {
			return false
		}
		if _, ignored := ignoredLinuxSSHExtraFSTypes[d.fsType]; ignored {
			return false
		}
	}
	devLow := strings.ToLower(d.device)
	if devLow == "tmpfs" || devLow == "devtmpfs" || devLow == "udev" || devLow == "overlay" || devLow == "shm" || devLow == "none" {
		return false
	}
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/run", "/snap/", "/var/lib/docker/", "/var/lib/containerd/"} {
		if d.mount == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(d.mount, prefix) {
			return false
		}
	}
	return true
}

func humanizeSSHError(err error, host string, port int) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	if strings.HasPrefix(msg, "SSH") {
		return msg
	}
	if strings.Contains(low, "unable to authenticate") || strings.Contains(low, "no supported methods remain") {
		return "SSH : authentification refusée — vérifiez l'utilisateur, le mot de passe ou la clé SSH"
	}
	if strings.Contains(low, "connection refused") {
		return fmt.Sprintf("SSH inaccessible sur %s:%d (connexion refusée) — vérifiez que le serveur OpenSSH est démarré", host, port)
	}
	if strings.Contains(low, "timeout") || strings.Contains(low, "deadline exceeded") {
		return fmt.Sprintf("SSH ne répond pas sur %s:%d (délai dépassé) — vérifiez l'adresse IP et le pare-feu", host, port)
	}
	if strings.Contains(low, "no such host") {
		return fmt.Sprintf("SSH : hôte %q introuvable", host)
	}
	return "SSH : " + msg
}
