package probes

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"meshwatch/internal/config"
)

const maxExporterBodyBytes = 16 << 20 // 16 MiB cap for /metrics scraping

// promSample is one parsed Prometheus text exposition metric line.
type promSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// parsePromMetrics parses Prometheus text exposition format with zero external dependencies.
func parsePromMetrics(r io.Reader) ([]promSample, error) {
	scanner := bufio.NewScanner(r)
	// Allow long metric lines (up to 1 MiB) while keeping baseline memory small.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var samples []promSample
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sample, ok := parsePromLine(line)
		if ok {
			samples = append(samples, sample)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return samples, nil
}

func parsePromLine(line string) (promSample, bool) {
	var (
		name   string
		labels map[string]string
		rest   string
	)

	if idx := strings.IndexByte(line, '{'); idx != -1 {
		name = strings.TrimSpace(line[:idx])
		end := findClosingBrace(line, idx+1)
		if end == -1 {
			return promSample{}, false
		}
		labels = parsePromLabels(line[idx+1 : end])
		rest = strings.TrimSpace(line[end+1:])
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return promSample{}, false
		}
		name = fields[0]
		rest = fields[1]
	}

	if name == "" || rest == "" {
		return promSample{}, false
	}

	// Value is the first token of rest (optional timestamp follows).
	valStr := rest
	if sp := strings.IndexAny(rest, " \t"); sp != -1 {
		valStr = rest[:sp]
	}
	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil || math.IsNaN(val) {
		return promSample{}, false
	}

	return promSample{
		Name:   name,
		Labels: labels,
		Value:  val,
	}, true
}

func findClosingBrace(s string, start int) int {
	inQuote := false
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote {
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inQuote = false
			}
			continue
		}
		if ch == '"' {
			inQuote = true
		} else if ch == '}' {
			return i
		}
	}
	return -1
}

func parsePromLabels(raw string) map[string]string {
	labels := make(map[string]string)
	i := 0
	n := len(raw)
	for i < n {
		for i < n && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		eq := strings.IndexByte(raw[i:], '=')
		if eq == -1 {
			break
		}
		key := strings.TrimSpace(raw[i : i+eq])
		i += eq + 1
		for i < n && (raw[i] == ' ' || raw[i] == '\t') {
			i++
		}
		if i >= n || raw[i] != '"' {
			break
		}
		i++ // skip opening quote
		var sb strings.Builder
		for i < n {
			ch := raw[i]
			i++
			if ch == '\\' && i < n {
				next := raw[i]
				i++
				switch next {
				case 'n':
					sb.WriteByte('\n')
				case '"':
					sb.WriteByte('"')
				case '\\':
					sb.WriteByte('\\')
				default:
					sb.WriteByte(next)
				}
				continue
			}
			if ch == '"' {
				break
			}
			sb.WriteByte(ch)
		}
		if key != "" {
			labels[key] = sb.String()
		}
	}
	return labels
}

func scrapePromEndpoint(ctx context.Context, client *http.Client, endpoint string) ([]promSample, int64, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "MeshWatch/1.0")

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return nil, latency, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, latency, fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
	}
	samples, err := parsePromMetrics(io.LimitReader(resp.Body, maxExporterBodyBytes))
	return samples, time.Since(start).Milliseconds(), err
}

// NodeExporterProbe scrapes a Linux Prometheus node_exporter endpoint (/metrics).
type NodeExporterProbe struct {
	id             string
	url            string
	maxRAMPercent  float64
	maxDiskPercent float64
	disks          []string
	client         *http.Client
}

// NewNodeExporterProbe creates a NodeExporterProbe from config.
func NewNodeExporterProbe(cfg config.ProbeConfig) *NodeExporterProbe {
	return &NodeExporterProbe{
		id:             cfg.ID,
		url:            cfg.URL,
		maxRAMPercent:  cfg.MaxRAMPercent,
		maxDiskPercent: cfg.MaxDiskPercent,
		disks:          append([]string(nil), cfg.Disks...),
		client:         &http.Client{Transport: &http.Transport{DisableKeepAlives: true}},
	}
}

func (p *NodeExporterProbe) ID() string   { return p.id }
func (p *NodeExporterProbe) Kind() string { return "node_exporter" }

var ignoredLinuxFSTypes = map[string]struct{}{
	"tmpfs":       {},
	"devtmpfs":    {},
	"overlay":     {},
	"squashfs":    {},
	"proc":        {},
	"sysfs":       {},
	"cgroup":      {},
	"cgroup2":     {},
	"nsfs":        {},
	"ramfs":       {},
	"autofs":      {},
	"tracefs":     {},
	"debugfs":     {},
	"securityfs":  {},
	"pstore":      {},
	"fuse.lxcfs":  {},
	"fuse.portal": {},
	"mqueue":      {},
	"hugetlbfs":   {},
	"rpc_pipefs":  {},
}

func (p *NodeExporterProbe) Check(ctx context.Context) ProbeResult {
	samples, latency, err := scrapePromEndpoint(ctx, p.client, p.url)
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("scrape node_exporter failed: %v", err),
			Latency: latency,
		}
	}

	var (
		memTotal, memAvail, memFree, memBuffers, memCached float64
		hasMemTotal, hasMemAvail                           bool
	)

	type fsStat struct {
		size  float64
		avail float64
		hasSz bool
		hasAv bool
	}
	filesystems := make(map[string]*fsStat)

	diskFilter := make(map[string]struct{}, len(p.disks))
	for _, d := range p.disks {
		diskFilter[d] = struct{}{}
	}

	for _, s := range samples {
		switch s.Name {
		case "node_memory_MemTotal_bytes":
			memTotal = s.Value
			hasMemTotal = true
		case "node_memory_MemAvailable_bytes":
			memAvail = s.Value
			hasMemAvail = true
		case "node_memory_MemFree_bytes":
			memFree = s.Value
		case "node_memory_Buffers_bytes":
			memBuffers = s.Value
		case "node_memory_Cached_bytes":
			memCached = s.Value
		case "node_filesystem_size_bytes", "node_filesystem_avail_bytes":
			mp := s.Labels["mountpoint"]
			if mp == "" {
				continue
			}
			if len(diskFilter) > 0 {
				if _, want := diskFilter[mp]; !want {
					continue
				}
			} else {
				if _, skip := ignoredLinuxFSTypes[s.Labels["fstype"]]; skip {
					continue
				}
			}
			st := filesystems[mp]
			if st == nil {
				st = &fsStat{}
				filesystems[mp] = st
			}
			if s.Name == "node_filesystem_size_bytes" {
				st.size = s.Value
				st.hasSz = true
			} else {
				st.avail = s.Value
				st.hasAv = true
			}
		}
	}

	var issues []string
	var okNotes []string
	m := &ProbeMetrics{}

	// Evaluate RAM
	if hasMemTotal && memTotal > 0 {
		avail := memAvail
		if !hasMemAvail {
			avail = memFree + memBuffers + memCached
		}
		ramPct := (1.0 - avail/memTotal) * 100.0
		if ramPct < 0 {
			ramPct = 0
		}
		m.RAMPercent = floatPtr(ramPct)
		m.RAMTotalMB = memTotal / (1024 * 1024)
		m.RAMUsedMB = (memTotal - avail) / (1024 * 1024)
		if m.RAMUsedMB < 0 {
			m.RAMUsedMB = 0
		}
		if p.maxRAMPercent > 0 && ramPct > p.maxRAMPercent {
			issues = append(issues, fmt.Sprintf("RAM %.1f%% > %.0f%%", ramPct, p.maxRAMPercent))
		} else {
			okNotes = append(okNotes, fmt.Sprintf("RAM %.0f%%", ramPct))
		}
	} else if p.maxRAMPercent > 0 {
		issues = append(issues, "missing node_memory_MemTotal_bytes")
	}

	// Evaluate Disks
	mounts := make([]string, 0, len(filesystems))
	for mp := range filesystems {
		mounts = append(mounts, mp)
	}
	sort.Strings(mounts)

	for _, want := range p.disks {
		if _, found := filesystems[want]; !found {
			issues = append(issues, fmt.Sprintf("disk %s missing", want))
		}
	}

	maxDiskUsed := -1.0
	maxDiskMount := ""
	for _, mp := range mounts {
		st := filesystems[mp]
		if !st.hasSz || !st.hasAv || st.size <= 0 {
			continue
		}
		usedPct := (1.0 - st.avail/st.size) * 100.0
		if usedPct < 0 {
			usedPct = 0
		}
		m.Disks = append(m.Disks, DiskMetric{
			Name:        mp,
			Mount:       mp,
			UsedPercent: usedPct,
			UsedGB:      (st.size - st.avail) / (1024 * 1024 * 1024),
			TotalGB:     st.size / (1024 * 1024 * 1024),
		})
		if usedPct > maxDiskUsed {
			maxDiskUsed = usedPct
			maxDiskMount = mp
		}
		if p.maxDiskPercent > 0 && usedPct > p.maxDiskPercent {
			issues = append(issues, fmt.Sprintf("Disk %s %.1f%% > %.0f%%", mp, usedPct, p.maxDiskPercent))
		}
	}
	if maxDiskUsed >= 0 {
		m.DiskMaxPct = floatPtr(maxDiskUsed)
		okNotes = append(okNotes, fmt.Sprintf("Disk %s %.0f%%", maxDiskMount, maxDiskUsed))
	}

	if len(issues) > 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: strings.Join(issues, "; "),
			Latency: latency,
			Metrics: m,
		}
	}
	if len(okNotes) == 0 {
		okNotes = append(okNotes, "metrics OK")
	}
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      true,
		Summary: strings.Join(okNotes, ", "),
		Latency: latency,
		Metrics: m,
	}
}

// WindowsExporterProbe scrapes a Windows Prometheus windows_exporter endpoint (/metrics).
type WindowsExporterProbe struct {
	id             string
	url            string
	maxRAMPercent  float64
	maxDiskPercent float64
	disks          []string
	services       []string
	client         *http.Client
}

// NewWindowsExporterProbe creates a WindowsExporterProbe from config.
func NewWindowsExporterProbe(cfg config.ProbeConfig) *WindowsExporterProbe {
	return &WindowsExporterProbe{
		id:             cfg.ID,
		url:            cfg.URL,
		maxRAMPercent:  cfg.MaxRAMPercent,
		maxDiskPercent: cfg.MaxDiskPercent,
		disks:          append([]string(nil), cfg.Disks...),
		services:       append([]string(nil), cfg.Services...),
		client:         &http.Client{Transport: &http.Transport{DisableKeepAlives: true}},
	}
}

func (p *WindowsExporterProbe) ID() string   { return p.id }
func (p *WindowsExporterProbe) Kind() string { return "windows_exporter" }

func (p *WindowsExporterProbe) Check(ctx context.Context) ProbeResult {
	samples, latency, err := scrapePromEndpoint(ctx, p.client, p.url)
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("scrape windows_exporter failed: %v", err),
			Latency: latency,
		}
	}

	var (
		memTotal, memFree float64
		hasTotal, hasFree bool
	)

	type volStat struct {
		name  string
		size  float64
		free  float64
		hasSz bool
		hasFr bool
	}
	volumes := make(map[string]*volStat)

	diskFilter := make(map[string]struct{}, len(p.disks))
	for _, d := range p.disks {
		diskFilter[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}

	// serviceRunning tracks lower(service_name) -> running (value == 1).
	serviceRunning := make(map[string]bool)
	serviceSeen := make(map[string]bool)

	for _, s := range samples {
		switch s.Name {
		case "windows_memory_physical_total_bytes", "windows_cs_physical_memory_bytes":
			memTotal = s.Value
			hasTotal = true
		case "windows_memory_physical_free_bytes", "windows_os_physical_memory_free_bytes":
			memFree = s.Value
			hasFree = true
		case "windows_logical_disk_size_bytes", "windows_logical_disk_free_bytes":
			vol := s.Labels["volume"]
			if vol == "" {
				continue
			}
			volKey := strings.ToLower(vol)
			if len(diskFilter) > 0 {
				if _, want := diskFilter[volKey]; !want {
					continue
				}
			} else if strings.HasPrefix(volKey, "harddiskvolume") {
				continue
			}
			st := volumes[volKey]
			if st == nil {
				st = &volStat{name: vol}
				volumes[volKey] = st
			}
			if s.Name == "windows_logical_disk_size_bytes" {
				st.size = s.Value
				st.hasSz = true
			} else {
				st.free = s.Value
				st.hasFr = true
			}
		case "windows_service_state":
			svc := strings.ToLower(strings.TrimSpace(s.Labels["name"]))
			if svc == "" {
				continue
			}
			serviceSeen[svc] = true
			if strings.EqualFold(s.Labels["state"], "running") && s.Value == 1 {
				serviceRunning[svc] = true
			}
		}
	}

	var issues []string
	var okNotes []string
	m := &ProbeMetrics{}

	// Evaluate RAM
	if hasTotal && hasFree && memTotal > 0 {
		ramPct := (1.0 - memFree/memTotal) * 100.0
		if ramPct < 0 {
			ramPct = 0
		}
		m.RAMPercent = floatPtr(ramPct)
		m.RAMTotalMB = memTotal / (1024 * 1024)
		m.RAMUsedMB = (memTotal - memFree) / (1024 * 1024)
		if m.RAMUsedMB < 0 {
			m.RAMUsedMB = 0
		}
		if p.maxRAMPercent > 0 && ramPct > p.maxRAMPercent {
			issues = append(issues, fmt.Sprintf("RAM %.1f%% > %.0f%%", ramPct, p.maxRAMPercent))
		} else {
			okNotes = append(okNotes, fmt.Sprintf("RAM %.0f%%", ramPct))
		}
	} else if p.maxRAMPercent > 0 {
		issues = append(issues, "missing Windows physical memory metrics")
	}

	// Evaluate Disks
	volKeys := make([]string, 0, len(volumes))
	for k := range volumes {
		volKeys = append(volKeys, k)
	}
	sort.Strings(volKeys)

	for _, want := range p.disks {
		if _, found := volumes[strings.ToLower(strings.TrimSpace(want))]; !found {
			issues = append(issues, fmt.Sprintf("Disk %s missing", want))
		}
	}

	maxDiskUsed := -1.0
	maxDiskName := ""
	for _, k := range volKeys {
		st := volumes[k]
		if !st.hasSz || !st.hasFr || st.size <= 0 {
			continue
		}
		usedPct := (1.0 - st.free/st.size) * 100.0
		if usedPct < 0 {
			usedPct = 0
		}
		m.Disks = append(m.Disks, DiskMetric{
			Name:        st.name,
			Mount:       st.name,
			UsedPercent: usedPct,
			UsedGB:      (st.size - st.free) / (1024 * 1024 * 1024),
			TotalGB:     st.size / (1024 * 1024 * 1024),
		})
		if usedPct > maxDiskUsed {
			maxDiskUsed = usedPct
			maxDiskName = st.name
		}
		if p.maxDiskPercent > 0 && usedPct > p.maxDiskPercent {
			issues = append(issues, fmt.Sprintf("Disk %s %.1f%% > %.0f%%", st.name, usedPct, p.maxDiskPercent))
		}
	}
	if maxDiskUsed >= 0 {
		m.DiskMaxPct = floatPtr(maxDiskUsed)
		okNotes = append(okNotes, fmt.Sprintf("Disk %s %.0f%%", maxDiskName, maxDiskUsed))
	}

	// Evaluate Services
	runningSvcCount := 0
	for _, svc := range p.services {
		key := strings.ToLower(strings.TrimSpace(svc))
		if !serviceSeen[key] {
			issues = append(issues, fmt.Sprintf("Service %s not found", svc))
			m.Services = append(m.Services, ServiceMetric{Name: svc, State: "missing", OK: false})
		} else if !serviceRunning[key] {
			issues = append(issues, fmt.Sprintf("Service %s stopped", svc))
			m.Services = append(m.Services, ServiceMetric{Name: svc, State: "stopped", OK: false})
		} else {
			runningSvcCount++
			m.Services = append(m.Services, ServiceMetric{Name: svc, State: "running", OK: true})
		}
	}
	if len(p.services) > 0 && runningSvcCount == len(p.services) {
		okNotes = append(okNotes, fmt.Sprintf("Services %d/%d running", runningSvcCount, len(p.services)))
	}

	if len(issues) > 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: strings.Join(issues, "; "),
			Latency: latency,
			Metrics: m,
		}
	}
	if len(okNotes) == 0 {
		okNotes = append(okNotes, "metrics OK")
	}
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      true,
		Summary: strings.Join(okNotes, ", "),
		Latency: latency,
		Metrics: m,
	}
}
