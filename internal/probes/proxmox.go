package probes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"meshwatch/internal/config"
)

const maxProxmoxBodyBytes = 8 << 20 // 8 MiB cap for Proxmox API responses

// ProxmoxProbe monitors a Proxmox VE node or cluster via the official REST API (/api2/json).
type ProxmoxProbe struct {
	id             string
	baseURL        string
	authHeader     string
	node           string
	maxCPUPercent  float64
	maxRAMPercent  float64
	maxDiskPercent float64
	disks          []string
	vms            []string
	client         *http.Client
}

// NewProxmoxProbe creates a ProxmoxProbe from configuration.
func NewProxmoxProbe(cfg config.ProbeConfig) *ProxmoxProbe {
	return &ProxmoxProbe{
		id:             cfg.ID,
		baseURL:        normalizeProxmoxBaseURL(cfg.URL),
		authHeader:     buildProxmoxAuthHeader(cfg.TokenID, cfg.TokenSecret),
		node:           strings.TrimSpace(cfg.Node),
		maxCPUPercent:  cfg.MaxCPUPercent,
		maxRAMPercent:  cfg.MaxRAMPercent,
		maxDiskPercent: cfg.MaxDiskPercent,
		disks:          append([]string(nil), cfg.Disks...),
		vms:            append([]string(nil), cfg.VMs...),
		client: &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // user-enabled for self-signed PVE certificates
				},
			},
		},
	}
}

func (p *ProxmoxProbe) ID() string   { return p.id }
func (p *ProxmoxProbe) Kind() string { return "proxmox" }

type pveResource struct {
	Type     string  `json:"type"`
	Node     string  `json:"node"`
	Status   string  `json:"status"`
	CPU      float64 `json:"cpu"`
	MaxCPU   float64 `json:"maxcpu"`
	Mem      float64 `json:"mem"`
	MaxMem   float64 `json:"maxmem"`
	Disk     float64 `json:"disk"`
	MaxDisk  float64 `json:"maxdisk"`
	Storage  string  `json:"storage"`
	Shared   int     `json:"shared"`
	VMID     int     `json:"vmid"`
	Name     string  `json:"name"`
	Template int     `json:"template"`
	Uptime   int64   `json:"uptime"`
}

func (p *ProxmoxProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	resources, code, err := p.fetchResources(ctx, "/api2/json/cluster/resources")
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: err.Error(),
			Latency: time.Since(start).Milliseconds(),
		}
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("Proxmox API: jeton refusé (HTTP %d) — vérifiez Token ID, secret et le rôle PVEAuditor", code),
			Latency: time.Since(start).Milliseconds(),
		}
	}
	if code != http.StatusOK {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("Proxmox API HTTP %d", code),
			Latency: time.Since(start).Milliseconds(),
		}
	}

	if len(resources) == 0 {
		nodeRes, nCode, nErr := p.fetchResources(ctx, "/api2/json/nodes")
		if nErr == nil && nCode == http.StatusOK && len(nodeRes) > 0 {
			for i := range nodeRes {
				nodeRes[i].Type = "node"
			}
			resources = nodeRes
		}
	}
	if len(resources) == 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: "Proxmox API connectée mais aucune ressource visible — accordez le rôle PVEAuditor sur / au jeton (ou décochez Privilege Separation)",
			Latency: time.Since(start).Milliseconds(),
		}
	}

	ok, summary, metrics := evaluateProxmoxResourcesDetailed(resources, p.node, p.maxCPUPercent, p.maxRAMPercent, p.maxDiskPercent, p.disks, p.vms)
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      ok,
		Summary: summary,
		Latency: time.Since(start).Milliseconds(),
		Metrics: metrics,
	}
}

func (p *ProxmoxProbe) fetchResources(ctx context.Context, path string) ([]pveResource, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("Proxmox URL invalide : %w", err)
	}
	req.Header.Set("Authorization", p.authHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MeshWatch/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Proxmox API inaccessible : %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxmoxBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("lecture Proxmox API échouée : %w", err)
	}
	var env struct {
		Data []pveResource `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("réponse Proxmox API invalide : %w", err)
	}
	return env.Data, resp.StatusCode, nil
}

func evaluateProxmoxResources(
	resources []pveResource,
	nodeFilter string,
	maxCPUPct, maxRAMPct, maxDiskPct float64,
	diskFilter []string,
	requiredVMs []string,
) (bool, string) {
	ok, summary, _ := evaluateProxmoxResourcesDetailed(resources, nodeFilter, maxCPUPct, maxRAMPct, maxDiskPct, diskFilter, requiredVMs)
	return ok, summary
}

func evaluateProxmoxResourcesDetailed(
	resources []pveResource,
	nodeFilter string,
	maxCPUPct, maxRAMPct, maxDiskPct float64,
	diskFilter []string,
	requiredVMs []string,
) (bool, string, *ProbeMetrics) {
	var (
		nodes    []pveResource
		storages []pveResource
		guests   []pveResource
	)
	for _, r := range resources {
		if nodeFilter != "" && !strings.EqualFold(strings.TrimSpace(r.Node), nodeFilter) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(r.Type)) {
		case "node":
			nodes = append(nodes, r)
		case "storage":
			storages = append(storages, r)
		case "qemu", "lxc":
			guests = append(guests, r)
		}
	}

	if len(nodes) > 0 && len(storages) == 0 && len(guests) == 0 {
		anyOffline := false
		anyMetrics := false
		for _, n := range nodes {
			if !strings.EqualFold(strings.TrimSpace(n.Status), "online") {
				anyOffline = true
			}
			if n.MaxCPU > 0 || n.MaxMem > 0 || n.MaxDisk > 0 {
				anyMetrics = true
			}
		}
		if !anyOffline && !anyMetrics {
			return false, "Proxmox API connectée, mais ce jeton n'a aucune permission de lecture (CPU/RAM/VM masqués) — dans Proxmox : Centre de données → Permissions → Ajouter → Permission de jeton d'API (Chemin « / », Rôle « PVEAuditor »), ou décochez « Séparation des privilèges »", nil
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		return strings.ToLower(nodes[i].Node) < strings.ToLower(nodes[j].Node)
	})
	sort.Slice(storages, func(i, j int) bool {
		if strings.ToLower(storages[i].Node) != strings.ToLower(storages[j].Node) {
			return strings.ToLower(storages[i].Node) < strings.ToLower(storages[j].Node)
		}
		return strings.ToLower(storages[i].Storage) < strings.ToLower(storages[j].Storage)
	})
	sort.Slice(guests, func(i, j int) bool {
		if guests[i].VMID != guests[j].VMID {
			return guests[i].VMID < guests[j].VMID
		}
		return strings.ToLower(guests[i].Name) < strings.ToLower(guests[j].Name)
	})

	var issues []string
	m := &ProbeMetrics{}
	onlineNodes := 0
	maxCPU := -1.0
	maxRAM := -1.0
	maxRootDisk := -1.0
	var totalRAMBytes, usedRAMBytes float64

	if nodeFilter != "" && len(nodes) == 0 {
		issues = append(issues, fmt.Sprintf("Node %s introuvable", nodeFilter))
	}

	for _, n := range nodes {
		name := fallbackStr(strings.TrimSpace(n.Node), "pve")
		st := strings.ToLower(strings.TrimSpace(n.Status))
		if st == "online" {
			onlineNodes++
		} else {
			issues = append(issues, fmt.Sprintf("Node %s %s", name, fallbackStr(n.Status, "unknown")))
		}

		nm := NodeMetric{
			Name:      name,
			Status:    fallbackStr(strings.TrimSpace(n.Status), "unknown"),
			UptimeSec: n.Uptime,
		}
		if len(nodes) == 1 {
			m.Hostname = name
			if n.Uptime > 0 {
				m.UptimeSec = n.Uptime
			}
		}

		if n.MaxCPU > 0 {
			cpuPct := n.CPU * 100.0
			if cpuPct < 0 {
				cpuPct = 0
			}
			nm.CPUPercent = cpuPct
			if cpuPct > maxCPU {
				maxCPU = cpuPct
			}
			if maxCPUPct > 0 && cpuPct > maxCPUPct {
				issues = append(issues, fmt.Sprintf("CPU (%s) %.1f%% > %.0f%%", name, cpuPct, maxCPUPct))
			}
		}

		if n.MaxMem > 0 {
			ramPct := (n.Mem / n.MaxMem) * 100.0
			if ramPct < 0 {
				ramPct = 0
			}
			nm.RAMPercent = ramPct
			usedRAMBytes += n.Mem
			totalRAMBytes += n.MaxMem
			if ramPct > maxRAM {
				maxRAM = ramPct
			}
			if maxRAMPct > 0 && ramPct > maxRAMPct {
				issues = append(issues, fmt.Sprintf("RAM (%s) %.1f%% > %.0f%%", name, ramPct, maxRAMPct))
			}
		}

		if n.MaxDisk > 0 {
			rootPct := (n.Disk / n.MaxDisk) * 100.0
			if rootPct < 0 {
				rootPct = 0
			}
			nm.DiskPercent = rootPct
			if rootPct > maxRootDisk {
				maxRootDisk = rootPct
			}
			if maxDiskPct > 0 && rootPct > maxDiskPct {
				issues = append(issues, fmt.Sprintf("Disque root (%s) %.1f%% > %.0f%%", name, rootPct, maxDiskPct))
			}
		}
		m.Nodes = append(m.Nodes, nm)
	}

	if maxCPU >= 0 {
		m.CPUPercent = floatPtr(maxCPU)
	}
	if maxRAM >= 0 {
		m.RAMPercent = floatPtr(maxRAM)
	}
	if totalRAMBytes > 0 {
		m.RAMUsedMB = usedRAMBytes / (1024 * 1024)
		m.RAMTotalMB = totalRAMBytes / (1024 * 1024)
	}

	wantedDisks := make(map[string]struct{}, len(diskFilter))
	for _, d := range diskFilter {
		if k := strings.ToLower(strings.TrimSpace(d)); k != "" {
			wantedDisks[k] = struct{}{}
		}
	}
	seenDisks := make(map[string]bool)
	seenSharedUsage := make(map[string]bool)
	maxStorPct := -1.0
	maxStorName := ""

	for _, s := range storages {
		storName := fallbackStr(strings.TrimSpace(s.Storage), strings.TrimSpace(s.Name))
		storKey := strings.ToLower(storName)
		if storKey == "" {
			continue
		}
		if len(wantedDisks) > 0 {
			if _, want := wantedDisks[storKey]; !want {
				continue
			}
		}
		seenDisks[storKey] = true

		st := strings.ToLower(strings.TrimSpace(s.Status))
		if st != "" && st != "available" && st != "active" {
			issues = append(issues, fmt.Sprintf("Stockage %s (%s) %s", storName, fallbackStr(s.Node, "pve"), s.Status))
		}

		if s.Shared == 1 {
			if seenSharedUsage[storKey] {
				continue
			}
			seenSharedUsage[storKey] = true
		}

		if s.MaxDisk > 0 {
			usedPct := (s.Disk / s.MaxDisk) * 100.0
			if usedPct < 0 {
				usedPct = 0
			}
			if usedPct > maxStorPct {
				maxStorPct = usedPct
				maxStorName = storName
			}
			if maxDiskPct > 0 && usedPct > maxDiskPct {
				issues = append(issues, fmt.Sprintf("Stockage %s %.1f%% > %.0f%%", storName, usedPct, maxDiskPct))
			}
			m.Disks = append(m.Disks, DiskMetric{
				Name:        storName,
				Mount:       s.Node,
				UsedPercent: usedPct,
				UsedGB:      s.Disk / (1024 * 1024 * 1024),
				TotalGB:     s.MaxDisk / (1024 * 1024 * 1024),
				Status:      fallbackStr(strings.TrimSpace(s.Status), "active"),
			})
		}
	}

	if maxStorPct >= 0 {
		m.DiskMaxPct = floatPtr(maxStorPct)
	} else if maxRootDisk >= 0 {
		m.DiskMaxPct = floatPtr(maxRootDisk)
	}

	for _, rawWant := range diskFilter {
		want := strings.TrimSpace(rawWant)
		if want != "" && !seenDisks[strings.ToLower(want)] {
			issues = append(issues, fmt.Sprintf("Stockage %s introuvable", want))
		}
	}

	byVMID := make(map[string]pveResource, len(guests))
	byName := make(map[string]pveResource, len(guests))
	totalGuests := 0
	runningGuests := 0
	for _, g := range guests {
		if g.VMID > 0 {
			byVMID[strconv.Itoa(g.VMID)] = g
		}
		if nameKey := strings.ToLower(strings.TrimSpace(g.Name)); nameKey != "" {
			byName[nameKey] = g
		}
		if g.Template == 1 {
			continue
		}
		totalGuests++
		if strings.EqualFold(strings.TrimSpace(g.Status), "running") {
			runningGuests++
		}
		gm := GuestMetric{
			ID:     strconv.Itoa(g.VMID),
			Name:   fallbackStr(strings.TrimSpace(g.Name), strconv.Itoa(g.VMID)),
			Type:   strings.ToLower(strings.TrimSpace(g.Type)),
			Node:   g.Node,
			Status: fallbackStr(strings.TrimSpace(g.Status), "unknown"),
		}
		if g.MaxCPU > 0 {
			gm.CPUPercent = floatPtr(g.CPU * 100.0)
		}
		if g.MaxMem > 0 {
			gm.RAMPercent = floatPtr((g.Mem / g.MaxMem) * 100.0)
		}
		m.Guests = append(m.Guests, gm)
	}

	for _, rawWant := range requiredVMs {
		want := strings.TrimSpace(rawWant)
		if want == "" {
			continue
		}
		g, ok := byVMID[want]
		if !ok {
			g, ok = byName[strings.ToLower(want)]
		}
		if !ok {
			issues = append(issues, fmt.Sprintf("VM/LXC %s introuvable", want))
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(g.Status), "running") {
			label := strings.TrimSpace(g.Name)
			if label != "" && g.VMID > 0 {
				issues = append(issues, fmt.Sprintf("VM/LXC %s (%d) %s", label, g.VMID, fallbackStr(g.Status, "stopped")))
			} else if g.VMID > 0 {
				issues = append(issues, fmt.Sprintf("VM/LXC %d %s", g.VMID, fallbackStr(g.Status, "stopped")))
			} else {
				issues = append(issues, fmt.Sprintf("VM/LXC %s %s", want, fallbackStr(g.Status, "stopped")))
			}
		}
	}

	if len(issues) > 0 {
		return false, strings.Join(issues, "; "), m
	}

	var parts []string
	if len(nodes) == 1 {
		parts = append(parts, fmt.Sprintf("%s en ligne", fallbackStr(strings.TrimSpace(nodes[0].Node), "pve")))
	} else if len(nodes) > 1 {
		parts = append(parts, fmt.Sprintf("%d/%d nœuds en ligne", onlineNodes, len(nodes)))
	}

	cpuPrefix := "CPU"
	ramPrefix := "RAM"
	if len(nodes) > 1 {
		cpuPrefix = "CPU max"
		ramPrefix = "RAM max"
	}
	if maxCPU >= 0 {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", cpuPrefix, maxCPU))
	}
	if maxRAM >= 0 {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", ramPrefix, maxRAM))
	}
	if maxStorPct >= 0 {
		parts = append(parts, fmt.Sprintf("Stockage %s %.0f%%", maxStorName, maxStorPct))
	} else if maxRootDisk >= 0 {
		parts = append(parts, fmt.Sprintf("Disque root %.0f%%", maxRootDisk))
	}
	if totalGuests > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d VM/LXC actives", runningGuests, totalGuests))
	}
	if len(parts) == 0 {
		parts = append(parts, "Proxmox API OK")
	}
	return true, strings.Join(parts, ", "), m
}

func normalizeProxmoxBaseURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if len(s) >= len("/api2/json") && strings.EqualFold(s[len(s)-len("/api2/json"):], "/api2/json") {
		s = strings.TrimRight(s[:len(s)-len("/api2/json")], "/")
	}
	return s
}

func buildProxmoxAuthHeader(tokenID, tokenSecret string) string {
	tid := strings.TrimSpace(tokenID)
	if len(tid) >= len("PVEAPIToken=") && strings.EqualFold(tid[:len("PVEAPIToken=")], "PVEAPIToken=") {
		tid = strings.TrimSpace(tid[len("PVEAPIToken="):])
	}
	sec := strings.TrimSpace(tokenSecret)
	if sec != "" {
		return "PVEAPIToken=" + tid + "=" + sec
	}
	return "PVEAPIToken=" + tid
}

func fallbackStr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
