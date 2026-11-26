package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"meshwatch/internal/config"
)

// DockerProbe inspects local or socket-proxy Docker containers over HTTP/Unix socket
// without pulling in the heavy official Docker client SDK.
type DockerProbe struct {
	id          string
	baseURL     string
	client      *http.Client
	containers  []string
	labelKey    string
	labelVal    string
	hasLabelVal bool
	maxRestarts int
}

type dockerContainerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

type dockerContainerInspect struct {
	RestartCount int `json:"RestartCount"`
	State        struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

// NewDockerProbe builds a lightweight Docker API probe targeting a Unix socket
// (e.g., /var/run/docker.sock) or a TCP socket-proxy (e.g., tcp://docker-socket-proxy:2375).
func NewDockerProbe(cfg config.ProbeConfig) (*DockerProbe, error) {
	socket := strings.TrimSpace(cfg.Socket)
	if socket == "" {
		socket = config.DefaultDockerSocket
	}

	var (
		baseURL string
		tr      *http.Transport
	)

	switch {
	case strings.HasPrefix(socket, "tcp://"):
		baseURL = "http://" + strings.TrimRight(strings.TrimPrefix(socket, "tcp://"), "/")
		tr = &http.Transport{DisableKeepAlives: true}
	case strings.HasPrefix(socket, "http://"), strings.HasPrefix(socket, "https://"):
		baseURL = strings.TrimRight(socket, "/")
		tr = &http.Transport{DisableKeepAlives: true}
	default:
		sockPath := strings.TrimPrefix(socket, "unix://")
		baseURL = "http://docker"
		tr = &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		}
	}

	p := &DockerProbe{
		id:          cfg.ID,
		baseURL:     baseURL,
		client:      &http.Client{Transport: tr},
		containers:  append([]string(nil), cfg.Containers...),
		maxRestarts: cfg.MaxRestarts,
	}

	if lbl := strings.TrimSpace(cfg.Label); lbl != "" {
		if k, v, ok := strings.Cut(lbl, "="); ok {
			p.labelKey = strings.TrimSpace(k)
			p.labelVal = strings.TrimSpace(v)
			p.hasLabelVal = true
		} else {
			p.labelKey = lbl
		}
	}

	return p, nil
}

func (p *DockerProbe) ID() string   { return p.id }
func (p *DockerProbe) Kind() string { return "docker" }

func (p *DockerProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	containers, err := p.listContainers(ctx)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("docker API error: %v", err),
			Latency: latency,
		}
	}

	var (
		total        int
		up           int
		issues       []string
		containerMetrics []ContainerMetric
	)

	if len(p.containers) > 0 {
		byName := make(map[string]dockerContainerSummary, len(containers))
		for _, c := range containers {
			for _, rawName := range c.Names {
				name := strings.TrimPrefix(rawName, "/")
				byName[name] = c
			}
			if len(c.ID) >= 12 {
				byName[c.ID[:12]] = c
			}
			byName[c.ID] = c
		}

		for _, target := range p.containers {
			total++
			c, found := byName[target]
			if !found {
				issues = append(issues, fmt.Sprintf("%s (missing)", target))
				containerMetrics = append(containerMetrics, ContainerMetric{
					Name:   target,
					State:  "missing",
					Status: "missing",
					OK:     false,
				})
				continue
			}
			issue, cm := p.evaluateContainer(ctx, target, c)
			containerMetrics = append(containerMetrics, cm)
			if issue != "" {
				issues = append(issues, issue)
			} else {
				up++
			}
		}
	} else {
		matched := make([]dockerContainerSummary, 0)
		for _, c := range containers {
			if p.matchesLabel(c.Labels) {
				matched = append(matched, c)
			}
		}
		sort.Slice(matched, func(i, j int) bool {
			return containerDisplayName(matched[i]) < containerDisplayName(matched[j])
		})
		for _, c := range matched {
			total++
			name := containerDisplayName(c)
			issue, cm := p.evaluateContainer(ctx, name, c)
			containerMetrics = append(containerMetrics, cm)
			if issue != "" {
				issues = append(issues, issue)
			} else {
				up++
			}
		}
	}

	m := &ProbeMetrics{Containers: containerMetrics}
	latency = time.Since(start).Milliseconds()
	if len(issues) > 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("%d/%d up; %s", up, total, strings.Join(issues, ", ")),
			Latency: latency,
			Metrics: m,
		}
	}
	if total == 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      true,
			Summary: "0/0 monitored",
			Latency: latency,
			Metrics: m,
		}
	}
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      true,
		Summary: fmt.Sprintf("%d/%d up", up, total),
		Latency: latency,
		Metrics: m,
	}
}

func (p *DockerProbe) matchesLabel(labels map[string]string) bool {
	if p.labelKey == "" {
		return true
	}
	v, ok := labels[p.labelKey]
	if !ok {
		return false
	}
	if p.hasLabelVal {
		return v == p.labelVal
	}
	return true
}

func (p *DockerProbe) evaluateContainer(ctx context.Context, name string, c dockerContainerSummary) (string, ContainerMetric) {
	state := strings.ToLower(strings.TrimSpace(c.State))
	health := ""
	lowStatus := strings.ToLower(c.Status)
	switch {
	case strings.Contains(lowStatus, "(healthy)"):
		health = "healthy"
	case strings.Contains(lowStatus, "(unhealthy)"):
		health = "unhealthy"
	case strings.Contains(lowStatus, "(health: starting)"):
		health = "starting"
	}
	cm := ContainerMetric{
		Name:   name,
		State:  state,
		Status: c.Status,
		Health: health,
		OK:     true,
	}
	if state != "running" {
		cm.OK = false
		return fmt.Sprintf("%s (%s)", name, state), cm
	}
	if health == "unhealthy" {
		cm.OK = false
		return fmt.Sprintf("%s (unhealthy)", name), cm
	}
	if p.maxRestarts > 0 {
		insp, err := p.inspectContainer(ctx, c.ID)
		if err != nil {
			cm.OK = false
			return fmt.Sprintf("%s (inspect err: %v)", name, err), cm
		}
		cm.Restarts = insp.RestartCount
		if insp.State.Health != nil && strings.TrimSpace(insp.State.Health.Status) != "" {
			cm.Health = strings.ToLower(strings.TrimSpace(insp.State.Health.Status))
		}
		if cm.Health == "unhealthy" {
			cm.OK = false
			return fmt.Sprintf("%s (unhealthy)", name), cm
		}
		if insp.RestartCount > p.maxRestarts {
			cm.OK = false
			return fmt.Sprintf("%s (restarts=%d > %d)", name, insp.RestartCount, p.maxRestarts), cm
		}
	}
	return "", cm
}

func (p *DockerProbe) listContainers(ctx context.Context) ([]dockerContainerSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/containers/json?all=true", nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var list []dockerContainerSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode containers JSON: %w", err)
	}
	return list, nil
}

func (p *DockerProbe) inspectContainer(ctx context.Context, id string) (*dockerContainerInspect, error) {
	endpoint := p.baseURL + "/containers/" + url.PathEscape(id) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var insp dockerContainerInspect
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&insp); err != nil {
		return nil, err
	}
	return &insp, nil
}

func containerDisplayName(c dockerContainerSummary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}
