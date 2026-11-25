package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DockerContainer describes a container discovered on the local Docker engine.
type DockerContainer struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Health  string            `json:"health"`
	Running bool              `json:"running"`
	Ports   []int             `json:"ports,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type rawDockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
	Ports  []struct {
		PrivatePort int `json:"PrivatePort"`
		PublicPort  int `json:"PublicPort"`
	} `json:"Ports"`
}

// ScanDocker lists all containers exposed by a local Docker Unix socket
// (e.g. /var/run/docker.sock) or a read-only TCP docker-socket-proxy.
func ScanDocker(ctx context.Context, socket string) ([]DockerContainer, error) {
	socket = strings.TrimSpace(socket)
	if socket == "" {
		socket = "/var/run/docker.sock"
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
			DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dctx, "unix", sockPath)
			},
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/containers/json?all=true", nil)
	if err != nil {
		return nil, fmt.Errorf("create docker list request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connexion à Docker impossible (%s) : %w", socket, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("Docker API HTTP %d : %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw []rawDockerContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("décodage liste Docker : %w", err)
	}

	out := make([]DockerContainer, 0, len(raw))
	for _, c := range raw {
		name := c.ID
		if len(name) > 12 {
			name = name[:12]
		}
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		state := strings.ToLower(strings.TrimSpace(c.State))
		statusLower := strings.ToLower(c.Status)
		health := "none"
		switch {
		case strings.Contains(statusLower, "(unhealthy)"):
			health = "unhealthy"
		case strings.Contains(statusLower, "(healthy)"):
			health = "healthy"
		case strings.Contains(statusLower, "(health: starting)"):
			health = "starting"
		}

		seenPorts := make(map[int]struct{})
		var ports []int
		for _, pt := range c.Ports {
			p := pt.PublicPort
			if p == 0 {
				p = pt.PrivatePort
			}
			if p > 0 {
				if _, ok := seenPorts[p]; !ok {
					seenPorts[p] = struct{}{}
					ports = append(ports, p)
				}
			}
		}
		sort.Ints(ports)

		out = append(out, DockerContainer{
			ID:      shortID,
			Name:    name,
			Image:   c.Image,
			State:   state,
			Status:  c.Status,
			Health:  health,
			Running: state == "running",
			Ports:   ports,
			Labels:  c.Labels,
		})
	}

	// Sort: running containers first, then alphabetical by name.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Running != out[j].Running {
			return out[i].Running
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}
