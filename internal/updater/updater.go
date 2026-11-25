package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"meshwatch/internal/version"
)

const defaultCacheTTL = 15 * time.Minute

// CheckResult describes whether a newer MeshWatch version is available on GitHub.
type CheckResult struct {
	CurrentVersion  string    `json:"current_version"`
	CurrentCommit   string    `json:"current_commit"`
	LatestVersion   string    `json:"latest_version"`
	LatestCommit    string    `json:"latest_commit,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	Building        bool      `json:"building,omitempty"`
	ReleaseName     string    `json:"release_name,omitempty"`
	ReleaseNotes    string    `json:"release_notes,omitempty"`
	ReleaseURL      string    `json:"release_url,omitempty"`
	CanAutoUpdate   bool      `json:"can_auto_update"`
	UpdateMethod    string    `json:"update_method"` // "docker" or "manual"
	Image           string    `json:"image"`
	CheckedAt       time.Time `json:"checked_at"`
}

// Config configures the GitHub release checker and Docker self-updater.
type Config struct {
	Repo          string
	Image         string
	DockerSocket  string
	APIBaseURL    string
	HTTPClient    *http.Client
	CurrentVer    string
	CurrentCommit string
}

// Updater checks GitHub for newer MeshWatch releases/commits and can orchestrate
// a zero-downtime-style Docker container self-update with automatic rollback.
type Updater struct {
	repo          string
	image         string
	dockerSocket  string
	apiBaseURL    string
	httpClient    *http.Client
	currentVer    string
	currentCommit string

	mu          sync.Mutex
	cached      *CheckResult
	cachedUntil time.Time
}

// New creates a new Updater with safe defaults.
func New(cfg Config) *Updater {
	repo := strings.TrimSpace(cfg.Repo)
	if repo == "" {
		repo = strings.TrimSpace(os.Getenv("MESHWATCH_UPDATE_REPO"))
	}
	if repo == "" {
		repo = version.DefaultUpdateRepo
	}
	image := strings.TrimSpace(cfg.Image)
	if image == "" {
		image = strings.TrimSpace(os.Getenv("MESHWATCH_UPDATE_IMAGE"))
	}
	if image == "" {
		image = version.DefaultDockerImage
	}
	sock := strings.TrimSpace(cfg.DockerSocket)
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	apiBase := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		}
	}
	curVer := strings.TrimSpace(cfg.CurrentVer)
	if curVer == "" {
		curVer = version.Version
	}
	curCommit := strings.TrimSpace(cfg.CurrentCommit)
	if curCommit == "" {
		curCommit = version.ShortCommit()
	}

	return &Updater{
		repo:          repo,
		image:         image,
		dockerSocket:  sock,
		apiBaseURL:    apiBase,
		httpClient:    client,
		currentVer:    curVer,
		currentCommit: curCommit,
	}
}

// Check queries GitHub releases (or latest main commit when no release exists) to detect updates.
func (u *Updater) Check(ctx context.Context, force bool) (CheckResult, error) {
	u.mu.Lock()
	if !force && u.cached != nil && time.Now().Before(u.cachedUntil) {
		res := *u.cached
		u.mu.Unlock()
		return res, nil
	}
	u.mu.Unlock()

	canAuto := u.canSelfUpdateDocker(ctx)
	method := "manual"
	if canAuto {
		method = "docker"
	}

	res := CheckResult{
		CurrentVersion: u.currentVer,
		CurrentCommit:  u.currentCommit,
		CanAutoUpdate:  canAuto,
		UpdateMethod:   method,
		Image:          u.image,
		CheckedAt:      time.Now().UTC(),
	}

	rel, foundRelease, err := u.fetchLatestRelease(ctx)
	if err != nil {
		return res, err
	}
	if foundRelease {
		res.LatestVersion = rel.TagName
		res.ReleaseName = rel.Name
		res.ReleaseNotes = trimNotes(rel.Body)
		res.ReleaseURL = rel.HTMLURL
		res.UpdateAvailable = isNewerVersion(u.currentVer, rel.TagName)
		if rel.TagName != "" {
			repoBase, _ := splitImageRef(u.image)
			res.Image = repoBase + ":" + rel.TagName
		}
	} else {
		// No tagged release yet: prefer the latest commit on main whose CI Docker image
		// actually succeeded and was pushed to GHCR, preventing stale pulls during builds.
		readyRun, building, hasRuns := u.fetchLatestReadyMainBuild(ctx)
		res.Building = building
		if hasRuns {
			short := readyRun.HeadSHA
			if len(short) > 7 {
				short = short[:7]
			}
			res.LatestCommit = short
			res.LatestVersion = "main@" + short
			res.ReleaseName = firstLine(readyRun.HeadCommit.Message)
			res.ReleaseNotes = trimNotes(readyRun.HeadCommit.Message)
			res.ReleaseURL = fmt.Sprintf("https://github.com/%s/commit/%s", u.repo, readyRun.HeadSHA)
			res.UpdateAvailable = u.currentCommit != "" && u.currentCommit != "none" && u.currentCommit != "dev" && !strings.HasPrefix(readyRun.HeadSHA, u.currentCommit)
			repoBase, _ := splitImageRef(u.image)
			res.Image = repoBase + ":main-" + short
		} else {
			commit, err := u.fetchLatestMainCommit(ctx)
			if err != nil {
				return res, err
			}
			short := commit.SHA
			if len(short) > 7 {
				short = short[:7]
			}
			res.LatestCommit = short
			res.LatestVersion = "main@" + short
			res.ReleaseName = firstLine(commit.Commit.Message)
			res.ReleaseNotes = trimNotes(commit.Commit.Message)
			res.ReleaseURL = commit.HTMLURL
			res.UpdateAvailable = u.currentCommit != "" && u.currentCommit != "none" && u.currentCommit != "dev" && !strings.HasPrefix(commit.SHA, u.currentCommit)
		}
	}

	u.mu.Lock()
	cp := res
	u.cached = &cp
	u.cachedUntil = time.Now().Add(defaultCacheTTL)
	u.mu.Unlock()

	return res, nil
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

func (u *Updater) fetchLatestRelease(ctx context.Context) (ghRelease, bool, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/releases/latest", u.apiBaseURL, u.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ghRelease{}, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return ghRelease{}, false, fmt.Errorf("vérification GitHub impossible : %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ghRelease{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return ghRelease{}, false, fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&rel); err != nil {
		return ghRelease{}, false, err
	}
	return rel, true, nil
}

type ghWorkflowRun struct {
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Event      string `json:"event"`
	HeadCommit struct {
		Message string `json:"message"`
	} `json:"head_commit"`
}

func (u *Updater) fetchLatestReadyMainBuild(ctx context.Context) (ready ghWorkflowRun, building bool, ok bool) {
	endpoint := fmt.Sprintf("%s/repos/%s/actions/runs?branch=main&event=push&per_page=10", u.apiBaseURL, u.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ghWorkflowRun{}, false, false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return ghWorkflowRun{}, false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ghWorkflowRun{}, false, false
	}

	var payload struct {
		WorkflowRuns []ghWorkflowRun `json:"workflow_runs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&payload); err != nil {
		return ghWorkflowRun{}, false, false
	}
	if len(payload.WorkflowRuns) == 0 {
		return ghWorkflowRun{}, false, false
	}

	// Check if the newest push run is still compiling/publishing.
	newest := payload.WorkflowRuns[0]
	if (newest.Status == "queued" || newest.Status == "in_progress") &&
		(u.currentCommit == "" || !strings.HasPrefix(newest.HeadSHA, u.currentCommit)) {
		building = true
	}

	for _, run := range payload.WorkflowRuns {
		if run.Status == "completed" && run.Conclusion == "success" && run.HeadSHA != "" {
			return run, building, true
		}
	}
	return ghWorkflowRun{}, building, false
}

type ghCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
	} `json:"commit"`
}

func (u *Updater) fetchLatestMainCommit(ctx context.Context) (ghCommit, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/commits/main", u.apiBaseURL, u.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ghCommit{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return ghCommit{}, fmt.Errorf("vérification GitHub impossible : %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ghCommit{}, fmt.Errorf("GitHub API commits HTTP %d", resp.StatusCode)
	}
	var c ghCommit
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&c); err != nil {
		return ghCommit{}, err
	}
	return c, nil
}

// ApplyDockerUpdate pulls the latest Docker image and spawns an ephemeral helper container
// running `meshwatch self-update` to replace the current container cleanly with rollback safety.
func (u *Updater) ApplyDockerUpdate(ctx context.Context, imageOverride string) error {
	targetImage := strings.TrimSpace(imageOverride)
	if targetImage == "" {
		targetImage = u.image
	}

	selfID, err := u.detectSelfContainerID(ctx)
	if err != nil {
		return err
	}

	client, baseURL := newDockerHTTPClient(u.dockerSocket, 3*time.Minute)

	// 1. Pull latest image before touching the running container.
	if err := dockerPullImage(ctx, client, baseURL, targetImage); err != nil {
		return fmt.Errorf("téléchargement de l'image %s échoué : %w", targetImage, err)
	}

	// 2. Spawn a short-lived helper container from the NEW image to swap the running container.
	helperBody := map[string]any{
		"Image": targetImage,
		"Cmd": []string{
			"self-update",
			"--container", selfID,
			"--image", targetImage,
			"--socket", u.dockerSocket,
		},
		"HostConfig": map[string]any{
			"AutoRemove": true,
			"Binds":      []string{strings.TrimPrefix(u.dockerSocket, "unix://") + ":/var/run/docker.sock"},
			"GroupAdd":   u.detectSelfGroupAdd(ctx, client, baseURL, selfID),
		},
	}

	rawBody, _ := json.Marshal(helperBody)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create", bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := client.Do(createReq)
	if err != nil {
		return fmt.Errorf("création du conteneur de mise à jour : %w", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(createResp.Body, 2048))
		return fmt.Errorf("Docker create helper HTTP %d : %s", createResp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil || created.ID == "" {
		return errors.New("réponse Docker create invalide")
	}

	startReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/"+url.PathEscape(created.ID)+"/start", nil)
	if err != nil {
		return err
	}
	startResp, err := client.Do(startReq)
	if err != nil {
		return fmt.Errorf("démarrage du helper de mise à jour : %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusNoContent && startResp.StatusCode != http.StatusOK && startResp.StatusCode != http.StatusNotModified {
		msg, _ := io.ReadAll(io.LimitReader(startResp.Body, 2048))
		return fmt.Errorf("Docker start helper HTTP %d : %s", startResp.StatusCode, strings.TrimSpace(string(msg)))
	}

	return nil
}

// RunSelfUpdateHelper is executed inside the short-lived helper container (`meshwatch self-update`).
// It stops the target container, renames it as backup, recreates it with the new image preserving
// all mounts/ports/env/networks, starts it, and automatically rolls back on any failure.
func RunSelfUpdateHelper(ctx context.Context, dockerSocket, targetContainer, newImage string) error {
	if strings.TrimSpace(targetContainer) == "" || strings.TrimSpace(newImage) == "" {
		return errors.New("self-update requires --container and --image")
	}

	client, baseURL := newDockerHTTPClient(dockerSocket, 60*time.Second)

	// 1. Inspect existing container configuration.
	inspReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(targetContainer)+"/json", nil)
	if err != nil {
		return err
	}
	inspResp, err := client.Do(inspReq)
	if err != nil {
		return fmt.Errorf("inspect target container: %w", err)
	}
	defer inspResp.Body.Close()
	if inspResp.StatusCode != http.StatusOK {
		return fmt.Errorf("inspect target container HTTP %d", inspResp.StatusCode)
	}

	var inspect map[string]any
	if err := json.NewDecoder(io.LimitReader(inspResp.Body, 4<<20)).Decode(&inspect); err != nil {
		return fmt.Errorf("decode container inspect: %w", err)
	}

	rawName, _ := inspect["Name"].(string)
	origName := strings.TrimPrefix(rawName, "/")
	if origName == "" {
		origName = "meshwatch-agent"
	}
	backupName := fmt.Sprintf("%s-backup-%d", origName, time.Now().Unix())

	cfgObj, _ := inspect["Config"].(map[string]any)
	hostCfgObj, _ := inspect["HostConfig"].(map[string]any)
	netSettings, _ := inspect["NetworkSettings"].(map[string]any)

	if cfgObj == nil {
		cfgObj = map[string]any{}
	}
	// Replace image and clear container-specific hostname so Docker assigns fresh hostname.
	cfgObj["Image"] = newImage
	delete(cfgObj, "Hostname")

	createPayload := map[string]any{}
	for k, v := range cfgObj {
		createPayload[k] = v
	}
	if hostCfgObj != nil {
		createPayload["HostConfig"] = hostCfgObj
	}
	if netSettings != nil {
		if nets, ok := netSettings["Networks"].(map[string]any); ok && len(nets) > 0 {
			endpoints := make(map[string]any, len(nets))
			for netName, netVal := range nets {
				if nv, ok := netVal.(map[string]any); ok {
					ep := map[string]any{}
					if aliases, ok := nv["Aliases"]; ok && aliases != nil {
						ep["Aliases"] = aliases
					}
					endpoints[netName] = ep
				}
			}
			createPayload["NetworkingConfig"] = map[string]any{
				"EndpointsConfig": endpoints,
			}
		}
	}

	// Brief pause so the UI receives the HTTP 202 response before the old container stops.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(600 * time.Millisecond):
	}

	// 2. Gracefully stop the old container.
	if err := dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(targetContainer)+"/stop?t=10", nil, []int{204, 304}); err != nil {
		return fmt.Errorf("stop old container: %w", err)
	}

	// 3. Rename old container to backup name so we can reuse the original name atomically.
	if err := dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(targetContainer)+"/rename?name="+url.QueryEscape(backupName), nil, []int{204}); err != nil {
		_ = dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(targetContainer)+"/start", nil, []int{204, 304})
		return fmt.Errorf("rename old container: %w", err)
	}

	rollback := func(cause error) error {
		_ = dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(targetContainer)+"/rename?name="+url.QueryEscape(origName), nil, []int{204})
		_ = dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(targetContainer)+"/start", nil, []int{204, 304})
		return cause
	}

	// 4. Create new container with original name and updated image.
	payloadBytes, err := json.Marshal(createPayload)
	if err != nil {
		return rollback(err)
	}
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/containers/create?name="+url.QueryEscape(origName), bytes.NewReader(payloadBytes))
	if err != nil {
		return rollback(err)
	}
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := client.Do(createReq)
	if err != nil {
		return rollback(fmt.Errorf("create updated container: %w", err))
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated && createResp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(createResp.Body, 2048))
		return rollback(fmt.Errorf("create updated container HTTP %d: %s", createResp.StatusCode, strings.TrimSpace(string(msg))))
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil || created.ID == "" {
		return rollback(errors.New("invalid create response"))
	}

	// 5. Start the new container.
	if err := dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(created.ID)+"/start", nil, []int{204, 304}); err != nil {
		delReq, _ := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/containers/"+url.PathEscape(created.ID)+"?force=true", nil)
		if delReq != nil {
			if r, e := client.Do(delReq); e == nil {
				_ = r.Body.Close()
			}
		}
		return rollback(fmt.Errorf("start updated container: %w", err))
	}

	// 6. Remove backup container now that the updated container is running.
	delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/containers/"+url.PathEscape(targetContainer), nil)
	if err == nil {
		if r, e := client.Do(delReq); e == nil {
			_ = r.Body.Close()
		}
	}

	return nil
}

func (u *Updater) canSelfUpdateDocker(ctx context.Context) bool {
	if _, err := u.detectSelfContainerID(ctx); err != nil {
		return false
	}
	return true
}

func (u *Updater) detectSelfContainerID(ctx context.Context) (string, error) {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return "", errors.New("mise à jour automatique disponible uniquement dans Docker")
	}
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "", errors.New("impossible d'identifier le conteneur courant")
	}

	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client, baseURL := newDockerHTTPClient(u.dockerSocket, 2*time.Second)
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(host)+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("socket Docker inaccessible (%s) : %w", u.dockerSocket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("conteneur courant introuvable sur Docker (HTTP %d)", resp.StatusCode)
	}
	var info struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil || info.ID == "" {
		return "", errors.New("réponse Docker inspect invalide")
	}
	return info.ID, nil
}

func (u *Updater) detectSelfGroupAdd(ctx context.Context, client *http.Client, baseURL, selfID string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(selfID)+"/json", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var info struct {
		HostConfig struct {
			GroupAdd []string `json:"GroupAdd"`
		} `json:"HostConfig"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return nil
	}
	return info.HostConfig.GroupAdd
}

func dockerPullImage(ctx context.Context, client *http.Client, baseURL, imageRef string) error {
	repo, tag := splitImageRef(imageRef)
	endpoint := fmt.Sprintf("%s/images/create?fromImage=%s&tag=%s", baseURL, url.QueryEscape(repo), url.QueryEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	// Drain streaming pull status so the image is completely pulled before returning.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func dockerPost(ctx context.Context, client *http.Client, endpoint string, body io.Reader, allowed []int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for _, code := range allowed {
		if resp.StatusCode == code {
			return nil
		}
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func newDockerHTTPClient(socket string, timeout time.Duration) (*http.Client, string) {
	socket = strings.TrimSpace(socket)
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	switch {
	case strings.HasPrefix(socket, "tcp://"):
		return &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}},
			"http://" + strings.TrimRight(strings.TrimPrefix(socket, "tcp://"), "/")
	case strings.HasPrefix(socket, "http://"), strings.HasPrefix(socket, "https://"):
		return &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}},
			strings.TrimRight(socket, "/")
	default:
		sockPath := strings.TrimPrefix(socket, "unix://")
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sockPath)
				},
			},
		}, "http://docker"
	}
}

func splitImageRef(ref string) (repo, tag string) {
	ref = strings.TrimSpace(ref)
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, "latest"
}

// isNewerVersion compares semver tags like "v1.0.0" vs "v1.2.1".
func isNewerVersion(current, latest string) bool {
	cParts, cOK := parseSemver(current)
	lParts, lOK := parseSemver(latest)
	if !lOK {
		return false
	}
	if !cOK {
		return strings.TrimSpace(current) != strings.TrimSpace(latest)
	}
	for i := 0; i < 3; i++ {
		if lParts[i] > cParts[i] {
			return true
		}
		if lParts[i] < cParts[i] {
			return false
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	if dash := strings.IndexByte(s, '-'); dash >= 0 {
		s = s[:dash]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

func trimNotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:397] + "..."
	}
	return s
}
