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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"meshwatch/internal/version"
)

const defaultCacheTTL = 15 * time.Minute

// CheckResult describes whether a newer MeshWatch version is available via GHCR or GitHub.
type CheckResult struct {
	CurrentVersion   string    `json:"current_version"`
	CurrentCommit    string    `json:"current_commit"`
	LatestVersion    string    `json:"latest_version"`
	LatestCommit     string    `json:"latest_commit,omitempty"`
	UpdateAvailable  bool      `json:"update_available"`
	Building         bool      `json:"building,omitempty"`
	Source           string    `json:"source,omitempty"` // "ghcr" or "github"
	ReleaseName      string    `json:"release_name,omitempty"`
	ReleaseNotes     string    `json:"release_notes,omitempty"`
	ReleaseURL       string    `json:"release_url,omitempty"`
	CanAutoUpdate    bool      `json:"can_auto_update"`
	AutoUpdateReason string    `json:"auto_update_reason,omitempty"`
	UpdateMethod     string    `json:"update_method"` // "docker" or "manual"
	Image            string    `json:"image"`
	CheckedAt        time.Time `json:"checked_at"`
}

// Config configures the GHCR / GitHub release checker and Docker self-updater.
type Config struct {
	Repo             string
	Image            string
	DockerSocket     string
	APIBaseURL       string
	RegistryBaseURL  string
	HTTPClient       *http.Client
	CurrentVer       string
	CurrentCommit    string
	CurrentBuildDate string
}

// Updater checks GHCR OCI labels (primary, zero GitHub REST rate limit) and GitHub releases/CI
// for newer MeshWatch images, and can orchestrate a Docker container self-update with rollback.
type Updater struct {
	repo             string
	image            string
	dockerSocket     string
	apiBaseURL       string
	registryBaseURL  string
	httpClient       *http.Client
	currentVer       string
	currentCommit    string
	currentBuildDate string

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
	regBase := strings.TrimRight(strings.TrimSpace(cfg.RegistryBaseURL), "/")
	if regBase == "" && apiBase == "" {
		regBase = "https://ghcr.io"
	}
	if strings.EqualFold(regBase, "none") {
		regBase = ""
	}
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
	curBuildDate := strings.TrimSpace(cfg.CurrentBuildDate)
	if curBuildDate == "" {
		curBuildDate = strings.TrimSpace(version.BuildDate)
	}

	return &Updater{
		repo:             repo,
		image:            image,
		dockerSocket:     sock,
		apiBaseURL:       apiBase,
		registryBaseURL:  regBase,
		httpClient:       client,
		currentVer:       curVer,
		currentCommit:    curCommit,
		currentBuildDate: curBuildDate,
	}
}

// Check queries GHCR OCI metadata first (avoiding GitHub REST API rate limits and confirming
// the image is already published), falling back to GitHub releases/CI/commits if needed.
func (u *Updater) Check(ctx context.Context, force bool) (CheckResult, error) {
	u.mu.Lock()
	if !force && u.cached != nil && time.Now().Before(u.cachedUntil) {
		res := *u.cached
		u.mu.Unlock()
		return res, nil
	}
	u.mu.Unlock()

	_, autoErr := u.detectSelfContainerID(ctx)
	canAuto := autoErr == nil
	method := "manual"
	autoReason := ""
	if canAuto {
		method = "docker"
	} else if autoErr != nil {
		autoReason = autoErr.Error()
	}

	res := CheckResult{
		CurrentVersion:   u.currentVer,
		CurrentCommit:    u.currentCommit,
		CanAutoUpdate:    canAuto,
		AutoUpdateReason: autoReason,
		UpdateMethod:     method,
		Image:            u.image,
		CheckedAt:        time.Now().UTC(),
	}

	// Primary path: query GHCR OCI manifest + config labels directly.
	if u.registryBaseURL != "" {
		if ghcrRes, ok := u.fetchLatestFromGHCR(ctx, res); ok {
			u.storeCache(ghcrRes, defaultCacheTTL)
			return ghcrRes, nil
		}
	}

	// Secondary path: GitHub Releases -> GitHub Actions ready builds -> main commit.
	rel, foundRelease, err := u.fetchLatestRelease(ctx)
	if err != nil {
		return res, err
	}
	if foundRelease {
		res.Source = "github"
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
		readyRun, alreadyAhead, building, hasRuns := u.fetchLatestReadyMainBuild(ctx)
		res.Building = building
		res.Source = "github"
		if hasRuns {
			short := shortCommit(readyRun.HeadSHA)
			res.LatestCommit = short
			res.LatestVersion = "main@" + short
			res.ReleaseName = firstLine(readyRun.HeadCommit.Message)
			res.ReleaseNotes = trimNotes(readyRun.HeadCommit.Message)
			res.ReleaseURL = fmt.Sprintf("https://github.com/%s/commit/%s", u.repo, readyRun.HeadSHA)
			if alreadyAhead {
				res.LatestCommit = u.currentCommit
				res.LatestVersion = "main@" + u.currentCommit
				res.UpdateAvailable = false
			} else {
				res.UpdateAvailable = isDifferentReleaseCommit(u.currentCommit, readyRun.HeadSHA)
			}
			repoBase, _ := splitImageRef(u.image)
			res.Image = repoBase + ":main-" + short
		} else {
			commit, err := u.fetchLatestMainCommit(ctx)
			if err != nil {
				return res, err
			}
			short := shortCommit(commit.SHA)
			res.LatestCommit = short
			res.LatestVersion = "main@" + short
			res.ReleaseName = firstLine(commit.Commit.Message)
			res.ReleaseNotes = trimNotes(commit.Commit.Message)
			res.ReleaseURL = commit.HTMLURL
			res.UpdateAvailable = isDifferentReleaseCommit(u.currentCommit, commit.SHA)
		}
	}

	u.storeCache(res, defaultCacheTTL)
	return res, nil
}

func (u *Updater) storeCache(res CheckResult, ttl time.Duration) {
	u.mu.Lock()
	cp := res
	u.cached = &cp
	u.cachedUntil = time.Now().Add(ttl)
	u.mu.Unlock()
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociManifestOrIndex struct {
	MediaType string          `json:"mediaType"`
	Manifests []ociDescriptor `json:"manifests"`
	Config    *ociDescriptor  `json:"config"`
}

type ociImageConfigBlob struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

func (u *Updater) fetchLatestFromGHCR(ctx context.Context, base CheckResult) (CheckResult, bool) {
	repoBase, tag := splitImageRef(u.image)
	imagePath := stripRegistryHost(repoBase)
	if imagePath == "" {
		return base, false
	}

	token, err := u.fetchRegistryToken(ctx, imagePath)
	if err != nil {
		return base, false
	}

	manifest, err := u.fetchRegistryManifest(ctx, imagePath, tag, token)
	if err != nil {
		return base, false
	}

	// Resolve multi-arch OCI Index / Manifest List to the current platform manifest.
	if len(manifest.Manifests) > 0 {
		selected := selectPlatformManifest(manifest.Manifests, runtime.GOARCH)
		if selected == "" {
			return base, false
		}
		manifest, err = u.fetchRegistryManifest(ctx, imagePath, selected, token)
		if err != nil {
			return base, false
		}
	}

	if manifest.Config == nil || manifest.Config.Digest == "" {
		return base, false
	}

	labels, err := u.fetchRegistryConfigLabels(ctx, imagePath, manifest.Config.Digest, token)
	if err != nil {
		return base, false
	}

	rev := strings.TrimSpace(labels["org.opencontainers.image.revision"])
	ver := strings.TrimSpace(labels["org.opencontainers.image.version"])
	title := strings.TrimSpace(labels["org.opencontainers.image.title"])
	created := strings.TrimSpace(labels["org.opencontainers.image.created"])
	if rev == "" {
		// Older image without OCI revision label: fall back to GitHub API.
		return base, false
	}

	shortRev := shortCommit(rev)
	out := base
	out.Source = "ghcr"
	out.LatestCommit = shortRev
	if ver != "" {
		out.LatestVersion = ver
	} else {
		out.LatestVersion = "main@" + shortRev
	}
	if line := firstLine(title); line != "" {
		out.ReleaseName = line
		out.ReleaseNotes = trimNotes(title)
	} else {
		out.ReleaseName = "Version " + out.LatestVersion
	}
	out.ReleaseURL = fmt.Sprintf("https://github.com/%s/commit/%s", u.repo, rev)

	targetTag := tag
	if ver != "" && !strings.ContainsAny(ver, " \t\r\n@") {
		targetTag = ver
	}
	out.Image = repoBase + ":" + targetTag

	out.UpdateAvailable = u.shouldOfferGHCRUpdate(ver, rev, created)
	return out, true
}

func (u *Updater) shouldOfferGHCRUpdate(remoteVer, remoteRev, remoteCreated string) bool {
	if isSameCommit(u.currentCommit, remoteRev) {
		return false
	}
	if isNewerTimeCheck(u.currentBuildDate, remoteCreated) {
		return false
	}
	if _, lOK := parseSemver(remoteVer); lOK {
		if _, cOK := parseSemver(u.currentVer); cOK {
			return isNewerVersion(u.currentVer, remoteVer)
		}
	}
	return isDifferentReleaseCommit(u.currentCommit, remoteRev)
}

// isNewerTimeCheck returns true if the local build is at least as new as the remote build.
func isNewerTimeCheck(localDateStr, remoteDateStr string) bool {
	if strings.TrimSpace(localDateStr) == "" || strings.TrimSpace(remoteDateStr) == "" {
		return false
	}
	localT, err1 := time.Parse(time.RFC3339, strings.TrimSpace(localDateStr))
	remoteT, err2 := time.Parse(time.RFC3339, strings.TrimSpace(remoteDateStr))
	if err1 != nil || err2 != nil {
		return false
	}
	return !remoteT.After(localT.Add(5 * time.Second))
}

func selectPlatformManifest(list []ociDescriptor, arch string) string {
	for _, m := range list {
		if m.Platform == nil {
			continue
		}
		if m.Annotations != nil && m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		if strings.EqualFold(m.Platform.OS, "linux") && strings.EqualFold(m.Platform.Architecture, arch) {
			return m.Digest
		}
	}
	for _, m := range list {
		if m.Platform == nil {
			continue
		}
		if m.Platform.Architecture != "" && !strings.EqualFold(m.Platform.Architecture, "unknown") {
			return m.Digest
		}
	}
	return ""
}

func (u *Updater) fetchRegistryToken(ctx context.Context, imagePath string) (string, error) {
	endpoint := fmt.Sprintf("%s/token?service=ghcr.io&scope=repository:%s:pull",
		u.registryBaseURL, url.QueryEscape(imagePath))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Token, nil
}

func (u *Updater) fetchRegistryManifest(ctx context.Context, imagePath, ref, token string) (ociManifestOrIndex, error) {
	endpoint := fmt.Sprintf("%s/v2/%s/manifests/%s", u.registryBaseURL, imagePath, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ociManifestOrIndex{}, err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return ociManifestOrIndex{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ociManifestOrIndex{}, fmt.Errorf("registry manifest HTTP %d", resp.StatusCode)
	}
	var out ociManifestOrIndex
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&out); err != nil {
		return ociManifestOrIndex{}, err
	}
	return out, nil
}

func (u *Updater) fetchRegistryConfigLabels(ctx context.Context, imagePath, digest, token string) (map[string]string, error) {
	endpoint := fmt.Sprintf("%s/v2/%s/blobs/%s", u.registryBaseURL, imagePath, digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry config blob HTTP %d", resp.StatusCode)
	}
	var blob ociImageConfigBlob
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&blob); err != nil {
		return nil, err
	}
	return blob.Config.Labels, nil
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
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return ghRelease{}, false, errors.New("limite temporaire de l'API GitHub atteinte : réessayez dans quelques minutes")
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

func (u *Updater) fetchLatestReadyMainBuild(ctx context.Context) (ready ghWorkflowRun, alreadyAhead bool, building bool, ok bool) {
	endpoint := fmt.Sprintf("%s/repos/%s/actions/runs?branch=main&event=push&per_page=10", u.apiBaseURL, u.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ghWorkflowRun{}, false, false, false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MeshWatch-Updater/1.0")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return ghWorkflowRun{}, false, false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ghWorkflowRun{}, false, false, false
	}

	var payload struct {
		WorkflowRuns []ghWorkflowRun `json:"workflow_runs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&payload); err != nil {
		return ghWorkflowRun{}, false, false, false
	}
	if len(payload.WorkflowRuns) == 0 {
		return ghWorkflowRun{}, false, false, false
	}

	newest := payload.WorkflowRuns[0]
	if (newest.Status == "queued" || newest.Status == "in_progress") &&
		!isSameCommit(u.currentCommit, newest.HeadSHA) {
		building = true
	}

	curIdx := -1
	readyIdx := -1
	for i, run := range payload.WorkflowRuns {
		if curIdx == -1 && isSameCommit(u.currentCommit, run.HeadSHA) {
			curIdx = i
		}
		if readyIdx == -1 && run.Status == "completed" && run.Conclusion == "success" && run.HeadSHA != "" {
			readyIdx = i
		}
	}
	if readyIdx >= 0 {
		if curIdx >= 0 && curIdx <= readyIdx {
			alreadyAhead = true
		}
		return payload.WorkflowRuns[readyIdx], alreadyAhead, building, true
	}
	return ghWorkflowRun{}, false, building, false
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

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return ghCommit{}, errors.New("limite temporaire de l'API GitHub atteinte : réessayez dans quelques minutes")
	}
	if resp.StatusCode != http.StatusOK {
		return ghCommit{}, fmt.Errorf("GitHub API commits HTTP %d", resp.StatusCode)
	}
	var c ghCommit
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&c); err != nil {
		return ghCommit{}, err
	}
	return c, nil
}

type selfContainerMeta struct {
	User         string
	GroupAdd     []string
	HostSockPath string
}

// ApplyDockerUpdate pulls the target Docker image and spawns an ephemeral helper container
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

	// 1. Inspect self container to mirror User, GroupAdd and host socket bind path into helper.
	meta := u.inspectSelfContainerMeta(ctx, client, baseURL, selfID)

	// 2. Pull target image before touching the running container.
	if err := dockerPullImage(ctx, client, baseURL, targetImage); err != nil {
		return fmt.Errorf("téléchargement de l'image %s échoué : %w", targetImage, err)
	}

	// Keep local :latest aligned best-effort when pulling a specific version/commit tag.
	repoBase, targetTag := splitImageRef(targetImage)
	if repoBase != "" && targetTag != "" && targetTag != "latest" {
		_ = dockerPost(ctx, client,
			fmt.Sprintf("%s/images/%s/tag?repo=%s&tag=latest", baseURL, url.PathEscape(targetImage), url.QueryEscape(repoBase)),
			nil, []int{201})
	}

	// 3. Spawn a short-lived helper container from the NEW image to swap the running container.
	sockMount := "/var/run/docker.sock"
	if meta.HostSockPath != "" {
		sockMount = meta.HostSockPath
	} else if !isNetworkDockerSocket(u.dockerSocket) {
		sockMount = strings.TrimPrefix(u.dockerSocket, "unix://")
	}

	helperSocketArg := u.dockerSocket
	hostConfig := map[string]any{
		"AutoRemove": true,
	}
	if !isNetworkDockerSocket(u.dockerSocket) {
		helperSocketArg = "/var/run/docker.sock"
		hostConfig["Binds"] = []string{sockMount + ":/var/run/docker.sock"}
	}
	if len(meta.GroupAdd) > 0 {
		hostConfig["GroupAdd"] = meta.GroupAdd
	}

	helperBody := map[string]any{
		"Image": targetImage,
		"Cmd": []string{
			"self-update",
			"--container", selfID,
			"--image", targetImage,
			"--socket", helperSocketArg,
		},
		"HostConfig": hostConfig,
	}
	if strings.TrimSpace(meta.User) != "" {
		helperBody["User"] = meta.User
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
// all mounts/ports/env/networks cleanly, starts it, verifies health, and rolls back on failure.
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

	fullID, _ := inspect["Id"].(string)
	rawName, _ := inspect["Name"].(string)
	origName := strings.TrimPrefix(rawName, "/")
	if origName == "" {
		origName = "meshwatch-agent"
	}
	backupName := fmt.Sprintf("%s-backup-%d", origName, time.Now().Unix())

	cfgObj, _ := inspect["Config"].(map[string]any)
	hostCfgObj, _ := inspect["HostConfig"].(map[string]any)
	netSettings, _ := inspect["NetworkSettings"].(map[string]any)

	origHostname := ""
	if cfgObj == nil {
		cfgObj = map[string]any{}
	} else {
		origHostname, _ = cfgObj["Hostname"].(string)
	}
	cfgObj["Image"] = newImage
	delete(cfgObj, "Hostname")
	delete(cfgObj, "Domainname")

	createPayload := map[string]any{}
	for k, v := range cfgObj {
		createPayload[k] = v
	}
	networkMode := ""
	if hostCfgObj != nil {
		createPayload["HostConfig"] = hostCfgObj
		networkMode, _ = hostCfgObj["NetworkMode"].(string)
	}

	primaryNet, primaryEndpoint, extraNets := buildCleanNetworkEndpoints(netSettings, networkMode, targetContainer, fullID, origHostname)
	if primaryNet != "" {
		createPayload["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": map[string]any{
				primaryNet: primaryEndpoint,
			},
		}
	}

	// Brief pause so the UI receives HTTP 202 before the old container stops.
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

	deleteFailedContainer := func(id string) {
		delReq, _ := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/containers/"+url.PathEscape(id)+"?force=true", nil)
		if delReq != nil {
			if r, e := client.Do(delReq); e == nil {
				_ = r.Body.Close()
			}
		}
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

	// 5. Connect any extra networks (Docker create accepts a single endpoint cleanly).
	for _, netConn := range extraNets {
		connectPayload, _ := json.Marshal(map[string]any{
			"Container":      created.ID,
			"EndpointConfig": netConn.endpoint,
		})
		if err := dockerPostJSON(ctx, client, baseURL+"/networks/"+url.PathEscape(netConn.name)+"/connect", connectPayload, []int{200, 204}); err != nil {
			deleteFailedContainer(created.ID)
			return rollback(fmt.Errorf("connect network %s: %w", netConn.name, err))
		}
	}

	// 6. Start the new container.
	if err := dockerPost(ctx, client, baseURL+"/containers/"+url.PathEscape(created.ID)+"/start", nil, []int{204, 304}); err != nil {
		deleteFailedContainer(created.ID)
		return rollback(fmt.Errorf("start updated container: %w", err))
	}

	// 7. Verify the new container stays healthy/running before removing backup.
	if err := verifyContainerRunning(ctx, client, baseURL, created.ID); err != nil {
		deleteFailedContainer(created.ID)
		return rollback(fmt.Errorf("new container failed startup check: %w", err))
	}

	// 8. Remove backup container now that the updated container is verified running.
	delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/containers/"+url.PathEscape(targetContainer), nil)
	if err == nil {
		if r, e := client.Do(delReq); e == nil {
			_ = r.Body.Close()
		}
	}

	return nil
}

type networkEndpoint struct {
	name     string
	endpoint map[string]any
}

func buildCleanNetworkEndpoints(netSettings map[string]any, networkMode, targetID, fullID, origHostname string) (string, map[string]any, []networkEndpoint) {
	mode := strings.ToLower(strings.TrimSpace(networkMode))
	if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") {
		return "", nil, nil
	}
	if netSettings == nil {
		return "", nil, nil
	}
	nets, ok := netSettings["Networks"].(map[string]any)
	if !ok || len(nets) == 0 {
		return "", nil, nil
	}

	names := make([]string, 0, len(nets))
	for name := range nets {
		names = append(names, name)
	}
	sort.Strings(names)

	var (
		primaryName string
		primaryEP   map[string]any
		extras      []networkEndpoint
	)
	for _, netName := range names {
		nv, ok := nets[netName].(map[string]any)
		if !ok {
			continue
		}
		ep := map[string]any{}
		if rawAliases, ok := nv["Aliases"].([]any); ok {
			cleaned := filterStaleAliases(rawAliases, targetID, fullID, origHostname)
			if len(cleaned) > 0 {
				ep["Aliases"] = cleaned
			}
		}
		if primaryName == "" {
			primaryName = netName
			primaryEP = ep
		} else {
			extras = append(extras, networkEndpoint{name: netName, endpoint: ep})
		}
	}
	return primaryName, primaryEP, extras
}

func filterStaleAliases(raw []any, targetID, fullID, origHostname string) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		alias, ok := item.(string)
		if !ok {
			continue
		}
		a := strings.TrimSpace(alias)
		if a == "" {
			continue
		}
		if a == origHostname || a == targetID || a == fullID {
			continue
		}
		if len(a) >= 12 && isHexString(a) {
			if (len(fullID) >= len(a) && strings.HasPrefix(fullID, a)) ||
				(len(targetID) >= len(a) && strings.HasPrefix(targetID, a)) {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func verifyContainerRunning(ctx context.Context, client *http.Client, baseURL, containerID string) error {
	deadline := time.Now().Add(3 * time.Second)
	for attempt := 0; attempt < 6; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(containerID)+"/json", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		var state struct {
			State struct {
				Running    bool   `json:"Running"`
				Restarting bool   `json:"Restarting"`
				Status     string `json:"Status"`
				ExitCode   int    `json:"ExitCode"`
				Error      string `json:"Error"`
			} `json:"State"`
		}
		decErr := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&state)
		_ = resp.Body.Close()
		if decErr != nil {
			return decErr
		}
		if !state.State.Running || state.State.Restarting {
			detail := state.State.Error
			if detail == "" {
				detail = fmt.Sprintf("status=%s exit=%d restarting=%v", state.State.Status, state.State.ExitCode, state.State.Restarting)
			}
			return errors.New(detail)
		}
		if attempt >= 2 || time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

func (u *Updater) detectSelfContainerID(ctx context.Context) (string, error) {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return "", errors.New("mise à jour automatique disponible uniquement dans Docker")
	}

	var candidates []string
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		candidates = append(candidates, strings.TrimSpace(host))
	}
	candidates = append(candidates, detectContainerIDsFromProc()...)
	if len(candidates) == 0 {
		return "", errors.New("impossible d'identifier le conteneur courant")
	}

	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client, baseURL := newDockerHTTPClient(u.dockerSocket, 3*time.Second)

	var lastErr error
	for _, cand := range candidates {
		req, err := http.NewRequestWithContext(dctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(cand)+"/json", nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(strings.ToLower(errMsg), "permission denied") {
				return "", fmt.Errorf("accès au socket Docker refusé (%s) : vérifiez group_add dans docker-compose.yml", u.dockerSocket)
			}
			if errors.Is(err, os.ErrNotExist) || strings.Contains(strings.ToLower(errMsg), "no such file") {
				return "", fmt.Errorf("socket Docker introuvable (%s)", u.dockerSocket)
			}
			return "", fmt.Errorf("socket Docker inaccessible (%s) : %w", u.dockerSocket, err)
		}
		var info struct {
			ID string `json:"Id"`
		}
		code := resp.StatusCode
		decErr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info)
		_ = resp.Body.Close()

		if code == http.StatusOK && decErr == nil && info.ID != "" {
			return info.ID, nil
		}
		lastErr = fmt.Errorf("conteneur courant introuvable sur Docker (HTTP %d)", code)
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("conteneur courant introuvable sur Docker")
}

func detectContainerIDsFromProc() []string {
	mountinfo, _ := os.ReadFile("/proc/self/mountinfo")
	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	return extractContainerIDsFromProc(string(mountinfo), string(cgroup))
}

func extractContainerIDsFromProc(mountinfo, cgroup string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(id string) {
		if len(id) == 64 && isHexString(id) && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}

	// Highest confidence: Docker container bind-mounts (/containers/<64-hex>/hosts|resolv.conf|hostname).
	for _, line := range strings.Split(mountinfo, "\n") {
		if idx := strings.Index(line, "/containers/"); idx >= 0 {
			rest := line[idx+len("/containers/"):]
			if id, _, ok := strings.Cut(rest, "/"); ok {
				add(id)
			}
		}
	}

	// Secondary: cgroup path (/docker/<64-hex> or docker-<64-hex>.scope).
	for _, field := range strings.FieldsFunc(cgroup, func(r rune) bool {
		return r == '/' || r == ':' || r == '-' || r == '.' || r == ' ' || r == '\t' || r == '\n'
	}) {
		add(field)
	}
	return out
}

func (u *Updater) inspectSelfContainerMeta(ctx context.Context, client *http.Client, baseURL, selfID string) selfContainerMeta {
	var meta selfContainerMeta
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/containers/"+url.PathEscape(selfID)+"/json", nil)
	if err != nil {
		return meta
	}
	resp, err := client.Do(req)
	if err != nil {
		return meta
	}
	defer resp.Body.Close()

	var info struct {
		Config struct {
			User string `json:"User"`
		} `json:"Config"`
		HostConfig struct {
			GroupAdd []string `json:"GroupAdd"`
		} `json:"HostConfig"`
		Mounts []struct {
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&info); err != nil {
		return meta
	}
	meta.User = info.Config.User
	meta.GroupAdd = info.HostConfig.GroupAdd

	sockDest := strings.TrimPrefix(u.dockerSocket, "unix://")
	for _, m := range info.Mounts {
		if m.Destination == sockDest && m.Source != "" {
			meta.HostSockPath = m.Source
			break
		}
	}
	return meta
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

	// Docker Engine reports registry/auth/pull errors inside JSON-lines even on HTTP 200.
	dec := json.NewDecoder(resp.Body)
	for {
		var event struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("lecture du flux Docker pull : %w", err)
		}
		if msg := strings.TrimSpace(event.ErrorDetail.Message); msg != "" {
			return errors.New(msg)
		}
		if msg := strings.TrimSpace(event.Error); msg != "" {
			return errors.New(msg)
		}
	}
	return nil
}

func dockerPost(ctx context.Context, client *http.Client, endpoint string, body io.Reader, allowed []int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	return doAllowedPost(client, req, allowed)
}

func dockerPostJSON(ctx context.Context, client *http.Client, endpoint string, rawJSON []byte, allowed []int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doAllowedPost(client, req, allowed)
}

func doAllowedPost(client *http.Client, req *http.Request, allowed []int) error {
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

func isNetworkDockerSocket(socket string) bool {
	s := strings.TrimSpace(socket)
	return strings.HasPrefix(s, "tcp://") || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
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

func stripRegistryHost(repo string) string {
	parts := strings.SplitN(strings.TrimSpace(repo), "/", 2)
	if len(parts) == 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		return parts[1]
	}
	return strings.TrimSpace(repo)
}

func shortCommit(sha string) string {
	s := strings.TrimSpace(sha)
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func isSameCommit(current, remote string) bool {
	c := strings.TrimSpace(current)
	r := strings.TrimSpace(remote)
	if c == "" || r == "" || c == "dev" || c == "none" {
		return false
	}
	return strings.HasPrefix(r, c) || strings.HasPrefix(c, r)
}

func isDifferentReleaseCommit(current, remote string) bool {
	c := strings.TrimSpace(current)
	r := strings.TrimSpace(remote)
	if c == "" || c == "dev" || c == "none" || r == "" {
		return false
	}
	return !isSameCommit(c, r)
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
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
