package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestCheckDetectsNewerRelease(t *testing.T) {
	ghMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/AL1X0/meshkuma/releases/latest" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v1.2.0",
				"name":     "MeshWatch v1.2.0",
				"body":     "Découverte réseau locale et interface simplifiée",
				"html_url": "https://github.com/AL1X0/meshkuma/releases/tag/v1.2.0",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ghMock.Close()

	u := New(Config{
		Repo:       "AL1X0/meshkuma",
		APIBaseURL: ghMock.URL,
		CurrentVer: "v1.0.0",
	})

	res, err := u.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !res.UpdateAvailable || res.LatestVersion != "v1.2.0" {
		t.Fatalf("expected UpdateAvailable=true for v1.2.0, got %+v", res)
	}

	uSame := New(Config{
		Repo:       "AL1X0/meshkuma",
		APIBaseURL: ghMock.URL,
		CurrentVer: "v1.2.0",
	})
	resSame, err := uSame.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check(same) error = %v", err)
	}
	if resSame.UpdateAvailable {
		t.Fatalf("expected UpdateAvailable=false when already on v1.2.0, got %+v", resSame)
	}
}

func TestCheckFallbackToMainCommit(t *testing.T) {
	ghMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/AL1X0/meshkuma/releases/latest":
			http.NotFound(w, r)
		case "/repos/AL1X0/meshkuma/commits/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha":      "abcdef1234567890",
				"html_url": "https://github.com/AL1X0/meshkuma/commit/abcdef1234567890",
				"commit":   map[string]any{"message": "feat: cooler UI"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghMock.Close()

	u := New(Config{
		Repo:          "AL1X0/meshkuma",
		APIBaseURL:    ghMock.URL,
		CurrentVer:    "v1.0.0",
		CurrentCommit: "1111111",
	})

	res, err := u.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !res.UpdateAvailable || res.LatestCommit != "abcdef1" {
		t.Fatalf("expected commit update detected, got %+v", res)
	}
}

func TestCheckWaitsForSuccessfulCIBuild(t *testing.T) {
	ghMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/AL1X0/meshkuma/releases/latest":
			http.NotFound(w, r)
		case "/repos/AL1X0/meshkuma/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workflow_runs": []map[string]any{
					{
						"head_sha":    "9999999abcdef0000",
						"status":      "in_progress",
						"conclusion":  "",
						"event":       "push",
						"head_commit": map[string]any{"message": "feat: still compiling"},
					},
					{
						"head_sha":    "1111111abcdef0000",
						"status":      "completed",
						"conclusion":  "success",
						"event":       "push",
						"head_commit": map[string]any{"message": "feat: ready build"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghMock.Close()

	u := New(Config{
		Repo:          "AL1X0/meshkuma",
		APIBaseURL:    ghMock.URL,
		CurrentVer:    "main-1111111",
		CurrentCommit: "1111111",
	})
	res, err := u.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if res.UpdateAvailable {
		t.Fatalf("must not advertise incomplete CI build as ready, got %+v", res)
	}
	if !res.Building {
		t.Fatalf("expected Building=true while newer CI run is in_progress, got %+v", res)
	}

	uOld := New(Config{
		Repo:          "AL1X0/meshkuma",
		APIBaseURL:    ghMock.URL,
		CurrentVer:    "main-0000000",
		CurrentCommit: "0000000",
	})
	resOld, err := uOld.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check(old) error = %v", err)
	}
	if !resOld.UpdateAvailable || resOld.Image != "ghcr.io/al1x0/meshkuma:main-1111111" {
		t.Fatalf("expected UpdateAvailable=true with exact tag main-1111111, got %+v", resOld)
	}

	uAhead := New(Config{
		Repo:          "AL1X0/meshkuma",
		APIBaseURL:    ghMock.URL,
		CurrentVer:    "main-9999999",
		CurrentCommit: "9999999",
	})
	resAhead, err := uAhead.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("Check(ahead) error = %v", err)
	}
	if resAhead.UpdateAvailable || resAhead.Building {
		t.Fatalf("must not downgrade or mark building when already on newest commit, got %+v", resAhead)
	}
}

func TestCheckGHCRIndexAndLabels(t *testing.T) {
	arch := runtime.GOARCH
	var githubCalls int

	ghMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		githubCalls++
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer ghMock.Close()

	ghcrMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "anon-tok"})
		case "/v2/al1x0/meshkuma/manifests/latest":
			if got := r.Header.Get("Authorization"); got != "Bearer anon-tok" {
				t.Errorf("missing Bearer token, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{
					{
						"digest": "sha256:attestation000",
						"annotations": map[string]string{
							"vnd.docker.reference.type": "attestation-manifest",
						},
						"platform": map[string]string{"os": "unknown", "architecture": "unknown"},
					},
					{
						"digest":   "sha256:platmanifest123",
						"platform": map[string]string{"os": "linux", "architecture": arch},
					},
				},
			})
		case "/v2/al1x0/meshkuma/manifests/sha256:platmanifest123":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2,
				"config":        map[string]string{"digest": "sha256:cfgblob456"},
			})
		case "/v2/al1x0/meshkuma/blobs/sha256:cfgblob456":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"config": map[string]any{
					"Labels": map[string]string{
						"org.opencontainers.image.revision": "cafe1234567890",
						"org.opencontainers.image.version":  "main-cafe123",
						"org.opencontainers.image.title":    "feat: instant self-update",
						"org.opencontainers.image.created":  "2026-11-25T12:00:00Z",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghcrMock.Close()

	// Older container sees available GHCR update without touching rate-limited GitHub REST API.
	u := New(Config{
		Repo:             "AL1X0/meshkuma",
		Image:            "ghcr.io/al1x0/meshkuma:latest",
		APIBaseURL:       ghMock.URL,
		RegistryBaseURL:  ghcrMock.URL,
		CurrentVer:       "main-1111111",
		CurrentCommit:    "1111111",
		CurrentBuildDate: "2026-11-24T12:00:00Z",
	})
	res, err := u.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("GHCR Check() error = %v", err)
	}
	if githubCalls != 0 {
		t.Fatalf("expected 0 GitHub API calls when GHCR succeeds, got %d", githubCalls)
	}
	if !res.UpdateAvailable || res.Source != "ghcr" || res.LatestCommit != "cafe123" || res.Image != "ghcr.io/al1x0/meshkuma:main-cafe123" {
		t.Fatalf("unexpected GHCR result: %+v", res)
	}

	// Same commit must report up-to-date.
	uSame := New(Config{
		Repo:             "AL1X0/meshkuma",
		APIBaseURL:       ghMock.URL,
		RegistryBaseURL:  ghcrMock.URL,
		CurrentVer:       "main-cafe123",
		CurrentCommit:    "cafe123",
		CurrentBuildDate: "2026-11-25T12:00:00Z",
	})
	resSame, err := uSame.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("GHCR Check(same) error = %v", err)
	}
	if resSame.UpdateAvailable {
		t.Fatalf("expected UpdateAvailable=false on matching commit, got %+v", resSame)
	}

	// Newer local build timestamp must never offer downgrade to older GHCR build.
	uAhead := New(Config{
		Repo:             "AL1X0/meshkuma",
		APIBaseURL:       ghMock.URL,
		RegistryBaseURL:  ghcrMock.URL,
		CurrentVer:       "main-deadbeef",
		CurrentCommit:    "deadbeef",
		CurrentBuildDate: "2026-11-26T12:00:00Z",
	})
	resAhead, err := uAhead.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("GHCR Check(ahead) error = %v", err)
	}
	if resAhead.UpdateAvailable {
		t.Fatalf("expected UpdateAvailable=false when local build date is newer, got %+v", resAhead)
	}
}

func TestDockerPullImageDetectsStreamError(t *testing.T) {
	dockerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\":\"Pulling from al1x0/meshkuma\"}\n{\"errorDetail\":{\"message\":\"manifest for ghcr.io/al1x0/meshkuma:bad not found\"},\"error\":\"manifest unknown\"}\n"))
	}))
	defer dockerMock.Close()

	err := dockerPullImage(context.Background(), dockerMock.Client(), dockerMock.URL, "ghcr.io/al1x0/meshkuma:bad")
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected stream error to be surfaced, got %v", err)
	}
}

func TestRunSelfUpdateHelperMultiNetworkAndAliasCleanup(t *testing.T) {
	var steps []string
	var createPayload map[string]any
	var connectedBody map[string]any

	dockerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/containers/0123456789abcdef/json":
			steps = append(steps, "inspect")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"Name": "/meshwatch-agent",
				"Config": map[string]any{
					"Image":    "ghcr.io/al1x0/meshkuma:old",
					"Hostname": "0123456789ab",
					"Env":      []string{"MESHWATCH_UI_ADDR=0.0.0.0:8080"},
				},
				"HostConfig": map[string]any{"ReadonlyRootfs": true},
				"NetworkSettings": map[string]any{
					"Networks": map[string]any{
						"net-a": map[string]any{"Aliases": []string{"meshwatch-agent", "0123456789ab"}},
						"net-b": map[string]any{"Aliases": []string{"meshwatch-b", "0123456789abcdef"}},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/0123456789abcdef/stop":
			steps = append(steps, "stop")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/0123456789abcdef/rename":
			steps = append(steps, "rename")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			steps = append(steps, "create")
			_ = json.NewDecoder(r.Body).Decode(&createPayload)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "new-id"})
		case r.Method == http.MethodPost && r.URL.Path == "/networks/net-b/connect":
			steps = append(steps, "connect-b")
			_ = json.NewDecoder(r.Body).Decode(&connectedBody)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/new-id/start":
			steps = append(steps, "start-new")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/containers/new-id/json":
			steps = append(steps, "verify")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"State": map[string]any{"Running": true, "Restarting": false},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/containers/0123456789abcdef":
			steps = append(steps, "delete-old")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerMock.Close()

	if err := RunSelfUpdateHelper(context.Background(), dockerMock.URL, "0123456789abcdef", "ghcr.io/al1x0/meshkuma:latest"); err != nil {
		t.Fatalf("RunSelfUpdateHelper error = %v", err)
	}
	if _, hasHostname := createPayload["Hostname"]; hasHostname {
		t.Fatalf("expected Hostname stripped from create payload")
	}
	nc, _ := createPayload["NetworkingConfig"].(map[string]any)
	eps, _ := nc["EndpointsConfig"].(map[string]any)
	if len(eps) != 1 || eps["net-a"] == nil {
		t.Fatalf("expected only primary network net-a in create EndpointsConfig, got %+v", eps)
	}
	netAAliases := eps["net-a"].(map[string]any)["Aliases"].([]any)
	if len(netAAliases) != 1 || netAAliases[0] != "meshwatch-agent" {
		t.Fatalf("expected stale short ID alias stripped, got %+v", netAAliases)
	}
	if connectedBody["Container"] != "new-id" {
		t.Fatalf("expected extra network connect for new-id, got %+v", connectedBody)
	}
	got := strings.Join(steps, "->")
	if !strings.HasPrefix(got, "inspect->stop->rename->create->connect-b->start-new->verify") || !strings.HasSuffix(got, "->delete-old") {
		t.Fatalf("unexpected steps sequence: %q", got)
	}
}

func TestRunSelfUpdateHelperRollbackOnImmediateCrash(t *testing.T) {
	var steps []string
	dockerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/containers/old-id/json":
			steps = append(steps, "inspect")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":   "old-id-full",
				"Name": "/meshwatch-agent",
				"Config": map[string]any{
					"Image": "ghcr.io/al1x0/meshkuma:old",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/old-id/stop":
			steps = append(steps, "stop")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/old-id/rename":
			steps = append(steps, "rename:"+r.URL.Query().Get("name"))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			steps = append(steps, "create")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "new-id"})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/new-id/start":
			steps = append(steps, "start-new")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/containers/new-id/json":
			steps = append(steps, "verify-crashed")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"State": map[string]any{"Running": false, "Status": "exited", "ExitCode": 1},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/containers/new-id":
			steps = append(steps, "delete-failed-new")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/old-id/start":
			steps = append(steps, "rollback-start-old")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Docker request during rollback: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerMock.Close()

	err := RunSelfUpdateHelper(context.Background(), dockerMock.URL, "old-id", "ghcr.io/al1x0/meshkuma:broken")
	if err == nil || !strings.Contains(err.Error(), "startup check") {
		t.Fatalf("expected startup check error on crashed container, got %v", err)
	}
	joined := strings.Join(steps, "->")
	if !strings.Contains(joined, "delete-failed-new->rename:meshwatch-agent->rollback-start-old") {
		t.Fatalf("expected automatic rollback sequence, got %q", joined)
	}
}
