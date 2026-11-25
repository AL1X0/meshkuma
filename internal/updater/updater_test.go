package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// Same version must report UpdateAvailable=false
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

	// Already on the last completed CI build (1111111), while 9999999 is still building:
	// must NOT tell user to click update yet, must report Building=true!
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

	// On an older build (0000000): must target the exact completed CI tag main-1111111.
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
}

func TestRunSelfUpdateHelperSuccess(t *testing.T) {
	var steps []string
	dockerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/containers/old-id/json":
			steps = append(steps, "inspect")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Name": "/meshwatch-agent",
				"Config": map[string]any{
					"Image": "ghcr.io/al1x0/meshkuma:old",
					"Env":   []string{"MESHWATCH_UI_ADDR=0.0.0.0:8080"},
				},
				"HostConfig": map[string]any{"ReadonlyRootfs": true},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/old-id/stop":
			steps = append(steps, "stop")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/old-id/rename":
			steps = append(steps, "rename")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			steps = append(steps, "create")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["Image"] != "ghcr.io/al1x0/meshkuma:latest" {
				t.Errorf("unexpected Image in create: %v", body["Image"])
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "new-id"})
		case r.Method == http.MethodPost && r.URL.Path == "/containers/new-id/start":
			steps = append(steps, "start-new")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/containers/old-id":
			steps = append(steps, "delete-old")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer dockerMock.Close()

	if err := RunSelfUpdateHelper(context.Background(), dockerMock.URL, "old-id", "ghcr.io/al1x0/meshkuma:latest"); err != nil {
		t.Fatalf("RunSelfUpdateHelper error = %v", err)
	}
	got := strings.Join(steps, "->")
	want := "inspect->stop->rename->create->start-new->delete-old"
	if got != want {
		t.Fatalf("steps = %q, want %q", got, want)
	}
}
