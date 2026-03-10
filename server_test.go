package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspacePreferencesPersistDefaultLanding(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	root := filepath.Join(t.TempDir(), "prefs")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	workspace, err := openWorkspace(root, []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if err := workspace.setDefaultLanding("hosts"); err != nil {
		t.Fatalf("setDefaultLanding() error = %v", err)
	}

	reloaded, err := openWorkspace(root, nil, logger)
	if err != nil {
		t.Fatalf("re-open workspace error = %v", err)
	}
	if got := reloaded.preferences().DefaultLanding; got != "hosts" {
		t.Fatalf("DefaultLanding = %q, want hosts", got)
	}
}

func TestRootRedirectHonorsDefaultLanding(t *testing.T) {
	app := newTestApplication(t, true)
	if err := app.workspace.setDefaultLanding("hosts"); err != nil {
		t.Fatalf("setDefaultLanding() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if location := recorder.Header().Get("Location"); location != "/hosts" {
		t.Fatalf("Location = %q, want /hosts", location)
	}
}

func TestRootRedirectsEmptyWorkspaceToWorkspacePage(t *testing.T) {
	app := newTestApplication(t, false)
	if err := app.workspace.setDefaultLanding("hosts"); err != nil {
		t.Fatalf("setDefaultLanding() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if location := recorder.Header().Get("Location"); location != "/workspace" {
		t.Fatalf("Location = %q, want /workspace", location)
	}
}

func TestLegacyAliasesRedirectToCanonicalRoutes(t *testing.T) {
	app := newTestApplication(t, true)
	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	tests := []struct {
		path string
		want string
	}{
		{path: "/ip/10.0.0.9?scan=test", want: "/hosts/10.0.0.9?scan=test"},
		{path: "/graph", want: "/topology"},
	}

	for _, test := range tests {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if location := recorder.Header().Get("Location"); location != test.want {
			t.Fatalf("redirect for %s = %q, want %q", test.path, location, test.want)
		}
	}
}

func TestExplorerJSONReturnsScanHosts(t *testing.T) {
	app := newTestApplication(t, true)
	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	scans := app.workspace.scanCatalog()
	if len(scans) == 0 {
		t.Fatal("scanCatalog() returned no scans")
	}

	request := httptest.NewRequest(http.MethodGet, "/api/explorer?kind=scan&id="+scans[0].ID, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var nodes []ExplorerNodeView
	if err := json.Unmarshal(recorder.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode explorer json error = %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("explorer returned no host nodes")
	}
	if nodes[0].Kind != "scan-host" {
		t.Fatalf("first node kind = %q, want scan-host", nodes[0].Kind)
	}
	if !strings.Contains(nodes[0].Href, "/hosts/") {
		t.Fatalf("first node href = %q, want host detail path", nodes[0].Href)
	}
}

func newTestApplication(t *testing.T, withSeed bool) *application {
	t.Helper()

	root := filepath.Join(t.TempDir(), "workspace")
	seedFiles := []string(nil)
	if withSeed {
		seedFiles = []string{writeSnapshotFixture(t)}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := newApplication(seedFiles, root, logger)
	if err != nil {
		t.Fatalf("newApplication() error = %v", err)
	}
	return app
}
