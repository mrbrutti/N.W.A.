package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakePlugin struct {
	id    string
	label string
}

func (p fakePlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:          p.id,
		Label:       p.label,
		Description: "test plugin",
		Mode:        "Managed command",
		Family:      "test",
	}
}

func (p fakePlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	if request.Progress != nil {
		request.Progress("test run completed")
	}
	return PluginRunResult{Summary: p.label + " completed"}, nil
}

func installFakeTool(t *testing.T, dir string, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake tool %s: %v", name, err)
	}
}

func readSSEEvent(reader *bufio.Reader) (string, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "event: ") {
			eventType := strings.TrimSpace(strings.TrimPrefix(trimmed, "event: "))
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return "", err
				}
				if strings.TrimSpace(line) == "" {
					return eventType, nil
				}
			}
		}
	}
}

func TestServiceModeRootRedirectsToLogin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
}

func TestPlatformLoginAndEngagementCreationFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	loginResponse, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	})
	if err != nil {
		t.Fatalf("login request error = %v", err)
	}
	if loginResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want %d", loginResponse.StatusCode, http.StatusSeeOther)
	}

	createResponse, err := client.PostForm(server.URL+"/admin/engagements", url.Values{
		"name":        {"Acme External"},
		"description": {"test"},
		"scope":       {"198.51.100.0/24"},
	})
	if err != nil {
		t.Fatalf("create engagement error = %v", err)
	}
	if createResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want %d", createResponse.StatusCode, http.StatusSeeOther)
	}
	location := createResponse.Header.Get("Location")
	if !strings.HasPrefix(location, "/engagements/acme-external") {
		t.Fatalf("Location = %q, want engagement route", location)
	}

	pageResponse, err := client.Get(server.URL + location)
	if err != nil {
		t.Fatalf("engagement page error = %v", err)
	}
	if pageResponse.StatusCode != http.StatusOK {
		t.Fatalf("engagement page status = %d, want %d", pageResponse.StatusCode, http.StatusOK)
	}
}

func TestPlatformSessionJSONFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{Jar: jar}

	response, err := client.Get(server.URL + "/api/v1/session")
	if err != nil {
		t.Fatalf("GET session error = %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET session status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var anonymous platformSessionPayload
	if err := json.NewDecoder(response.Body).Decode(&anonymous); err != nil {
		t.Fatalf("decode anonymous session error = %v", err)
	}
	if anonymous.Authenticated {
		t.Fatal("anonymous session unexpectedly authenticated")
	}

	requestBody := bytes.NewBufferString(`{"login":"admin","password":"adminpass"}`)
	loginResponse, err := client.Post(server.URL+"/api/v1/session/login", "application/json", requestBody)
	if err != nil {
		t.Fatalf("POST session login error = %v", err)
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("POST session login status = %d, want %d", loginResponse.StatusCode, http.StatusOK)
	}
	var session platformSessionPayload
	if err := json.NewDecoder(loginResponse.Body).Decode(&session); err != nil {
		t.Fatalf("decode login session error = %v", err)
	}
	if !session.Authenticated || session.User == nil {
		t.Fatalf("session = %+v, want authenticated user payload", session)
	}
	if session.RedirectTo != "/app/admin" {
		t.Fatalf("RedirectTo = %q, want /app/admin", session.RedirectTo)
	}

	engagementResponse, err := client.Get(server.URL + "/api/v1/engagements")
	if err != nil {
		t.Fatalf("GET engagements error = %v", err)
	}
	defer engagementResponse.Body.Close()
	if engagementResponse.StatusCode != http.StatusOK {
		t.Fatalf("GET engagements status = %d, want %d", engagementResponse.StatusCode, http.StatusOK)
	}
	var engagements PlatformListResponse[PlatformEngagementView]
	if err := json.NewDecoder(engagementResponse.Body).Decode(&engagements); err != nil {
		t.Fatalf("decode engagements error = %v", err)
	}
	if len(engagements.Items) == 0 {
		t.Fatal("expected at least one engagement view after bootstrap")
	}
}

func TestPlatformEngagementJSONResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	}); err != nil {
		t.Fatalf("login request error = %v", err)
	}
	if _, err := client.PostForm(server.URL+"/admin/engagements", url.Values{
		"name":        {"Acme Internal"},
		"description": {"test"},
		"scope":       {"198.51.100.0/24\ncorp.example.com"},
	}); err != nil {
		t.Fatalf("create engagement error = %v", err)
	}

	checkJSON := func(path string) any {
		t.Helper()
		response, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s error = %v", path, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d", path, response.StatusCode, http.StatusOK)
		}
		var payload any
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			t.Fatalf("decode %s error = %v", path, err)
		}
		return payload
	}

	for _, path := range []string{
		"/api/v1/admin/overview",
		"/api/v1/admin/users",
		"/api/v1/admin/engagements",
		"/api/v1/admin/workers",
		"/api/v1/admin/connectors",
		"/api/v1/admin/audit",
		"/api/v1/admin/tools",
		"/api/v1/engagements/acme-internal",
		"/api/v1/engagements/acme-internal/summary",
		"/api/v1/engagements/acme-internal/scope",
		"/api/v1/engagements/acme-internal/zones",
		"/api/v1/engagements/acme-internal/sources",
		"/api/v1/engagements/acme-internal/runs",
		"/api/v1/engagements/acme-internal/campaigns",
		"/api/v1/engagements/acme-internal/hosts",
		"/api/v1/engagements/acme-internal/ports",
		"/api/v1/engagements/acme-internal/findings",
		"/api/v1/engagements/acme-internal/topology",
		"/api/v1/engagements/acme-internal/recommendations",
		"/api/v1/engagements/acme-internal/settings",
	} {
		_ = checkJSON(path)
	}

	eventResponse, err := client.Get(server.URL + "/api/v1/engagements/acme-internal/events")
	if err != nil {
		t.Fatalf("GET events error = %v", err)
	}
	defer eventResponse.Body.Close()
	if contentType := eventResponse.Header.Get("Content-Type"); !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("events content type = %q, want text/event-stream", contentType)
	}
	reader := bufio.NewReader(eventResponse.Body)
	eventType, err := readSSEEvent(reader)
	if err != nil {
		t.Fatalf("readSSEEvent() error = %v", err)
	}
	if eventType != "engagement.snapshot" {
		t.Fatalf("event type = %q, want engagement.snapshot", eventType)
	}
}

func TestPlatformEngagementEventsPushOnJobUpdates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	loginResponse, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	})
	if err != nil {
		t.Fatalf("login request error = %v", err)
	}
	_ = loginResponse.Body.Close()

	workspace := app.workspace
	engagement, err := app.platform.store.engagementByWorkspaceID(workspace.id)
	if err != nil {
		t.Fatalf("engagementByWorkspaceID() error = %v", err)
	}
	workspace.plugins.mu.Lock()
	workspace.plugins.plugins["fake-manual"] = fakePlugin{id: "fake-manual", label: "Fake Manual"}
	workspace.plugins.mu.Unlock()

	eventResponse, err := client.Get(server.URL + "/api/v1/engagements/" + engagement.Slug + "/events")
	if err != nil {
		t.Fatalf("GET events error = %v", err)
	}
	defer eventResponse.Body.Close()

	reader := bufio.NewReader(eventResponse.Body)
	if _, err := readSSEEvent(reader); err != nil {
		t.Fatalf("initial readSSEEvent() error = %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := readSSEEvent(reader)
		result <- err
	}()

	if _, err := workspace.plugins.submitDetailed(pluginSubmission{
		PluginID:   "fake-manual",
		RawTargets: []string{"198.51.100.25"},
		Summary:    "Manual follow-up",
	}); err != nil {
		t.Fatalf("submitDetailed() error = %v", err)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("second readSSEEvent() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected job update to trigger SSE event without polling delay")
	}
}

func TestPlatformEngagementCreationSurvivesBlockedKickoff(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	t.Setenv("PATH", t.TempDir())
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	}); err != nil {
		t.Fatalf("login request error = %v", err)
	}

	createResponse, err := client.PostForm(server.URL+"/admin/engagements", url.Values{
		"name":        {"Acme Degraded"},
		"description": {"test"},
		"scope":       {"203.0.113.0/24\ncorp.example.com"},
	})
	if err != nil {
		t.Fatalf("create engagement error = %v", err)
	}
	if createResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want %d", createResponse.StatusCode, http.StatusSeeOther)
	}
	location := createResponse.Header.Get("Location")
	if !strings.HasPrefix(location, "/engagements/acme-degraded") {
		t.Fatalf("Location = %q, want engagement route", location)
	}

	pageResponse, err := client.Get(server.URL + "/engagements/acme-degraded/scope")
	if err != nil {
		t.Fatalf("scope page error = %v", err)
	}
	if pageResponse.StatusCode != http.StatusOK {
		t.Fatalf("scope page status = %d, want %d", pageResponse.StatusCode, http.StatusOK)
	}
}

func TestAdminGetRoutesRedirectToReactShell(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	for path, want := range map[string]string{
		"/admin":             "/app/admin",
		"/admin/users":       "/app/admin/users",
		"/admin/engagements": "/app/admin/engagements",
		"/admin/workers":     "/app/admin/workers",
		"/admin/connectors":  "/app/admin/connectors",
		"/admin/audit":       "/app/admin/audit",
		"/admin/tools":       "/app/admin/tools",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("%s status = %d, want %d", path, recorder.Code, http.StatusSeeOther)
		}
		if got := recorder.Header().Get("Location"); got != want {
			t.Fatalf("%s Location = %q, want %q", path, got, want)
		}
	}
}

func TestEngagementInventoryRoutesRedirectAndDetailJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		SeedFiles:       []string{writeSnapshotFixture(t)},
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	}); err != nil {
		t.Fatalf("login request error = %v", err)
	}

	job := &pluginJob{ID: "job-1", PluginID: "nuclei", PluginLabel: "Nuclei HTTP Enrichment"}
	result := PluginRunResult{
		NucleiFindings: map[string][]storedNucleiFinding{
			"10.0.0.9": {{
				TemplateID: "http-missing-header",
				Name:       "Missing security header",
				Severity:   "medium",
				Target:     "http://10.0.0.9",
				MatchedAt:  "http://10.0.0.9",
				Type:       "http",
			}},
		},
		Findings: FindingSummary{Total: 1, Medium: 1},
	}
	if err := app.workspace.applyPluginResult(job, result); err != nil {
		t.Fatalf("applyPluginResult() error = %v", err)
	}

	engagement, err := app.platform.store.engagementByWorkspaceID(app.workspace.id)
	if err != nil {
		t.Fatalf("engagementByWorkspaceID() error = %v", err)
	}
	if err := app.platform.syncEngagement(engagement); err != nil {
		t.Fatalf("syncEngagement() error = %v", err)
	}

	checkJSON := func(path string) map[string]any {
		t.Helper()
		response, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s error = %v", path, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d", path, response.StatusCode, http.StatusOK)
		}
		var payload map[string]any
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			t.Fatalf("decode %s error = %v", path, err)
		}
		return payload
	}

	hostPayload := checkJSON("/api/v1/engagements/engagement-alpha/hosts/10.0.0.9")
	if _, ok := hostPayload["host"]; !ok {
		t.Fatalf("host detail payload missing host: %#v", hostPayload)
	}

	portPayload := checkJSON("/api/v1/engagements/engagement-alpha/ports/tcp/80")
	if _, ok := portPayload["port"]; !ok {
		t.Fatalf("port detail payload missing port: %#v", portPayload)
	}

	groupID := ""
	for _, item := range app.workspace.findingGroups() {
		if item.TemplateID == "http-missing-header" {
			groupID = item.ID
			break
		}
	}
	if groupID == "" {
		t.Fatal("failed to derive finding group id from workspace")
	}
	findingPayload := checkJSON("/api/v1/engagements/engagement-alpha/findings/" + url.PathEscape(groupID))
	if _, ok := findingPayload["finding"]; !ok {
		t.Fatalf("finding detail payload missing finding: %#v", findingPayload)
	}

	for path, want := range map[string]string{
		"/engagements/engagement-alpha/zones":               "/app/engagements/engagement-alpha/zones",
		"/engagements/engagement-alpha/hosts":               "/app/engagements/engagement-alpha/hosts",
		"/engagements/engagement-alpha/hosts/10.0.0.9":      "/app/engagements/engagement-alpha/hosts/10.0.0.9",
		"/engagements/engagement-alpha/ports":               "/app/engagements/engagement-alpha/ports",
		"/engagements/engagement-alpha/ports/tcp/80":        "/app/engagements/engagement-alpha/ports/tcp/80",
		"/engagements/engagement-alpha/findings":            "/app/engagements/engagement-alpha/findings",
		"/engagements/engagement-alpha/findings/" + groupID: "/app/engagements/engagement-alpha/findings/" + groupID,
	} {
		response, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s error = %v", path, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("GET %s status = %d, want %d", path, response.StatusCode, http.StatusSeeOther)
		}
		if location := response.Header.Get("Location"); location != want {
			t.Fatalf("GET %s Location = %q, want %q", path, location, want)
		}
	}
}

func TestScopeKickoffCreatesChunksAndApproval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}
	workspace := app.workspace
	toolsDir := t.TempDir()
	installFakeTool(t, toolsDir, "naabu")
	installFakeTool(t, toolsDir, "nmap")
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	workspace.plugins.mu.Lock()
	workspace.plugins.plugins["naabu"] = fakePlugin{id: "naabu", label: "Naabu"}
	workspace.plugins.plugins["nmap-enrich"] = fakePlugin{id: "nmap-enrich", label: "Nmap enrich"}
	workspace.plugins.mu.Unlock()

	if _, err := workspace.ingestScope("Kickoff", "203.0.113.0/24", "test", false); err != nil {
		t.Fatalf("ingestScope() error = %v", err)
	}

	if len(workspace.scopeSeedViews()) != 1 {
		t.Fatalf("scopeSeedViews() = %d, want 1", len(workspace.scopeSeedViews()))
	}
	if len(workspace.targetChunkViews()) == 0 {
		t.Fatal("targetChunkViews() returned no chunks")
	}
	approvals := workspace.approvalViews()
	if len(approvals) != 1 || approvals[0].Status != approvalPending {
		t.Fatalf("approvalViews() = %#v, want one pending approval", approvals)
	}
	if err := workspace.approveKickoff(approvals[0].ID); err != nil {
		t.Fatalf("approveKickoff() error = %v", err)
	}
	if got := workspace.approvalViews()[0].Status; got != approvalApproved {
		t.Fatalf("approval status = %q, want approved", got)
	}
	if len(workspace.plugins.recentJobs(10)) == 0 {
		t.Fatal("recentJobs() returned no orchestrated jobs")
	}
}

func TestKickoffToolRequestsPreferPingDiscovery(t *testing.T) {
	workspace := &workspace{
		preferencesState: defaultWorkspacePreferences(),
	}

	workspace.mu.Lock()
	cidrRequests := workspace.kickoffToolRequestsLocked(targetChunkRecord{
		Name:   "Network discovery 1",
		Kind:   "cidr",
		Stage:  "discovery",
		Values: []string{"203.0.113.0/24"},
	})
	workspace.mu.Unlock()
	if len(cidrRequests) != 1 {
		t.Fatalf("cidr kickoff requests = %#v, want single ping discovery request", cidrRequests)
	}
	if cidrRequests[0].PluginID != "nmap-enrich" || cidrRequests[0].Options["profile"] != "ping" {
		t.Fatalf("cidr kickoff request = %#v, want nmap ping discovery", cidrRequests[0])
	}

	workspace.mu.Lock()
	domainRequests := workspace.kickoffToolRequestsLocked(targetChunkRecord{
		Name:   "Host recon 1",
		Kind:   "domain",
		Stage:  "recon",
		Values: []string{"example.com"},
	})
	workspace.mu.Unlock()
	if len(domainRequests) != 2 {
		t.Fatalf("domain kickoff requests = %#v, want subfinder + nmap ping", domainRequests)
	}
	if domainRequests[0].PluginID != "subfinder" {
		t.Fatalf("domain kickoff first request = %#v, want subfinder", domainRequests[0])
	}
	if domainRequests[1].PluginID != "nmap-enrich" || domainRequests[1].Options["profile"] != "ping" {
		t.Fatalf("domain kickoff second request = %#v, want nmap ping discovery", domainRequests[1])
	}
}

func TestPlatformCampaignManualRunFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	toolsDir := t.TempDir()
	installFakeTool(t, toolsDir, "nmap")
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	}); err != nil {
		t.Fatalf("login request error = %v", err)
	}

	createResponse, err := client.PostForm(server.URL+"/admin/engagements", url.Values{
		"name":        {"Acme Manual"},
		"description": {"test"},
		"scope":       {"198.51.100.10"},
	})
	if err != nil {
		t.Fatalf("create engagement error = %v", err)
	}
	if createResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want %d", createResponse.StatusCode, http.StatusSeeOther)
	}

	engagement, err := app.platform.store.engagementBySlug("acme-manual")
	if err != nil {
		t.Fatalf("engagementBySlug() error = %v", err)
	}
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		t.Fatalf("loadWorkspaceByID() error = %v", err)
	}
	workspace.plugins.mu.Lock()
	workspace.plugins.plugins["nmap-enrich"] = fakePlugin{id: "nmap-enrich", label: "Nmap"}
	workspace.plugins.mu.Unlock()

	runResponse, err := client.PostForm(server.URL+"/engagements/acme-manual/campaigns", url.Values{
		"plugin":      {"nmap-enrich"},
		"target_mode": {"manual"},
		"targets":     {"198.51.100.10"},
		"profile":     {"default"},
	})
	if err != nil {
		t.Fatalf("manual run request error = %v", err)
	}
	if runResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("manual run status = %d, want %d", runResponse.StatusCode, http.StatusSeeOther)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(workspace.plugins.recentJobs(10)) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("manual engagement run did not enqueue a plugin job")
}

func TestPlatformHostsPageRendersTopMenuAndPagination(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	admin, err := app.platform.store.userByLogin("admin")
	if err != nil {
		t.Fatalf("userByLogin() error = %v", err)
	}
	engagement, err := app.platform.createEngagement(admin, "Pagination Test", "test", "")
	if err != nil {
		t.Fatalf("createEngagement() error = %v", err)
	}

	hosts := make([]platformHostRecord, 0, 65)
	for index := 1; index <= 65; index++ {
		hosts = append(hosts, platformHostRecord{
			IP:            fmt.Sprintf("198.51.100.%d", index),
			DisplayName:   fmt.Sprintf("host-%02d", index),
			OSName:        "linux",
			ExposureLabel: "Elevated",
			ExposureTone:  "warning",
			CoverageLabel: "default-tcp",
			SourceCount:   1,
			OpenPortCount: 2,
			FindingTotal:  index % 5,
			ZoneCount:     1,
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
		})
	}
	if err := app.platform.store.replaceEngagementProjection(engagement.ID, nil, nil, nil, nil, nil, nil, nil, nil, hosts, nil, nil, nil, nil); err != nil {
		t.Fatalf("replaceEngagementProjection() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/engagements/pagination-test/hosts", nil)
	recorder := httptest.NewRecorder()
	app.renderEngagementHosts(recorder, request, admin, engagement)

	body := recorder.Body.String()
	if !strings.Contains(body, "platform-menubar") {
		t.Fatal("hosts page did not render the top menubar")
	}
	if count := strings.Count(body, "/engagements/pagination-test/hosts/198.51.100."); count != 20 {
		t.Fatalf("default hosts page rendered %d host rows, want 20", count)
	}
	if !strings.Contains(body, "hosts_page_size=50") || !strings.Contains(body, "hosts_page_size=100") {
		t.Fatal("hosts page did not render 50/100 page size controls")
	}

	request50 := httptest.NewRequest(http.MethodGet, "/engagements/pagination-test/hosts?hosts_page_size=50", nil)
	recorder50 := httptest.NewRecorder()
	app.renderEngagementHosts(recorder50, request50, admin, engagement)
	if count := strings.Count(recorder50.Body.String(), "/engagements/pagination-test/hosts/198.51.100."); count != 50 {
		t.Fatalf("hosts page rendered %d host rows for page size 50, want 50", count)
	}
}

func TestAdminToolCommandTemplateCanBeUpdated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	}); err != nil {
		t.Fatalf("login request error = %v", err)
	}

	template := "sudo {{binary}} {{args}}"
	requestBody := bytes.NewBufferString(`{"commandTemplate":"` + template + `"}`)
	request, err := http.NewRequest(http.MethodPatch, server.URL+"/api/v1/admin/tools/nmap-enrich", requestBody)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("update tool command error = %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tool update status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	resolved, err := app.platform.store.toolCommandTemplate("nmap-enrich")
	if err != nil {
		t.Fatalf("toolCommandTemplate() error = %v", err)
	}
	if resolved != template {
		t.Fatalf("toolCommandTemplate() = %q, want %q", resolved, template)
	}

	pageResponse, err := client.Get(server.URL + "/admin/tools")
	if err != nil {
		t.Fatalf("GET /admin/tools error = %v", err)
	}
	_ = pageResponse.Body.Close()
	if pageResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET /admin/tools status = %d, want %d", pageResponse.StatusCode, http.StatusSeeOther)
	}
	if location := pageResponse.Header.Get("Location"); location != "/app/admin/tools" {
		t.Fatalf("GET /admin/tools Location = %q, want /app/admin/tools", location)
	}
}

func TestRunCLICommandUsesCommandTemplate(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "echo-tool")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nprintf '%s' \"$*\"\n"), 0o755); err != nil {
		t.Fatalf("write script error = %v", err)
	}

	output, commandLine, err := runCLICommand(context.Background(), pluginRunRequest{
		CommandTemplate: "{{binary}} --hello {{args}}",
	}, scriptPath, []string{"world"})
	if err != nil {
		t.Fatalf("runCLICommand() error = %v", err)
	}
	if !strings.Contains(commandLine, "--hello") {
		t.Fatalf("commandLine = %q, want custom flag", commandLine)
	}
	if string(output) != "--hello world" {
		t.Fatalf("output = %q, want custom command output", string(output))
	}
}

func TestServiceStoreExportsAndImportsBundle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := openServiceStore(filepath.Join(t.TempDir(), "service.sqlite"), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("openServiceStore() error = %v", err)
	}
	defer service.close()

	meta, err := service.createWorkspace("engagement-alpha", "test")
	if err != nil {
		t.Fatalf("createWorkspace() error = %v", err)
	}
	workspace, err := openWorkspaceWithStore(meta, meta.BundlePath, service.workspaceArtifactsDir(meta.ID), service.workspaceStore(meta), []string{writeSnapshotFixture(t)}, logger)
	if err != nil {
		t.Fatalf("openWorkspaceWithStore() error = %v", err)
	}
	if workspace.workspaceStatus().ScanCount == 0 {
		t.Fatal("workspace imported no scans")
	}
	if err := service.exportWorkspaceBundle(meta); err != nil {
		t.Fatalf("exportWorkspaceBundle() error = %v", err)
	}

	imported, err := service.importWorkspaceBundle(meta.BundlePath, "engagement-beta")
	if err != nil {
		t.Fatalf("importWorkspaceBundle() error = %v", err)
	}
	importedWorkspace, err := openWorkspaceWithStore(imported, imported.BundlePath, service.workspaceArtifactsDir(imported.ID), service.workspaceStore(imported), nil, logger)
	if err != nil {
		t.Fatalf("open imported workspace error = %v", err)
	}
	if importedWorkspace.workspaceStatus().ScanCount == 0 {
		t.Fatal("imported workspace lost scans during round-trip")
	}
}

func TestLLMPlannerRecommendationRouteGracefullyErrorsWithoutAuth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("NWA_CODEX_CMD", filepath.Join(t.TempDir(), "missing-codex"))
	t.Setenv("CODEX_HOME", filepath.Join(t.TempDir(), "empty-codex-home"))
	app := newTestApplication(t, true)
	app.logger = logger
	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/recommendations/llm", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestOrchestratedJobsEventuallyCompleteWithFakePlugins(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	workspace := app.workspace
	toolsDir := t.TempDir()
	installFakeTool(t, toolsDir, "naabu")
	installFakeTool(t, toolsDir, "nmap")
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	workspace.plugins.mu.Lock()
	workspace.plugins.plugins["naabu"] = fakePlugin{id: "naabu", label: "Naabu"}
	workspace.plugins.plugins["nmap-enrich"] = fakePlugin{id: "nmap-enrich", label: "Nmap enrich"}
	workspace.plugins.mu.Unlock()

	if _, err := workspace.ingestScope("Kickoff", "198.51.100.1", "test", true); err != nil {
		t.Fatalf("ingestScope() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allDone := true
		for _, job := range workspace.plugins.recentJobs(10) {
			if job.Status == jobQueued || job.Status == jobRunning {
				allDone = false
				break
			}
		}
		if allDone {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("orchestrated jobs did not complete in time")
}

func TestScopeKickoffBlocksUnavailableToolsInsteadOfFailingApproval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	workspace := app.workspace
	t.Setenv("PATH", t.TempDir())
	if _, err := workspace.ingestScope("Kickoff", "section9labs.com", "test", true); err != nil {
		t.Fatalf("ingestScope() error = %v", err)
	}

	chunks := workspace.targetChunkViews()
	if len(chunks) != 1 {
		t.Fatalf("targetChunkViews() len = %d, want 1", len(chunks))
	}
	if chunks[0].Status != targetChunkBlocked {
		t.Fatalf("chunk status = %q, want %q", chunks[0].Status, targetChunkBlocked)
	}
	if chunks[0].Detail == "" {
		t.Fatal("blocked chunk detail was empty")
	}
}

func TestPluginReadinessGroupsReflectInstalledTools(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	toolsDir := t.TempDir()
	installFakeTool(t, toolsDir, "nmap")
	installFakeTool(t, toolsDir, "nuclei")
	t.Setenv("PATH", toolsDir)

	groups := app.workspace.plugins.readinessGroups()
	if len(groups) == 0 {
		t.Fatal("readinessGroups() returned no groups")
	}

	byLabel := map[string]ToolReadinessGroup{}
	for _, group := range groups {
		byLabel[group.Label] = group
	}

	if got := byLabel["Discovery"].Ready; got != 1 {
		t.Fatalf("Discovery.Ready = %d, want 1", got)
	}
	if got := byLabel["Validation"].Ready; got != 1 {
		t.Fatalf("Validation.Ready = %d, want 1", got)
	}
	if got := byLabel["Recon"].Ready; got != 0 {
		t.Fatalf("Recon.Ready = %d, want 0", got)
	}
}
