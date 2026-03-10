package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (app *application) handleArtifact(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	relPath := strings.TrimPrefix(request.URL.Path, "/artifacts/")
	relPath = filepath.Clean(strings.TrimSpace(relPath))
	if relPath == "." || strings.HasPrefix(relPath, "..") {
		http.NotFound(writer, request)
		return
	}
	fullPath := filepath.Join(workspace.artifactRoot(), relPath)
	if !strings.HasPrefix(fullPath, filepath.Clean(workspace.artifactRoot())+string(os.PathSeparator)) && fullPath != filepath.Clean(workspace.artifactRoot()) {
		http.NotFound(writer, request)
		return
	}
	http.ServeFile(writer, request, fullPath)
}

func (app *application) handleWorkspaces(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, meta, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}

	items, err := app.workspaceDirectoryItems(meta.ID)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	data := WorkspacesPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"workspaces",
			"Engagements",
			"Command-center engagement registry with portable bundles, posture snapshots, and fast switching.",
			SearchState{},
			[]Breadcrumb{{Label: "Engagements", Href: "/workspaces"}},
			nil,
		),
		Items: items,
	}
	app.render(writer, http.StatusOK, "workspaces", data)
}

func (app *application) handleWorkspaceCreate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if app.center == nil || !app.center.hasService() {
		http.Error(writer, "workspace creation requires service mode", http.StatusBadRequest)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	workspace, meta, err := app.center.createWorkspace(request.FormValue("name"), request.FormValue("description"), nil)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if scope := strings.TrimSpace(request.FormValue("scope")); scope != "" {
		if _, err := workspace.ingestScope(request.FormValue("name"), scope, "workspace-create", request.FormValue("auto_approve") == "1"); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
	}
	app.center.setWorkspaceCookie(writer, meta.ID)
	http.Redirect(writer, request, "/scope", http.StatusSeeOther)
}

func (app *application) handleWorkspaceSelect(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if app.center == nil || !app.center.hasService() {
		http.Redirect(writer, request, "/overview", http.StatusSeeOther)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(request.FormValue("workspace"))
	meta, err := app.center.service.workspaceByID(id)
	if err != nil {
		meta, err = app.center.service.workspaceBySlug(id)
	}
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	app.center.setWorkspaceCookie(writer, meta.ID)
	http.Redirect(writer, request, chooseString(request.FormValue("return_to"), "/overview"), http.StatusSeeOther)
}

func (app *application) handleWorkspaceImport(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseMultipartForm(64 << 20); err != nil && err != http.ErrNotMultipart {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if app.center == nil || !app.center.hasService() {
		http.Error(writer, "bundle import requires service mode", http.StatusBadRequest)
		return
	}

	path := strings.TrimSpace(request.FormValue("bundle_path"))
	if path == "" {
		file, header, err := request.FormFile("bundle_file")
		if err != nil {
			http.Error(writer, "missing bundle path or file", http.StatusBadRequest)
			return
		}
		defer file.Close()
		targetDir := filepath.Join(app.center.dataDir, "uploads")
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		path = filepath.Join(targetDir, filepath.Base(header.Filename))
		out, err := os.Create(path)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		defer out.Close()
		if _, err := io.Copy(out, file); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	_, meta, err := app.center.importBundle(path, request.FormValue("name"))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	app.center.setWorkspaceCookie(writer, meta.ID)
	http.Redirect(writer, request, "/sources", http.StatusSeeOther)
}

func (app *application) handleWorkspaceExport(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost && request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, meta, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if err := app.center.exportWorkspace(meta); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = workspace
	data, err := os.ReadFile(meta.BundlePath)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(meta.BundlePath)+`"`)
	_, _ = writer.Write(data)
}

func (app *application) handleScope(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	data := ScopePageData{
		CommonPageData: app.commonPageData(
			workspace,
			"scope",
			"Scope",
			"Normalize scope seeds into bounded execution chunks, review approvals, and stage the command-center kickoff.",
			SearchState{},
			[]Breadcrumb{{Label: "Scope", Href: "/scope"}},
			nil,
		),
		Stats:           workspace.scopeStats(),
		Readiness:       workspace.plugins.readinessGroups(),
		Seeds:           workspace.scopeSeedViews(),
		Targets:         workspace.scopeTargetViews(),
		Chunks:          workspace.targetChunkViews(),
		Approvals:       workspace.pendingApprovalViews(),
		Recommendations: workspace.recommendationViews(),
	}
	app.render(writer, http.StatusOK, "scope", data)
}

func (app *application) handleScopeKickoff(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if _, err := workspace.ingestScope(request.FormValue("name"), request.FormValue("scope"), "scope-page", request.FormValue("auto_approve") == "1"); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, "/scope", http.StatusSeeOther)
}

func (app *application) handleCampaigns(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	data := CampaignsPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"campaigns",
			"Campaigns",
			"Orchestrated campaign graph, chunk execution state, approvals, and recent runs for the current workspace.",
			SearchState{},
			[]Breadcrumb{{Label: "Campaigns", Href: "/campaigns"}},
			nil,
		),
		Stats:           workspace.scopeStats(),
		Readiness:       workspace.plugins.readinessGroups(),
		Campaigns:       workspace.campaignCatalog(),
		Chunks:          workspace.targetChunkViews(),
		Approvals:       workspace.pendingApprovalViews(),
		Recommendations: workspace.recommendationViews(),
		Jobs:            workspace.plugins.recentJobs(24),
	}
	app.render(writer, http.StatusOK, "campaigns", data)
}

func (app *application) handleApprovalApprove(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if err := workspace.approveKickoff(request.FormValue("approval_id")); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, chooseString(request.FormValue("return_to"), "/campaigns"), http.StatusSeeOther)
}

func (app *application) handleRecommendations(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	data := RecommendationsPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"recommendations",
			"Recommendations",
			"Operator recommendation queue combining heuristic and planner-backed next steps with explicit approval requirements.",
			SearchState{},
			[]Breadcrumb{{Label: "Recommendations", Href: "/recommendations"}},
			nil,
		),
		Stats:           workspace.scopeStats(),
		Recommendations: workspace.recommendationViews(),
		Approvals:       workspace.pendingApprovalViews(),
		Campaigns:       workspace.campaignCatalog(),
	}
	app.render(writer, http.StatusOK, "recommendations", data)
}

func (app *application) handleRecommendationLLM(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if _, err := workspace.generateLLMRecommendations(request.FormValue("campaign_id")); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, "/recommendations", http.StatusSeeOther)
}

func (app *application) workspaceDirectoryItems(selectedID string) ([]WorkspaceDirectoryItem, error) {
	metas, err := app.center.listWorkspaces()
	if err != nil {
		return nil, err
	}
	items := make([]WorkspaceDirectoryItem, 0, len(metas))
	for _, meta := range metas {
		workspace, _, err := app.center.loadWorkspace(meta, nil)
		if err != nil {
			return nil, err
		}
		status := workspace.workspaceStatus()
		stats := []StatCard{
			{Label: "Hosts", Value: strconv.Itoa(workspace.currentSnapshot().meta.LiveHosts), Detail: "Live inventory", Tone: "accent"},
			{Label: "Findings", Value: strconv.Itoa(status.TotalFindings), Detail: "Current posture", Tone: "warning"},
			{Label: "Running", Value: strconv.Itoa(status.RunningJobs), Detail: "Queued or active", Tone: "calm"},
		}
		items = append(items, WorkspaceDirectoryItem{
			ID:          meta.ID,
			Slug:        meta.Slug,
			Name:        meta.Name,
			Description: chooseString(meta.Description, "Central workspace"),
			BundlePath:  meta.BundlePath,
			Mode:        status.Mode,
			Href:        "/overview?workspace=" + url.QueryEscape(meta.ID),
			Selected:    meta.ID == selectedID,
			Stats:       stats,
		})
	}
	return items, nil
}
