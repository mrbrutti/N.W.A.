package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var platformPaginationSizes = []int{20, 50, 100}

func (app *application) handleLogin(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	switch request.Method {
	case http.MethodGet:
		app.render(writer, http.StatusOK, "platform_login", LoginPageData{
			Page: PlatformPageMeta{
				Title:       "Login",
				Description: "Sign in to the NWA platform.",
				Section:     "login",
			},
			Error:           strings.TrimSpace(request.URL.Query().Get("error")),
			BootstrapHint:   app.platform.bootstrapHint,
			DefaultUsername: "admin",
		})
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		user, token, err := app.platform.authenticate(request.FormValue("login"), request.FormValue("password"), request)
		if err != nil {
			http.Redirect(writer, request, "/login?error=Invalid+credentials", http.StatusSeeOther)
			return
		}
		http.SetCookie(writer, &http.Cookie{
			Name:     platformSessionCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(7 * 24 * time.Hour),
		})
		target := "/engagements"
		if user.IsAdmin {
			target = "/admin"
		}
		http.Redirect(writer, request, target, http.StatusSeeOther)
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (app *application) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	user, token, ok := app.requirePlatformUser(writer, request, false)
	if !ok {
		return
	}
	app.platform.logout(token, user)
	http.SetCookie(writer, &http.Cookie{
		Name:     platformSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	http.Redirect(writer, request, "/login", http.StatusSeeOther)
}

func (app *application) handleAdminOverview(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, true)
	if !ok {
		return
	}
	health, err := app.platform.store.healthSummary()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	engagements, err := app.platform.engagementViewsForUser(user)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	workers, _ := app.platform.store.listWorkers()
	tools, _ := app.platform.store.listTools()
	audit, _ := app.platform.store.recentAudit(0)
	workers, workersPager := paginatePlatformSlice(request, "workers", workers)
	engagements, engagementsPager := paginatePlatformSlice(request, "engagements", engagements)
	tools, toolsPager := paginatePlatformSlice(request, "tools", tools)
	audit, auditPager := paginatePlatformSlice(request, "audit", audit)
	base := app.platformBasePage(user, PlatformEngagementView{}, true, "admin", "System Overview", "Admin health, tools, workers, and current engagements.")
	base.Pagers = platformPaginationMap(workersPager, engagementsPager, toolsPager, auditPager)
	app.render(writer, http.StatusOK, "platform_admin_overview", AdminOverviewPageData{
		PlatformBasePage: base,
		Health:           health,
		Engagements:      engagements,
		Workers:          workers,
		Tools:            tools,
		RecentAudit:      audit,
	})
}

func (app *application) handleAdminUsers(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, true)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		users, err := app.platform.store.listUsers()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		engagements, _ := app.platform.engagementViewsForUser(user)
		items := make([]PlatformUserView, 0, len(users))
		for _, item := range users {
			items = append(items, platformUserView(item))
		}
		items, usersPager := paginatePlatformSlice(request, "users", items)
		base := app.platformBasePage(user, PlatformEngagementView{}, true, "users", "Users", "Manage platform accounts and roles.")
		base.Pagers = platformPaginationMap(usersPager)
		app.render(writer, http.StatusOK, "platform_admin_users", AdminUsersPageData{
			PlatformBasePage: base,
			Users:            items,
			Engagements:      engagements,
		})
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		admin := request.FormValue("admin") == "on"
		if err := app.platform.createPlatformUser(user, request.FormValue("username"), request.FormValue("email"), request.FormValue("password"), request.FormValue("display_name"), admin); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(writer, request, "/admin/users", http.StatusSeeOther)
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (app *application) handleAdminEngagements(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, true)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		engagements, err := app.platform.engagementViewsForUser(user)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		users, _ := app.platform.store.listUsers()
		userViews := make([]PlatformUserView, 0, len(users))
		for _, item := range users {
			userViews = append(userViews, platformUserView(item))
		}
		engagements, engagementsPager := paginatePlatformSlice(request, "engagements", engagements)
		base := app.platformBasePage(user, PlatformEngagementView{}, true, "engagements", "Engagements", "Create and manage multi-user engagements.")
		base.Pagers = platformPaginationMap(engagementsPager)
		app.render(writer, http.StatusOK, "platform_admin_engagements", AdminEngagementsPageData{
			PlatformBasePage: base,
			Engagements:      engagements,
			Users:            userViews,
		})
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		engagement, err := app.platform.createEngagement(user, request.FormValue("name"), request.FormValue("description"), request.FormValue("scope"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(writer, request, "/engagements/"+engagement.Slug, http.StatusSeeOther)
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (app *application) handleAdminTools(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, true)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		tools, _ := app.platform.store.listTools()
		connectors, _ := app.platform.store.listConnectors()
		workers, _ := app.platform.store.listWorkers()
		tools, toolsPager := paginatePlatformSlice(request, "tools", tools)
		connectors, connectorsPager := paginatePlatformSlice(request, "connectors", connectors)
		workers, workersPager := paginatePlatformSlice(request, "workers", workers)
		base := app.platformBasePage(user, PlatformEngagementView{}, true, "tools", "Tools", "Tool registry, connector state, worker readiness, and editable CLI commands.")
		base.Pagers = platformPaginationMap(toolsPager, connectorsPager, workersPager)
		app.render(writer, http.StatusOK, "platform_admin_tools", AdminToolsPageData{
			PlatformBasePage: base,
			Tools:            tools,
			Connectors:       connectors,
			Workers:          workers,
		})
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		action := strings.TrimSpace(request.FormValue("action"))
		if action != "update_tool_command" && action != "reset_tool_command" {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		toolID := strings.TrimSpace(request.FormValue("tool_id"))
		tools, err := app.platform.store.listTools()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		toolByID := map[string]PlatformToolView{}
		for _, item := range tools {
			toolByID[item.ID] = item
		}
		tool, ok := toolByID[toolID]
		if !ok || !tool.CommandEditable {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		template := strings.TrimSpace(request.FormValue("command_template"))
		if action == "reset_tool_command" || template == strings.TrimSpace(tool.DefaultCommandTemplate) {
			template = ""
		}
		if err := app.platform.store.updateToolCommandTemplate(toolID, template); err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		http.Redirect(writer, request, "/admin/tools#tool-"+url.QueryEscape(toolID), http.StatusSeeOther)
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (app *application) handleEngagementsIndex(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, false)
	if !ok {
		return
	}
	engagements, err := app.platform.engagementViewsForUser(user)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if len(engagements) == 1 {
		http.Redirect(writer, request, engagements[0].OverviewHref, http.StatusSeeOther)
		return
	}
	engagements, engagementsPager := paginatePlatformSlice(request, "engagements", engagements)
	base := app.platformBasePage(user, PlatformEngagementView{}, false, "engagements", "Engagements", "Choose an engagement and continue into its inventory.")
	base.Pagers = platformPaginationMap(engagementsPager)
	app.render(writer, http.StatusOK, "platform_admin_engagements", AdminEngagementsPageData{
		PlatformBasePage: base,
		Engagements:      engagements,
	})
}

func (app *application) handleEngagementRouter(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	user, _, ok := app.requirePlatformUser(writer, request, false)
	if !ok {
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/engagements/")
	path = strings.Trim(path, "/")
	if path == "" {
		app.handleEngagementsIndex(writer, request)
		return
	}
	parts := strings.Split(path, "/")
	slug := parts[0]
	section := "overview"
	if len(parts) > 1 {
		section = parts[1]
	}
	engagement, role, err := app.platform.requireEngagement(user, slug)
	if err != nil {
		if errors.Is(err, errPlatformForbidden) {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		http.NotFound(writer, request)
		return
	}
	if request.Method == http.MethodGet {
		switch section {
		case "overview", "zones", "hosts", "ports", "findings", "sources", "campaigns", "topology", "recommendations", "settings":
			app.handleEngagementReactRedirect(writer, request)
			return
		}
		_ = app.platform.syncEngagement(engagement)
	}

	switch section {
	case "overview":
		app.renderEngagementOverview(writer, request, user, engagement)
	case "scope":
		if request.Method == http.MethodPost {
			app.handleEngagementScopeAdd(writer, request, user, engagement)
			return
		}
		app.renderEngagementScope(writer, request, user, engagement)
	case "zones":
		app.renderEngagementZones(writer, request, user, engagement)
	case "sources":
		if request.Method == http.MethodPost {
			app.handleEngagementSourceImport(writer, request, user, engagement)
			return
		}
		app.renderEngagementSources(writer, request, user, engagement)
	case "hosts":
		if len(parts) > 2 {
			app.renderEngagementHostDetail(writer, request, user, engagement, parts[2])
			return
		}
		app.renderEngagementHosts(writer, request, user, engagement)
	case "ports":
		if len(parts) > 3 {
			app.renderEngagementPortDetail(writer, request, user, engagement, parts[2], parts[3])
			return
		}
		app.renderEngagementPorts(writer, request, user, engagement)
	case "findings":
		if len(parts) > 2 {
			app.renderEngagementFindingDetail(writer, request, user, engagement, parts[2])
			return
		}
		app.renderEngagementFindings(writer, request, user, engagement)
	case "campaigns":
		if request.Method == http.MethodPost {
			app.handleEngagementCampaignRun(writer, request, user, engagement, role)
			return
		}
		app.renderEngagementCampaigns(writer, request, user, engagement, role)
	case "topology":
		app.renderEngagementTopology(writer, request, user, engagement)
	case "recommendations":
		app.renderEngagementRecommendations(writer, request, user, engagement)
	case "settings":
		if request.Method == http.MethodPost {
			app.handleEngagementMembershipAdd(writer, request, user, engagement)
			return
		}
		app.renderEngagementSettings(writer, request, user, engagement)
	default:
		http.NotFound(writer, request)
	}
}

func (app *application) handleEngagementCampaignRun(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord, role string) {
	_ = user
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	action := chooseString(strings.TrimSpace(request.FormValue("action")), "queue_run")
	returnTo := chooseString(request.FormValue("return_to"), "/engagements/"+engagement.Slug+"/campaigns")
	input := platformCampaignActionInput{
		Action:            action,
		PolicyID:          strings.TrimSpace(request.FormValue("policy_id")),
		PolicyName:        strings.TrimSpace(request.FormValue("policy_name")),
		PolicyDescription: strings.TrimSpace(request.FormValue("policy_description")),
		StepID:            strings.TrimSpace(request.FormValue("step_id")),
		StepOrder:         parseTargetLines(strings.ReplaceAll(request.FormValue("step_order"), "|", "\n")),
		Label:             strings.TrimSpace(request.FormValue("label")),
		Trigger:           strings.TrimSpace(request.FormValue("trigger")),
		PluginID:          strings.TrimSpace(request.FormValue("plugin")),
		Stage:             strings.TrimSpace(request.FormValue("stage")),
		TargetSource:      strings.TrimSpace(request.FormValue("target_source")),
		MatchKinds:        policyKindsFromInput(request.FormValue("match_kinds")),
		WhenPlugin:        strings.TrimSpace(request.FormValue("when_plugin")),
		WhenProfile:       strings.TrimSpace(request.FormValue("when_profile")),
		Summary:           strings.TrimSpace(request.FormValue("summary")),
		TargetMode:        strings.TrimSpace(request.FormValue("target_mode")),
		Targets:           parseTargetLines(request.FormValue("targets")),
		ProfileScope:      strings.TrimSpace(request.FormValue("profile_scope")),
		Severity:          strings.TrimSpace(request.FormValue("severity")),
		Templates:         strings.TrimSpace(request.FormValue("templates")),
		Concurrency:       strings.TrimSpace(request.FormValue("concurrency")),
		Profile:           strings.TrimSpace(request.FormValue("profile")),
		Ports:             strings.TrimSpace(request.FormValue("ports")),
		TopPorts:          strings.TrimSpace(request.FormValue("top_ports")),
		CrawlDepth:        strings.TrimSpace(request.FormValue("crawl_depth")),
		Level:             strings.TrimSpace(request.FormValue("level")),
		Risk:              strings.TrimSpace(request.FormValue("risk")),
		APIBaseURL:        strings.TrimSpace(request.FormValue("api_base_url")),
		ScanID:            strings.TrimSpace(request.FormValue("scan_id")),
		SiteID:            strings.TrimSpace(request.FormValue("site_id")),
		ParentID:          strings.TrimSpace(request.FormValue("parent_id")),
		ScanConfigIDs:     strings.TrimSpace(request.FormValue("scan_config_ids")),
		APIInsecure:       strings.EqualFold(strings.TrimSpace(request.FormValue("api_insecure")), "true"),
		Enabled:           !strings.EqualFold(strings.TrimSpace(request.FormValue("enabled")), "false"),
		ExtraArgs:         strings.TrimSpace(request.FormValue("extra_args")),
	}

	if err := app.runEngagementCampaignAction(engagement, role, input); err != nil {
		if errors.Is(err, errPlatformForbidden) {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, returnTo, http.StatusSeeOther)
}

func (app *application) handleEngagementScopeAdd(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	campaign, err := workspace.ingestScope(request.FormValue("name"), request.FormValue("scope"), "engagement-scope", false)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(campaign.ApprovalID) != "" {
		if approveErr := workspace.approveKickoff(campaign.ApprovalID); approveErr != nil && app.logger != nil {
			app.logger.Warn("engagement scope kickoff degraded", "engagement", engagement.Slug, "campaign", campaign.ID, "error", approveErr)
		}
	}
	_ = app.platform.syncEngagement(engagement)
	http.Redirect(writer, request, "/engagements/"+engagement.Slug+"/scope", http.StatusSeeOther)
}

func (app *application) handleEngagementSourceImport(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	_ = user
	if err := request.ParseMultipartForm(64 << 20); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	file, header, err := request.FormFile("scan_file")
	if err != nil {
		http.Error(writer, "scan_file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if err := app.importEngagementSourceFile(engagement, header.Filename, file); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, "/engagements/"+engagement.Slug+"/sources", http.StatusSeeOther)
}

func (app *application) handleEngagementMembershipAdd(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := app.addEngagementMembership(user, engagement, request.FormValue("user"), request.FormValue("role")); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, "/engagements/"+engagement.Slug+"/settings", http.StatusSeeOther)
}

func (app *application) renderEngagementOverview(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, err := app.platform.engagementViewByID(user, engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	zones, _ := app.platform.store.listEngagementZones(engagement.ID)
	sources, _ := app.platform.store.listEngagementSources(engagement.ID, 0)
	runs, _ := app.platform.store.listEngagementRuns(engagement.ID, 0)
	hosts, _ := app.platform.store.listEngagementHosts(engagement.ID, "", "", 8)
	ports, _ := app.platform.store.listEngagementPorts(engagement.ID, "", 8)
	findings, _ := app.platform.store.listEngagementFindings(engagement.ID, "", "all", 8)
	hosts = decorateHostLinks(view.Slug, hosts)
	ports = decoratePortLinks(view.Slug, ports)
	findings = decorateFindingLinks(view.Slug, findings)
	sourceMix := platformSourceBuckets(sources)
	runStatusMix := platformRunStatusBuckets(runs)
	sources, sourcesPager := paginatePlatformSlice(request, "recent_sources", sources)
	runs, runsPager := paginatePlatformSlice(request, "recent_runs", runs)
	members, _ := app.platform.store.listMemberships(engagement.ID)
	base := app.platformBasePage(user, view, false, "overview", "Engagement Overview", "Scope posture, live operations, and current inventory.")
	base.Pagers = platformPaginationMap(sourcesPager, runsPager)
	app.render(writer, http.StatusOK, "platform_engagement_overview", EngagementOverviewPageData{
		PlatformBasePage: base,
		Stats:            stats,
		SourceMix:        sourceMix,
		SeverityMix:      platformSeverityBuckets(findings),
		ZoneMix:          platformZoneBuckets(zones),
		PortMix:          platformPortBuckets(view.Slug, ports),
		ServiceMix:       platformServiceBuckets(view.Slug, ports),
		RunStatusMix:     runStatusMix,
		RecentSources:    sources,
		RecentRuns:       runs,
		Zones:            zones,
		TopHosts:         hosts,
		TopPorts:         ports,
		TopFindings:      findings,
		Memberships:      members,
	})
}

func (app *application) renderEngagementScope(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, err := app.platform.engagementViewByID(user, engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	seeds, _ := app.platform.store.listEngagementScopeSeeds(engagement.ID)
	targets, _ := app.platform.store.listEngagementScopeTargets(engagement.ID)
	chunks, _ := app.platform.store.listEngagementChunks(engagement.ID)
	approvals, _ := app.platform.store.listEngagementApprovals(engagement.ID)
	runs, _ := app.platform.store.listEngagementRuns(engagement.ID, 12)
	seeds, seedsPager := paginatePlatformSlice(request, "seeds", seeds)
	chunks, chunksPager := paginatePlatformSlice(request, "chunks", chunks)
	approvals, approvalsPager := paginatePlatformSlice(request, "approvals", approvals)
	base := app.platformBasePage(user, view, false, "scope", "Scope", "Normalize targets into execution-ready chunks and inspect approvals.")
	base.Pagers = platformPaginationMap(seedsPager, chunksPager, approvalsPager)
	app.render(writer, http.StatusOK, "platform_engagement_scope", EngagementScopePageData{
		PlatformBasePage: base,
		Stats:            stats,
		Seeds:            seeds,
		Targets:          targets,
		Chunks:           chunks,
		Approvals:        approvals,
		Runs:             runs,
	})
}

func (app *application) renderEngagementZones(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	zones, _ := app.platform.store.listEngagementZones(engagement.ID)
	selectedZone := strings.TrimSpace(request.URL.Query().Get("zone"))
	hosts, _ := app.platform.store.listEngagementHosts(engagement.ID, selectedZone, "", 0)
	hosts = decorateHostLinks(view.Slug, hosts)
	zoneMix := platformZoneHostBuckets(view.Slug, zones)
	zones, zonesPager := paginatePlatformSlice(request, "zones", zones)
	hosts, hostsPager := paginatePlatformSlice(request, "zone_hosts", hosts)
	base := app.platformBasePage(user, view, false, "zones", "Zones", "Navigate large inventories by scope-derived and subnet-derived groups.")
	base.Pagers = platformPaginationMap(zonesPager, hostsPager)
	app.render(writer, http.StatusOK, "platform_engagement_zones", EngagementZonesPageData{
		PlatformBasePage: base,
		Stats:            stats,
		ZoneMix:          zoneMix,
		SelectedZone:     selectedZone,
		Zones:            zones,
		Hosts:            hosts,
	})
}

func (app *application) renderEngagementSources(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	sources, _ := app.platform.store.listEngagementSources(engagement.ID, 0)
	runs, _ := app.platform.store.listEngagementRuns(engagement.ID, 0)
	scannerMix := platformSourceBuckets(sources)
	runStatusMix := platformRunStatusBuckets(runs)
	toolMix := platformRunToolBuckets(runs)
	sources, sourcesPager := paginatePlatformSlice(request, "sources", sources)
	runs, runsPager := paginatePlatformSlice(request, "runs", runs)
	base := app.platformBasePage(user, view, false, "sources", "Sources", "Imported evidence, generated scans, and run output provenance.")
	base.Pagers = platformPaginationMap(sourcesPager, runsPager)
	app.render(writer, http.StatusOK, "platform_engagement_sources", EngagementSourcesPageData{
		PlatformBasePage: base,
		Stats:            stats,
		ScannerMix:       scannerMix,
		RunStatusMix:     runStatusMix,
		ToolMix:          toolMix,
		Sources:          sources,
		Runs:             runs,
	})
}

func (app *application) renderEngagementHosts(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	zones, _ := app.platform.store.listEngagementZones(engagement.ID)
	zoneFilter := strings.TrimSpace(request.URL.Query().Get("zone"))
	query := strings.TrimSpace(request.URL.Query().Get("query"))
	hosts, _ := app.platform.store.listEngagementHosts(engagement.ID, zoneFilter, query, 0)
	hosts = decorateHostLinks(view.Slug, hosts)
	exposureMix := platformHostExposureBuckets(hosts)
	osMix := platformHostOSBuckets(hosts)
	hosts, hostsPager := paginatePlatformSlice(request, "hosts", hosts)
	zoneList, zonesPager := paginatePlatformSlice(request, "host_zones", append([]PlatformZoneView(nil), zones...))
	base := app.platformBasePage(user, view, false, "hosts", "Hosts", "Canonical host inventory organized for zone-first triage.")
	base.Pagers = platformPaginationMap(hostsPager, zonesPager)
	app.render(writer, http.StatusOK, "platform_engagement_hosts", EngagementHostsPageData{
		PlatformBasePage: base,
		Stats:            stats,
		ExposureMix:      exposureMix,
		OSMix:            osMix,
		ZoneOptions:      zoneOptions(zones, zoneFilter),
		ZoneFilter:       zoneFilter,
		Query:            query,
		Hosts:            hosts,
		Zones:            zoneList,
	})
}

func (app *application) renderEngagementHostDetail(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord, hostIP string) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	host, ok := workspace.currentSnapshot().host(strings.TrimSpace(hostIP))
	if !ok {
		http.NotFound(writer, request)
		return
	}
	runs := hostRunViews(workspace.hostJobs(host.IP, 12))
	portSummary, _ := app.platform.store.listEngagementPorts(engagement.ID, host.IP, 0)
	zones, _ := app.platform.store.listZonesForHost(engagement.ID, host.IP)
	portSummary, portsPager := paginatePlatformSlice(request, "host_ports", portSummary)
	runs, runsPager := paginatePlatformSlice(request, "recent_runs", runs)
	relatedZones, zonesPager := paginatePlatformSlice(request, "related_zones", zones)
	hostFindings, findingsPager := paginatePlatformSlice(request, "host_findings", findingGroupsForRecords([]hostRecord{{summary: host.HostSummary, detail: host}}, workspace.scanTimeByName()))
	base := app.platformBasePage(user, view, false, "hosts", host.DisplayName, "Host detail inside the engagement command center.")
	base.Pagers = platformPaginationMap(portsPager, runsPager, zonesPager, findingsPager)
	app.render(writer, http.StatusOK, "platform_engagement_host_detail", EngagementHostDetailPageData{
		PlatformBasePage: base,
		Host:             host,
		RelatedZones:     relatedZones,
		RecentRuns:       runs,
		Findings:         hostFindings,
		PortSummary:      portSummary,
	})
}

func (app *application) renderEngagementPorts(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	query := strings.TrimSpace(request.URL.Query().Get("query"))
	ports, _ := app.platform.store.listEngagementPorts(engagement.ID, query, 0)
	ports = decoratePortLinks(view.Slug, ports)
	serviceMix := platformServiceBuckets(view.Slug, ports)
	portMix := platformPortBuckets(view.Slug, ports)
	ports, portsPager := paginatePlatformSlice(request, "ports", ports)
	base := app.platformBasePage(user, view, false, "ports", "Ports", "Global service inventory grouped from host-level port evidence.")
	base.Pagers = platformPaginationMap(portsPager)
	app.render(writer, http.StatusOK, "platform_engagement_ports", EngagementPortsPageData{
		PlatformBasePage: base,
		Stats:            stats,
		ServiceMix:       serviceMix,
		PortMix:          portMix,
		Query:            query,
		Ports:            ports,
	})
}

func (app *application) renderEngagementPortDetail(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord, protocol string, port string) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	detail, ok := workspace.portDetail(protocol, port, "", "")
	if !ok {
		http.NotFound(writer, request)
		return
	}
	recentRuns := make([]PlatformRunView, 0)
	seen := map[string]struct{}{}
	for _, host := range detail.Hosts {
		for _, run := range hostRunViews(workspace.hostJobs(host.IP, 6)) {
			if _, ok := seen[run.ID]; ok {
				continue
			}
			seen[run.ID] = struct{}{}
			recentRuns = append(recentRuns, run)
		}
	}
	pagedHosts, hostsPager := paginatePlatformSlice(request, "port_hosts", detail.Hosts)
	detail.Hosts = pagedHosts
	recentRuns, runsPager := paginatePlatformSlice(request, "recent_runs", recentRuns)
	relatedFindings, findingsPager := paginatePlatformSlice(request, "port_findings", detail.RelatedFindings)
	detail.RelatedFindings = relatedFindings
	base := app.platformBasePage(user, view, false, "ports", detail.Label, "Port-level exposure and finding detail.")
	base.Pagers = platformPaginationMap(hostsPager, runsPager, findingsPager)
	app.render(writer, http.StatusOK, "platform_engagement_port_detail", EngagementPortDetailPageData{
		PlatformBasePage: base,
		Port:             detail,
		RecentRuns:       recentRuns,
	})
}

func (app *application) renderEngagementFindings(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	query := strings.TrimSpace(request.URL.Query().Get("query"))
	severity := normalizeFindingSeverityFilter(request.URL.Query().Get("severity"))
	findings, _ := app.platform.store.listEngagementFindings(engagement.ID, query, severity, 0)
	findings = decorateFindingLinks(view.Slug, findings)
	severityMix := platformSeverityBuckets(findings)
	sourceMix := platformFindingSourceBuckets(view.Slug, findings)
	findings, findingsPager := paginatePlatformSlice(request, "findings", findings)
	base := app.platformBasePage(user, view, false, "findings", "Findings", "Grouped findings attached to host ports, with host-level items under port 0.")
	base.Pagers = platformPaginationMap(findingsPager)
	app.render(writer, http.StatusOK, "platform_engagement_findings", EngagementFindingsPageData{
		PlatformBasePage: base,
		Stats:            stats,
		SeverityMix:      severityMix,
		SourceMix:        sourceMix,
		Query:            query,
		SelectedSeverity: severity,
		SeverityOptions:  severityOptions(severity),
		Findings:         findings,
	})
}

func (app *application) renderEngagementFindingDetail(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord, groupID string) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	detail, ok := workspace.findingDetail(groupID, "", "", "", "")
	if !ok {
		http.NotFound(writer, request)
		return
	}
	pagedOccurrences, occurrencesPager := paginatePlatformSlice(request, "finding_occurrences", detail.Occurrences)
	detail.Occurrences = pagedOccurrences
	recentRuns, runsPager := paginatePlatformSlice(request, "recent_runs", hostRunViews(detail.RelatedJobs))
	base := app.platformBasePage(user, view, false, "findings", detail.Group.Name, "Finding evidence grouped across hosts and ports.")
	base.Pagers = platformPaginationMap(occurrencesPager, runsPager)
	app.render(writer, http.StatusOK, "platform_engagement_finding_detail", EngagementFindingDetailPageData{
		PlatformBasePage: base,
		Finding:          detail,
		RecentRuns:       recentRuns,
	})
}

func (app *application) renderEngagementCampaigns(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord, role string) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	stats, _ := app.platform.store.engagementStats(engagement.ID)
	runs, _ := app.platform.store.listEngagementRuns(engagement.ID, 0)
	chunks, _ := app.platform.store.listEngagementChunks(engagement.ID)
	statusMix := platformRunStatusBuckets(runs)
	stageMix := platformChunkStageBuckets(chunks)
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	runs, runsPager := paginatePlatformSlice(request, "runs", runs)
	chunks, chunksPager := paginatePlatformSlice(request, "chunks", chunks)
	base := app.platformBasePage(user, view, false, "campaigns", "Campaigns", "Automatic discovery, chunk execution, and operator-triggered scans.")
	base.Pagers = platformPaginationMap(runsPager, chunksPager)
	app.render(writer, http.StatusOK, "platform_engagement_campaigns", EngagementCampaignsPageData{
		PlatformBasePage: base,
		Stats:            stats,
		StatusMix:        statusMix,
		StageMix:         stageMix,
		Runs:             runs,
		Chunks:           chunks,
		Tools:            workspace.plugins.catalog(),
		RunProfiles:      workspace.commandCenterRunProfiles(),
		Readiness:        workspace.plugins.readinessGroups(),
		Policies:         workspace.orchestrationPolicies(),
		CanOperate:       role != "viewer",
	})
}

func (app *application) renderEngagementTopology(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	topology := workspace.currentSnapshot().topology
	topNodes, nodesPager := paginatePlatformSlice(request, "top_nodes", workspace.currentSnapshot().topNodes)
	topEdges, edgesPager := paginatePlatformSlice(request, "top_edges", workspace.currentSnapshot().topEdges)
	base := app.platformBasePage(user, view, false, "topology", "Topology", "Traceroute-derived network graph inside the engagement shell.")
	base.Pagers = platformPaginationMap(nodesPager, edgesPager)
	app.render(writer, http.StatusOK, "platform_engagement_topology", EngagementTopologyPageData{
		PlatformBasePage: base,
		Summary:          topology.Summary,
		TopNodes:         topNodes,
		TopEdges:         topEdges,
		Exports: []ExportLink{
			{Label: "Graph JSON", Detail: "Topology API payload", Href: "/api/graph?workspace=" + engagement.LegacyWorkspaceID},
		},
	})
}

func (app *application) renderEngagementRecommendations(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	recommendations, recommendationsPager := paginatePlatformSlice(request, "recommendations", workspace.recommendationViews())
	approvals, approvalsPager := paginatePlatformSlice(request, "approvals", workspace.pendingApprovalViews())
	recentRuns, runsPager := paginatePlatformSlice(request, "recent_runs", hostRunViews(workspace.plugins.recentJobs(12)))
	base := app.platformBasePage(user, view, false, "recommendations", "Recommendations", "Next-step queue generated from scope, coverage, and findings.")
	base.Pagers = platformPaginationMap(recommendationsPager, approvalsPager, runsPager)
	app.render(writer, http.StatusOK, "platform_engagement_recommendations", EngagementRecommendationsPageData{
		PlatformBasePage: base,
		Recommendations:  recommendations,
		Approvals:        approvals,
		RecentRuns:       recentRuns,
	})
}

func (app *application) renderEngagementSettings(writer http.ResponseWriter, request *http.Request, user platformUserRecord, engagement platformEngagementRecord) {
	view, _ := app.platform.engagementViewByID(user, engagement.ID)
	memberships, _ := app.platform.store.listMemberships(engagement.ID)
	tools, _ := app.platform.store.listTools()
	connectors, _ := app.platform.store.listConnectors()
	memberships, membershipsPager := paginatePlatformSlice(request, "memberships", memberships)
	toolList, toolsPager := paginatePlatformSlice(request, "settings_tools", tools)
	connectorList, connectorsPager := paginatePlatformSlice(request, "settings_connectors", connectors)
	base := app.platformBasePage(user, view, false, "settings", "Settings", "Memberships, tooling posture, and engagement-level operations.")
	base.Pagers = platformPaginationMap(membershipsPager, toolsPager, connectorsPager)
	app.render(writer, http.StatusOK, "platform_engagement_settings", EngagementSettingsPageData{
		PlatformBasePage: base,
		Memberships:      memberships,
		Tools:            toolList,
		Connectors:       connectorList,
	})
}

func (app *application) requirePlatformUser(writer http.ResponseWriter, request *http.Request, adminOnly bool) (platformUserRecord, string, bool) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return platformUserRecord{}, "", false
	}
	user, token, err := app.platform.userFromRequest(request)
	if err != nil {
		if strings.HasPrefix(request.URL.Path, "/api/") {
			http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		} else {
			http.Redirect(writer, request, "/login", http.StatusSeeOther)
		}
		return platformUserRecord{}, "", false
	}
	if adminOnly && !user.IsAdmin {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return platformUserRecord{}, "", false
	}
	return user, token, true
}

func platformPaginationParam(key string, field string) string {
	if strings.TrimSpace(key) == "" {
		return field
	}
	return key + "_" + field
}

func platformPageSizeFromRequest(request *http.Request, key string) int {
	raw := strings.TrimSpace(request.URL.Query().Get(platformPaginationParam(key, "page_size")))
	if raw == "" {
		return platformPaginationSizes[0]
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return platformPaginationSizes[0]
	}
	for _, size := range platformPaginationSizes {
		if value == size {
			return size
		}
	}
	return platformPaginationSizes[0]
}

func platformPageFromRequest(request *http.Request, key string) int {
	raw := strings.TrimSpace(request.URL.Query().Get(platformPaginationParam(key, "page")))
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 1
	}
	return value
}

func platformPaginationURL(request *http.Request, key string, page int, pageSize int) string {
	values := request.URL.Query()
	values.Set(platformPaginationParam(key, "page"), strconv.Itoa(page))
	values.Set(platformPaginationParam(key, "page_size"), strconv.Itoa(pageSize))
	encoded := values.Encode()
	if encoded == "" {
		return request.URL.Path
	}
	return request.URL.Path + "?" + encoded
}

func paginatePlatformSlice[T any](request *http.Request, key string, items []T) ([]T, PlatformPaginationView) {
	pageSize := platformPageSizeFromRequest(request, key)
	page := platformPageFromRequest(request, key)
	total := len(items)
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	if page > totalPages {
		page = totalPages
	}
	startIndex := 0
	if total > 0 {
		startIndex = (page - 1) * pageSize
		if startIndex < 0 {
			startIndex = 0
		}
		if startIndex > total {
			startIndex = total
		}
	}
	endIndex := startIndex + pageSize
	if endIndex > total {
		endIndex = total
	}
	start := 0
	end := 0
	if total > 0 && endIndex >= startIndex {
		start = startIndex + 1
		end = endIndex
	}
	pager := PlatformPaginationView{
		Key:        key,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		Start:      start,
		End:        end,
		HasPrev:    page > 1 && total > 0,
		HasNext:    total > 0 && page < totalPages,
	}
	if pager.HasPrev {
		pager.PrevHref = platformPaginationURL(request, key, page-1, pageSize)
	}
	if pager.HasNext {
		pager.NextHref = platformPaginationURL(request, key, page+1, pageSize)
	}
	pager.PageSizeHrefs = make([]PlatformPaginationLink, 0, len(platformPaginationSizes))
	for _, size := range platformPaginationSizes {
		pager.PageSizeHrefs = append(pager.PageSizeHrefs, PlatformPaginationLink{
			Label:  strconv.Itoa(size),
			Href:   platformPaginationURL(request, key, 1, size),
			Active: size == pageSize,
		})
	}
	if total == 0 {
		return items[:0], pager
	}
	return items[startIndex:endIndex], pager
}

func platformPaginationMap(items ...PlatformPaginationView) map[string]PlatformPaginationView {
	if len(items) == 0 {
		return nil
	}
	result := make(map[string]PlatformPaginationView, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.Key) == "" {
			continue
		}
		result[item.Key] = item
	}
	return result
}

func activateNavGroups(groups []PlatformNavGroup) []PlatformNavGroup {
	for index := range groups {
		for _, item := range groups[index].Items {
			if item.Active {
				groups[index].Active = true
				break
			}
		}
	}
	return groups
}

func (app *application) platformBasePage(user platformUserRecord, engagement PlatformEngagementView, adminArea bool, section string, title string, description string) PlatformBasePage {
	engagementSwitch, _ := app.platform.engagementViewsForUser(user)
	adminNav := []PlatformNavLink{
		{Label: "System", Href: "/admin", Active: adminArea && section == "admin", Description: "Global health, workers, audit, and overview."},
		{Label: "Users", Href: "/admin/users", Active: adminArea && section == "users", Description: "Accounts and platform roles."},
		{Label: "Engagements", Href: "/admin/engagements", Active: (adminArea && section == "engagements") || (!adminArea && section == "engagements"), Description: "Engagement registry and creation."},
		{Label: "Tools", Href: "/admin/tools", Active: adminArea && section == "tools", Description: "Tool, connector, and worker readiness."},
	}
	engagementNav := []PlatformNavLink{}
	adminGroups := activateNavGroups([]PlatformNavGroup{
		{
			Label:       "Control",
			Description: "Platform posture and registry.",
			Items: []PlatformNavLink{
				adminNav[0],
				adminNav[2],
			},
		},
		{
			Label:       "Access",
			Description: "Users and platform permissions.",
			Items: []PlatformNavLink{
				adminNav[1],
			},
		},
		{
			Label:       "Runtime",
			Description: "Tools, connectors, and workers.",
			Items: []PlatformNavLink{
				adminNav[3],
			},
		},
	})
	engagementGroups := []PlatformNavGroup{}
	topMenuGroups := adminGroups
	primaryTabs := adminNav
	if engagement.ID != "" {
		engagementNav = []PlatformNavLink{
			{Label: "Overview", Href: engagement.OverviewHref, Active: !adminArea && section == "overview"},
			{Label: "Scope", Href: engagement.ScopeHref, Active: !adminArea && section == "scope"},
			{Label: "Zones", Href: engagement.ZonesHref, Active: !adminArea && section == "zones"},
			{Label: "Campaigns", Href: engagement.CampaignsHref, Active: !adminArea && section == "campaigns"},
			{Label: "Sources", Href: engagement.SourcesHref, Active: !adminArea && section == "sources"},
			{Label: "Hosts", Href: engagement.HostsHref, Active: !adminArea && section == "hosts"},
			{Label: "Ports", Href: engagement.PortsHref, Active: !adminArea && section == "ports"},
			{Label: "Findings", Href: engagement.FindingsHref, Active: !adminArea && section == "findings"},
			{Label: "Topology", Href: "/engagements/" + engagement.Slug + "/topology", Active: !adminArea && section == "topology"},
			{Label: "Recommendations", Href: "/engagements/" + engagement.Slug + "/recommendations", Active: !adminArea && section == "recommendations"},
			{Label: "Settings", Href: engagement.SettingsHref, Active: !adminArea && section == "settings"},
		}
		engagementGroups = activateNavGroups([]PlatformNavGroup{
			{
				Label:       "Engagement",
				Description: "Mission setup, evidence lanes, and governance.",
				Items: []PlatformNavLink{
					engagementNav[0],
					engagementNav[1],
					engagementNav[4],
					engagementNav[10],
				},
			},
			{
				Label:       "Operations",
				Description: "Campaign control and guided follow-up.",
				Items: []PlatformNavLink{
					engagementNav[3],
					engagementNav[9],
				},
			},
			{
				Label:       "Inventory",
				Description: "Zone-first triage and asset drill-downs.",
				Items: []PlatformNavLink{
					engagementNav[2],
					engagementNav[5],
					engagementNav[6],
					engagementNav[7],
				},
			},
			{
				Label:       "Analysis",
				Description: "Network graph and cross-surface context.",
				Items: []PlatformNavLink{
					engagementNav[8],
				},
			},
		})
		topMenuGroups = engagementGroups
		primaryTabs = engagementNav
	} else if !adminArea {
		registryLink := PlatformNavLink{
			Label:       "Engagements",
			Href:        "/engagements",
			Active:      section == "engagements",
			Description: "Choose an engagement and enter its command center.",
		}
		topMenuGroups = activateNavGroups([]PlatformNavGroup{
			{
				Label:       "Registry",
				Description: "Browse and switch engagements.",
				Items:       []PlatformNavLink{registryLink},
			},
		})
		primaryTabs = []PlatformNavLink{registryLink}
	}
	return PlatformBasePage{
		Page: PlatformPageMeta{
			Title:       title,
			Description: description,
			Section:     section,
		},
		CurrentUser:      platformUserView(user),
		AdminNav:         adminNav,
		EngagementNav:    engagementNav,
		AdminGroups:      adminGroups,
		EngagementGroups: engagementGroups,
		TopMenuGroups:    topMenuGroups,
		PrimaryTabs:      primaryTabs,
		EngagementSwitch: engagementSwitch,
		Engagement:       engagement,
		IsAdminArea:      adminArea,
	}
}

func platformUserView(item platformUserRecord) PlatformUserView {
	role := "user"
	if item.IsAdmin {
		role = "admin"
	}
	return PlatformUserView{
		ID:          item.ID,
		Username:    item.Username,
		Email:       item.Email,
		DisplayName: item.DisplayName,
		Role:        role,
		Status:      item.Status,
		IsAdmin:     item.IsAdmin,
		CreatedAt:   displayTimestamp(item.CreatedAt),
		LastLoginAt: displayTimestamp(item.LastLoginAt),
	}
}

func (p *platformService) engagementViewsForUser(user platformUserRecord) ([]PlatformEngagementView, error) {
	counts, err := p.store.engagementCounts()
	if err != nil {
		return nil, err
	}
	records, err := p.store.listEngagementsForUser(user)
	if err != nil {
		return nil, err
	}
	items := make([]PlatformEngagementView, 0, len(records))
	for _, record := range records {
		view := counts[record.ID]
		if view.ID == "" {
			view = PlatformEngagementView{
				ID:           record.ID,
				Slug:         record.Slug,
				Name:         record.Name,
				Description:  record.Description,
				ScopeSummary: record.ScopeSummary,
				Status:       record.Status,
				WorkspaceID:  record.LegacyWorkspaceID,
				CreatedAt:    displayTimestamp(record.CreatedAt),
				UpdatedAt:    displayTimestamp(record.UpdatedAt),
			}
		}
		items = append(items, view)
	}
	return items, nil
}

func (p *platformService) engagementViewByID(user platformUserRecord, engagementID string) (PlatformEngagementView, error) {
	items, err := p.engagementViewsForUser(user)
	if err != nil {
		return PlatformEngagementView{}, err
	}
	for _, item := range items {
		if item.ID == engagementID {
			return item, nil
		}
	}
	return PlatformEngagementView{}, http.ErrNoCookie
}

func platformSourceBuckets(items []PlatformSourceView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.Scanner, item.Kind, "unknown")]++
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformSeverityBuckets(items []PlatformFindingView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[severityLabel(item.Severity)] += item.Occurrences
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformZoneBuckets(items []PlatformZoneView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[item.Kind] += item.HostCount
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformZoneHostBuckets(slug string, items []PlatformZoneView) []Bucket {
	results := make([]Bucket, 0, len(items))
	for _, item := range items {
		if item.HostCount <= 0 {
			continue
		}
		results = append(results, Bucket{
			Label: item.Name,
			Count: item.HostCount,
			Href:  "/engagements/" + slug + "/zones?zone=" + url.QueryEscape(item.ID),
		})
	}
	return results
}

func platformPortBuckets(slug string, items []PlatformPortView) []Bucket {
	results := make([]Bucket, 0, len(items))
	for _, item := range items {
		if item.Hosts <= 0 {
			continue
		}
		results = append(results, Bucket{
			Label: item.Label,
			Count: item.Hosts,
			Href:  item.Href,
		})
	}
	return results
}

func platformServiceBuckets(slug string, items []PlatformPortView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.Service, "unknown service")] += item.Hosts
	}
	return sortedBucketCounts(counts, func(label string) string {
		return "/engagements/" + slug + "/ports?query=" + url.QueryEscape(label)
	})
}

func platformRunStatusBuckets(items []PlatformRunView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.Status, "unknown")]++
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformRunToolBuckets(items []PlatformRunView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.ToolLabel, item.ToolID, "unknown")]++
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformChunkStageBuckets(items []TargetChunkView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.Stage, "unknown")]++
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformHostExposureBuckets(items []PlatformHostView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.Exposure, "unknown")]++
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformHostOSBuckets(items []PlatformHostView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.OS, "unknown")]++
	}
	return sortedBucketCounts(counts, func(label string) string { return "" })
}

func platformFindingSourceBuckets(slug string, items []PlatformFindingView) []Bucket {
	counts := map[string]int{}
	for _, item := range items {
		counts[chooseString(item.Source, "unknown")] += item.Occurrences
	}
	return sortedBucketCounts(counts, func(label string) string {
		return "/engagements/" + slug + "/findings?query=" + url.QueryEscape(label)
	})
}

func zoneOptions(items []PlatformZoneView, selected string) []SelectOption {
	options := []SelectOption{{Value: "", Label: "All zones", Selected: selected == ""}}
	for _, item := range items {
		options = append(options, SelectOption{
			Value:    item.ID,
			Label:    item.Name + " (" + strconv.Itoa(item.HostCount) + ")",
			Selected: selected == item.ID,
		})
	}
	return options
}

func severityOptions(selected string) []SelectOption {
	items := []string{"all", "critical", "high", "medium", "low", "info"}
	options := make([]SelectOption, 0, len(items))
	for _, item := range items {
		label := strings.Title(item)
		if item == "all" {
			label = "All severities"
		}
		options = append(options, SelectOption{
			Value:    item,
			Label:    label,
			Selected: item == selected || (selected == "" && item == "all"),
		})
	}
	return options
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}

func hostRunViews(items []PluginJobView) []PlatformRunView {
	results := make([]PlatformRunView, 0, len(items))
	for _, item := range items {
		results = append(results, PlatformRunView{
			ID:          item.ID,
			ToolID:      item.PluginID,
			ToolLabel:   item.PluginLabel,
			Status:      item.Status,
			StatusTone:  item.StatusTone,
			Stage:       item.Stage,
			ChunkName:   item.ChunkID,
			TargetCount: item.TargetCount,
			Summary:     item.Summary,
			Error:       item.Error,
			CreatedAt:   item.CreatedAt,
			StartedAt:   item.StartedAt,
			FinishedAt:  item.FinishedAt,
			WorkerMode:  item.WorkerMode,
			WorkerZone:  item.WorkerZone,
		})
	}
	return results
}

func decorateHostLinks(slug string, items []PlatformHostView) []PlatformHostView {
	for index := range items {
		items[index].Href = "/engagements/" + slug + "/hosts/" + url.PathEscape(items[index].IP)
	}
	return items
}

func decoratePortLinks(slug string, items []PlatformPortView) []PlatformPortView {
	for index := range items {
		items[index].Href = "/engagements/" + slug + "/ports/" + url.PathEscape(items[index].Protocol) + "/" + url.PathEscape(items[index].Port)
	}
	return items
}

func decorateFindingLinks(slug string, items []PlatformFindingView) []PlatformFindingView {
	for index := range items {
		items[index].Href = "/engagements/" + slug + "/findings/" + url.PathEscape(items[index].ID)
	}
	return items
}
