package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type application struct {
	logger    *slog.Logger
	templates *template.Template
	center    *commandCenter
	workspace *workspace
	platform  *platformService
}

func (app *application) routes() (http.Handler, error) {
	mux := http.NewServeMux()

	cssFS, err := embeddedSubdir("web/css")
	if err != nil {
		return nil, err
	}
	jsFS, err := embeddedSubdir("web/js")
	if err != nil {
		return nil, err
	}
	imageFS, err := embeddedSubdir("web/images")
	if err != nil {
		return nil, err
	}

	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.FS(cssFS))))
	mux.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.FS(jsFS))))
	mux.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.FS(imageFS))))
	mux.HandleFunc("/artifacts/", app.handleArtifact)
	mux.HandleFunc("/app", app.handleReactApp)
	mux.HandleFunc("/app/", app.handleReactApp)

	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/admin", app.handleAdminOverview)
	mux.HandleFunc("/admin/users", app.handleAdminUsers)
	mux.HandleFunc("/admin/engagements", app.handleAdminEngagements)
	mux.HandleFunc("/admin/tools", app.handleAdminTools)
	mux.HandleFunc("/engagements", app.handleEngagementsIndex)
	mux.HandleFunc("/engagements/", app.handleEngagementRouter)
	mux.HandleFunc("/api/v1/session", app.handleSessionJSON)
	mux.HandleFunc("/api/v1/session/login", app.handleSessionLoginJSON)
	mux.HandleFunc("/api/v1/session/logout", app.handleSessionLogoutJSON)
	mux.HandleFunc("/api/v1/engagements", app.handleEngagementsJSON)
	mux.HandleFunc("/api/v1/admin/health", app.handlePlatformHealthJSON)
	mux.HandleFunc("/api/v1/admin/tools", app.handleAdminToolsJSON)
	mux.HandleFunc("/api/v1/admin/tools/", app.handleAdminToolJSON)
	mux.HandleFunc("/api/v1/engagements/", app.handleEngagementInventoryJSON)
	mux.HandleFunc("/workspaces", app.handleWorkspaces)
	mux.HandleFunc("/workspaces/create", app.handleWorkspaceCreate)
	mux.HandleFunc("/workspaces/select", app.handleWorkspaceSelect)
	mux.HandleFunc("/workspaces/import", app.handleWorkspaceImport)
	mux.HandleFunc("/workspaces/export", app.handleWorkspaceExport)
	mux.HandleFunc("/overview", app.handleOverview)
	mux.HandleFunc("/workspace", app.handleWorkspace)
	mux.HandleFunc("/sources", app.handleWorkspace)
	mux.HandleFunc("/workspace/import", app.handleScanImport)
	mux.HandleFunc("/workspace/preferences", app.handleWorkspacePreferences)
	mux.HandleFunc("/scope", app.handleScope)
	mux.HandleFunc("/scope/kickoff", app.handleScopeKickoff)
	mux.HandleFunc("/campaigns", app.handleCampaigns)
	mux.HandleFunc("/approvals/approve", app.handleApprovalApprove)
	mux.HandleFunc("/recommendations", app.handleRecommendations)
	mux.HandleFunc("/recommendations/llm", app.handleRecommendationLLM)

	mux.HandleFunc("/scans/import", app.handleScanImport)
	mux.HandleFunc("/scans/download", app.handleScanDownload)
	mux.HandleFunc("/scans/", app.handleScanDetail)
	mux.HandleFunc("/scans", app.handleScansIndex)

	mux.HandleFunc("/hosts/annotate", app.handleHostAnnotate)
	mux.HandleFunc("/hosts/", app.handleHostDetail)
	mux.HandleFunc("/hosts", app.handleHostsIndex)

	mux.HandleFunc("/ports/", app.handlePortDetail)
	mux.HandleFunc("/ports", app.handlePortsIndex)

	mux.HandleFunc("/findings/", app.handleFindingDetail)
	mux.HandleFunc("/findings", app.handleFindingsIndex)

	mux.HandleFunc("/changes", app.handleChanges)
	mux.HandleFunc("/topology", app.handleTopology)
	mux.HandleFunc("/graph", app.handleGraphAlias)
	mux.HandleFunc("/ip/", app.handleIPAlias)
	mux.HandleFunc("/all", app.handleAllAlias)
	mux.HandleFunc("/list", app.handleListAlias)

	mux.HandleFunc("/api/explorer", app.handleExplorerJSON)
	mux.HandleFunc("/api/diff", app.handleDiffJSON)
	mux.HandleFunc("/api/observations", app.handleObservationsJSON)
	mux.HandleFunc("/api/graph", app.handleTopologyJSON)
	mux.HandleFunc("/json/", app.handleTraceJSON)

	mux.HandleFunc("/exports/hosts.txt", app.handleHostExport)
	mux.HandleFunc("/exports/hosts.csv", app.handleCSVExport)
	mux.HandleFunc("/exports/nuclei.txt", app.handleNucleiExport)

	mux.HandleFunc("/views/save", app.handleSaveView)
	mux.HandleFunc("/campaigns/create", app.handleCampaignCreate)
	mux.HandleFunc("/plugins/run", app.handlePluginRun)
	mux.HandleFunc("/search", app.handleSearchRedirect)
	mux.HandleFunc("/healthz", app.handleHealth)

	return app.logRequests(mux), nil
}

func (app *application) handleRoot(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if app.platform != nil {
		user, _, err := app.platform.userFromRequest(request)
		if err != nil {
			http.Redirect(writer, request, "/login", http.StatusSeeOther)
			return
		}
		if user.IsAdmin {
			http.Redirect(writer, request, "/admin", http.StatusSeeOther)
			return
		}
		http.Redirect(writer, request, "/engagements", http.StatusSeeOther)
		return
	}

	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}

	target := "/workspace"
	status := workspace.workspaceStatus()
	if status.HasImportedScans {
		switch workspace.preferences().DefaultLanding {
		case "workspace":
			target = "/workspace"
		case "hosts":
			target = "/hosts"
		default:
			target = "/overview"
		}
	}
	http.Redirect(writer, request, target, http.StatusSeeOther)
}

func (app *application) handleOverview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	snapshot := workspace.currentSnapshot()
	latestDiff, hasLatestDiff := workspace.latestChange()
	findings := workspace.findingGroups()
	if len(findings) > 8 {
		findings = findings[:8]
	}

	data := OverviewPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"overview",
			"Overview",
			"Workspace summary, activity, findings, and latest change.",
			SearchState{},
			[]Breadcrumb{{Label: "Overview", Href: "/overview"}},
			nil,
		),
		ExecutiveSummary: snapshot.summaryLine,
		Stats:            snapshot.stats,
		TopPorts:         snapshot.portBuckets,
		TopOS:            snapshot.osBuckets,
		TopServices:      snapshot.serviceBuckets,
		FindingTotals:    snapshot.findingTotals,
		RecentScans:      workspace.recentScans(6),
		RecentFindings:   findings,
		LatestDiff:       latestDiff,
		HasLatestDiff:    hasLatestDiff,
		PriorityHosts:    snapshot.highExposure,
		Observations:     workspace.recentObservations(6),
	}
	app.render(writer, http.StatusOK, "overview", data)
}

func (app *application) handleWorkspace(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	snapshot := workspace.currentSnapshot()
	preferences := workspace.preferences()
	scans := workspace.recentScans(6)
	jobs := workspace.plugins.recentJobs(64)
	data := WorkspacePageData{
		CommonPageData: app.commonPageData(
			workspace,
			"workspace",
			"Workspace",
			"Engagement operations, source intake, managed runs, settings, and workspace activity.",
			SearchState{},
			[]Breadcrumb{{Label: "Workspace", Href: "/workspace"}},
			nil,
		),
		ExecutiveSummary: snapshot.summaryLine,
		Preferences: WorkspacePreferenceView{
			DefaultLanding: preferences.DefaultLanding,
			LandingOptions: landingOptions(preferences.DefaultLanding),
		},
		Scans:         scans,
		Plugins:       workspace.plugins.catalog(),
		RecentJobs:    workspace.plugins.recentJobs(8),
		Jobs:          jobs,
		FindingTotals: snapshot.findingTotals,
		HighExposure:  snapshot.highExposure,
		TopFindings:   snapshot.topFindings,
		SourceMix:     scannerBuckets(workspace.scanCatalog()),
		CoverageMix:   coverageBuckets(snapshot),
		JobStatus:     jobStatusBuckets(jobs),
		RunProfiles:   recommendedRunProfiles(snapshot),
		SavedViews:    workspace.savedViewCatalog(),
		Campaigns:     workspace.campaignCatalog(),
		Observations:  workspace.recentObservations(18),
		Readiness:     workspace.plugins.readinessGroups(),
		IsEmpty:       !workspace.workspaceStatus().HasImportedScans,
	}
	app.render(writer, http.StatusOK, "workspace", data)
}

func (app *application) handleWorkspacePreferences(writer http.ResponseWriter, request *http.Request) {
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
	if err := workspace.setDefaultLanding(request.FormValue("default_landing")); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, "/workspace", http.StatusSeeOther)
}

func (app *application) handleScansIndex(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/scans" {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	data := ScanIndexPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"scans",
			"Scans",
			"Imported source records for the current workspace, treated as provenance and coverage history rather than the primary investigation surface.",
			SearchState{},
			[]Breadcrumb{{Label: "Scans", Href: "/scans"}},
			nil,
		),
		Scans: workspace.scanCatalog(),
	}
	app.render(writer, http.StatusOK, "scans_index", data)
}

func (app *application) handleScanDetail(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/scans/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	scan, found := workspace.scanDetail(id)
	if !found {
		http.NotFound(writer, request)
		return
	}

	data := ScanPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"scans",
			"Scan · "+scan.Summary.Name,
			"Scan-local host observations, ports, findings, and provenance for a single imported source.",
			SearchState{},
			[]Breadcrumb{
				{Label: "Scans", Href: "/scans"},
				{Label: scan.Summary.Name, Href: "/scans/" + scan.Summary.ID},
			},
			[]ExplorerPathStep{{Kind: "scan", ID: scan.Summary.ID}},
		),
		Scan:    scan,
		Plugins: workspace.plugins.catalog(),
	}
	app.render(writer, http.StatusOK, "scan", data)
}

func (app *application) handleHostsIndex(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/hosts" {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	snapshot := workspace.currentSnapshot()
	filter := parseHostFilter(request, defaultPageSize)
	latestDiff, hasLatestDiff := workspace.latestChange()
	filteredRecords := snapshot.recordsForFilter(filter)
	filteredPorts := buildBuckets(filteredRecords, "port")
	filteredOS := buildBuckets(filteredRecords, "os")
	filteredServices := buildBuckets(filteredRecords, "service")
	data := HostsPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"hosts",
			"Hosts",
			"Canonical merged host inventory for the workspace, with analyst filters, exports, and saved cuts.",
			SearchState{Query: filter.Query, Scope: filter.Scope, Sort: filter.Sort},
			[]Breadcrumb{{Label: "Hosts", Href: "/hosts"}},
			nil,
		),
		ExecutiveSummary: snapshot.summaryLine,
		Stats:            snapshot.stats,
		SliceStats:       buildStatCards(filteredRecords, filteredPorts, filteredOS, filteredServices),
		TopPorts:         filteredPorts,
		TopOS:            filteredOS,
		TopServices:      filteredServices,
		FindingTotals:    summarizeFindingsForRecords(filteredRecords),
		ScopeOptions:     scopeOptions(filter.Scope),
		SortOptions:      sortOptions(filter.Sort),
		PageSizeOptions:  pageSizeOptions(filter.PageSize),
		Filter:           filter,
		Results:          rebaseHostPage("/hosts", filter, snapshot.searchHosts(filter)),
		SavedViews:       workspace.savedViewCatalog(),
		Exports:          snapshot.exportLinks(filter),
		LatestDiff:       latestDiff,
		HasLatestDiff:    hasLatestDiff,
	}
	app.render(writer, http.StatusOK, "hosts", data)
}

func (app *application) handleHostDetail(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimPrefix(request.URL.Path, "/hosts/")
	if ip == "" || strings.Contains(ip, "/") {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	snapshot := workspace.currentSnapshot()
	host, found := snapshot.host(ip)
	if !found {
		http.NotFound(writer, request)
		return
	}
	host.Observations = workspace.hostObservations(ip, 20)

	var (
		scope       *HostScopeView
		expandPath  []ExplorerPathStep
		breadcrumbs = []Breadcrumb{{Label: "Hosts", Href: "/hosts"}}
	)
	if scanID := strings.TrimSpace(request.URL.Query().Get("scan")); scanID != "" {
		if scopedHost, found := workspace.scanScopedHost(scanID, ip); found {
			if scanItem, exists := workspace.scanCatalogItem(scanID); exists {
				scope = &HostScopeView{
					Active:            true,
					Scan:              scanItem,
					ObservedOpenPorts: scopedHost.OpenPortCount,
					ObservedFindings:  scopedHost.Findings,
					ObservedPorts:     scopedHost.Ports,
				}
				breadcrumbs = append(breadcrumbs,
					Breadcrumb{Label: "Scans", Href: "/scans"},
					Breadcrumb{Label: scanItem.Name, Href: "/scans/" + scanItem.ID},
				)
				expandPath = []ExplorerPathStep{
					{Kind: "scan", ID: scanItem.ID},
					{Kind: "scan-host", ID: scanItem.ID + "|" + ip},
				}
			}
		}
	}
	breadcrumbs = append(breadcrumbs, Breadcrumb{Label: chooseString(host.DisplayName, ip), Href: "/hosts/" + ip})

	data := HostPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"hosts",
			"Host · "+ip,
			"Canonical host dossier with merged services, findings, route data, provenance, and analyst annotations.",
			SearchState{},
			breadcrumbs,
			expandPath,
		),
		Host:    host,
		Plugins: workspace.plugins.catalog(),
		Jobs:    workspace.hostJobs(ip, 5),
		Scope:   scope,
	}
	app.render(writer, http.StatusOK, "host", data)
}

func (app *application) handlePortsIndex(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/ports" {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	query := strings.TrimSpace(request.URL.Query().Get("query"))
	sortBy := normalizePortSort(request.URL.Query().Get("sort"))
	rows := workspace.filteredPortSummaries(query, sortBy)

	data := PortIndexPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"ports",
			"Ports",
			"Global port inventory across the current workspace, grouped by protocol and port number to highlight recurring exposure.",
			SearchState{Query: query, Scope: "port"},
			[]Breadcrumb{{Label: "Ports", Href: "/ports"}},
			nil,
		),
		Query:           query,
		Stats:           portStats(rows),
		SortOptions:     portSortOptions(sortBy),
		ServiceBuckets:  portServiceBuckets(rows),
		ExposureBuckets: portExposureBuckets(rows),
		HostBuckets:     portHostBuckets(rows),
		Ports:           rows,
	}
	app.render(writer, http.StatusOK, "ports", data)
}

func (app *application) handlePortDetail(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/ports/"), "/")
	if len(parts) != 2 {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	protocol, port := parts[0], parts[1]
	scanID := strings.TrimSpace(request.URL.Query().Get("scan"))
	hostIP := strings.TrimSpace(request.URL.Query().Get("host"))
	detail, found := workspace.portDetail(protocol, port, scanID, hostIP)
	if !found {
		http.NotFound(writer, request)
		return
	}

	breadcrumbs := []Breadcrumb{{Label: "Ports", Href: "/ports"}}
	var expandPath []ExplorerPathStep
	if scanID != "" && hostIP != "" {
		if scanItem, found := workspace.scanCatalogItem(scanID); found {
			breadcrumbs = append(breadcrumbs,
				Breadcrumb{Label: "Scans", Href: "/scans"},
				Breadcrumb{Label: scanItem.Name, Href: "/scans/" + scanItem.ID},
				Breadcrumb{Label: hostIP, Href: "/hosts/" + hostIP + "?scan=" + url.QueryEscape(scanID)},
			)
			expandPath = []ExplorerPathStep{
				{Kind: "scan", ID: scanID},
				{Kind: "scan-host", ID: scanID + "|" + hostIP},
				{Kind: "scan-port", ID: strings.Join([]string{scanID, hostIP, protocol, port}, "|")},
			}
		}
	}
	breadcrumbs = append(breadcrumbs, Breadcrumb{Label: detail.Label, Href: "/ports/" + protocol + "/" + port})

	data := PortPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"ports",
			"Port · "+detail.Label,
			"Port-centric view of exposure, affected hosts, related findings, and provenance across the workspace.",
			SearchState{},
			breadcrumbs,
			expandPath,
		),
		Port:             detail,
		IntegrationLanes: workspace.portIntegrationLanes(detail),
	}
	app.render(writer, http.StatusOK, "port", data)
}

func (app *application) handleFindingsIndex(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/findings" {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	query := strings.TrimSpace(request.URL.Query().Get("query"))
	severity := normalizeFindingSeverityFilter(request.URL.Query().Get("severity"))
	source := strings.TrimSpace(request.URL.Query().Get("source"))
	sortBy := normalizeFindingSort(request.URL.Query().Get("sort"))
	allGroups := workspace.findingGroups()
	groups := workspace.filteredFindingGroups(query, severity, source, sortBy)

	data := FindingsPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"findings",
			"Findings",
			"Grouped findings index keyed by finding definition rather than raw occurrences, spanning imported integrations and workspace enrichments.",
			SearchState{Query: query},
			[]Breadcrumb{{Label: "Findings", Href: "/findings"}},
			nil,
		),
		Query:            query,
		SelectedSeverity: severity,
		SelectedSource:   source,
		Stats:            findingStats(groups),
		SeverityOptions:  findingSeverityOptions(severity),
		SourceOptions:    findingSourceOptions(allGroups, source),
		SortOptions:      findingSortOptions(sortBy),
		SeverityBuckets:  findingSeverityBuckets(groups),
		SourceBuckets:    findingSourceBuckets(groups),
		PortBuckets:      workspace.filteredFindingPortBuckets(query, severity, source),
		Findings:         groups,
	}
	app.render(writer, http.StatusOK, "findings", data)
}

func (app *application) handleFindingDetail(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	groupID := strings.TrimPrefix(request.URL.Path, "/findings/")
	if groupID == "" || strings.Contains(groupID, "/") {
		http.NotFound(writer, request)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	scanID := strings.TrimSpace(request.URL.Query().Get("scan"))
	hostIP := strings.TrimSpace(request.URL.Query().Get("host"))
	protocol := strings.TrimSpace(request.URL.Query().Get("protocol"))
	port := strings.TrimSpace(request.URL.Query().Get("port"))
	detail, found := workspace.findingDetail(groupID, scanID, hostIP, protocol, port)
	if !found {
		http.NotFound(writer, request)
		return
	}

	breadcrumbs := []Breadcrumb{{Label: "Findings", Href: "/findings"}}
	var expandPath []ExplorerPathStep
	if scanID != "" && hostIP != "" && protocol != "" && port != "" {
		if scanItem, found := workspace.scanCatalogItem(scanID); found {
			breadcrumbs = append(breadcrumbs,
				Breadcrumb{Label: "Scans", Href: "/scans"},
				Breadcrumb{Label: scanItem.Name, Href: "/scans/" + scanItem.ID},
				Breadcrumb{Label: hostIP, Href: "/hosts/" + hostIP + "?scan=" + url.QueryEscape(scanID)},
				Breadcrumb{Label: protocol + "/" + port, Href: "/ports/" + protocol + "/" + port + "?scan=" + url.QueryEscape(scanID) + "&host=" + url.QueryEscape(hostIP)},
			)
			expandPath = []ExplorerPathStep{
				{Kind: "scan", ID: scanID},
				{Kind: "scan-host", ID: scanID + "|" + hostIP},
				{Kind: "scan-port", ID: strings.Join([]string{scanID, hostIP, protocol, port}, "|")},
			}
		}
	}
	breadcrumbs = append(breadcrumbs, Breadcrumb{Label: detail.Group.Name, Href: "/findings/" + detail.Group.ID})

	data := FindingPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"findings",
			"Finding · "+detail.Group.Name,
			"Finding definition detail with affected hosts, ports, related scans, and job context.",
			SearchState{},
			breadcrumbs,
			expandPath,
		),
		Finding:          detail,
		HostTargets:      findingHostTargets(detail),
		IntegrationLanes: workspace.findingIntegrationLanes(detail),
	}
	app.render(writer, http.StatusOK, "finding", data)
}

func (app *application) handleChanges(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	diff, compare, checkpoints, hasHistory := workspace.changeComparison(
		strings.TrimSpace(request.URL.Query().Get("from")),
		strings.TrimSpace(request.URL.Query().Get("to")),
	)
	data := ChangesPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"changes",
			"Changes",
			"Replay checkpoints and compare host, port, finding, and route drift across the active workspace.",
			SearchState{},
			[]Breadcrumb{{Label: "Changes", Href: "/changes"}},
			nil,
		),
		Compare:     compare,
		Diff:        diff,
		Checkpoints: checkpoints,
		HasHistory:  hasHistory,
		Exports: []ExportLink{
			{Label: "Diff JSON", Detail: "Current comparison as JSON for notebooks or external automation.", Href: "/api/diff?" + changeQuery(compare.FromID, compare.ToID)},
			{Label: "Host inventory CSV", Detail: "Current merged host inventory.", Href: "/exports/hosts.csv"},
			{Label: "Sources", Detail: "Source catalog, jobs, and observation ledger.", Href: "/sources"},
		},
		Plugins:              workspace.plugins.catalog(),
		Campaigns:            workspace.campaignCatalog(),
		CampaignScopeOptions: campaignScopeOptions("all-changed"),
	}
	app.render(writer, http.StatusOK, "changes", data)
}

func (app *application) handleTopology(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if !app.redirectToWorkspaceWhenEmpty(workspace, writer, request) {
		return
	}

	snapshot := workspace.currentSnapshot()
	data := GraphPageData{
		CommonPageData: app.commonPageData(
			workspace,
			"topology",
			"Topology",
			"Aggregated traceroute topology for route analysis, chokepoint review, and graph export.",
			SearchState{},
			[]Breadcrumb{{Label: "Topology", Href: "/topology"}},
			nil,
		),
		Summary:  snapshot.topology.Summary,
		TopNodes: snapshot.topNodes,
		TopEdges: snapshot.topEdges,
		Exports: []ExportLink{
			{Label: "Graph JSON", Detail: "Aggregated topology graph for external tooling.", Href: "/api/graph"},
			{Label: "Nuclei targets", Detail: "HTTP surfaces inferred from the full workspace.", Href: "/exports/nuclei.txt"},
			{Label: "Host inventory CSV", Detail: "Dense inventory for notebooks or spreadsheets.", Href: "/exports/hosts.csv"},
		},
	}
	app.render(writer, http.StatusOK, "topology", data)
}

func (app *application) handleScanImport(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}

	if err := request.ParseMultipartForm(64 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(request.FormValue("name"))
	path := strings.TrimSpace(request.FormValue("path"))
	switch {
	case path != "":
		if _, err := workspace.importScanFromPath(path, "filesystem", chooseString(name, filepath.Base(path))); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		file, header, err := request.FormFile("scan_file")
		if err != nil {
			http.Error(writer, "missing scan file or path", http.StatusBadRequest)
			return
		}
		defer file.Close()

		if _, err := workspace.importUploadedScan(chooseString(name, header.Filename), file); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
	}

	http.Redirect(writer, request, chooseString(request.FormValue("return_to"), "/sources"), http.StatusSeeOther)
}

func (app *application) handleScanDownload(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	name, ext, payload, found := workspace.scanContent(request.URL.Query().Get("id"))
	if !found {
		http.NotFound(writer, request)
		return
	}
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeDownloadName(name, ext)))
	_, _ = writer.Write(payload)
}

func (app *application) handleSaveView(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	filter := HostFilter{
		Query:    strings.TrimSpace(request.FormValue("query")),
		Scope:    request.FormValue("scope"),
		Sort:     request.FormValue("sort"),
		Page:     1,
		PageSize: formInt(request, "page_size", defaultPageSize),
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if _, err := workspace.saveView(request.FormValue("name"), filter); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(writer, request, chooseString(request.FormValue("return_to"), request.Referer(), "/hosts"), http.StatusSeeOther)
}

func (app *application) handleHostAnnotate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	hostIP := strings.TrimSpace(request.FormValue("host"))
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if err := workspace.annotateHost(hostIP, parseTagList(request.FormValue("tags")), request.FormValue("note")); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(writer, request, chooseString(request.FormValue("return_to"), "/hosts/"+hostIP), http.StatusSeeOther)
}

func (app *application) handleCampaignCreate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	options := map[string]string{
		"severity":        strings.TrimSpace(request.FormValue("severity")),
		"templates":       strings.TrimSpace(request.FormValue("templates")),
		"concurrency":     strings.TrimSpace(request.FormValue("concurrency")),
		"profile":         strings.TrimSpace(request.FormValue("profile")),
		"profile_scope":   strings.TrimSpace(request.FormValue("profile_scope")),
		"ports":           strings.TrimSpace(request.FormValue("ports")),
		"crawl_depth":     strings.TrimSpace(request.FormValue("crawl_depth")),
		"level":           strings.TrimSpace(request.FormValue("level")),
		"risk":            strings.TrimSpace(request.FormValue("risk")),
		"api_base_url":    strings.TrimSpace(request.FormValue("api_base_url")),
		"scan_id":         strings.TrimSpace(request.FormValue("scan_id")),
		"site_id":         strings.TrimSpace(request.FormValue("site_id")),
		"parent_id":       strings.TrimSpace(request.FormValue("parent_id")),
		"scan_config_ids": strings.TrimSpace(request.FormValue("scan_config_ids")),
		"api_insecure":    strings.TrimSpace(request.FormValue("api_insecure")),
		"extra_args":      strings.TrimSpace(request.FormValue("extra_args")),
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	if _, err := workspace.createCampaign(
		request.FormValue("name"),
		request.FormValue("plugin"),
		request.FormValue("scope"),
		request.FormValue("from"),
		request.FormValue("to"),
		options,
	); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(writer, request, chooseString(request.FormValue("return_to"), request.Referer(), "/changes"), http.StatusSeeOther)
}

func (app *application) handlePluginRun(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	pluginID := strings.TrimSpace(request.FormValue("plugin"))
	targetMode := strings.TrimSpace(request.FormValue("target_mode"))
	returnTo := chooseString(request.FormValue("return_to"), request.Referer(), "/sources")
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}

	var (
		rawTargets []string
		hostIPs    []string
		summary    string
	)

	switch targetMode {
	case "host":
		host := strings.TrimSpace(request.FormValue("host"))
		rawTargets = uniqueStrings([]string{host})
		hostIPs = uniqueStrings([]string{host})
		summary = "single host · " + host
	case "profile":
		profileScope := strings.TrimSpace(request.FormValue("profile_scope"))
		rawTargets, hostIPs, summary = workspace.profileTargets(pluginID, profileScope)
	case "manual":
		rawTargets = parseTargetLines(request.FormValue("targets"))
		hostIPs = resolveKnownHosts(workspace.currentSnapshot(), rawTargets)
		summary = fmt.Sprintf("manual scope · %d targets", len(rawTargets))
	default:
		filter := HostFilter{
			Query:    strings.TrimSpace(request.FormValue("query")),
			Scope:    request.FormValue("scope"),
			Sort:     request.FormValue("sort"),
			Page:     1,
			PageSize: maxInt(len(workspace.currentSnapshot().records), defaultPageSize),
		}
		hostIPs = workspace.matchingHostIPs(filter)
		rawTargets = append([]string(nil), hostIPs...)
		summary = fmt.Sprintf("current filter · %d hosts", len(hostIPs))
	}

	options := map[string]string{
		"severity":      strings.TrimSpace(request.FormValue("severity")),
		"templates":     strings.TrimSpace(request.FormValue("templates")),
		"concurrency":   strings.TrimSpace(request.FormValue("concurrency")),
		"profile":       strings.TrimSpace(request.FormValue("profile")),
		"profile_scope": strings.TrimSpace(request.FormValue("profile_scope")),
		"ports":         strings.TrimSpace(request.FormValue("ports")),
		"crawl_depth":   strings.TrimSpace(request.FormValue("crawl_depth")),
		"level":         strings.TrimSpace(request.FormValue("level")),
		"risk":          strings.TrimSpace(request.FormValue("risk")),
		"extra_args":    strings.TrimSpace(request.FormValue("extra_args")),
	}

	if _, err := workspace.plugins.submit(pluginID, rawTargets, hostIPs, summary, options); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(writer, request, returnTo, http.StatusSeeOther)
}

func (app *application) handleExplorerJSON(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	nodes := workspace.explorerChildren(
		chooseString(strings.TrimSpace(request.URL.Query().Get("kind")), "workspace"),
		strings.TrimSpace(request.URL.Query().Get("id")),
	)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(nodes); err != nil {
		app.logger.Error("encode explorer json", "error", err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (app *application) handleTraceJSON(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	snapshot := workspace.currentSnapshot()
	ip := strings.TrimPrefix(request.URL.Path, "/json/")
	graph := snapshot.traceGraph(ip)

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(graph); err != nil {
		app.logger.Error("encode trace json", "error", err, "ip", ip)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (app *application) handleDiffJSON(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	diff, _, _, _ := workspace.changeComparison(
		strings.TrimSpace(request.URL.Query().Get("from")),
		strings.TrimSpace(request.URL.Query().Get("to")),
	)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(diff); err != nil {
		app.logger.Error("encode diff json", "error", err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (app *application) handleObservationsJSON(writer http.ResponseWriter, request *http.Request) {
	limit := queryInt(request.URL.Query(), "limit", 24)
	hostIP := strings.TrimSpace(request.URL.Query().Get("host"))
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}

	var observations []ObservationView
	if hostIP != "" {
		observations = workspace.hostObservations(hostIP, limit)
	} else {
		observations = workspace.recentObservations(limit)
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(observations); err != nil {
		app.logger.Error("encode observations json", "error", err, "host", hostIP)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (app *application) handleTopologyJSON(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	snapshot := workspace.currentSnapshot()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(snapshot.topology); err != nil {
		app.logger.Error("encode topology json", "error", err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (app *application) handleHostExport(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	snapshot := workspace.currentSnapshot()
	filter := parseHostFilter(request, defaultPageSize)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="hosts.txt"`)
	_, _ = writer.Write([]byte(snapshot.hostListText(filter)))
}

func (app *application) handleCSVExport(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	snapshot := workspace.currentSnapshot()
	filter := parseHostFilter(request, defaultPageSize)
	writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="hosts.csv"`)
	_, _ = writer.Write([]byte(snapshot.inventoryCSV(filter)))
}

func (app *application) handleNucleiExport(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	snapshot := workspace.currentSnapshot()
	filter := parseHostFilter(request, defaultPageSize)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="nuclei-targets.txt"`)
	_, _ = writer.Write([]byte(snapshot.nucleiTargets(filter)))
}

func (app *application) handleSearchRedirect(writer http.ResponseWriter, request *http.Request) {
	values := url.Values{}
	query := strings.TrimSpace(request.FormValue("query"))
	scope := request.FormValue("type")
	if scope == "" {
		scope = request.FormValue("scope")
	}

	if query != "" {
		values.Set("query", query)
	}
	if normalized := normalizeScope(scope); normalized != "all" {
		values.Set("scope", normalized)
	}

	target := "/hosts"
	if encoded := values.Encode(); encoded != "" {
		target += "?" + encoded
	}

	http.Redirect(writer, request, target, http.StatusSeeOther)
}

func (app *application) handleHealth(writer http.ResponseWriter, request *http.Request) {
	workspace, _, ok := app.requireWorkspace(writer, request)
	if !ok {
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"status":       "ok",
		"scans":        workspace.workspaceStatus().ScanCount,
		"running_jobs": workspace.workspaceStatus().RunningJobs,
	})
}

func (app *application) handleGraphAlias(writer http.ResponseWriter, request *http.Request) {
	app.redirectWithQuery(writer, request, "/topology")
}

func (app *application) handleIPAlias(writer http.ResponseWriter, request *http.Request) {
	ip := strings.TrimPrefix(request.URL.Path, "/ip/")
	app.redirectWithQuery(writer, request, "/hosts/"+ip)
}

func (app *application) handleAllAlias(writer http.ResponseWriter, request *http.Request) {
	app.redirectWithQuery(writer, request, "/hosts")
}

func (app *application) handleListAlias(writer http.ResponseWriter, request *http.Request) {
	target := "/ports"
	if normalizeListKind(request.URL.Query().Get("type")) == "os" {
		target = "/hosts?scope=os"
	}
	app.redirectWithQuery(writer, request, target)
}

func (app *application) redirectWithQuery(writer http.ResponseWriter, request *http.Request, target string) {
	if request.URL.RawQuery != "" {
		separator := "?"
		if strings.Contains(target, "?") {
			separator = "&"
		}
		target += separator + request.URL.RawQuery
	}
	http.Redirect(writer, request, target, http.StatusMovedPermanently)
}

func (app *application) render(writer http.ResponseWriter, status int, name string, data any) {
	var buffer bytes.Buffer
	if err := app.templates.ExecuteTemplate(&buffer, name, data); err != nil {
		app.logger.Error("render template", "template", name, "error", err)
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(buffer.Bytes())
}

func (app *application) workspaceForRequest(request *http.Request) (*workspace, workspaceMetaRecord, error) {
	if app.center != nil {
		workspace, meta, err := app.center.workspaceFromRequest(request)
		if err == nil && workspace != nil {
			return workspace, meta, nil
		}
	}
	if app.workspace == nil {
		return nil, workspaceMetaRecord{}, errors.New("workspace is unavailable")
	}
	return app.workspace, workspaceMetaRecord{
		ID:         app.workspace.id,
		Slug:       app.workspace.slug,
		Name:       app.workspace.name,
		BundlePath: app.workspace.bundlePath,
	}, nil
}

func (app *application) requireWorkspace(writer http.ResponseWriter, request *http.Request) (*workspace, workspaceMetaRecord, bool) {
	workspace, meta, err := app.workspaceForRequest(request)
	if err == nil && workspace != nil {
		return workspace, meta, true
	}
	http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	return nil, workspaceMetaRecord{}, false
}

func (app *application) commonPageData(workspace *workspace, active string, title string, description string, search SearchState, breadcrumbs []Breadcrumb, expandPath []ExplorerPathStep) CommonPageData {
	snapshot := workspace.currentSnapshot()
	navGroups := []NavGroup{
		{
			Label:   "Engagement",
			Summary: "Registry, posture, and workspace-wide operations for the active engagement.",
			Items: []NavItem{
				{Label: "Engagements", Href: "/workspaces", Active: active == "workspaces", Description: "Switch or create command-center workspaces."},
				{Label: "Overview", Href: "/overview", Active: active == "overview", Description: "Executive posture, activity, and latest changes."},
				{Label: "Workspace", Href: "/workspace", Active: active == "workspace" || active == "sources", Description: "Intake, jobs, preferences, and operations."},
			},
		},
		{
			Label:   "Operations",
			Summary: "Define scope, orchestrate campaigns, and steer next-step automation.",
			Items: []NavItem{
				{Label: "Scope", Href: "/scope", Active: active == "scope", Description: "Normalize seeds into execution chunks and approvals."},
				{Label: "Campaigns", Href: "/campaigns", Active: active == "campaigns", Description: "Track chunk execution, runs, and orchestration state."},
				{Label: "Recommendations", Href: "/recommendations", Active: active == "recommendations", Description: "Review queued next steps and operator approvals."},
			},
		},
		{
			Label:   "Inventory",
			Summary: "Canonical investigation surfaces built from imported sources and observations.",
			Items: []NavItem{
				{Label: "Scans", Href: "/scans", Active: active == "scans", Description: "Source provenance and scan coverage history."},
				{Label: "Hosts", Href: "/hosts", Active: active == "hosts", Description: "Merged host dossiers and follow-up actions."},
				{Label: "Ports", Href: "/ports", Active: active == "ports", Description: "Service surface and exposure by port."},
				{Label: "Findings", Href: "/findings", Active: active == "findings", Description: "Grouped findings with affected assets and evidence."},
			},
		},
		{
			Label:   "Analysis",
			Summary: "Diffs, topology, and cross-source reasoning over the current engagement.",
			Items: []NavItem{
				{Label: "Changes", Href: "/changes", Active: active == "changes", Description: "Checkpoint diffs and drift review."},
				{Label: "Topology", Href: "/topology", Active: active == "topology", Description: "Traceroute-backed graph and route analysis."},
			},
		},
	}

	nav := make([]NavItem, 0, 8)
	activeGroup := NavGroup{}
	for _, group := range navGroups {
		activeLabel := ""
		for _, item := range group.Items {
			if item.Active {
				group.Active = true
				activeLabel = item.Label
			}
		}
		if activeLabel == "" && len(group.Items) > 0 {
			activeLabel = group.Items[0].Label
		}
		group.ActiveLabel = activeLabel
		if group.Active || activeGroup.Label == "" {
			if group.Active {
				activeGroup = group
			}
		}
		nav = append(nav, group.Items...)
	}
	if activeGroup.Label == "" && len(navGroups) > 0 {
		activeGroup = navGroups[0]
	}

	return CommonPageData{
		Page: PageMeta{
			Title:       title,
			Description: description,
			ActiveNav:   active,
		},
		Scan:        snapshot.meta,
		Workspace:   workspace.workspaceStatus(),
		Search:      SearchState{Query: search.Query, Scope: normalizeScope(search.Scope), Sort: normalizeSort(search.Sort)},
		Nav:         nav,
		NavGroups:   navGroups,
		ActiveGroup: activeGroup,
		Breadcrumbs: breadcrumbs,
		Explorer:    workspace.explorerRoot(expandPath),
	}
}

func (app *application) redirectToWorkspaceWhenEmpty(workspace *workspace, writer http.ResponseWriter, request *http.Request) bool {
	if workspace.workspaceStatus().HasImportedScans {
		return true
	}
	http.Redirect(writer, request, "/workspace", http.StatusSeeOther)
	return false
}

func (app *application) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		startedAt := time.Now()
		next.ServeHTTP(writer, request)
		app.logger.Info("request complete",
			"method", request.Method,
			"path", request.URL.Path,
			"query", request.URL.RawQuery,
			"duration", time.Since(startedAt),
		)
	})
}

func parseHostFilter(request *http.Request, pageSize int) HostFilter {
	query := request.URL.Query()
	requestedPageSize := queryInt(query, "page_size", pageSize)
	page := queryInt(query, "page", 1)
	start := queryInt(query, "start", -1)
	if start >= 0 && page == 1 && requestedPageSize > 0 {
		page = (start / requestedPageSize) + 1
	}

	return HostFilter{
		Query:    strings.TrimSpace(query.Get("query")),
		Scope:    query.Get("scope"),
		Sort:     query.Get("sort"),
		Page:     page,
		PageSize: requestedPageSize,
	}
}

func scopeOptions(selected string) []SelectOption {
	selected = normalizeScope(selected)
	return []SelectOption{
		{Value: "all", Label: "Everything", Selected: selected == "all"},
		{Value: "os", Label: "OS", Selected: selected == "os"},
		{Value: "service", Label: "Service", Selected: selected == "service"},
		{Value: "banner", Label: "Banner", Selected: selected == "banner"},
		{Value: "port", Label: "Port", Selected: selected == "port"},
	}
}

func sortOptions(selected string) []SelectOption {
	selected = normalizeSort(selected)
	return []SelectOption{
		{Value: "exposure", Label: "Exposure", Selected: selected == "exposure"},
		{Value: "findings", Label: "Findings", Selected: selected == "findings"},
		{Value: "coverage", Label: "Coverage gaps", Selected: selected == "coverage"},
		{Value: "ports", Label: "Open Ports", Selected: selected == "ports"},
		{Value: "hostname", Label: "Hostname", Selected: selected == "hostname"},
		{Value: "os", Label: "OS", Selected: selected == "os"},
		{Value: "ip", Label: "IP", Selected: selected == "ip"},
	}
}

func pageSizeOptions(selected int) []SelectOption {
	selected = normalizePageSize(selected)
	return []SelectOption{
		{Value: "25", Label: "25 rows", Selected: selected == 25},
		{Value: "50", Label: "50 rows", Selected: selected == 50},
		{Value: "100", Label: "100 rows", Selected: selected == 100},
		{Value: "250", Label: "250 rows", Selected: selected == 250},
		{Value: "500", Label: "500 rows", Selected: selected == 500},
	}
}

func portSortOptions(selected string) []SelectOption {
	selected = normalizePortSort(selected)
	return []SelectOption{
		{Value: "hosts", Label: "Hosts", Selected: selected == "hosts"},
		{Value: "findings", Label: "Findings", Selected: selected == "findings"},
		{Value: "scans", Label: "Scans", Selected: selected == "scans"},
		{Value: "port", Label: "Port", Selected: selected == "port"},
	}
}

func findingSeverityOptions(selected string) []SelectOption {
	selected = normalizeFindingSeverityFilter(selected)
	return []SelectOption{
		{Value: "all", Label: "All severities", Selected: selected == "all"},
		{Value: "critical", Label: "Critical", Selected: selected == "critical"},
		{Value: "high", Label: "High", Selected: selected == "high"},
		{Value: "medium", Label: "Medium", Selected: selected == "medium"},
		{Value: "low", Label: "Low", Selected: selected == "low"},
		{Value: "info", Label: "Info", Selected: selected == "info"},
	}
}

func findingSortOptions(selected string) []SelectOption {
	selected = normalizeFindingSort(selected)
	return []SelectOption{
		{Value: "severity", Label: "Severity", Selected: selected == "severity"},
		{Value: "hosts", Label: "Hosts", Selected: selected == "hosts"},
		{Value: "occurrences", Label: "Occurrences", Selected: selected == "occurrences"},
		{Value: "recent", Label: "Last seen", Selected: selected == "recent"},
	}
}

func rebaseHostPage(base string, filter HostFilter, page HostPage) HostPage {
	page.PrevLink = filterHrefFrom(base, filter, maxInt(page.Page-1, 1))
	page.NextLink = filterHrefFrom(base, filter, minInt(page.Page+1, page.TotalPages))
	for index := range page.Links {
		if page.Links[index].Disabled {
			page.Links[index].Href = ""
			continue
		}
		targetPage := page.Page
		if parsed, err := strconv.Atoi(page.Links[index].Label); err == nil {
			targetPage = parsed
		} else if page.Links[index].Label == "Prev" {
			targetPage = maxInt(page.Page-1, 1)
		} else if page.Links[index].Label == "Next" {
			targetPage = minInt(page.Page+1, page.TotalPages)
		}
		page.Links[index].Href = filterHrefFrom(base, filter, targetPage)
	}
	return page
}

func normalizeListKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "os", "service":
		return strings.ToLower(strings.TrimSpace(kind))
	default:
		return "port"
	}
}

func changeQuery(fromID string, toID string) string {
	values := url.Values{}
	if strings.TrimSpace(fromID) != "" {
		values.Set("from", strings.TrimSpace(fromID))
	}
	if strings.TrimSpace(toID) != "" {
		values.Set("to", strings.TrimSpace(toID))
	}
	return values.Encode()
}

func sanitizeDownloadName(name string, ext string) string {
	stem := sanitizeFileStem(name)
	if ext == "" {
		return stem
	}
	if filepath.Ext(stem) == ext {
		return stem
	}
	return stem + ext
}

func parseTargetLines(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == '\t' || r == ' '
	})
	return uniqueStrings(fields)
}

func resolveKnownHosts(snapshot *snapshot, rawTargets []string) []string {
	if snapshot == nil {
		return nil
	}
	results := make([]string, 0, len(rawTargets))
	for _, candidate := range rawTargets {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		for _, record := range snapshot.records {
			if record.summary.IP == candidate {
				results = append(results, candidate)
				break
			}
			if strings.EqualFold(record.summary.DisplayName, candidate) || slicesContains(record.summary.Hostnames, candidate) {
				results = append(results, record.summary.IP)
				break
			}
		}
	}
	return uniqueStrings(results)
}

func queryInt(values url.Values, key string, fallback int) int {
	if values.Get(key) == "" {
		return fallback
	}
	value, err := strconv.Atoi(values.Get(key))
	if err != nil {
		return fallback
	}
	return value
}

func formInt(request *http.Request, key string, fallback int) int {
	value := strings.TrimSpace(request.FormValue(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
