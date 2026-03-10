package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (app *application) handleEngagementJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, context.View)
}

func (app *application) handleEngagementSummaryJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	stats, err := app.platform.store.engagementStats(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, stats)
}

func (app *application) handleEngagementScopeJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	_ = app.platform.syncEngagement(context.Engagement)
	stats, err := app.platform.store.engagementStats(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	seeds, err := app.platform.store.listEngagementScopeSeeds(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	targets, err := app.platform.store.listEngagementScopeTargets(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	chunks, err := app.platform.store.listEngagementChunks(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	approvals, err := app.platform.store.listEngagementApprovals(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	runs, err := app.platform.store.listEngagementRuns(context.Engagement.ID, 0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, PlatformScopeAPI{
		Stats:     stats,
		Seeds:     paginateAPIItems(request, seeds),
		Targets:   paginateAPIItems(request, targets),
		Chunks:    paginateAPIItems(request, chunks),
		Approvals: paginateAPIItems(request, approvals),
		Runs:      paginateAPIItems(request, runs),
	})
}

func (app *application) handleEngagementZonesJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	items, err := app.platform.store.listEngagementZones(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	sortPlatformZones(items, request.URL.Query().Get("sort"))
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleEngagementHostsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	items, err := app.platform.store.listEngagementHosts(
		context.Engagement.ID,
		strings.TrimSpace(request.URL.Query().Get("zone")),
		strings.TrimSpace(request.URL.Query().Get("query")),
		0,
	)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	items = decorateHostLinks(context.View.Slug, items)
	sortPlatformHosts(items, request.URL.Query().Get("sort"))
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleEngagementPortsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	items, err := app.platform.store.listEngagementPorts(context.Engagement.ID, strings.TrimSpace(request.URL.Query().Get("query")), 0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	items = decoratePortLinks(context.View.Slug, items)
	sortPlatformPorts(items, request.URL.Query().Get("sort"))
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleEngagementFindingsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	items, err := app.platform.store.listEngagementFindings(
		context.Engagement.ID,
		strings.TrimSpace(request.URL.Query().Get("query")),
		normalizeFindingSeverityFilter(request.URL.Query().Get("severity")),
		0,
	)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	items = decorateFindingLinks(context.View.Slug, items)
	sortPlatformFindings(items, request.URL.Query().Get("sort"))
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleEngagementHostDetailJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	hostIP := strings.TrimSpace(request.PathValue("ip"))
	host, ok := context.Workspace.currentSnapshot().host(hostIP)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	host.DisplayName = chooseString(strings.TrimSpace(host.DisplayName), strings.TrimSpace(host.IP))
	portSummary, err := app.platform.store.listEngagementPorts(context.Engagement.ID, host.IP, 0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	portSummary = decoratePortLinks(context.View.Slug, portSummary)
	relatedZones, err := app.platform.store.listZonesForHost(context.Engagement.ID, host.IP)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	hostFindings := decorateFindingGroupLinks(context.View.Slug, findingGroupsForRecords([]hostRecord{{summary: host.HostSummary, detail: host}}, context.Workspace.scanTimeByName()))
	runs := hostRunViews(context.Workspace.hostJobs(host.IP, 12))
	writeJSON(writer, http.StatusOK, PlatformHostDetailAPI{
		Host:         host,
		RelatedZones: relatedZones,
		RecentRuns:   runs,
		Findings:     hostFindings,
		PortSummary:  portSummary,
	})
}

func (app *application) handleEngagementPortDetailJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	protocol := strings.TrimSpace(request.PathValue("protocol"))
	port := strings.TrimSpace(request.PathValue("port"))
	detail, ok := context.Workspace.portDetail(protocol, port, "", "")
	if !ok {
		http.NotFound(writer, request)
		return
	}
	decoratePortHosts(context.View.Slug, detail.Hosts)
	detail.RelatedFindings = decorateFindingGroupLinks(context.View.Slug, detail.RelatedFindings)
	recentRuns := make([]PlatformRunView, 0)
	seen := map[string]struct{}{}
	for _, host := range detail.Hosts {
		for _, run := range hostRunViews(context.Workspace.hostJobs(host.IP, 6)) {
			if _, ok := seen[run.ID]; ok {
				continue
			}
			seen[run.ID] = struct{}{}
			recentRuns = append(recentRuns, run)
		}
	}
	writeJSON(writer, http.StatusOK, PlatformPortDetailAPI{
		Port:       detail,
		RecentRuns: recentRuns,
	})
}

func (app *application) handleEngagementFindingDetailJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	groupID := strings.TrimSpace(request.PathValue("groupID"))
	detail, ok := context.Workspace.findingDetail(groupID, "", "", "", "")
	if !ok {
		http.NotFound(writer, request)
		return
	}
	detail.Group.Href = "/engagements/" + context.View.Slug + "/findings/" + groupID
	decorateFindingOccurrences(context.View.Slug, detail.Occurrences)
	writeJSON(writer, http.StatusOK, PlatformFindingDetailAPI{
		Finding:    detail,
		RecentRuns: hostRunViews(detail.RelatedJobs),
	})
}

func (app *application) handleEngagementSourcesJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	items, err := app.platform.store.listEngagementSources(context.Engagement.ID, 0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleEngagementRunsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	_ = app.platform.syncEngagement(context.Engagement)
	items, err := app.platform.store.listEngagementRuns(context.Engagement.ID, 0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleEngagementCampaignsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	_ = app.platform.syncEngagement(context.Engagement)
	stats, err := app.platform.store.engagementStats(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	runs, err := app.platform.store.listEngagementRuns(context.Engagement.ID, 0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	chunks, err := app.platform.store.listEngagementChunks(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	tools, err := app.platform.store.listTools()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, PlatformCampaignsAPI{
		Stats:       stats,
		StatusMix:   platformRunStatusBuckets(runs),
		StageMix:    platformChunkStageBuckets(chunks),
		Runs:        paginateAPIItems(request, runs),
		Chunks:      paginateAPIItems(request, chunks),
		Tools:       paginateAPIItems(request, tools),
		RunProfiles: context.Workspace.commandCenterRunProfiles(),
		Readiness:   context.Workspace.plugins.readinessGroups(),
		Policies:    context.Workspace.orchestrationPolicies(),
	})
}

func (app *application) handleEngagementTopologyJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, context.Workspace.currentSnapshot().topology)
}

func (app *application) handleEngagementRecommendationsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, PlatformRecommendationsAPI{
		Recommendations: paginateAPIItems(request, context.Workspace.recommendationViews()),
		Approvals:       paginateAPIItems(request, context.Workspace.pendingApprovalViews()),
		Runs:            paginateAPIItems(request, hostRunViews(context.Workspace.plugins.recentJobs(12))),
	})
}

func (app *application) handleEngagementSettingsJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	memberships, err := app.platform.store.listMemberships(context.Engagement.ID)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	tools, err := app.platform.store.listTools()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	connectors, err := app.platform.store.listConnectors()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	users, err := app.platform.store.listUsers()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	userViews := make([]PlatformUserView, 0, len(users))
	for _, item := range users {
		userViews = append(userViews, platformUserView(item))
	}
	writeJSON(writer, http.StatusOK, PlatformSettingsAPI{
		Memberships: paginateAPIItems(request, memberships),
		Users:       paginateAPIItems(request, userViews),
		Tools:       paginateAPIItems(request, tools),
		Connectors:  paginateAPIItems(request, connectors),
	})
}

func (app *application) handleEngagementSourceImportJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	if err := request.ParseMultipartForm(64 << 20); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid multipart payload"})
		return
	}
	file, header, err := request.FormFile("scan_file")
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "scan_file is required"})
		return
	}
	defer file.Close()
	if err := app.importEngagementSourceFile(context.Engagement, header.Filename, file); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (app *application) handleEngagementCampaignActionJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	_, role, err := app.platform.requireEngagement(context.User, context.View.Slug)
	if err != nil {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": http.StatusText(http.StatusForbidden)})
		return
	}
	var payload platformCampaignActionInput
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if err := app.runEngagementCampaignAction(context.Engagement, role, payload); err != nil {
		status := http.StatusBadRequest
		if err == errPlatformForbidden {
			status = http.StatusForbidden
		}
		writeJSON(writer, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (app *application) handleEngagementApprovalJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	if err := app.approveEngagementApproval(context.Engagement, request.PathValue("approvalID")); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{"status": "approved"})
}

func (app *application) handleEngagementRecommendationLLMJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	payload := struct {
		CampaignID string `json:"campaignId"`
	}{}
	if request.Body != nil {
		_ = json.NewDecoder(request.Body).Decode(&payload)
	}
	if err := app.requestEngagementLLMRecommendations(context.Engagement, payload.CampaignID); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (app *application) handleEngagementMembershipJSON(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, false)
	if !ok {
		return
	}
	payload := struct {
		User string `json:"user"`
		Role string `json:"role"`
	}{}
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if err := app.addEngagementMembership(context.User, context.Engagement, payload.User, payload.Role); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]string{"status": "created"})
}

func (app *application) handleEngagementEventsSSE(writer http.ResponseWriter, request *http.Request) {
	context, ok := app.requireAPIEngagementContext(writer, request, true)
	if !ok {
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	events, cancel := context.Workspace.plugins.subscribe()
	defer cancel()

	send := func() bool {
		if app.platform != nil {
			_ = app.platform.syncEngagement(context.Engagement)
		}
		stats, err := app.platform.store.engagementStats(context.Engagement.ID)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return false
		}
		payload, err := json.Marshal(PlatformEngagementEvent{
			Type:       "engagement.snapshot",
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Engagement: context.View,
			Stats:      stats,
		})
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return false
		}
		_, _ = writer.Write([]byte("event: engagement.snapshot\n"))
		_, _ = writer.Write([]byte("data: " + string(payload) + "\n\n"))
		flusher.Flush()
		return true
	}

	if !send() {
		return
	}

	keepAlive := time.NewTicker(30 * time.Second)
	defer keepAlive.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-events:
			for len(events) > 0 {
				<-events
			}
			if !send() {
				return
			}
		case <-keepAlive.C:
			_, _ = writer.Write([]byte(": keep-alive\n\n"))
			flusher.Flush()
		}
	}
}

func sortPlatformZones(items []PlatformZoneView, sortBy string) {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "name":
		sort.SliceStable(items, func(left, right int) bool {
			return strings.ToLower(items[left].Name) < strings.ToLower(items[right].Name)
		})
	default:
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].HostCount != items[right].HostCount {
				return items[left].HostCount > items[right].HostCount
			}
			return strings.ToLower(items[left].Name) < strings.ToLower(items[right].Name)
		})
	}
}

func sortPlatformHosts(items []PlatformHostView, sortBy string) {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "name":
		sort.SliceStable(items, func(left, right int) bool {
			return strings.ToLower(items[left].DisplayName) < strings.ToLower(items[right].DisplayName)
		})
	case "ports":
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].OpenPorts != items[right].OpenPorts {
				return items[left].OpenPorts > items[right].OpenPorts
			}
			return compareIPStrings(items[left].IP, items[right].IP) < 0
		})
	case "critical":
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].Critical != items[right].Critical {
				return items[left].Critical > items[right].Critical
			}
			if items[left].High != items[right].High {
				return items[left].High > items[right].High
			}
			return compareIPStrings(items[left].IP, items[right].IP) < 0
		})
	case "sources":
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].SourceCount != items[right].SourceCount {
				return items[left].SourceCount > items[right].SourceCount
			}
			return compareIPStrings(items[left].IP, items[right].IP) < 0
		})
	default:
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].Findings != items[right].Findings {
				return items[left].Findings > items[right].Findings
			}
			if items[left].OpenPorts != items[right].OpenPorts {
				return items[left].OpenPorts > items[right].OpenPorts
			}
			return compareIPStrings(items[left].IP, items[right].IP) < 0
		})
	}
}

func sortPlatformPorts(items []PlatformPortView, sortBy string) {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "port":
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].Protocol != items[right].Protocol {
				return items[left].Protocol < items[right].Protocol
			}
			return comparePortNumbers(items[left].Port, items[right].Port) < 0
		})
	case "service":
		sort.SliceStable(items, func(left, right int) bool {
			if strings.ToLower(items[left].Service) != strings.ToLower(items[right].Service) {
				return strings.ToLower(items[left].Service) < strings.ToLower(items[right].Service)
			}
			return comparePortNumbers(items[left].Port, items[right].Port) < 0
		})
	default:
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].Hosts != items[right].Hosts {
				return items[left].Hosts > items[right].Hosts
			}
			if items[left].Findings != items[right].Findings {
				return items[left].Findings > items[right].Findings
			}
			return comparePortNumbers(items[left].Port, items[right].Port) < 0
		})
	}
}

func sortPlatformFindings(items []PlatformFindingView, sortBy string) {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "hosts":
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].Hosts != items[right].Hosts {
				return items[left].Hosts > items[right].Hosts
			}
			return strings.ToLower(items[left].Name) < strings.ToLower(items[right].Name)
		})
	case "recent":
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].LastSeen != items[right].LastSeen {
				return items[left].LastSeen > items[right].LastSeen
			}
			return strings.ToLower(items[left].Name) < strings.ToLower(items[right].Name)
		})
	case "name":
		sort.SliceStable(items, func(left, right int) bool {
			return strings.ToLower(items[left].Name) < strings.ToLower(items[right].Name)
		})
	default:
		sort.SliceStable(items, func(left, right int) bool {
			if severityWeight(items[left].Severity) != severityWeight(items[right].Severity) {
				return severityWeight(items[left].Severity) > severityWeight(items[right].Severity)
			}
			if items[left].Occurrences != items[right].Occurrences {
				return items[left].Occurrences > items[right].Occurrences
			}
			return strings.ToLower(items[left].Name) < strings.ToLower(items[right].Name)
		})
	}
}

func comparePortNumbers(left string, right string) int {
	leftValue := portSortValue(left)
	rightValue := portSortValue(right)
	switch {
	case leftValue < rightValue:
		return -1
	case leftValue > rightValue:
		return 1
	default:
		return strings.Compare(left, right)
	}
}

func portSortValue(value string) int {
	if value == "" {
		return 0
	}
	result := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			break
		}
		result = result*10 + int(r-'0')
	}
	return result
}

func decoratePortHosts(slug string, items []PortHostView) {
	for index := range items {
		items[index].Href = "/engagements/" + slug + "/hosts/" + items[index].IP
	}
}

func decorateFindingOccurrences(slug string, items []FindingOccurrenceView) {
	for index := range items {
		items[index].Href = "/engagements/" + slug + "/hosts/" + items[index].HostIP
	}
}

func decorateFindingGroupLinks(slug string, items []FindingGroupView) []FindingGroupView {
	for index := range items {
		items[index].Href = "/engagements/" + slug + "/findings/" + items[index].ID
	}
	return items
}
