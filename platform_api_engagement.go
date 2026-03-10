package main

import (
	"encoding/json"
	"net/http"
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
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
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
	writeJSON(writer, http.StatusOK, PlatformSettingsAPI{
		Memberships: paginateAPIItems(request, memberships),
		Tools:       paginateAPIItems(request, tools),
		Connectors:  paginateAPIItems(request, connectors),
	})
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
