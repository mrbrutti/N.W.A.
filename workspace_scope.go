package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	scopeSeedActive      = "active"
	scopeTargetReady     = "ready"
	targetChunkPlanned   = "planned"
	targetChunkQueued    = "queued"
	targetChunkRunning   = "running"
	targetChunkCompleted = "completed"
	targetChunkPartial   = "partial"
	targetChunkBlocked   = "blocked"
	approvalPending      = "pending"
	approvalApproved     = "approved"
	approvalRejected     = "rejected"
	recommendationOpen   = "open"
	recommendationQueued = "queued"
	recommendationDone   = "done"
)

func (w *workspace) scopeSeedsCatalog() []scopeSeedRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()
	items := append([]scopeSeedRecord(nil), w.scopeSeeds...)
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].CreatedAt > items[right].CreatedAt
	})
	return items
}

func (w *workspace) scopeTargetsCatalog() []scopeTargetRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()
	items := append([]scopeTargetRecord(nil), w.scopeTargets...)
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Kind != items[right].Kind {
			return items[left].Kind < items[right].Kind
		}
		return items[left].Normalized < items[right].Normalized
	})
	return items
}

func (w *workspace) targetChunksCatalog() []targetChunkRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()
	items := append([]targetChunkRecord(nil), w.targetChunks...)
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].CreatedAt > items[right].CreatedAt
	})
	return items
}

func (w *workspace) approvalsCatalog() []approvalRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()
	items := append([]approvalRecord(nil), w.approvals...)
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].CreatedAt > items[right].CreatedAt
	})
	return items
}

func (w *workspace) recommendationsCatalog() []recommendationRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()
	items := append([]recommendationRecord(nil), w.recommendations...)
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].CreatedAt > items[right].CreatedAt
	})
	return items
}

func (w *workspace) scopeSeedViews() []ScopeSeedView {
	records := w.scopeSeedsCatalog()
	items := make([]ScopeSeedView, 0, len(records))
	for _, record := range records {
		items = append(items, ScopeSeedView{
			ID:        record.ID,
			Kind:      strings.ToUpper(record.Kind),
			Value:     record.Value,
			Source:    chooseString(record.Source, "manual"),
			Status:    record.Status,
			Detail:    record.Detail,
			CreatedAt: displayTimestamp(record.CreatedAt),
		})
	}
	return items
}

func (w *workspace) scopeTargetViews() []ScopeTargetView {
	records := w.scopeTargetsCatalog()
	items := make([]ScopeTargetView, 0, len(records))
	for _, record := range records {
		items = append(items, ScopeTargetView{
			ID:         record.ID,
			Kind:       strings.ToUpper(record.Kind),
			Value:      record.Value,
			Normalized: record.Normalized,
			Status:     record.Status,
			SeedID:     record.SeedID,
			CreatedAt:  displayTimestamp(record.CreatedAt),
		})
	}
	return items
}

func (w *workspace) targetChunkViews() []TargetChunkView {
	records := w.targetChunksCatalog()
	items := make([]TargetChunkView, 0, len(records))
	for _, record := range records {
		items = append(items, TargetChunkView{
			ID:           record.ID,
			CampaignID:   record.CampaignID,
			Name:         record.Name,
			Stage:        strings.Title(record.Stage),
			Kind:         strings.ToUpper(record.Kind),
			Status:       record.Status,
			StatusTone:   jobStatusTone(record.Status),
			Detail:       record.StatusDetail,
			Size:         record.Size,
			CreatedAt:    displayTimestamp(record.CreatedAt),
			StartedAt:    displayTimestamp(record.StartedAt),
			FinishedAt:   displayTimestamp(record.FinishedAt),
			Values:       append([]string(nil), record.Values...),
			RunIDs:       append([]string(nil), record.RunIDs...),
			ToolIDs:      append([]string(nil), record.ToolIDs...),
			SkippedTools: append([]string(nil), record.SkippedTools...),
		})
	}
	return items
}

func (w *workspace) approvalViews() []ApprovalView {
	records := w.approvalsCatalog()
	items := make([]ApprovalView, 0, len(records))
	for _, record := range records {
		items = append(items, ApprovalView{
			ID:             record.ID,
			CampaignID:     record.CampaignID,
			Scope:          record.Scope,
			Status:         record.Status,
			StatusTone:     approvalTone(record.Status),
			Summary:        record.Summary,
			Detail:         record.Detail,
			RequiredClass:  record.RequiredClass,
			AllowedToolIDs: append([]string(nil), record.AllowedToolIDs...),
			CreatedAt:      displayTimestamp(record.CreatedAt),
			DecidedAt:      displayTimestamp(record.DecidedAt),
		})
	}
	return items
}

func (w *workspace) pendingApprovalViews() []ApprovalView {
	items := make([]ApprovalView, 0)
	for _, item := range w.approvalViews() {
		if item.Status == approvalPending {
			items = append(items, item)
		}
	}
	return items
}

func (w *workspace) recommendationViews() []RecommendationQueueView {
	records := w.recommendationsCatalog()
	items := make([]RecommendationQueueView, 0, len(records))
	for _, record := range records {
		items = append(items, RecommendationQueueView{
			ID:               record.ID,
			CampaignID:       record.CampaignID,
			Type:             record.Type,
			Status:           record.Status,
			StatusTone:       recommendationTone(record.Status, record.ExpectedValue),
			Title:            record.Title,
			Detail:           record.Detail,
			Rationale:        record.Rationale,
			ExpectedValue:    record.ExpectedValue,
			RequiredApproval: record.RequiredApproval,
			Confidence:       fmt.Sprintf("%.0f%%", record.Confidence*100),
			ToolIDs:          append([]string(nil), record.ToolIDs...),
			CreatedAt:        displayTimestamp(record.CreatedAt),
			UpdatedAt:        displayTimestamp(record.UpdatedAt),
		})
	}
	return items
}

func (w *workspace) scopeStats() []StatCard {
	seeds := len(w.scopeSeedsCatalog())
	targets := len(w.scopeTargetsCatalog())
	chunks := len(w.targetChunksCatalog())
	openApprovals := 0
	for _, record := range w.approvalsCatalog() {
		if record.Status == approvalPending {
			openApprovals++
		}
	}
	return []StatCard{
		{Label: "Seeds", Value: strconv.Itoa(seeds), Detail: "Declared scope inputs", Tone: "calm"},
		{Label: "Targets", Value: strconv.Itoa(targets), Detail: "Normalized hosts and network units", Tone: "accent"},
		{Label: "Chunks", Value: strconv.Itoa(chunks), Detail: "Bounded execution slices", Tone: "warning"},
		{Label: "Approvals", Value: strconv.Itoa(openApprovals), Detail: "Open operator gates", Tone: "risk"},
	}
}

func approvalTone(status string) string {
	switch status {
	case approvalApproved:
		return "ok"
	case approvalRejected:
		return "risk"
	default:
		return "warning"
	}
}

func recommendationTone(status string, expectedValue string) string {
	if status == recommendationDone {
		return "ok"
	}
	if strings.EqualFold(expectedValue, "high") {
		return "risk"
	}
	if strings.EqualFold(expectedValue, "medium") {
		return "warning"
	}
	return "accent"
}

func (w *workspace) ingestScope(name string, raw string, source string, autoApprove bool) (campaignRecord, error) {
	lines := splitScopeInputs(raw)
	if len(lines) == 0 {
		return campaignRecord{}, errors.New("scope input is empty")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	w.mu.Lock()
	defer w.mu.Unlock()

	existingSeeds := map[string]struct{}{}
	for _, seed := range w.scopeSeeds {
		existingSeeds[seed.Kind+"|"+seed.Value] = struct{}{}
	}
	existingTargets := map[string]struct{}{}
	for _, target := range w.scopeTargets {
		existingTargets[target.Kind+"|"+target.Normalized] = struct{}{}
	}

	newSeeds := make([]scopeSeedRecord, 0, len(lines))
	newTargets := make([]scopeTargetRecord, 0, len(lines))
	addedTargetIDs := make([]string, 0, len(lines))

	for _, line := range lines {
		kind, normalized, detail, err := classifyScopeSeed(line)
		if err != nil {
			continue
		}
		seedKey := kind + "|" + normalized
		if _, seen := existingSeeds[seedKey]; seen {
			continue
		}
		seed := scopeSeedRecord{
			ID:        newWorkspaceID("seed"),
			Kind:      kind,
			Value:     normalized,
			Source:    chooseString(strings.TrimSpace(source), "manual"),
			Status:    scopeSeedActive,
			Detail:    detail,
			CreatedAt: now,
		}
		existingSeeds[seedKey] = struct{}{}
		newSeeds = append(newSeeds, seed)

		targets := expandScopeTargets(seed)
		for _, target := range targets {
			targetKey := target.Kind + "|" + target.Normalized
			if _, seen := existingTargets[targetKey]; seen {
				continue
			}
			existingTargets[targetKey] = struct{}{}
			newTargets = append(newTargets, target)
			addedTargetIDs = append(addedTargetIDs, target.ID)
		}
	}
	if len(newTargets) == 0 {
		return campaignRecord{}, errors.New("scope input did not add any new targets")
	}

	campaignName := chooseString(strings.TrimSpace(name), "Scope kickoff · "+time.Now().UTC().Format("2006-01-02 15:04"))
	chunks := buildTargetChunks(newTargets, "")
	allowedToolIDs := w.allowedToolIDsForChunksLocked(chunks)
	campaign := campaignRecord{
		ID:          newWorkspaceID("campaign"),
		Name:        campaignName,
		PluginID:    "orchestrator",
		PluginLabel: "Command center orchestrator",
		Scope:       "workspace-scope",
		Options: map[string]string{
			"source": chooseString(strings.TrimSpace(source), "manual"),
			"mode":   "command-center",
		},
		Status:     approvalPending,
		Summary:    fmt.Sprintf("Prepared %d targets across %d chunks. Awaiting approval to launch discovery and recon.", len(newTargets), len(chunks)),
		CreatedAt:  now,
		Stage:      "approval",
		StageLabel: "Awaiting approval",
		TargetKind: summarizeTargetKinds(newTargets),
		ChunkIDs:   chunkIDs(chunks),
		Policy: map[string]string{
			"worker_mode": "central",
			"approval":    "required",
			"llm":         "advisory",
		},
	}
	for index := range chunks {
		chunks[index].CampaignID = campaign.ID
	}
	approval := approvalRecord{
		ID:             newWorkspaceID("approval"),
		CampaignID:     campaign.ID,
		Scope:          "workspace-kickoff",
		Status:         approvalPending,
		Summary:        fmt.Sprintf("Approve automated discovery for %d chunks", len(chunks)),
		Detail:         "This approval allows the command center to queue discovery, recon, and fingerprinting tools against the normalized scope chunks.",
		RequiredClass:  "operator",
		CreatedAt:      now,
		AllowedToolIDs: allowedToolIDs,
		Policy: map[string]string{
			"worker_mode": "central",
			"noise":       "moderate",
			"llm":         "assist-only",
		},
	}
	campaign.ApprovalID = approval.ID

	recommendations := buildKickoffRecommendations(campaign, chunks, allowedToolIDs, now)

	w.scopeSeeds = append(w.scopeSeeds, newSeeds...)
	w.scopeTargets = append(w.scopeTargets, newTargets...)
	w.targetChunks = append(w.targetChunks, chunks...)
	w.campaigns = append(w.campaigns, campaign)
	w.approvals = append(w.approvals, approval)
	w.recommendations = append(w.recommendations, recommendations...)
	sortScopeStateLocked(w)

	if err := w.persistStateLocked(); err != nil {
		return campaignRecord{}, err
	}
	if err := w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:      "Scope",
		KindTone:  "accent",
		Label:     campaign.Name,
		Summary:   campaign.Summary,
		CreatedAt: now,
		RefID:     campaign.ID,
		Observations: []observationRecord{{
			ID:       newWorkspaceID("obs"),
			Kind:     "scope",
			KindTone: "accent",
			Source:   "Scope onboarding",
			Label:    fmt.Sprintf("%d scope seeds", len(newSeeds)),
			Detail:   fmt.Sprintf("%d normalized targets in %d chunks", len(newTargets), len(chunks)),
			Href:     "/scope",
		}},
	}); err != nil {
		return campaignRecord{}, err
	}
	if autoApprove {
		if err := w.approveKickoffLocked(approval.ID); err != nil {
			return campaignRecord{}, err
		}
	}
	return campaign, nil
}

func (w *workspace) approveKickoff(approvalID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.approveKickoffLocked(approvalID)
}

func (w *workspace) approveKickoffLocked(approvalID string) error {
	approvalIndex := -1
	for index, approval := range w.approvals {
		if approval.ID == strings.TrimSpace(approvalID) {
			approvalIndex = index
			break
		}
	}
	if approvalIndex < 0 {
		return fmt.Errorf("approval %s was not found", approvalID)
	}
	approval := w.approvals[approvalIndex]
	if approval.Status == approvalApproved {
		return nil
	}
	if w.plugins == nil {
		return errors.New("plugin manager is unavailable")
	}

	queuedJobs := 0
	blockedChunks := 0
	for index, chunk := range w.targetChunks {
		if chunk.CampaignID != approval.CampaignID || chunk.Status != targetChunkPlanned {
			continue
		}
		requests := w.kickoffToolRequestsLocked(chunk)
		availableRequests, blockedTools := w.resolveExecutableToolRequests(requests)
		chunk.ToolIDs = make([]string, 0, len(availableRequests))
		for _, request := range availableRequests {
			chunk.ToolIDs = append(chunk.ToolIDs, request.PluginID)
		}
		chunk.ToolIDs = uniqueStrings(chunk.ToolIDs)
		chunk.SkippedTools = append([]string(nil), blockedTools...)
		for _, request := range availableRequests {
			summary := fmt.Sprintf("%s · %d targets", chunk.Name, len(chunk.Values))
			if strings.TrimSpace(request.Summary) != "" {
				summary = request.Summary
			}
			options := cloneStringMap(request.Options)
			options["campaign_id"] = approval.CampaignID
			options["chunk_id"] = chunk.ID
			options["stage"] = request.Stage
			jobView, err := w.plugins.submitDetailed(pluginSubmission{
				PluginID:   request.PluginID,
				RawTargets: append([]string(nil), request.RawTargets...),
				HostIPs:    chunkResolvedHostIPs(chunk),
				Summary:    summary,
				Options:    options,
				CampaignID: approval.CampaignID,
				ChunkID:    chunk.ID,
				Stage:      request.Stage,
				WorkerMode: "central",
			})
			if err != nil {
				return err
			}
			chunk.RunIDs = append(chunk.RunIDs, jobView.ID)
			queuedJobs++
		}
		if len(availableRequests) == 0 {
			blockedChunks++
			chunk.FinishedAt = newEventTimestamp()
		}
		chunk = w.recomputeChunkStateLocked(chunk)
		w.targetChunks[index] = chunk
	}
	for index, campaign := range w.campaigns {
		if campaign.ID != approval.CampaignID {
			continue
		}
		campaign.Stage = "discovery"
		campaign.StageLabel = "Discovery queued"
		w.campaigns[index] = campaign
		break
	}
	w.syncCampaignProgressLocked(approval.CampaignID, queuedJobs, blockedChunks)
	approval.Status = approvalApproved
	approval.DecidedAt = newEventTimestamp()
	w.approvals[approvalIndex] = approval
	if err := w.refreshRecommendationsLocked(); err != nil {
		return err
	}
	if err := w.persistStateLocked(); err != nil {
		return err
	}
	return w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:      "Approval",
		KindTone:  "ok",
		Label:     "Kickoff approved",
		Summary:   fmt.Sprintf("Approved automated discovery for campaign %s.", approval.CampaignID),
		CreatedAt: approval.DecidedAt,
		RefID:     approval.ID,
		Observations: []observationRecord{{
			ID:       newWorkspaceID("obs"),
			Kind:     "approval",
			KindTone: "ok",
			Source:   "Command center",
			Label:    "Automation approved",
			Detail:   fmt.Sprintf("%d tools allowed", len(approval.AllowedToolIDs)),
			Href:     "/campaigns",
		}},
	})
}

func (w *workspace) syncCommandCenterJob(job *pluginJob) {
	if job == nil || strings.TrimSpace(job.CampaignID) == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	for index, chunk := range w.targetChunks {
		if chunk.ID != job.ChunkID {
			continue
		}
		for _, followUp := range w.followUpSubmissionsLocked(chunk, job) {
			jobView, err := w.plugins.submitDetailed(pluginSubmission{
				PluginID:   followUp.PluginID,
				RawTargets: append([]string(nil), followUp.RawTargets...),
				HostIPs:    append([]string(nil), followUp.HostIPs...),
				Summary:    followUp.Summary,
				Options:    cloneStringMap(followUp.Options),
				CampaignID: job.CampaignID,
				ChunkID:    chunk.ID,
				Stage:      followUp.Stage,
				WorkerMode: "central",
			})
			if err != nil {
				if w.logger != nil {
					w.logger.Warn("command-center follow-up degraded", "job", job.ID, "plugin", followUp.PluginID, "error", err)
				}
				continue
			}
			chunk.RunIDs = append(chunk.RunIDs, jobView.ID)
			chunk.ToolIDs = uniqueStrings(append(chunk.ToolIDs, followUp.PluginID))
			chunk.Status = targetChunkQueued
		}
		w.targetChunks[index] = w.recomputeChunkStateLocked(chunk)
	}
	w.syncCampaignProgressLocked(job.CampaignID, 0, 0)
	w.refreshRecommendationsLocked()
	_ = w.persistStateLocked()
}

func (w *workspace) resolveExecutableToolRequests(requests []toolRequest) (available []toolRequest, blocked []string) {
	for _, request := range requests {
		definition, ok := w.plugins.definition(request.PluginID)
		if !ok {
			blocked = append(blocked, fmt.Sprintf("%s: unknown tool", request.PluginID))
			continue
		}
		availability := resolveDefinitionAvailability(definition, request.Options)
		if availability.Available {
			available = append(available, request)
			continue
		}
		blocked = append(blocked, fmt.Sprintf("%s: %s", request.PluginID, availability.Reason))
	}
	return available, blocked
}

func (w *workspace) recomputeChunkStateLocked(chunk targetChunkRecord) targetChunkRecord {
	queued := 0
	running := 0
	completed := 0
	failed := 0
	startedAt := strings.TrimSpace(chunk.StartedAt)
	finishedAt := ""
	errors := make([]string, 0)

	for _, runID := range chunk.RunIDs {
		if w.plugins == nil {
			continue
		}
		job, ok := w.plugins.jobByID(runID)
		if !ok || job == nil {
			continue
		}
		switch job.Status {
		case jobQueued:
			queued++
		case jobRunning:
			running++
		case jobCompleted:
			completed++
		case jobFailed:
			failed++
			if strings.TrimSpace(job.Error) != "" {
				errors = append(errors, fmt.Sprintf("%s: %s", job.PluginID, job.Error))
			}
		}
		if startedAt == "" {
			startedAt = chooseString(job.StartedAt, job.CreatedAt)
		}
		if strings.TrimSpace(job.FinishedAt) != "" {
			finishedAt = job.FinishedAt
		}
	}

	switch {
	case len(chunk.RunIDs) == 0 && len(chunk.SkippedTools) > 0:
		chunk.Status = targetChunkBlocked
	case running > 0:
		chunk.Status = targetChunkRunning
	case queued > 0:
		chunk.Status = targetChunkQueued
	case failed > 0 && completed == 0 && len(chunk.SkippedTools) == 0:
		chunk.Status = jobFailed
	case completed > 0 && failed == 0 && len(chunk.SkippedTools) == 0 && completed == len(chunk.RunIDs):
		chunk.Status = targetChunkCompleted
	case completed > 0 || failed > 0 || len(chunk.SkippedTools) > 0:
		chunk.Status = targetChunkPartial
	case len(chunk.RunIDs) > 0:
		chunk.Status = targetChunkQueued
	default:
		chunk.Status = targetChunkPlanned
	}

	if startedAt != "" {
		chunk.StartedAt = startedAt
	}
	if chunk.Status == targetChunkCompleted || chunk.Status == targetChunkPartial || chunk.Status == targetChunkBlocked || chunk.Status == jobFailed {
		chunk.FinishedAt = chooseString(finishedAt, chunk.FinishedAt, newEventTimestamp())
	} else {
		chunk.FinishedAt = ""
	}

	chunk.StatusDetail = summarizeChunkDetail(chunk, errors)
	return chunk
}

func summarizeChunkDetail(chunk targetChunkRecord, jobErrors []string) string {
	parts := make([]string, 0, 3)
	if len(chunk.ToolIDs) > 0 {
		parts = append(parts, "runs: "+strings.Join(chunk.ToolIDs, ", "))
	}
	if len(chunk.SkippedTools) > 0 {
		parts = append(parts, "blocked: "+strings.Join(chunk.SkippedTools, "; "))
	}
	if len(jobErrors) > 0 {
		parts = append(parts, "errors: "+strings.Join(uniqueStrings(jobErrors), "; "))
	}
	return strings.Join(parts, " · ")
}

func (w *workspace) syncCampaignProgressLocked(campaignID string, queuedJobs int, blockedChunks int) {
	if strings.TrimSpace(campaignID) == "" {
		return
	}

	totalChunks := 0
	statusCounts := map[string]int{}
	for _, chunk := range w.targetChunks {
		if chunk.CampaignID != campaignID {
			continue
		}
		totalChunks++
		statusCounts[chunk.Status]++
	}
	if totalChunks == 0 {
		return
	}

	for index, campaign := range w.campaigns {
		if campaign.ID != campaignID {
			continue
		}
		switch {
		case statusCounts[targetChunkRunning] > 0:
			campaign.Status = jobRunning
			campaign.StageLabel = "Discovery running"
		case statusCounts[targetChunkQueued] > 0 || queuedJobs > 0:
			campaign.Status = jobQueued
			campaign.StageLabel = "Discovery queued"
		case statusCounts[targetChunkCompleted] == totalChunks:
			campaign.Status = jobCompleted
			campaign.StageLabel = "Discovery completed"
		case statusCounts[targetChunkBlocked] == totalChunks:
			campaign.Status = targetChunkBlocked
			campaign.StageLabel = "Discovery blocked"
		case statusCounts[jobFailed] == totalChunks:
			campaign.Status = jobFailed
			campaign.StageLabel = "Discovery failed"
		default:
			campaign.Status = targetChunkPartial
			campaign.StageLabel = "Discovery partial"
		}

		switch campaign.Status {
		case jobCompleted:
			campaign.Summary = fmt.Sprintf("All %d execution chunks completed.", totalChunks)
		case targetChunkBlocked:
			campaign.Summary = "Kickoff prepared chunks, but no executable tools were available in the current environment."
		case jobFailed:
			campaign.Summary = fmt.Sprintf("All %d execution chunks failed.", totalChunks)
		case targetChunkPartial:
			campaign.Summary = fmt.Sprintf("%d chunks completed, %d blocked, %d failed.", statusCounts[targetChunkCompleted], maxInt(statusCounts[targetChunkBlocked], blockedChunks), statusCounts[jobFailed])
		default:
			campaign.Summary = fmt.Sprintf("Queued %d jobs across %d chunks.", maxInt(queuedJobs, statusCounts[targetChunkQueued]+statusCounts[targetChunkRunning]+statusCounts[targetChunkCompleted]+statusCounts[jobFailed]), totalChunks)
			if blockedChunks > 0 || statusCounts[targetChunkBlocked] > 0 {
				campaign.Summary += fmt.Sprintf(" %d chunks are blocked by missing tools.", maxInt(blockedChunks, statusCounts[targetChunkBlocked]))
			}
		}
		w.campaigns[index] = campaign
		return
	}
}

func (w *workspace) generateLLMRecommendations(campaignID string) ([]recommendationRecord, error) {
	planner, err := newLLMPlanner(w.artifactRoot())
	if err != nil {
		return nil, err
	}

	w.mu.RLock()
	var campaign *campaignRecord
	for _, record := range w.campaigns {
		if record.ID == strings.TrimSpace(campaignID) {
			copy := record
			campaign = &copy
			break
		}
	}
	w.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	items, err := planner.RecommendNextSteps(ctx, w, campaign)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	byKey := map[string]recommendationRecord{}
	for _, record := range w.recommendations {
		key := strings.TrimSpace(record.Type) + "|" + strings.TrimSpace(record.Title)
		byKey[key] = record
	}
	for _, item := range items {
		key := strings.TrimSpace(item.Type) + "|" + strings.TrimSpace(item.Title)
		if existing, ok := byKey[key]; ok {
			item.ID = existing.ID
			item.CreatedAt = existing.CreatedAt
			item.Status = existing.Status
		}
		byKey[key] = item
	}
	merged := make([]recommendationRecord, 0, len(byKey))
	for _, record := range byKey {
		merged = append(merged, record)
	}
	sort.SliceStable(merged, func(left, right int) bool {
		return merged[left].CreatedAt > merged[right].CreatedAt
	})
	w.recommendations = merged
	if err := w.persistStateLocked(); err != nil {
		return nil, err
	}
	if err := w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:      "Recommendation",
		KindTone:  "accent",
		Label:     "LLM planner",
		Summary:   fmt.Sprintf("Generated %d planner-backed next-step recommendations.", len(items)),
		CreatedAt: newEventTimestamp(),
		Observations: []observationRecord{{
			ID:       newWorkspaceID("obs"),
			Kind:     "recommendation",
			KindTone: "accent",
			Source:   "LLM planner",
			Label:    fmt.Sprintf("%d new suggestions", len(items)),
			Detail:   "Planner recommendations were added to the recommendation queue.",
			Href:     "/recommendations",
		}},
	}); err != nil {
		return nil, err
	}
	return items, nil
}

func (w *workspace) refreshRecommendationsLocked() error {
	byKey := map[string]recommendationRecord{}
	for _, record := range w.recommendations {
		key := strings.TrimSpace(record.Type) + "|" + strings.TrimSpace(record.Title)
		byKey[key] = record
	}

	recommended := make([]recommendationRecord, 0)
	now := newEventTimestamp()
	snapshot := w.snapshot
	if snapshot != nil {
		httpTargets := 0
		databaseTargets := 0
		highExposure := 0
		for _, record := range snapshot.records {
			httpTargets += record.summary.HTTPTargets
			if record.summary.Exposure.Score >= 70 {
				highExposure++
			}
			for _, port := range record.detail.Ports {
				service := strings.ToLower(strings.TrimSpace(port.Service))
				if service == "mysql" || service == "postgresql" || service == "mssql" {
					databaseTargets++
				}
			}
		}
		if httpTargets > 0 {
			recommended = append(recommended, w.mergeRecommendationLocked(byKey, recommendationRecord{
				ID:               newWorkspaceID("rec"),
				Type:             "tool-chain",
				Status:           recommendationOpen,
				Title:            "Validate discovered HTTP surfaces",
				Detail:           fmt.Sprintf("%d HTTP targets are in scope for nuclei, ZAP, Burp, and SQLMap follow-up.", httpTargets),
				Rationale:        "Recon and fingerprinting have already identified HTTP exposure, so validation tooling now has a useful surface to work against.",
				ExpectedValue:    "medium",
				RequiredApproval: "operator",
				CreatedAt:        now,
				Confidence:       0.84,
				ToolIDs:          []string{"nuclei", "nikto", "zap-connector", "burp-connector", "sqlmap"},
			}))
		}
		if databaseTargets > 0 {
			recommended = append(recommended, w.mergeRecommendationLocked(byKey, recommendationRecord{
				ID:               newWorkspaceID("rec"),
				Type:             "service-follow-up",
				Status:           recommendationOpen,
				Title:            "Deepen database service validation",
				Detail:           fmt.Sprintf("%d database service observations are available for deeper fingerprinting and configuration review.", databaseTargets),
				Rationale:        "Open database services usually justify additional credential, exposure, and configuration validation after basic discovery.",
				ExpectedValue:    "high",
				RequiredApproval: "operator",
				CreatedAt:        now,
				Confidence:       0.71,
				ToolIDs:          []string{"nmap-enrich", "tenable-connector", "nessus-connector"},
			}))
		}
		if highExposure > 0 {
			recommended = append(recommended, w.mergeRecommendationLocked(byKey, recommendationRecord{
				ID:               newWorkspaceID("rec"),
				Type:             "coverage-gap",
				Status:           recommendationOpen,
				Title:            "Expand high-exposure host coverage",
				Detail:           fmt.Sprintf("%d high-exposure hosts should be revisited with deeper service and script coverage.", highExposure),
				Rationale:        "High-exposure assets create the most value when the orchestrator confirms versions, scripts, and vulnerability coverage early.",
				ExpectedValue:    "high",
				RequiredApproval: "operator",
				CreatedAt:        now,
				Confidence:       0.78,
				ToolIDs:          []string{"nmap-enrich", "nuclei", "tenable-connector"},
			}))
		}
	}

	for _, record := range recommended {
		key := strings.TrimSpace(record.Type) + "|" + strings.TrimSpace(record.Title)
		byKey[key] = record
	}
	items := make([]recommendationRecord, 0, len(byKey))
	for _, record := range byKey {
		items = append(items, record)
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Status != items[right].Status {
			return items[left].Status < items[right].Status
		}
		return items[left].CreatedAt > items[right].CreatedAt
	})
	w.recommendations = items
	return nil
}

func (w *workspace) mergeRecommendationLocked(existing map[string]recommendationRecord, next recommendationRecord) recommendationRecord {
	key := strings.TrimSpace(next.Type) + "|" + strings.TrimSpace(next.Title)
	if record, ok := existing[key]; ok {
		if record.Status != recommendationOpen {
			next.Status = record.Status
		}
		next.ID = record.ID
		next.CreatedAt = chooseString(record.CreatedAt, next.CreatedAt)
		next.UpdatedAt = newEventTimestamp()
	}
	return next
}

func sortScopeStateLocked(w *workspace) {
	sort.SliceStable(w.scopeSeeds, func(left, right int) bool {
		return w.scopeSeeds[left].CreatedAt < w.scopeSeeds[right].CreatedAt
	})
	sort.SliceStable(w.scopeTargets, func(left, right int) bool {
		if w.scopeTargets[left].Kind != w.scopeTargets[right].Kind {
			return w.scopeTargets[left].Kind < w.scopeTargets[right].Kind
		}
		return w.scopeTargets[left].Normalized < w.scopeTargets[right].Normalized
	})
	sort.SliceStable(w.targetChunks, func(left, right int) bool {
		return w.targetChunks[left].CreatedAt < w.targetChunks[right].CreatedAt
	})
	sort.SliceStable(w.approvals, func(left, right int) bool {
		return w.approvals[left].CreatedAt < w.approvals[right].CreatedAt
	})
	sort.SliceStable(w.recommendations, func(left, right int) bool {
		return w.recommendations[left].CreatedAt < w.recommendations[right].CreatedAt
	})
	sort.SliceStable(w.campaigns, func(left, right int) bool {
		return w.campaigns[left].CreatedAt < w.campaigns[right].CreatedAt
	})
}

func splitScopeInputs(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\t' || r == ',' || r == ' '
	})
	items := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		items = append(items, field)
	}
	return uniqueStrings(items)
}

func classifyScopeSeed(value string) (kind string, normalized string, detail string, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", "", errors.New("empty scope seed")
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return "ip", addr.String(), "Single host target", nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return "cidr", prefix.Masked().String(), "Network scope", nil
	}
	host := strings.Trim(strings.ToLower(value), ".")
	if host == "" {
		return "", "", "", errors.New("invalid host seed")
	}
	if net.ParseIP(host) != nil {
		return "ip", host, "Single host target", nil
	}
	if strings.Contains(host, ".") {
		if containsAnyLetter(host) {
			return "domain", host, "Domain scope", nil
		}
		return "hostname", host, "Hostname scope", nil
	}
	return "hostname", host, "Hostname scope", nil
}

func containsAnyLetter(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func expandScopeTargets(seed scopeSeedRecord) []scopeTargetRecord {
	switch seed.Kind {
	case "cidr":
		return expandCIDRSeed(seed)
	default:
		return []scopeTargetRecord{{
			ID:         newWorkspaceID("target"),
			SeedID:     seed.ID,
			Kind:       seed.Kind,
			Value:      seed.Value,
			Normalized: seed.Value,
			Status:     scopeTargetReady,
			CreatedAt:  seed.CreatedAt,
			Meta: map[string]string{
				"seed_kind": seed.Kind,
			},
		}}
	}
}

func expandCIDRSeed(seed scopeSeedRecord) []scopeTargetRecord {
	prefix, err := netip.ParsePrefix(seed.Value)
	if err != nil {
		return nil
	}
	prefix = prefix.Masked()
	addrBits := prefix.Addr().BitLen()
	targetBits := addrBits - 8
	if prefix.Bits() > targetBits {
		targetBits = prefix.Bits()
	}
	if targetBits < 0 {
		targetBits = prefix.Bits()
	}
	if addrBits == 128 && targetBits < 120 {
		targetBits = 120
	}

	subPrefixes := splitPrefix(prefix, targetBits)
	targets := make([]scopeTargetRecord, 0, len(subPrefixes))
	for _, sub := range subPrefixes {
		targets = append(targets, scopeTargetRecord{
			ID:         newWorkspaceID("target"),
			SeedID:     seed.ID,
			Kind:       "cidr",
			Value:      sub.String(),
			Normalized: sub.String(),
			Status:     scopeTargetReady,
			CreatedAt:  seed.CreatedAt,
			Meta: map[string]string{
				"seed_kind":  seed.Kind,
				"chunk_size": strconv.Itoa(prefixAddressCapacity(sub)),
			},
		})
	}
	return targets
}

func splitPrefix(prefix netip.Prefix, targetBits int) []netip.Prefix {
	prefix = prefix.Masked()
	if targetBits <= prefix.Bits() || targetBits > prefix.Addr().BitLen() {
		return []netip.Prefix{prefix}
	}

	items := make([]netip.Prefix, 0)
	current := prefix.Addr()
	for prefix.Contains(current) {
		items = append(items, netip.PrefixFrom(current, targetBits).Masked())
		next, ok := advanceAddr(current, 1<<(current.BitLen()-targetBits))
		if !ok || !prefix.Contains(next) {
			break
		}
		current = next
	}
	return items
}

func advanceAddr(addr netip.Addr, steps int) (netip.Addr, bool) {
	next := addr
	for count := 0; count < steps; count++ {
		if !next.IsValid() {
			return netip.Addr{}, false
		}
		next = next.Next()
		if !next.IsValid() {
			return netip.Addr{}, false
		}
	}
	return next, true
}

func prefixAddressCapacity(prefix netip.Prefix) int {
	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits <= 0 {
		return 1
	}
	if bits > 16 {
		return 1 << 16
	}
	return 1 << bits
}

func buildTargetChunks(targets []scopeTargetRecord, campaignID string) []targetChunkRecord {
	grouped := map[string][]scopeTargetRecord{}
	for _, target := range targets {
		groupKey := target.Kind
		grouped[groupKey] = append(grouped[groupKey], target)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	chunks := make([]targetChunkRecord, 0)
	for _, key := range keys {
		rows := grouped[key]
		chunkSize := 64
		stage := "recon"
		namePrefix := "Recon"
		if key == "ip" || key == "cidr" {
			chunkSize = 128
			stage = "discovery"
			namePrefix = "Network discovery"
		} else if key == "domain" || key == "hostname" {
			stage = "recon"
			namePrefix = "Host recon"
		}
		sort.SliceStable(rows, func(left, right int) bool {
			return rows[left].Normalized < rows[right].Normalized
		})
		for offset := 0; offset < len(rows); offset += chunkSize {
			end := minInt(offset+chunkSize, len(rows))
			slice := rows[offset:end]
			chunk := targetChunkRecord{
				ID:         newWorkspaceID("chunk"),
				CampaignID: campaignID,
				Name:       fmt.Sprintf("%s %d", namePrefix, (offset/chunkSize)+1),
				Stage:      stage,
				Kind:       key,
				Status:     targetChunkPlanned,
				CreatedAt:  newEventTimestamp(),
				Size:       len(slice),
			}
			for _, target := range slice {
				chunk.TargetIDs = append(chunk.TargetIDs, target.ID)
				chunk.Values = append(chunk.Values, target.Normalized)
			}
			chunks = append(chunks, chunk)
		}
	}
	return chunks
}

func (w *workspace) allowedToolIDsForChunksLocked(chunks []targetChunkRecord) []string {
	toolIDs := make([]string, 0)
	for _, step := range w.activeOrchestrationPolicyLocked().Steps {
		if step.Enabled {
			toolIDs = append(toolIDs, step.PluginID)
		}
	}
	for _, chunk := range chunks {
		for _, request := range w.kickoffToolRequestsLocked(chunk) {
			toolIDs = append(toolIDs, request.PluginID)
		}
	}
	toolIDs = append(toolIDs, "dnsx", "subfinder", "nmap-enrich", "naabu", "nuclei", "nikto", "sqlmap", "zap-connector", "burp-connector", "tenable-connector", "nessus-connector")
	if w.plugins != nil {
		for _, tool := range w.plugins.catalog() {
			if tool.InstallSource == toolInstallSourceCustom {
				toolIDs = append(toolIDs, tool.ID)
			}
		}
	}
	return uniqueStrings(toolIDs)
}

func buildKickoffRecommendations(campaign campaignRecord, chunks []targetChunkRecord, allowedToolIDs []string, createdAt string) []recommendationRecord {
	records := make([]recommendationRecord, 0, 3)
	records = append(records, recommendationRecord{
		ID:               newWorkspaceID("rec"),
		CampaignID:       campaign.ID,
		Type:             "approval",
		Status:           recommendationOpen,
		Title:            "Approve automated kickoff",
		Detail:           fmt.Sprintf("Launch discovery and recon across %d chunks with central workers.", len(chunks)),
		Rationale:        "The scope is normalized and chunked; the next step is to allow the orchestrator to start discovery without manual target slicing.",
		ExpectedValue:    "high",
		RequiredApproval: "operator",
		CreatedAt:        createdAt,
		Confidence:       0.94,
		ToolIDs:          allowedToolIDs,
	})
	records = append(records, recommendationRecord{
		ID:               newWorkspaceID("rec"),
		CampaignID:       campaign.ID,
		Type:             "llm-plan",
		Status:           recommendationOpen,
		Title:            "Generate next-step operator plan",
		Detail:           "Use the LLM planner to rank the first follow-up actions once discovery results start landing.",
		Rationale:        "The planner can turn raw changes in exposure and services into prioritized next actions for the operator after the first pass runs complete.",
		ExpectedValue:    "medium",
		RequiredApproval: "operator",
		CreatedAt:        createdAt,
		Confidence:       0.61,
		ToolIDs:          []string{"llm-planner"},
	})
	return records
}

func summarizeTargetKinds(targets []scopeTargetRecord) string {
	counts := map[string]int{}
	for _, target := range targets {
		counts[target.Kind]++
	}
	parts := make([]string, 0, len(counts))
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[key], key))
	}
	return strings.Join(parts, " · ")
}

func chunkIDs(chunks []targetChunkRecord) []string {
	ids := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		ids = append(ids, chunk.ID)
	}
	return ids
}

func chunkResolvedHostIPs(chunk targetChunkRecord) []string {
	ips := make([]string, 0, len(chunk.Values))
	for _, value := range chunk.Values {
		if addr, err := netip.ParseAddr(value); err == nil {
			ips = append(ips, addr.String())
		}
	}
	return uniqueStrings(ips)
}
