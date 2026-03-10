package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

func (w *workspace) savedViewCatalog() []SavedView {
	w.mu.RLock()
	defer w.mu.RUnlock()

	records := append([]savedViewRecord(nil), w.savedViews...)
	sort.SliceStable(records, func(left, right int) bool {
		return records[left].CreatedAt > records[right].CreatedAt
	})

	items := make([]SavedView, 0, len(records))
	for _, record := range records {
		items = append(items, savedViewFromRecord(record))
	}
	return items
}

func (w *workspace) saveView(name string, filter HostFilter) (SavedView, error) {
	filter = normalizeFilter(filter)
	filter.Page = 1

	record := savedViewRecord{
		ID:        newWorkspaceID("view"),
		Name:      chooseString(strings.TrimSpace(name), defaultSavedViewName(filter)),
		Query:     strings.TrimSpace(filter.Query),
		Scope:     normalizeScope(filter.Scope),
		Sort:      normalizeSort(filter.Sort),
		PageSize:  normalizePageSize(filter.PageSize),
		CreatedAt: newEventTimestamp(),
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.savedViews = append(w.savedViews, record)
	sort.SliceStable(w.savedViews, func(left, right int) bool {
		return w.savedViews[left].CreatedAt < w.savedViews[right].CreatedAt
	})
	if err := w.persistStateLocked(); err != nil {
		return SavedView{}, err
	}
	if err := w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:      "Analyst",
		KindTone:  "accent",
		Label:     "Saved view · " + record.Name,
		Summary:   fmt.Sprintf("Saved analyst view %q for %s.", record.Name, describeFilter(record.Query, record.Scope, record.Sort, record.PageSize)),
		CreatedAt: record.CreatedAt,
		RefID:     record.ID,
		Observations: []observationRecord{{
			ID:       newWorkspaceID("obs"),
			Kind:     "view",
			KindTone: "accent",
			Source:   "Analyst",
			Label:    record.Name,
			Detail:   describeFilter(record.Query, record.Scope, record.Sort, record.PageSize),
			Href:     savedViewHref(record),
		}},
	}); err != nil {
		return SavedView{}, err
	}
	return savedViewFromRecord(record), nil
}

func (w *workspace) annotateHost(ip string, tags []string, noteText string) error {
	ip = strings.TrimSpace(ip)
	noteText = strings.TrimSpace(noteText)
	if ip == "" {
		return errors.New("host IP is required")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.snapshot == nil {
		return errors.New("workspace snapshot is unavailable")
	}
	if _, ok := w.snapshot.host(ip); !ok {
		return fmt.Errorf("host %s is not present in the current workspace", ip)
	}

	current := w.enrichments[ip]
	normalizedTags := normalizeTags(tags)
	observations := make([]observationRecord, 0, 2)
	summaryParts := make([]string, 0, 2)

	if !stringSetsEqual(current.Tags, normalizedTags) {
		current.Tags = normalizedTags
		tagDetail := "cleared analyst tags"
		if len(normalizedTags) > 0 {
			tagDetail = strings.Join(normalizedTags, ", ")
			summaryParts = append(summaryParts, fmt.Sprintf("updated %d tags", len(normalizedTags)))
		} else {
			summaryParts = append(summaryParts, "cleared analyst tags")
		}
		observations = append(observations, observationRecord{
			ID:       newWorkspaceID("obs"),
			Kind:     "tag",
			KindTone: "ok",
			Source:   "Analyst",
			HostIP:   ip,
			Label:    "Tags updated",
			Detail:   tagDetail,
			Href:     "/ip/" + ip,
		})
	}

	if noteText != "" {
		current.Notes = append(current.Notes, analystNote{
			ID:        newWorkspaceID("note"),
			Text:      noteText,
			CreatedAt: newEventTimestamp(),
		})
		summaryParts = append(summaryParts, "added analyst note")
		observations = append(observations, observationRecord{
			ID:       newWorkspaceID("obs"),
			Kind:     "note",
			KindTone: "accent",
			Source:   "Analyst",
			HostIP:   ip,
			Label:    "Analyst note",
			Detail:   truncateText(noteText, 140),
			Href:     "/ip/" + ip,
		})
	}

	if len(observations) == 0 {
		return errors.New("no annotation changes were provided")
	}

	w.enrichments[ip] = current
	w.rebuildSnapshotLocked()
	if err := w.persistStateLocked(); err != nil {
		return err
	}
	return w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:         "Analyst",
		KindTone:     "accent",
		Label:        "Host annotation · " + ip,
		Summary:      strings.Join(summaryParts, " and ") + " on " + ip + ".",
		CreatedAt:    newEventTimestamp(),
		RefID:        ip,
		HostIPs:      []string{ip},
		Observations: observations,
	})
}

func (w *workspace) campaignCatalog() []CampaignView {
	w.mu.RLock()
	defer w.mu.RUnlock()

	records := append([]campaignRecord(nil), w.campaigns...)
	sort.SliceStable(records, func(left, right int) bool {
		return records[left].CreatedAt > records[right].CreatedAt
	})

	items := make([]CampaignView, 0, len(records))
	for _, record := range records {
		items = append(items, w.campaignViewLocked(record))
	}
	return items
}

func (w *workspace) createCampaign(name string, pluginID string, scope string, fromID string, toID string, options map[string]string) (CampaignView, error) {
	if w.plugins == nil {
		return CampaignView{}, errors.New("plugin manager is unavailable")
	}

	diff, compare, _, ok := w.changeComparison(fromID, toID)
	if !ok {
		return CampaignView{}, errors.New("no diff checkpoints are available for campaign targeting")
	}

	scope = normalizeCampaignScope(scope)
	hostIPs := campaignHostIPs(w.currentSnapshot(), diff, scope)
	if len(hostIPs) == 0 {
		return CampaignView{}, errors.New("the selected diff scope did not resolve any live hosts")
	}

	scopeLabel := campaignScopeLabel(scope)
	targetSummary := fmt.Sprintf("%s · %d hosts", scopeLabel, len(hostIPs))
	job, err := w.plugins.submit(pluginID, hostIPs, hostIPs, targetSummary, options)
	if err != nil {
		return CampaignView{}, err
	}

	record := campaignRecord{
		ID:          newWorkspaceID("campaign"),
		Name:        chooseString(strings.TrimSpace(name), job.PluginLabel+" · "+scopeLabel),
		PluginID:    pluginID,
		PluginLabel: job.PluginLabel,
		Scope:       scope,
		CompareFrom: compare.FromID,
		CompareTo:   compare.ToID,
		HostIPs:     append([]string(nil), hostIPs...),
		Options:     cloneStringMap(options),
		Status:      job.Status,
		Summary:     fmt.Sprintf("%s queued across %d hosts from %s to %s.", job.PluginLabel, len(hostIPs), diff.From.Label, diff.To.Label),
		CreatedAt:   newEventTimestamp(),
		JobID:       job.ID,
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.campaigns = append(w.campaigns, record)
	sort.SliceStable(w.campaigns, func(left, right int) bool {
		return w.campaigns[left].CreatedAt < w.campaigns[right].CreatedAt
	})
	if err := w.persistStateLocked(); err != nil {
		return CampaignView{}, err
	}
	if err := w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:      "Campaign",
		KindTone:  "accent",
		Label:     record.Name,
		Summary:   record.Summary,
		CreatedAt: record.CreatedAt,
		RefID:     record.ID,
		HostIPs:   append([]string(nil), hostIPs...),
		Observations: []observationRecord{{
			ID:       newWorkspaceID("obs"),
			Kind:     "campaign",
			KindTone: "accent",
			Source:   job.PluginLabel,
			Label:    record.Name,
			Detail:   targetSummary,
			Href:     "/changes?" + changeQuery(compare.FromID, compare.ToID),
		}},
	}); err != nil {
		return CampaignView{}, err
	}
	return w.campaignViewLocked(record), nil
}

func savedViewFromRecord(record savedViewRecord) SavedView {
	return SavedView{
		ID:        record.ID,
		Name:      record.Name,
		Href:      savedViewHref(record),
		Query:     record.Query,
		Scope:     record.Scope,
		Sort:      record.Sort,
		PageSize:  record.PageSize,
		CreatedAt: displayTimestamp(record.CreatedAt),
	}
}

func savedViewHref(record savedViewRecord) string {
	return filterHrefFrom("/hosts", HostFilter{
		Query:    record.Query,
		Scope:    record.Scope,
		Sort:     record.Sort,
		Page:     1,
		PageSize: record.PageSize,
	}, 1)
}

func defaultSavedViewName(filter HostFilter) string {
	description := describeFilter(filter.Query, filter.Scope, filter.Sort, filter.PageSize)
	description = strings.ReplaceAll(description, " · ", " ")
	return "View · " + description
}

func describeFilter(query string, scope string, sort string, pageSize int) string {
	parts := make([]string, 0, 4)
	query = strings.TrimSpace(query)
	if query == "" {
		parts = append(parts, "all hosts")
	} else {
		parts = append(parts, "query "+query)
	}
	if normalized := normalizeScope(scope); normalized != "all" {
		parts = append(parts, "scope "+normalized)
	}
	parts = append(parts, "sort "+normalizeSort(sort))
	parts = append(parts, fmt.Sprintf("%d rows", normalizePageSize(pageSize)))
	return strings.Join(parts, " · ")
}

func campaignScopeOptions(selected string) []SelectOption {
	selected = normalizeCampaignScope(selected)
	options := []struct {
		value string
		label string
	}{
		{value: "all-changed", label: "All changed hosts"},
		{value: "high-priority", label: "High-priority drift"},
		{value: "new-hosts", label: "New hosts"},
		{value: "opened-ports", label: "Opened ports"},
		{value: "service-drift", label: "Service drift"},
		{value: "os-drift", label: "OS drift"},
		{value: "new-findings", label: "New findings"},
		{value: "route-drift", label: "Route drift"},
	}

	items := make([]SelectOption, 0, len(options))
	for _, option := range options {
		items = append(items, SelectOption{
			Value:    option.value,
			Label:    option.label,
			Selected: option.value == selected,
		})
	}
	return items
}

func normalizeCampaignScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "new-hosts", "opened-ports", "service-drift", "os-drift", "new-findings", "route-drift", "high-priority":
		return strings.ToLower(strings.TrimSpace(scope))
	default:
		return "all-changed"
	}
}

func campaignScopeLabel(scope string) string {
	switch normalizeCampaignScope(scope) {
	case "new-hosts":
		return "new hosts"
	case "opened-ports":
		return "opened ports"
	case "service-drift":
		return "service drift"
	case "os-drift":
		return "OS drift"
	case "new-findings":
		return "new findings"
	case "route-drift":
		return "route drift"
	case "high-priority":
		return "high-priority drift"
	default:
		return "all changed hosts"
	}
}

func campaignHostIPs(snapshot *snapshot, diff WorkspaceDiffView, scope string) []string {
	candidates := make([]string, 0)
	addKnown := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" || snapshot == nil {
			return
		}
		if _, ok := snapshot.host(ip); ok {
			candidates = append(candidates, ip)
		}
	}

	switch normalizeCampaignScope(scope) {
	case "new-hosts":
		for _, item := range diff.AddedHosts {
			addKnown(item.IP)
		}
	case "opened-ports":
		for _, item := range diff.OpenedPorts {
			addKnown(item.HostIP)
		}
	case "service-drift":
		for _, item := range diff.ServiceChanges {
			addKnown(item.HostIP)
		}
	case "os-drift":
		for _, item := range diff.OSChanges {
			addKnown(item.IP)
		}
	case "new-findings":
		for _, item := range diff.AddedFindings {
			addKnown(item.HostIP)
		}
	case "route-drift":
		for _, item := range diff.AddedRoutes {
			addKnown(item.TargetIP)
		}
		for _, item := range diff.RemovedRoutes {
			addKnown(item.TargetIP)
		}
	case "high-priority":
		for _, item := range diff.AddedFindings {
			if severityWeight(item.Severity) >= severityWeight("high") {
				addKnown(item.HostIP)
			}
		}
		for _, item := range diff.OpenedPorts {
			if _, ok := criticalPorts[portNumber(item.Port)]; ok {
				addKnown(item.HostIP)
			}
		}
	default:
		for _, item := range diff.AddedHosts {
			addKnown(item.IP)
		}
		for _, item := range diff.OpenedPorts {
			addKnown(item.HostIP)
		}
		for _, item := range diff.ServiceChanges {
			addKnown(item.HostIP)
		}
		for _, item := range diff.OSChanges {
			addKnown(item.IP)
		}
		for _, item := range diff.AddedFindings {
			addKnown(item.HostIP)
		}
		for _, item := range diff.AddedRoutes {
			addKnown(item.TargetIP)
		}
	}

	return uniqueStrings(candidates)
}

func (w *workspace) campaignViewLocked(record campaignRecord) CampaignView {
	status := strings.TrimSpace(record.Status)
	summary := strings.TrimSpace(record.Summary)
	if w.plugins != nil {
		if job, ok := w.plugins.jobByID(record.JobID); ok {
			status = chooseString(job.Status, status)
			if strings.TrimSpace(job.Summary) != "" {
				summary = job.Summary
			} else if strings.TrimSpace(job.Error) != "" {
				summary = job.Error
			}
		}
	}
	if status == "" {
		status = jobQueued
	}
	return CampaignView{
		ID:          record.ID,
		Name:        record.Name,
		PluginID:    record.PluginID,
		PluginLabel: record.PluginLabel,
		Scope:       campaignScopeLabel(record.Scope),
		Stage:       chooseString(record.StageLabel, record.Stage, "queued"),
		Status:      status,
		StatusTone:  jobStatusTone(status),
		Summary:     summary,
		TargetCount: len(record.HostIPs),
		CreatedAt:   displayTimestamp(record.CreatedAt),
		JobID:       record.JobID,
	}
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	items := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, tag)
	}
	sort.SliceStable(items, func(left, right int) bool {
		return strings.ToLower(items[left]) < strings.ToLower(items[right])
	})
	return items
}

func parseTagList(raw string) []string {
	return normalizeTags(strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	}))
}

func stringSetsEqual(left []string, right []string) bool {
	left = normalizeTags(left)
	right = normalizeTags(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !strings.EqualFold(left[index], right[index]) {
			return false
		}
	}
	return true
}

func truncateText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit]) + "..."
}
