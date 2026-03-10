package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const changeListLimit = 24

type workspaceHistory struct {
	checkpoints []workspaceCheckpoint
	indexByID   map[string]int
}

type workspaceCheckpoint struct {
	meta  ChangeCheckpointView
	state workspaceCheckpointState
}

type workspaceCheckpointState struct {
	hosts    map[string]historyHost
	ports    map[string]historyPort
	findings map[string]historyFinding
	routes   map[string]historyRoute
}

type historyHost struct {
	IP          string
	DisplayName string
	OS          string
}

type historyPort struct {
	Key       string
	HostIP    string
	Protocol  string
	Port      string
	Service   string
	Product   string
	Version   string
	ExtraInfo string
}

type historyFinding struct {
	Key       string
	HostIP    string
	Name      string
	Source    string
	Severity  string
	Target    string
	MatchedAt string
	KnownHost bool
}

type historyRoute struct {
	Key         string
	TargetIP    string
	TargetLabel string
	Path        string
	Depth       int
}

type replayEvent struct {
	id      string
	at      string
	order   int
	label   string
	kind    string
	tone    string
	summary string
	apply   func(*workspaceReplayState)
}

type workspaceReplayState struct {
	scans       []managedScan
	enrichments map[string]hostEnrichment
}

func buildWorkspaceHistory(scans []managedScan, enrichments map[string]hostEnrichment, jobs []*pluginJob, runsDir string, logger *slog.Logger) *workspaceHistory {
	history := &workspaceHistory{
		indexByID: map[string]int{},
	}

	baselineState := buildCheckpointState(nil, nil)
	history.append(workspaceCheckpoint{
		meta: ChangeCheckpointView{
			ID:           "baseline",
			Label:        "Empty workspace",
			Kind:         "Baseline",
			KindTone:     "ok",
			At:           "n/a",
			Summary:      "No scans or integration findings had been imported yet.",
			HostCount:    len(baselineState.hosts),
			FindingCount: len(baselineState.findings),
			RouteCount:   len(baselineState.routes),
		},
		state: baselineState,
	})

	events := buildReplayEvents(scans, jobs, runsDir, logger)
	replay := workspaceReplayState{
		enrichments: map[string]hostEnrichment{},
	}

	for _, event := range events {
		event.apply(&replay)
		state := buildCheckpointState(replay.scans, replay.enrichments)
		history.append(workspaceCheckpoint{
			meta: ChangeCheckpointView{
				ID:           event.id,
				Label:        event.label,
				Kind:         event.kind,
				KindTone:     event.tone,
				At:           displayTimestamp(event.at),
				Summary:      event.summary,
				HostCount:    len(state.hosts),
				FindingCount: len(state.findings),
				RouteCount:   len(state.routes),
			},
			state: state,
		})
	}

	finalState := buildCheckpointState(scans, enrichments)
	if !history.matchesFinalState(finalState) {
		history.append(workspaceCheckpoint{
			meta: ChangeCheckpointView{
				ID:           "reconciled",
				Label:        "Reconciled workspace state",
				Kind:         "Integration",
				KindTone:     "warning",
				At:           displayTimestamp(""),
				Summary:      "Stored enrichment state could not be fully replayed from artifacts, so the current workspace was appended as a reconciliation checkpoint.",
				HostCount:    len(finalState.hosts),
				FindingCount: len(finalState.findings),
				RouteCount:   len(finalState.routes),
			},
			state: finalState,
		})
	}

	return history
}

func buildReplayEvents(scans []managedScan, jobs []*pluginJob, runsDir string, logger *slog.Logger) []replayEvent {
	jobByID := map[string]*pluginJob{}
	for _, job := range jobs {
		jobByID[job.ID] = job
	}

	events := make([]replayEvent, 0, len(scans)+len(jobs))
	for index, scan := range scans {
		label, kind, tone, summary := scanEventMeta(scan.record, jobByID)
		scanCopy := scan
		events = append(events, replayEvent{
			id:      scan.record.ID,
			at:      chooseString(scan.record.ImportedAt, scan.record.StartedAt),
			order:   index,
			label:   label,
			kind:    kind,
			tone:    tone,
			summary: summary,
			apply: func(state *workspaceReplayState) {
				state.scans = append(state.scans, scanCopy)
			},
		})
	}

	offset := len(events)
	for index, job := range jobs {
		if strings.TrimSpace(job.PluginID) != "nuclei" || job.Status != jobCompleted {
			continue
		}

		findingsPath := jobArtifactPath(job, runsDir, "findings.jsonl")
		if findingsPath == "" {
			continue
		}
		findings, summary, err := parseNucleiJSONL(findingsPath)
		if err != nil {
			if logger != nil {
				logger.Warn("replay nuclei findings for history", "job", job.ID, "error", err)
			}
			continue
		}
		if len(findings) == 0 {
			continue
		}

		findingsCopy := cloneFindingMap(findings)
		events = append(events, replayEvent{
			id:      "job-" + job.ID,
			at:      chooseString(job.FinishedAt, job.StartedAt, job.CreatedAt),
			order:   offset + index,
			label:   job.PluginLabel,
			kind:    "Integration",
			tone:    "accent",
			summary: fmt.Sprintf("%s added %d findings across %d hosts.", job.PluginLabel, summary.Total, len(findingsCopy)),
			apply: func(state *workspaceReplayState) {
				for ip, hostFindings := range findingsCopy {
					current := state.enrichments[ip]
					current.Nuclei = mergeStoredFindings(current.Nuclei, hostFindings)
					state.enrichments[ip] = current
				}
			},
		})
	}

	sort.SliceStable(events, func(left, right int) bool {
		if events[left].at != events[right].at {
			return events[left].at < events[right].at
		}
		return events[left].order < events[right].order
	})
	return events
}

func buildCheckpointState(scans []managedScan, enrichments map[string]hostEnrichment) workspaceCheckpointState {
	inputs := mergedInputs(scans, enrichments)
	records := buildHostRecordsFromInputs(inputs)
	slices.SortStableFunc(records, compareHostRecordsByIP)

	state := workspaceCheckpointState{
		hosts:    map[string]historyHost{},
		ports:    map[string]historyPort{},
		findings: map[string]historyFinding{},
		routes:   map[string]historyRoute{},
	}

	for _, record := range records {
		ip := strings.TrimSpace(record.summary.IP)
		if ip == "" {
			continue
		}

		state.hosts[ip] = historyHost{
			IP:          ip,
			DisplayName: chooseString(record.summary.DisplayName, ip),
			OS:          strings.TrimSpace(record.summary.OS),
		}

		for _, port := range record.detail.Ports {
			if strings.ToLower(strings.TrimSpace(port.State)) != "open" {
				continue
			}

			key := ip + "|" + port.Protocol + "|" + port.Port
			state.ports[key] = historyPort{
				Key:       key,
				HostIP:    ip,
				Protocol:  port.Protocol,
				Port:      port.Port,
				Service:   strings.TrimSpace(port.Service),
				Product:   strings.TrimSpace(port.Product),
				Version:   strings.TrimSpace(port.Version),
				ExtraInfo: strings.TrimSpace(port.ExtraInfo),
			}
		}

		for _, finding := range record.detail.NucleiFindings {
			key := strings.Join([]string{ip, normalizedFindingSource(finding.Source), strings.TrimSpace(finding.TemplateID), strings.TrimSpace(finding.Target), strings.TrimSpace(finding.Name), strings.TrimSpace(finding.MatchedAt)}, "|")
			state.findings[key] = historyFinding{
				Key:       key,
				HostIP:    ip,
				Name:      strings.TrimSpace(finding.Name),
				Source:    normalizedFindingSource(finding.Source),
				Severity:  normalizeSeverity(finding.Severity),
				Target:    strings.TrimSpace(finding.Target),
				MatchedAt: strings.TrimSpace(finding.MatchedAt),
				KnownHost: true,
			}
		}

		if len(record.detail.Trace) > 0 {
			hops := make([]string, 0, len(record.detail.Trace))
			for _, hop := range record.detail.Trace {
				nodeID := graphNodeID(hop)
				if nodeID == "" {
					continue
				}
				hops = appendGraphHop(hops, nodeID)
			}
			if len(hops) > 0 {
				key := ip + "|" + strings.Join(hops, ">")
				state.routes[key] = historyRoute{
					Key:         key,
					TargetIP:    ip,
					TargetLabel: topologyRouteTargetLabel(record.summary, ip),
					Path:        strings.Join(hops, " -> "),
					Depth:       len(hops),
				}
			}
		}
	}

	for ip, enrichment := range enrichments {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		for _, finding := range enrichment.Nuclei {
			key := strings.Join([]string{ip, normalizedFindingSource(finding.Source), strings.TrimSpace(finding.TemplateID), strings.TrimSpace(finding.Target), strings.TrimSpace(finding.Name), strings.TrimSpace(finding.MatchedAt)}, "|")
			if _, ok := state.findings[key]; ok {
				continue
			}
			_, knownHost := state.hosts[ip]
			state.findings[key] = historyFinding{
				Key:       key,
				HostIP:    ip,
				Name:      strings.TrimSpace(finding.Name),
				Source:    normalizedFindingSource(finding.Source),
				Severity:  normalizeSeverity(finding.Severity),
				Target:    strings.TrimSpace(finding.Target),
				MatchedAt: strings.TrimSpace(finding.MatchedAt),
				KnownHost: knownHost,
			}
		}
	}

	return state
}

func (h *workspaceHistory) matchesFinalState(state workspaceCheckpointState) bool {
	if h == nil || len(h.checkpoints) == 0 {
		return len(state.hosts) == 0 && len(state.findings) == 0
	}
	last := h.checkpoints[len(h.checkpoints)-1].state
	return mapsEqual(last.hosts, state.hosts) &&
		mapsEqual(last.ports, state.ports) &&
		mapsEqual(last.findings, state.findings) &&
		mapsEqual(last.routes, state.routes)
}

func (h *workspaceHistory) append(checkpoint workspaceCheckpoint) {
	if h == nil {
		return
	}
	h.indexByID[checkpoint.meta.ID] = len(h.checkpoints)
	h.checkpoints = append(h.checkpoints, checkpoint)
}

func (h *workspaceHistory) hasEvents() bool {
	return h != nil && len(h.checkpoints) > 1
}

func (h *workspaceHistory) comparison(fromID string, toID string) (WorkspaceDiffView, CompareSelection, []ChangeCheckpointView, bool) {
	if h == nil || len(h.checkpoints) == 0 {
		return WorkspaceDiffView{}, CompareSelection{}, nil, false
	}

	fromIndex, toIndex := h.resolveBounds(fromID, toID)
	diff := buildWorkspaceDiff(h.checkpoints[fromIndex], h.checkpoints[toIndex], h.rangeMeta(fromIndex, toIndex))
	return diff, CompareSelection{
		FromID:      h.checkpoints[fromIndex].meta.ID,
		ToID:        h.checkpoints[toIndex].meta.ID,
		FromOptions: h.options(h.checkpoints[fromIndex].meta.ID, toIndex),
		ToOptions:   h.options(h.checkpoints[toIndex].meta.ID, len(h.checkpoints)-1),
	}, h.meta(), len(h.checkpoints) > 1
}

func (h *workspaceHistory) latestDiff() (WorkspaceDiffView, bool) {
	if h == nil || len(h.checkpoints) < 2 {
		return WorkspaceDiffView{}, false
	}
	fromIndex, toIndex := h.latestDiffBounds()
	diff := buildWorkspaceDiff(h.checkpoints[fromIndex], h.checkpoints[toIndex], h.rangeMeta(fromIndex, toIndex))
	return diff, true
}

func (h *workspaceHistory) resolveBounds(fromID string, toID string) (int, int) {
	if strings.TrimSpace(fromID) == "" && strings.TrimSpace(toID) == "" {
		return h.latestDiffBounds()
	}
	if len(h.checkpoints) == 1 {
		return 0, 0
	}

	toIndex := len(h.checkpoints) - 1
	if index, ok := h.indexByID[toID]; ok {
		toIndex = index
	}

	fromIndex := maxInt(toIndex-1, 0)
	if index, ok := h.indexByID[fromID]; ok {
		fromIndex = index
	}

	if fromIndex >= toIndex {
		fromIndex = maxInt(toIndex-1, 0)
	}
	return fromIndex, toIndex
}

func (h *workspaceHistory) latestDiffBounds() (int, int) {
	if h == nil || len(h.checkpoints) <= 1 {
		return 0, 0
	}
	for toIndex := len(h.checkpoints) - 1; toIndex > 0; toIndex-- {
		fromIndex := toIndex - 1
		if !checkpointStatesEqual(h.checkpoints[fromIndex].state, h.checkpoints[toIndex].state) {
			return fromIndex, toIndex
		}
	}
	return maxInt(len(h.checkpoints)-2, 0), len(h.checkpoints) - 1
}

func (h *workspaceHistory) rangeMeta(fromIndex int, toIndex int) []ChangeCheckpointView {
	if h == nil || fromIndex < 0 || toIndex >= len(h.checkpoints) || fromIndex >= toIndex {
		return nil
	}
	items := make([]ChangeCheckpointView, 0, toIndex-fromIndex)
	for index := fromIndex + 1; index <= toIndex; index++ {
		items = append(items, h.checkpoints[index].meta)
	}
	return items
}

func (h *workspaceHistory) meta() []ChangeCheckpointView {
	if h == nil {
		return nil
	}
	items := make([]ChangeCheckpointView, 0, len(h.checkpoints))
	for _, checkpoint := range h.checkpoints {
		items = append(items, checkpoint.meta)
	}
	return items
}

func (h *workspaceHistory) options(selected string, maxIndex int) []SelectOption {
	if h == nil {
		return nil
	}
	if maxIndex < 0 || maxIndex >= len(h.checkpoints) {
		maxIndex = len(h.checkpoints) - 1
	}
	options := make([]SelectOption, 0, maxIndex+1)
	for index := 0; index <= maxIndex; index++ {
		checkpoint := h.checkpoints[index].meta
		label := checkpoint.Label
		if checkpoint.At != "n/a" {
			label = checkpoint.At + " · " + checkpoint.Label
		}
		options = append(options, SelectOption{
			Value:    checkpoint.ID,
			Label:    label,
			Selected: checkpoint.ID == selected,
		})
	}
	return options
}

func buildWorkspaceDiff(from workspaceCheckpoint, to workspaceCheckpoint, events []ChangeCheckpointView) WorkspaceDiffView {
	diff := WorkspaceDiffView{
		From:   from.meta,
		To:     to.meta,
		Events: events,
	}

	for ip, host := range to.state.hosts {
		if _, ok := from.state.hosts[ip]; !ok {
			diff.AddedHosts = append(diff.AddedHosts, ChangeHostView{
				IP:     host.IP,
				Label:  host.DisplayName,
				Detail: strings.TrimSpace(host.OS),
				Href:   hostHref(host.IP, to.state.hosts),
			})
		}
	}
	for ip, host := range from.state.hosts {
		if _, ok := to.state.hosts[ip]; !ok {
			diff.RemovedHosts = append(diff.RemovedHosts, ChangeHostView{
				IP:     host.IP,
				Label:  host.DisplayName,
				Detail: strings.TrimSpace(host.OS),
				Href:   hostHref(host.IP, from.state.hosts),
			})
		}
	}

	for key, before := range from.state.ports {
		after, ok := to.state.ports[key]
		if !ok {
			diff.ClosedPorts = append(diff.ClosedPorts, makePortView(before))
			continue
		}
		if portFingerprint(before) != portFingerprint(after) {
			diff.ServiceChanges = append(diff.ServiceChanges, ChangeServiceView{
				HostIP: before.HostIP,
				Port:   before.Protocol + "/" + before.Port,
				Before: portFingerprint(before),
				After:  portFingerprint(after),
				Href:   hostHref(before.HostIP, to.state.hosts),
			})
		}
	}
	for key, after := range to.state.ports {
		if _, ok := from.state.ports[key]; !ok {
			diff.OpenedPorts = append(diff.OpenedPorts, makePortView(after))
		}
	}

	for ip, after := range to.state.hosts {
		before, ok := from.state.hosts[ip]
		if !ok {
			continue
		}
		if normalizeOS(before.OS) != normalizeOS(after.OS) {
			diff.OSChanges = append(diff.OSChanges, ChangeOSView{
				IP:     ip,
				Label:  chooseString(after.DisplayName, before.DisplayName, ip),
				Before: chooseString(before.OS, "Unknown operating system"),
				After:  chooseString(after.OS, "Unknown operating system"),
				Href:   hostHref(ip, to.state.hosts),
			})
		}
	}

	for key, finding := range to.state.findings {
		if _, ok := from.state.findings[key]; !ok {
			diff.AddedFindings = append(diff.AddedFindings, makeFindingView(finding))
		}
	}
	for key, finding := range from.state.findings {
		if _, ok := to.state.findings[key]; !ok {
			diff.RemovedFindings = append(diff.RemovedFindings, makeFindingView(finding))
		}
	}

	for key, route := range to.state.routes {
		if _, ok := from.state.routes[key]; !ok {
			diff.AddedRoutes = append(diff.AddedRoutes, makeRouteView(route))
		}
	}
	for key, route := range from.state.routes {
		if _, ok := to.state.routes[key]; !ok {
			diff.RemovedRoutes = append(diff.RemovedRoutes, makeRouteView(route))
		}
	}

	sortDiffViews(&diff)
	diff.Summary = ChangeSummary{
		HostsAdded:      len(diff.AddedHosts),
		HostsRemoved:    len(diff.RemovedHosts),
		PortsOpened:     len(diff.OpenedPorts),
		PortsClosed:     len(diff.ClosedPorts),
		ServiceChanges:  len(diff.ServiceChanges),
		OSChanges:       len(diff.OSChanges),
		FindingsAdded:   len(diff.AddedFindings),
		FindingsRemoved: len(diff.RemovedFindings),
		RoutesAdded:     len(diff.AddedRoutes),
		RoutesRemoved:   len(diff.RemovedRoutes),
	}
	diff.SummaryLine = buildChangeSummaryLine(diff.Summary)
	diff.AddedHosts = limitHostViews(diff.AddedHosts, changeListLimit)
	diff.RemovedHosts = limitHostViews(diff.RemovedHosts, changeListLimit)
	diff.OpenedPorts = limitPortViews(diff.OpenedPorts, changeListLimit)
	diff.ClosedPorts = limitPortViews(diff.ClosedPorts, changeListLimit)
	diff.ServiceChanges = limitServiceViews(diff.ServiceChanges, changeListLimit)
	diff.OSChanges = limitOSViews(diff.OSChanges, changeListLimit)
	diff.AddedFindings = limitFindingViews(diff.AddedFindings, changeListLimit)
	diff.RemovedFindings = limitFindingViews(diff.RemovedFindings, changeListLimit)
	diff.AddedRoutes = limitRouteViews(diff.AddedRoutes, changeListLimit)
	diff.RemovedRoutes = limitRouteViews(diff.RemovedRoutes, changeListLimit)
	return diff
}

func sortDiffViews(diff *WorkspaceDiffView) {
	sort.SliceStable(diff.AddedHosts, func(left, right int) bool {
		return compareIPStrings(diff.AddedHosts[left].IP, diff.AddedHosts[right].IP) < 0
	})
	sort.SliceStable(diff.RemovedHosts, func(left, right int) bool {
		return compareIPStrings(diff.RemovedHosts[left].IP, diff.RemovedHosts[right].IP) < 0
	})
	sort.SliceStable(diff.OpenedPorts, func(left, right int) bool {
		if compare := compareIPStrings(diff.OpenedPorts[left].HostIP, diff.OpenedPorts[right].HostIP); compare != 0 {
			return compare < 0
		}
		return comparePorts(portNumber(diff.OpenedPorts[left].Port), protocolName(diff.OpenedPorts[left].Port), portNumber(diff.OpenedPorts[right].Port), protocolName(diff.OpenedPorts[right].Port))
	})
	sort.SliceStable(diff.ClosedPorts, func(left, right int) bool {
		if compare := compareIPStrings(diff.ClosedPorts[left].HostIP, diff.ClosedPorts[right].HostIP); compare != 0 {
			return compare < 0
		}
		return comparePorts(portNumber(diff.ClosedPorts[left].Port), protocolName(diff.ClosedPorts[left].Port), portNumber(diff.ClosedPorts[right].Port), protocolName(diff.ClosedPorts[right].Port))
	})
	sort.SliceStable(diff.ServiceChanges, func(left, right int) bool {
		if compare := compareIPStrings(diff.ServiceChanges[left].HostIP, diff.ServiceChanges[right].HostIP); compare != 0 {
			return compare < 0
		}
		return diff.ServiceChanges[left].Port < diff.ServiceChanges[right].Port
	})
	sort.SliceStable(diff.OSChanges, func(left, right int) bool {
		return compareIPStrings(diff.OSChanges[left].IP, diff.OSChanges[right].IP) < 0
	})
	sort.SliceStable(diff.AddedFindings, func(left, right int) bool {
		if severityWeight(diff.AddedFindings[left].Severity) != severityWeight(diff.AddedFindings[right].Severity) {
			return severityWeight(diff.AddedFindings[left].Severity) > severityWeight(diff.AddedFindings[right].Severity)
		}
		if compare := compareIPStrings(diff.AddedFindings[left].HostIP, diff.AddedFindings[right].HostIP); compare != 0 {
			return compare < 0
		}
		return diff.AddedFindings[left].Name < diff.AddedFindings[right].Name
	})
	sort.SliceStable(diff.RemovedFindings, func(left, right int) bool {
		if severityWeight(diff.RemovedFindings[left].Severity) != severityWeight(diff.RemovedFindings[right].Severity) {
			return severityWeight(diff.RemovedFindings[left].Severity) > severityWeight(diff.RemovedFindings[right].Severity)
		}
		if compare := compareIPStrings(diff.RemovedFindings[left].HostIP, diff.RemovedFindings[right].HostIP); compare != 0 {
			return compare < 0
		}
		return diff.RemovedFindings[left].Name < diff.RemovedFindings[right].Name
	})
	sort.SliceStable(diff.AddedRoutes, func(left, right int) bool {
		if diff.AddedRoutes[left].Target != diff.AddedRoutes[right].Target {
			return diff.AddedRoutes[left].Target < diff.AddedRoutes[right].Target
		}
		return diff.AddedRoutes[left].Path < diff.AddedRoutes[right].Path
	})
	sort.SliceStable(diff.RemovedRoutes, func(left, right int) bool {
		if diff.RemovedRoutes[left].Target != diff.RemovedRoutes[right].Target {
			return diff.RemovedRoutes[left].Target < diff.RemovedRoutes[right].Target
		}
		return diff.RemovedRoutes[left].Path < diff.RemovedRoutes[right].Path
	})
}

func scanEventMeta(record scanRecord, jobs map[string]*pluginJob) (string, string, string, string) {
	if strings.HasPrefix(record.Source, "job:") {
		jobID := strings.TrimPrefix(record.Source, "job:")
		if job := jobs[jobID]; job != nil {
			return job.PluginLabel, "Integration", "accent", fmt.Sprintf("%s imported %d live hosts as %s.", job.PluginLabel, record.LiveHosts, record.Name)
		}
	}
	return chooseString(record.Name, "Imported scan"), "Scan import", "warning", fmt.Sprintf("%s imported %d live hosts.", chooseString(record.Name, "Scan"), record.LiveHosts)
}

func makePortView(port historyPort) ChangePortView {
	return ChangePortView{
		HostIP:  port.HostIP,
		Port:    port.Protocol + "/" + port.Port,
		Service: chooseString(port.Service, "unknown"),
		Detail:  portFingerprint(port),
		Href:    "/ip/" + port.HostIP,
	}
}

func makeFindingView(finding historyFinding) ChangeFindingView {
	href := ""
	if finding.KnownHost {
		href = "/ip/" + finding.HostIP
	}
	return ChangeFindingView{
		HostIP:    finding.HostIP,
		Name:      finding.Name,
		Source:    finding.Source,
		Severity:  finding.Severity,
		Target:    finding.Target,
		Href:      href,
		Inventory: finding.KnownHost,
	}
}

func makeRouteView(route historyRoute) ChangeRouteView {
	return ChangeRouteView{
		Target:   route.TargetLabel,
		TargetIP: route.TargetIP,
		Path:     route.Path,
		Detail:   fmt.Sprintf("%d hops", route.Depth),
	}
}

func buildChangeSummaryLine(summary ChangeSummary) string {
	parts := make([]string, 0, 10)
	if summary.HostsAdded > 0 {
		parts = append(parts, fmt.Sprintf("%d new %s", summary.HostsAdded, pluralWord(summary.HostsAdded, "host", "hosts")))
	}
	if summary.HostsRemoved > 0 {
		parts = append(parts, fmt.Sprintf("%d removed %s", summary.HostsRemoved, pluralWord(summary.HostsRemoved, "host", "hosts")))
	}
	if summary.PortsOpened > 0 {
		parts = append(parts, fmt.Sprintf("%d opened %s", summary.PortsOpened, pluralWord(summary.PortsOpened, "port", "ports")))
	}
	if summary.PortsClosed > 0 {
		parts = append(parts, fmt.Sprintf("%d closed %s", summary.PortsClosed, pluralWord(summary.PortsClosed, "port", "ports")))
	}
	if summary.ServiceChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d service drifts", summary.ServiceChanges))
	}
	if summary.OSChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d OS drifts", summary.OSChanges))
	}
	if summary.FindingsAdded > 0 {
		parts = append(parts, fmt.Sprintf("%d added %s", summary.FindingsAdded, pluralWord(summary.FindingsAdded, "finding", "findings")))
	}
	if summary.FindingsRemoved > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved %s", summary.FindingsRemoved, pluralWord(summary.FindingsRemoved, "finding", "findings")))
	}
	if summary.RoutesAdded > 0 {
		parts = append(parts, fmt.Sprintf("%d new %s", summary.RoutesAdded, pluralWord(summary.RoutesAdded, "route", "routes")))
	}
	if summary.RoutesRemoved > 0 {
		parts = append(parts, fmt.Sprintf("%d removed %s", summary.RoutesRemoved, pluralWord(summary.RoutesRemoved, "route", "routes")))
	}
	if len(parts) == 0 {
		return "No net changes were observed between the selected checkpoints."
	}
	return strings.Join(parts, " · ") + "."
}

func pluralWord(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func cloneFindingMap(values map[string][]storedNucleiFinding) map[string][]storedNucleiFinding {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string][]storedNucleiFinding, len(values))
	for key, findings := range values {
		cloned[key] = append([]storedNucleiFinding(nil), findings...)
	}
	return cloned
}

func jobArtifactPath(job *pluginJob, runsDir string, suffix string) string {
	if job == nil {
		return ""
	}
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	for _, artifact := range job.Artifacts {
		relPath := filepath.ToSlash(strings.TrimSpace(artifact.RelPath))
		if relPath == "" {
			continue
		}
		if suffix == "" || strings.HasSuffix(strings.ToLower(relPath), suffix) {
			return filepath.Join(runsDir, filepath.FromSlash(relPath))
		}
	}
	return ""
}

func portFingerprint(port historyPort) string {
	parts := make([]string, 0, 4)
	if strings.TrimSpace(port.Service) != "" {
		parts = append(parts, port.Service)
	}
	if strings.TrimSpace(port.Product) != "" {
		parts = append(parts, port.Product)
	}
	if strings.TrimSpace(port.Version) != "" {
		parts = append(parts, port.Version)
	}
	if strings.TrimSpace(port.ExtraInfo) != "" {
		parts = append(parts, port.ExtraInfo)
	}
	if len(parts) == 0 {
		return "unclassified service"
	}
	return strings.Join(parts, " · ")
}

func normalizeOS(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "unknown operating system" {
		return ""
	}
	return value
}

func compareIPStrings(left string, right string) int {
	leftAddr, leftErr := netip.ParseAddr(strings.TrimSpace(left))
	rightAddr, rightErr := netip.ParseAddr(strings.TrimSpace(right))
	if leftErr == nil && rightErr == nil {
		if compare := leftAddr.Compare(rightAddr); compare != 0 {
			return compare
		}
	}
	if leftErr == nil && rightErr != nil {
		return -1
	}
	if leftErr != nil && rightErr == nil {
		return 1
	}
	return strings.Compare(left, right)
}

func mapsEqual[T comparable](left map[string]T, right map[string]T) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValue := range left {
		rightValue, ok := right[key]
		if !ok || rightValue != leftValue {
			return false
		}
	}
	return true
}

func checkpointStatesEqual(left workspaceCheckpointState, right workspaceCheckpointState) bool {
	return mapsEqual(left.hosts, right.hosts) &&
		mapsEqual(left.ports, right.ports) &&
		mapsEqual(left.findings, right.findings) &&
		mapsEqual(left.routes, right.routes)
}

func appendReconciliationCheckpoint(history *workspaceHistory, state workspaceCheckpointState) {
	if history == nil {
		return
	}
	history.append(workspaceCheckpoint{
		meta: ChangeCheckpointView{
			ID:           "reconciled",
			Label:        "Reconciled workspace state",
			Kind:         "Integration",
			KindTone:     "warning",
			At:           displayTimestamp(""),
			Summary:      "The current workspace state was appended because the event ledger did not fully match persisted inventory state.",
			HostCount:    len(state.hosts),
			FindingCount: len(state.findings),
			RouteCount:   len(state.routes),
		},
		state: state,
	})
}

func protocolName(value string) string {
	if index := strings.Index(value, "/"); index >= 0 {
		return value[:index]
	}
	return ""
}

func portNumber(value string) string {
	if index := strings.Index(value, "/"); index >= 0 && index+1 < len(value) {
		return value[index+1:]
	}
	return value
}

func hostHref(ip string, hosts map[string]historyHost) string {
	if _, ok := hosts[ip]; ok {
		return "/hosts/" + ip
	}
	return ""
}

func limitHostViews(items []ChangeHostView, limit int) []ChangeHostView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitPortViews(items []ChangePortView, limit int) []ChangePortView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitServiceViews(items []ChangeServiceView, limit int) []ChangeServiceView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitOSViews(items []ChangeOSView, limit int) []ChangeOSView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitFindingViews(items []ChangeFindingView, limit int) []ChangeFindingView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitRouteViews(items []ChangeRouteView, limit int) []ChangeRouteView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}
