package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type findingGroupAccumulator struct {
	group        FindingGroupView
	occurrences  []FindingOccurrenceView
	relatedScans map[string]struct{}
	relatedHosts map[string]struct{}
	relatedPorts map[string]struct{}
	description  string
	tags         map[string]struct{}
}

func (w *workspace) scanByID(id string) (managedScan, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, scan := range w.scans {
		if scan.record.ID == strings.TrimSpace(id) {
			return scan, true
		}
	}
	return managedScan{}, false
}

func (w *workspace) scanCatalogItem(id string) (ScanCatalogItem, bool) {
	for _, item := range w.scanCatalog() {
		if item.ID == strings.TrimSpace(id) {
			return item, true
		}
	}
	return ScanCatalogItem{}, false
}

func (w *workspace) recentScans(limit int) []ScanCatalogItem {
	items := w.scanCatalog()
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

func (w *workspace) scanHostRecords(id string) ([]hostRecord, managedScan, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, scan := range w.scans {
		if scan.record.ID != strings.TrimSpace(id) {
			continue
		}

		inputs := make([]hostBuildInput, 0, len(scan.scan.Alive()))
		for _, host := range scan.scan.Alive() {
			ip := strings.TrimSpace(host.Address.Addr)
			inputs = append(inputs, hostBuildInput{
				host:       host,
				sources:    []string{scan.record.Name},
				enrichment: w.enrichments[ip],
			})
		}
		records := buildHostRecordsFromInputs(inputs)
		sort.SliceStable(records, func(left, right int) bool {
			return compareHostRecordsByIP(records[left], records[right]) < 0
		})
		return records, scan, true
	}
	return nil, managedScan{}, false
}

func (w *workspace) scanScopedHost(id string, ip string) (HostDetail, bool) {
	records, _, ok := w.scanHostRecords(id)
	if !ok {
		return HostDetail{}, false
	}
	for _, record := range records {
		if record.summary.IP == strings.TrimSpace(ip) {
			return record.detail, true
		}
	}
	return HostDetail{}, false
}

func (w *workspace) scanDetail(id string) (ScanDetailView, bool) {
	records, scan, ok := w.scanHostRecords(id)
	if !ok {
		return ScanDetailView{}, false
	}

	summary, _ := w.scanCatalogItem(id)
	detail := ScanDetailView{
		Summary:       summary,
		SourceLabel:   chooseString(scan.record.Source, "scan-import"),
		Description:   fmt.Sprintf("%s imported %d live %s.", chooseString(scan.record.Name, "Scan"), scan.record.LiveHosts, pluralWord(scan.record.LiveHosts, "host", "hosts")),
		HostCount:     len(records),
		FindingTotals: summarizeFindingsForRecords(records),
		Hosts:         make([]HostSummary, 0, len(records)),
		Ports:         portSummariesForRecords(records),
		Findings:      findingGroupsForRecords(records, w.scanTimeByName()),
		Jobs:          w.jobsForScan(scan.record),
	}
	for _, record := range records {
		detail.Hosts = append(detail.Hosts, record.summary)
	}
	return detail, true
}

func (w *workspace) jobsForScan(record scanRecord) []PluginJobView {
	if w.plugins == nil {
		return nil
	}
	if jobID, ok := strings.CutPrefix(strings.TrimSpace(record.Source), "job:"); ok {
		if job, found := w.plugins.jobByID(jobID); found {
			return []PluginJobView{jobView(job)}
		}
	}
	return nil
}

func (w *workspace) portSummaries() []PortSummaryView {
	return portSummariesForRecords(w.currentSnapshot().records)
}

func (w *workspace) filteredPortSummaries(query string, sortBy string) []PortSummaryView {
	query = strings.ToLower(strings.TrimSpace(query))
	rows := w.portSummaries()
	if query != "" {
		filtered := make([]PortSummaryView, 0, len(rows))
		for _, row := range rows {
			haystack := strings.ToLower(strings.Join([]string{
				row.Label,
				row.Protocol,
				row.Port,
				row.Service,
				row.Exposure,
			}, " "))
			if strings.Contains(haystack, query) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	sort.SliceStable(rows, func(left, right int) bool {
		switch normalizePortSort(sortBy) {
		case "findings":
			if rows[left].Findings != rows[right].Findings {
				return rows[left].Findings > rows[right].Findings
			}
		case "scans":
			if rows[left].Scans != rows[right].Scans {
				return rows[left].Scans > rows[right].Scans
			}
		case "port":
			if rows[left].Protocol != rows[right].Protocol {
				return rows[left].Protocol < rows[right].Protocol
			}
			return comparePorts(rows[left].Port, rows[left].Protocol, rows[right].Port, rows[right].Protocol)
		default:
			if rows[left].Hosts != rows[right].Hosts {
				return rows[left].Hosts > rows[right].Hosts
			}
		}
		if rows[left].Hosts != rows[right].Hosts {
			return rows[left].Hosts > rows[right].Hosts
		}
		if rows[left].Findings != rows[right].Findings {
			return rows[left].Findings > rows[right].Findings
		}
		return comparePorts(rows[left].Port, rows[left].Protocol, rows[right].Port, rows[right].Protocol)
	})
	return rows
}

func portSummariesForRecords(records []hostRecord) []PortSummaryView {
	type portAccumulator struct {
		protocol string
		port     string
		service  string
		hosts    map[string]struct{}
		scans    map[string]struct{}
		findings int
	}

	ports := map[string]*portAccumulator{}
	for _, record := range records {
		for _, port := range record.detail.Ports {
			if !strings.EqualFold(port.State, "open") {
				continue
			}
			key := port.Protocol + "|" + port.Port
			entry := ports[key]
			if entry == nil {
				entry = &portAccumulator{
					protocol: port.Protocol,
					port:     port.Port,
					service:  chooseString(strings.TrimSpace(port.Service), strings.TrimSpace(port.Product), "unknown service"),
					hosts:    map[string]struct{}{},
					scans:    map[string]struct{}{},
				}
				ports[key] = entry
			}
			entry.hosts[record.summary.IP] = struct{}{}
			for _, scanName := range record.detail.SourceScans {
				entry.scans[scanName] = struct{}{}
			}
			if findingCount := countPortFindings(record.detail.NucleiFindings, record.summary.IP, port.Protocol, port.Port); findingCount > 0 {
				entry.findings += findingCount
			}
		}
	}

	rows := make([]PortSummaryView, 0, len(ports))
	for _, entry := range ports {
		label := entry.protocol + "/" + entry.port
		rows = append(rows, PortSummaryView{
			Protocol: entry.protocol,
			Port:     entry.port,
			Label:    label,
			Service:  entry.service,
			Hosts:    len(entry.hosts),
			Findings: entry.findings,
			Scans:    len(entry.scans),
			Exposure: portExposureLabel(entry.port, entry.findings),
			Href:     "/ports/" + entry.protocol + "/" + entry.port,
		})
	}

	sort.SliceStable(rows, func(left, right int) bool {
		if rows[left].Hosts != rows[right].Hosts {
			return rows[left].Hosts > rows[right].Hosts
		}
		if rows[left].Findings != rows[right].Findings {
			return rows[left].Findings > rows[right].Findings
		}
		return comparePorts(rows[left].Port, rows[left].Protocol, rows[right].Port, rows[right].Protocol)
	})
	return rows
}

func portServiceBuckets(rows []PortSummaryView) []Bucket {
	counts := map[string]int{}
	for _, row := range rows {
		label := chooseString(strings.TrimSpace(row.Service), "unknown service")
		counts[label] += row.Hosts
	}
	return sortedBucketCounts(counts, func(label string) string {
		return "/ports?query=" + url.QueryEscape(label)
	})
}

func portExposureBuckets(rows []PortSummaryView) []Bucket {
	counts := map[string]int{}
	for _, row := range rows {
		counts[chooseString(strings.TrimSpace(row.Exposure), "baseline")]++
	}
	return sortedBucketCounts(counts, func(label string) string {
		return "/ports?query=" + url.QueryEscape(label)
	})
}

func portStats(rows []PortSummaryView) []StatCard {
	totalHosts := 0
	totalFindings := 0
	findingBacked := 0
	for _, row := range rows {
		totalHosts += row.Hosts
		totalFindings += row.Findings
		if row.Findings > 0 {
			findingBacked++
		}
	}

	topService := "No services mapped"
	serviceBuckets := portServiceBuckets(rows)
	if len(serviceBuckets) > 0 {
		topService = serviceBuckets[0].Label + " carries the most host exposure"
	}

	return []StatCard{
		{Label: "Distinct ports", Value: strconv.Itoa(len(rows)), Detail: topService, Tone: "accent"},
		{Label: "Host exposures", Value: strconv.Itoa(totalHosts), Detail: "Total host-to-port observations in this slice", Tone: "calm"},
		{Label: "Finding-backed", Value: strconv.Itoa(findingBacked), Detail: strconv.Itoa(totalFindings) + " findings tied to these ports", Tone: "warning"},
	}
}

func (w *workspace) portDetail(protocol string, port string, scanID string, hostIP string) (PortDetailView, bool) {
	snapshot := w.currentSnapshot()
	protocol = strings.TrimSpace(protocol)
	port = strings.TrimSpace(port)
	hostIP = strings.TrimSpace(hostIP)

	rows := make([]PortHostView, 0)
	relatedScanNames := map[string]struct{}{}
	matchingRecords := make([]hostRecord, 0)
	totals := FindingSummary{}
	service := ""

	for _, record := range snapshot.records {
		if hostIP != "" && record.summary.IP != hostIP {
			continue
		}
		if scanID != "" && !slicesContains(record.detail.SourceScans, w.scanNameForID(scanID)) {
			continue
		}

		for _, portRow := range record.detail.Ports {
			if !strings.EqualFold(portRow.State, "open") {
				continue
			}
			if portRow.Protocol != protocol || portRow.Port != port {
				continue
			}

			service = chooseString(strings.TrimSpace(portRow.Service), strings.TrimSpace(portRow.Product), service, "unknown service")
			findings := portFindingSummary(record.detail.NucleiFindings, record.summary.IP, protocol, port)
			totals.Total += findings.Total
			totals.Critical += findings.Critical
			totals.High += findings.High
			totals.Medium += findings.Medium
			totals.Low += findings.Low
			totals.Info += findings.Info
			rows = append(rows, PortHostView{
				IP:          record.summary.IP,
				DisplayName: record.summary.DisplayName,
				OS:          record.summary.OS,
				Service:     strings.TrimSpace(portRow.Service),
				Product:     strings.TrimSpace(portRow.Product),
				Version:     strings.TrimSpace(portRow.Version),
				Findings:    findings.Total,
				Scans:       append([]string(nil), record.detail.SourceScans...),
				Href:        "/hosts/" + record.summary.IP,
			})
			matchingRecords = append(matchingRecords, record)
			for _, scanName := range record.detail.SourceScans {
				relatedScanNames[scanName] = struct{}{}
			}
			break
		}
	}

	if len(rows) == 0 {
		return PortDetailView{}, false
	}

	sort.SliceStable(rows, func(left, right int) bool {
		if rows[left].Findings != rows[right].Findings {
			return rows[left].Findings > rows[right].Findings
		}
		return compareIPStrings(rows[left].IP, rows[right].IP) < 0
	})

	return PortDetailView{
		Protocol:        protocol,
		Port:            port,
		Label:           protocol + "/" + port,
		Service:         service,
		HostCount:       len(rows),
		FindingTotals:   totals,
		Hosts:           rows,
		RelatedScans:    w.scanItemsForNames(relatedScanNames),
		RelatedFindings: findingGroupsForPort(matchingRecords, protocol, port, w.scanTimeByName()),
		HostTargets:     portHostTargets(rows),
	}, true
}

func (w *workspace) findingGroups() []FindingGroupView {
	return findingGroupsForRecords(w.currentSnapshot().records, w.scanTimeByName())
}

func (w *workspace) filteredFindingGroups(query string, severity string, source string, sortBy string) []FindingGroupView {
	groups := w.findingGroups()
	query = strings.ToLower(strings.TrimSpace(query))
	severity = normalizeFindingSeverityFilter(severity)
	source = strings.ToLower(strings.TrimSpace(source))

	filtered := make([]FindingGroupView, 0, len(groups))
	for _, group := range groups {
		if severity != "all" && normalizeSeverity(group.Severity) != severity {
			continue
		}
		if source != "" && source != "all" && strings.ToLower(strings.TrimSpace(group.Source)) != source {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{
				group.Name,
				group.TemplateID,
				group.Source,
				group.Severity,
			}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, group)
	}

	sort.SliceStable(filtered, func(left, right int) bool {
		switch normalizeFindingSort(sortBy) {
		case "hosts":
			if filtered[left].Hosts != filtered[right].Hosts {
				return filtered[left].Hosts > filtered[right].Hosts
			}
		case "occurrences":
			if filtered[left].Occurrences != filtered[right].Occurrences {
				return filtered[left].Occurrences > filtered[right].Occurrences
			}
		case "recent":
			if filtered[left].LastSeen != filtered[right].LastSeen {
				return filtered[left].LastSeen > filtered[right].LastSeen
			}
		default:
			if severityWeight(filtered[left].Severity) != severityWeight(filtered[right].Severity) {
				return severityWeight(filtered[left].Severity) > severityWeight(filtered[right].Severity)
			}
		}
		if severityWeight(filtered[left].Severity) != severityWeight(filtered[right].Severity) {
			return severityWeight(filtered[left].Severity) > severityWeight(filtered[right].Severity)
		}
		if filtered[left].Occurrences != filtered[right].Occurrences {
			return filtered[left].Occurrences > filtered[right].Occurrences
		}
		return filtered[left].Name < filtered[right].Name
	})
	return filtered
}

func (w *workspace) findingDetail(groupID string, scanID string, hostIP string, protocol string, port string) (FindingDetailView, bool) {
	groupID = strings.TrimSpace(groupID)
	scanName := w.scanNameForID(scanID)
	accumulators := groupFindings(w.currentSnapshot().records, w.scanTimeByName())
	accumulator, ok := accumulators[groupID]
	if !ok {
		return FindingDetailView{}, false
	}

	filtered := make([]FindingOccurrenceView, 0, len(accumulator.occurrences))
	for _, occurrence := range accumulator.occurrences {
		if hostIP != "" && occurrence.HostIP != hostIP {
			continue
		}
		if scanName != "" && !slicesContains(occurrence.Scans, scanName) {
			continue
		}
		if port != "" && occurrence.Port != port {
			continue
		}
		if protocol != "" && occurrence.Port != "" && !strings.Contains(strings.ToLower(occurrence.Target), protocol) {
			// Keep protocol filtering best-effort for URL-style targets.
		}
		filtered = append(filtered, occurrence)
	}
	if len(filtered) == 0 && (hostIP != "" || scanName != "" || port != "") {
		return FindingDetailView{}, false
	}
	if len(filtered) == 0 {
		filtered = append(filtered, accumulator.occurrences...)
	}

	relatedJobs := w.relatedJobsForFinding(filtered)
	return FindingDetailView{
		Group:        accumulator.group,
		Occurrences:  filtered,
		RelatedScans: w.scanItemsForNames(accumulator.relatedScans),
		RelatedJobs:  relatedJobs,
		Description:  accumulator.description,
		Tags:         sortedKeys(accumulator.tags),
	}, true
}

func (w *workspace) relatedJobsForFinding(occurrences []FindingOccurrenceView) []PluginJobView {
	if w.plugins == nil {
		return nil
	}
	seen := map[string]PluginJobView{}
	for _, occurrence := range occurrences {
		for _, job := range w.hostJobs(occurrence.HostIP, 8) {
			seen[job.ID] = job
		}
	}
	items := make([]PluginJobView, 0, len(seen))
	for _, job := range seen {
		items = append(items, job)
	}
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].CreatedAt > items[right].CreatedAt
	})
	if len(items) > 12 {
		items = items[:12]
	}
	return items
}

func findingGroupsForRecords(records []hostRecord, scanTimes map[string][]string) []FindingGroupView {
	accumulators := groupFindings(records, scanTimes)
	items := make([]FindingGroupView, 0, len(accumulators))
	for _, accumulator := range accumulators {
		items = append(items, accumulator.group)
	}
	sort.SliceStable(items, func(left, right int) bool {
		if severityWeight(items[left].Severity) != severityWeight(items[right].Severity) {
			return severityWeight(items[left].Severity) > severityWeight(items[right].Severity)
		}
		if items[left].Occurrences != items[right].Occurrences {
			return items[left].Occurrences > items[right].Occurrences
		}
		return items[left].Name < items[right].Name
	})
	return items
}

func findingGroupsForPort(records []hostRecord, protocol string, port string, scanTimes map[string][]string) []FindingGroupView {
	filtered := make([]hostRecord, 0, len(records))
	for _, record := range records {
		copyRecord := record
		copyRecord.detail.NucleiFindings = filterPortFindings(record.detail.NucleiFindings, record.summary.IP, protocol, port)
		if len(copyRecord.detail.NucleiFindings) == 0 {
			continue
		}
		filtered = append(filtered, copyRecord)
	}
	return findingGroupsForRecords(filtered, scanTimes)
}

func filterPortFindings(findings []NucleiFindingView, hostIP string, protocol string, port string) []NucleiFindingView {
	filtered := make([]NucleiFindingView, 0)
	for _, finding := range findings {
		if targetMatchesPort(hostIP, protocol, port, finding.Target) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func portHostTargets(rows []PortHostView) []string {
	targets := make([]string, 0, len(rows))
	for _, row := range rows {
		targets = append(targets, row.IP)
	}
	return uniqueStrings(targets)
}

func findingHostTargets(detail FindingDetailView) []string {
	targets := make([]string, 0, len(detail.Occurrences))
	for _, occurrence := range detail.Occurrences {
		targets = append(targets, occurrence.HostIP)
	}
	return uniqueStrings(targets)
}

func findingSeverityBuckets(groups []FindingGroupView) []Bucket {
	counts := map[string]int{}
	for _, group := range groups {
		counts[severityLabel(group.Severity)] += group.Occurrences
	}
	return sortedBucketCounts(counts, func(label string) string {
		return "/findings?severity=" + url.QueryEscape(strings.ToLower(label))
	})
}

func findingSourceBuckets(groups []FindingGroupView) []Bucket {
	counts := map[string]int{}
	for _, group := range groups {
		counts[group.Source] += group.Occurrences
	}
	return sortedBucketCounts(counts, func(label string) string {
		return "/findings?source=" + url.QueryEscape(label)
	})
}

func findingStats(groups []FindingGroupView) []StatCard {
	hostHits := 0
	occurrences := 0
	critical := 0
	high := 0
	for _, group := range groups {
		hostHits += group.Hosts
		occurrences += group.Occurrences
		switch normalizeSeverity(group.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		}
	}

	topSource := "No findings loaded"
	sourceBuckets := findingSourceBuckets(groups)
	if len(sourceBuckets) > 0 {
		topSource = sourceBuckets[0].Label + " contributes the most occurrences"
	}

	return []StatCard{
		{Label: "Definitions", Value: strconv.Itoa(len(groups)), Detail: topSource, Tone: "accent"},
		{Label: "Occurrences", Value: strconv.Itoa(occurrences), Detail: "Raw matched findings in the current slice", Tone: "warning"},
		{Label: "Host hits", Value: strconv.Itoa(hostHits), Detail: "Affected host memberships across grouped definitions", Tone: "calm"},
		{Label: "Critical/high", Value: strconv.Itoa(critical + high), Detail: strconv.Itoa(critical) + " critical · " + strconv.Itoa(high) + " high", Tone: "risk"},
	}
}

func findingSourceOptions(groups []FindingGroupView, selected string) []SelectOption {
	selected = strings.ToLower(strings.TrimSpace(selected))
	items := []SelectOption{{Value: "all", Label: "All sources", Selected: selected == "" || selected == "all"}}
	seen := map[string]struct{}{}
	for _, group := range groups {
		source := strings.TrimSpace(group.Source)
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		items = append(items, SelectOption{
			Value:    source,
			Label:    source,
			Selected: selected == strings.ToLower(source),
		})
	}
	sort.SliceStable(items[1:], func(left, right int) bool {
		return items[left+1].Label < items[right+1].Label
	})
	return items
}

func sortedBucketCounts(counts map[string]int, href func(label string) string) []Bucket {
	items := make([]Bucket, 0, len(counts))
	for label, count := range counts {
		if strings.TrimSpace(label) == "" || count <= 0 {
			continue
		}
		items = append(items, Bucket{
			Label: label,
			Count: count,
			Href:  href(label),
		})
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Count != items[right].Count {
			return items[left].Count > items[right].Count
		}
		return strings.ToLower(items[left].Label) < strings.ToLower(items[right].Label)
	})
	return items
}

func normalizePortSort(sortBy string) string {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "findings", "scans", "port":
		return strings.ToLower(strings.TrimSpace(sortBy))
	default:
		return "hosts"
	}
}

func normalizeFindingSeverityFilter(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "all"
	}
}

func normalizeFindingSort(sortBy string) string {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "hosts", "occurrences", "recent":
		return strings.ToLower(strings.TrimSpace(sortBy))
	default:
		return "severity"
	}
}

func severityLabel(value string) string {
	switch normalizeSeverity(value) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

func groupFindings(records []hostRecord, scanTimes map[string][]string) map[string]*findingGroupAccumulator {
	accumulators := map[string]*findingGroupAccumulator{}
	for _, record := range records {
		hostLabel := chooseString(record.summary.DisplayName, record.summary.IP)
		for _, finding := range record.detail.NucleiFindings {
			groupID := findingGroupID(finding.Source, finding.TemplateID, finding.Name, finding.Severity)
			accumulator := accumulators[groupID]
			if accumulator == nil {
				accumulator = &findingGroupAccumulator{
					group: FindingGroupView{
						ID:           groupID,
						TemplateID:   finding.TemplateID,
						Name:         finding.Name,
						Source:       normalizedFindingSource(finding.Source),
						Severity:     normalizeSeverity(finding.Severity),
						SeverityTone: severityTone(finding.Severity),
						Href:         "/findings/" + groupID,
					},
					relatedScans: map[string]struct{}{},
					relatedHosts: map[string]struct{}{},
					relatedPorts: map[string]struct{}{},
					tags:         map[string]struct{}{},
				}
				accumulators[groupID] = accumulator
			}

			port := extractTargetPort(finding.Target)
			accumulator.group.Occurrences++
			accumulator.relatedHosts[record.summary.IP] = struct{}{}
			if port != "" {
				accumulator.relatedPorts[port] = struct{}{}
			}
			for _, scanName := range record.detail.SourceScans {
				accumulator.relatedScans[scanName] = struct{}{}
			}
			if accumulator.description == "" && strings.TrimSpace(finding.Description) != "" {
				accumulator.description = strings.TrimSpace(finding.Description)
			}
			for _, tag := range finding.Tags {
				tag = strings.TrimSpace(tag)
				if tag == "" {
					continue
				}
				accumulator.tags[tag] = struct{}{}
			}
			accumulator.occurrences = append(accumulator.occurrences, FindingOccurrenceView{
				HostIP:    record.summary.IP,
				HostLabel: hostLabel,
				Target:    finding.Target,
				Port:      port,
				Scans:     append([]string(nil), record.detail.SourceScans...),
				MatchedAt: finding.MatchedAt,
				Href:      "/hosts/" + record.summary.IP,
			})
		}
	}

	for _, accumulator := range accumulators {
		accumulator.group.Hosts = len(accumulator.relatedHosts)
		accumulator.group.Ports = len(accumulator.relatedPorts)
		accumulator.group.RelatedScans = len(accumulator.relatedScans)
		accumulator.group.FirstSeen, accumulator.group.LastSeen = summarizeFindingTimes(accumulator.relatedScans, scanTimes)
		sort.SliceStable(accumulator.occurrences, func(left, right int) bool {
			if compare := compareIPStrings(accumulator.occurrences[left].HostIP, accumulator.occurrences[right].HostIP); compare != 0 {
				return compare < 0
			}
			return accumulator.occurrences[left].Target < accumulator.occurrences[right].Target
		})
	}
	return accumulators
}

func (w *workspace) scanTimeByName() map[string][]string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	index := map[string][]string{}
	for _, scan := range w.scans {
		name := strings.TrimSpace(scan.record.Name)
		if name == "" {
			continue
		}
		index[name] = append(index[name], chooseString(scan.record.ImportedAt, scan.record.StartedAt))
	}
	return index
}

func summarizeFindingTimes(scanNames map[string]struct{}, scanTimes map[string][]string) (string, string) {
	values := make([]string, 0)
	for scanName := range scanNames {
		values = append(values, scanTimes[scanName]...)
	}
	if len(values) == 0 {
		return "n/a", "n/a"
	}
	sort.Strings(values)
	return displayTimestamp(values[0]), displayTimestamp(values[len(values)-1])
}

func summarizeFindingsForRecords(records []hostRecord) FindingSummary {
	summary := FindingSummary{}
	for _, record := range records {
		summary.Total += record.summary.Findings.Total
		summary.Critical += record.summary.Findings.Critical
		summary.High += record.summary.Findings.High
		summary.Medium += record.summary.Findings.Medium
		summary.Low += record.summary.Findings.Low
		summary.Info += record.summary.Findings.Info
	}
	return summary
}

func portExposureLabel(port string, findings int) string {
	if _, ok := criticalPorts[port]; ok && findings > 0 {
		return "high-interest"
	}
	if _, ok := criticalPorts[port]; ok {
		return "watch"
	}
	if findings > 0 {
		return "finding-backed"
	}
	return "baseline"
}

func countPortFindings(findings []NucleiFindingView, hostIP string, protocol string, port string) int {
	total := 0
	for _, finding := range findings {
		if targetMatchesPort(hostIP, protocol, port, finding.Target) {
			total++
		}
	}
	return total
}

func portFindingSummary(findings []NucleiFindingView, hostIP string, protocol string, port string) FindingSummary {
	summary := FindingSummary{}
	for _, finding := range findings {
		if !targetMatchesPort(hostIP, protocol, port, finding.Target) {
			continue
		}
		summary = addFindingSeverity(summary, finding.Severity)
	}
	return summary
}

func targetMatchesPort(hostIP string, protocol string, port string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		return parsed.Hostname() == hostIP && parsed.Port() == port
	}
	if strings.Contains(target, hostIP+":"+port) {
		return true
	}
	if strings.Contains(target, "/"+protocol) && strings.Contains(target, ":"+port) && strings.Contains(target, hostIP) {
		return true
	}
	return false
}

func extractTargetPort(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		return parsed.Port()
	}
	if index := strings.LastIndex(target, ":"); index >= 0 && index+1 < len(target) {
		remainder := target[index+1:]
		if slash := strings.Index(remainder, "/"); slash >= 0 {
			remainder = remainder[:slash]
		}
		if _, err := strconv.Atoi(remainder); err == nil {
			return remainder
		}
	}
	return ""
}

func findingGroupID(source string, templateID string, name string, severity string) string {
	hash := sha1.Sum([]byte(strings.Join([]string{
		normalizedFindingSource(source),
		strings.TrimSpace(templateID),
		strings.TrimSpace(name),
		normalizeSeverity(severity),
	}, "|")))
	return hex.EncodeToString(hash[:8])
}

func sortedKeys(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func (w *workspace) scanNameForID(id string) string {
	if id == "" {
		return ""
	}
	if item, ok := w.scanCatalogItem(id); ok {
		return item.Name
	}
	return ""
}

func (w *workspace) scanItemsForNames(names map[string]struct{}) []ScanCatalogItem {
	if len(names) == 0 {
		return nil
	}
	items := make([]ScanCatalogItem, 0, len(names))
	for _, item := range w.scanCatalog() {
		if _, ok := names[item.Name]; ok {
			items = append(items, item)
		}
	}
	return items
}

func (w *workspace) explorerRoot(activePath []ExplorerPathStep) ExplorerView {
	status := w.workspaceStatus()
	if !status.HasImportedScans {
		return ExplorerView{}
	}

	snapshot := w.currentSnapshot()
	scans := w.scanCatalog()
	children := make([]ExplorerNodeView, 0, len(scans))
	for _, scan := range scans {
		children = append(children, ExplorerNodeView{
			Kind:       "scan",
			ID:         scan.ID,
			Label:      scan.Name,
			Meta:       fmt.Sprintf("%d live hosts", scan.LiveHosts),
			Count:      scan.LiveHosts,
			Href:       "/scans/" + scan.ID,
			Expandable: scan.LiveHosts > 0,
		})
	}

	root := ExplorerNodeView{
		Kind:       "workspace",
		ID:         "workspace",
		Label:      chooseString(strings.TrimSuffix(baseName(status.Root), ".nwa"), "workspace"),
		Meta:       fmt.Sprintf("%d scans", status.ScanCount),
		Count:      status.ScanCount,
		Href:       "/workspace",
		Expandable: len(children) > 0,
		Expanded:   true,
		Children:   children,
	}
	return ExplorerView{
		Enabled:    true,
		Endpoint:   "/api/explorer",
		Root:       root,
		ExpandPath: activePath,
		Scans:      recentScanJumps(scans, 4),
		Hosts:      highExposureJumps(snapshot.highExposure, 5),
		Ports:      portJumpViews(w.portSummaries(), 5),
		Findings:   findingJumpViews(snapshot.topFindings, 5),
	}
}

func (w *workspace) explorerChildren(kind string, id string) []ExplorerNodeView {
	switch strings.TrimSpace(kind) {
	case "workspace":
		return w.explorerRoot(nil).Root.Children
	case "scan":
		records, scan, ok := w.scanHostRecords(id)
		if !ok {
			return nil
		}
		items := make([]ExplorerNodeView, 0, len(records))
		for _, record := range records {
			nodeID := scan.record.ID + "|" + record.summary.IP
			items = append(items, ExplorerNodeView{
				Kind:       "scan-host",
				ID:         nodeID,
				Label:      chooseString(record.summary.DisplayName, record.summary.IP),
				Meta:       fmt.Sprintf("%s · %d open ports", record.summary.IP, record.summary.OpenPortCount),
				Count:      record.summary.OpenPortCount,
				Href:       "/hosts/" + record.summary.IP + "?scan=" + url.QueryEscape(scan.record.ID),
				Expandable: record.summary.OpenPortCount > 0,
			})
		}
		return items
	case "scan-host":
		scanID, hostIP, ok := splitScanHostID(id)
		if !ok {
			return nil
		}
		host, ok := w.scanScopedHost(scanID, hostIP)
		if !ok {
			return nil
		}
		items := make([]ExplorerNodeView, 0)
		for _, port := range host.Ports {
			if !strings.EqualFold(port.State, "open") {
				continue
			}
			nodeID := strings.Join([]string{scanID, hostIP, port.Protocol, port.Port}, "|")
			findings := countPortFindings(host.NucleiFindings, hostIP, port.Protocol, port.Port)
			items = append(items, ExplorerNodeView{
				Kind:       "scan-port",
				ID:         nodeID,
				Label:      port.Protocol + "/" + port.Port,
				Meta:       chooseString(strings.TrimSpace(port.Service), strings.TrimSpace(port.Product), "open"),
				Count:      findings,
				Href:       "/ports/" + port.Protocol + "/" + port.Port + "?scan=" + url.QueryEscape(scanID) + "&host=" + url.QueryEscape(hostIP),
				Expandable: findings > 0,
			})
		}
		return items
	case "scan-port":
		scanID, hostIP, protocol, port, ok := splitScanPortID(id)
		if !ok {
			return nil
		}
		host, ok := w.scanScopedHost(scanID, hostIP)
		if !ok {
			return nil
		}
		items := make([]ExplorerNodeView, 0)
		seen := map[string]struct{}{}
		for _, finding := range host.NucleiFindings {
			if !targetMatchesPort(hostIP, protocol, port, finding.Target) {
				continue
			}
			groupID := findingGroupID(finding.Source, finding.TemplateID, finding.Name, finding.Severity)
			if _, ok := seen[groupID]; ok {
				continue
			}
			seen[groupID] = struct{}{}
			href := "/findings/" + groupID + "?scan=" + url.QueryEscape(scanID) + "&host=" + url.QueryEscape(hostIP) + "&protocol=" + url.QueryEscape(protocol) + "&port=" + url.QueryEscape(port)
			items = append(items, ExplorerNodeView{
				Kind:       "finding",
				ID:         groupID,
				Label:      finding.Name,
				Meta:       strings.ToUpper(normalizeSeverity(finding.Severity)),
				Count:      1,
				Href:       href,
				Expandable: false,
			})
		}
		return items
	default:
		return nil
	}
}

func splitScanHostID(value string) (string, string, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func splitScanPortID(value string) (string, string, string, string, bool) {
	parts := strings.Split(value, "|")
	if len(parts) != 4 {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func baseName(path string) string {
	index := strings.LastIndex(path, "/")
	if index < 0 || index+1 >= len(path) {
		return path
	}
	return path[index+1:]
}

func recentScanJumps(items []ScanCatalogItem, limit int) []ExplorerJumpView {
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	results := make([]ExplorerJumpView, 0, len(items))
	for _, item := range items {
		meta := chooseString(strings.TrimSpace(item.Scanner), strings.TrimSpace(item.Kind), "source")
		results = append(results, ExplorerJumpView{
			Label: item.Name,
			Meta:  meta,
			Count: fmt.Sprintf("%dh", item.LiveHosts),
			Href:  "/scans/" + item.ID,
		})
	}
	return results
}

func highExposureJumps(items []HostSummary, limit int) []ExplorerJumpView {
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	results := make([]ExplorerJumpView, 0, len(items))
	for _, item := range items {
		metaParts := make([]string, 0, 3)
		if item.DisplayName != "" && item.DisplayName != item.IP {
			metaParts = append(metaParts, item.IP)
		}
		metaParts = append(metaParts, fmt.Sprintf("%dp open", item.OpenPortCount))
		metaParts = append(metaParts, fmt.Sprintf("%df", item.Findings.Total))
		results = append(results, ExplorerJumpView{
			Label: chooseString(item.DisplayName, item.IP),
			Meta:  strings.Join(metaParts, " · "),
			Count: item.Exposure.Label,
			Href:  "/hosts/" + item.IP,
		})
	}
	return results
}

func portJumpViews(items []PortSummaryView, limit int) []ExplorerJumpView {
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	results := make([]ExplorerJumpView, 0, len(items))
	for _, item := range items {
		results = append(results, ExplorerJumpView{
			Label: item.Label,
			Meta:  chooseString(item.Service, "service"),
			Count: fmt.Sprintf("%dh", item.Hosts),
			Href:  item.Href,
		})
	}
	return results
}

func findingJumpViews(items []FindingTemplateSummary, limit int) []ExplorerJumpView {
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	results := make([]ExplorerJumpView, 0, len(items))
	for _, item := range items {
		groupID := findingGroupID(item.Source, item.TemplateID, item.Name, item.Severity)
		results = append(results, ExplorerJumpView{
			Label: item.Name,
			Meta:  strings.ToUpper(item.Severity),
			Count: fmt.Sprintf("%d", item.Count),
			Href:  "/findings/" + groupID,
		})
	}
	return results
}
