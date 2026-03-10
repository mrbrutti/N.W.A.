package main

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"nwa/nmap"
)

const defaultPageSize = 50

var criticalPorts = map[string]string{
	"21":   "ftp",
	"22":   "ssh",
	"23":   "telnet",
	"25":   "smtp",
	"53":   "dns",
	"80":   "http",
	"111":  "rpcbind",
	"139":  "netbios",
	"1433": "mssql",
	"1521": "oracle",
	"2049": "nfs",
	"2375": "docker",
	"3306": "mysql",
	"3389": "rdp",
	"445":  "smb",
	"5432": "postgres",
	"5900": "vnc",
	"6379": "redis",
	"8080": "http-alt",
	"8443": "https-alt",
	"9200": "elasticsearch",
}

type snapshot struct {
	meta           ScanMeta
	stats          []StatCard
	records        []hostRecord
	hostByIP       map[string]HostDetail
	portBuckets    []Bucket
	osBuckets      []Bucket
	serviceBuckets []Bucket
	portIndex      map[string][]int
	topology       TopologyGraph
	topNodes       []TopologyNodeSummary
	topEdges       []TopologyEdgeSummary
	highExposure   []HostSummary
	findingTotals  FindingSummary
	topFindings    []FindingTemplateSummary
	summaryLine    string
}

type hostRecord struct {
	summary       HostSummary
	detail        HostDetail
	ipAddr        netip.Addr
	displayKey    string
	osKey         string
	allSearch     string
	osSearch      string
	serviceSearch string
	bannerSearch  string
	portSearch    string
}

type hostBuildInput struct {
	host       nmap.Host
	sources    []string
	enrichment hostEnrichment
}

func loadSnapshot(filename string) (*snapshot, error) {
	parsed, err := parseImportFile(filename)
	if err != nil {
		var partial *nmap.PartialParseError
		if !errors.As(err, &partial) {
			return nil, err
		}
	}

	return buildSnapshotFromScans([]managedScan{{
		record: scanRecord{
			ID:        "seed",
			Name:      filepath.Base(filename),
			Path:      filename,
			Scanner:   parsed.Scan.Scanner,
			Version:   parsed.Scan.Version,
			StartedAt: parsed.Scan.Startstr,
			Command:   parsed.Scan.Args,
			Type:      parsed.Scan.ScanInfo.Type,
			Protocol:  parsed.Scan.ScanInfo.Protocol,
			LiveHosts: len(parsed.Scan.Alive()),
		},
		scan: parsed.Scan,
	}}, enrichmentsFromFindings(parsed.Findings)), nil
}

func buildHostRecords(hosts []nmap.Host) []hostRecord {
	inputs := make([]hostBuildInput, 0, len(hosts))
	for _, host := range hosts {
		inputs = append(inputs, hostBuildInput{host: host})
	}
	return buildHostRecordsFromInputs(inputs)
}

func buildHostRecordsFromInputs(hosts []hostBuildInput) []hostRecord {
	if len(hosts) == 0 {
		return nil
	}

	records := make([]hostRecord, len(hosts))
	workers := minInt(runtime.GOMAXPROCS(0), len(hosts))
	chunkSize := (len(hosts) + workers - 1) / workers

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		start := worker * chunkSize
		end := minInt(start+chunkSize, len(hosts))
		if start >= len(hosts) {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for index := start; index < end; index++ {
				records[index] = buildHostRecord(hosts[index])
			}
		}(start, end)
	}

	wg.Wait()
	return records
}

func buildHostRecord(input hostBuildInput) hostRecord {
	host := input.host
	hostnames := host.HostnameLabels()
	displayName := strings.TrimSpace(host.Address.Addr)
	if len(hostnames) > 0 {
		displayName = hostnames[0]
	}
	if displayName == "" {
		displayName = "Unknown host"
	}

	osLabel := strings.TrimSpace(host.OSGuess())
	if osLabel == "" {
		osLabel = "Unknown operating system"
	}

	sortedPorts := slices.Clone(host.Ports)
	sort.SliceStable(sortedPorts, func(left, right int) bool {
		return comparePorts(sortedPorts[left].Portid, sortedPorts[left].Protocol, sortedPorts[right].Portid, sortedPorts[right].Protocol)
	})

	portRows := make([]PortRow, 0, len(sortedPorts))
	scriptGroups := make([]ScriptGroup, 0)
	fingerprints := make([]FingerprintSection, 0)
	portChips := make([]PortChip, 0, 5)
	serviceSet := map[string]struct{}{}
	criticalLabels := make([]string, 0)
	criticalSeen := map[string]struct{}{}
	criticalServices := make([]string, 0)
	allTerms := []string{host.Address.Addr, displayName, strings.Join(hostnames, " "), osLabel}
	allTerms = append(allTerms, input.enrichment.Tags...)
	serviceTerms := make([]string, 0)
	bannerTerms := make([]string, 0)
	portTerms := make([]string, 0)
	scriptCount := 0
	openPortCount := 0
	for _, note := range input.enrichment.Notes {
		allTerms = append(allTerms, note.Text)
	}

	for _, port := range sortedPorts {
		row := PortRow{
			Port:        port.Portid,
			Protocol:    port.Protocol,
			State:       port.State.State,
			Service:     strings.TrimSpace(port.Service.Name),
			Product:     strings.TrimSpace(port.Service.Product),
			Version:     strings.TrimSpace(port.Service.Version),
			ExtraInfo:   strings.TrimSpace(port.Service.ExtraInfo),
			OSType:      strings.TrimSpace(port.Service.OSType),
			Method:      strings.TrimSpace(port.Service.Method),
			Confidence:  strings.TrimSpace(port.Service.Conf),
			Fingerprint: strings.TrimSpace(port.Service.FingerPrint),
			CPEs:        cpeValues(port.Service.CPEs),
		}

		if len(port.Scripts) > 0 {
			scriptOutputs := make([]ScriptOutput, 0, len(port.Scripts))
			for _, script := range port.Scripts {
				scriptOutputs = append(scriptOutputs, ScriptOutput{
					ID:     strings.TrimSpace(script.Id),
					Output: strings.TrimSpace(script.Output),
				})
				scriptCount++
				bannerTerms = append(bannerTerms, script.Id, script.Output)
			}

			row.Scripts = scriptOutputs
			scriptGroups = append(scriptGroups, ScriptGroup{
				Port:    port.Portid,
				Service: serviceLabel(port),
				Scripts: scriptOutputs,
			})
		}

		if row.Fingerprint != "" {
			fingerprints = append(fingerprints, FingerprintSection{
				Port:        port.Portid,
				Service:     serviceLabel(port),
				Fingerprint: row.Fingerprint,
			})
		}

		portRows = append(portRows, row)

		if row.State != "open" {
			continue
		}

		openPortCount++
		portTerms = append(portTerms, port.Portid)
		serviceName := serviceLabel(port)
		serviceSet[serviceName] = struct{}{}
		serviceTerms = append(serviceTerms, row.Service, row.Product, row.Version, row.ExtraInfo, row.OSType)
		bannerTerms = append(bannerTerms, row.Product, row.Version, row.ExtraInfo, row.Fingerprint)
		allTerms = append(allTerms, port.Portid, serviceName, row.Product, row.Version, row.ExtraInfo, row.Fingerprint)

		if len(portChips) < cap(portChips) {
			portChips = append(portChips, PortChip{Port: port.Portid, Service: serviceName})
		}

		if label, ok := criticalPorts[port.Portid]; ok {
			descriptor := fmt.Sprintf("%s/%s", port.Portid, label)
			if _, seen := criticalSeen[descriptor]; !seen {
				criticalSeen[descriptor] = struct{}{}
				criticalLabels = append(criticalLabels, descriptor)
			}

			serviceDescriptor := fmt.Sprintf("%s/%s", port.Portid, serviceName)
			criticalServices = append(criticalServices, serviceDescriptor)
		}
	}

	osMatches := make([]OSMatchView, 0, len(host.OS.OSMatches))
	for _, match := range host.OS.OSMatches {
		cpes := make([]string, 0)
		types := make([]string, 0)
		vendors := make([]string, 0)
		families := make([]string, 0)
		gens := make([]string, 0)
		for _, class := range match.OSClasses {
			if class.Type != "" {
				types = append(types, class.Type)
			}
			if class.Vendor != "" {
				vendors = append(vendors, class.Vendor)
			}
			if class.OSFamily != "" {
				families = append(families, class.OSFamily)
			}
			if class.OSGen != "" {
				gens = append(gens, class.OSGen)
			}
			for _, cpe := range class.CPEs {
				value := strings.TrimSpace(cpe.Value)
				if value != "" {
					cpes = append(cpes, value)
				}
			}
		}

		osMatches = append(osMatches, OSMatchView{
			Name:     strings.TrimSpace(match.Name),
			Accuracy: strings.TrimSpace(match.Accuracy),
			Line:     strings.TrimSpace(match.Line),
			Type:     strings.Join(types, ", "),
			Vendor:   strings.Join(vendors, ", "),
			Family:   strings.Join(families, ", "),
			Gen:      strings.Join(gens, ", "),
			CPEs:     cpes,
		})
	}

	findings := findingSummaryForEnrichment(input.enrichment)
	coverage := buildCoverage(scriptCount > 0, len(osMatches) > 0 || host.OS.OSFingerPrint.Fingerprint != "", len(host.Trace.Hops) > 0)
	portsUsed := make([]PortUseView, 0, len(host.OS.PortsUsed))
	for _, port := range host.OS.PortsUsed {
		portsUsed = append(portsUsed, PortUseView{
			Port:     port.Portid,
			Protocol: port.Protocol,
			State:    port.State,
		})
	}

	trace := makeTraceViews(host.Trace.Hops)
	nucleiTargets := hostNucleiTargets(host.Address.Addr, portRows)
	nucleiFindings := nucleiFindingViews(input.enrichment.Nuclei)
	notes := analystNoteViews(input.enrichment.Notes)
	recommendations := buildRecommendations(coverage, findings, portRows, len(nucleiTargets) > 0)
	vulnerabilities := buildKnownVulnerabilities(portRows)
	exposure := assessExposure(openPortCount, scriptCount, criticalLabels, findings, vulnerabilities)
	summary := HostSummary{
		IP:               host.Address.Addr,
		DisplayName:      displayName,
		Hostnames:        hostnames,
		OS:               osLabel,
		SourceCount:      len(input.sources),
		OpenPortCount:    openPortCount,
		ServiceCount:     len(serviceSet),
		ScriptCount:      scriptCount,
		Ports:            portChips,
		HiddenPortCount:  maxInt(openPortCount-len(portChips), 0),
		Exposure:         exposure,
		CriticalServices: criticalServices,
		Findings:         findings,
		Coverage:         coverage,
		HTTPTargets:      len(nucleiTargets),
	}

	detail := HostDetail{
		HostSummary:     summary,
		Status:          strings.TrimSpace(host.Status.State),
		Reason:          strings.TrimSpace(host.Status.Reason),
		Distance:        strings.TrimSpace(host.Distance),
		ClosedPortCount: maxInt(len(portRows)-openPortCount, 0),
		Ports:           portRows,
		ScriptGroups:    scriptGroups,
		Fingerprints:    fingerprints,
		PortsUsed:       portsUsed,
		OSFingerprint:   strings.TrimSpace(host.OS.OSFingerPrint.Fingerprint),
		OSMatches:       osMatches,
		Trace:           trace,
		Timing: TimingView{
			SRTT:    strings.TrimSpace(host.Times.Srtt),
			RTTVar:  strings.TrimSpace(host.Times.Tttvar),
			Timeout: strings.TrimSpace(host.Times.To),
		},
		SourceScans:     append([]string(nil), input.sources...),
		NucleiTargets:   nucleiTargets,
		NucleiFindings:  nucleiFindings,
		Recommendations: recommendations,
		Vulnerabilities: vulnerabilities,
		Tags:            append([]string(nil), input.enrichment.Tags...),
		Notes:           notes,
	}

	ipAddr, _ := netip.ParseAddr(host.Address.Addr)
	return hostRecord{
		summary:       summary,
		detail:        detail,
		ipAddr:        ipAddr,
		displayKey:    strings.ToLower(displayName),
		osKey:         strings.ToLower(osLabel),
		allSearch:     normalizeSearchTerms(allTerms),
		osSearch:      normalizeSearchTerms([]string{osLabel, strings.Join(hostnames, " ")}),
		serviceSearch: normalizeSearchTerms(serviceTerms),
		bannerSearch:  normalizeSearchTerms(bannerTerms),
		portSearch:    normalizeSearchTerms(portTerms),
	}
}

func (s *snapshot) searchHosts(filter HostFilter) HostPage {
	filter = normalizeFilter(filter)
	matches := s.filterMatches(filter)
	s.sortMatches(matches, filter.Sort)

	total := len(matches)
	totalPages := maxInt((total+filter.PageSize-1)/filter.PageSize, 1)
	if filter.Page > totalPages {
		filter.Page = totalPages
	}

	startIndex := (filter.Page - 1) * filter.PageSize
	if startIndex > total {
		startIndex = maxInt(total-filter.PageSize, 0)
	}
	endIndex := minInt(startIndex+filter.PageSize, total)

	items := make([]HostSummary, 0, endIndex-startIndex)
	for _, index := range matches[startIndex:endIndex] {
		items = append(items, s.records[index].summary)
	}

	start := 0
	end := 0
	if total > 0 {
		start = startIndex + 1
		end = endIndex
	}

	return HostPage{
		Items:      items,
		Total:      total,
		Start:      start,
		End:        end,
		Page:       filter.Page,
		TotalPages: totalPages,
		PrevLink:   filterHref(filter, maxInt(filter.Page-1, 1)),
		NextLink:   filterHref(filter, minInt(filter.Page+1, totalPages)),
		HasPrev:    filter.Page > 1,
		HasNext:    filter.Page < totalPages,
		Links:      paginationLinks(filter, totalPages),
	}
}

func (s *snapshot) recordsForFilter(filter HostFilter) []hostRecord {
	indices := s.matchingIndices(filter)
	records := make([]hostRecord, 0, len(indices))
	for _, index := range indices {
		records = append(records, s.records[index])
	}
	return records
}

func (s *snapshot) host(ip string) (HostDetail, bool) {
	host, ok := s.hostByIP[ip]
	return host, ok
}

func (s *snapshot) traceGraph(ip string) TraceGraph {
	host, ok := s.host(ip)
	if !ok || len(host.Trace) == 0 {
		return TraceGraph{}
	}

	nodes := make([]TraceNode, 0, len(host.Trace))
	links := make([]TraceLink, 0, maxInt(len(host.Trace)-1, 0))
	for index, hop := range host.Trace {
		nodes = append(nodes, TraceNode{
			Group: index + 1,
			Name:  hop.Address,
			RTT:   hop.RTT,
		})
		if index == 0 {
			continue
		}
		links = append(links, TraceLink{
			Source: index - 1,
			Target: index,
			Value:  parseRTT(hop.RTT),
		})
	}

	return TraceGraph{
		Nodes: nodes,
		Links: links,
	}
}

func (s *snapshot) filterMatches(filter HostFilter) []int {
	if len(s.records) == 0 {
		return nil
	}

	query := strings.ToLower(strings.TrimSpace(filter.Query))
	if query == "" {
		indices := make([]int, len(s.records))
		for index := range s.records {
			indices[index] = index
		}
		return indices
	}

	if filter.Scope == "port" {
		if exact, ok := s.portIndex[query]; ok {
			return slices.Clone(exact)
		}
	}

	match := func(record hostRecord) bool {
		switch filter.Scope {
		case "os":
			return strings.Contains(record.osSearch, query)
		case "service":
			return strings.Contains(record.serviceSearch, query)
		case "banner":
			return strings.Contains(record.bannerSearch, query)
		case "port":
			return strings.Contains(record.portSearch, query)
		default:
			return strings.Contains(record.allSearch, query)
		}
	}

	if len(s.records) < 128 {
		return sequentialMatches(s.records, match)
	}
	return parallelMatches(s.records, match)
}

func (s *snapshot) sortMatches(indices []int, sortBy string) {
	sort.SliceStable(indices, func(left, right int) bool {
		a := s.records[indices[left]]
		b := s.records[indices[right]]

		switch sortBy {
		case "ip":
			return compareHostRecordsByIP(a, b) < 0
		case "hostname":
			if a.displayKey != b.displayKey {
				return a.displayKey < b.displayKey
			}
		case "os":
			if a.osKey != b.osKey {
				return a.osKey < b.osKey
			}
		case "ports":
			if a.summary.OpenPortCount != b.summary.OpenPortCount {
				return a.summary.OpenPortCount > b.summary.OpenPortCount
			}
		case "findings":
			if a.summary.Findings.Total != b.summary.Findings.Total {
				return a.summary.Findings.Total > b.summary.Findings.Total
			}
			if a.summary.Findings.Critical != b.summary.Findings.Critical {
				return a.summary.Findings.Critical > b.summary.Findings.Critical
			}
		case "coverage":
			if coverageSortRank(a.summary.Coverage) != coverageSortRank(b.summary.Coverage) {
				return coverageSortRank(a.summary.Coverage) < coverageSortRank(b.summary.Coverage)
			}
		default:
			if a.summary.Exposure.Score != b.summary.Exposure.Score {
				return a.summary.Exposure.Score > b.summary.Exposure.Score
			}
			if a.summary.OpenPortCount != b.summary.OpenPortCount {
				return a.summary.OpenPortCount > b.summary.OpenPortCount
			}
		}

		return compareHostRecordsByIP(a, b) < 0
	})
}

func buildHostMap(records []hostRecord) map[string]HostDetail {
	result := make(map[string]HostDetail, len(records))
	for _, record := range records {
		result[record.summary.IP] = record.detail
	}
	return result
}

func buildPortIndex(records []hostRecord) map[string][]int {
	index := map[string][]int{}
	for recordIndex, record := range records {
		for _, port := range record.detail.Ports {
			if port.State != "open" {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(port.Port))
			index[key] = append(index[key], recordIndex)
		}
	}
	return index
}

func buildBuckets(records []hostRecord, scope string) []Bucket {
	counts := map[string]int{}
	for _, record := range records {
		switch scope {
		case "port":
			for _, port := range record.detail.Ports {
				if port.State == "open" {
					counts[port.Port]++
				}
			}
		case "os":
			counts[record.summary.OS]++
		case "service":
			seen := map[string]struct{}{}
			for _, port := range record.detail.Ports {
				if port.State != "open" {
					continue
				}
				label := port.Service
				if label == "" {
					label = port.Product
				}
				if label == "" {
					continue
				}
				key := strings.TrimSpace(label)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				counts[key]++
			}
		}
	}

	buckets := make([]Bucket, 0, len(counts))
	totalHosts := maxInt(len(records), 1)
	for label, count := range counts {
		buckets = append(buckets, Bucket{
			Label: label,
			Count: count,
			Scope: scope,
			Query: label,
			Href:  bucketHref(scope, label),
			Share: fmt.Sprintf("%.1f%%", (float64(count)/float64(totalHosts))*100),
		})
	}

	sort.SliceStable(buckets, func(left, right int) bool {
		if buckets[left].Count != buckets[right].Count {
			return buckets[left].Count > buckets[right].Count
		}
		return strings.ToLower(buckets[left].Label) < strings.ToLower(buckets[right].Label)
	})
	return buckets
}

func buildStatCards(records []hostRecord, portBuckets []Bucket, osBuckets []Bucket, serviceBuckets []Bucket) []StatCard {
	totalOpenPorts := 0
	exposedHosts := 0
	totalScripts := 0
	totalFindings := 0
	for _, record := range records {
		totalOpenPorts += record.summary.OpenPortCount
		totalScripts += record.summary.ScriptCount
		totalFindings += record.summary.Findings.Total
		if record.summary.Exposure.Tone == "risk" || record.summary.Exposure.Tone == "warning" {
			exposedHosts++
		}
	}

	averageOpenPorts := "0.0"
	if len(records) > 0 {
		averageOpenPorts = fmt.Sprintf("%.1f", float64(totalOpenPorts)/float64(len(records)))
	}

	topPortDetail := "No open ports detected"
	if len(portBuckets) > 0 {
		topPortDetail = fmt.Sprintf("%s is the most common exposed port", portBuckets[0].Label)
	}

	topOSDetail := "No OS matches detected"
	if len(osBuckets) > 0 {
		topOSDetail = fmt.Sprintf("%s appears most often", osBuckets[0].Label)
	}

	topServiceDetail := "No services fingerprinted"
	if len(serviceBuckets) > 0 {
		topServiceDetail = fmt.Sprintf("%s is the most common service", serviceBuckets[0].Label)
	}

	return []StatCard{
		{
			Label:  "Live hosts",
			Value:  strconv.Itoa(len(records)),
			Detail: topOSDetail,
			Tone:   "accent",
		},
		{
			Label:  "Open ports",
			Value:  strconv.Itoa(totalOpenPorts),
			Detail: averageOpenPorts + " per host on average",
			Tone:   "calm",
		},
		{
			Label:  "Mapped services",
			Value:  strconv.Itoa(len(serviceBuckets)),
			Detail: topServiceDetail,
			Tone:   "neutral",
		},
		{
			Label:  "Exposed hosts",
			Value:  strconv.Itoa(exposedHosts),
			Detail: topPortDetail + fmt.Sprintf(" · %d scripts collected", totalScripts),
			Tone:   "risk",
		},
		{
			Label:  "Findings",
			Value:  strconv.Itoa(totalFindings),
			Detail: "Imported and plugin-ingested findings tied back to hosts",
			Tone:   "warning",
		},
	}
}

func compareHostRecordsByIP(left, right hostRecord) int {
	if left.ipAddr.IsValid() && right.ipAddr.IsValid() {
		if compare := left.ipAddr.Compare(right.ipAddr); compare != 0 {
			return compare
		}
	}
	if left.ipAddr.IsValid() != right.ipAddr.IsValid() {
		if left.ipAddr.IsValid() {
			return -1
		}
		return 1
	}
	return strings.Compare(left.summary.IP, right.summary.IP)
}

func comparePorts(leftPort, leftProtocol, rightPort, rightProtocol string) bool {
	leftValue, leftErr := strconv.Atoi(leftPort)
	rightValue, rightErr := strconv.Atoi(rightPort)
	if leftErr == nil && rightErr == nil && leftValue != rightValue {
		return leftValue < rightValue
	}
	if leftErr == nil && rightErr != nil {
		return true
	}
	if leftErr != nil && rightErr == nil {
		return false
	}
	if leftPort != rightPort {
		return leftPort < rightPort
	}
	return leftProtocol < rightProtocol
}

func makeTraceViews(hops []nmap.Hop) []TraceHopView {
	if len(hops) == 0 {
		return nil
	}

	views := make([]TraceHopView, 0, len(hops))
	maxRTT := 0.0
	for _, hop := range hops {
		if value := parseRTT(hop.Rtt); value > maxRTT {
			maxRTT = value
		}
	}
	if maxRTT == 0 {
		maxRTT = 1
	}

	for _, hop := range hops {
		weight := int((parseRTT(hop.Rtt) / maxRTT) * 100)
		if weight < 20 {
			weight = 20
		}
		views = append(views, TraceHopView{
			TTL:       strings.TrimSpace(hop.Ttl),
			Address:   strings.TrimSpace(hop.IPAddr),
			Host:      strings.TrimSpace(hop.Host),
			RTT:       strings.TrimSpace(hop.Rtt),
			WeightPct: weight,
		})
	}

	return views
}

func findingSummaryForEnrichment(enrichment hostEnrichment) FindingSummary {
	summary := FindingSummary{}
	for _, finding := range enrichment.Nuclei {
		summary = addFindingSeverity(summary, finding.Severity)
	}
	return summary
}

func nucleiFindingViews(findings []storedNucleiFinding) []NucleiFindingView {
	if len(findings) == 0 {
		return nil
	}

	views := make([]NucleiFindingView, 0, len(findings))
	for _, finding := range findings {
		views = append(views, NucleiFindingView{
			TemplateID:   finding.TemplateID,
			Name:         finding.Name,
			Source:       normalizedFindingSource(finding.Source),
			Severity:     normalizeSeverity(finding.Severity),
			SeverityTone: severityTone(finding.Severity),
			Target:       finding.Target,
			MatchedAt:    finding.MatchedAt,
			Type:         finding.Type,
			Description:  finding.Description,
			Tags:         append([]string(nil), finding.Tags...),
		})
	}
	return views
}

func analystNoteViews(notes []analystNote) []AnalystNoteView {
	if len(notes) == 0 {
		return nil
	}

	sorted := append([]analystNote(nil), notes...)
	sort.SliceStable(sorted, func(left, right int) bool {
		return sorted[left].CreatedAt > sorted[right].CreatedAt
	})

	views := make([]AnalystNoteView, 0, len(sorted))
	for _, note := range sorted {
		views = append(views, AnalystNoteView{
			ID:        note.ID,
			Text:      strings.TrimSpace(note.Text),
			CreatedAt: displayTimestamp(note.CreatedAt),
		})
	}
	return views
}

func buildCoverage(hasScripts bool, hasOS bool, hasTrace bool) CoverageView {
	coverage := CoverageView{
		HasScripts: hasScripts,
		HasOS:      hasOS,
		HasTrace:   hasTrace,
	}

	switch {
	case hasScripts && hasOS && hasTrace:
		coverage.Level = "ok"
		coverage.Label = "Deep"
		coverage.Detail = "Scripts, OS detection, and traceroute are present."
	case hasScripts || hasOS || hasTrace:
		coverage.Level = "warning"
		coverage.Label = "Partial"
		coverage.Detail = "Some enrichment is present, but the host can still benefit from a managed nmap follow-up."
		coverage.NeedsEnrichment = true
	default:
		coverage.Level = "risk"
		coverage.Label = "Surface"
		coverage.Detail = "Only the base scan is available. Run deep nmap enrichment for better context."
		coverage.NeedsEnrichment = true
	}
	return coverage
}

func hostNucleiTargets(host string, ports []PortRow) []string {
	targets := map[string]struct{}{}
	for _, port := range ports {
		if port.State != "open" || !looksLikeHTTP(port) {
			continue
		}

		scheme := "http"
		if looksLikeHTTPS(port) {
			scheme = "https"
		}

		switch {
		case port.Port == "80" && scheme == "http":
			targets[scheme+"://"+host] = struct{}{}
		case port.Port == "443" && scheme == "https":
			targets[scheme+"://"+host] = struct{}{}
		default:
			targets[fmt.Sprintf("%s://%s:%s", scheme, host, port.Port)] = struct{}{}
		}
	}

	results := make([]string, 0, len(targets))
	for target := range targets {
		results = append(results, target)
	}
	sort.Strings(results)
	return results
}

func serviceLabel(port nmap.Port) string {
	if name := strings.TrimSpace(port.Service.Name); name != "" {
		return name
	}
	if product := strings.TrimSpace(port.Service.Product); product != "" {
		return product
	}
	if port.Protocol != "" {
		return port.Protocol
	}
	return "unknown"
}

func assessExposure(openPortCount int, scriptCount int, critical []string, findings FindingSummary, vulnerabilities []VulnerabilityMatchView) Exposure {
	score := openPortCount + scriptCount + (len(critical) * 3) + (findings.Critical * 8) + (findings.High * 5) + (findings.Medium * 3) + findings.Low + findings.Info
	vulnerabilityCount := len(vulnerabilities)
	for _, vulnerability := range vulnerabilities {
		switch normalizeSeverity(vulnerability.Severity) {
		case "critical":
			score += 8
		case "high":
			score += 5
		case "medium":
			score += 3
		case "low":
			score++
		default:
			score++
		}
	}

	switch {
	case findings.Critical > 0 || findings.High > 1 || vulnerabilityCount > 0 || len(critical) >= 2 || score >= 14:
		detail := fmt.Sprintf("%d critical ports are open", len(critical))
		if vulnerabilityCount > 0 {
			detail = fmt.Sprintf("%d curated vulnerability matches need analyst validation", vulnerabilityCount)
		} else if findings.Total > 0 {
			detail = fmt.Sprintf("%d findings ingested across this host", findings.Total)
		}
		return Exposure{
			Label:         "High exposure",
			Tone:          "risk",
			Detail:        detail,
			Score:         score,
			CriticalPorts: critical,
		}
	case findings.Medium > 0 || len(critical) >= 1 || score >= 7:
		detail := fmt.Sprintf("%d critical port is visible", len(critical))
		if findings.Total > 0 {
			detail = fmt.Sprintf("%d findings are awaiting analyst review", findings.Total)
		}
		return Exposure{
			Label:         "Elevated",
			Tone:          "warning",
			Detail:        detail,
			Score:         score,
			CriticalPorts: critical,
		}
	default:
		return Exposure{
			Label:         "Observed",
			Tone:          "ok",
			Detail:        "No obviously high-risk ports matched the watch list",
			Score:         score,
			CriticalPorts: critical,
		}
	}
}

func paginationLinks(filter HostFilter, totalPages int) []PaginationLink {
	if totalPages <= 1 {
		return nil
	}

	start := maxInt(filter.Page-2, 1)
	end := minInt(start+4, totalPages)
	start = maxInt(end-4, 1)

	links := make([]PaginationLink, 0, end-start+1)
	for page := start; page <= end; page++ {
		links = append(links, PaginationLink{
			Label:  strconv.Itoa(page),
			Href:   filterHref(filter, page),
			Active: page == filter.Page,
		})
	}
	return links
}

func normalizeFilter(filter HostFilter) HostFilter {
	filter.Scope = normalizeScope(filter.Scope)
	filter.Sort = normalizeSort(filter.Sort)
	filter.Query = strings.TrimSpace(filter.Query)
	if filter.Page <= 0 {
		filter.Page = 1
	}
	filter.PageSize = normalizePageSize(filter.PageSize)
	return filter
}

func normalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "os", "service", "banner", "port":
		return strings.ToLower(strings.TrimSpace(scope))
	default:
		return "all"
	}
}

func normalizeSort(sortBy string) string {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "ip", "hostname", "os", "ports", "findings", "coverage":
		return strings.ToLower(strings.TrimSpace(sortBy))
	default:
		return "exposure"
	}
}

func coverageSortRank(coverage CoverageView) int {
	switch coverage.Level {
	case "risk":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

func filterHref(filter HostFilter, page int) string {
	encoded := filterQuery(filter, page)
	if encoded == "" {
		return "/"
	}
	return "/?" + encoded
}

func filterQuery(filter HostFilter, page int) string {
	values := url.Values{}
	if filter.Query != "" {
		values.Set("query", filter.Query)
	}
	if filter.Scope != "" && filter.Scope != "all" {
		values.Set("scope", filter.Scope)
	}
	if filter.Sort != "" && filter.Sort != "exposure" {
		values.Set("sort", filter.Sort)
	}
	if normalizedPageSize := normalizePageSize(filter.PageSize); normalizedPageSize != defaultPageSize {
		values.Set("page_size", strconv.Itoa(normalizedPageSize))
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	return values.Encode()
}

func filterHrefFrom(base string, filter HostFilter, page int) string {
	encoded := filterQuery(filter, page)
	if encoded == "" {
		return base
	}
	return base + "?" + encoded
}

func bucketHref(scope string, query string) string {
	values := url.Values{}
	values.Set("scope", normalizeScope(scope))
	values.Set("query", strings.TrimSpace(query))
	return "/?" + values.Encode()
}

func sequentialMatches(records []hostRecord, match func(hostRecord) bool) []int {
	indices := make([]int, 0)
	for index, record := range records {
		if match(record) {
			indices = append(indices, index)
		}
	}
	return indices
}

func parallelMatches(records []hostRecord, match func(hostRecord) bool) []int {
	workers := minInt(runtime.GOMAXPROCS(0), len(records))
	chunkSize := (len(records) + workers - 1) / workers
	results := make([][]int, workers)

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		start := worker * chunkSize
		end := minInt(start+chunkSize, len(records))
		if start >= len(records) {
			break
		}

		wg.Add(1)
		go func(slot, start, end int) {
			defer wg.Done()
			local := make([]int, 0, end-start)
			for index := start; index < end; index++ {
				if match(records[index]) {
					local = append(local, index)
				}
			}
			results[slot] = local
		}(worker, start, end)
	}

	wg.Wait()

	indices := make([]int, 0)
	for _, group := range results {
		indices = append(indices, group...)
	}
	return indices
}

func normalizeSearchTerms(terms []string) string {
	cleaned := make([]string, 0, len(terms))
	for _, term := range terms {
		trimmed := strings.TrimSpace(term)
		if trimmed != "" {
			cleaned = append(cleaned, strings.ToLower(trimmed))
		}
	}
	return strings.Join(cleaned, " ")
}

func parseRTT(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || parsed <= 0 {
		return 1
	}
	return parsed
}

func normalizePageSize(pageSize int) int {
	switch pageSize {
	case 25, 50, 100, 250, 500:
		return pageSize
	default:
		if pageSize > 500 {
			return pageSize
		}
		return defaultPageSize
	}
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}
