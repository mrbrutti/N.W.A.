package main

import (
	"encoding/csv"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func buildHighExposure(records []hostRecord, limit int) []HostSummary {
	if len(records) == 0 || limit <= 0 {
		return nil
	}

	indices := make([]int, len(records))
	for index := range records {
		indices[index] = index
	}

	sort.SliceStable(indices, func(left, right int) bool {
		a := records[indices[left]]
		b := records[indices[right]]
		if a.summary.Exposure.Score != b.summary.Exposure.Score {
			return a.summary.Exposure.Score > b.summary.Exposure.Score
		}
		if a.summary.OpenPortCount != b.summary.OpenPortCount {
			return a.summary.OpenPortCount > b.summary.OpenPortCount
		}
		return compareHostRecordsByIP(a, b) < 0
	})

	if len(indices) > limit {
		indices = indices[:limit]
	}

	results := make([]HostSummary, 0, len(indices))
	for _, index := range indices {
		results = append(results, records[index].summary)
	}
	return results
}

func buildExecutiveSummary(records []hostRecord, portBuckets []Bucket, osBuckets []Bucket, serviceBuckets []Bucket) string {
	if len(records) == 0 {
		return "No live hosts are loaded yet. Import scan data from supported tools or launch a managed plugin job from the workspace page."
	}

	exposedHosts := 0
	findings := FindingSummary{}
	for _, record := range records {
		if record.summary.Exposure.Tone == "risk" || record.summary.Exposure.Tone == "warning" {
			exposedHosts++
		}
		findings.Total += record.summary.Findings.Total
		findings.Critical += record.summary.Findings.Critical
		findings.High += record.summary.Findings.High
	}

	topPort := "no dominant port"
	if len(portBuckets) > 0 {
		topPort = "port " + portBuckets[0].Label + " leads exposure"
	}

	topOS := "OS fingerprints are sparse"
	if len(osBuckets) > 0 {
		topOS = osBuckets[0].Label + " is the most common fingerprint"
	}

	topService := "service coverage is limited"
	if len(serviceBuckets) > 0 {
		topService = serviceBuckets[0].Label + " is the top mapped service"
	}

	findingLine := "No integration findings have been ingested yet."
	if findings.Total > 0 {
		findingLine = fmt.Sprintf("%d findings ingested, including %d critical and %d high.", findings.Total, findings.Critical, findings.High)
	}

	return fmt.Sprintf("%d live hosts. %d hosts are elevated or high exposure. %s. %s. %s. %s",
		len(records),
		exposedHosts,
		topPort,
		topOS,
		topService,
		findingLine,
	)
}

func buildTopologyGraph(records []hostRecord) (TopologyGraph, []TopologyNodeSummary, []TopologyEdgeSummary) {
	type nodeAccumulator struct {
		label      string
		hostname   string
		provider   string
		count      int
		ttlSum     float64
		rttSum     float64
		targets    int
		sourceHits int
		icon       string
		osLabel    string
	}

	type edgeAccumulator struct {
		source string
		target string
		count  int
		rttSum float64
	}

	type routeAccumulator struct {
		id          string
		targetID    string
		targetLabel string
		hops        []string
		count       int
	}

	nodes := map[string]*nodeAccumulator{}
	edges := map[string]*edgeAccumulator{}
	routes := map[string]*routeAccumulator{}
	summary := TopologySummary{}
	hostIcons := map[string]struct {
		icon string
		os   string
	}{}
	for _, record := range records {
		hostIcons[record.summary.IP] = struct {
			icon string
			os   string
		}{
			icon: topologyIconForOS(record.summary.OS),
			os:   record.summary.OS,
		}
	}

	for _, record := range records {
		trace := record.detail.Trace
		if len(trace) == 0 {
			continue
		}

		summary.TracedHosts++
		if len(trace) > summary.MaxDepth {
			summary.MaxDepth = len(trace)
		}

		var previousID string
		routeHops := make([]string, 0, len(trace))
		for index, hop := range trace {
			nodeID := graphNodeID(hop)
			if nodeID == "" {
				continue
			}
			routeHops = appendGraphHop(routeHops, nodeID)

			if nodes[nodeID] == nil {
				hostname := strings.TrimSpace(hop.Host)
				nodes[nodeID] = &nodeAccumulator{
					label:    graphNodeLabel(hop, nodeID),
					hostname: hostname,
					provider: topologyProviderKey(hostname, nodeID),
					icon:     "unknown",
				}
			}
			nodes[nodeID].count++
			nodes[nodeID].ttlSum += ttlValue(hop.TTL, index)
			nodes[nodeID].rttSum += parseRTT(hop.RTT)
			if nodes[nodeID].hostname == "" {
				nodes[nodeID].hostname = strings.TrimSpace(hop.Host)
			}
			if nodes[nodeID].provider == "" {
				nodes[nodeID].provider = topologyProviderKey(nodes[nodeID].hostname, nodeID)
			}
			if metadata, ok := hostIcons[nodeID]; ok {
				nodes[nodeID].icon = metadata.icon
				nodes[nodeID].osLabel = metadata.os
			}
			if index == 0 {
				nodes[nodeID].sourceHits++
				nodes[nodeID].icon = "home"
				nodes[nodeID].osLabel = "Source-side node"
				nodes[nodeID].provider = "source"
			}
			if index == len(trace)-1 || nodeID == record.summary.IP {
				nodes[nodeID].targets++
			}

			if previousID != "" && previousID != nodeID {
				key := previousID + "->" + nodeID
				if edges[key] == nil {
					edges[key] = &edgeAccumulator{source: previousID, target: nodeID}
				}
				edges[key].count++
				edges[key].rttSum += parseRTT(hop.RTT)
			}

			previousID = nodeID
		}

		if len(routeHops) > 0 {
			targetID := record.summary.IP
			if targetID == "" {
				targetID = routeHops[len(routeHops)-1]
			}
			routeKey := targetID + "|" + strings.Join(routeHops, ">")
			if routes[routeKey] == nil {
				hops := make([]string, len(routeHops))
				copy(hops, routeHops)
				routes[routeKey] = &routeAccumulator{
					id:          routeKey,
					targetID:    targetID,
					targetLabel: topologyRouteTargetLabel(record.summary, targetID),
					hops:        hops,
				}
			}
			routes[routeKey].count++
		}
	}

	graphNodes := make([]TopologyGraphNode, 0, len(nodes))
	nodeRows := make([]TopologyNodeSummary, 0, len(nodes))
	for id, accumulator := range nodes {
		averageTTL := accumulator.ttlSum / float64(maxInt(accumulator.count, 1))
		averageRTT := accumulator.rttSum / float64(maxInt(accumulator.count, 1))
		role := "transit"
		if accumulator.sourceHits > 0 {
			role = "source"
		} else if accumulator.targets > 0 && accumulator.targets == accumulator.count {
			role = "target"
		} else if accumulator.targets > 0 {
			role = "mixed"
		}

		graphNodes = append(graphNodes, TopologyGraphNode{
			ID:       id,
			Label:    accumulator.label,
			Count:    accumulator.count,
			AvgTTL:   averageTTL,
			AvgRTT:   averageRTT,
			Role:     role,
			Targets:  accumulator.targets,
			Icon:     accumulator.icon,
			OSLabel:  accumulator.osLabel,
			Source:   accumulator.sourceHits > 0,
			Hostname: accumulator.hostname,
			Provider: accumulator.provider,
		})

		nodeRows = append(nodeRows, TopologyNodeSummary{
			Label:   accumulator.label,
			Count:   accumulator.count,
			AvgTTL:  fmt.Sprintf("%.1f", averageTTL),
			AvgRTT:  fmt.Sprintf("%.2f", averageRTT),
			Role:    role,
			Targets: accumulator.targets,
		})
	}

	graphEdges := make([]TopologyGraphEdge, 0, len(edges))
	edgeRows := make([]TopologyEdgeSummary, 0, len(edges))
	for _, accumulator := range edges {
		averageRTT := accumulator.rttSum / float64(maxInt(accumulator.count, 1))
		graphEdges = append(graphEdges, TopologyGraphEdge{
			Source: accumulator.source,
			Target: accumulator.target,
			Count:  accumulator.count,
			AvgRTT: averageRTT,
		})

		edgeRows = append(edgeRows, TopologyEdgeSummary{
			Source: accumulator.source,
			Target: accumulator.target,
			Count:  accumulator.count,
			AvgRTT: fmt.Sprintf("%.2f", averageRTT),
		})
	}

	graphRoutes := make([]TopologyRoute, 0, len(routes))
	for _, accumulator := range routes {
		graphRoutes = append(graphRoutes, TopologyRoute{
			ID:          accumulator.id,
			TargetID:    accumulator.targetID,
			TargetLabel: accumulator.targetLabel,
			Count:       accumulator.count,
			Depth:       len(accumulator.hops),
			Hops:        accumulator.hops,
		})
	}

	sort.SliceStable(graphNodes, func(left, right int) bool {
		if graphNodes[left].Count != graphNodes[right].Count {
			return graphNodes[left].Count > graphNodes[right].Count
		}
		return graphNodes[left].Label < graphNodes[right].Label
	})
	sort.SliceStable(nodeRows, func(left, right int) bool {
		if nodeRows[left].Count != nodeRows[right].Count {
			return nodeRows[left].Count > nodeRows[right].Count
		}
		return nodeRows[left].Label < nodeRows[right].Label
	})
	sort.SliceStable(graphEdges, func(left, right int) bool {
		if graphEdges[left].Count != graphEdges[right].Count {
			return graphEdges[left].Count > graphEdges[right].Count
		}
		if graphEdges[left].Source != graphEdges[right].Source {
			return graphEdges[left].Source < graphEdges[right].Source
		}
		return graphEdges[left].Target < graphEdges[right].Target
	})
	sort.SliceStable(edgeRows, func(left, right int) bool {
		if edgeRows[left].Count != edgeRows[right].Count {
			return edgeRows[left].Count > edgeRows[right].Count
		}
		if edgeRows[left].Source != edgeRows[right].Source {
			return edgeRows[left].Source < edgeRows[right].Source
		}
		return edgeRows[left].Target < edgeRows[right].Target
	})
	sort.SliceStable(graphRoutes, func(left, right int) bool {
		if graphRoutes[left].Count != graphRoutes[right].Count {
			return graphRoutes[left].Count > graphRoutes[right].Count
		}
		if graphRoutes[left].TargetLabel != graphRoutes[right].TargetLabel {
			return graphRoutes[left].TargetLabel < graphRoutes[right].TargetLabel
		}
		return graphRoutes[left].ID < graphRoutes[right].ID
	})

	if len(nodeRows) > 12 {
		nodeRows = nodeRows[:12]
	}
	if len(edgeRows) > 12 {
		edgeRows = edgeRows[:12]
	}

	summary.Nodes = len(graphNodes)
	summary.Edges = len(graphEdges)
	return TopologyGraph{
		Summary: summary,
		Nodes:   graphNodes,
		Edges:   graphEdges,
		Routes:  graphRoutes,
	}, nodeRows, edgeRows
}

func (s *snapshot) matchingIndices(filter HostFilter) []int {
	filter = normalizeFilter(filter)
	indices := s.filterMatches(filter)
	s.sortMatches(indices, filter.Sort)
	return indices
}

func (s *snapshot) exportLinks(filter HostFilter) []ExportLink {
	return []ExportLink{
		{
			Label:  "Host list",
			Detail: "Filtered IP list for external tooling.",
			Href:   exportHref("/exports/hosts.txt", filter),
		},
		{
			Label:  "Inventory CSV",
			Detail: "Current result set as analyst-friendly CSV.",
			Href:   exportHref("/exports/hosts.csv", filter),
		},
		{
			Label:  "Nuclei targets",
			Detail: "HTTP/HTTPS URLs inferred from open services.",
			Href:   exportHref("/exports/nuclei.txt", filter),
		},
		{
			Label:  "Route graph JSON",
			Detail: "Aggregated topology for external graph tooling.",
			Href:   "/api/graph",
		},
	}
}

func (s *snapshot) hostListText(filter HostFilter) string {
	var builder strings.Builder
	for _, index := range s.matchingIndices(filter) {
		builder.WriteString(s.records[index].summary.IP)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func (s *snapshot) inventoryCSV(filter HostFilter) string {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	_ = writer.Write([]string{"ip", "hostname", "os", "exposure", "coverage", "open_ports", "services", "scripts", "findings", "critical_ports"})
	for _, index := range s.matchingIndices(filter) {
		record := s.records[index].summary
		_ = writer.Write([]string{
			record.IP,
			record.DisplayName,
			record.OS,
			record.Exposure.Label,
			record.Coverage.Label,
			strconv.Itoa(record.OpenPortCount),
			strconv.Itoa(record.ServiceCount),
			strconv.Itoa(record.ScriptCount),
			strconv.Itoa(record.Findings.Total),
			strings.Join(record.Exposure.CriticalPorts, " "),
		})
	}
	writer.Flush()
	return builder.String()
}

func (s *snapshot) nucleiTargets(filter HostFilter) string {
	targets := map[string]struct{}{}
	for _, index := range s.matchingIndices(filter) {
		record := s.records[index].detail
		for _, target := range record.NucleiTargets {
			targets[target] = struct{}{}
		}
	}

	lines := make([]string, 0, len(targets))
	for target := range targets {
		lines = append(lines, target)
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func exportHref(path string, filter HostFilter) string {
	values := url.Values{}
	filter = normalizeFilter(filter)
	if filter.Query != "" {
		values.Set("query", filter.Query)
	}
	if filter.Scope != "" && filter.Scope != "all" {
		values.Set("scope", filter.Scope)
	}
	if filter.Sort != "" && filter.Sort != "exposure" {
		values.Set("sort", filter.Sort)
	}
	if filter.PageSize != defaultPageSize {
		values.Set("page_size", strconv.Itoa(filter.PageSize))
	}
	encoded := values.Encode()
	if encoded == "" {
		return path
	}
	return path + "?" + encoded
}

func graphNodeID(hop TraceHopView) string {
	if hop.Address != "" {
		return hop.Address
	}
	return hop.Host
}

func graphNodeLabel(hop TraceHopView, id string) string {
	if hop.Host != "" && hop.Host != hop.Address {
		return id + " · " + hop.Host
	}
	return id
}

func appendGraphHop(hops []string, nodeID string) []string {
	if nodeID == "" {
		return hops
	}
	if len(hops) > 0 && hops[len(hops)-1] == nodeID {
		return hops
	}
	return append(hops, nodeID)
}

func topologyRouteTargetLabel(summary HostSummary, targetID string) string {
	if targetID == "" {
		return "Unknown target"
	}

	displayName := strings.TrimSpace(summary.DisplayName)
	switch {
	case displayName != "" && displayName != targetID:
		return targetID + " · " + displayName
	case len(summary.Hostnames) > 0 && summary.Hostnames[0] != "" && summary.Hostnames[0] != targetID:
		return targetID + " · " + summary.Hostnames[0]
	default:
		return targetID
	}
}

func topologyProviderKey(hostname string, nodeID string) string {
	hostname = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(hostname, ".")))
	if hostname != "" {
		if addr, err := netip.ParseAddr(hostname); err == nil && addr.IsValid() {
			return ""
		}

		parts := strings.FieldsFunc(hostname, func(r rune) bool {
			return r == '.'
		})
		if len(parts) == 0 {
			return hostname
		}
		if len(parts) == 1 {
			return parts[0]
		}
		if len(parts) >= 3 && len(parts[len(parts)-1]) == 2 && len(parts[len(parts)-2]) <= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	_ = nodeID
	return ""
}

func topologyIconForOS(osLabel string) string {
	label := strings.ToLower(strings.TrimSpace(osLabel))
	switch {
	case label == "":
		return "unknown"
	case strings.Contains(label, "windows") || strings.Contains(label, "microsoft"):
		return "windows"
	case strings.Contains(label, "linksys"):
		return "linksys"
	case strings.Contains(label, "cisco") || strings.Contains(label, "routeros") || strings.Contains(label, "ios") || strings.Contains(label, "mikrotik"):
		return "cisco"
	case strings.Contains(label, "linux"),
		strings.Contains(label, "ubuntu"),
		strings.Contains(label, "debian"),
		strings.Contains(label, "centos"),
		strings.Contains(label, "red hat"),
		strings.Contains(label, "suse"),
		strings.Contains(label, "unix"),
		strings.Contains(label, "bsd"),
		strings.Contains(label, "solaris"):
		return "linux"
	default:
		return "unknown"
	}
}

func ttlValue(ttl string, fallback int) float64 {
	parsed, err := strconv.Atoi(strings.TrimSpace(ttl))
	if err != nil || parsed <= 0 {
		return float64(fallback + 1)
	}
	return float64(parsed)
}

func looksLikeHTTP(port PortRow) bool {
	service := strings.ToLower(port.Service + " " + port.Product + " " + port.ExtraInfo)
	if strings.Contains(service, "http") || strings.Contains(service, "web") {
		return true
	}
	switch port.Port {
	case "80", "81", "443", "591", "593", "8000", "8008", "8080", "8081", "8088", "8443", "8888", "9000", "9443":
		return true
	default:
		return false
	}
}

func looksLikeHTTPS(port PortRow) bool {
	service := strings.ToLower(port.Service + " " + port.Product + " " + port.ExtraInfo)
	if strings.Contains(service, "https") || strings.Contains(service, "ssl") || strings.Contains(service, "tls") {
		return true
	}
	switch port.Port {
	case "443", "8443", "9443":
		return true
	default:
		return false
	}
}

func scannerBuckets(scans []ScanCatalogItem) []Bucket {
	if len(scans) == 0 {
		return nil
	}

	counts := map[string]int{}
	for _, scan := range scans {
		label := chooseString(strings.TrimSpace(scan.Scanner), strings.TrimSpace(scan.Kind), "source")
		counts[label]++
	}

	items := make([]Bucket, 0, len(counts))
	for label, count := range counts {
		items = append(items, Bucket{
			Label: label,
			Count: count,
			Href:  "/scans",
		})
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Count != items[right].Count {
			return items[left].Count > items[right].Count
		}
		return items[left].Label < items[right].Label
	})
	return items
}

func coverageBuckets(snapshot *snapshot) []Bucket {
	if snapshot == nil || len(snapshot.records) == 0 {
		return nil
	}

	counts := map[string]int{}
	for _, record := range snapshot.records {
		label := chooseString(strings.TrimSpace(record.summary.Coverage.Label), "Unknown")
		counts[label]++
	}

	items := make([]Bucket, 0, len(counts))
	for label, count := range counts {
		items = append(items, Bucket{
			Label: label,
			Count: count,
			Href:  "/hosts?sort=exposure",
		})
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Count != items[right].Count {
			return items[left].Count > items[right].Count
		}
		return items[left].Label < items[right].Label
	})
	return items
}

func jobStatusBuckets(jobs []PluginJobView) []Bucket {
	if len(jobs) == 0 {
		return nil
	}

	counts := map[string]int{}
	for _, job := range jobs {
		label := humanizeStatus(strings.TrimSpace(job.Status))
		if label == "" {
			label = "Unknown"
		}
		counts[label]++
	}

	items := make([]Bucket, 0, len(counts))
	for label, count := range counts {
		items = append(items, Bucket{
			Label: label,
			Count: count,
			Href:  "/workspace#jobs",
		})
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Count != items[right].Count {
			return items[left].Count > items[right].Count
		}
		return items[left].Label < items[right].Label
	})
	return items
}

func recommendedRunProfiles(snapshot *snapshot) []RunProfileView {
	if snapshot == nil {
		return nil
	}

	webHosts := 0
	coverageHosts := 0
	priorityHosts := 0
	for _, record := range snapshot.records {
		if len(record.detail.NucleiTargets) > 0 {
			webHosts++
		}
		if record.summary.Coverage.NeedsEnrichment {
			coverageHosts++
		}
		if record.summary.Exposure.Tone == "risk" || record.summary.Exposure.Tone == "warning" {
			priorityHosts++
		}
	}

	return []RunProfileView{
		{
			Label:        "Nmap list scan",
			PluginID:     "nmap-enrich",
			ProfileScope: "all-hosts",
			Detail:       "Render the declared live host slice as an address inventory without attempting transport probes.",
			Count:        len(snapshot.records),
			CountLabel:   "live hosts",
			ModeLabel:    "List targets",
			Profile:      "list",
		},
		{
			Label:        "Nmap ping discovery",
			PluginID:     "nmap-enrich",
			ProfileScope: "all-hosts",
			Detail:       "Re-check reachability for the current host slice with host discovery only.",
			Count:        len(snapshot.records),
			CountLabel:   "live hosts",
			ModeLabel:    "Host discovery",
			Profile:      "ping",
		},
		{
			Label:        "Nmap default TCP",
			PluginID:     "nmap-enrich",
			ProfileScope: "all-hosts",
			Detail:       "Run the default nmap service scan across all live hosts currently recorded in the workspace.",
			Count:        len(snapshot.records),
			CountLabel:   "live hosts",
			ModeLabel:    "Default ports",
			Profile:      "default",
		},
		{
			Label:        "Nmap full TCP",
			PluginID:     "nmap-enrich",
			ProfileScope: "all-hosts",
			Detail:       "Escalate to a full TCP sweep with service detection, OS fingerprinting, and traceroute.",
			Count:        len(snapshot.records),
			CountLabel:   "live hosts",
			ModeLabel:    "All TCP ports",
			Profile:      "all-tcp",
		},
		{
			Label:        "Nmap top UDP",
			PluginID:     "nmap-enrich",
			ProfileScope: "all-hosts",
			Detail:       "Probe the top UDP ports across the current host inventory before deciding on full UDP expansion.",
			Count:        len(snapshot.records),
			CountLabel:   "live hosts",
			ModeLabel:    "Top UDP ports",
			Profile:      "udp-top",
		},
		{
			Label:        "HTTPX census",
			PluginID:     "httpx",
			ProfileScope: "web",
			Detail:       "Probe mapped web surfaces for titles, technologies, and response fingerprints.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "Web census",
		},
		{
			Label:        "Nuclei web sweep",
			PluginID:     "nuclei",
			ProfileScope: "web",
			Detail:       "Validate inferred HTTP surfaces and attach findings back to mapped hosts.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "HTTP validation",
			Severity:     "critical,high,medium",
		},
		{
			Label:        "Nikto baseline",
			PluginID:     "nikto",
			ProfileScope: "web",
			Detail:       "Run a baseline Nikto pass against the mapped web slice and retain the raw output as workspace artifacts.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "Baseline web scan",
			Profile:      "basic",
		},
		{
			Label:        "Nikto comprehensive",
			PluginID:     "nikto",
			ProfileScope: "web",
			Detail:       "Escalate to a broader Nikto pass with the full check class set enabled.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "Comprehensive web scan",
			Profile:      "comprehensive",
		},
		{
			Label:        "Nmap coverage gaps",
			PluginID:     "nmap-enrich",
			ProfileScope: "coverage-gap",
			Detail:       "Deepen hosts that still only have surface or partial coverage.",
			Count:        coverageHosts,
			CountLabel:   "coverage gaps",
			ModeLabel:    "Coverage follow-up",
			Profile:      "safe",
		},
		{
			Label:        "Nmap priority hosts",
			PluginID:     "nmap-enrich",
			ProfileScope: "high-exposure",
			Detail:       "Run deeper scripts, OS detection, and traceroute against the riskiest inventory slice.",
			Count:        priorityHosts,
			CountLabel:   "priority hosts",
			ModeLabel:    "Priority follow-up",
			Profile:      "deep",
		},
		{
			Label:        "Naabu priority sweep",
			PluginID:     "naabu",
			ProfileScope: "high-exposure",
			Detail:       "Run a fast port sweep across the riskiest host slice and import the observed exposure.",
			Count:        priorityHosts,
			CountLabel:   "priority hosts",
			ModeLabel:    "Port discovery",
		},
		{
			Label:        "SQLMap web probes",
			PluginID:     "sqlmap",
			ProfileScope: "web",
			Detail:       "Probe mapped web roots with form crawling and import likely SQL injection hits.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "SQLi validation",
			CrawlDepth:   "1",
		},
		{
			Label:        "Katana path crawl",
			PluginID:     "katana",
			ProfileScope: "web",
			Detail:       "Discover reachable paths and application edges across mapped web hosts.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "Path discovery",
			CrawlDepth:   "2",
		},
		{
			Label:        "ZAP web validation",
			PluginID:     "zap-connector",
			ProfileScope: "web",
			Detail:       "Launch a ZAP spider and active scan against the mapped web slice.",
			Count:        webHosts,
			CountLabel:   "web hosts",
			ModeLabel:    "DAST connector",
		},
	}
}

func (w *workspace) commandCenterRunProfiles() []RunProfileView {
	snapshot := w.currentSnapshot()
	items := recommendedRunProfiles(snapshot)
	domainTargets := w.domainScopeTargets()
	if len(domainTargets) == 0 {
		return items
	}

	items = append([]RunProfileView{
		{
			Label:        "Subdomain discovery",
			PluginID:     "subfinder",
			ProfileScope: "domains",
			Detail:       "Query passive sources for subdomains attached to the declared engagement domains and feed them back into discovery.",
			Count:        len(domainTargets),
			CountLabel:   "domains",
			ModeLabel:    "Passive DNS recon",
		},
		{
			Label:        "DNS validation",
			PluginID:     "dnsx",
			ProfileScope: "domains",
			Detail:       "Resolve the declared engagement domains before expanding into deeper host discovery.",
			Count:        len(domainTargets),
			CountLabel:   "domains",
			ModeLabel:    "DNS resolve",
		},
	}, items...)
	return items
}

func hostHasDatabasePort(ports []PortRow) bool {
	for _, port := range ports {
		if !strings.EqualFold(port.State, "open") {
			continue
		}
		switch strings.TrimSpace(port.Port) {
		case "1433", "1521", "3306", "5432", "6379", "9200", "27017":
			return true
		}
	}
	return false
}

func humanizeStatus(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	parts := strings.Fields(strings.ReplaceAll(value, "-", " "))
	for index, part := range parts {
		if part == "" {
			continue
		}
		parts[index] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
