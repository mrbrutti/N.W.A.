package main

import (
	"net/url"
	"strings"
)

var webPortSet = map[string]struct{}{
	"80":   {},
	"81":   {},
	"443":  {},
	"444":  {},
	"591":  {},
	"593":  {},
	"8000": {},
	"8008": {},
	"8080": {},
	"8081": {},
	"8088": {},
	"8443": {},
	"8888": {},
	"9000": {},
	"9443": {},
}

func portHostBuckets(rows []PortSummaryView) []Bucket {
	buckets := make([]Bucket, 0, len(rows))
	for _, row := range rows {
		if row.Hosts <= 0 {
			continue
		}
		buckets = append(buckets, Bucket{
			Label: row.Label,
			Count: row.Hosts,
			Href:  row.Href,
		})
	}
	if len(buckets) == 0 {
		return nil
	}
	sortBuckets(buckets)
	return buckets
}

func (w *workspace) filteredFindingPortBuckets(query string, severity string, source string) []Bucket {
	query = strings.ToLower(strings.TrimSpace(query))
	severity = normalizeFindingSeverityFilter(severity)
	source = strings.ToLower(strings.TrimSpace(source))

	counts := map[string]int{}
	for _, record := range w.currentSnapshot().records {
		for _, finding := range record.detail.NucleiFindings {
			if !findingMatchesSlice(finding, query, severity, source) {
				continue
			}
			port := extractTargetPort(finding.Target)
			if port == "" {
				continue
			}
			counts[port]++
		}
	}

	return sortedBucketCounts(counts, func(label string) string {
		return "/ports?query=" + url.QueryEscape(label)
	})
}

func findingMatchesSlice(finding NucleiFindingView, query string, severity string, source string) bool {
	if severity != "all" && normalizeSeverity(finding.Severity) != severity {
		return false
	}
	if source != "" && source != "all" && strings.ToLower(strings.TrimSpace(normalizedFindingSource(finding.Source))) != source {
		return false
	}
	if query == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{
		finding.Name,
		finding.TemplateID,
		finding.Source,
		finding.Severity,
		finding.Target,
		finding.Description,
		strings.Join(finding.Tags, " "),
	}, " "))
	return strings.Contains(haystack, query)
}

func sortBuckets(items []Bucket) {
	for left := 0; left < len(items); left++ {
		best := left
		for right := left + 1; right < len(items); right++ {
			if items[right].Count > items[best].Count || (items[right].Count == items[best].Count && strings.ToLower(items[right].Label) < strings.ToLower(items[best].Label)) {
				best = right
			}
		}
		items[left], items[best] = items[best], items[left]
	}
}

func (w *workspace) portIntegrationLanes(detail PortDetailView) []IntegrationLaneView {
	targets := strings.Join(uniqueStrings(detail.HostTargets), "\n")
	isWeb := looksWebFacing(detail.Service, detail.Port)
	return []IntegrationLaneView{
		{
			Label:  "Managed commands",
			Detail: "Runnable directly from the queue against the current port slice.",
			Actions: []IntegrationActionView{
				managedAction("nmap-enrich", "Nmap deep enrichment", "Managed command", "Network discovery", "Re-scan the affected hosts with richer service, OS, and traceroute coverage.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "", "deep", "", false),
				managedAction("naabu", "Naabu fast sweep", "Managed command", "Network discovery", "Re-check fast port exposure across the same host slice and import the discovered surface back into the workspace.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "", "", "", false),
				managedAction("httpx", "HTTPX census", "Managed command", "Web discovery", "Probe reachable web edges on this host set and capture titles, status codes, and technology fingerprints.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "", "", "", !isWeb),
				managedAction("nuclei", "Nuclei service sweep", "Managed command", "Web validation", "Generate HTTP targets from the host set on this port and attach findings back to inventory.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "critical,high,medium", "", "", !isWeb),
				managedAction("nikto", "Nikto baseline", "Managed command", "Web validation", "Run Nikto against the inferred web roots on this port slice and retain the resulting output for review.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "", "basic", "", !isWeb),
				managedAction("katana", "Katana crawl", "Managed command", "Web discovery", "Crawl application paths starting from the inferred web roots on this port slice.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "", "", "2", !isWeb),
				managedAction("sqlmap", "SQLMap probe", "Managed command", "Web validation", "Probe application endpoints inferred from this port slice for injectable parameters.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, "", "", "1", !isWeb),
			},
		},
		{
			Label:  "Report ingestion",
			Detail: "Import external evidence and merge it into the same host and port graph.",
			Actions: []IntegrationActionView{
				importAction("nessus-report", "Nessus or Tenable report", "Report import", "Vulnerability management", "Bring validated vulnerability scan output back into the workspace and diff it against this port slice.", "/workspace#import"),
				importAction("masscan-zmap", "Masscan or ZMap discovery", "Report import", "Discovery import", "Import high-volume discovery output to compare coverage and recurrence on this port.", "/workspace#import"),
			},
		},
		{
			Label:  "Connectors",
			Detail: "API-driven scanners and external platforms that can run or sync against the current slice.",
			Actions: []IntegrationActionView{
				connectorAction("burp-connector", "Burp Suite DAST", "API connector", "Web DAST", "Launch an on-demand Burp scan or sync Burp issues back into the workspace.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, !isWeb),
				connectorAction("zap-connector", "OWASP ZAP", "API connector", "Web DAST", "Run spider and active-scan stages through ZAP and attach alerts to the same hosts.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, !isWeb),
				connectorAction("tenable-connector", "Tenable VM", "API connector", "Vulnerability management", "Launch a configured Tenable scan, export the .nessus results, and import them into this workspace slice.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, false),
				connectorAction("nessus-connector", "Nessus Manager", "API connector", "Vulnerability management", "Launch a Nessus-managed scan and import the resulting report into this workspace slice.", detail.HostCount, targets, "/ports/"+detail.Protocol+"/"+detail.Port, false),
			},
		},
	}
}

func (w *workspace) findingIntegrationLanes(detail FindingDetailView) []IntegrationLaneView {
	targets := strings.Join(findingHostTargets(detail), "\n")
	isWeb := findingLooksWeb(detail)
	return []IntegrationLaneView{
		{
			Label:  "Managed commands",
			Detail: "Direct follow-up paths against the affected host membership.",
			Actions: []IntegrationActionView{
				managedAction("nmap-enrich", "Nmap deep enrichment", "Managed command", "Network discovery", "Revalidate service, script, OS, and traceroute coverage for the hosts attached to this definition.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "deep", "", false),
				managedAction("naabu", "Naabu fast sweep", "Managed command", "Network discovery", "Re-check fast exposure across the affected host set and import the resulting port observations.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "", "", false),
				managedAction("httpx", "HTTPX census", "Managed command", "Web discovery", "Probe the affected web surfaces and capture titles, technologies, and response fingerprints.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "", "", !isWeb),
				managedAction("nuclei", "Nuclei revalidation", "Managed command", "Web validation", "Re-run nuclei with the current severity scope and compare refreshed findings against this definition.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, detail.Group.Severity, "", "", !isWeb),
				managedAction("nikto", "Nikto baseline", "Managed command", "Web validation", "Run Nikto against the affected web surfaces and keep the raw output alongside the current findings.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "basic", "", !isWeb),
				managedAction("katana", "Katana crawl", "Managed command", "Web discovery", "Crawl the affected applications and surface additional paths or endpoints linked to this definition.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "", "2", !isWeb),
				managedAction("sqlmap", "SQLMap probe", "Managed command", "Web validation", "Probe web targets related to this definition for likely SQL injection paths.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "", "1", !isWeb),
				managedAction("dnsx", "DNSX validation", "Managed command", "DNS validation", "Resolve hostnames tied to the affected hosts and attach DNS observations back to the same records.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, "", "", "", false),
			},
		},
		{
			Label:  "Report ingestion",
			Detail: "Bring additional scanner evidence back into the same finding definition space.",
			Actions: []IntegrationActionView{
				importAction("nmap-xml", "Nmap XML import", "Report import", "Discovery import", "Import a deeper scan or NSE-heavy pass and diff it against the current finding footprint.", "/workspace#import"),
				importAction("nessus-report", "Nessus or Tenable report", "Report import", "Vulnerability management", "Import Nessus results to compare external vulnerability state with this grouped finding.", "/workspace#import"),
			},
		},
		{
			Label:  "Connectors",
			Detail: "API-driven scanners and external platforms that can validate or sync against the same affected hosts.",
			Actions: []IntegrationActionView{
				connectorAction("burp-connector", "Burp Suite DAST", "API connector", "Web DAST", "Launch or sync Burp scans tied back to the hosts affected by this definition.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, !isWeb),
				connectorAction("zap-connector", "OWASP ZAP", "API connector", "Web DAST", "Run spider and active-scan stages in ZAP against the affected application edges.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, !isWeb),
				connectorAction("tenable-connector", "Tenable VM", "API connector", "Vulnerability management", "Launch a configured Tenable scan and import the resulting report for this host set.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, false),
				connectorAction("nessus-connector", "Nessus Manager", "API connector", "Vulnerability management", "Launch a Nessus-managed scan and import its report for the same hosts.", detail.Group.Hosts, targets, "/findings/"+detail.Group.ID, false),
			},
		},
	}
}

func managedAction(pluginID string, label string, mode string, family string, description string, count int, targets string, returnTo string, severity string, profile string, crawlDepth string, disabled bool) IntegrationActionView {
	return IntegrationActionView{
		ID:               pluginID,
		Label:            label,
		Mode:             mode,
		Family:           family,
		Description:      description,
		Availability:     chooseString(map[bool]string{true: "limited", false: "available"}[disabled], "available"),
		AvailabilityTone: chooseString(map[bool]string{true: "warning", false: "accent"}[disabled], "accent"),
		ActionLabel:      "Queue",
		PluginID:         pluginID,
		TargetMode:       "manual",
		Targets:          targets,
		ReturnTo:         returnTo,
		Severity:         severity,
		Profile:          profile,
		CrawlDepth:       crawlDepth,
		Disabled:         disabled || strings.TrimSpace(targets) == "",
		Count:            count,
	}
}

func importAction(id string, label string, mode string, family string, description string, href string) IntegrationActionView {
	return IntegrationActionView{
		ID:               id,
		Label:            label,
		Mode:             mode,
		Family:           family,
		Description:      description,
		Availability:     "import-only",
		AvailabilityTone: "info",
		ActionLabel:      "Open workspace",
		Href:             href,
	}
}

func connectorAction(id string, label string, mode string, family string, description string, count int, targets string, returnTo string, disabled bool) IntegrationActionView {
	return IntegrationActionView{
		ID:               id,
		Label:            label,
		Mode:             mode,
		Family:           family,
		Description:      description,
		Availability:     chooseString(map[bool]string{true: "limited", false: "available"}[disabled], "available"),
		AvailabilityTone: chooseString(map[bool]string{true: "warning", false: "accent"}[disabled], "accent"),
		ActionLabel:      "Queue",
		PluginID:         id,
		TargetMode:       "manual",
		Targets:          targets,
		ReturnTo:         returnTo,
		Disabled:         disabled || strings.TrimSpace(targets) == "",
		Count:            count,
	}
}

func looksWebFacing(service string, port string) bool {
	service = strings.ToLower(strings.TrimSpace(service))
	if strings.Contains(service, "http") || strings.Contains(service, "web") || strings.Contains(service, "ssl") || strings.Contains(service, "tls") {
		return true
	}
	_, ok := webPortSet[strings.TrimSpace(port)]
	return ok
}

func findingLooksWeb(detail FindingDetailView) bool {
	source := strings.ToLower(strings.TrimSpace(detail.Group.Source))
	if strings.Contains(source, "nuclei") || strings.Contains(source, "sqlmap") || strings.Contains(source, "burp") || strings.Contains(source, "zap") {
		return true
	}
	for _, occurrence := range detail.Occurrences {
		target := strings.ToLower(strings.TrimSpace(occurrence.Target))
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return true
		}
		if looksWebFacing("", occurrence.Port) {
			return true
		}
	}
	for _, tag := range detail.Tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if strings.Contains(tag, "http") || strings.Contains(tag, "web") || strings.Contains(tag, "sqli") || strings.Contains(tag, "xss") {
			return true
		}
	}
	name := strings.ToLower(strings.Join([]string{detail.Group.Name, detail.Description}, " "))
	return strings.Contains(name, "http") || strings.Contains(name, "web") || strings.Contains(name, "sql")
}
