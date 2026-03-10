package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"nwa/nmap"
)

type mergedHost struct {
	host    nmap.Host
	sources []string
}

func buildSnapshotFromScans(scans []managedScan, enrichments map[string]hostEnrichment) *snapshot {
	inputs := mergedInputs(scans, enrichments)
	records := buildHostRecordsFromInputs(inputs)
	slices.SortStableFunc(records, compareHostRecordsByIP)

	s := &snapshot{
		meta:    buildScanMeta(scans, records),
		records: records,
	}

	var wg sync.WaitGroup
	wg.Add(8)

	go func() {
		defer wg.Done()
		s.hostByIP = buildHostMap(records)
	}()

	go func() {
		defer wg.Done()
		s.portBuckets = buildBuckets(records, "port")
	}()

	go func() {
		defer wg.Done()
		s.osBuckets = buildBuckets(records, "os")
	}()

	go func() {
		defer wg.Done()
		s.serviceBuckets = buildBuckets(records, "service")
	}()

	go func() {
		defer wg.Done()
		s.portIndex = buildPortIndex(records)
	}()

	go func() {
		defer wg.Done()
		s.topology, s.topNodes, s.topEdges = buildTopologyGraph(records)
	}()

	go func() {
		defer wg.Done()
		s.highExposure = buildHighExposure(records, 10)
	}()

	go func() {
		defer wg.Done()
		s.findingTotals, s.topFindings = buildFindingSummaries(records, 12)
	}()

	wg.Wait()
	s.stats = buildStatCards(records, s.portBuckets, s.osBuckets, s.serviceBuckets)
	s.summaryLine = buildExecutiveSummary(records, s.portBuckets, s.osBuckets, s.serviceBuckets)
	return s
}

func buildScanMeta(scans []managedScan, records []hostRecord) ScanMeta {
	if len(scans) == 0 {
		return ScanMeta{
			SourceFile: "No scans imported",
			Scanner:    "n/a",
			StartedAt:  "Awaiting imported scan data or managed plugin runs",
			Type:       "n/a",
			Protocol:   "n/a",
			LiveHosts:  0,
			ScanCount:  0,
		}
	}

	latest := scans[len(scans)-1].record
	sourceLabel := latest.Name
	if len(scans) > 1 {
		sourceLabel = fmt.Sprintf("%d imported scans", len(scans))
	}
	return ScanMeta{
		SourceFile: sourceLabel,
		Scanner:    chooseString(latest.Scanner, "nmap"),
		Version:    latest.Version,
		StartedAt:  chooseString(latest.StartedAt, latest.ImportedAt),
		Command:    latest.Command,
		Type:       chooseString(latest.Type, "n/a"),
		Protocol:   chooseString(latest.Protocol, "n/a"),
		LiveHosts:  len(records),
		ScanCount:  len(scans),
	}
}

func mergedInputs(scans []managedScan, enrichments map[string]hostEnrichment) []hostBuildInput {
	if len(scans) == 0 {
		return nil
	}

	accumulators := map[string]*mergedHost{}
	order := make([]string, 0)
	for _, scan := range scans {
		for _, host := range scan.scan.Alive() {
			ip := strings.TrimSpace(host.Address.Addr)
			if ip == "" {
				continue
			}

			current := accumulators[ip]
			if current == nil {
				accumulators[ip] = &mergedHost{
					host:    host,
					sources: []string{scan.record.Name},
				}
				order = append(order, ip)
				continue
			}

			current.host = mergeHosts(current.host, host)
			if !slices.Contains(current.sources, scan.record.Name) {
				current.sources = append(current.sources, scan.record.Name)
			}
		}
	}

	inputs := make([]hostBuildInput, 0, len(order))
	for _, ip := range order {
		entry := accumulators[ip]
		sort.Strings(entry.sources)
		inputs = append(inputs, hostBuildInput{
			host:       entry.host,
			sources:    entry.sources,
			enrichment: enrichments[ip],
		})
	}
	return inputs
}

func mergeHosts(left nmap.Host, right nmap.Host) nmap.Host {
	result := left
	if strings.TrimSpace(result.Status.State) == "" || strings.EqualFold(right.Status.State, "up") {
		result.Status = right.Status
	}
	if strings.TrimSpace(result.Address.Addr) == "" {
		result.Address = right.Address
	}
	result.HostNames = mergeHostNames(result.HostNames, right.HostNames)
	result.Ports = mergePorts(result.Ports, right.Ports)
	result.OS = mergeOS(result.OS, right.OS)
	result.Distance = preferString(result.Distance, right.Distance)
	result.DistanceValue = right.DistanceValue
	result.Trace = mergeTrace(result.Trace, right.Trace)
	result.Times = mergeTimes(result.Times, right.Times)
	result.TCPSequence = mergeTCPSequence(result.TCPSequence, right.TCPSequence)
	result.IPIDSequence = mergeIPIDSequence(result.IPIDSequence, right.IPIDSequence)
	result.TCPTSSequence = mergeTCPTSSequence(result.TCPTSSequence, right.TCPTSSequence)
	result.StartTime = preferString(result.StartTime, right.StartTime)
	result.EndTime = preferString(result.EndTime, right.EndTime)
	return result
}

func mergeHostNames(left []nmap.HostName, right []nmap.HostName) []nmap.HostName {
	seen := map[string]struct{}{}
	results := make([]nmap.HostName, 0, len(left)+len(right))
	for _, host := range append(left, right...) {
		key := strings.ToLower(strings.TrimSpace(host.Name))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, host)
	}
	return results
}

func mergePorts(left []nmap.Port, right []nmap.Port) []nmap.Port {
	type keyedPort struct {
		key  string
		port nmap.Port
	}

	seen := map[string]nmap.Port{}
	order := make([]string, 0, len(left)+len(right))
	for _, port := range left {
		key := port.Protocol + "/" + port.Portid
		seen[key] = port
		order = append(order, key)
	}
	for _, port := range right {
		key := port.Protocol + "/" + port.Portid
		current, ok := seen[key]
		if !ok {
			seen[key] = port
			order = append(order, key)
			continue
		}
		seen[key] = mergePort(current, port)
	}

	results := make([]nmap.Port, 0, len(order))
	for _, key := range order {
		results = append(results, seen[key])
	}
	sort.SliceStable(results, func(leftIndex, rightIndex int) bool {
		return comparePorts(results[leftIndex].Portid, results[leftIndex].Protocol, results[rightIndex].Portid, results[rightIndex].Protocol)
	})
	return results
}

func mergePort(left nmap.Port, right nmap.Port) nmap.Port {
	result := left
	if portStateWeight(right.State.State) > portStateWeight(left.State.State) {
		result.State = right.State
	}
	result.Service = mergeService(left.Service, right.Service)
	result.Scripts = mergeScripts(left.Scripts, right.Scripts)
	return result
}

func mergeService(left nmap.Service, right nmap.Service) nmap.Service {
	return nmap.Service{
		Name:        preferRicherString(left.Name, right.Name),
		Product:     preferRicherString(left.Product, right.Product),
		Version:     preferRicherString(left.Version, right.Version),
		FingerPrint: preferRicherString(left.FingerPrint, right.FingerPrint),
		ExtraInfo:   preferRicherString(left.ExtraInfo, right.ExtraInfo),
		OSType:      preferRicherString(left.OSType, right.OSType),
		Method:      preferRicherString(left.Method, right.Method),
		Conf:        preferRicherString(left.Conf, right.Conf),
		CPEs:        mergeCPEs(left.CPEs, right.CPEs),
	}
}

func mergeCPEs(left []nmap.Cpe, right []nmap.Cpe) []nmap.Cpe {
	seen := map[string]struct{}{}
	results := make([]nmap.Cpe, 0, len(left)+len(right))
	for _, cpe := range append(left, right...) {
		key := strings.TrimSpace(cpe.Value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, cpe)
	}
	return results
}

func mergeScripts(left []nmap.Script, right []nmap.Script) []nmap.Script {
	seen := map[string]struct{}{}
	results := make([]nmap.Script, 0, len(left)+len(right))
	for _, script := range append(left, right...) {
		key := strings.TrimSpace(script.Id) + "|" + strings.TrimSpace(script.Output)
		if strings.TrimSpace(script.Id) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, script)
	}
	return results
}

func mergeOS(left nmap.OS, right nmap.OS) nmap.OS {
	result := left
	result.PortsUsed = mergePortsUsed(left.PortsUsed, right.PortsUsed)
	result.OSMatches = mergeOSMatches(left.OSMatches, right.OSMatches)
	if len(strings.TrimSpace(right.OSFingerPrint.Fingerprint)) > len(strings.TrimSpace(left.OSFingerPrint.Fingerprint)) {
		result.OSFingerPrint = right.OSFingerPrint
	}
	return result
}

func mergePortsUsed(left []nmap.PortUsed, right []nmap.PortUsed) []nmap.PortUsed {
	seen := map[string]struct{}{}
	results := make([]nmap.PortUsed, 0, len(left)+len(right))
	for _, port := range append(left, right...) {
		key := port.Protocol + "/" + port.Portid + "/" + port.State
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, port)
	}
	return results
}

func mergeOSMatches(left []nmap.OSMatch, right []nmap.OSMatch) []nmap.OSMatch {
	seen := map[string]struct{}{}
	results := make([]nmap.OSMatch, 0, len(left)+len(right))
	for _, match := range append(left, right...) {
		key := strings.TrimSpace(match.Name) + "|" + strings.TrimSpace(match.Accuracy)
		if strings.TrimSpace(match.Name) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, match)
	}
	sort.SliceStable(results, func(leftIndex, rightIndex int) bool {
		if results[leftIndex].Accuracy != results[rightIndex].Accuracy {
			return results[leftIndex].Accuracy > results[rightIndex].Accuracy
		}
		return results[leftIndex].Name < results[rightIndex].Name
	})
	return results
}

func mergeTrace(left nmap.Trace, right nmap.Trace) nmap.Trace {
	if len(right.Hops) > len(left.Hops) {
		return right
	}
	if len(left.Hops) == 0 {
		return right
	}
	return left
}

func mergeTimes(left nmap.Times, right nmap.Times) nmap.Times {
	return nmap.Times{
		Srtt:   preferRicherString(left.Srtt, right.Srtt),
		Tttvar: preferRicherString(left.Tttvar, right.Tttvar),
		To:     preferRicherString(left.To, right.To),
	}
}

func mergeTCPSequence(left nmap.TCPSequence, right nmap.TCPSequence) nmap.TCPSequence {
	return nmap.TCPSequence{
		Index:      preferRicherString(left.Index, right.Index),
		Difficulty: preferRicherString(left.Difficulty, right.Difficulty),
		Values:     preferRicherString(left.Values, right.Values),
	}
}

func mergeIPIDSequence(left nmap.IPIDSequence, right nmap.IPIDSequence) nmap.IPIDSequence {
	return nmap.IPIDSequence{
		Class:  preferRicherString(left.Class, right.Class),
		Values: preferRicherString(left.Values, right.Values),
	}
}

func mergeTCPTSSequence(left nmap.TCPTSSequence, right nmap.TCPTSSequence) nmap.TCPTSSequence {
	return nmap.TCPTSSequence{
		Class:  preferRicherString(left.Class, right.Class),
		Values: preferRicherString(left.Values, right.Values),
	}
}

func preferString(left string, right string) string {
	if strings.TrimSpace(right) != "" {
		return right
	}
	return left
}

func preferRicherString(left string, right string) string {
	if len(strings.TrimSpace(right)) > len(strings.TrimSpace(left)) {
		return right
	}
	if strings.TrimSpace(left) != "" {
		return left
	}
	return right
}

func portStateWeight(state string) int {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "open":
		return 3
	case "filtered":
		return 2
	case "closed":
		return 1
	default:
		return 0
	}
}

func buildFindingSummaries(records []hostRecord, limit int) (FindingSummary, []FindingTemplateSummary) {
	totals := FindingSummary{}
	counts := map[string]*FindingTemplateSummary{}
	for _, record := range records {
		totals.Total += record.summary.Findings.Total
		totals.Critical += record.summary.Findings.Critical
		totals.High += record.summary.Findings.High
		totals.Medium += record.summary.Findings.Medium
		totals.Low += record.summary.Findings.Low
		totals.Info += record.summary.Findings.Info

		for _, finding := range record.detail.NucleiFindings {
			key := finding.Source + "|" + finding.TemplateID + "|" + finding.Name + "|" + finding.Severity
			if counts[key] == nil {
				counts[key] = &FindingTemplateSummary{
					TemplateID: finding.TemplateID,
					Name:       finding.Name,
					Source:     finding.Source,
					Severity:   finding.Severity,
				}
			}
			counts[key].Count++
		}
	}

	rows := make([]FindingTemplateSummary, 0, len(counts))
	for _, row := range counts {
		rows = append(rows, *row)
	}
	sort.SliceStable(rows, func(left, right int) bool {
		if severityWeight(rows[left].Severity) != severityWeight(rows[right].Severity) {
			return severityWeight(rows[left].Severity) > severityWeight(rows[right].Severity)
		}
		if rows[left].Count != rows[right].Count {
			return rows[left].Count > rows[right].Count
		}
		return rows[left].Name < rows[right].Name
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return totals, rows
}
