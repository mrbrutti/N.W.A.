package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"nwa/nmap"
)

type workspaceEvent struct {
	ID           string              `json:"id"`
	Kind         string              `json:"kind"`
	KindTone     string              `json:"kind_tone"`
	Label        string              `json:"label"`
	Summary      string              `json:"summary"`
	CreatedAt    string              `json:"created_at"`
	RefID        string              `json:"ref_id,omitempty"`
	HostIPs      []string            `json:"host_ips,omitempty"`
	Observations []observationRecord `json:"observations,omitempty"`
	Checkpoint   checkpointSnapshot  `json:"checkpoint"`
}

type observationRecord struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	KindTone string `json:"kind_tone"`
	Source   string `json:"source"`
	HostIP   string `json:"host_ip,omitempty"`
	Port     string `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	Severity string `json:"severity,omitempty"`
	Href     string `json:"href,omitempty"`
}

type checkpointSnapshot struct {
	Hosts    []checkpointHost    `json:"hosts,omitempty"`
	Ports    []checkpointPort    `json:"ports,omitempty"`
	Findings []checkpointFinding `json:"findings,omitempty"`
	Routes   []checkpointRoute   `json:"routes,omitempty"`
}

type checkpointHost struct {
	IP          string `json:"ip"`
	DisplayName string `json:"display_name"`
	OS          string `json:"os"`
}

type checkpointPort struct {
	Key       string `json:"key"`
	HostIP    string `json:"host_ip"`
	Protocol  string `json:"protocol"`
	Port      string `json:"port"`
	Service   string `json:"service"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
}

type checkpointFinding struct {
	Key       string `json:"key"`
	HostIP    string `json:"host_ip"`
	Name      string `json:"name"`
	Source    string `json:"source,omitempty"`
	Severity  string `json:"severity"`
	Target    string `json:"target"`
	MatchedAt string `json:"matched_at"`
	KnownHost bool   `json:"known_host"`
}

type checkpointRoute struct {
	Key         string `json:"key"`
	TargetIP    string `json:"target_ip"`
	TargetLabel string `json:"target_label"`
	Path        string `json:"path"`
	Depth       int    `json:"depth"`
}

func (w *workspace) loadLedger() error {
	events, err := w.store.loadEvents()
	if err != nil {
		return err
	}
	w.events = events
	if len(events) == 0 {
		return w.backfillLedger()
	}
	return nil
}

func (w *workspace) backfillLedger() error {
	var jobs []*pluginJob
	if w.plugins != nil {
		jobs = w.plugins.completedJobs()
	}
	history := buildWorkspaceHistory(w.scans, w.enrichments, jobs, w.runsDir, w.logger)
	if history == nil || len(history.checkpoints) <= 1 {
		w.events = nil
		return nil
	}

	events := make([]workspaceEvent, 0, len(history.checkpoints)-1)
	for index := 1; index < len(history.checkpoints); index++ {
		previous := history.checkpoints[index-1]
		current := history.checkpoints[index]
		events = append(events, workspaceEvent{
			ID:           current.meta.ID,
			Kind:         normalizeEventKind(current.meta.Kind),
			KindTone:     current.meta.KindTone,
			Label:        current.meta.Label,
			Summary:      current.meta.Summary,
			CreatedAt:    checkpointTimestamp(current.meta.At),
			RefID:        current.meta.ID,
			HostIPs:      observationHostIPs(observationsFromCheckpointDelta(previous.state, current.state)),
			Observations: observationsFromCheckpointDelta(previous.state, current.state),
			Checkpoint:   snapshotFromCheckpointState(current.state),
		})
	}
	if err := w.store.replaceEvents(events); err != nil {
		return err
	}
	w.events = events
	return nil
}

func (w *workspace) appendWorkspaceEventLocked(event workspaceEvent) error {
	if strings.TrimSpace(event.ID) == "" {
		event.ID = newWorkspaceID("evt")
	}
	if strings.TrimSpace(event.CreatedAt) == "" {
		event.CreatedAt = newEventTimestamp()
	}
	if len(event.HostIPs) == 0 {
		event.HostIPs = observationHostIPs(event.Observations)
	}
	if len(event.Checkpoint.Hosts) == 0 && len(event.Checkpoint.Ports) == 0 && len(event.Checkpoint.Findings) == 0 && len(event.Checkpoint.Routes) == 0 {
		event.Checkpoint = snapshotFromCheckpointState(buildCheckpointState(w.scans, w.enrichments))
	}

	if err := w.store.appendEvent(event); err != nil {
		return err
	}
	w.events = append(w.events, event)
	w.history = buildWorkspaceHistoryFromLedger(w.events)
	return nil
}

func (w *workspace) recentObservations(limit int) []ObservationView {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return recentObservationViews(w.events, "", limit)
}

func (w *workspace) hostObservations(ip string, limit int) []ObservationView {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return recentObservationViews(w.events, strings.TrimSpace(ip), limit)
}

func recentObservationViews(events []workspaceEvent, hostIP string, limit int) []ObservationView {
	if len(events) == 0 || limit == 0 {
		return nil
	}

	items := make([]ObservationView, 0, limit)
	for eventIndex := len(events) - 1; eventIndex >= 0; eventIndex-- {
		event := events[eventIndex]
		for observationIndex := len(event.Observations) - 1; observationIndex >= 0; observationIndex-- {
			observation := event.Observations[observationIndex]
			if hostIP != "" && observation.HostIP != hostIP {
				continue
			}
			items = append(items, ObservationView{
				ID:       observation.ID,
				At:       displayTimestamp(event.CreatedAt),
				Kind:     observation.Kind,
				KindTone: observation.KindTone,
				Source:   chooseString(observation.Source, event.Label),
				HostIP:   observation.HostIP,
				Label:    observation.Label,
				Detail:   observation.Detail,
				Severity: observation.Severity,
				Href:     observation.Href,
			})
			if len(items) >= limit {
				return items
			}
		}
	}
	return items
}

func buildWorkspaceHistoryFromLedger(events []workspaceEvent) *workspaceHistory {
	history := &workspaceHistory{
		indexByID: map[string]int{},
	}
	baseline := buildCheckpointState(nil, nil)
	history.append(workspaceCheckpoint{
		meta: ChangeCheckpointView{
			ID:           "baseline",
			Label:        "Empty workspace",
			Kind:         "Baseline",
			KindTone:     "ok",
			At:           "n/a",
			Summary:      "No scans or integration findings had been imported yet.",
			HostCount:    len(baseline.hosts),
			FindingCount: len(baseline.findings),
			RouteCount:   len(baseline.routes),
		},
		state: baseline,
	})

	for _, event := range events {
		state := checkpointStateFromSnapshot(event.Checkpoint)
		history.append(workspaceCheckpoint{
			meta: ChangeCheckpointView{
				ID:           event.ID,
				Label:        event.Label,
				Kind:         event.Kind,
				KindTone:     event.KindTone,
				At:           displayTimestamp(event.CreatedAt),
				Summary:      event.Summary,
				HostCount:    len(state.hosts),
				FindingCount: len(state.findings),
				RouteCount:   len(state.routes),
			},
			state: state,
		})
	}
	return history
}

func snapshotFromCheckpointState(state workspaceCheckpointState) checkpointSnapshot {
	snapshot := checkpointSnapshot{
		Hosts:    make([]checkpointHost, 0, len(state.hosts)),
		Ports:    make([]checkpointPort, 0, len(state.ports)),
		Findings: make([]checkpointFinding, 0, len(state.findings)),
		Routes:   make([]checkpointRoute, 0, len(state.routes)),
	}

	for _, host := range state.hosts {
		snapshot.Hosts = append(snapshot.Hosts, checkpointHost{
			IP:          host.IP,
			DisplayName: host.DisplayName,
			OS:          host.OS,
		})
	}
	for _, port := range state.ports {
		snapshot.Ports = append(snapshot.Ports, checkpointPort{
			Key:       port.Key,
			HostIP:    port.HostIP,
			Protocol:  port.Protocol,
			Port:      port.Port,
			Service:   port.Service,
			Product:   port.Product,
			Version:   port.Version,
			ExtraInfo: port.ExtraInfo,
		})
	}
	for _, finding := range state.findings {
		snapshot.Findings = append(snapshot.Findings, checkpointFinding{
			Key:       finding.Key,
			HostIP:    finding.HostIP,
			Name:      finding.Name,
			Source:    finding.Source,
			Severity:  finding.Severity,
			Target:    finding.Target,
			MatchedAt: finding.MatchedAt,
			KnownHost: finding.KnownHost,
		})
	}
	for _, route := range state.routes {
		snapshot.Routes = append(snapshot.Routes, checkpointRoute{
			Key:         route.Key,
			TargetIP:    route.TargetIP,
			TargetLabel: route.TargetLabel,
			Path:        route.Path,
			Depth:       route.Depth,
		})
	}

	sort.SliceStable(snapshot.Hosts, func(left, right int) bool {
		return compareIPStrings(snapshot.Hosts[left].IP, snapshot.Hosts[right].IP) < 0
	})
	sort.SliceStable(snapshot.Ports, func(left, right int) bool {
		if compare := compareIPStrings(snapshot.Ports[left].HostIP, snapshot.Ports[right].HostIP); compare != 0 {
			return compare < 0
		}
		return comparePorts(snapshot.Ports[left].Port, snapshot.Ports[left].Protocol, snapshot.Ports[right].Port, snapshot.Ports[right].Protocol)
	})
	sort.SliceStable(snapshot.Findings, func(left, right int) bool {
		if severityWeight(snapshot.Findings[left].Severity) != severityWeight(snapshot.Findings[right].Severity) {
			return severityWeight(snapshot.Findings[left].Severity) > severityWeight(snapshot.Findings[right].Severity)
		}
		return snapshot.Findings[left].Key < snapshot.Findings[right].Key
	})
	sort.SliceStable(snapshot.Routes, func(left, right int) bool {
		return snapshot.Routes[left].Key < snapshot.Routes[right].Key
	})
	return snapshot
}

func checkpointStateFromSnapshot(snapshot checkpointSnapshot) workspaceCheckpointState {
	state := workspaceCheckpointState{
		hosts:    map[string]historyHost{},
		ports:    map[string]historyPort{},
		findings: map[string]historyFinding{},
		routes:   map[string]historyRoute{},
	}

	for _, host := range snapshot.Hosts {
		state.hosts[host.IP] = historyHost{
			IP:          host.IP,
			DisplayName: host.DisplayName,
			OS:          host.OS,
		}
	}
	for _, port := range snapshot.Ports {
		state.ports[port.Key] = historyPort{
			Key:       port.Key,
			HostIP:    port.HostIP,
			Protocol:  port.Protocol,
			Port:      port.Port,
			Service:   port.Service,
			Product:   port.Product,
			Version:   port.Version,
			ExtraInfo: port.ExtraInfo,
		}
	}
	for _, finding := range snapshot.Findings {
		state.findings[finding.Key] = historyFinding{
			Key:       finding.Key,
			HostIP:    finding.HostIP,
			Name:      finding.Name,
			Source:    finding.Source,
			Severity:  finding.Severity,
			Target:    finding.Target,
			MatchedAt: finding.MatchedAt,
			KnownHost: finding.KnownHost,
		}
	}
	for _, route := range snapshot.Routes {
		state.routes[route.Key] = historyRoute{
			Key:         route.Key,
			TargetIP:    route.TargetIP,
			TargetLabel: route.TargetLabel,
			Path:        route.Path,
			Depth:       route.Depth,
		}
	}
	return state
}

func scanObservations(scan nmap.Scan, label string) []observationRecord {
	observations := make([]observationRecord, 0)
	for _, host := range scan.Alive() {
		ip := strings.TrimSpace(host.Address.Addr)
		if ip == "" {
			continue
		}

		displayName := ip
		if hostnames := host.HostnameLabels(); len(hostnames) > 0 {
			displayName = hostnames[0]
		}
		observations = append(observations, observationRecord{
			ID:       newWorkspaceID("obs"),
			Kind:     "host",
			KindTone: "ok",
			Source:   label,
			HostIP:   ip,
			Label:    displayName,
			Detail:   chooseString(strings.TrimSpace(host.OSGuess()), "Host observed"),
			Href:     "/ip/" + ip,
		})

		if osLabel := strings.TrimSpace(host.OSGuess()); osLabel != "" {
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "os",
				KindTone: "accent",
				Source:   label,
				HostIP:   ip,
				Label:    osLabel,
				Detail:   "OS fingerprint observed",
				Href:     "/ip/" + ip,
			})
		}

		for _, port := range host.Ports {
			if strings.ToLower(strings.TrimSpace(port.State.State)) != "open" {
				continue
			}
			service := serviceLabel(port)
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "port",
				KindTone: "ok",
				Source:   label,
				HostIP:   ip,
				Port:     port.Portid,
				Protocol: port.Protocol,
				Label:    port.Protocol + "/" + port.Portid,
				Detail:   chooseString(service, "open port"),
				Href:     "/ip/" + ip,
			})
			if detail := portFingerprint(historyPort{
				Protocol:  port.Protocol,
				Port:      port.Portid,
				Service:   strings.TrimSpace(port.Service.Name),
				Product:   strings.TrimSpace(port.Service.Product),
				Version:   strings.TrimSpace(port.Service.Version),
				ExtraInfo: strings.TrimSpace(port.Service.ExtraInfo),
			}); detail != "unclassified service" {
				observations = append(observations, observationRecord{
					ID:       newWorkspaceID("obs"),
					Kind:     "service",
					KindTone: "accent",
					Source:   label,
					HostIP:   ip,
					Port:     port.Portid,
					Protocol: port.Protocol,
					Label:    chooseString(service, port.Protocol+"/"+port.Portid),
					Detail:   detail,
					Href:     "/ip/" + ip,
				})
			}
		}

		if len(host.Trace.Hops) > 0 {
			hops := make([]string, 0, len(host.Trace.Hops))
			for _, hop := range host.Trace.Hops {
				nodeID := strings.TrimSpace(chooseString(hop.Host, hop.IPAddr))
				if nodeID == "" {
					continue
				}
				hops = appendGraphHop(hops, nodeID)
			}
			if len(hops) > 0 {
				observations = append(observations, observationRecord{
					ID:       newWorkspaceID("obs"),
					Kind:     "route",
					KindTone: "accent",
					Source:   label,
					HostIP:   ip,
					Label:    chooseString(displayName, ip),
					Detail:   fmt.Sprintf("%d-hop traceroute", len(hops)),
					Href:     "/ip/" + ip,
				})
			}
		}
	}
	return observations
}

func findingObservations(findings map[string][]storedNucleiFinding, label string) []observationRecord {
	observations := make([]observationRecord, 0)
	for hostIP, hostFindings := range findings {
		for _, finding := range hostFindings {
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "finding",
				KindTone: severityTone(finding.Severity),
				Source:   label,
				HostIP:   hostIP,
				Label:    chooseString(finding.Name, finding.TemplateID),
				Detail:   chooseString(finding.Target, finding.MatchedAt),
				Severity: normalizeSeverity(finding.Severity),
				Href:     "/ip/" + hostIP,
			})
		}
	}
	sort.SliceStable(observations, func(left, right int) bool {
		if severityWeight(observations[left].Severity) != severityWeight(observations[right].Severity) {
			return severityWeight(observations[left].Severity) > severityWeight(observations[right].Severity)
		}
		return observations[left].Label < observations[right].Label
	})
	return observations
}

func observationsFromCheckpointDelta(previous workspaceCheckpointState, current workspaceCheckpointState) []observationRecord {
	observations := make([]observationRecord, 0)
	for key, host := range current.hosts {
		if _, ok := previous.hosts[key]; !ok {
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "host",
				KindTone: "ok",
				HostIP:   host.IP,
				Label:    chooseString(host.DisplayName, host.IP),
				Detail:   chooseString(host.OS, "Host observed"),
				Href:     "/ip/" + host.IP,
			})
		}
	}
	for key, port := range current.ports {
		if _, ok := previous.ports[key]; !ok {
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "port",
				KindTone: "ok",
				HostIP:   port.HostIP,
				Port:     port.Port,
				Protocol: port.Protocol,
				Label:    port.Protocol + "/" + port.Port,
				Detail:   portFingerprint(port),
				Href:     "/ip/" + port.HostIP,
			})
		}
	}
	for key, finding := range current.findings {
		if _, ok := previous.findings[key]; !ok {
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "finding",
				KindTone: severityTone(finding.Severity),
				HostIP:   finding.HostIP,
				Label:    finding.Name,
				Detail:   finding.Target,
				Severity: finding.Severity,
				Href:     hostHref(finding.HostIP, current.hosts),
			})
		}
	}
	for key, route := range current.routes {
		if _, ok := previous.routes[key]; !ok {
			observations = append(observations, observationRecord{
				ID:       newWorkspaceID("obs"),
				Kind:     "route",
				KindTone: "accent",
				HostIP:   route.TargetIP,
				Label:    route.TargetLabel,
				Detail:   route.Path,
				Href:     hostHref(route.TargetIP, current.hosts),
			})
		}
	}
	return observations
}

func normalizeEventKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "scan import":
		return "Scan import"
	case "integration":
		return "Integration"
	case "baseline":
		return "Baseline"
	case "analyst":
		return "Analyst"
	case "campaign":
		return "Campaign"
	default:
		return chooseString(kind, "Event")
	}
}

func observationHostIPs(observations []observationRecord) []string {
	ips := make([]string, 0, len(observations))
	for _, observation := range observations {
		if observation.HostIP != "" {
			ips = append(ips, observation.HostIP)
		}
	}
	return uniqueStrings(ips)
}

func checkpointTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "n/a" {
		return newEventTimestamp()
	}
	return value
}

func newEventTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
