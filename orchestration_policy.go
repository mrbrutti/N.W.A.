package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type orchestrationPolicyRecord struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	CreatedAt   string                    `json:"created_at"`
	UpdatedAt   string                    `json:"updated_at"`
	Steps       []orchestrationStepRecord `json:"steps"`
}

type toolRequest struct {
	PluginID   string
	RawTargets []string
	HostIPs    []string
	Stage      string
	Summary    string
	Options    map[string]string
}

type orchestrationStepRecord struct {
	ID           string            `json:"id"`
	Label        string            `json:"label"`
	Trigger      string            `json:"trigger"`
	PluginID     string            `json:"plugin_id"`
	Stage        string            `json:"stage"`
	TargetSource string            `json:"target_source"`
	MatchKinds   []string          `json:"match_kinds,omitempty"`
	WhenPlugin   string            `json:"when_plugin,omitempty"`
	WhenProfile  string            `json:"when_profile,omitempty"`
	Summary      string            `json:"summary,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
	Enabled      bool              `json:"enabled"`
}

type OrchestrationPolicyView struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Active      bool                    `json:"active"`
	CreatedAt   string                  `json:"createdAt"`
	UpdatedAt   string                  `json:"updatedAt"`
	Steps       []OrchestrationStepView `json:"steps"`
}

type OrchestrationStepView struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Trigger      string   `json:"trigger"`
	PluginID     string   `json:"pluginId"`
	Stage        string   `json:"stage"`
	TargetSource string   `json:"targetSource"`
	MatchKinds   []string `json:"matchKinds"`
	WhenPlugin   string   `json:"whenPlugin"`
	WhenProfile  string   `json:"whenProfile"`
	Summary      string   `json:"summary"`
	Enabled      bool     `json:"enabled"`
}

func defaultOrchestrationPolicies() []orchestrationPolicyRecord {
	now := newEventTimestamp()
	return []orchestrationPolicyRecord{
		{
			ID:          "balanced-external",
			Name:        "Balanced external",
			Description: "Ping first, learn what is alive, then move to default TCP coverage. Domain scope expands through passive subdomain discovery before follow-up scanning.",
			CreatedAt:   now,
			UpdatedAt:   now,
			Steps: []orchestrationStepRecord{
				{
					ID:           "balanced-kickoff-net-ping",
					Label:        "Ping scoped networks and hosts",
					Trigger:      "kickoff",
					PluginID:     "nmap-enrich",
					Stage:        "discovery-ping",
					TargetSource: "chunk-values",
					MatchKinds:   []string{"ip", "cidr", "hostname"},
					Enabled:      true,
					Options:      map[string]string{"profile": "ping"},
				},
				{
					ID:           "balanced-kickoff-domain-subfinder",
					Label:        "Enumerate subdomains",
					Trigger:      "kickoff",
					PluginID:     "subfinder",
					Stage:        "subdomain-discovery",
					TargetSource: "chunk-values",
					MatchKinds:   []string{"domain"},
					Enabled:      true,
				},
				{
					ID:           "balanced-kickoff-domain-ping",
					Label:        "Ping declared domains",
					Trigger:      "kickoff",
					PluginID:     "nmap-enrich",
					Stage:        "discovery-ping",
					TargetSource: "chunk-values",
					MatchKinds:   []string{"domain"},
					Enabled:      true,
					Options:      map[string]string{"profile": "ping"},
				},
				{
					ID:           "balanced-after-subfinder-dnsx",
					Label:        "Resolve discovered subdomains",
					Trigger:      "after-job",
					PluginID:     "dnsx",
					Stage:        "subdomain-resolution",
					TargetSource: "derived-targets",
					WhenPlugin:   "subfinder",
					Enabled:      true,
				},
				{
					ID:           "balanced-after-subfinder-ping",
					Label:        "Ping discovered subdomains",
					Trigger:      "after-job",
					PluginID:     "nmap-enrich",
					Stage:        "subdomain-ping",
					TargetSource: "derived-targets",
					WhenPlugin:   "subfinder",
					Enabled:      true,
					Options:      map[string]string{"profile": "ping"},
				},
				{
					ID:           "balanced-after-ping-default",
					Label:        "Run default TCP scan on live hosts",
					Trigger:      "after-job",
					PluginID:     "nmap-enrich",
					Stage:        "default-ports",
					TargetSource: "live-hosts",
					WhenPlugin:   "nmap-enrich",
					WhenProfile:  "ping",
					Enabled:      true,
					Options:      map[string]string{"profile": "default"},
				},
			},
		},
		{
			ID:          "discovery-only",
			Name:        "Discovery only",
			Description: "Keep kickoff quiet. Only determine what responds and what names resolve. Leave deeper coverage to the operator.",
			CreatedAt:   now,
			UpdatedAt:   now,
			Steps: []orchestrationStepRecord{
				{
					ID:           "discovery-net-ping",
					Label:        "Ping scoped networks and hosts",
					Trigger:      "kickoff",
					PluginID:     "nmap-enrich",
					Stage:        "discovery-ping",
					TargetSource: "chunk-values",
					MatchKinds:   []string{"ip", "cidr", "hostname", "domain"},
					Enabled:      true,
					Options:      map[string]string{"profile": "ping"},
				},
				{
					ID:           "discovery-domain-subfinder",
					Label:        "Enumerate subdomains",
					Trigger:      "kickoff",
					PluginID:     "subfinder",
					Stage:        "subdomain-discovery",
					TargetSource: "chunk-values",
					MatchKinds:   []string{"domain"},
					Enabled:      true,
				},
				{
					ID:           "discovery-after-subfinder-dnsx",
					Label:        "Resolve discovered subdomains",
					Trigger:      "after-job",
					PluginID:     "dnsx",
					Stage:        "subdomain-resolution",
					TargetSource: "derived-targets",
					WhenPlugin:   "subfinder",
					Enabled:      true,
				},
			},
		},
	}
}

func normalizePolicies(preferences workspacePreferences) workspacePreferences {
	if len(preferences.Policies) == 0 {
		preferences.Policies = defaultOrchestrationPolicies()
	}

	seen := map[string]struct{}{}
	for index := range preferences.Policies {
		policy := &preferences.Policies[index]
		if strings.TrimSpace(policy.ID) == "" {
			policy.ID = fmt.Sprintf("policy-%d", index+1)
		}
		if _, ok := seen[policy.ID]; ok {
			policy.ID = fmt.Sprintf("%s-%d", policy.ID, index+1)
		}
		seen[policy.ID] = struct{}{}
		if strings.TrimSpace(policy.CreatedAt) == "" {
			policy.CreatedAt = newEventTimestamp()
		}
		if strings.TrimSpace(policy.UpdatedAt) == "" {
			policy.UpdatedAt = policy.CreatedAt
		}
		for stepIndex := range policy.Steps {
			step := &policy.Steps[stepIndex]
			if strings.TrimSpace(step.ID) == "" {
				step.ID = fmt.Sprintf("%s-step-%d", policy.ID, stepIndex+1)
			}
			if strings.TrimSpace(step.Label) == "" {
				step.Label = humanizePolicyPlugin(step.PluginID)
			}
			step.Trigger = normalizePolicyTrigger(step.Trigger)
			step.TargetSource = normalizePolicyTargetSource(step.TargetSource)
			step.MatchKinds = normalizePolicyKinds(step.MatchKinds)
			if !step.Enabled {
				step.Enabled = step.Enabled || step.Trigger != ""
			}
		}
	}

	if strings.TrimSpace(preferences.ActivePolicyID) == "" || !policyExists(preferences.Policies, preferences.ActivePolicyID) {
		preferences.ActivePolicyID = preferences.Policies[0].ID
	}
	return preferences
}

func normalizePolicyTrigger(value string) string {
	switch strings.TrimSpace(value) {
	case "after-job":
		return "after-job"
	default:
		return "kickoff"
	}
}

func normalizePolicyTargetSource(value string) string {
	switch strings.TrimSpace(value) {
	case "live-hosts", "derived-targets":
		return value
	default:
		return "chunk-values"
	}
}

func normalizePolicyKinds(values []string) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		switch strings.TrimSpace(strings.ToLower(value)) {
		case "ip", "cidr", "domain", "hostname":
			items = append(items, strings.TrimSpace(strings.ToLower(value)))
		}
	}
	sort.Strings(items)
	return uniqueStrings(items)
}

func policyExists(policies []orchestrationPolicyRecord, id string) bool {
	for _, policy := range policies {
		if policy.ID == strings.TrimSpace(id) {
			return true
		}
	}
	return false
}

func humanizePolicyPlugin(pluginID string) string {
	switch strings.TrimSpace(pluginID) {
	case "nmap-enrich":
		return "Nmap"
	case "subfinder":
		return "Subfinder"
	case "dnsx":
		return "DNSX"
	case "naabu":
		return "Naabu"
	case "httpx":
		return "HTTPX"
	case "katana":
		return "Katana"
	case "nuclei":
		return "Nuclei"
	case "nikto":
		return "Nikto"
	case "sqlmap":
		return "SQLMap"
	default:
		return strings.TrimSpace(pluginID)
	}
}

func policyKindsFromInput(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	return normalizePolicyKinds(fields)
}

func (w *workspace) orchestrationPolicies() []OrchestrationPolicyView {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.orchestrationPoliciesLocked()
}

func (w *workspace) orchestrationPoliciesLocked() []OrchestrationPolicyView {
	preferences := normalizePolicies(w.preferencesState)
	items := make([]OrchestrationPolicyView, 0, len(preferences.Policies))
	for _, policy := range preferences.Policies {
		view := OrchestrationPolicyView{
			ID:          policy.ID,
			Name:        policy.Name,
			Description: policy.Description,
			Active:      policy.ID == preferences.ActivePolicyID,
			CreatedAt:   displayTimestamp(policy.CreatedAt),
			UpdatedAt:   displayTimestamp(policy.UpdatedAt),
			Steps:       make([]OrchestrationStepView, 0, len(policy.Steps)),
		}
		for _, step := range policy.Steps {
			view.Steps = append(view.Steps, OrchestrationStepView{
				ID:           step.ID,
				Label:        step.Label,
				Trigger:      step.Trigger,
				PluginID:     step.PluginID,
				Stage:        step.Stage,
				TargetSource: step.TargetSource,
				MatchKinds:   append([]string(nil), step.MatchKinds...),
				WhenPlugin:   step.WhenPlugin,
				WhenProfile:  step.WhenProfile,
				Summary:      step.Summary,
				Enabled:      step.Enabled,
			})
		}
		items = append(items, view)
	}
	return items
}

func (w *workspace) activeOrchestrationPolicyLocked() orchestrationPolicyRecord {
	preferences := normalizePolicies(w.preferencesState)
	for _, policy := range preferences.Policies {
		if policy.ID == preferences.ActivePolicyID {
			return policy
		}
	}
	return preferences.Policies[0]
}

func (w *workspace) setActivePolicy(policyID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	preferences := normalizePolicies(w.preferencesState)
	if !policyExists(preferences.Policies, policyID) {
		return fmt.Errorf("policy %s was not found", policyID)
	}
	preferences.ActivePolicyID = policyID
	w.preferencesState = preferences
	return w.store.savePreferences(preferences)
}

func (w *workspace) addPolicyStep(policyID string, step orchestrationStepRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	preferences := normalizePolicies(w.preferencesState)
	for index := range preferences.Policies {
		if preferences.Policies[index].ID != policyID {
			continue
		}
		step.ID = newWorkspaceID("policy-step")
		step.Trigger = normalizePolicyTrigger(step.Trigger)
		step.TargetSource = normalizePolicyTargetSource(step.TargetSource)
		step.MatchKinds = normalizePolicyKinds(step.MatchKinds)
		if strings.TrimSpace(step.Label) == "" {
			step.Label = humanizePolicyPlugin(step.PluginID)
		}
		step.Enabled = true
		preferences.Policies[index].Steps = append(preferences.Policies[index].Steps, step)
		preferences.Policies[index].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		w.preferencesState = preferences
		return w.store.savePreferences(preferences)
	}
	return fmt.Errorf("policy %s was not found", policyID)
}

func (w *workspace) reorderPolicySteps(policyID string, orderedIDs []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	preferences := normalizePolicies(w.preferencesState)
	for index := range preferences.Policies {
		if preferences.Policies[index].ID != policyID {
			continue
		}
		policy := &preferences.Policies[index]
		byID := map[string]orchestrationStepRecord{}
		for _, step := range policy.Steps {
			byID[step.ID] = step
		}
		reordered := make([]orchestrationStepRecord, 0, len(policy.Steps))
		for _, id := range orderedIDs {
			if step, ok := byID[strings.TrimSpace(id)]; ok {
				reordered = append(reordered, step)
				delete(byID, strings.TrimSpace(id))
			}
		}
		for _, step := range policy.Steps {
			if _, ok := byID[step.ID]; ok {
				reordered = append(reordered, step)
			}
		}
		policy.Steps = reordered
		policy.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		w.preferencesState = preferences
		return w.store.savePreferences(preferences)
	}
	return fmt.Errorf("policy %s was not found", policyID)
}

func (w *workspace) removePolicyStep(policyID string, stepID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	preferences := normalizePolicies(w.preferencesState)
	for index := range preferences.Policies {
		if preferences.Policies[index].ID != policyID {
			continue
		}
		steps := make([]orchestrationStepRecord, 0, len(preferences.Policies[index].Steps))
		removed := false
		for _, step := range preferences.Policies[index].Steps {
			if step.ID == stepID {
				removed = true
				continue
			}
			steps = append(steps, step)
		}
		if !removed {
			return fmt.Errorf("step %s was not found", stepID)
		}
		preferences.Policies[index].Steps = steps
		preferences.Policies[index].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		w.preferencesState = preferences
		return w.store.savePreferences(preferences)
	}
	return fmt.Errorf("policy %s was not found", policyID)
}

func (w *workspace) kickoffToolRequestsLocked(chunk targetChunkRecord) []toolRequest {
	policy := w.activeOrchestrationPolicyLocked()
	return w.requestsForPolicyTriggerLocked(policy, chunk, nil, "kickoff")
}

func (w *workspace) followUpSubmissionsLocked(chunk targetChunkRecord, job *pluginJob) []toolRequest {
	if job == nil || job.Status != jobCompleted {
		return nil
	}
	policy := w.activeOrchestrationPolicyLocked()
	return w.requestsForPolicyTriggerLocked(policy, chunk, job, "after-job")
}

func (w *workspace) requestsForPolicyTriggerLocked(policy orchestrationPolicyRecord, chunk targetChunkRecord, job *pluginJob, trigger string) []toolRequest {
	items := make([]toolRequest, 0)
	for _, step := range policy.Steps {
		if !step.Enabled || normalizePolicyTrigger(step.Trigger) != trigger {
			continue
		}
		if trigger == "kickoff" && !policyStepMatchesChunk(step, chunk) {
			continue
		}
		if trigger == "after-job" && !policyStepMatchesJob(step, job) {
			continue
		}

		request := w.toolRequestForPolicyStepLocked(chunk, job, step)
		if len(request.RawTargets) == 0 && len(request.HostIPs) == 0 {
			continue
		}
		if w.chunkHasJobStageLocked(chunk, request.PluginID, request.Stage) {
			continue
		}
		items = append(items, request)
	}
	return items
}

func policyStepMatchesChunk(step orchestrationStepRecord, chunk targetChunkRecord) bool {
	if len(step.MatchKinds) == 0 {
		return true
	}
	for _, kind := range step.MatchKinds {
		if kind == strings.TrimSpace(strings.ToLower(chunk.Kind)) {
			return true
		}
	}
	return false
}

func policyStepMatchesJob(step orchestrationStepRecord, job *pluginJob) bool {
	if job == nil {
		return false
	}
	if strings.TrimSpace(step.WhenPlugin) != "" && step.WhenPlugin != strings.TrimSpace(job.PluginID) {
		return false
	}
	if strings.TrimSpace(step.WhenProfile) != "" && step.WhenProfile != strings.TrimSpace(job.Options["profile"]) {
		return false
	}
	return true
}

func (w *workspace) toolRequestForPolicyStepLocked(chunk targetChunkRecord, job *pluginJob, step orchestrationStepRecord) toolRequest {
	rawTargets, hostIPs := w.policyTargetsForStepLocked(chunk, job, step)
	summary := strings.TrimSpace(step.Summary)
	if summary == "" {
		summary = fmt.Sprintf("%s · %s", step.Label, chunk.Name)
	}
	return toolRequest{
		PluginID:   step.PluginID,
		RawTargets: rawTargets,
		HostIPs:    hostIPs,
		Stage:      strings.TrimSpace(step.Stage),
		Summary:    summary,
		Options:    cloneStringMap(step.Options),
	}
}

func (w *workspace) policyTargetsForStepLocked(chunk targetChunkRecord, job *pluginJob, step orchestrationStepRecord) ([]string, []string) {
	switch normalizePolicyTargetSource(step.TargetSource) {
	case "derived-targets":
		targets := uniqueStrings(job.DerivedTargets)
		return targets, w.resolveKnownHostsLocked(targets)
	case "live-hosts":
		targets := w.liveHostTargetsForChunkLocked(chunk, job)
		return targets, targets
	default:
		targets := uniqueStrings(append([]string(nil), chunk.Values...))
		return targets, chunkResolvedHostIPs(chunk)
	}
}

func (w *workspace) resolveKnownHostsLocked(rawTargets []string) []string {
	if w.snapshot == nil {
		return nil
	}
	results := make([]string, 0, len(rawTargets))
	for _, candidate := range rawTargets {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		for _, record := range w.snapshot.records {
			if record.summary.IP == candidate {
				results = append(results, candidate)
				break
			}
			if strings.EqualFold(record.summary.DisplayName, candidate) || slicesContains(record.summary.Hostnames, candidate) {
				results = append(results, record.summary.IP)
				break
			}
		}
	}
	return uniqueStrings(results)
}

func (w *workspace) chunkHasJobStageLocked(chunk targetChunkRecord, pluginID string, stage string) bool {
	if w.plugins == nil {
		return false
	}
	for _, runID := range chunk.RunIDs {
		job, ok := w.plugins.jobByID(runID)
		if !ok || job == nil {
			continue
		}
		if job.PluginID == pluginID && strings.EqualFold(strings.TrimSpace(job.Stage), strings.TrimSpace(stage)) {
			return true
		}
	}
	return false
}

func (w *workspace) liveHostTargetsForChunkLocked(chunk targetChunkRecord, job *pluginJob) []string {
	snapshot := w.snapshot
	if snapshot == nil {
		return nil
	}

	targets := append([]string(nil), chunk.Values...)
	if job != nil && len(job.RawTargets) > 0 {
		targets = append(targets, job.RawTargets...)
	}
	targets = uniqueStrings(targets)
	if len(targets) == 0 {
		return nil
	}

	results := make([]string, 0)
	for _, record := range snapshot.records {
		for _, target := range targets {
			if snapshotRecordMatchesTarget(record, target) {
				results = append(results, record.summary.IP)
				break
			}
		}
	}
	sort.Strings(results)
	return uniqueStrings(results)
}

func snapshotRecordMatchesTarget(record hostRecord, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		return record.summary.IP == addr.String()
	}
	if prefix, err := netip.ParsePrefix(target); err == nil {
		if record.ipAddr.IsValid() {
			return prefix.Contains(record.ipAddr)
		}
		return false
	}

	normalized := strings.Trim(strings.ToLower(target), ".")
	if normalized == "" {
		return false
	}
	if strings.EqualFold(record.summary.DisplayName, normalized) {
		return true
	}
	for _, hostname := range record.summary.Hostnames {
		if strings.EqualFold(strings.Trim(hostname, "."), normalized) {
			return true
		}
	}
	return false
}
