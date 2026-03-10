package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mergeSnapshotFixture = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -sC -O --traceroute" start="1710001000" startstr="Mon Mar  1 10:10:00 2026" version="7.95" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="2" services="22,443"/>
  <verbose level="1"/>
  <debugging level="0"/>
  <host starttime="1710001001" endtime="1710001002">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="alpha-secondary.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="nginx" version="1.24"/>
        <script id="http-title" output="alpha secure portal"/>
      </port>
    </ports>
    <distance value="3"/>
    <os>
      <osmatch name="Linux 6.x" accuracy="99" line="1">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="99"/>
      </osmatch>
    </os>
    <trace port="443" proto="tcp">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="1.10"/>
      <hop ttl="2" ipaddr="10.0.0.5" rtt="1.90"/>
    </trace>
  </host>
</nmaprun>`

func TestWorkspaceImportsAndMergesScans(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	mergePath := filepath.Join(t.TempDir(), "merge.xml")
	if err := os.WriteFile(mergePath, []byte(mergeSnapshotFixture), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(t.TempDir(), []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if _, err := workspace.importScanFromPath(mergePath, "test", "merge.xml"); err != nil {
		t.Fatalf("importScanFromPath() error = %v", err)
	}

	snapshot := workspace.currentSnapshot()
	host, ok := snapshot.host("10.0.0.5")
	if !ok {
		t.Fatalf("merged host 10.0.0.5 not found")
	}
	if snapshot.meta.ScanCount != 2 {
		t.Fatalf("ScanCount = %d, want 2", snapshot.meta.ScanCount)
	}
	if host.OpenPortCount != 2 {
		t.Fatalf("OpenPortCount = %d, want 2", host.OpenPortCount)
	}
	if !host.Coverage.HasScripts || !host.Coverage.HasTrace {
		t.Fatalf("coverage = %#v, want scripts and trace after merge", host.Coverage)
	}
	if len(host.SourceScans) != 2 {
		t.Fatalf("SourceScans = %#v, want 2 entries", host.SourceScans)
	}
}

func TestApplyPluginResultAddsNucleiFindings(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(t.TempDir(), []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	job := &pluginJob{ID: "job-1", PluginID: "nuclei", PluginLabel: "Nuclei HTTP Enrichment"}
	result := PluginRunResult{
		NucleiFindings: map[string][]storedNucleiFinding{
			"10.0.0.9": {{
				TemplateID: "http-missing-header",
				Name:       "Missing security header",
				Severity:   "medium",
				Target:     "http://10.0.0.9",
				MatchedAt:  "http://10.0.0.9",
				Type:       "http",
			}},
		},
		Findings: FindingSummary{Total: 1, Medium: 1},
	}
	if err := workspace.applyPluginResult(job, result); err != nil {
		t.Fatalf("applyPluginResult() error = %v", err)
	}

	host, ok := workspace.currentSnapshot().host("10.0.0.9")
	if !ok {
		t.Fatalf("host not found after plugin apply")
	}
	if host.Findings.Total != 1 {
		t.Fatalf("Findings.Total = %d, want 1", host.Findings.Total)
	}
	if len(host.NucleiFindings) != 1 {
		t.Fatalf("NucleiFindings = %d, want 1", len(host.NucleiFindings))
	}
	if host.NucleiFindings[0].Severity != "medium" {
		t.Fatalf("Severity = %q, want medium", host.NucleiFindings[0].Severity)
	}
}

func TestParseNucleiJSONLMapsURLsToHostIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	payload := `{"template-id":"test-template","host":"http://10.0.0.9","matched-at":"http://10.0.0.9/login","type":"http","info":{"name":"Test template","severity":"high","description":"desc","tags":["web"]}}` + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	findings, summary, err := parseNucleiJSONL(path)
	if err != nil {
		t.Fatalf("parseNucleiJSONL() error = %v", err)
	}
	if summary.Total != 1 || summary.High != 1 {
		t.Fatalf("summary = %#v, want 1 high finding", summary)
	}
	if len(findings["10.0.0.9"]) != 1 {
		t.Fatalf("findings for host = %#v, want single mapped result", findings)
	}
}

func TestWorkspaceHistoryTracksScanAndIntegrationDiffs(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	mergePath := filepath.Join(t.TempDir(), "merge.xml")
	if err := os.WriteFile(mergePath, []byte(mergeSnapshotFixture), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(t.TempDir(), []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if _, err := workspace.importScanFromPath(mergePath, "test", "merge.xml"); err != nil {
		t.Fatalf("importScanFromPath() error = %v", err)
	}

	jobID := "job-history"
	runDir := filepath.Join(workspace.artifactRoot(), jobID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	findingsPath := filepath.Join(runDir, "findings.jsonl")
	payload := `{"template-id":"test-template","host":"http://10.0.0.9","matched-at":"http://10.0.0.9/login","type":"http","info":{"name":"Test template","severity":"high","description":"desc","tags":["web"]}}` + "\n"
	if err := os.WriteFile(findingsPath, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	job := &pluginJob{
		ID:          jobID,
		PluginID:    "nuclei",
		PluginLabel: "Nuclei HTTP Enrichment",
		Status:      jobCompleted,
		FinishedAt:  "2026-03-01T10:30:00Z",
		Artifacts:   []jobArtifact{{Label: "Findings", RelPath: filepath.Join(jobID, "findings.jsonl")}},
	}
	workspace.plugins.mu.Lock()
	workspace.plugins.jobs[jobID] = job
	workspace.plugins.mu.Unlock()

	result := PluginRunResult{
		NucleiFindings: map[string][]storedNucleiFinding{
			"10.0.0.9": {{
				TemplateID: "test-template",
				Name:       "Test template",
				Severity:   "high",
				Target:     "http://10.0.0.9/login",
				MatchedAt:  "http://10.0.0.9/login",
				Type:       "http",
			}},
		},
		Findings: FindingSummary{Total: 1, High: 1},
	}
	if err := workspace.applyPluginResult(job, result); err != nil {
		t.Fatalf("applyPluginResult() error = %v", err)
	}
	workspace.refreshHistory()

	diff, compare, checkpoints, ok := workspace.changeComparison("baseline", "")
	if !ok {
		t.Fatalf("changeComparison() reported no history")
	}
	if compare.ToID == "baseline" {
		t.Fatalf("comparison selected baseline as latest checkpoint")
	}
	if len(checkpoints) < 4 {
		t.Fatalf("checkpoints = %d, want baseline + scan + merge + integration", len(checkpoints))
	}
	if diff.Summary.PortsOpened == 0 {
		t.Fatalf("PortsOpened = %d, want non-zero after merge scan", diff.Summary.PortsOpened)
	}
	if diff.Summary.FindingsAdded != 1 {
		t.Fatalf("FindingsAdded = %d, want 1", diff.Summary.FindingsAdded)
	}
	if len(diff.AddedFindings) != 1 || diff.AddedFindings[0].HostIP != "10.0.0.9" {
		t.Fatalf("AddedFindings = %#v, want mapped nuclei finding", diff.AddedFindings)
	}
	foundIntegration := false
	for _, checkpoint := range checkpoints {
		if checkpoint.Kind == "Integration" && strings.Contains(checkpoint.Summary, "findings") {
			foundIntegration = true
			break
		}
	}
	if !foundIntegration {
		t.Fatalf("checkpoints = %#v, want integration checkpoint", checkpoints)
	}
}

func TestWorkspaceSaveViewPersistsAndEmitsObservation(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	workspace, err := openWorkspace(root, []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	view, err := workspace.saveView("Web review", HostFilter{
		Query:    "http",
		Scope:    "service",
		Sort:     "ip",
		Page:     1,
		PageSize: 100,
	})
	if err != nil {
		t.Fatalf("saveView() error = %v", err)
	}
	if !strings.Contains(view.Href, "query=http") {
		t.Fatalf("view.Href = %q, want query parameter", view.Href)
	}

	reloaded, err := openWorkspace(root, nil, logger)
	if err != nil {
		t.Fatalf("re-open workspace error = %v", err)
	}

	views := reloaded.savedViewCatalog()
	if len(views) != 1 || views[0].Name != "Web review" {
		t.Fatalf("savedViewCatalog() = %#v, want persisted view", views)
	}

	observations := reloaded.recentObservations(8)
	foundView := false
	for _, observation := range observations {
		if observation.Kind == "view" && observation.Label == "Web review" {
			foundView = true
			break
		}
	}
	if !foundView {
		t.Fatalf("recentObservations() = %#v, want saved view observation", observations)
	}
}

func TestWorkspaceAnnotateHostPersistsTagsNotesAndObservations(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	workspace, err := openWorkspace(root, []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	if err := workspace.annotateHost("10.0.0.9", []string{"mail", "critical"}, "Confirmed external mail path"); err != nil {
		t.Fatalf("annotateHost() error = %v", err)
	}

	host, ok := workspace.currentSnapshot().host("10.0.0.9")
	if !ok {
		t.Fatalf("host not found after annotateHost()")
	}
	if len(host.Tags) != 2 {
		t.Fatalf("Tags = %#v, want 2 tags", host.Tags)
	}
	if len(host.Notes) != 1 || !strings.Contains(host.Notes[0].Text, "mail path") {
		t.Fatalf("Notes = %#v, want persisted analyst note", host.Notes)
	}

	observations := workspace.hostObservations("10.0.0.9", 12)
	foundTag := false
	foundNote := false
	for _, observation := range observations {
		if observation.Kind == "tag" {
			foundTag = true
		}
		if observation.Kind == "note" {
			foundNote = true
		}
	}
	if !foundTag || !foundNote {
		t.Fatalf("hostObservations() = %#v, want tag and note entries", observations)
	}

	reloaded, err := openWorkspace(root, nil, logger)
	if err != nil {
		t.Fatalf("re-open workspace error = %v", err)
	}
	reloadedHost, ok := reloaded.currentSnapshot().host("10.0.0.9")
	if !ok {
		t.Fatalf("reloaded host missing")
	}
	if len(reloadedHost.Tags) != 2 || len(reloadedHost.Notes) != 1 {
		t.Fatalf("reloaded host = %#v, want persisted annotations", reloadedHost)
	}
}

func TestCreateCampaignTargetsDiffScopeAndRecordsLedgerEvent(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	mergePath := filepath.Join(t.TempDir(), "merge.xml")
	if err := os.WriteFile(mergePath, []byte(mergeSnapshotFixture), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(root, []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if _, err := workspace.importScanFromPath(mergePath, "test", "merge.xml"); err != nil {
		t.Fatalf("importScanFromPath() error = %v", err)
	}

	workspace.plugins = &pluginManager{
		logger:    logger,
		store:     workspace.store,
		workspace: workspace,
		queue:     make(chan string, 8),
		plugins: map[string]plugin{
			"nmap-enrich": &nmapEnrichmentPlugin{},
			"nuclei":      &nucleiPlugin{},
		},
		jobs: map[string]*pluginJob{},
	}

	checkpoints := workspace.currentHistory().meta()
	if len(checkpoints) < 3 {
		t.Fatalf("checkpoints = %#v, want baseline + two imports", checkpoints)
	}

	campaign, err := workspace.createCampaign("Opened port follow-up", "nmap-enrich", "opened-ports", checkpoints[1].ID, checkpoints[2].ID, map[string]string{
		"profile": "safe",
	})
	if err != nil {
		t.Fatalf("createCampaign() error = %v", err)
	}
	if campaign.TargetCount != 1 {
		t.Fatalf("TargetCount = %d, want 1 host for opened-port diff", campaign.TargetCount)
	}
	if campaign.Status != jobQueued {
		t.Fatalf("Status = %q, want queued", campaign.Status)
	}

	campaigns := workspace.campaignCatalog()
	if len(campaigns) != 1 || campaigns[0].Name != "Opened port follow-up" {
		t.Fatalf("campaignCatalog() = %#v, want saved campaign", campaigns)
	}

	observations := workspace.recentObservations(10)
	foundCampaign := false
	for _, observation := range observations {
		if observation.Kind == "campaign" && observation.Label == "Opened port follow-up" {
			foundCampaign = true
			break
		}
	}
	if !foundCampaign {
		t.Fatalf("recentObservations() = %#v, want campaign observation", observations)
	}
}

func TestLatestChangeSkipsNonInventoryAnalystEvents(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	workspace, err := openWorkspace(t.TempDir(), []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if _, err := workspace.saveView("Mail hosts", HostFilter{
		Query:    "smtp",
		Scope:    "service",
		Sort:     "ip",
		Page:     1,
		PageSize: 50,
	}); err != nil {
		t.Fatalf("saveView() error = %v", err)
	}

	diff, ok := workspace.latestChange()
	if !ok {
		t.Fatalf("latestChange() reported no diff")
	}
	if diff.Summary.PortsOpened == 0 {
		t.Fatalf("latestChange() = %#v, want inventory delta rather than zero-diff analyst event", diff)
	}
}

func TestProfileTargetsResolveWorkspaceSlices(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	workspace, err := openWorkspace(t.TempDir(), []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	rawTargets, hostIPs, summary := workspace.profileTargets("nuclei", "web")
	if len(hostIPs) != 1 || hostIPs[0] != "10.0.0.9" {
		t.Fatalf("profileTargets(web) hostIPs = %#v, want only HTTP host", hostIPs)
	}
	if len(rawTargets) != 1 || rawTargets[0] != "http://10.0.0.9" {
		t.Fatalf("profileTargets(web) rawTargets = %#v, want inferred HTTP target", rawTargets)
	}
	if !strings.Contains(summary, "web") {
		t.Fatalf("profileTargets(web) summary = %q, want profile label", summary)
	}

	rawTargets, hostIPs, summary = workspace.profileTargets("nikto", "web")
	if len(hostIPs) != 1 || hostIPs[0] != "10.0.0.9" {
		t.Fatalf("profileTargets(nikto/web) hostIPs = %#v, want only HTTP host", hostIPs)
	}
	if len(rawTargets) != 1 || rawTargets[0] != "http://10.0.0.9" {
		t.Fatalf("profileTargets(nikto/web) rawTargets = %#v, want inferred HTTP target", rawTargets)
	}
	if !strings.Contains(summary, "web") {
		t.Fatalf("profileTargets(nikto/web) summary = %q, want profile label", summary)
	}

	rawTargets, hostIPs, _ = workspace.profileTargets("nmap-enrich", "coverage-gap")
	if len(hostIPs) != 2 {
		t.Fatalf("profileTargets(coverage-gap) hostIPs = %#v, want both fixture hosts", hostIPs)
	}
	if len(rawTargets) != 2 {
		t.Fatalf("profileTargets(coverage-gap) rawTargets = %#v, want host IP targets", rawTargets)
	}

	rawTargets, hostIPs, summary = workspace.profileTargets("nmap-enrich", "all-hosts")
	if len(hostIPs) != 2 || len(rawTargets) != 2 {
		t.Fatalf("profileTargets(all-hosts) rawTargets = %#v hostIPs = %#v, want full host slice", rawTargets, hostIPs)
	}
	if !strings.Contains(summary, "all hosts") && !strings.Contains(summary, "all-hosts") {
		t.Fatalf("profileTargets(all-hosts) summary = %q, want all-hosts label", summary)
	}

	if _, err := workspace.ingestScope("Domains", "corp.example.com\nvpn.example.com", "test", false); err != nil {
		t.Fatalf("ingestScope(domains) error = %v", err)
	}
	rawTargets, hostIPs, summary = workspace.profileTargets("subfinder", "domains")
	if len(hostIPs) != 0 {
		t.Fatalf("profileTargets(domains) hostIPs = %#v, want no resolved host IPs for passive domain scope", hostIPs)
	}
	if len(rawTargets) != 2 || rawTargets[0] != "corp.example.com" || rawTargets[1] != "vpn.example.com" {
		t.Fatalf("profileTargets(domains) rawTargets = %#v, want declared domain scope", rawTargets)
	}
	if !strings.Contains(summary, "domains") {
		t.Fatalf("profileTargets(domains) summary = %q, want domains label", summary)
	}
}

func TestWorkspacePolicyChangesPersist(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	workspace, err := openWorkspace(root, []string{basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	policies := workspace.orchestrationPolicies()
	if len(policies) < 2 {
		t.Fatalf("orchestrationPolicies() = %#v, want built-in policy library", policies)
	}
	if err := workspace.setActivePolicy("discovery-only"); err != nil {
		t.Fatalf("setActivePolicy() error = %v", err)
	}
	if err := workspace.addPolicyStep("discovery-only", orchestrationStepRecord{
		Label:        "HTTP census after discovery",
		Trigger:      "after-job",
		PluginID:     "httpx",
		Stage:        "http-census",
		TargetSource: "live-hosts",
		WhenPlugin:   "nmap-enrich",
		WhenProfile:  "default",
	}); err != nil {
		t.Fatalf("addPolicyStep() error = %v", err)
	}

	reloaded, err := openWorkspace(root, nil, logger)
	if err != nil {
		t.Fatalf("re-open workspace error = %v", err)
	}
	policies = reloaded.orchestrationPolicies()
	activeFound := false
	stepFound := false
	for _, policy := range policies {
		if policy.ID == "discovery-only" {
			if !policy.Active {
				t.Fatalf("discovery-only policy = %#v, want active after reload", policy)
			}
			activeFound = true
			for _, step := range policy.Steps {
				if step.Label == "HTTP census after discovery" && step.PluginID == "httpx" {
					stepFound = true
				}
			}
		}
	}
	if !activeFound || !stepFound {
		t.Fatalf("reloaded policies = %#v, want active policy and appended step", policies)
	}
}

func TestOpenWorkspaceSkipsInvalidSeedFilesWhenOthersImport(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	invalidPath := filepath.Join(t.TempDir(), "broken.xml")
	if err := os.WriteFile(invalidPath, []byte("<nmaprun><host>"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(t.TempDir(), []string{invalidPath, basePath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	status := workspace.workspaceStatus()
	if status.ScanCount != 1 {
		t.Fatalf("ScanCount = %d, want 1 valid imported scan", status.ScanCount)
	}
	if _, ok := workspace.currentSnapshot().host("10.0.0.5"); !ok {
		t.Fatalf("valid seed file was not imported after skipping broken XML")
	}
}

func TestOpenWorkspaceFailsWhenAllSeedFilesAreInvalid(t *testing.T) {
	invalidPath := filepath.Join(t.TempDir(), "broken.xml")
	if err := os.WriteFile(invalidPath, []byte("<nmaprun><host>"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := openWorkspace(t.TempDir(), []string{invalidPath}, logger)
	if err == nil {
		t.Fatal("openWorkspace() error = nil, want failure when every seed file is invalid")
	}
	if !strings.Contains(err.Error(), "broken.xml") {
		t.Fatalf("error = %q, want failing file path in message", err)
	}
}

func TestOpenWorkspaceRecoversHostsFromTruncatedSeedFile(t *testing.T) {
	basePath := writeSnapshotFixture(t)
	payload, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	truncated := string(payload)
	cut := strings.Index(truncated, `<host starttime="1710000003"`)
	if cut <= 0 {
		t.Fatal("failed to derive truncated seed fixture")
	}
	truncated = truncated[:cut] + `<host starttime="1710000003"><status state="up"`

	truncatedPath := filepath.Join(t.TempDir(), "truncated.xml")
	if err := os.WriteFile(truncatedPath, []byte(truncated), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(t.TempDir(), []string{truncatedPath}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	if workspace.workspaceStatus().ScanCount != 1 {
		t.Fatalf("ScanCount = %d, want recovered partial seed imported", workspace.workspaceStatus().ScanCount)
	}
	snapshot := workspace.currentSnapshot()
	if _, ok := snapshot.host("10.0.0.5"); !ok {
		t.Fatalf("recovered host 10.0.0.5 missing from snapshot")
	}
	if _, ok := snapshot.host("10.0.0.9"); ok {
		t.Fatalf("incomplete trailing host should not have been imported")
	}
}

func TestOpenWorkspaceImportsSupportedFilesFromDirectorySources(t *testing.T) {
	importDir := filepath.Join(t.TempDir(), "imports")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	xmlPath := filepath.Join(importDir, "seed.xml")
	if err := os.WriteFile(xmlPath, []byte(snapshotFixture), 0o600); err != nil {
		t.Fatalf("WriteFile(seed.xml) error = %v", err)
	}
	nessusPath := filepath.Join(importDir, "seed.nessus")
	if err := os.WriteFile(nessusPath, []byte(nessusFixture), 0o600); err != nil {
		t.Fatalf("WriteFile(seed.nessus) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(importDir, "notes.md"), []byte("ignore me"), 0o600); err != nil {
		t.Fatalf("WriteFile(notes.md) error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(t.TempDir(), []string{importDir}, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}

	if workspace.workspaceStatus().ScanCount != 2 {
		t.Fatalf("ScanCount = %d, want 2 imported sources from directory walk", workspace.workspaceStatus().ScanCount)
	}
	snapshot := workspace.currentSnapshot()
	if _, ok := snapshot.host("10.0.0.5"); !ok {
		t.Fatalf("expected XML host 10.0.0.5 from directory import")
	}
	if _, ok := snapshot.host("10.0.0.44"); !ok {
		t.Fatalf("expected Nessus host 10.0.0.44 from directory import")
	}
}
