package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"nwa/nmap"
)

const (
	jobQueued    = "queued"
	jobRunning   = "running"
	jobCompleted = "completed"
	jobFailed    = "failed"
)

type jobArtifact struct {
	Label   string `json:"label"`
	RelPath string `json:"rel_path"`
}

type pluginJob struct {
	ID             string            `json:"id"`
	PluginID       string            `json:"plugin_id"`
	PluginLabel    string            `json:"plugin_label"`
	PluginKind     string            `json:"plugin_kind,omitempty"`
	SafetyClass    string            `json:"safety_class,omitempty"`
	CostProfile    string            `json:"cost_profile,omitempty"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	Status         string            `json:"status"`
	TargetSummary  string            `json:"target_summary"`
	TargetCount    int               `json:"target_count"`
	RawTargets     []string          `json:"raw_targets"`
	HostIPs        []string          `json:"host_ips"`
	CampaignID     string            `json:"campaign_id,omitempty"`
	ChunkID        string            `json:"chunk_id,omitempty"`
	Stage          string            `json:"stage,omitempty"`
	WorkerMode     string            `json:"worker_mode,omitempty"`
	WorkerID       string            `json:"worker_id,omitempty"`
	WorkerZone     string            `json:"worker_zone,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	CreatedAt      string            `json:"created_at"`
	StartedAt      string            `json:"started_at,omitempty"`
	FinishedAt     string            `json:"finished_at,omitempty"`
	Summary        string            `json:"summary,omitempty"`
	Error          string            `json:"error,omitempty"`
	Artifacts      []jobArtifact     `json:"artifacts,omitempty"`
	Findings       FindingSummary    `json:"findings,omitempty"`
	DerivedTargets []string          `json:"derived_targets,omitempty"`
}

type pluginRunRequest struct {
	Job             *pluginJob
	WorkDir         string
	RawTargets      []string
	Hosts           []HostDetail
	Options         map[string]string
	CommandTemplate string
	Progress        func(string)
}

type PluginRunResult struct {
	Summary          string
	Artifacts        []jobArtifact
	Findings         FindingSummary
	NucleiFindings   map[string][]storedNucleiFinding
	ImportedScanPath string
	ImportedScanName string
	DerivedTargets   []string
}

type plugin interface {
	Definition() PluginDefinitionView
	Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error)
}

type pluginManager struct {
	logger           *slog.Logger
	store            workspaceStateStore
	workspace        *workspace
	queue            chan string
	mu               sync.RWMutex
	plugins          map[string]plugin
	dynamicPluginIDs map[string]struct{}
	jobs             map[string]*pluginJob
}

type pluginSubmission struct {
	PluginID   string
	RawTargets []string
	HostIPs    []string
	Summary    string
	Options    map[string]string
	CampaignID string
	ChunkID    string
	Stage      string
	WorkerMode string
	WorkerID   string
	WorkerZone string
}

type pluginAvailability struct {
	Available bool
	Label     string
	Tone      string
	Reason    string
}

func resolveDefinitionAvailability(def PluginDefinitionView, options map[string]string) pluginAvailability {
	def = normalizedPluginDefinition(def)
	switch strings.TrimSpace(def.ID) {
	case "nmap-enrich":
		return resolveCommandAvailability("nmap", "Installed", "Missing binary `nmap` in PATH")
	case "subfinder":
		return resolveCommandAvailability("subfinder", "Installed", "Missing binary `subfinder` in PATH")
	case "nuclei":
		return resolveCommandAvailability("nuclei", "Installed", "Missing binary `nuclei` in PATH")
	case "nikto":
		return resolveCommandAvailability("nikto", "Installed", "Missing binary `nikto` in PATH")
	case "naabu":
		return resolveCommandAvailability("naabu", "Installed", "Missing binary `naabu` in PATH")
	case "dnsx":
		return resolveCommandAvailability("dnsx", "Installed", "Missing binary `dnsx` in PATH")
	case "httpx":
		return resolveCommandAvailability("httpx", "Installed", "Missing binary `httpx` in PATH")
	case "katana":
		return resolveCommandAvailability("katana", "Installed", "Missing binary `katana` in PATH")
	case "sqlmap":
		return resolveCommandAvailability("sqlmap", "Installed", "Missing binary `sqlmap` in PATH")
	case "zap-connector":
		baseURL := chooseString(optionOrEnv(options, []string{"api_base_url"}, "NWA_ZAP_API_URL", "ZAP_API_URL"), "http://127.0.0.1:8080")
		return pluginAvailability{
			Available: true,
			Label:     "Endpoint unchecked",
			Tone:      "info",
			Reason:    "ZAP uses " + baseURL + "; the endpoint is not health-checked before kickoff",
		}
	case "burp-connector":
		if strings.TrimSpace(optionOrEnv(options, []string{"api_base_url"}, "NWA_BURP_API_URL", "BURP_API_URL")) == "" ||
			strings.TrimSpace(optionOrEnv(options, nil, "NWA_BURP_API_TOKEN", "BURP_API_TOKEN")) == "" {
			return pluginAvailability{
				Available: false,
				Label:     "Needs config",
				Tone:      "warning",
				Reason:    "Missing Burp connector configuration (`BURP_API_URL` and `BURP_API_TOKEN`)",
			}
		}
		return pluginAvailability{
			Available: true,
			Label:     "Configured",
			Tone:      "ok",
			Reason:    "Burp API credentials are present; endpoint health is deferred to execution time",
		}
	case "tenable-connector":
		if strings.TrimSpace(optionOrEnv(options, []string{"scan_id"}, "NWA_TENABLE_SCAN_ID", "TENABLE_SCAN_ID")) == "" ||
			strings.TrimSpace(optionOrEnv(options, nil, "NWA_TENABLE_ACCESS_KEY", "TENABLE_ACCESS_KEY")) == "" ||
			strings.TrimSpace(optionOrEnv(options, nil, "NWA_TENABLE_SECRET_KEY", "TENABLE_SECRET_KEY")) == "" {
			return pluginAvailability{
				Available: false,
				Label:     "Needs config",
				Tone:      "warning",
				Reason:    "Missing Tenable connector configuration (`TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`, `TENABLE_SCAN_ID`)",
			}
		}
		return pluginAvailability{
			Available: true,
			Label:     "Configured",
			Tone:      "ok",
			Reason:    "Tenable credentials are present; API reachability is checked only when a run starts",
		}
	case "nessus-connector":
		if strings.TrimSpace(optionOrEnv(options, []string{"scan_id"}, "NWA_NESSUS_SCAN_ID", "NESSUS_SCAN_ID")) == "" ||
			strings.TrimSpace(optionOrEnv(options, nil, "NWA_NESSUS_ACCESS_KEY", "NESSUS_ACCESS_KEY")) == "" ||
			strings.TrimSpace(optionOrEnv(options, nil, "NWA_NESSUS_SECRET_KEY", "NESSUS_SECRET_KEY")) == "" {
			return pluginAvailability{
				Available: false,
				Label:     "Needs config",
				Tone:      "warning",
				Reason:    "Missing Nessus connector configuration (`NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`, `NESSUS_SCAN_ID`)",
			}
		}
		return pluginAvailability{
			Available: true,
			Label:     "Configured",
			Tone:      "ok",
			Reason:    "Nessus credentials are present; API reachability is checked only when a run starts",
		}
	}
	if def.Kind == "managed-command" && strings.TrimSpace(def.BinaryName) != "" {
		return resolveCommandAvailability(def.BinaryName, "Installed", "Missing binary `"+strings.TrimSpace(def.BinaryName)+"` in PATH")
	}
	return pluginAvailability{
		Available: true,
		Label:     "Ready",
		Tone:      "ok",
		Reason:    "",
	}
}

func resolveCommandAvailability(binary string, availableLabel string, missingReason string) pluginAvailability {
	if _, err := exec.LookPath(strings.TrimSpace(binary)); err != nil {
		return pluginAvailability{
			Available: false,
			Label:     "Missing",
			Tone:      "warning",
			Reason:    missingReason,
		}
	}
	return pluginAvailability{
		Available: true,
		Label:     availableLabel,
		Tone:      "ok",
	}
}

func runCLICommand(ctx context.Context, request pluginRunRequest, binary string, args []string) ([]byte, string, error) {
	commandLine := strings.TrimSpace(request.CommandTemplate)
	if commandLine == "" {
		output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		return output, shellJoin(append([]string{binary}, args...)), err
	}

	commandLine = strings.ReplaceAll(commandLine, "{{binary}}", shellQuote(binary))
	commandLine = strings.ReplaceAll(commandLine, "{{args}}", shellJoin(args))

	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.CommandContext(ctx, "cmd", "/C", commandLine)
	} else {
		command = exec.CommandContext(ctx, "sh", "-lc", commandLine)
	}
	output, err := command.CombinedOutput()
	return output, commandLine, err
}

func writeCommandLog(path string, commandLine string, output []byte) {
	commandLine = strings.TrimSpace(commandLine)
	if commandLine == "" {
		_ = os.WriteFile(path, output, 0o600)
		return
	}
	payload := "$ " + commandLine + "\n\n" + string(output)
	_ = os.WriteFile(path, []byte(payload), 0o600)
}

func shellJoin(values []string) string {
	if len(values) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, shellQuote(value))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	if value == "" {
		if runtime.GOOS == "windows" {
			return `""`
		}
		return "''"
	}
	if runtime.GOOS == "windows" {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func newPluginManager(store workspaceStateStore, workspace *workspace, logger *slog.Logger) (*pluginManager, error) {
	manager := &pluginManager{
		logger:    logger,
		store:     store,
		workspace: workspace,
		queue:     make(chan string, 64),
		plugins: map[string]plugin{
			"burp-connector":    &burpConnectorPlugin{},
			"dnsx":              &dnsxPlugin{},
			"httpx":             &httpxPlugin{},
			"katana":            &katanaPlugin{},
			"naabu":             &naabuPlugin{},
			"nessus-connector":  &nessusConnectorPlugin{},
			"nikto":             &niktoPlugin{},
			"nmap-enrich":       &nmapEnrichmentPlugin{},
			"nuclei":            &nucleiPlugin{},
			"sqlmap":            &sqlmapPlugin{},
			"subfinder":         &subfinderPlugin{},
			"tenable-connector": &tenableConnectorPlugin{},
			"zap-connector":     &zapConnectorPlugin{},
		},
		dynamicPluginIDs: map[string]struct{}{},
		jobs:             map[string]*pluginJob{},
	}
	if err := manager.syncDynamicPlugins(); err != nil {
		return nil, err
	}

	if err := manager.load(); err != nil {
		return nil, err
	}

	workers := minInt(maxInt(runtime.GOMAXPROCS(0)/2, 1), 4)
	for index := 0; index < workers; index++ {
		go manager.worker()
	}
	return manager, nil
}

func (m *pluginManager) syncDynamicPlugins() error {
	if m.store == nil {
		return nil
	}
	definitions, err := m.store.customToolDefinitions()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncDynamicPluginsLocked(definitions)
	return nil
}

func (m *pluginManager) syncDynamicPluginsLocked(definitions []PluginDefinitionView) {
	for toolID := range m.dynamicPluginIDs {
		delete(m.plugins, toolID)
	}
	clear(m.dynamicPluginIDs)
	for _, definition := range definitions {
		definition = normalizedPluginDefinition(definition)
		if strings.TrimSpace(definition.ID) == "" {
			continue
		}
		m.plugins[definition.ID] = &genericCommandPlugin{definition: definition}
		m.dynamicPluginIDs[definition.ID] = struct{}{}
	}
}

func (m *pluginManager) load() error {
	jobs, err := m.store.loadJobs()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, job := range jobs {
		if job.Status == jobRunning || job.Status == jobQueued {
			job.Status = jobFailed
			job.Error = "server restarted before job completion"
			job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		}
		m.jobs[job.ID] = job
	}
	return m.persistLocked()
}

func (m *pluginManager) persistLocked() error {
	jobs := make([]*pluginJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		jobs = append(jobs, cloneJob(job))
	}
	sort.SliceStable(jobs, func(left, right int) bool {
		return jobs[left].CreatedAt < jobs[right].CreatedAt
	})

	return m.store.saveJobs(jobs)
}

func (m *pluginManager) submit(pluginID string, rawTargets []string, hostIPs []string, summary string, options map[string]string) (PluginJobView, error) {
	return m.submitDetailed(pluginSubmission{
		PluginID:   pluginID,
		RawTargets: rawTargets,
		HostIPs:    hostIPs,
		Summary:    summary,
		Options:    options,
	})
}

func (m *pluginManager) submitDetailed(input pluginSubmission) (PluginJobView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store != nil {
		definitions, err := m.store.customToolDefinitions()
		if err != nil {
			return PluginJobView{}, err
		}
		m.syncDynamicPluginsLocked(definitions)
	}

	plugin, ok := m.plugins[input.PluginID]
	if !ok {
		return PluginJobView{}, fmt.Errorf("unknown plugin %q", input.PluginID)
	}
	definition := normalizedPluginDefinition(plugin.Definition())
	availability := resolveDefinitionAvailability(definition, input.Options)
	if !availability.Available {
		return PluginJobView{}, errors.New(availability.Reason)
	}

	rawTargets := uniqueStrings(input.RawTargets)
	hostIPs := uniqueStrings(input.HostIPs)
	targetCount := len(rawTargets)
	if len(hostIPs) > targetCount {
		targetCount = len(hostIPs)
	}
	if targetCount == 0 {
		return PluginJobView{}, errors.New("no targets were resolved for this job")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	job := &pluginJob{
		ID:            newWorkspaceID("job"),
		PluginID:      input.PluginID,
		PluginLabel:   definition.Label,
		PluginKind:    definition.Kind,
		SafetyClass:   definition.SafetyClass,
		CostProfile:   definition.CostProfile,
		Capabilities:  append([]string(nil), definition.Capabilities...),
		Status:        jobQueued,
		TargetSummary: chooseString(input.Summary, fmt.Sprintf("%d targets", targetCount)),
		TargetCount:   targetCount,
		RawTargets:    rawTargets,
		HostIPs:       hostIPs,
		CampaignID:    strings.TrimSpace(input.CampaignID),
		ChunkID:       strings.TrimSpace(input.ChunkID),
		Stage:         strings.TrimSpace(input.Stage),
		WorkerMode:    chooseString(strings.TrimSpace(input.WorkerMode), "central"),
		WorkerID:      strings.TrimSpace(input.WorkerID),
		WorkerZone:    strings.TrimSpace(input.WorkerZone),
		Options:       cloneStringMap(input.Options),
		CreatedAt:     now,
		Summary:       "Queued for execution",
	}

	m.jobs[job.ID] = job
	if err := m.persistLocked(); err != nil {
		delete(m.jobs, job.ID)
		return PluginJobView{}, err
	}

	m.queue <- job.ID
	return jobView(job), nil
}

func (m *pluginManager) targetStrategy(pluginID string) string {
	if err := m.syncDynamicPlugins(); err != nil && m.logger != nil {
		m.logger.Warn("sync custom tools", "error", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	plugin, ok := m.plugins[strings.TrimSpace(pluginID)]
	if !ok {
		return normalizedPluginDefinition(PluginDefinitionView{ID: pluginID}).TargetStrategy
	}
	return normalizedPluginDefinition(plugin.Definition()).TargetStrategy
}

func (m *pluginManager) definition(pluginID string) (PluginDefinitionView, bool) {
	if err := m.syncDynamicPlugins(); err != nil && m.logger != nil {
		m.logger.Warn("sync custom tools", "error", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	plugin, ok := m.plugins[strings.TrimSpace(pluginID)]
	if !ok {
		return PluginDefinitionView{}, false
	}
	return normalizedPluginDefinition(plugin.Definition()), true
}

func (m *pluginManager) worker() {
	for jobID := range m.queue {
		m.execute(jobID)
	}
}

func (m *pluginManager) execute(jobID string) {
	m.mu.Lock()
	job := m.jobs[jobID]
	if job == nil || job.Status != jobQueued {
		m.mu.Unlock()
		return
	}
	plugin := m.plugins[job.PluginID]
	job.Status = jobRunning
	job.StartedAt = time.Now().UTC().Format(time.RFC3339)
	job.Summary = "Launching " + plugin.Definition().Label
	_ = m.persistLocked()
	jobCopy := cloneJob(job)
	m.mu.Unlock()

	workDir := filepath.Join(m.workspace.artifactRoot(), jobCopy.ID)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		m.finish(jobCopy.ID, PluginRunResult{}, err)
		return
	}

	hosts := m.workspace.targetHosts(jobCopy.HostIPs)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	result, err := plugin.Run(ctx, pluginRunRequest{
		Job:             jobCopy,
		WorkDir:         workDir,
		RawTargets:      jobCopy.RawTargets,
		Hosts:           hosts,
		Options:         cloneStringMap(jobCopy.Options),
		CommandTemplate: m.commandTemplate(jobCopy.PluginID),
		Progress: func(summary string) {
			m.updateJobSummary(jobCopy.ID, summary)
		},
	})
	if err == nil {
		err = m.workspace.applyPluginResult(jobCopy, result)
	}
	m.finish(jobCopy.ID, result, err)
}

func (m *pluginManager) updateJobSummary(jobID string, summary string) {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	job := m.jobs[jobID]
	if job == nil || job.Status != jobRunning {
		return
	}
	job.Summary = summary
	_ = m.persistLocked()
}

func (m *pluginManager) finish(jobID string, result PluginRunResult, runErr error) {
	m.mu.Lock()

	job := m.jobs[jobID]
	if job == nil {
		m.mu.Unlock()
		return
	}

	job.Artifacts = append([]jobArtifact(nil), result.Artifacts...)
	job.Findings = result.Findings
	job.DerivedTargets = append([]string(nil), result.DerivedTargets...)
	job.Summary = result.Summary
	job.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if runErr != nil {
		job.Status = jobFailed
		job.Error = runErr.Error()
	} else {
		job.Status = jobCompleted
		job.Error = ""
	}

	_ = m.persistLocked()
	m.mu.Unlock()
	if m.workspace != nil {
		m.workspace.syncCommandCenterJob(job)
		m.workspace.refreshHistory()
	}
}

func (m *pluginManager) catalog() []PluginDefinitionView {
	if err := m.syncDynamicPlugins(); err != nil && m.logger != nil {
		m.logger.Warn("sync custom tools", "error", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]PluginDefinitionView, 0, len(m.plugins))
	for _, plugin := range m.plugins {
		definition := normalizedPluginDefinition(plugin.Definition())
		availability := resolveDefinitionAvailability(definition, nil)
		definition.Availability = availability.Label
		definition.AvailabilityTone = availability.Tone
		definition.AvailabilityDetail = availability.Reason
		items = append(items, definition)
	}
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].Label < items[right].Label
	})
	return items
}

func (m *pluginManager) commandTemplate(pluginID string) string {
	if m.store == nil {
		return ""
	}
	template, err := m.store.toolCommandTemplate(pluginID)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(template)
}

func (m *pluginManager) readinessGroups() []ToolReadinessGroup {
	type readinessConfig struct {
		Label   string
		Detail  string
		ToolIDs []string
	}

	configs := []readinessConfig{
		{
			Label:   "Discovery",
			Detail:  "Host reachability and first-pass service census for IP, CIDR, and discovered hostname targets.",
			ToolIDs: []string{"nmap-enrich", "naabu"},
		},
		{
			Label:   "Recon",
			Detail:  "Subdomain enumeration, hostname validation, and web surface reconnaissance for domain-driven scope.",
			ToolIDs: []string{"subfinder", "dnsx", "httpx", "katana"},
		},
		{
			Label:   "Validation",
			Detail:  "HTTP validation and focused exploitability checks after recon produces useful surfaces.",
			ToolIDs: []string{"nuclei", "nikto", "sqlmap"},
		},
		{
			Label:   "Connectors",
			Detail:  "External scanners and API-backed systems that can enrich or validate the workspace.",
			ToolIDs: []string{"zap-connector", "burp-connector", "tenable-connector", "nessus-connector"},
		},
	}

	catalogItems := m.catalog()
	catalog := map[string]PluginDefinitionView{}
	customToolIDs := make([]string, 0)
	for _, item := range catalogItems {
		catalog[item.ID] = item
		if item.InstallSource == toolInstallSourceCustom {
			customToolIDs = append(customToolIDs, item.ID)
		}
	}
	sort.Strings(customToolIDs)
	if len(customToolIDs) > 0 {
		configs = append(configs, readinessConfig{
			Label:   "Custom tools",
			Detail:  "Admin-installed managed commands loaded from the tool install API.",
			ToolIDs: customToolIDs,
		})
	}

	groups := make([]ToolReadinessGroup, 0, len(configs))
	for _, config := range configs {
		group := ToolReadinessGroup{
			Label:  config.Label,
			Detail: config.Detail,
			Tone:   "accent",
			Tools:  make([]PluginDefinitionView, 0, len(config.ToolIDs)),
		}
		for _, toolID := range config.ToolIDs {
			item, ok := catalog[toolID]
			if !ok {
				continue
			}
			group.Tools = append(group.Tools, item)
			group.Total++
			if item.AvailabilityTone == "ok" || item.AvailabilityTone == "accent" {
				group.Ready++
			}
		}
		switch {
		case group.Total == 0:
			group.Tone = "info"
		case group.Ready == group.Total:
			group.Tone = "ok"
		case group.Ready == 0:
			group.Tone = "risk"
		default:
			group.Tone = "warning"
		}
		groups = append(groups, group)
	}
	return groups
}

func (m *pluginManager) recentJobs(limit int) []PluginJobView {
	m.mu.RLock()
	defer m.mu.RUnlock()

	jobs := make([]*pluginJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		jobs = append(jobs, job)
	}
	sort.SliceStable(jobs, func(left, right int) bool {
		return jobs[left].CreatedAt > jobs[right].CreatedAt
	})
	if limit > 0 && len(jobs) > limit {
		jobs = jobs[:limit]
	}

	items := make([]PluginJobView, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, jobView(job))
	}
	return items
}

func (m *pluginManager) jobsForHost(ip string, limit int) []PluginJobView {
	m.mu.RLock()
	defer m.mu.RUnlock()

	jobs := make([]*pluginJob, 0)
	for _, job := range m.jobs {
		if slicesContains(job.HostIPs, ip) {
			jobs = append(jobs, job)
		}
	}
	sort.SliceStable(jobs, func(left, right int) bool {
		return jobs[left].CreatedAt > jobs[right].CreatedAt
	})
	if limit > 0 && len(jobs) > limit {
		jobs = jobs[:limit]
	}

	items := make([]PluginJobView, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, jobView(job))
	}
	return items
}

func (m *pluginManager) jobCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.jobs)
}

func (m *pluginManager) runningCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total := 0
	for _, job := range m.jobs {
		if job.Status == jobQueued || job.Status == jobRunning {
			total++
		}
	}
	return total
}

func (m *pluginManager) completedJobs() []*pluginJob {
	m.mu.RLock()
	defer m.mu.RUnlock()

	jobs := make([]*pluginJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		if job.Status != jobCompleted {
			continue
		}
		jobs = append(jobs, cloneJob(job))
	}
	sort.SliceStable(jobs, func(left, right int) bool {
		if jobs[left].FinishedAt != jobs[right].FinishedAt {
			return jobs[left].FinishedAt < jobs[right].FinishedAt
		}
		return jobs[left].CreatedAt < jobs[right].CreatedAt
	})
	return jobs
}

func (m *pluginManager) jobByID(id string) (*pluginJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	job := m.jobs[strings.TrimSpace(id)]
	if job == nil {
		return nil, false
	}
	return cloneJob(job), true
}

type nucleiPlugin struct{}

func (p *nucleiPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "nuclei",
		Label:            "Nuclei HTTP Enrichment",
		Description:      "Generate HTTP targets from mapped services or manual URLs, run nuclei in the background, and ingest findings per host.",
		Mode:             "Managed command",
		Family:           "Web validation",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *nucleiPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := uniqueStrings(append(nucleiTargetsForHosts(request.Hosts), request.RawTargets...))
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("nuclei requires HTTP targets or hosts with HTTP-like services")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	findingsPath := filepath.Join(request.WorkDir, "findings.jsonl")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := os.WriteFile(targetsPath, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		return PluginRunResult{}, err
	}

	args := []string{"-list", targetsPath, "-jsonl", "-o", findingsPath}
	if severity := strings.TrimSpace(request.Options["severity"]); severity != "" {
		args = append(args, "-severity", severity)
	}
	if templates := strings.TrimSpace(request.Options["templates"]); templates != "" {
		args = append(args, "-t", templates)
	}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "-c", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	output, commandLine, err := runCLICommand(ctx, request, "nuclei", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{
			Artifacts: []jobArtifact{
				{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
				{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
			},
		}, err
	}

	parsed, totals, err := parseNucleiJSONL(findingsPath)
	if err != nil {
		return PluginRunResult{}, err
	}
	parsed = remapFindingsToKnownIPs(parsed, buildHostResolutionMap(request))

	artifacts := []jobArtifact{
		{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
		{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
	}
	if len(parsed) > 0 || fileExists(findingsPath) {
		artifacts = append(artifacts, jobArtifact{Label: "Findings", RelPath: filepath.Join(request.Job.ID, "findings.jsonl")})
	}

	summary := fmt.Sprintf("nuclei completed across %d targets with %d findings.", len(targets), totals.Total)
	if totals.Total == 0 {
		summary = fmt.Sprintf("nuclei completed across %d targets with no findings.", len(targets))
	}
	return PluginRunResult{
		Summary:        summary,
		Artifacts:      artifacts,
		Findings:       totals,
		NucleiFindings: parsed,
	}, nil
}

type sqlmapPlugin struct{}

func (p *sqlmapPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "sqlmap",
		Label:            "SQLMap Web Validation",
		Description:      "Run sqlmap against manual URLs or mapped HTTP roots, capture likely SQL injection findings, and attach them back to hosts.",
		Mode:             "Managed command",
		Family:           "Web validation",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *sqlmapPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := sqlmapTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("sqlmap requires HTTP/HTTPS targets or hosts with mapped HTTP services")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.csv")
	logPath := filepath.Join(request.WorkDir, "command.log")
	outputDir := filepath.Join(request.WorkDir, "output")
	if err := os.WriteFile(targetsPath, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		return PluginRunResult{}, err
	}

	args := []string{"-m", targetsPath, "--batch", "--forms", "--output-dir", outputDir, "--results-file", resultsPath}
	if level := strings.TrimSpace(request.Options["level"]); level != "" {
		args = append(args, "--level", level)
	}
	if risk := strings.TrimSpace(request.Options["risk"]); risk != "" {
		args = append(args, "--risk", risk)
	}
	if crawlDepth := strings.TrimSpace(request.Options["crawl_depth"]); crawlDepth != "" {
		args = append(args, "--crawl", crawlDepth)
	} else {
		args = append(args, "--crawl", "1")
	}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "--threads", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	output, commandLine, err := runCLICommand(ctx, request, "sqlmap", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{
			Artifacts: []jobArtifact{
				{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
				{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
			},
		}, err
	}

	findings, totals, err := parseSQLMapResults(resultsPath, buildHostResolutionMap(request))
	if err != nil {
		return PluginRunResult{}, err
	}

	artifacts := []jobArtifact{
		{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
		{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
	}
	if len(findings) > 0 || fileExists(resultsPath) {
		artifacts = append(artifacts, jobArtifact{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.csv")})
	}

	summary := fmt.Sprintf("sqlmap evaluated %d targets with %d likely SQL injection findings.", len(targets), totals.Total)
	if totals.Total == 0 {
		summary = fmt.Sprintf("sqlmap evaluated %d targets with no SQL injection findings.", len(targets))
	}

	return PluginRunResult{
		Summary:        summary,
		Artifacts:      artifacts,
		Findings:       totals,
		NucleiFindings: findings,
	}, nil
}

type nmapEnrichmentPlugin struct{}

func (p *nmapEnrichmentPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:             "nmap-enrich",
		Label:          "Nmap Managed Scan",
		Description:    "Run profile-driven nmap host discovery, default TCP service scans, or deeper TCP and UDP follow-up against engagement targets.",
		Mode:           "Managed command",
		Family:         "Network discovery",
		BinaryName:     "nmap",
		TargetStrategy: "host",
		Profiles: []ToolCommandProfileView{
			{ID: "deep", Label: "Deep coverage", Description: "Service detection, default scripts, OS detection, and traceroute.", Default: true},
			{ID: "list", Label: "List targets", Description: "Inventory targets without probing them."},
			{ID: "ping", Label: "Ping discovery", Description: "Host discovery only with no port scan."},
			{ID: "syn", Label: "TCP SYN", Description: "SYN scan with service detection."},
			{ID: "connect", Label: "TCP connect", Description: "Full TCP connect scan with service detection."},
			{ID: "default", Label: "Default TCP", Description: "Default TCP service scan with default scripts."},
			{ID: "safe", Label: "Safe service probe", Description: "Lighter-weight service probing with version-light."},
			{ID: "traceroute", Label: "Traceroute", Description: "Service detection with traceroute enabled."},
			{ID: "all-tcp", Label: "Full TCP", Description: "Full TCP range with scripts, OS detection, and traceroute."},
			{ID: "udp-top", Label: "Top UDP", Description: "Top UDP ports with version detection."},
			{ID: "udp-full", Label: "Full UDP", Description: "Full UDP range with version detection."},
			{ID: "http-enum", Label: "HTTP enum", Description: "HTTP enumeration NSE script."},
			{ID: "http-methods", Label: "HTTP methods", Description: "HTTP methods NSE script."},
			{ID: "http-headers", Label: "HTTP headers", Description: "HTTP headers NSE script."},
			{ID: "smb-enum-shares", Label: "SMB shares", Description: "SMB share enumeration NSE script."},
			{ID: "ftp-anon", Label: "FTP anonymous", Description: "FTP anonymous access NSE script."},
		},
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *nmapEnrichmentPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := uniqueStrings(append(request.RawTargets, hostIPsFromDetails(request.Hosts)...))
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("nmap enrichment requires at least one target")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	xmlPath := filepath.Join(request.WorkDir, "scan.xml")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := os.WriteFile(targetsPath, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil {
		return PluginRunResult{}, err
	}

	profile := strings.TrimSpace(request.Options["profile"])
	if profile == "" {
		profile = "deep"
	}
	args := []string{"-Pn", "-n", "-sV", "-sC", "-oX", xmlPath, "-iL", targetsPath}
	switch profile {
	case "list":
		args = []string{"-sL", "-n", "-oX", xmlPath, "-iL", targetsPath}
	case "safe":
		args = []string{"-Pn", "-n", "-sV", "--version-light", "-oX", xmlPath, "-iL", targetsPath}
	case "ping":
		args = []string{"-sn", "-n", "-oX", xmlPath, "-iL", targetsPath}
	case "syn":
		args = []string{"-Pn", "-n", "-sS", "-sV", "-oX", xmlPath, "-iL", targetsPath}
	case "connect":
		args = []string{"-Pn", "-n", "-sT", "-sV", "-oX", xmlPath, "-iL", targetsPath}
	case "default":
		args = []string{"-Pn", "-n", "-sV", "-sC", "-oX", xmlPath, "-iL", targetsPath}
	case "all-tcp":
		args = []string{"-Pn", "-n", "-p-", "-sV", "-sC", "-O", "--traceroute", "-oX", xmlPath, "-iL", targetsPath}
	case "traceroute":
		args = []string{"-Pn", "-n", "-sV", "--traceroute", "-oX", xmlPath, "-iL", targetsPath}
	case "udp-top":
		args = []string{"-Pn", "-n", "-sU", "--top-ports", chooseString(strings.TrimSpace(request.Options["top_ports"]), "200"), "-sV", "-oX", xmlPath, "-iL", targetsPath}
	case "udp-full":
		args = []string{"-Pn", "-n", "-sU", "-p-", "-sV", "-oX", xmlPath, "-iL", targetsPath}
	case "http-enum":
		args = []string{"-Pn", "-n", "-sV", "--script", "http-enum", "-oX", xmlPath, "-iL", targetsPath}
	case "http-methods":
		args = []string{"-Pn", "-n", "-sV", "--script", "http-methods", "-oX", xmlPath, "-iL", targetsPath}
	case "http-headers":
		args = []string{"-Pn", "-n", "-sV", "--script", "http-headers", "-oX", xmlPath, "-iL", targetsPath}
	case "smb-enum-shares":
		args = []string{"-Pn", "-n", "-sV", "--script", "smb-enum-shares", "-oX", xmlPath, "-iL", targetsPath}
	case "ftp-anon":
		args = []string{"-Pn", "-n", "-sV", "--script", "ftp-anon", "-oX", xmlPath, "-iL", targetsPath}
	default:
		args = []string{"-Pn", "-n", "-sV", "-sC", "-O", "--traceroute", "-oX", xmlPath, "-iL", targetsPath}
	}
	if ports := strings.TrimSpace(request.Options["ports"]); ports != "" {
		args = append([]string{"-p", ports}, args...)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	output, commandLine, err := runCLICommand(ctx, request, "nmap", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{
			Artifacts: []jobArtifact{
				{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
				{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
			},
		}, err
	}

	scan, err := nmap.ParseFile(xmlPath)
	if err != nil {
		var partial *nmap.PartialParseError
		if !errors.As(err, &partial) {
			return PluginRunResult{}, err
		}
	}

	summary := fmt.Sprintf("nmap %s imported %d live hosts.", profile, len(scan.Alive()))
	if err != nil {
		summary = fmt.Sprintf("nmap %s recovered %d live hosts from malformed XML.", profile, len(scan.Alive()))
	}

	return PluginRunResult{
		Summary:          summary,
		Artifacts:        []jobArtifact{{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")}, {Label: "XML", RelPath: filepath.Join(request.Job.ID, "scan.xml")}, {Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")}},
		ImportedScanPath: xmlPath,
		ImportedScanName: "nmap-enrich-" + request.Job.ID,
	}, nil
}

type nucleiFindingLine struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	IP         string `json:"ip"`
	Type       string `json:"type"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
}

func parseNucleiJSONL(path string) (map[string][]storedNucleiFinding, FindingSummary, error) {
	results := map[string][]storedNucleiFinding{}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return results, FindingSummary{}, nil
		}
		return nil, FindingSummary{}, err
	}
	defer file.Close()

	summary := FindingSummary{}
	decoder := json.NewDecoder(file)
	for {
		var entry nucleiFindingLine
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			return nil, FindingSummary{}, err
		}

		ip := extractFindingIP(entry)
		if ip == "" {
			continue
		}

		finding := storedNucleiFinding{
			Source:      "nuclei",
			TemplateID:  strings.TrimSpace(entry.TemplateID),
			Name:        chooseString(strings.TrimSpace(entry.Info.Name), strings.TrimSpace(entry.TemplateID)),
			Severity:    normalizeSeverity(entry.Info.Severity),
			Target:      chooseString(strings.TrimSpace(entry.MatchedAt), strings.TrimSpace(entry.Host)),
			MatchedAt:   chooseString(strings.TrimSpace(entry.MatchedAt), strings.TrimSpace(entry.Host)),
			Type:        strings.TrimSpace(entry.Type),
			Description: strings.TrimSpace(entry.Info.Description),
			Tags:        entry.Info.Tags,
		}
		results[ip] = append(results[ip], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}

	for ip, findings := range results {
		results[ip] = mergeStoredFindings(nil, findings)
	}
	return results, summary, nil
}

func extractFindingIP(entry nucleiFindingLine) string {
	if strings.TrimSpace(entry.IP) != "" {
		return strings.TrimSpace(entry.IP)
	}

	for _, candidate := range []string{entry.MatchedAt, entry.Host} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if parsed, err := url.Parse(candidate); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
		if strings.Contains(candidate, ":") {
			if parsed, err := url.Parse("scheme://" + candidate); err == nil && parsed.Hostname() != "" {
				return parsed.Hostname()
			}
		}
		return candidate
	}

	return ""
}

func hostIPsFromDetails(hosts []HostDetail) []string {
	results := make([]string, 0, len(hosts))
	for _, host := range hosts {
		results = append(results, host.IP)
	}
	return uniqueStrings(results)
}

func nucleiTargetsForHosts(hosts []HostDetail) []string {
	targets := make([]string, 0)
	for _, host := range hosts {
		targets = append(targets, host.NucleiTargets...)
	}
	return uniqueStrings(targets)
}

func sqlmapTargetsForRequest(request pluginRunRequest) []string {
	targets := make([]string, 0, len(request.RawTargets))
	targets = append(targets, nucleiTargetsForHosts(request.Hosts)...)
	for _, target := range request.RawTargets {
		target = strings.TrimSpace(target)
		if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
			continue
		}
		targets = append(targets, target)
	}
	return uniqueStrings(targets)
}

func buildHostResolutionMap(request pluginRunRequest) map[string]string {
	results := map[string]string{}
	for _, host := range request.Hosts {
		ip := strings.TrimSpace(host.IP)
		if ip == "" {
			continue
		}
		results[strings.ToLower(ip)] = ip
		if displayName := strings.TrimSpace(host.DisplayName); displayName != "" {
			results[strings.ToLower(displayName)] = ip
		}
		for _, hostname := range host.Hostnames {
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				continue
			}
			results[strings.ToLower(hostname)] = ip
		}
		for _, target := range host.NucleiTargets {
			if parsed, err := url.Parse(strings.TrimSpace(target)); err == nil && parsed.Hostname() != "" {
				results[strings.ToLower(parsed.Hostname())] = ip
			}
		}
	}
	for _, target := range request.RawTargets {
		target = strings.TrimSpace(target)
		if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
			host := strings.ToLower(parsed.Hostname())
			if ip, ok := results[host]; ok {
				results[strings.ToLower(target)] = ip
			}
			continue
		}
		if target != "" {
			results[strings.ToLower(target)] = target
		}
	}
	return results
}

func remapFindingsToKnownIPs(findings map[string][]storedNucleiFinding, resolutions map[string]string) map[string][]storedNucleiFinding {
	if len(findings) == 0 {
		return nil
	}
	results := make(map[string][]storedNucleiFinding, len(findings))
	for key, rows := range findings {
		resolved := resolveKnownIP(key, resolutions)
		if resolved == "" {
			resolved = strings.TrimSpace(key)
		}
		if resolved == "" {
			continue
		}
		results[resolved] = mergeStoredFindings(results[resolved], rows)
	}
	return results
}

func resolveKnownIP(value string, resolutions map[string]string) string {
	candidates := make([]string, 0, 3)
	trimmed := strings.TrimSpace(value)
	if trimmed != "" {
		candidates = append(candidates, strings.ToLower(trimmed))
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
		candidates = append(candidates, strings.ToLower(parsed.Hostname()))
	}
	if strings.Contains(trimmed, ":") {
		if parsed, err := url.Parse("scheme://" + trimmed); err == nil && parsed.Hostname() != "" {
			candidates = append(candidates, strings.ToLower(parsed.Hostname()))
		}
	}

	for _, candidate := range candidates {
		if resolved, ok := resolutions[candidate]; ok {
			return resolved
		}
	}
	return ""
}

func parseSQLMapResults(path string, resolutions map[string]string) (map[string][]storedNucleiFinding, FindingSummary, error) {
	results := map[string][]storedNucleiFinding{}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return results, FindingSummary{}, nil
		}
		return nil, FindingSummary{}, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return results, FindingSummary{}, nil
		}
		return nil, FindingSummary{}, err
	}

	indexByName := map[string]int{}
	for index, name := range header {
		indexByName[strings.ToLower(strings.TrimSpace(name))] = index
	}

	summary := FindingSummary{}
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, FindingSummary{}, err
		}

		target := csvLookup(record, indexByName, "target url", "url", "target")
		if target == "" {
			continue
		}
		hostIP := resolveKnownIP(target, resolutions)
		if hostIP == "" {
			if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
				hostIP = parsed.Hostname()
			}
		}
		if hostIP == "" {
			continue
		}

		parameter := csvLookup(record, indexByName, "parameter", "parameter(s)")
		place := csvLookup(record, indexByName, "place")
		techniques := csvLookup(record, indexByName, "techniques", "technique(s)")
		detailParts := make([]string, 0, 2)
		if place != "" {
			detailParts = append(detailParts, "place: "+place)
		}
		if techniques != "" {
			detailParts = append(detailParts, "techniques: "+techniques)
		}

		name := "Potential SQL injection"
		if parameter != "" {
			name = "Potential SQL injection via " + parameter
		}
		finding := storedNucleiFinding{
			Source:      "sqlmap",
			TemplateID:  chooseString(parameter, "sqlmap"),
			Name:        name,
			Severity:    "high",
			Target:      target,
			MatchedAt:   target,
			Type:        "sql-injection",
			Description: strings.Join(detailParts, " · "),
		}
		results[hostIP] = append(results[hostIP], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}

	for hostIP, rows := range results {
		results[hostIP] = mergeStoredFindings(nil, rows)
	}
	return results, summary, nil
}

func csvLookup(record []string, indexByName map[string]int, names ...string) string {
	for _, name := range names {
		index, ok := indexByName[strings.ToLower(strings.TrimSpace(name))]
		if !ok || index < 0 || index >= len(record) {
			continue
		}
		value := strings.TrimSpace(record[index])
		if value != "" {
			return value
		}
	}
	return ""
}

func jobView(job *pluginJob) PluginJobView {
	view := PluginJobView{
		ID:            job.ID,
		PluginID:      job.PluginID,
		PluginLabel:   job.PluginLabel,
		PluginKind:    job.PluginKind,
		SafetyClass:   job.SafetyClass,
		CostProfile:   job.CostProfile,
		Capabilities:  append([]string(nil), job.Capabilities...),
		Status:        job.Status,
		StatusTone:    jobStatusTone(job.Status),
		TargetSummary: job.TargetSummary,
		TargetCount:   job.TargetCount,
		CampaignID:    job.CampaignID,
		ChunkID:       job.ChunkID,
		Stage:         job.Stage,
		WorkerMode:    job.WorkerMode,
		WorkerZone:    job.WorkerZone,
		CreatedAt:     displayTimestamp(job.CreatedAt),
		StartedAt:     displayTimestamp(job.StartedAt),
		FinishedAt:    displayTimestamp(job.FinishedAt),
		Summary:       job.Summary,
		Error:         job.Error,
		Findings:      job.Findings,
	}
	for _, artifact := range job.Artifacts {
		view.Artifacts = append(view.Artifacts, JobArtifactView{
			Label: artifact.Label,
			Href:  "/artifacts/" + filepath.ToSlash(artifact.RelPath),
		})
	}
	return view
}

func jobStatusTone(status string) string {
	switch status {
	case jobCompleted:
		return "ok"
	case targetChunkPartial:
		return "warning"
	case targetChunkBlocked:
		return "info"
	case jobFailed:
		return "risk"
	case jobRunning:
		return "accent"
	default:
		return "warning"
	}
}

func cloneJob(job *pluginJob) *pluginJob {
	if job == nil {
		return nil
	}
	copy := *job
	copy.RawTargets = append([]string(nil), job.RawTargets...)
	copy.HostIPs = append([]string(nil), job.HostIPs...)
	copy.Capabilities = append([]string(nil), job.Capabilities...)
	copy.Options = cloneStringMap(job.Options)
	copy.Artifacts = append([]jobArtifact(nil), job.Artifacts...)
	return &copy
}

func normalizedPluginDefinition(def PluginDefinitionView) PluginDefinitionView {
	if strings.TrimSpace(def.Kind) == "" {
		switch def.Mode {
		case "API connector":
			def.Kind = "api-connector"
		case "Import":
			def.Kind = "importer"
		default:
			def.Kind = "managed-command"
		}
	}
	if strings.TrimSpace(def.SafetyClass) == "" {
		switch def.Kind {
		case "api-connector":
			def.SafetyClass = "controlled"
		case "parser-only":
			def.SafetyClass = "passive"
		default:
			def.SafetyClass = "active"
		}
	}
	if strings.TrimSpace(def.CostProfile) == "" {
		switch def.ID {
		case "nmap-enrich", "katana", "sqlmap", "nikto", "burp-connector", "zap-connector":
			def.CostProfile = "high"
		case "nuclei", "httpx", "tenable-connector", "nessus-connector":
			def.CostProfile = "medium"
		default:
			def.CostProfile = "low"
		}
	}
	if strings.TrimSpace(def.InstallSource) == "" {
		def.InstallSource = toolInstallSourceBuiltin
	}
	if strings.TrimSpace(def.TargetStrategy) == "" {
		switch def.ID {
		case "nuclei", "nikto", "sqlmap", "httpx", "katana", "zap-connector", "burp-connector":
			def.TargetStrategy = "web"
		case "subfinder", "dnsx":
			def.TargetStrategy = "domain"
		default:
			def.TargetStrategy = "host"
		}
	}
	if len(def.Capabilities) == 0 {
		switch def.ID {
		case "naabu", "masscan", "zmap":
			def.Capabilities = []string{"discovery", "ports"}
		case "nmap-enrich":
			def.Capabilities = []string{"discovery", "services", "fingerprinting"}
		case "httpx":
			def.Capabilities = []string{"http", "recon"}
		case "dnsx":
			def.Capabilities = []string{"dns", "recon"}
		case "katana":
			def.Capabilities = []string{"http", "crawl"}
		case "nuclei":
			def.Capabilities = []string{"http", "validation", "findings"}
		case "nikto":
			def.Capabilities = []string{"http", "validation", "headers"}
		case "sqlmap":
			def.Capabilities = []string{"http", "database", "validation"}
		case "burp-connector", "zap-connector":
			def.Capabilities = []string{"http", "dast", "validation"}
		case "tenable-connector", "nessus-connector":
			def.Capabilities = []string{"vuln-management", "findings"}
		default:
			def.Capabilities = []string{"general"}
		}
	}
	if def.Kind == "managed-command" {
		def.CommandEditable = true
		if strings.TrimSpace(def.DefaultCommandTemplate) == "" {
			def.DefaultCommandTemplate = "{{binary}} {{args}}"
		}
	}
	return def
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func addFindingSeverity(summary FindingSummary, severity string) FindingSummary {
	summary.Total++
	switch normalizeSeverity(severity) {
	case "critical":
		summary.Critical++
	case "high":
		summary.High++
	case "medium":
		summary.Medium++
	case "low":
		summary.Low++
	default:
		summary.Info++
	}
	return summary
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func severityWeight(severity string) int {
	switch normalizeSeverity(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func severityTone(severity string) string {
	switch normalizeSeverity(severity) {
	case "critical", "high":
		return "risk"
	case "medium":
		return "warning"
	case "low":
		return "accent"
	default:
		return "ok"
	}
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	results := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		results = append(results, value)
	}
	return results
}

func slicesContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
