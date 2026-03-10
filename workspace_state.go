package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nwa/nmap"
)

var workspaceIDSequence atomic.Uint64

type scanRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Path       string `json:"path"`
	Hash       string `json:"hash"`
	Scanner    string `json:"scanner"`
	Version    string `json:"version"`
	StartedAt  string `json:"started_at"`
	ImportedAt string `json:"imported_at"`
	Command    string `json:"command"`
	Type       string `json:"type"`
	Protocol   string `json:"protocol"`
	LiveHosts  int    `json:"live_hosts"`
}

type managedScan struct {
	record  scanRecord
	scan    nmap.Scan
	payload []byte
}

type storedNucleiFinding struct {
	Source      string   `json:"source,omitempty"`
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Target      string   `json:"target"`
	MatchedAt   string   `json:"matched_at"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type analystNote struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	CreatedAt string `json:"created_at"`
}

type hostEnrichment struct {
	Nuclei []storedNucleiFinding `json:"nuclei,omitempty"`
	Tags   []string              `json:"tags,omitempty"`
	Notes  []analystNote         `json:"notes,omitempty"`
}

type savedViewRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Query     string `json:"query"`
	Scope     string `json:"scope"`
	Sort      string `json:"sort"`
	PageSize  int    `json:"page_size"`
	CreatedAt string `json:"created_at"`
}

type scopeSeedRecord struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Source    string `json:"source,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	CreatedAt string `json:"created_at"`
}

type scopeTargetRecord struct {
	ID         string            `json:"id"`
	SeedID     string            `json:"seed_id"`
	Kind       string            `json:"kind"`
	Value      string            `json:"value"`
	Normalized string            `json:"normalized"`
	Status     string            `json:"status"`
	CreatedAt  string            `json:"created_at"`
	Meta       map[string]string `json:"meta,omitempty"`
}

type targetChunkRecord struct {
	ID           string   `json:"id"`
	CampaignID   string   `json:"campaign_id,omitempty"`
	Name         string   `json:"name"`
	Stage        string   `json:"stage"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	StatusDetail string   `json:"status_detail,omitempty"`
	CreatedAt    string   `json:"created_at"`
	StartedAt    string   `json:"started_at,omitempty"`
	FinishedAt   string   `json:"finished_at,omitempty"`
	Size         int      `json:"size"`
	TargetIDs    []string `json:"target_ids,omitempty"`
	Values       []string `json:"values,omitempty"`
	RunIDs       []string `json:"run_ids,omitempty"`
	ToolIDs      []string `json:"tool_ids,omitempty"`
	SkippedTools []string `json:"skipped_tools,omitempty"`
}

type approvalRecord struct {
	ID             string            `json:"id"`
	CampaignID     string            `json:"campaign_id,omitempty"`
	Scope          string            `json:"scope"`
	Status         string            `json:"status"`
	Summary        string            `json:"summary"`
	Detail         string            `json:"detail,omitempty"`
	RequiredClass  string            `json:"required_class"`
	CreatedAt      string            `json:"created_at"`
	DecidedAt      string            `json:"decided_at,omitempty"`
	AllowedToolIDs []string          `json:"allowed_tool_ids,omitempty"`
	Policy         map[string]string `json:"policy,omitempty"`
}

type recommendationRecord struct {
	ID               string   `json:"id"`
	CampaignID       string   `json:"campaign_id,omitempty"`
	ChunkID          string   `json:"chunk_id,omitempty"`
	Type             string   `json:"type"`
	Status           string   `json:"status"`
	Title            string   `json:"title"`
	Detail           string   `json:"detail"`
	Rationale        string   `json:"rationale"`
	ExpectedValue    string   `json:"expected_value"`
	RequiredApproval string   `json:"required_approval"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
	Confidence       float64  `json:"confidence"`
	ToolIDs          []string `json:"tool_ids,omitempty"`
	TargetIDs        []string `json:"target_ids,omitempty"`
}

type campaignRecord struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	PluginID    string            `json:"plugin_id"`
	PluginLabel string            `json:"plugin_label"`
	Scope       string            `json:"scope"`
	CompareFrom string            `json:"compare_from"`
	CompareTo   string            `json:"compare_to"`
	HostIPs     []string          `json:"host_ips,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	Status      string            `json:"status"`
	Summary     string            `json:"summary,omitempty"`
	CreatedAt   string            `json:"created_at"`
	JobID       string            `json:"job_id,omitempty"`
	Stage       string            `json:"stage,omitempty"`
	StageLabel  string            `json:"stage_label,omitempty"`
	TargetKind  string            `json:"target_kind,omitempty"`
	ChunkIDs    []string          `json:"chunk_ids,omitempty"`
	ApprovalID  string            `json:"approval_id,omitempty"`
	Policy      map[string]string `json:"policy,omitempty"`
}

type workspace struct {
	id               string
	slug             string
	name             string
	mode             string
	bundlePath       string
	logger           *slog.Logger
	root             string
	workspace        string
	runsDir          string
	store            workspaceStateStore
	mu               sync.RWMutex
	scans            []managedScan
	enrichments      map[string]hostEnrichment
	savedViews       []savedViewRecord
	campaigns        []campaignRecord
	scopeSeeds       []scopeSeedRecord
	scopeTargets     []scopeTargetRecord
	targetChunks     []targetChunkRecord
	approvals        []approvalRecord
	recommendations  []recommendationRecord
	events           []workspaceEvent
	preferencesState workspacePreferences
	snapshot         *snapshot
	history          *workspaceHistory
	plugins          *pluginManager
}

func openWorkspace(rootDir string, seedFiles []string, logger *slog.Logger) (*workspace, error) {
	workspacePath, err := resolveWorkspacePath(rootDir)
	if err != nil {
		return nil, err
	}
	runsDir := deriveWorkspaceArtifactsDir(workspacePath)
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		return nil, err
	}
	store, err := openWorkspaceStore(workspacePath)
	if err != nil {
		return nil, err
	}

	name := strings.TrimSpace(strings.TrimSuffix(filepath.Base(workspacePath), filepath.Ext(workspacePath)))
	if name == "" {
		name = "Workspace"
	}
	meta := workspaceMetaRecord{
		ID:         newWorkspaceID("ws"),
		Slug:       slugifyWorkspaceName(name),
		Name:       name,
		BundlePath: workspacePath,
	}
	return openWorkspaceWithStore(meta, workspacePath, runsDir, store, seedFiles, logger)
}

func openWorkspaceWithStore(meta workspaceMetaRecord, displayRoot string, runsDir string, store workspaceStateStore, seedFiles []string, logger *slog.Logger) (*workspace, error) {
	w := &workspace{
		id:          meta.ID,
		slug:        meta.Slug,
		name:        meta.Name,
		mode:        "bundle",
		bundlePath:  chooseString(meta.BundlePath, displayRoot),
		logger:      logger,
		root:        displayRoot,
		workspace:   displayRoot,
		runsDir:     runsDir,
		store:       store,
		enrichments: map[string]hostEnrichment{},
	}
	if _, ok := store.(*serviceWorkspaceStore); ok {
		w.mode = "service"
	}

	if err := w.loadState(); err != nil {
		return nil, err
	}

	manager, err := newPluginManager(w.store, w, logger)
	if err != nil {
		return nil, err
	}
	w.plugins = manager
	if err := w.loadLedger(); err != nil {
		return nil, err
	}
	resolvedSeeds, err := resolveSeedFiles(seedFiles)
	if err != nil {
		return nil, err
	}
	importedSeeds := 0
	seedErrors := make([]string, 0)
	for _, seedFile := range resolvedSeeds {
		if _, err := w.importScanFromPath(seedFile, "seed-file", filepath.Base(seedFile)); err != nil {
			seedErrors = append(seedErrors, fmt.Sprintf("%s: %v", seedFile, err))
			if logger != nil {
				logger.Warn("seed scan import failed", "path", seedFile, "error", err)
			}
			continue
		}
		importedSeeds++
	}
	if len(seedErrors) > 0 && importedSeeds == 0 && len(w.scans) == 0 {
		return nil, fmt.Errorf("no seed scans were imported; first failure: %s", seedErrors[0])
	}
	if len(seedErrors) > 0 && logger != nil {
		logger.Warn("seed scan import completed with errors", "imported", importedSeeds, "failed", len(seedErrors))
	}
	w.mu.Lock()
	w.rebuildDerivedStateLocked()
	w.mu.Unlock()
	return w, nil
}

func (w *workspace) loadState() error {
	state, err := w.store.loadState()
	if err != nil {
		return err
	}
	preferences, err := w.store.loadPreferences()
	if err != nil {
		return err
	}
	w.preferencesState = preferences
	if len(state.Enrichments) > 0 {
		w.enrichments = state.Enrichments
	}
	if len(state.SavedViews) > 0 {
		w.savedViews = state.SavedViews
	}
	if len(state.Campaigns) > 0 {
		w.campaigns = state.Campaigns
	}
	if len(state.ScopeSeeds) > 0 {
		w.scopeSeeds = state.ScopeSeeds
	}
	if len(state.ScopeTargets) > 0 {
		w.scopeTargets = state.ScopeTargets
	}
	if len(state.TargetChunks) > 0 {
		w.targetChunks = state.TargetChunks
	}
	if len(state.Approvals) > 0 {
		w.approvals = state.Approvals
	}
	if len(state.Recommendations) > 0 {
		w.recommendations = state.Recommendations
	}

	scans := make([]managedScan, 0, len(state.Scans))
	for _, stored := range state.Scans {
		parsed, err := parseImportPayload(stored.Payload, chooseString(stored.Record.Name, stored.Record.Path))
		if err != nil {
			var partial *nmap.PartialParseError
			if !errors.As(err, &partial) {
				return fmt.Errorf("parse scan %s: %w", stored.Record.Name, err)
			}
			if w.logger != nil {
				w.logger.Warn("workspace scan recovered from malformed payload", "name", stored.Record.Name, "recovered_hosts", partial.RecoveredHosts, "error", partial.Cause)
			}
		}
		scans = append(scans, managedScan{
			record:  stored.Record,
			scan:    parsed.Scan,
			payload: append([]byte(nil), stored.Payload...),
		})
	}

	sort.SliceStable(scans, func(left, right int) bool {
		return scans[left].record.ImportedAt < scans[right].record.ImportedAt
	})

	w.scans = scans
	w.snapshot = buildSnapshotFromScans(w.scans, w.enrichments)
	return nil
}

func (w *workspace) persistStateLocked() error {
	return w.store.saveState(
		w.scans,
		w.enrichments,
		w.savedViews,
		w.campaigns,
		w.scopeSeeds,
		w.scopeTargets,
		w.targetChunks,
		w.approvals,
		w.recommendations,
	)
}

func (w *workspace) rebuildSnapshotLocked() {
	w.snapshot = buildSnapshotFromScans(w.scans, w.enrichments)
}

func (w *workspace) rebuildDerivedStateLocked() {
	w.rebuildSnapshotLocked()
	currentState := buildCheckpointState(w.scans, w.enrichments)
	if len(w.events) > 0 {
		w.history = buildWorkspaceHistoryFromLedger(w.events)
		if !w.history.matchesFinalState(currentState) {
			appendReconciliationCheckpoint(w.history, currentState)
		}
		return
	}
	var jobs []*pluginJob
	if w.plugins != nil {
		jobs = w.plugins.completedJobs()
	}
	w.history = buildWorkspaceHistory(w.scans, w.enrichments, jobs, w.runsDir, w.logger)
}

func (w *workspace) currentSnapshot() *snapshot {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.snapshot == nil {
		return buildSnapshotFromScans(nil, nil)
	}
	return w.snapshot
}

func (w *workspace) currentHistory() *workspaceHistory {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.history
}

func (w *workspace) refreshHistory() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rebuildDerivedStateLocked()
}

func (w *workspace) importScanFromPath(path string, source string, name string) (scanRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return scanRecord{}, err
	}
	if name == "" {
		name = filepath.Base(path)
	}
	record, err := w.importScanPayload(payload, name, source, "scan-import")
	if err != nil {
		return scanRecord{}, fmt.Errorf("import %s: %w", path, err)
	}
	return record, nil
}

func (w *workspace) importUploadedScan(filename string, body io.Reader) (scanRecord, error) {
	payload, err := io.ReadAll(body)
	if err != nil {
		return scanRecord{}, err
	}
	return w.importScanPayload(payload, filename, "upload", "scan-import")
}

func (w *workspace) importScanPayload(payload []byte, name string, source string, kind string) (scanRecord, error) {
	parsed, err := parseImportPayload(payload, name)
	if err != nil {
		var partial *nmap.PartialParseError
		if !errors.As(err, &partial) {
			return scanRecord{}, err
		}
		if w.logger != nil {
			w.logger.Warn("scan recovered from malformed XML", "name", name, "source", source, "recovered_hosts", partial.RecoveredHosts, "error", partial.Cause)
		}
	}
	scan := parsed.Scan
	findings := parsed.Findings

	hashBytes := sha256.Sum256(payload)
	hash := hex.EncodeToString(hashBytes[:])
	now := time.Now().UTC().Format(time.RFC3339)

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, existing := range w.scans {
		if existing.record.Hash == hash {
			return existing.record, nil
		}
	}

	id := newWorkspaceID("scan")
	fileExt := chooseImportExt(parsed.FileExt, normalizedFileExt(name))
	if fileExt == "" {
		fileExt = ".xml"
	}
	filename := fmt.Sprintf("%s-%s%s", id, sanitizeFileStem(name), fileExt)

	record := scanRecord{
		ID:         id,
		Name:       chooseString(strings.TrimSpace(name), filename),
		Kind:       kind,
		Source:     source,
		Path:       filename,
		Hash:       hash,
		Scanner:    scan.Scanner,
		Version:    scan.Version,
		StartedAt:  scan.Startstr,
		ImportedAt: now,
		Command:    scan.Args,
		Type:       scan.ScanInfo.Type,
		Protocol:   scan.ScanInfo.Protocol,
		LiveHosts:  len(scan.Alive()),
	}

	w.scans = append(w.scans, managedScan{
		record:  record,
		scan:    scan,
		payload: append([]byte(nil), payload...),
	})
	for ip, hostFindings := range findings {
		current := w.enrichments[ip]
		current.Nuclei = mergeStoredFindings(current.Nuclei, hostFindings)
		w.enrichments[ip] = current
	}
	sort.SliceStable(w.scans, func(left, right int) bool {
		return w.scans[left].record.ImportedAt < w.scans[right].record.ImportedAt
	})

	w.rebuildDerivedStateLocked()
	if err := w.refreshRecommendationsLocked(); err != nil {
		return scanRecord{}, err
	}
	if err := w.persistStateLocked(); err != nil {
		return scanRecord{}, err
	}
	observations := scanObservations(scan, record.Name)
	summaryParts := []string{fmt.Sprintf("%s imported %d live hosts", chooseString(record.Name, "Scan"), record.LiveHosts)}
	if summary := findingsSummary(findings); summary.Total > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d findings across %d hosts", summary.Total, len(findings)))
		observations = append(observations, findingObservations(findings, record.Name)...)
	}
	if err := w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:         "Scan import",
		KindTone:     "warning",
		Label:        record.Name,
		Summary:      strings.Join(summaryParts, " and ") + ".",
		CreatedAt:    record.ImportedAt,
		RefID:        record.ID,
		Observations: observations,
	}); err != nil {
		return scanRecord{}, err
	}
	return record, nil
}

func (w *workspace) applyPluginResult(job *pluginJob, result PluginRunResult) error {
	var importedPayload []byte
	var importedScan nmap.Scan
	var importedScanApplied bool
	if result.ImportedScanPath != "" {
		payload, err := os.ReadFile(result.ImportedScanPath)
		if err != nil {
			return err
		}
		importedPayload = payload
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if len(result.NucleiFindings) > 0 {
		for ip, findings := range result.NucleiFindings {
			current := w.enrichments[ip]
			current.Nuclei = mergeStoredFindings(current.Nuclei, findings)
			w.enrichments[ip] = current
		}
	}

	if len(importedPayload) > 0 {
		parsed, err := parseImportPayload(importedPayload, chooseString(result.ImportedScanName, filepath.Base(result.ImportedScanPath)))
		if err != nil {
			var partial *nmap.PartialParseError
			if !errors.As(err, &partial) {
				return err
			}
			if w.logger != nil {
				w.logger.Warn("plugin scan recovered from malformed XML", "job", job.ID, "name", result.ImportedScanName, "recovered_hosts", partial.RecoveredHosts, "error", partial.Cause)
			}
		}
		importedScan = parsed.Scan
		for ip, findings := range parsed.Findings {
			current := w.enrichments[ip]
			current.Nuclei = mergeStoredFindings(current.Nuclei, findings)
			w.enrichments[ip] = current
		}
		hashBytes := sha256.Sum256(importedPayload)
		hash := hex.EncodeToString(hashBytes[:])
		duplicate := false
		for _, existing := range w.scans {
			if existing.record.Hash == hash {
				duplicate = true
				break
			}
		}
		if !duplicate {
			id := newWorkspaceID("scan")
			fileExt := chooseImportExt(parsed.FileExt, normalizedFileExt(result.ImportedScanPath))
			if fileExt == "" {
				fileExt = ".xml"
			}
			filename := fmt.Sprintf("%s-%s%s", id, sanitizeFileStem(result.ImportedScanName), fileExt)

			record := scanRecord{
				ID:         id,
				Name:       chooseString(strings.TrimSpace(result.ImportedScanName), filename),
				Kind:       "plugin-import",
				Source:     "job:" + job.ID,
				Path:       filename,
				Hash:       hash,
				Scanner:    importedScan.Scanner,
				Version:    importedScan.Version,
				StartedAt:  importedScan.Startstr,
				ImportedAt: time.Now().UTC().Format(time.RFC3339),
				Command:    importedScan.Args,
				Type:       importedScan.ScanInfo.Type,
				Protocol:   importedScan.ScanInfo.Protocol,
				LiveHosts:  len(importedScan.Alive()),
			}
			w.scans = append(w.scans, managedScan{
				record:  record,
				scan:    importedScan,
				payload: append([]byte(nil), importedPayload...),
			})
			importedScanApplied = true
			sort.SliceStable(w.scans, func(left, right int) bool {
				return w.scans[left].record.ImportedAt < w.scans[right].record.ImportedAt
			})
		}
	}

	w.rebuildDerivedStateLocked()
	if err := w.refreshRecommendationsLocked(); err != nil {
		return err
	}
	if err := w.persistStateLocked(); err != nil {
		return err
	}

	observations := findingObservations(result.NucleiFindings, job.PluginLabel)
	summaryParts := make([]string, 0, 2)
	if result.Findings.Total > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d findings across %d hosts", result.Findings.Total, len(result.NucleiFindings)))
	}
	if importedScanApplied {
		observations = append(observations, scanObservations(importedScan, job.PluginLabel)...)
		summaryParts = append(summaryParts, fmt.Sprintf("imported %d live hosts", len(importedScan.Alive())))
	}
	if len(observations) == 0 {
		return nil
	}
	summary := strings.Join(summaryParts, " and ")
	if summary == "" {
		summary = chooseString(result.Summary, job.PluginLabel+" updated the workspace.")
	}
	return w.appendWorkspaceEventLocked(workspaceEvent{
		Kind:         "Integration",
		KindTone:     "accent",
		Label:        job.PluginLabel,
		Summary:      strings.TrimSuffix(summary, ".") + ".",
		CreatedAt:    chooseString(job.FinishedAt, job.StartedAt, job.CreatedAt),
		RefID:        job.ID,
		Observations: observations,
	})
}

func (w *workspace) workspaceStatus() WorkspaceStatusView {
	w.mu.RLock()
	scanCount := len(w.scans)
	snapshot := w.snapshot
	findingHosts := len(w.enrichments)
	w.mu.RUnlock()

	status := WorkspaceStatusView{
		ID:               w.id,
		Name:             chooseString(w.name, strings.TrimSuffix(filepath.Base(w.workspace), filepath.Ext(w.workspace))),
		Slug:             w.slug,
		Mode:             chooseString(w.mode, "bundle"),
		Root:             w.workspace,
		BundlePath:       chooseString(w.bundlePath, w.workspace),
		ScanCount:        scanCount,
		FindingHosts:     findingHosts,
		HasImportedScans: scanCount > 0,
	}
	if snapshot != nil {
		status.TotalFindings = snapshot.findingTotals.Total
	}
	if w.plugins != nil {
		status.JobCount = w.plugins.jobCount()
		status.RunningJobs = w.plugins.runningCount()
	}
	return status
}

func (w *workspace) scanCatalog() []ScanCatalogItem {
	w.mu.RLock()
	defer w.mu.RUnlock()

	items := make([]ScanCatalogItem, 0, len(w.scans))
	for i := len(w.scans) - 1; i >= 0; i-- {
		record := w.scans[i].record
		items = append(items, ScanCatalogItem{
			ID:         record.ID,
			Name:       record.Name,
			Kind:       record.Kind,
			Source:     record.Source,
			Scanner:    record.Scanner,
			Version:    record.Version,
			StartedAt:  displayTimestamp(record.StartedAt),
			ImportedAt: displayTimestamp(record.ImportedAt),
			Command:    record.Command,
			LiveHosts:  record.LiveHosts,
			Download:   "/scans/download?id=" + record.ID,
		})
	}
	return items
}

func (w *workspace) scanContent(id string) (string, string, []byte, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, scan := range w.scans {
		if scan.record.ID == id {
			return scan.record.Name, filepath.Ext(scan.record.Path), append([]byte(nil), scan.payload...), true
		}
	}
	return "", "", nil, false
}

func (w *workspace) artifactRoot() string {
	return w.runsDir
}

func (w *workspace) targetHosts(ips []string) []HostDetail {
	snapshot := w.currentSnapshot()
	hosts := make([]HostDetail, 0, len(ips))
	for _, ip := range uniqueStrings(ips) {
		host, ok := snapshot.host(ip)
		if !ok {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func (w *workspace) matchingHostIPs(filter HostFilter) []string {
	snapshot := w.currentSnapshot()
	indices := snapshot.matchingIndices(filter)
	ips := make([]string, 0, len(indices))
	for _, index := range indices {
		ips = append(ips, snapshot.records[index].summary.IP)
	}
	return uniqueStrings(ips)
}

func (w *workspace) profileTargets(pluginID string, profileScope string) ([]string, []string, string) {
	if profileScope == "domains" {
		domains := w.domainScopeTargets()
		if len(domains) == 0 {
			return nil, nil, ""
		}
		return domains, nil, fmt.Sprintf("profile · domains · %d %s", len(domains), pluralWord(len(domains), "target", "targets"))
	}

	snapshot := w.currentSnapshot()
	if snapshot == nil || len(snapshot.records) == 0 {
		return nil, nil, ""
	}

	rawTargets := make([]string, 0)
	hostIPs := make([]string, 0)
	targetStrategy := normalizedPluginDefinition(PluginDefinitionView{ID: pluginID}).TargetStrategy
	if w.plugins != nil {
		targetStrategy = w.plugins.targetStrategy(pluginID)
	}
	for _, record := range snapshot.records {
		include := false
		switch strings.TrimSpace(profileScope) {
		case "all-hosts":
			include = true
		case "web":
			include = len(record.detail.NucleiTargets) > 0
		case "coverage-gap":
			include = record.summary.Coverage.NeedsEnrichment
		case "high-exposure":
			include = record.summary.Exposure.Tone == "risk" || record.summary.Exposure.Tone == "warning"
		case "database":
			include = hostHasDatabasePort(record.detail.Ports)
		}
		if !include {
			continue
		}

		hostIPs = append(hostIPs, record.summary.IP)
		switch targetStrategy {
		case "web":
			rawTargets = append(rawTargets, record.detail.NucleiTargets...)
		default:
			rawTargets = append(rawTargets, record.summary.IP)
		}
	}

	hostIPs = uniqueStrings(hostIPs)
	rawTargets = uniqueStrings(rawTargets)
	targetCount := len(hostIPs)
	if len(rawTargets) > targetCount {
		targetCount = len(rawTargets)
	}
	if targetCount == 0 {
		return nil, nil, ""
	}

	summary := fmt.Sprintf("profile · %s · %d %s", strings.ReplaceAll(profileScope, "-", " "), targetCount, pluralWord(targetCount, "target", "targets"))
	return rawTargets, hostIPs, summary
}

func (w *workspace) domainScopeTargets() []string {
	records := w.scopeTargetsCatalog()
	items := make([]string, 0, len(records))
	for _, record := range records {
		switch strings.TrimSpace(record.Kind) {
		case "domain":
			items = append(items, record.Normalized)
		}
	}
	sort.Strings(items)
	return uniqueStrings(items)
}

func (w *workspace) hostJobs(ip string, limit int) []PluginJobView {
	if w.plugins == nil {
		return nil
	}
	return w.plugins.jobsForHost(ip, limit)
}

func (w *workspace) changeComparison(fromID string, toID string) (WorkspaceDiffView, CompareSelection, []ChangeCheckpointView, bool) {
	history := w.currentHistory()
	if history == nil {
		return WorkspaceDiffView{}, CompareSelection{}, nil, false
	}
	return history.comparison(fromID, toID)
}

func (w *workspace) latestChange() (WorkspaceDiffView, bool) {
	history := w.currentHistory()
	if history == nil {
		return WorkspaceDiffView{}, false
	}
	return history.latestDiff()
}

func chooseString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func normalizedFindingSource(source string) string {
	return chooseString(strings.TrimSpace(source), "integration")
}

func sanitizeFileStem(value string) string {
	cleaned := strings.ToLower(strings.TrimSpace(value))
	cleaned = strings.ReplaceAll(cleaned, " ", "-")
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", ";", "-", "\t", "-", "\n", "-", "\r", "-")
	cleaned = replacer.Replace(cleaned)
	cleaned = strings.Trim(cleaned, "-.")
	if cleaned == "" {
		return "scan"
	}
	return cleaned
}

func newWorkspaceID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UTC().UnixNano(), workspaceIDSequence.Add(1))
}

func displayTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "n/a"
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05", "Mon Jan 2 15:04:05 2006"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.Local().Format("2006-01-02 15:04:05")
		}
	}
	return value
}

func mergeStoredFindings(existing []storedNucleiFinding, incoming []storedNucleiFinding) []storedNucleiFinding {
	seen := map[string]struct{}{}
	merged := make([]storedNucleiFinding, 0, len(existing)+len(incoming))
	for _, finding := range append(existing, incoming...) {
		key := strings.Join([]string{
			normalizedFindingSource(finding.Source),
			finding.TemplateID,
			finding.Target,
			finding.MatchedAt,
			finding.Name,
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, finding)
	}

	sort.SliceStable(merged, func(left, right int) bool {
		if severityWeight(merged[left].Severity) != severityWeight(merged[right].Severity) {
			return severityWeight(merged[left].Severity) > severityWeight(merged[right].Severity)
		}
		if merged[left].Name != merged[right].Name {
			return merged[left].Name < merged[right].Name
		}
		return merged[left].Target < merged[right].Target
	})
	return merged
}

func resolveSeedFiles(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	resolved := make([]string, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		expanded := expandHomeDir(input)
		if hasGlobPattern(expanded) {
			matches, err := filepath.Glob(expanded)
			if err != nil {
				return nil, err
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("no files matched %q", input)
			}
			sort.Strings(matches)
			for _, match := range matches {
				if err := collectSeedPath(match, seen, &resolved); err != nil {
					return nil, err
				}
			}
			continue
		}

		if err := collectSeedPath(expanded, seen, &resolved); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

func collectSeedPath(path string, seen map[string]struct{}, resolved *[]string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !supportedImportPath(current) {
				return nil
			}
			if _, ok := seen[current]; ok {
				return nil
			}
			seen[current] = struct{}{}
			*resolved = append(*resolved, current)
			return nil
		})
	}
	if !supportedImportPath(path) {
		return fmt.Errorf("unsupported import source %q", path)
	}
	if _, ok := seen[path]; ok {
		return nil
	}
	seen[path] = struct{}{}
	*resolved = append(*resolved, path)
	return nil
}

func hasGlobPattern(value string) bool {
	return strings.ContainsAny(value, "*?[")
}

func expandHomeDir(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value[0] != '~' {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return value
	}
	if value == "~" {
		return home
	}
	if strings.HasPrefix(value, "~/") {
		return filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	return value
}
