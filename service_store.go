package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type workspaceMetaRecord struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	BundlePath  string `json:"bundle_path,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type serviceStore struct {
	driver  string
	dsn     string
	dataDir string
	db      *sql.DB
}

type serviceWorkspaceStore struct {
	service     *serviceStore
	workspaceID string
}

func openServiceStore(dsn string, dataDir string) (*serviceStore, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		dataDir = ".nwa-service"
	}
	absDataDir, err := filepath.Abs(expandHomeDir(dataDir))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absDataDir, 0o755); err != nil {
		return nil, err
	}

	driver := "sqlite"
	if isPostgresDSN(dsn) {
		driver = "pgx"
	} else {
		if strings.TrimSpace(dsn) == "" {
			dsn = filepath.Join(absDataDir, "command-center.sqlite")
		} else {
			dsn = expandHomeDir(dsn)
		}
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	store := &serviceStore{
		driver:  driver,
		dsn:     dsn,
		dataDir: absDataDir,
		db:      db,
	}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *serviceStore) init() error {
	if s.driver == "sqlite" {
		for _, statement := range []string{
			`PRAGMA journal_mode=WAL;`,
			`PRAGMA busy_timeout=5000;`,
			`PRAGMA foreign_keys=ON;`,
		} {
			if _, err := s.db.Exec(statement); err != nil {
				return err
			}
		}
	}

	payloadType := "BLOB"
	if s.driver == "pgx" {
		payloadType = "BYTEA"
	}

	statements := []string{
		`CREATE TABLE IF NOT EXISTS workspaces (
			id TEXT PRIMARY KEY,
			slug TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			bundle_path TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			settings_json TEXT NOT NULL DEFAULT '{}'
		);`,
		`CREATE TABLE IF NOT EXISTS scans (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			imported_at TEXT NOT NULL,
			record_json TEXT NOT NULL,
			payload ` + payloadType + ` NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS scans_workspace_imported_idx ON scans(workspace_id, imported_at);`,
		`CREATE TABLE IF NOT EXISTS enrichments (
			workspace_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, host_ip)
		);`,
		`CREATE TABLE IF NOT EXISTS saved_views (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS saved_views_workspace_created_idx ON saved_views(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS campaigns (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS campaigns_workspace_created_idx ON campaigns(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS scope_seeds (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS scope_seeds_workspace_created_idx ON scope_seeds(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS scope_targets (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS scope_targets_workspace_created_idx ON scope_targets(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS target_chunks (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS target_chunks_workspace_created_idx ON target_chunks(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS approvals (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS approvals_workspace_created_idx ON approvals(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS recommendations (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS recommendations_workspace_created_idx ON recommendations(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS jobs (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS jobs_workspace_created_idx ON jobs(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS events (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS events_workspace_created_idx ON events(workspace_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS observations (
			workspace_id TEXT NOT NULL,
			id TEXT NOT NULL,
			event_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			kind TEXT NOT NULL,
			source TEXT NOT NULL,
			host_ip TEXT NOT NULL DEFAULT '',
			port TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT '',
			label TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL DEFAULT '',
			href TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL,
			PRIMARY KEY(workspace_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS observations_workspace_created_idx ON observations(workspace_id, created_at);`,
		`CREATE INDEX IF NOT EXISTS observations_workspace_host_idx ON observations(workspace_id, host_ip);`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func isPostgresDSN(dsn string) bool {
	normalized := strings.ToLower(strings.TrimSpace(dsn))
	return strings.HasPrefix(normalized, "postgres://") || strings.HasPrefix(normalized, "postgresql://")
}

func (s *serviceStore) workspaceArtifactsDir(workspaceID string) string {
	return filepath.Join(s.dataDir, "artifacts", workspaceID)
}

func (s *serviceStore) workspaceBundlePath(slug string) string {
	return filepath.Join(s.dataDir, "bundles", slug+".nwa")
}

func (s *serviceStore) placeholder(index int) string {
	if s.driver == "pgx" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (s *serviceStore) listWorkspaces() ([]workspaceMetaRecord, error) {
	query := `SELECT id, slug, name, description, bundle_path, created_at, updated_at FROM workspaces ORDER BY updated_at DESC, created_at DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]workspaceMetaRecord, 0)
	for rows.Next() {
		var item workspaceMetaRecord
		if err := rows.Scan(&item.ID, &item.Slug, &item.Name, &item.Description, &item.BundlePath, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *serviceStore) workspaceBySlug(slug string) (workspaceMetaRecord, error) {
	return s.workspaceByField("slug", slug)
}

func (s *serviceStore) workspaceByID(id string) (workspaceMetaRecord, error) {
	return s.workspaceByField("id", id)
}

func (s *serviceStore) workspaceByField(field string, value string) (workspaceMetaRecord, error) {
	field = strings.TrimSpace(field)
	value = strings.TrimSpace(value)
	if field == "" || value == "" {
		return workspaceMetaRecord{}, sql.ErrNoRows
	}
	query := fmt.Sprintf(`SELECT id, slug, name, description, bundle_path, created_at, updated_at FROM workspaces WHERE %s = %s`, field, s.placeholder(1))
	row := s.db.QueryRow(query, value)
	var item workspaceMetaRecord
	if err := row.Scan(&item.ID, &item.Slug, &item.Name, &item.Description, &item.BundlePath, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return workspaceMetaRecord{}, err
	}
	return item, nil
}

func (s *serviceStore) createWorkspace(name string, description string) (workspaceMetaRecord, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Workspace " + time.Now().UTC().Format("2006-01-02 15:04")
	}
	slugBase := slugifyWorkspaceName(name)
	slug, err := s.nextWorkspaceSlug(slugBase)
	if err != nil {
		return workspaceMetaRecord{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	item := workspaceMetaRecord{
		ID:          newWorkspaceID("ws"),
		Slug:        slug,
		Name:        name,
		Description: strings.TrimSpace(description),
		BundlePath:  s.workspaceBundlePath(slug),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	query := `INSERT INTO workspaces(id, slug, name, description, bundle_path, created_at, updated_at, settings_json) VALUES(` +
		s.placeholder(1) + `, ` + s.placeholder(2) + `, ` + s.placeholder(3) + `, ` + s.placeholder(4) + `, ` + s.placeholder(5) + `, ` + s.placeholder(6) + `, ` + s.placeholder(7) + `, '{}')`
	if _, err := s.db.Exec(query, item.ID, item.Slug, item.Name, item.Description, item.BundlePath, item.CreatedAt, item.UpdatedAt); err != nil {
		return workspaceMetaRecord{}, err
	}
	return item, nil
}

func (s *serviceStore) nextWorkspaceSlug(base string) (string, error) {
	slug := slugifyWorkspaceName(base)
	if slug == "" {
		slug = "workspace"
	}
	candidate := slug
	for index := 2; index < 1000; index++ {
		_, err := s.workspaceBySlug(candidate)
		if errors.Is(err, sql.ErrNoRows) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
		candidate = fmt.Sprintf("%s-%d", slug, index)
	}
	return "", errors.New("unable to allocate workspace slug")
}

func (s *serviceStore) ensureWorkspace(name string) (workspaceMetaRecord, error) {
	slug := slugifyWorkspaceName(name)
	if slug != "" {
		if item, err := s.workspaceBySlug(slug); err == nil {
			return item, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return workspaceMetaRecord{}, err
		}
	}
	return s.createWorkspace(name, "")
}

func (s *serviceStore) workspaceStore(meta workspaceMetaRecord) workspaceStateStore {
	return &serviceWorkspaceStore{
		service:     s,
		workspaceID: meta.ID,
	}
}

func (s *serviceStore) exportWorkspaceBundle(meta workspaceMetaRecord) error {
	store := s.workspaceStore(meta)
	state, err := store.loadState()
	if err != nil {
		return err
	}
	events, err := store.loadEvents()
	if err != nil {
		return err
	}
	jobs, err := store.loadJobs()
	if err != nil {
		return err
	}
	preferences, err := store.loadPreferences()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(meta.BundlePath), 0o755); err != nil {
		return err
	}
	bundle, err := openWorkspaceStore(meta.BundlePath)
	if err != nil {
		return err
	}
	defer bundle.db.Close()
	if err := bundle.saveState(managedScansFromPersisted(state.Scans), state.Enrichments, state.SavedViews, state.Campaigns, state.ScopeSeeds, state.ScopeTargets, state.TargetChunks, state.Approvals, state.Recommendations); err != nil {
		return err
	}
	if err := bundle.replaceEvents(events); err != nil {
		return err
	}
	if err := bundle.saveJobs(jobs); err != nil {
		return err
	}
	return bundle.savePreferences(preferences)
}

func (s *serviceStore) importWorkspaceBundle(bundlePath string, name string) (workspaceMetaRecord, error) {
	bundlePath = expandHomeDir(strings.TrimSpace(bundlePath))
	store, err := openWorkspaceStore(bundlePath)
	if err != nil {
		return workspaceMetaRecord{}, err
	}
	defer store.db.Close()

	state, err := store.loadState()
	if err != nil {
		return workspaceMetaRecord{}, err
	}
	events, err := store.loadEvents()
	if err != nil {
		return workspaceMetaRecord{}, err
	}
	jobs, err := store.loadJobs()
	if err != nil {
		return workspaceMetaRecord{}, err
	}
	preferences, err := store.loadPreferences()
	if err != nil {
		return workspaceMetaRecord{}, err
	}

	if strings.TrimSpace(name) == "" {
		name = strings.TrimSuffix(filepath.Base(bundlePath), filepath.Ext(bundlePath))
	}
	meta, err := s.createWorkspace(name, "Imported from bundle")
	if err != nil {
		return workspaceMetaRecord{}, err
	}
	workspaceStore := s.workspaceStore(meta)
	if err := workspaceStore.saveState(managedScansFromPersisted(state.Scans), state.Enrichments, state.SavedViews, state.Campaigns, state.ScopeSeeds, state.ScopeTargets, state.TargetChunks, state.Approvals, state.Recommendations); err != nil {
		return workspaceMetaRecord{}, err
	}
	if err := workspaceStore.replaceEvents(events); err != nil {
		return workspaceMetaRecord{}, err
	}
	if err := workspaceStore.saveJobs(jobs); err != nil {
		return workspaceMetaRecord{}, err
	}
	if err := workspaceStore.savePreferences(preferences); err != nil {
		return workspaceMetaRecord{}, err
	}
	return meta, s.exportWorkspaceBundle(meta)
}

func (s *serviceStore) close() error {
	return s.db.Close()
}

func (s *serviceWorkspaceStore) loadState() (workspaceStoreState, error) {
	state := workspaceStoreState{
		Enrichments: map[string]hostEnrichment{},
	}

	query := `SELECT record_json, payload FROM scans WHERE workspace_id = ` + s.service.placeholder(1) + ` ORDER BY imported_at ASC`
	rows, err := s.service.db.Query(query, s.workspaceID)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var recordJSON string
		var payload []byte
		if err := rows.Scan(&recordJSON, &payload); err != nil {
			return state, err
		}
		var record scanRecord
		if err := json.Unmarshal([]byte(recordJSON), &record); err != nil {
			return state, err
		}
		state.Scans = append(state.Scans, persistedScan{
			Record:  record,
			Payload: append([]byte(nil), payload...),
		})
	}
	if err := rows.Err(); err != nil {
		return state, err
	}

	enrichmentQuery := `SELECT host_ip, payload_json FROM enrichments WHERE workspace_id = ` + s.service.placeholder(1)
	enrichmentRows, err := s.service.db.Query(enrichmentQuery, s.workspaceID)
	if err != nil {
		return state, err
	}
	defer enrichmentRows.Close()
	for enrichmentRows.Next() {
		var hostIP string
		var payloadJSON string
		var enrichment hostEnrichment
		if err := enrichmentRows.Scan(&hostIP, &payloadJSON); err != nil {
			return state, err
		}
		if err := json.Unmarshal([]byte(payloadJSON), &enrichment); err != nil {
			return state, err
		}
		state.Enrichments[hostIP] = enrichment
	}
	if err := enrichmentRows.Err(); err != nil {
		return state, err
	}

	if state.SavedViews, err = loadServiceJSONRows[savedViewRecord](s, "saved_views"); err != nil {
		return state, err
	}
	if state.Campaigns, err = loadServiceJSONRows[campaignRecord](s, "campaigns"); err != nil {
		return state, err
	}
	if state.ScopeSeeds, err = loadServiceJSONRows[scopeSeedRecord](s, "scope_seeds"); err != nil {
		return state, err
	}
	if state.ScopeTargets, err = loadServiceJSONRows[scopeTargetRecord](s, "scope_targets"); err != nil {
		return state, err
	}
	if state.TargetChunks, err = loadServiceJSONRows[targetChunkRecord](s, "target_chunks"); err != nil {
		return state, err
	}
	if state.Approvals, err = loadServiceJSONRows[approvalRecord](s, "approvals"); err != nil {
		return state, err
	}
	if state.Recommendations, err = loadServiceJSONRows[recommendationRecord](s, "recommendations"); err != nil {
		return state, err
	}
	return state, nil
}

func (s *serviceWorkspaceStore) saveState(
	scans []managedScan,
	enrichments map[string]hostEnrichment,
	savedViews []savedViewRecord,
	campaigns []campaignRecord,
	scopeSeeds []scopeSeedRecord,
	scopeTargets []scopeTargetRecord,
	targetChunks []targetChunkRecord,
	approvals []approvalRecord,
	recommendations []recommendationRecord,
) error {
	tx, err := s.service.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = s.replaceScans(tx, scans); err != nil {
		return err
	}
	if err = s.replaceEnrichments(tx, enrichments); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "saved_views", savedViews, func(item savedViewRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "campaigns", campaigns, func(item campaignRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "scope_seeds", scopeSeeds, func(item scopeSeedRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "scope_targets", scopeTargets, func(item scopeTargetRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "target_chunks", targetChunks, func(item targetChunkRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "approvals", approvals, func(item approvalRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceServiceJSONPayloadTable(tx, s, "recommendations", recommendations, func(item recommendationRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}

	updateQuery := `UPDATE workspaces SET updated_at = ` + s.service.placeholder(1) + ` WHERE id = ` + s.service.placeholder(2)
	if _, err = tx.Exec(updateQuery, time.Now().UTC().Format(time.RFC3339), s.workspaceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *serviceWorkspaceStore) loadEvents() ([]workspaceEvent, error) {
	return loadServiceJSONRows[workspaceEvent](s, "events")
}

func (s *serviceWorkspaceStore) replaceEvents(events []workspaceEvent) error {
	tx, err := s.service.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = replaceServiceJSONPayloadTable(tx, s, "events", events, func(item workspaceEvent) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = s.replaceObservations(tx, events); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *serviceWorkspaceStore) appendEvent(event workspaceEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	tx, err := s.service.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	query := `INSERT INTO events(workspace_id, id, created_at, payload_json) VALUES(` + s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `)
		ON CONFLICT(workspace_id, id) DO UPDATE SET created_at = excluded.created_at, payload_json = excluded.payload_json`
	if _, err = tx.Exec(query, s.workspaceID, event.ID, event.CreatedAt, string(payload)); err != nil {
		return err
	}
	if err = s.appendObservations(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *serviceWorkspaceStore) loadJobs() ([]*pluginJob, error) {
	return loadServiceJSONRows[*pluginJob](s, "jobs")
}

func (s *serviceWorkspaceStore) upsertJob(job *pluginJob) error {
	if job == nil {
		return errors.New("nil job")
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return err
	}
	query := `INSERT INTO jobs(workspace_id, id, created_at, payload_json) VALUES(` + s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `)`
	if s.service.driver == "pgx" {
		query += ` ON CONFLICT(workspace_id, id) DO UPDATE SET created_at=EXCLUDED.created_at, payload_json=EXCLUDED.payload_json`
	} else {
		query += ` ON CONFLICT(workspace_id, id) DO UPDATE SET created_at=excluded.created_at, payload_json=excluded.payload_json`
	}
	_, err = s.service.db.Exec(query, s.workspaceID, job.ID, job.CreatedAt, string(payload))
	return err
}

func (s *serviceWorkspaceStore) claimQueuedJobs(workerID string, limit int, leaseUntil string) ([]*pluginJob, error) {
	tx, err := s.service.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	query := `SELECT id, payload_json FROM jobs WHERE workspace_id = ` + s.service.placeholder(1) + ` ORDER BY created_at ASC`
	rows, err := tx.Query(query, s.workspaceID)
	if err != nil {
		return nil, err
	}
	type jobRow struct {
		id      string
		payload string
	}
	jobRows := make([]jobRow, 0)
	for rows.Next() {
		var row jobRow
		if err := rows.Scan(&row.id, &row.payload); err != nil {
			_ = rows.Close()
			return nil, err
		}
		jobRows = append(jobRows, row)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	claimed := make([]*pluginJob, 0, maxInt(limit, 1))
	for _, row := range jobRows {
		if limit > 0 && len(claimed) >= limit {
			break
		}

		var job pluginJob
		if err := json.Unmarshal([]byte(row.payload), &job); err != nil {
			return nil, err
		}
		if !jobClaimable(&job, now) {
			continue
		}

		job.Status = jobRunning
		job.WorkerMode = chooseString(strings.TrimSpace(job.WorkerMode), "central")
		job.WorkerID = chooseString(strings.TrimSpace(job.WorkerID), workerID)
		job.LeaseOwner = workerID
		job.LeaseExpiresAt = leaseUntil
		job.UpdatedAt = now
		if strings.TrimSpace(job.StartedAt) == "" {
			job.StartedAt = now
		}

		newPayload, marshalErr := json.Marshal(&job)
		if marshalErr != nil {
			return nil, marshalErr
		}
		updateQuery := `UPDATE jobs SET payload_json = ` + s.service.placeholder(1) + ` WHERE workspace_id = ` + s.service.placeholder(2) + ` AND id = ` + s.service.placeholder(3) + ` AND payload_json = ` + s.service.placeholder(4)
		result, execErr := tx.Exec(updateQuery, string(newPayload), s.workspaceID, row.id, row.payload)
		if execErr != nil {
			return nil, execErr
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return nil, rowsErr
		}
		if affected == 0 {
			continue
		}
		claimed = append(claimed, cloneJob(&job))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

func (s *serviceWorkspaceStore) saveJobs(jobs []*pluginJob) error {
	tx, err := s.service.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = replaceServiceJSONPayloadTable(tx, s, "jobs", jobs, func(item *pluginJob) (string, string, error) {
		if item == nil {
			return "", "", errors.New("nil job")
		}
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *serviceWorkspaceStore) loadPreferences() (workspacePreferences, error) {
	query := `SELECT settings_json FROM workspaces WHERE id = ` + s.service.placeholder(1)
	row := s.service.db.QueryRow(query, s.workspaceID)
	var payload string
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return defaultWorkspacePreferences(), nil
		}
		return workspacePreferences{}, err
	}
	if strings.TrimSpace(payload) == "" {
		return defaultWorkspacePreferences(), nil
	}
	preferences := defaultWorkspacePreferences()
	if err := json.Unmarshal([]byte(payload), &preferences); err != nil {
		return workspacePreferences{}, err
	}
	preferences.DefaultLanding = normalizeLandingPreference(preferences.DefaultLanding)
	return preferences, nil
}

func (s *serviceWorkspaceStore) savePreferences(preferences workspacePreferences) error {
	preferences.DefaultLanding = normalizeLandingPreference(preferences.DefaultLanding)
	payload, err := json.Marshal(preferences)
	if err != nil {
		return err
	}
	query := `UPDATE workspaces SET settings_json = ` + s.service.placeholder(1) + `, updated_at = ` + s.service.placeholder(2) + ` WHERE id = ` + s.service.placeholder(3)
	_, err = s.service.db.Exec(query, string(payload), time.Now().UTC().Format(time.RFC3339), s.workspaceID)
	return err
}

func (s *serviceWorkspaceStore) toolCommandTemplate(pluginID string) (string, error) {
	return s.service.platformToolCommandTemplate(pluginID)
}

func (s *serviceWorkspaceStore) customToolDefinitions() ([]PluginDefinitionView, error) {
	return s.service.platformCustomToolDefinitions()
}

func (s *serviceStore) platformToolCommandTemplate(pluginID string) (string, error) {
	store, err := newPlatformStore(s)
	if err != nil {
		return "", err
	}
	return store.toolCommandTemplate(pluginID)
}

func (s *serviceStore) platformCustomToolDefinitions() ([]PluginDefinitionView, error) {
	store, err := newPlatformStore(s)
	if err != nil {
		return nil, err
	}
	return store.listCustomToolDefinitions()
}

func loadServiceJSONRows[T any](store *serviceWorkspaceStore, table string) ([]T, error) {
	query := `SELECT payload_json FROM ` + table + ` WHERE workspace_id = ` + store.service.placeholder(1) + ` ORDER BY created_at ASC`
	rows, err := store.service.db.Query(query, store.workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	values := make([]T, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var value T
		if err := json.Unmarshal([]byte(payload), &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func (s *serviceWorkspaceStore) replaceScans(tx *sql.Tx, scans []managedScan) error {
	deleteQuery := `DELETE FROM scans WHERE workspace_id = ` + s.service.placeholder(1)
	if _, err := tx.Exec(deleteQuery, s.workspaceID); err != nil {
		return err
	}
	insertQuery := `INSERT INTO scans(workspace_id, id, imported_at, record_json, payload) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `)`
	statement, err := tx.Prepare(insertQuery)
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, scan := range scans {
		recordJSON, err := json.Marshal(scan.record)
		if err != nil {
			return err
		}
		if _, err := statement.Exec(s.workspaceID, scan.record.ID, scan.record.ImportedAt, string(recordJSON), scan.payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *serviceWorkspaceStore) replaceEnrichments(tx *sql.Tx, enrichments map[string]hostEnrichment) error {
	deleteQuery := `DELETE FROM enrichments WHERE workspace_id = ` + s.service.placeholder(1)
	if _, err := tx.Exec(deleteQuery, s.workspaceID); err != nil {
		return err
	}
	insertQuery := `INSERT INTO enrichments(workspace_id, host_ip, payload_json) VALUES(` + s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `)`
	statement, err := tx.Prepare(insertQuery)
	if err != nil {
		return err
	}
	defer statement.Close()

	keys := make([]string, 0, len(enrichments))
	for key := range enrichments {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		payload, err := json.Marshal(enrichments[key])
		if err != nil {
			return err
		}
		if _, err := statement.Exec(s.workspaceID, key, string(payload)); err != nil {
			return err
		}
	}
	return nil
}

func replaceServiceJSONPayloadTable[T any](tx *sql.Tx, store *serviceWorkspaceStore, table string, values []T, meta func(T) (string, string, error)) error {
	deleteQuery := `DELETE FROM ` + table + ` WHERE workspace_id = ` + store.service.placeholder(1)
	if _, err := tx.Exec(deleteQuery, store.workspaceID); err != nil {
		return err
	}
	insertQuery := `INSERT INTO ` + table + `(workspace_id, id, created_at, payload_json) VALUES(` + store.service.placeholder(1) + `, ` + store.service.placeholder(2) + `, ` + store.service.placeholder(3) + `, ` + store.service.placeholder(4) + `)`
	statement, err := tx.Prepare(insertQuery)
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, value := range values {
		id, createdAt, err := meta(value)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := statement.Exec(store.workspaceID, id, createdAt, string(payload)); err != nil {
			return err
		}
	}
	return nil
}

func (s *serviceWorkspaceStore) replaceObservations(tx *sql.Tx, events []workspaceEvent) error {
	deleteQuery := `DELETE FROM observations WHERE workspace_id = ` + s.service.placeholder(1)
	if _, err := tx.Exec(deleteQuery, s.workspaceID); err != nil {
		return err
	}
	for _, event := range events {
		if err := s.appendObservations(tx, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *serviceWorkspaceStore) appendObservations(tx *sql.Tx, event workspaceEvent) error {
	insertQuery := `INSERT INTO observations(workspace_id, id, event_id, created_at, kind, source, host_ip, port, protocol, label, detail, severity, href, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `, ` + s.service.placeholder(11) + `, ` + s.service.placeholder(12) + `, ` + s.service.placeholder(13) + `, ` + s.service.placeholder(14) + `)
		ON CONFLICT(workspace_id, id) DO UPDATE SET created_at = excluded.created_at, payload_json = excluded.payload_json, detail = excluded.detail, severity = excluded.severity, href = excluded.href`
	statement, err := tx.Prepare(insertQuery)
	if err != nil {
		return err
	}
	defer statement.Close()

	for index, observation := range event.Observations {
		observationID := strings.TrimSpace(observation.ID)
		if observationID == "" {
			observationID = fmt.Sprintf("%s-%d", event.ID, index)
		}
		payload, err := json.Marshal(observation)
		if err != nil {
			return err
		}
		if _, err := statement.Exec(
			s.workspaceID,
			observationID,
			event.ID,
			event.CreatedAt,
			observation.Kind,
			chooseString(observation.Source, event.Label),
			strings.TrimSpace(observation.HostIP),
			strings.TrimSpace(observation.Port),
			strings.TrimSpace(observation.Protocol),
			observation.Label,
			observation.Detail,
			observation.Severity,
			observation.Href,
			string(payload),
		); err != nil {
			return err
		}
	}
	return nil
}

func slugifyWorkspaceName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	builder := strings.Builder{}
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func managedScansFromPersisted(scans []persistedScan) []managedScan {
	items := make([]managedScan, 0, len(scans))
	for _, scan := range scans {
		items = append(items, managedScan{
			record:  scan.Record,
			payload: append([]byte(nil), scan.Payload...),
		})
	}
	return items
}
