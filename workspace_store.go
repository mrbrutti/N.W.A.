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

	_ "modernc.org/sqlite"
)

const (
	workspaceSchemaVersion = 1
	defaultWorkspaceFile   = "workspace.nwa"
)

type workspaceStore struct {
	path string
	db   *sql.DB
}

type persistedScan struct {
	Record  scanRecord
	Payload []byte
}

type workspaceStoreState struct {
	Scans           []persistedScan
	Enrichments     map[string]hostEnrichment
	SavedViews      []savedViewRecord
	Campaigns       []campaignRecord
	ScopeSeeds      []scopeSeedRecord
	ScopeTargets    []scopeTargetRecord
	TargetChunks    []targetChunkRecord
	Approvals       []approvalRecord
	Recommendations []recommendationRecord
}

func openWorkspaceStore(path string) (*workspaceStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	store := &workspaceStore{
		path: path,
		db:   db,
	}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *workspaceStore) init() error {
	statements := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=ON;`,
		`CREATE TABLE IF NOT EXISTS metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			imported_at TEXT NOT NULL,
			record_json TEXT NOT NULL,
			payload BLOB NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS scans_imported_at_idx ON scans(imported_at);`,
		`CREATE TABLE IF NOT EXISTS enrichments (
			host_ip TEXT PRIMARY KEY,
			payload_json TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS saved_views (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS saved_views_created_at_idx ON saved_views(created_at);`,
		`CREATE TABLE IF NOT EXISTS campaigns (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS campaigns_created_at_idx ON campaigns(created_at);`,
		`CREATE TABLE IF NOT EXISTS scope_seeds (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS scope_seeds_created_at_idx ON scope_seeds(created_at);`,
		`CREATE TABLE IF NOT EXISTS scope_targets (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS scope_targets_created_at_idx ON scope_targets(created_at);`,
		`CREATE TABLE IF NOT EXISTS target_chunks (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS target_chunks_created_at_idx ON target_chunks(created_at);`,
		`CREATE TABLE IF NOT EXISTS approvals (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS approvals_created_at_idx ON approvals(created_at);`,
		`CREATE TABLE IF NOT EXISTS recommendations (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS recommendations_created_at_idx ON recommendations(created_at);`,
		`CREATE TABLE IF NOT EXISTS jobs (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS jobs_created_at_idx ON jobs(created_at);`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS events_created_at_idx ON events(created_at);`,
		`CREATE TABLE IF NOT EXISTS observations (
			id TEXT PRIMARY KEY,
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
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS observations_created_at_idx ON observations(created_at);`,
		`CREATE INDEX IF NOT EXISTS observations_host_ip_idx ON observations(host_ip);`,
	}

	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}

	if _, err := s.db.Exec(`INSERT INTO metadata(key, value) VALUES('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprintf("%d", workspaceSchemaVersion)); err != nil {
		return err
	}
	return nil
}

func (s *workspaceStore) loadState() (workspaceStoreState, error) {
	state := workspaceStoreState{
		Enrichments: map[string]hostEnrichment{},
	}

	scanRows, err := s.db.Query(`SELECT record_json, payload FROM scans ORDER BY imported_at ASC`)
	if err != nil {
		return state, err
	}
	defer scanRows.Close()

	for scanRows.Next() {
		var (
			recordJSON string
			payload    []byte
		)
		if err := scanRows.Scan(&recordJSON, &payload); err != nil {
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
	if err := scanRows.Err(); err != nil {
		return state, err
	}

	enrichmentRows, err := s.db.Query(`SELECT host_ip, payload_json FROM enrichments`)
	if err != nil {
		return state, err
	}
	defer enrichmentRows.Close()

	for enrichmentRows.Next() {
		var (
			hostIP      string
			payloadJSON string
			enrichment  hostEnrichment
		)
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

	if state.SavedViews, err = loadJSONRows[savedViewRecord](s.db, `SELECT payload_json FROM saved_views ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	if state.Campaigns, err = loadJSONRows[campaignRecord](s.db, `SELECT payload_json FROM campaigns ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	if state.ScopeSeeds, err = loadJSONRows[scopeSeedRecord](s.db, `SELECT payload_json FROM scope_seeds ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	if state.ScopeTargets, err = loadJSONRows[scopeTargetRecord](s.db, `SELECT payload_json FROM scope_targets ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	if state.TargetChunks, err = loadJSONRows[targetChunkRecord](s.db, `SELECT payload_json FROM target_chunks ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	if state.Approvals, err = loadJSONRows[approvalRecord](s.db, `SELECT payload_json FROM approvals ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	if state.Recommendations, err = loadJSONRows[recommendationRecord](s.db, `SELECT payload_json FROM recommendations ORDER BY created_at ASC`); err != nil {
		return state, err
	}
	return state, nil
}

func (s *workspaceStore) saveState(
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
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = replaceScans(tx, scans); err != nil {
		return err
	}
	if err = replaceEnrichments(tx, enrichments); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "saved_views", savedViews, func(item savedViewRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "campaigns", campaigns, func(item campaignRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "scope_seeds", scopeSeeds, func(item scopeSeedRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "scope_targets", scopeTargets, func(item scopeTargetRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "target_chunks", targetChunks, func(item targetChunkRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "approvals", approvals, func(item approvalRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceJSONPayloadTable(tx, "recommendations", recommendations, func(item recommendationRecord) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *workspaceStore) loadEvents() ([]workspaceEvent, error) {
	return loadJSONRows[workspaceEvent](s.db, `SELECT payload_json FROM events ORDER BY created_at ASC`)
}

func (s *workspaceStore) replaceEvents(events []workspaceEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = replaceJSONPayloadTable(tx, "events", events, func(item workspaceEvent) (string, string, error) {
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	if err = replaceObservationTable(tx, events); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *workspaceStore) appendEvent(event workspaceEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.Exec(`INSERT OR REPLACE INTO events(id, created_at, payload_json) VALUES(?, ?, ?)`, event.ID, event.CreatedAt, string(payload)); err != nil {
		return err
	}
	if err = appendObservations(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *workspaceStore) loadJobs() ([]*pluginJob, error) {
	return loadJSONRows[*pluginJob](s.db, `SELECT payload_json FROM jobs ORDER BY created_at ASC`)
}

func (s *workspaceStore) loadPreferences() (workspacePreferences, error) {
	row := s.db.QueryRow(`SELECT value FROM metadata WHERE key = 'preferences_json'`)

	var payload string
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return defaultWorkspacePreferences(), nil
		}
		return workspacePreferences{}, err
	}

	preferences := defaultWorkspacePreferences()
	if err := json.Unmarshal([]byte(payload), &preferences); err != nil {
		return workspacePreferences{}, err
	}
	preferences.DefaultLanding = normalizeLandingPreference(preferences.DefaultLanding)
	return preferences, nil
}

func (s *workspaceStore) savePreferences(preferences workspacePreferences) error {
	preferences.DefaultLanding = normalizeLandingPreference(preferences.DefaultLanding)
	payload, err := json.Marshal(preferences)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO metadata(key, value) VALUES('preferences_json', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		string(payload),
	)
	return err
}

func (s *workspaceStore) toolCommandTemplate(pluginID string) (string, error) {
	_ = pluginID
	return "", nil
}

func (s *workspaceStore) customToolDefinitions() ([]PluginDefinitionView, error) {
	return nil, nil
}

func (s *workspaceStore) saveJobs(jobs []*pluginJob) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = replaceJSONPayloadTable(tx, "jobs", jobs, func(item *pluginJob) (string, string, error) {
		if item == nil {
			return "", "", errors.New("nil job")
		}
		return item.ID, item.CreatedAt, nil
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceScans(tx *sql.Tx, scans []managedScan) error {
	if _, err := tx.Exec(`DELETE FROM scans`); err != nil {
		return err
	}

	statement, err := tx.Prepare(`INSERT INTO scans(id, imported_at, record_json, payload) VALUES(?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer statement.Close()

	for _, scan := range scans {
		recordJSON, err := json.Marshal(scan.record)
		if err != nil {
			return err
		}
		if _, err := statement.Exec(scan.record.ID, scan.record.ImportedAt, string(recordJSON), scan.payload); err != nil {
			return err
		}
	}
	return nil
}

func replaceEnrichments(tx *sql.Tx, enrichments map[string]hostEnrichment) error {
	if _, err := tx.Exec(`DELETE FROM enrichments`); err != nil {
		return err
	}
	statement, err := tx.Prepare(`INSERT INTO enrichments(host_ip, payload_json) VALUES(?, ?)`)
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
		if _, err := statement.Exec(key, string(payload)); err != nil {
			return err
		}
	}
	return nil
}

func replaceJSONPayloadTable[T any](tx *sql.Tx, table string, values []T, meta func(T) (string, string, error)) error {
	if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
		return err
	}

	statement, err := tx.Prepare(`INSERT INTO ` + table + `(id, created_at, payload_json) VALUES(?, ?, ?)`)
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
		if _, err := statement.Exec(id, createdAt, string(payload)); err != nil {
			return err
		}
	}
	return nil
}

func replaceObservationTable(tx *sql.Tx, events []workspaceEvent) error {
	if _, err := tx.Exec(`DELETE FROM observations`); err != nil {
		return err
	}
	for _, event := range events {
		if err := appendObservations(tx, event); err != nil {
			return err
		}
	}
	return nil
}

func appendObservations(tx *sql.Tx, event workspaceEvent) error {
	statement, err := tx.Prepare(`INSERT OR REPLACE INTO observations(id, event_id, created_at, kind, source, host_ip, port, protocol, label, detail, severity, href, payload_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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

func loadJSONRows[T any](db *sql.DB, query string) ([]T, error) {
	rows, err := db.Query(query)
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

func resolveWorkspacePath(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		target = defaultWorkspaceFile
	}
	target = expandHomeDir(target)

	if info, err := os.Stat(target); err == nil && info.IsDir() {
		target = filepath.Join(target, filepath.Base(target)+".nwa")
	} else if err == nil && !info.IsDir() {
		// keep explicit file targets
	} else if errors.Is(err, os.ErrNotExist) && filepath.Ext(target) == "" {
		target += ".nwa"
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	absPath, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return "", err
	}
	return absPath, nil
}

func deriveWorkspaceArtifactsDir(workspacePath string) string {
	ext := filepath.Ext(workspacePath)
	if ext == "" {
		return workspacePath + ".artifacts"
	}
	return strings.TrimSuffix(workspacePath, ext) + ".artifacts"
}

func supportedImportPath(path string) bool {
	switch strings.ToLower(strings.TrimSpace(filepath.Ext(path))) {
	case ".xml", ".nessus", ".csv", ".json", ".jsonl", ".ndjson", ".txt", ".lst", ".list":
		return true
	default:
		return false
	}
}
