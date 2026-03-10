package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type platformStore struct {
	service *serviceStore
}

type platformUserRecord struct {
	ID           string
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string
	IsAdmin      bool
	Status       string
	CreatedAt    string
	UpdatedAt    string
	LastLoginAt  string
}

type platformSessionRecord struct {
	ID         string
	UserID     string
	Token      string
	CreatedAt  string
	ExpiresAt  string
	LastSeenAt string
	UserAgent  string
	RemoteAddr string
}

type platformEngagementRecord struct {
	ID                string
	Slug              string
	Name              string
	Description       string
	ScopeSummary      string
	Status            string
	LegacyWorkspaceID string
	CreatedAt         string
	UpdatedAt         string
}

type platformMembershipRecord struct {
	EngagementID string
	UserID       string
	Role         string
	CreatedAt    string
}

type platformWorkerRecord struct {
	ID         string
	Label      string
	Mode       string
	Zone       string
	Status     string
	Detail     string
	LastSeenAt string
	UpdatedAt  string
}

type platformSourceRecord struct {
	ID         string
	Name       string
	Kind       string
	Scanner    string
	LiveHosts  int
	ImportedAt string
	Payload    string
}

type platformRunRecord struct {
	ID          string
	ToolID      string
	ToolLabel   string
	Status      string
	Stage       string
	ChunkID     string
	ChunkName   string
	TargetCount int
	Summary     string
	Error       string
	CreatedAt   string
	StartedAt   string
	FinishedAt  string
	WorkerMode  string
	WorkerZone  string
	Payload     string
}

type platformZoneRecord struct {
	ID        string
	Name      string
	Kind      string
	Scope     string
	HostCount int
	CreatedAt string
	UpdatedAt string
}

type platformHostRecord struct {
	IP              string
	DisplayName     string
	OSName          string
	ExposureLabel   string
	ExposureTone    string
	ExposureScore   int
	CoverageLabel   string
	SourceCount     int
	OpenPortCount   int
	FindingTotal    int
	FindingCritical int
	FindingHigh     int
	ZoneCount       int
	UpdatedAt       string
	Payload         string
}

type platformPortRecord struct {
	HostIP       string
	Protocol     string
	PortNumber   int
	Label        string
	ServiceName  string
	State        string
	FindingTotal int
	UpdatedAt    string
	Payload      string
}

type platformFindingRecord struct {
	ID          string
	TemplateID  string
	Name        string
	Source      string
	Severity    string
	Occurrences int
	Hosts       int
	Ports       int
	FirstSeen   string
	LastSeen    string
	UpdatedAt   string
	Payload     string
}

type platformFindingOccurrenceRecord struct {
	FindingID  string
	HostIP     string
	Protocol   string
	PortNumber int
	Target     string
	MatchedAt  string
	Payload    string
}

type platformScopeSeedRecord struct {
	ID        string
	CreatedAt string
	Payload   string
}

type platformScopeTargetRecord struct {
	ID        string
	CreatedAt string
	Payload   string
}

type platformChunkRecord struct {
	ID        string
	CreatedAt string
	Payload   string
}

type platformApprovalRow struct {
	ID        string
	CreatedAt string
	Payload   string
}

type platformAuditRecord struct {
	ID           string
	UserID       string
	EngagementID string
	Kind         string
	Summary      string
	CreatedAt    string
}

func newPlatformStore(service *serviceStore) (*platformStore, error) {
	store := &platformStore{service: service}
	if err := store.init(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *platformStore) init() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS platform_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			user_agent TEXT NOT NULL DEFAULT '',
			remote_addr TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS platform_sessions_user_idx ON platform_sessions(user_id);`,
		`CREATE TABLE IF NOT EXISTS platform_engagements (
			id TEXT PRIMARY KEY,
			slug TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			scope_summary TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			legacy_workspace_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS platform_engagement_memberships (
			engagement_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(engagement_id, user_id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_tool_definitions (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			kind TEXT NOT NULL,
			family TEXT NOT NULL,
			install_source TEXT NOT NULL DEFAULT 'builtin',
			binary_name TEXT NOT NULL DEFAULT '',
			target_strategy TEXT NOT NULL DEFAULT 'host',
			safety_class TEXT NOT NULL,
			cost_profile TEXT NOT NULL,
			description TEXT NOT NULL,
			capabilities_json TEXT NOT NULL DEFAULT '[]',
			profiles_json TEXT NOT NULL DEFAULT '[]',
			required_config_json TEXT NOT NULL DEFAULT '[]',
			default_command_template TEXT NOT NULL DEFAULT '',
			command_editable INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS platform_tool_installations (
			tool_id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			detail TEXT NOT NULL,
			command_template TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS platform_connector_configs (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			status TEXT NOT NULL,
			detail TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS platform_workers (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			mode TEXT NOT NULL,
			zone_name TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			last_seen_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS platform_system_events (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			severity TEXT NOT NULL,
			summary TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS platform_audit_events (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			engagement_id TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL,
			summary TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS platform_audit_created_idx ON platform_audit_events(created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_scope_seeds (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_scope_targets (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_target_chunks (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_approvals (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_sources (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			scanner TEXT NOT NULL,
			live_hosts INTEGER NOT NULL DEFAULT 0,
			imported_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_runs (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			tool_id TEXT NOT NULL,
			tool_label TEXT NOT NULL,
			status TEXT NOT NULL,
			stage TEXT NOT NULL DEFAULT '',
			chunk_id TEXT NOT NULL DEFAULT '',
			chunk_name TEXT NOT NULL DEFAULT '',
			target_count INTEGER NOT NULL DEFAULT 0,
			summary TEXT NOT NULL DEFAULT '',
			error_text TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			started_at TEXT NOT NULL DEFAULT '',
			finished_at TEXT NOT NULL DEFAULT '',
			worker_mode TEXT NOT NULL DEFAULT '',
			worker_zone TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS platform_runs_engagement_status_idx ON platform_runs(engagement_id, status);`,
		`CREATE TABLE IF NOT EXISTS platform_zones (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			host_count INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_zone_memberships (
			engagement_id TEXT NOT NULL,
			zone_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			PRIMARY KEY(engagement_id, zone_id, host_ip)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_hosts (
			engagement_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			display_name TEXT NOT NULL,
			os_name TEXT NOT NULL,
			exposure_label TEXT NOT NULL,
			exposure_tone TEXT NOT NULL,
			exposure_score INTEGER NOT NULL DEFAULT 0,
			coverage_label TEXT NOT NULL,
			source_count INTEGER NOT NULL DEFAULT 0,
			open_port_count INTEGER NOT NULL DEFAULT 0,
			finding_total INTEGER NOT NULL DEFAULT 0,
			finding_critical INTEGER NOT NULL DEFAULT 0,
			finding_high INTEGER NOT NULL DEFAULT 0,
			zone_count INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, ip)
		);`,
		`CREATE INDEX IF NOT EXISTS platform_hosts_engagement_exposure_idx ON platform_hosts(engagement_id, exposure_score DESC);`,
		`CREATE TABLE IF NOT EXISTS platform_host_names (
			engagement_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			hostname TEXT NOT NULL,
			PRIMARY KEY(engagement_id, host_ip, hostname)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_ports (
			engagement_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			protocol TEXT NOT NULL,
			port_number INTEGER NOT NULL,
			label TEXT NOT NULL,
			service_name TEXT NOT NULL,
			state TEXT NOT NULL,
			finding_total INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, host_ip, protocol, port_number)
		);`,
		`CREATE INDEX IF NOT EXISTS platform_ports_engagement_state_idx ON platform_ports(engagement_id, state);`,
		`CREATE TABLE IF NOT EXISTS platform_findings (
			engagement_id TEXT NOT NULL,
			id TEXT NOT NULL,
			template_id TEXT NOT NULL,
			name TEXT NOT NULL,
			source TEXT NOT NULL,
			severity TEXT NOT NULL,
			occurrences INTEGER NOT NULL DEFAULT 0,
			hosts INTEGER NOT NULL DEFAULT 0,
			ports INTEGER NOT NULL DEFAULT 0,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, id)
		);`,
		`CREATE INDEX IF NOT EXISTS platform_findings_engagement_severity_idx ON platform_findings(engagement_id, severity);`,
		`CREATE TABLE IF NOT EXISTS platform_finding_occurrences (
			engagement_id TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			protocol TEXT NOT NULL,
			port_number INTEGER NOT NULL,
			target TEXT NOT NULL,
			matched_at TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			PRIMARY KEY(engagement_id, finding_id, host_ip, protocol, port_number, target)
		);`,
		`CREATE TABLE IF NOT EXISTS platform_notes (
			id TEXT PRIMARY KEY,
			engagement_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS platform_tags (
			engagement_id TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			tag TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(engagement_id, host_ip, tag)
		);`,
	}
	for _, statement := range statements {
		if _, err := s.service.db.Exec(statement); err != nil {
			return err
		}
	}
	for _, column := range []struct {
		table      string
		name       string
		definition string
	}{
		{table: "platform_tool_definitions", name: "install_source", definition: "TEXT NOT NULL DEFAULT 'builtin'"},
		{table: "platform_tool_definitions", name: "binary_name", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "platform_tool_definitions", name: "target_strategy", definition: "TEXT NOT NULL DEFAULT 'host'"},
		{table: "platform_tool_definitions", name: "default_command_template", definition: "TEXT NOT NULL DEFAULT ''"},
		{table: "platform_tool_definitions", name: "profiles_json", definition: "TEXT NOT NULL DEFAULT '[]'"},
		{table: "platform_tool_definitions", name: "command_editable", definition: "INTEGER NOT NULL DEFAULT 0"},
		{table: "platform_tool_installations", name: "command_template", definition: "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumn(column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) ensureColumn(table string, column string, definition string) error {
	exists, err := s.columnExists(table, column)
	if err != nil || exists {
		return err
	}
	_, err = s.service.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

func (s *platformStore) columnExists(table string, column string) (bool, error) {
	var row *sql.Row
	if s.service.driver == "pgx" {
		row = s.service.db.QueryRow(`SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`, table, column)
	} else {
		row = s.service.db.QueryRow(`SELECT 1 FROM pragma_table_info('`+table+`') WHERE name = ? LIMIT 1`, column)
	}
	var exists int
	if err := row.Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *platformStore) now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func (s *platformStore) hasUsers() (bool, error) {
	row := s.service.db.QueryRow(`SELECT COUNT(*) FROM platform_users`)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *platformStore) createUser(record platformUserRecord) error {
	query := `INSERT INTO platform_users(id, username, email, display_name, password_hash, is_admin, status, created_at, updated_at, last_login_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `)`
	_, err := s.service.db.Exec(query,
		record.ID,
		record.Username,
		record.Email,
		record.DisplayName,
		record.PasswordHash,
		boolToInt(record.IsAdmin),
		chooseString(record.Status, "active"),
		record.CreatedAt,
		record.UpdatedAt,
		record.LastLoginAt,
	)
	return err
}

func (s *platformStore) userByLogin(login string) (platformUserRecord, error) {
	login = strings.TrimSpace(strings.ToLower(login))
	query := `SELECT id, username, email, display_name, password_hash, is_admin, status, created_at, updated_at, last_login_at FROM platform_users WHERE lower(username) = ` + s.service.placeholder(1) + ` OR lower(email) = ` + s.service.placeholder(2)
	row := s.service.db.QueryRow(query, login, login)
	return scanPlatformUser(row)
}

func (s *platformStore) userByID(id string) (platformUserRecord, error) {
	query := `SELECT id, username, email, display_name, password_hash, is_admin, status, created_at, updated_at, last_login_at FROM platform_users WHERE id = ` + s.service.placeholder(1)
	row := s.service.db.QueryRow(query, strings.TrimSpace(id))
	return scanPlatformUser(row)
}

func (s *platformStore) listUsers() ([]platformUserRecord, error) {
	rows, err := s.service.db.Query(`SELECT id, username, email, display_name, password_hash, is_admin, status, created_at, updated_at, last_login_at FROM platform_users ORDER BY is_admin DESC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]platformUserRecord, 0)
	for rows.Next() {
		item, err := scanPlatformUser(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanPlatformUser(scanner interface{ Scan(...any) error }) (platformUserRecord, error) {
	var item platformUserRecord
	var isAdmin int
	err := scanner.Scan(&item.ID, &item.Username, &item.Email, &item.DisplayName, &item.PasswordHash, &isAdmin, &item.Status, &item.CreatedAt, &item.UpdatedAt, &item.LastLoginAt)
	item.IsAdmin = isAdmin > 0
	return item, err
}

func (s *platformStore) touchUserLogin(userID string) error {
	now := s.now()
	query := `UPDATE platform_users SET last_login_at = ` + s.service.placeholder(1) + `, updated_at = ` + s.service.placeholder(2) + ` WHERE id = ` + s.service.placeholder(3)
	_, err := s.service.db.Exec(query, now, now, userID)
	return err
}

func (s *platformStore) createSession(record platformSessionRecord) error {
	query := `INSERT INTO platform_sessions(id, user_id, token, created_at, expires_at, last_seen_at, user_agent, remote_addr) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `)`
	_, err := s.service.db.Exec(query, record.ID, record.UserID, record.Token, record.CreatedAt, record.ExpiresAt, record.LastSeenAt, record.UserAgent, record.RemoteAddr)
	return err
}

func (s *platformStore) sessionByToken(token string) (platformSessionRecord, error) {
	query := `SELECT id, user_id, token, created_at, expires_at, last_seen_at, user_agent, remote_addr FROM platform_sessions WHERE token = ` + s.service.placeholder(1)
	row := s.service.db.QueryRow(query, strings.TrimSpace(token))
	var item platformSessionRecord
	err := row.Scan(&item.ID, &item.UserID, &item.Token, &item.CreatedAt, &item.ExpiresAt, &item.LastSeenAt, &item.UserAgent, &item.RemoteAddr)
	return item, err
}

func (s *platformStore) touchSession(token string) error {
	query := `UPDATE platform_sessions SET last_seen_at = ` + s.service.placeholder(1) + ` WHERE token = ` + s.service.placeholder(2)
	_, err := s.service.db.Exec(query, s.now(), token)
	return err
}

func (s *platformStore) deleteSession(token string) error {
	query := `DELETE FROM platform_sessions WHERE token = ` + s.service.placeholder(1)
	_, err := s.service.db.Exec(query, token)
	return err
}

func (s *platformStore) createEngagement(record platformEngagementRecord) error {
	query := `INSERT INTO platform_engagements(id, slug, name, description, scope_summary, status, legacy_workspace_id, created_at, updated_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `)`
	_, err := s.service.db.Exec(query, record.ID, record.Slug, record.Name, record.Description, record.ScopeSummary, record.Status, record.LegacyWorkspaceID, record.CreatedAt, record.UpdatedAt)
	return err
}

func (s *platformStore) updateEngagementScopeSummary(id string, scopeSummary string) error {
	query := `UPDATE platform_engagements SET scope_summary = ` + s.service.placeholder(1) + `, updated_at = ` + s.service.placeholder(2) + ` WHERE id = ` + s.service.placeholder(3)
	_, err := s.service.db.Exec(query, strings.TrimSpace(scopeSummary), s.now(), id)
	return err
}

func (s *platformStore) engagementBySlug(slug string) (platformEngagementRecord, error) {
	query := `SELECT id, slug, name, description, scope_summary, status, legacy_workspace_id, created_at, updated_at FROM platform_engagements WHERE slug = ` + s.service.placeholder(1)
	row := s.service.db.QueryRow(query, strings.TrimSpace(slug))
	return scanPlatformEngagement(row)
}

func (s *platformStore) engagementByWorkspaceID(workspaceID string) (platformEngagementRecord, error) {
	query := `SELECT id, slug, name, description, scope_summary, status, legacy_workspace_id, created_at, updated_at FROM platform_engagements WHERE legacy_workspace_id = ` + s.service.placeholder(1)
	row := s.service.db.QueryRow(query, strings.TrimSpace(workspaceID))
	return scanPlatformEngagement(row)
}

func scanPlatformEngagement(scanner interface{ Scan(...any) error }) (platformEngagementRecord, error) {
	var item platformEngagementRecord
	err := scanner.Scan(&item.ID, &item.Slug, &item.Name, &item.Description, &item.ScopeSummary, &item.Status, &item.LegacyWorkspaceID, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *platformStore) listEngagementsForUser(user platformUserRecord) ([]platformEngagementRecord, error) {
	if user.IsAdmin {
		rows, err := s.service.db.Query(`SELECT id, slug, name, description, scope_summary, status, legacy_workspace_id, created_at, updated_at FROM platform_engagements ORDER BY updated_at DESC, created_at DESC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := make([]platformEngagementRecord, 0)
		for rows.Next() {
			item, err := scanPlatformEngagement(rows)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, rows.Err()
	}
	query := `SELECT e.id, e.slug, e.name, e.description, e.scope_summary, e.status, e.legacy_workspace_id, e.created_at, e.updated_at
		FROM platform_engagements e
		INNER JOIN platform_engagement_memberships m ON m.engagement_id = e.id
		WHERE m.user_id = ` + s.service.placeholder(1) + `
		ORDER BY e.updated_at DESC, e.created_at DESC`
	rows, err := s.service.db.Query(query, user.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]platformEngagementRecord, 0)
	for rows.Next() {
		item, err := scanPlatformEngagement(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) addMembership(record platformMembershipRecord) error {
	query := `INSERT INTO platform_engagement_memberships(engagement_id, user_id, role, created_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `)
		ON CONFLICT(engagement_id, user_id) DO UPDATE SET role = excluded.role`
	_, err := s.service.db.Exec(query, record.EngagementID, record.UserID, record.Role, record.CreatedAt)
	return err
}

func (s *platformStore) deleteMembership(engagementID string, userID string) error {
	query := `DELETE FROM platform_engagement_memberships WHERE engagement_id = ` + s.service.placeholder(1) + ` AND user_id = ` + s.service.placeholder(2)
	_, err := s.service.db.Exec(query, engagementID, userID)
	return err
}

func (s *platformStore) roleForUser(engagementID string, user platformUserRecord) (string, error) {
	if user.IsAdmin {
		return "admin", nil
	}
	query := `SELECT role FROM platform_engagement_memberships WHERE engagement_id = ` + s.service.placeholder(1) + ` AND user_id = ` + s.service.placeholder(2)
	row := s.service.db.QueryRow(query, engagementID, user.ID)
	var role string
	if err := row.Scan(&role); err != nil {
		return "", err
	}
	return role, nil
}

func (s *platformStore) listMemberships(engagementID string) ([]PlatformMembershipView, error) {
	query := `SELECT u.id, u.username, u.display_name, u.email, m.role, m.created_at
		FROM platform_engagement_memberships m
		INNER JOIN platform_users u ON u.id = m.user_id
		WHERE m.engagement_id = ` + s.service.placeholder(1) + `
		ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END, u.username ASC`
	rows, err := s.service.db.Query(query, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformMembershipView, 0)
	for rows.Next() {
		var item PlatformMembershipView
		if err := rows.Scan(&item.UserID, &item.Username, &item.DisplayName, &item.Email, &item.Role, &item.JoinedAt); err != nil {
			return nil, err
		}
		item.JoinedAt = displayTimestamp(item.JoinedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) recordAudit(record platformAuditRecord) error {
	query := `INSERT INTO platform_audit_events(id, user_id, engagement_id, kind, summary, created_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `)`
	_, err := s.service.db.Exec(query, record.ID, record.UserID, record.EngagementID, record.Kind, record.Summary, record.CreatedAt)
	return err
}

func (s *platformStore) recentAudit(limit int) ([]PlatformAuditEventView, error) {
	query := `SELECT a.created_at, COALESCE(u.display_name, u.username, 'system') AS actor, a.kind, a.summary, COALESCE(e.name, '') AS engagement_name
		FROM platform_audit_events a
		LEFT JOIN platform_users u ON u.id = a.user_id
		LEFT JOIN platform_engagements e ON e.id = a.engagement_id
		ORDER BY a.created_at DESC`
	if limit > 0 {
		query += ` LIMIT ` + strconv.Itoa(limit)
	}
	rows, err := s.service.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformAuditEventView, 0)
	for rows.Next() {
		var item PlatformAuditEventView
		if err := rows.Scan(&item.CreatedAt, &item.ActorLabel, &item.Kind, &item.Summary, &item.EngagementName); err != nil {
			return nil, err
		}
		item.CreatedAt = displayTimestamp(item.CreatedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) upsertWorker(record platformWorkerRecord) error {
	query := `INSERT INTO platform_workers(id, label, mode, zone_name, status, detail, last_seen_at, updated_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `)
		ON CONFLICT(id) DO UPDATE SET label = excluded.label, mode = excluded.mode, zone_name = excluded.zone_name, status = excluded.status, detail = excluded.detail, last_seen_at = excluded.last_seen_at, updated_at = excluded.updated_at`
	_, err := s.service.db.Exec(query, record.ID, record.Label, record.Mode, record.Zone, record.Status, record.Detail, record.LastSeenAt, record.UpdatedAt)
	return err
}

func (s *platformStore) listWorkers() ([]PlatformWorkerView, error) {
	rows, err := s.service.db.Query(`SELECT id, label, mode, zone_name, status, detail, last_seen_at FROM platform_workers ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformWorkerView, 0)
	for rows.Next() {
		var item PlatformWorkerView
		if err := rows.Scan(&item.ID, &item.Label, &item.Mode, &item.Zone, &item.Status, &item.Detail, &item.LastSeenAt); err != nil {
			return nil, err
		}
		item.StatusTone = toneForWorkerStatus(item.Status, item.LastSeenAt)
		item.LastSeenAt = displayTimestamp(item.LastSeenAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) upsertToolDefinition(item PluginDefinitionView, requiredConfig []string) error {
	item = normalizedPluginDefinition(item)
	capabilityJSON, err := json.Marshal(item.Capabilities)
	if err != nil {
		return err
	}
	profilesJSON, err := json.Marshal(cloneToolProfiles(item.Profiles))
	if err != nil {
		return err
	}
	configJSON, err := json.Marshal(requiredConfig)
	if err != nil {
		return err
	}
	query := `INSERT INTO platform_tool_definitions(id, label, kind, family, install_source, binary_name, target_strategy, safety_class, cost_profile, description, capabilities_json, profiles_json, required_config_json, default_command_template, command_editable) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `, ` + s.service.placeholder(11) + `, ` + s.service.placeholder(12) + `, ` + s.service.placeholder(13) + `, ` + s.service.placeholder(14) + `, ` + s.service.placeholder(15) + `)
		ON CONFLICT(id) DO UPDATE SET label = excluded.label, kind = excluded.kind, family = excluded.family, install_source = excluded.install_source, binary_name = excluded.binary_name, target_strategy = excluded.target_strategy, safety_class = excluded.safety_class, cost_profile = excluded.cost_profile, description = excluded.description, capabilities_json = excluded.capabilities_json, profiles_json = excluded.profiles_json, required_config_json = excluded.required_config_json, default_command_template = excluded.default_command_template, command_editable = excluded.command_editable`
	_, err = s.service.db.Exec(
		query,
		item.ID,
		item.Label,
		item.Kind,
		item.Family,
		chooseString(strings.TrimSpace(item.InstallSource), toolInstallSourceBuiltin),
		strings.TrimSpace(item.BinaryName),
		normalizeTargetStrategy(item.TargetStrategy),
		item.SafetyClass,
		item.CostProfile,
		item.Description,
		string(capabilityJSON),
		string(profilesJSON),
		string(configJSON),
		item.DefaultCommandTemplate,
		boolToInt(item.CommandEditable),
	)
	return err
}

func (s *platformStore) upsertToolInstallation(toolID string, status string, detail string) error {
	query := `INSERT INTO platform_tool_installations(tool_id, status, detail, command_template, updated_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `)
		ON CONFLICT(tool_id) DO UPDATE SET status = excluded.status, detail = excluded.detail, updated_at = excluded.updated_at`
	_, err := s.service.db.Exec(query, toolID, status, detail, "", s.now())
	return err
}

func (s *platformStore) updateToolCommandTemplate(toolID string, template string) error {
	query := `INSERT INTO platform_tool_installations(tool_id, status, detail, command_template, updated_at)
		VALUES(
			` + s.service.placeholder(1) + `,
			COALESCE((SELECT status FROM platform_tool_installations WHERE tool_id = ` + s.service.placeholder(2) + `), 'Configured'),
			COALESCE((SELECT detail FROM platform_tool_installations WHERE tool_id = ` + s.service.placeholder(3) + `), ''),
			` + s.service.placeholder(4) + `,
			` + s.service.placeholder(5) + `
		)
		ON CONFLICT(tool_id) DO UPDATE SET command_template = excluded.command_template, updated_at = excluded.updated_at`
	_, err := s.service.db.Exec(query, toolID, toolID, toolID, strings.TrimSpace(template), s.now())
	return err
}

func (s *platformStore) upsertConnectorConfig(id string, label string, status string, detail string) error {
	query := `INSERT INTO platform_connector_configs(id, label, status, detail, updated_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `)
		ON CONFLICT(id) DO UPDATE SET label = excluded.label, status = excluded.status, detail = excluded.detail, updated_at = excluded.updated_at`
	_, err := s.service.db.Exec(query, id, label, status, detail, s.now())
	return err
}

func (s *platformStore) listTools() ([]PlatformToolView, error) {
	query := `SELECT d.id, d.label, d.kind, d.family, d.install_source, d.binary_name, d.target_strategy, d.safety_class, d.cost_profile, d.description, d.capabilities_json, d.profiles_json, d.required_config_json, d.default_command_template, d.command_editable, COALESCE(i.status, ''), COALESCE(i.detail, ''), COALESCE(i.command_template, '')
		FROM platform_tool_definitions d
		LEFT JOIN platform_tool_installations i ON i.tool_id = d.id
		ORDER BY d.kind ASC, d.family ASC, d.label ASC`
	rows, err := s.service.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformToolView, 0)
	for rows.Next() {
		var (
			item             PlatformToolView
			capabilitiesJSON string
			profilesJSON     string
			configJSON       string
			commandEditable  int
		)
		if err := rows.Scan(&item.ID, &item.Label, &item.Kind, &item.Family, &item.InstallSource, &item.BinaryName, &item.TargetStrategy, &item.SafetyClass, &item.CostProfile, &item.Description, &capabilitiesJSON, &profilesJSON, &configJSON, &item.DefaultCommandTemplate, &commandEditable, &item.Status, &item.StatusDetail, &item.CommandTemplate); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(capabilitiesJSON), &item.Capabilities)
		_ = json.Unmarshal([]byte(profilesJSON), &item.Profiles)
		_ = json.Unmarshal([]byte(configJSON), &item.RequiredConfig)
		item.InstallSource = chooseString(strings.TrimSpace(item.InstallSource), toolInstallSourceBuiltin)
		item.TargetStrategy = normalizeTargetStrategy(item.TargetStrategy)
		item.Profiles = cloneToolProfiles(item.Profiles)
		item.CommandEditable = commandEditable == 1
		item.CommandTemplate = strings.TrimSpace(item.CommandTemplate)
		item.ResolvedCommandTemplate = chooseString(item.CommandTemplate, item.DefaultCommandTemplate)
		item.StatusTone = toneForToolStatus(item.Status)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listCustomToolDefinitions() ([]PluginDefinitionView, error) {
	tools, err := s.listTools()
	if err != nil {
		return nil, err
	}
	items := make([]PluginDefinitionView, 0)
	for _, tool := range tools {
		if tool.InstallSource != toolInstallSourceCustom {
			continue
		}
		items = append(items, pluginDefinitionFromToolView(tool))
	}
	return items, nil
}

func (s *platformStore) deleteCustomTool(toolID string) error {
	toolID = strings.TrimSpace(toolID)
	if toolID == "" {
		return errors.New("tool id is required")
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
	deleteInstallationQuery := `DELETE FROM platform_tool_installations WHERE tool_id = ` + s.service.placeholder(1)
	if _, err = tx.Exec(deleteInstallationQuery, toolID); err != nil {
		return err
	}
	deleteDefinitionQuery := `DELETE FROM platform_tool_definitions WHERE id = ` + s.service.placeholder(1) + ` AND install_source = ` + s.service.placeholder(2)
	result, err := tx.Exec(deleteDefinitionQuery, toolID, toolInstallSourceCustom)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (s *platformStore) toolCommandTemplate(toolID string) (string, error) {
	query := `SELECT COALESCE(i.command_template, '')
		FROM platform_tool_installations i
		WHERE i.tool_id = ` + s.service.placeholder(1)
	var template string
	err := s.service.db.QueryRow(query, strings.TrimSpace(toolID)).Scan(&template)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(template), nil
}

func (s *platformStore) listConnectors() ([]PlatformConnectorView, error) {
	rows, err := s.service.db.Query(`SELECT id, label, status, detail FROM platform_connector_configs ORDER BY label ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformConnectorView, 0)
	for rows.Next() {
		var item PlatformConnectorView
		if err := rows.Scan(&item.ID, &item.Label, &item.Status, &item.StatusDetail); err != nil {
			return nil, err
		}
		item.StatusTone = toneForToolStatus(item.Status)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) replaceEngagementProjection(
	engagementID string,
	seeds []platformScopeSeedRecord,
	targets []platformScopeTargetRecord,
	chunks []platformChunkRecord,
	approvals []platformApprovalRow,
	sources []platformSourceRecord,
	runs []platformRunRecord,
	zones []platformZoneRecord,
	zoneMemberships map[string][]string,
	hosts []platformHostRecord,
	hostnames map[string][]string,
	ports []platformPortRecord,
	findings []platformFindingRecord,
	occurrences []platformFindingOccurrenceRecord,
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

	deleteTables := []string{
		"platform_scope_seeds",
		"platform_scope_targets",
		"platform_target_chunks",
		"platform_approvals",
		"platform_sources",
		"platform_runs",
		"platform_zones",
		"platform_zone_memberships",
		"platform_hosts",
		"platform_host_names",
		"platform_ports",
		"platform_findings",
		"platform_finding_occurrences",
		"platform_notes",
		"platform_tags",
	}
	for _, table := range deleteTables {
		query := `DELETE FROM ` + table + ` WHERE engagement_id = ` + s.service.placeholder(1)
		if _, err = tx.Exec(query, engagementID); err != nil {
			return err
		}
	}

	if err = insertProjectionJSONTable(tx, s, "platform_scope_seeds", engagementID, seeds); err != nil {
		return err
	}
	if err = insertProjectionJSONTable(tx, s, "platform_scope_targets", engagementID, targets); err != nil {
		return err
	}
	if err = insertProjectionJSONTable(tx, s, "platform_target_chunks", engagementID, chunks); err != nil {
		return err
	}
	if err = insertProjectionJSONTable(tx, s, "platform_approvals", engagementID, approvals); err != nil {
		return err
	}
	if err = s.insertSources(tx, engagementID, sources); err != nil {
		return err
	}
	if err = s.insertRuns(tx, engagementID, runs); err != nil {
		return err
	}
	if err = s.insertZones(tx, engagementID, zones); err != nil {
		return err
	}
	if err = s.insertZoneMemberships(tx, engagementID, zoneMemberships); err != nil {
		return err
	}
	if err = s.insertHosts(tx, engagementID, hosts); err != nil {
		return err
	}
	if err = s.insertHostNames(tx, engagementID, hostnames); err != nil {
		return err
	}
	if err = s.insertPorts(tx, engagementID, ports); err != nil {
		return err
	}
	if err = s.insertFindings(tx, engagementID, findings); err != nil {
		return err
	}
	if err = s.insertFindingOccurrences(tx, engagementID, occurrences); err != nil {
		return err
	}
	update := `UPDATE platform_engagements SET updated_at = ` + s.service.placeholder(1) + ` WHERE id = ` + s.service.placeholder(2)
	if _, err = tx.Exec(update, s.now(), engagementID); err != nil {
		return err
	}
	return tx.Commit()
}

func insertProjectionJSONTable[T interface {
	projectionMeta() (string, string, string)
}](tx *sql.Tx, store *platformStore, table string, engagementID string, values []T) error {
	query := `INSERT INTO ` + table + `(engagement_id, id, created_at, payload_json) VALUES(` +
		store.service.placeholder(1) + `, ` + store.service.placeholder(2) + `, ` + store.service.placeholder(3) + `, ` + store.service.placeholder(4) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		id, createdAt, payload := value.projectionMeta()
		if _, err := stmt.Exec(engagementID, id, createdAt, payload); err != nil {
			return err
		}
	}
	return nil
}

func (r platformScopeSeedRecord) projectionMeta() (string, string, string) {
	return r.ID, r.CreatedAt, r.Payload
}
func (r platformScopeTargetRecord) projectionMeta() (string, string, string) {
	return r.ID, r.CreatedAt, r.Payload
}
func (r platformChunkRecord) projectionMeta() (string, string, string) {
	return r.ID, r.CreatedAt, r.Payload
}
func (r platformApprovalRow) projectionMeta() (string, string, string) {
	return r.ID, r.CreatedAt, r.Payload
}

func (s *platformStore) insertSources(tx *sql.Tx, engagementID string, values []platformSourceRecord) error {
	query := `INSERT INTO platform_sources(engagement_id, id, name, kind, scanner, live_hosts, imported_at, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.ID, value.Name, value.Kind, value.Scanner, value.LiveHosts, value.ImportedAt, value.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) insertRuns(tx *sql.Tx, engagementID string, values []platformRunRecord) error {
	query := `INSERT INTO platform_runs(engagement_id, id, tool_id, tool_label, status, stage, chunk_id, chunk_name, target_count, summary, error_text, created_at, started_at, finished_at, worker_mode, worker_zone, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `, ` + s.service.placeholder(11) + `, ` + s.service.placeholder(12) + `, ` + s.service.placeholder(13) + `, ` + s.service.placeholder(14) + `, ` + s.service.placeholder(15) + `, ` + s.service.placeholder(16) + `, ` + s.service.placeholder(17) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.ID, value.ToolID, value.ToolLabel, value.Status, value.Stage, value.ChunkID, value.ChunkName, value.TargetCount, value.Summary, value.Error, value.CreatedAt, value.StartedAt, value.FinishedAt, value.WorkerMode, value.WorkerZone, value.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) insertZones(tx *sql.Tx, engagementID string, values []platformZoneRecord) error {
	query := `INSERT INTO platform_zones(engagement_id, id, name, kind, scope, host_count, created_at, updated_at) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.ID, value.Name, value.Kind, value.Scope, value.HostCount, value.CreatedAt, value.UpdatedAt); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) insertZoneMemberships(tx *sql.Tx, engagementID string, values map[string][]string) error {
	query := `INSERT INTO platform_zone_memberships(engagement_id, zone_id, host_ip) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	zoneIDs := make([]string, 0, len(values))
	for zoneID := range values {
		zoneIDs = append(zoneIDs, zoneID)
	}
	sort.Strings(zoneIDs)
	for _, zoneID := range zoneIDs {
		hosts := append([]string(nil), values[zoneID]...)
		sort.Strings(hosts)
		for _, hostIP := range hosts {
			if _, err := stmt.Exec(engagementID, zoneID, hostIP); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *platformStore) insertHosts(tx *sql.Tx, engagementID string, values []platformHostRecord) error {
	query := `INSERT INTO platform_hosts(engagement_id, ip, display_name, os_name, exposure_label, exposure_tone, exposure_score, coverage_label, source_count, open_port_count, finding_total, finding_critical, finding_high, zone_count, updated_at, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `, ` + s.service.placeholder(11) + `, ` + s.service.placeholder(12) + `, ` + s.service.placeholder(13) + `, ` + s.service.placeholder(14) + `, ` + s.service.placeholder(15) + `, ` + s.service.placeholder(16) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.IP, value.DisplayName, value.OSName, value.ExposureLabel, value.ExposureTone, value.ExposureScore, value.CoverageLabel, value.SourceCount, value.OpenPortCount, value.FindingTotal, value.FindingCritical, value.FindingHigh, value.ZoneCount, value.UpdatedAt, value.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) insertHostNames(tx *sql.Tx, engagementID string, values map[string][]string) error {
	query := `INSERT INTO platform_host_names(engagement_id, host_ip, hostname) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		names := uniqueStrings(values[key])
		sort.Strings(names)
		for _, name := range names {
			if _, err := stmt.Exec(engagementID, key, name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *platformStore) insertPorts(tx *sql.Tx, engagementID string, values []platformPortRecord) error {
	query := `INSERT INTO platform_ports(engagement_id, host_ip, protocol, port_number, label, service_name, state, finding_total, updated_at, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.HostIP, value.Protocol, value.PortNumber, value.Label, value.ServiceName, value.State, value.FindingTotal, value.UpdatedAt, value.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) insertFindings(tx *sql.Tx, engagementID string, values []platformFindingRecord) error {
	query := `INSERT INTO platform_findings(engagement_id, id, template_id, name, source, severity, occurrences, hosts, ports, first_seen, last_seen, updated_at, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `, ` + s.service.placeholder(9) + `, ` + s.service.placeholder(10) + `, ` + s.service.placeholder(11) + `, ` + s.service.placeholder(12) + `, ` + s.service.placeholder(13) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.ID, value.TemplateID, value.Name, value.Source, value.Severity, value.Occurrences, value.Hosts, value.Ports, value.FirstSeen, value.LastSeen, value.UpdatedAt, value.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) insertFindingOccurrences(tx *sql.Tx, engagementID string, values []platformFindingOccurrenceRecord) error {
	query := `INSERT INTO platform_finding_occurrences(engagement_id, finding_id, host_ip, protocol, port_number, target, matched_at, payload_json) VALUES(` +
		s.service.placeholder(1) + `, ` + s.service.placeholder(2) + `, ` + s.service.placeholder(3) + `, ` + s.service.placeholder(4) + `, ` + s.service.placeholder(5) + `, ` + s.service.placeholder(6) + `, ` + s.service.placeholder(7) + `, ` + s.service.placeholder(8) + `)`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		if _, err := stmt.Exec(engagementID, value.FindingID, value.HostIP, value.Protocol, value.PortNumber, value.Target, value.MatchedAt, value.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *platformStore) healthSummary() (PlatformHealthView, error) {
	view := PlatformHealthView{}
	pairs := []struct {
		query string
		dest  *int
	}{
		{`SELECT COUNT(*) FROM platform_users`, &view.UserCount},
		{`SELECT COUNT(*) FROM platform_engagements`, &view.EngagementCount},
		{`SELECT COUNT(*) FROM platform_workers`, &view.WorkerCount},
		{`SELECT COUNT(*) FROM platform_workers WHERE status = 'online'`, &view.LiveWorkers},
		{`SELECT COUNT(*) FROM platform_tool_definitions`, &view.ToolCount},
		{`SELECT COUNT(*) FROM platform_tool_installations WHERE status IN ('Installed', 'Configured', 'Ready', 'Endpoint unchecked')`, &view.ReadyTools},
		{`SELECT COUNT(*) FROM platform_connector_configs`, &view.ConnectorCount},
		{`SELECT COUNT(*) FROM platform_connector_configs WHERE status IN ('Configured', 'Endpoint unchecked')`, &view.ConfiguredConnectors},
		{`SELECT COUNT(*) FROM platform_runs WHERE status = 'running'`, &view.RunningRuns},
		{`SELECT COUNT(*) FROM platform_runs WHERE status = 'queued'`, &view.QueuedRuns},
	}
	for _, pair := range pairs {
		if err := s.service.db.QueryRow(pair.query).Scan(pair.dest); err != nil {
			return view, err
		}
	}
	return view, nil
}

func (s *platformStore) engagementStats(engagementID string) ([]StatCard, error) {
	type row struct {
		query string
		value *int
	}
	hostCount := 0
	portCount := 0
	findingCount := 0
	zoneCount := 0
	sourceCount := 0
	runningCount := 0
	for _, item := range []row{
		{`SELECT COUNT(*) FROM platform_hosts WHERE engagement_id = ` + s.service.placeholder(1), &hostCount},
		{`SELECT COUNT(*) FROM platform_ports WHERE engagement_id = ` + s.service.placeholder(1) + ` AND state = 'open'`, &portCount},
		{`SELECT COUNT(*) FROM platform_findings WHERE engagement_id = ` + s.service.placeholder(1), &findingCount},
		{`SELECT COUNT(*) FROM platform_zones WHERE engagement_id = ` + s.service.placeholder(1), &zoneCount},
		{`SELECT COUNT(*) FROM platform_sources WHERE engagement_id = ` + s.service.placeholder(1), &sourceCount},
		{`SELECT COUNT(*) FROM platform_runs WHERE engagement_id = ` + s.service.placeholder(1) + ` AND status IN ('queued', 'running')`, &runningCount},
	} {
		if err := s.service.db.QueryRow(item.query, engagementID).Scan(item.value); err != nil {
			return nil, err
		}
	}
	return []StatCard{
		{Label: "Hosts", Value: strconv.Itoa(hostCount), Detail: "Canonical hosts in this engagement", Tone: "accent"},
		{Label: "Open ports", Value: strconv.Itoa(portCount), Detail: "Observed open services across all hosts", Tone: "calm"},
		{Label: "Findings", Value: strconv.Itoa(findingCount), Detail: "Grouped finding definitions in current evidence", Tone: "warning"},
		{Label: "Zones", Value: strconv.Itoa(zoneCount), Detail: "Derived and scoped navigation groups", Tone: "neutral"},
		{Label: "Sources", Value: strconv.Itoa(sourceCount), Detail: "Imported files and run-generated evidence", Tone: "neutral"},
		{Label: "Running", Value: strconv.Itoa(runningCount), Detail: "Queued or active tooling runs", Tone: "risk"},
	}, nil
}

func (s *platformStore) listEngagementZones(engagementID string) ([]PlatformZoneView, error) {
	query := `SELECT id, name, kind, scope, host_count FROM platform_zones WHERE engagement_id = ` + s.service.placeholder(1) + ` ORDER BY host_count DESC, name ASC`
	rows, err := s.service.db.Query(query, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformZoneView, 0)
	for rows.Next() {
		var item PlatformZoneView
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Scope, &item.HostCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listZonesForHost(engagementID string, hostIP string) ([]PlatformZoneView, error) {
	query := `SELECT z.id, z.name, z.kind, z.scope, z.host_count
		FROM platform_zones z
		INNER JOIN platform_zone_memberships zm ON zm.engagement_id = z.engagement_id AND zm.zone_id = z.id
		WHERE z.engagement_id = ` + s.service.placeholder(1) + ` AND zm.host_ip = ` + s.service.placeholder(2) + `
		ORDER BY z.host_count DESC, z.name ASC`
	rows, err := s.service.db.Query(query, engagementID, hostIP)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformZoneView, 0)
	for rows.Next() {
		var item PlatformZoneView
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Scope, &item.HostCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementHosts(engagementID string, zoneID string, query string, limit int) ([]PlatformHostView, error) {
	args := []any{engagementID}
	base := `SELECT h.ip, h.display_name, h.os_name, h.zone_count, h.open_port_count, h.finding_total, h.finding_critical, h.finding_high, h.exposure_label, h.exposure_tone, h.coverage_label, h.source_count
		FROM platform_hosts h`
	clauses := []string{`h.engagement_id = ` + s.service.placeholder(len(args))}
	if strings.TrimSpace(zoneID) != "" {
		args = append(args, zoneID)
		base += ` INNER JOIN platform_zone_memberships zm ON zm.engagement_id = h.engagement_id AND zm.host_ip = h.ip`
		clauses = append(clauses, `zm.zone_id = `+s.service.placeholder(len(args)))
	}
	if trimmed := strings.TrimSpace(strings.ToLower(query)); trimmed != "" {
		args = append(args, "%"+trimmed+"%", "%"+trimmed+"%", "%"+trimmed+"%")
		clauses = append(clauses, `(lower(h.ip) LIKE `+s.service.placeholder(len(args)-2)+` OR lower(h.display_name) LIKE `+s.service.placeholder(len(args)-1)+` OR lower(h.os_name) LIKE `+s.service.placeholder(len(args))+`)`)
	}
	sqlQuery := base + ` WHERE ` + strings.Join(clauses, ` AND `) + ` ORDER BY h.exposure_score DESC, h.finding_total DESC, h.open_port_count DESC, h.ip ASC`
	if limit > 0 {
		sqlQuery += ` LIMIT ` + strconv.Itoa(limit)
	}
	rows, err := s.service.db.Query(sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformHostView, 0)
	for rows.Next() {
		var item PlatformHostView
		if err := rows.Scan(&item.IP, &item.DisplayName, &item.OS, &item.ZoneCount, &item.OpenPorts, &item.Findings, &item.Critical, &item.High, &item.Exposure, &item.ExposureTone, &item.Coverage, &item.SourceCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementSources(engagementID string, limit int) ([]PlatformSourceView, error) {
	query := `SELECT id, name, kind, scanner, live_hosts, imported_at FROM platform_sources WHERE engagement_id = ` + s.service.placeholder(1) + ` ORDER BY imported_at DESC`
	if limit > 0 {
		query += ` LIMIT ` + strconv.Itoa(limit)
	}
	rows, err := s.service.db.Query(query, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformSourceView, 0)
	for rows.Next() {
		var item PlatformSourceView
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Scanner, &item.LiveHosts, &item.ImportedAt); err != nil {
			return nil, err
		}
		item.ImportedAt = displayTimestamp(item.ImportedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementRuns(engagementID string, limit int) ([]PlatformRunView, error) {
	query := `SELECT id, tool_id, tool_label, status, stage, chunk_name, target_count, summary, error_text, created_at, started_at, finished_at, worker_mode, worker_zone
		FROM platform_runs WHERE engagement_id = ` + s.service.placeholder(1) + ` ORDER BY created_at DESC`
	if limit > 0 {
		query += ` LIMIT ` + strconv.Itoa(limit)
	}
	rows, err := s.service.db.Query(query, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformRunView, 0)
	for rows.Next() {
		var item PlatformRunView
		if err := rows.Scan(&item.ID, &item.ToolID, &item.ToolLabel, &item.Status, &item.Stage, &item.ChunkName, &item.TargetCount, &item.Summary, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt, &item.WorkerMode, &item.WorkerZone); err != nil {
			return nil, err
		}
		item.StatusTone = toneForRunStatus(item.Status)
		item.CreatedAt = displayTimestamp(item.CreatedAt)
		item.StartedAt = displayTimestamp(item.StartedAt)
		item.FinishedAt = displayTimestamp(item.FinishedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementPorts(engagementID string, query string, limit int) ([]PlatformPortView, error) {
	args := []any{engagementID}
	clauses := []string{`engagement_id = ` + s.service.placeholder(1), `state = 'open'`}
	if trimmed := strings.TrimSpace(strings.ToLower(query)); trimmed != "" {
		args = append(args, "%"+trimmed+"%", "%"+trimmed+"%")
		clauses = append(clauses, `(lower(label) LIKE `+s.service.placeholder(len(args)-1)+` OR lower(service_name) LIKE `+s.service.placeholder(len(args))+`)`)
	}
	querySQL := `SELECT protocol, CAST(port_number AS TEXT) AS port_number, label, service_name, COUNT(*) AS hosts, COALESCE(SUM(finding_total), 0) AS findings
		FROM platform_ports WHERE ` + strings.Join(clauses, ` AND `) + `
		GROUP BY protocol, port_number, label, service_name
		ORDER BY hosts DESC, findings DESC, port_number ASC`
	if limit > 0 {
		querySQL += ` LIMIT ` + strconv.Itoa(limit)
	}
	rows, err := s.service.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformPortView, 0)
	for rows.Next() {
		var item PlatformPortView
		if err := rows.Scan(&item.Protocol, &item.Port, &item.Label, &item.Service, &item.Hosts, &item.Findings); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementFindings(engagementID string, query string, severity string, limit int) ([]PlatformFindingView, error) {
	args := []any{engagementID}
	clauses := []string{`engagement_id = ` + s.service.placeholder(1)}
	if normalized := normalizeFindingSeverityFilter(severity); normalized != "" && normalized != "all" {
		args = append(args, normalized)
		clauses = append(clauses, `severity = `+s.service.placeholder(len(args)))
	}
	if trimmed := strings.TrimSpace(strings.ToLower(query)); trimmed != "" {
		args = append(args, "%"+trimmed+"%", "%"+trimmed+"%", "%"+trimmed+"%")
		clauses = append(clauses, `(lower(name) LIKE `+s.service.placeholder(len(args)-2)+` OR lower(source) LIKE `+s.service.placeholder(len(args)-1)+` OR lower(template_id) LIKE `+s.service.placeholder(len(args))+`)`)
	}
	querySQL := `SELECT id, template_id, name, source, severity, occurrences, hosts, ports, first_seen, last_seen
		FROM platform_findings WHERE ` + strings.Join(clauses, ` AND `) + `
		ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, occurrences DESC, name ASC`
	if limit > 0 {
		querySQL += ` LIMIT ` + strconv.Itoa(limit)
	}
	rows, err := s.service.db.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformFindingView, 0)
	for rows.Next() {
		var item PlatformFindingView
		if err := rows.Scan(&item.ID, &item.TemplateID, &item.Name, &item.Source, &item.Severity, &item.Occurrences, &item.Hosts, &item.Ports, &item.FirstSeen, &item.LastSeen); err != nil {
			return nil, err
		}
		item.SeverityTone = severityTone(item.Severity)
		item.FirstSeen = displayTimestamp(item.FirstSeen)
		item.LastSeen = displayTimestamp(item.LastSeen)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementScopeSeeds(engagementID string) ([]ScopeSeedView, error) {
	rows, err := s.service.db.Query(`SELECT payload_json FROM platform_scope_seeds WHERE engagement_id = `+s.service.placeholder(1)+` ORDER BY created_at DESC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ScopeSeedView, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var item ScopeSeedView
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementScopeTargets(engagementID string) ([]ScopeTargetView, error) {
	rows, err := s.service.db.Query(`SELECT payload_json FROM platform_scope_targets WHERE engagement_id = `+s.service.placeholder(1)+` ORDER BY created_at ASC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ScopeTargetView, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var item ScopeTargetView
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementChunks(engagementID string) ([]TargetChunkView, error) {
	rows, err := s.service.db.Query(`SELECT payload_json FROM platform_target_chunks WHERE engagement_id = `+s.service.placeholder(1)+` ORDER BY created_at DESC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TargetChunkView, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var item TargetChunkView
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) listEngagementApprovals(engagementID string) ([]ApprovalView, error) {
	rows, err := s.service.db.Query(`SELECT payload_json FROM platform_approvals WHERE engagement_id = `+s.service.placeholder(1)+` ORDER BY created_at DESC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ApprovalView, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var item ApprovalView
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *platformStore) engagementCounts() (map[string]PlatformEngagementView, error) {
	items := map[string]PlatformEngagementView{}
	rows, err := s.service.db.Query(`SELECT e.id, e.slug, e.name, e.description, e.scope_summary, e.status, e.legacy_workspace_id, e.created_at, e.updated_at,
		(SELECT COUNT(*) FROM platform_engagement_memberships m WHERE m.engagement_id = e.id) AS member_count,
		(SELECT COUNT(*) FROM platform_hosts h WHERE h.engagement_id = e.id) AS host_count,
		(SELECT COUNT(*) FROM platform_ports p WHERE p.engagement_id = e.id AND p.state = 'open') AS port_count,
		(SELECT COUNT(*) FROM platform_findings f WHERE f.engagement_id = e.id) AS finding_count,
		(SELECT COUNT(*) FROM platform_zones z WHERE z.engagement_id = e.id) AS zone_count,
		(SELECT COUNT(*) FROM platform_sources s2 WHERE s2.engagement_id = e.id) AS source_count,
		(SELECT COUNT(*) FROM platform_runs r WHERE r.engagement_id = e.id AND r.status IN ('queued', 'running')) AS running_runs
		FROM platform_engagements e
		ORDER BY e.updated_at DESC, e.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PlatformEngagementView
		if err := rows.Scan(&item.ID, &item.Slug, &item.Name, &item.Description, &item.ScopeSummary, &item.Status, &item.WorkspaceID, &item.CreatedAt, &item.UpdatedAt, &item.MemberCount, &item.HostCount, &item.PortCount, &item.FindingCount, &item.ZoneCount, &item.SourceCount, &item.RunningRuns); err != nil {
			return nil, err
		}
		item.CreatedAt = displayTimestamp(item.CreatedAt)
		item.UpdatedAt = displayTimestamp(item.UpdatedAt)
		item.OverviewHref = "/engagements/" + item.Slug
		item.ScopeHref = "/engagements/" + item.Slug + "/scope"
		item.ZonesHref = "/engagements/" + item.Slug + "/zones"
		item.HostsHref = "/engagements/" + item.Slug + "/hosts"
		item.PortsHref = "/engagements/" + item.Slug + "/ports"
		item.FindingsHref = "/engagements/" + item.Slug + "/findings"
		item.SourcesHref = "/engagements/" + item.Slug + "/sources"
		item.CampaignsHref = "/engagements/" + item.Slug + "/campaigns"
		item.SettingsHref = "/engagements/" + item.Slug + "/settings"
		items[item.ID] = item
	}
	return items, rows.Err()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func toneForToolStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "installed", "configured", "ready":
		return "ok"
	case "endpoint unchecked":
		return "accent"
	case "needs config":
		return "warning"
	default:
		return "risk"
	}
}

func toneForRunStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed":
		return "ok"
	case "running":
		return "accent"
	case "queued":
		return "warning"
	default:
		return "risk"
	}
}

func toneForWorkerStatus(status string, lastSeenAt string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "online":
		return "ok"
	case "degraded":
		return "warning"
	default:
		if lastSeenAt == "" {
			return "risk"
		}
		return "warning"
	}
}

func normalizeRole(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "owner", "editor", "viewer":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "viewer"
	}
}

func requiredConfigForPlugin(pluginID string) []string {
	switch strings.TrimSpace(pluginID) {
	case "burp-connector":
		return []string{"BURP_API_URL", "BURP_API_TOKEN"}
	case "zap-connector":
		return []string{"ZAP_API_URL", "ZAP_API_KEY"}
	case "tenable-connector":
		return []string{"TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY", "TENABLE_SCAN_ID"}
	case "nessus-connector":
		return []string{"NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY", "NESSUS_SCAN_ID"}
	default:
		return nil
	}
}

func remoteAddrFromRequest(requestRemote string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(requestRemote))
	if err == nil {
		return host
	}
	return strings.TrimSpace(requestRemote)
}

var errPlatformForbidden = errors.New("forbidden")
