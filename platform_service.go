package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const platformSessionCookie = "nwa_session"

type platformService struct {
	logger        *slog.Logger
	store         *platformStore
	center        *commandCenter
	bootstrapHint string
}

func newPlatformService(center *commandCenter, logger *slog.Logger) (*platformService, error) {
	if center == nil || center.service == nil {
		return nil, nil
	}
	store, err := newPlatformStore(center.service)
	if err != nil {
		return nil, err
	}
	service := &platformService{
		logger: logger,
		store:  store,
		center: center,
	}
	if err := service.ensureBootstrapAdmin(); err != nil {
		return nil, err
	}
	if err := service.syncToolCatalog(); err != nil {
		return nil, err
	}
	if err := service.syncLegacyWorkspaces(); err != nil {
		return nil, err
	}
	if err := service.heartbeatLocalWorker(); err != nil {
		return nil, err
	}
	return service, nil
}

func (p *platformService) ensureBootstrapAdmin() error {
	hasUsers, err := p.store.hasUsers()
	if err != nil {
		return err
	}
	if hasUsers {
		return nil
	}

	username := chooseString(strings.TrimSpace(os.Getenv("NWA_ADMIN_USERNAME")), "admin")
	email := chooseString(strings.TrimSpace(os.Getenv("NWA_ADMIN_EMAIL")), "admin@nwa.local")
	password := strings.TrimSpace(os.Getenv("NWA_ADMIN_PASSWORD"))
	if password == "" {
		password = randomToken(12)
		p.bootstrapHint = fmt.Sprintf("Bootstrap account: %s / %s", username, password)
		if p.logger != nil {
			p.logger.Warn("created bootstrap admin account", "username", username, "email", email, "temporary_password", password)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return p.store.createUser(platformUserRecord{
		ID:           newWorkspaceID("user"),
		Username:     username,
		Email:        email,
		DisplayName:  "Platform Admin",
		PasswordHash: string(hash),
		IsAdmin:      true,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}

func (p *platformService) syncToolCatalog() error {
	workspace, _, err := p.center.defaultWorkspace()
	if err != nil || workspace == nil || workspace.plugins == nil {
		return nil
	}
	for _, item := range workspace.plugins.catalog() {
		if err := p.store.upsertToolDefinition(item, requiredConfigForPlugin(item.ID)); err != nil {
			return err
		}
		availability := resolveDefinitionAvailability(item, nil)
		if err := p.store.upsertToolInstallation(item.ID, availability.Label, chooseString(availability.Reason, item.Description)); err != nil {
			return err
		}
		if strings.Contains(item.ID, "connector") {
			if err := p.store.upsertConnectorConfig(item.ID, item.Label, availability.Label, chooseString(availability.Reason, item.Description)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *platformService) heartbeatLocalWorker() error {
	now := time.Now().UTC().Format(time.RFC3339)
	return p.store.upsertWorker(platformWorkerRecord{
		ID:         "central-local",
		Label:      "Central Worker",
		Mode:       "central",
		Zone:       "default",
		Status:     "online",
		Detail:     "Built-in local execution worker",
		LastSeenAt: now,
		UpdatedAt:  now,
	})
}

func (p *platformService) syncLegacyWorkspaces() error {
	workspaces, err := p.center.listWorkspaces()
	if err != nil {
		return err
	}
	admin, err := p.firstAdmin()
	if err != nil {
		return err
	}
	for _, meta := range workspaces {
		if _, err := p.store.engagementByWorkspaceID(meta.ID); err == nil {
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		slug, err := p.nextEngagementSlug(meta.Slug)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339)
		record := platformEngagementRecord{
			ID:                newWorkspaceID("eng"),
			Slug:              slug,
			Name:              chooseString(meta.Name, meta.Slug),
			Description:       chooseString(meta.Description, "Imported execution workspace"),
			ScopeSummary:      "",
			Status:            "active",
			LegacyWorkspaceID: meta.ID,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		if err := p.store.createEngagement(record); err != nil {
			return err
		}
		if err := p.store.addMembership(platformMembershipRecord{
			EngagementID: record.ID,
			UserID:       admin.ID,
			Role:         "owner",
			CreatedAt:    now,
		}); err != nil {
			return err
		}
		if err := p.syncEngagement(record); err != nil {
			return err
		}
	}
	return nil
}

func (p *platformService) firstAdmin() (platformUserRecord, error) {
	users, err := p.store.listUsers()
	if err != nil {
		return platformUserRecord{}, err
	}
	for _, user := range users {
		if user.IsAdmin {
			return user, nil
		}
	}
	return platformUserRecord{}, errors.New("no admin user exists")
}

func (p *platformService) nextEngagementSlug(base string) (string, error) {
	slug := slugifyWorkspaceName(base)
	if slug == "" {
		slug = "engagement"
	}
	candidate := slug
	for index := 2; index < 1000; index++ {
		_, err := p.store.engagementBySlug(candidate)
		if errors.Is(err, sql.ErrNoRows) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
		candidate = fmt.Sprintf("%s-%d", slug, index)
	}
	return "", errors.New("unable to allocate engagement slug")
}

func (p *platformService) authenticate(login string, password string, request *http.Request) (platformUserRecord, string, error) {
	user, err := p.store.userByLogin(login)
	if err != nil {
		return platformUserRecord{}, "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return platformUserRecord{}, "", errors.New("invalid credentials")
	}
	if err := p.store.touchUserLogin(user.ID); err != nil {
		return platformUserRecord{}, "", err
	}
	now := time.Now().UTC()
	token := randomToken(32)
	session := platformSessionRecord{
		ID:         newWorkspaceID("sess"),
		UserID:     user.ID,
		Token:      token,
		CreatedAt:  now.Format(time.RFC3339),
		ExpiresAt:  now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		LastSeenAt: now.Format(time.RFC3339),
		UserAgent:  strings.TrimSpace(request.UserAgent()),
		RemoteAddr: remoteAddrFromRequest(request.RemoteAddr),
	}
	if err := p.store.createSession(session); err != nil {
		return platformUserRecord{}, "", err
	}
	_ = p.store.recordAudit(platformAuditRecord{
		ID:        newWorkspaceID("audit"),
		UserID:    user.ID,
		Kind:      "auth.login",
		Summary:   fmt.Sprintf("%s signed in", user.Username),
		CreatedAt: now.Format(time.RFC3339),
	})
	return user, token, nil
}

func (p *platformService) logout(token string, user platformUserRecord) {
	_ = p.store.deleteSession(token)
	_ = p.store.recordAudit(platformAuditRecord{
		ID:        newWorkspaceID("audit"),
		UserID:    user.ID,
		Kind:      "auth.logout",
		Summary:   fmt.Sprintf("%s signed out", user.Username),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func (p *platformService) userFromRequest(request *http.Request) (platformUserRecord, string, error) {
	cookie, err := request.Cookie(platformSessionCookie)
	if err != nil {
		return platformUserRecord{}, "", err
	}
	session, err := p.store.sessionByToken(cookie.Value)
	if err != nil {
		return platformUserRecord{}, "", err
	}
	if expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt); err == nil && time.Now().UTC().After(expiresAt) {
		_ = p.store.deleteSession(session.Token)
		return platformUserRecord{}, "", errors.New("session expired")
	}
	_ = p.store.touchSession(session.Token)
	user, err := p.store.userByID(session.UserID)
	if err != nil {
		return platformUserRecord{}, "", err
	}
	return user, session.Token, nil
}

func (p *platformService) requireEngagement(user platformUserRecord, slug string) (platformEngagementRecord, string, error) {
	engagement, err := p.store.engagementBySlug(slug)
	if err != nil {
		return platformEngagementRecord{}, "", err
	}
	role, err := p.store.roleForUser(engagement.ID, user)
	if err != nil {
		return platformEngagementRecord{}, "", errPlatformForbidden
	}
	if err := p.syncEngagement(engagement); err != nil {
		return platformEngagementRecord{}, "", err
	}
	return engagement, role, nil
}

func (p *platformService) createEngagement(owner platformUserRecord, name string, description string, scope string) (platformEngagementRecord, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "New Engagement"
	}
	meta, err := p.center.service.createWorkspace(name, description)
	if err != nil {
		return platformEngagementRecord{}, err
	}
	slug, err := p.nextEngagementSlug(name)
	if err != nil {
		return platformEngagementRecord{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := platformEngagementRecord{
		ID:                newWorkspaceID("eng"),
		Slug:              slug,
		Name:              name,
		Description:       strings.TrimSpace(description),
		ScopeSummary:      strings.TrimSpace(scope),
		Status:            "active",
		LegacyWorkspaceID: meta.ID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := p.store.createEngagement(record); err != nil {
		return platformEngagementRecord{}, err
	}
	if err := p.store.addMembership(platformMembershipRecord{
		EngagementID: record.ID,
		UserID:       owner.ID,
		Role:         "owner",
		CreatedAt:    now,
	}); err != nil {
		return platformEngagementRecord{}, err
	}
	workspace, _, err := p.center.loadWorkspaceByID(meta.ID)
	if err != nil {
		return platformEngagementRecord{}, err
	}
	kickoffErr := error(nil)
	if strings.TrimSpace(scope) != "" {
		campaign, err := workspace.ingestScope("Engagement kickoff", scope, "engagement-create", false)
		if err != nil {
			return platformEngagementRecord{}, err
		}
		if strings.TrimSpace(campaign.ApprovalID) != "" {
			if err := workspace.approveKickoff(campaign.ApprovalID); err != nil {
				kickoffErr = err
				if p.logger != nil {
					p.logger.Warn("engagement kickoff degraded", "engagement", record.Slug, "error", err)
				}
			}
		}
	}
	if err := p.syncEngagement(record); err != nil {
		return platformEngagementRecord{}, err
	}
	_ = p.store.recordAudit(platformAuditRecord{
		ID:           newWorkspaceID("audit"),
		UserID:       owner.ID,
		EngagementID: record.ID,
		Kind:         "engagement.create",
		Summary:      fmt.Sprintf("Created engagement %s", record.Name),
		CreatedAt:    now,
	})
	if kickoffErr != nil {
		_ = p.store.recordAudit(platformAuditRecord{
			ID:           newWorkspaceID("audit"),
			UserID:       owner.ID,
			EngagementID: record.ID,
			Kind:         "engagement.kickoff.degraded",
			Summary:      fmt.Sprintf("Engagement %s created with blocked kickoff: %s", record.Name, kickoffErr.Error()),
			CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		})
	}
	return record, nil
}

func (p *platformService) addEngagementMember(actor platformUserRecord, engagement platformEngagementRecord, usernameOrEmail string, role string) error {
	user, err := p.store.userByLogin(usernameOrEmail)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := p.store.addMembership(platformMembershipRecord{
		EngagementID: engagement.ID,
		UserID:       user.ID,
		Role:         normalizeRole(role),
		CreatedAt:    now,
	}); err != nil {
		return err
	}
	return p.store.recordAudit(platformAuditRecord{
		ID:           newWorkspaceID("audit"),
		UserID:       actor.ID,
		EngagementID: engagement.ID,
		Kind:         "membership.add",
		Summary:      fmt.Sprintf("Added %s as %s", user.Username, normalizeRole(role)),
		CreatedAt:    now,
	})
}

func (p *platformService) createPlatformUser(actor platformUserRecord, username string, email string, password string, displayName string, admin bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	record := platformUserRecord{
		ID:           newWorkspaceID("user"),
		Username:     strings.TrimSpace(username),
		Email:        strings.TrimSpace(email),
		DisplayName:  chooseString(strings.TrimSpace(displayName), strings.TrimSpace(username)),
		PasswordHash: string(hash),
		IsAdmin:      admin,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := p.store.createUser(record); err != nil {
		return err
	}
	return p.store.recordAudit(platformAuditRecord{
		ID:        newWorkspaceID("audit"),
		UserID:    actor.ID,
		Kind:      "user.create",
		Summary:   fmt.Sprintf("Created user %s", record.Username),
		CreatedAt: now,
	})
}

func (p *platformService) syncEngagement(engagement platformEngagementRecord) error {
	workspace, _, err := p.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		return err
	}
	snapshot := workspace.currentSnapshot()
	scanTimes := workspace.scanTimeByName()
	findings := findingGroupsForRecords(snapshot.records, scanTimes)
	scopeSeeds := workspace.scopeSeedViews()
	scopeTargets := workspace.scopeTargetViews()
	chunks := workspace.targetChunkViews()
	approvals := workspace.approvalViews()
	scans := workspace.scanCatalog()
	jobs := workspace.plugins.recentJobs(0)
	zones, zoneMemberships := deriveZones(engagement, snapshot.records, scopeSeeds)

	hostZoneCounts := map[string]int{}
	for _, hostIPs := range zoneMemberships {
		for _, hostIP := range hostIPs {
			hostZoneCounts[hostIP]++
		}
	}

	projectedSeeds := make([]platformScopeSeedRecord, 0, len(scopeSeeds))
	for _, item := range scopeSeeds {
		payload, _ := json.Marshal(item)
		projectedSeeds = append(projectedSeeds, platformScopeSeedRecord{
			ID:        item.ID,
			CreatedAt: reverseDisplayTimestamp(item.CreatedAt),
			Payload:   string(payload),
		})
	}

	projectedTargets := make([]platformScopeTargetRecord, 0, len(scopeTargets))
	for _, item := range scopeTargets {
		payload, _ := json.Marshal(item)
		projectedTargets = append(projectedTargets, platformScopeTargetRecord{
			ID:        item.ID,
			CreatedAt: reverseDisplayTimestamp(item.CreatedAt),
			Payload:   string(payload),
		})
	}

	projectedChunks := make([]platformChunkRecord, 0, len(chunks))
	chunkNames := map[string]string{}
	for _, item := range chunks {
		payload, _ := json.Marshal(item)
		projectedChunks = append(projectedChunks, platformChunkRecord{
			ID:        item.ID,
			CreatedAt: reverseDisplayTimestamp(item.CreatedAt),
			Payload:   string(payload),
		})
		chunkNames[item.ID] = item.Name
	}

	projectedApprovals := make([]platformApprovalRow, 0, len(approvals))
	for _, item := range approvals {
		payload, _ := json.Marshal(item)
		projectedApprovals = append(projectedApprovals, platformApprovalRow{
			ID:        item.ID,
			CreatedAt: reverseDisplayTimestamp(item.CreatedAt),
			Payload:   string(payload),
		})
	}

	projectedSources := make([]platformSourceRecord, 0, len(scans))
	for _, item := range scans {
		view := PlatformSourceView{
			ID:         item.ID,
			Name:       item.Name,
			Kind:       item.Kind,
			Scanner:    item.Scanner,
			LiveHosts:  item.LiveHosts,
			ImportedAt: displayTimestamp(item.ImportedAt),
		}
		payload, _ := json.Marshal(view)
		projectedSources = append(projectedSources, platformSourceRecord{
			ID:         item.ID,
			Name:       item.Name,
			Kind:       item.Kind,
			Scanner:    item.Scanner,
			LiveHosts:  item.LiveHosts,
			ImportedAt: item.ImportedAt,
			Payload:    string(payload),
		})
	}

	projectedRuns := make([]platformRunRecord, 0, len(jobs))
	for _, item := range jobs {
		payload, _ := json.Marshal(item)
		projectedRuns = append(projectedRuns, platformRunRecord{
			ID:          item.ID,
			ToolID:      item.PluginID,
			ToolLabel:   item.PluginLabel,
			Status:      item.Status,
			Stage:       item.Stage,
			ChunkID:     item.ChunkID,
			ChunkName:   chunkNames[item.ChunkID],
			TargetCount: item.TargetCount,
			Summary:     item.Summary,
			Error:       item.Error,
			CreatedAt:   reverseDisplayTimestamp(item.CreatedAt),
			StartedAt:   reverseDisplayTimestamp(item.StartedAt),
			FinishedAt:  reverseDisplayTimestamp(item.FinishedAt),
			WorkerMode:  item.WorkerMode,
			WorkerZone:  item.WorkerZone,
			Payload:     string(payload),
		})
	}

	projectedZones := make([]platformZoneRecord, 0, len(zones))
	for _, zone := range zones {
		projectedZones = append(projectedZones, platformZoneRecord{
			ID:        zone.ID,
			Name:      zone.Name,
			Kind:      zone.Kind,
			Scope:     zone.Scope,
			HostCount: zone.HostCount,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}

	projectedHosts := make([]platformHostRecord, 0, len(snapshot.records))
	hostnames := map[string][]string{}
	projectedPorts := make([]platformPortRecord, 0)
	projectedFindings := make([]platformFindingRecord, 0, len(findings))
	projectedOccurrences := make([]platformFindingOccurrenceRecord, 0)

	for _, record := range snapshot.records {
		hostView := PlatformHostView{
			IP:           record.summary.IP,
			DisplayName:  chooseString(record.summary.DisplayName, record.summary.IP),
			OS:           record.summary.OS,
			ZoneCount:    hostZoneCounts[record.summary.IP],
			OpenPorts:    record.summary.OpenPortCount,
			Findings:     record.summary.Findings.Total,
			Critical:     record.summary.Findings.Critical,
			High:         record.summary.Findings.High,
			Exposure:     record.summary.Exposure.Label,
			ExposureTone: record.summary.Exposure.Tone,
			Coverage:     record.summary.Coverage.Label,
			SourceCount:  record.summary.SourceCount,
			Href:         "/engagements/" + engagement.Slug + "/hosts?query=" + url.QueryEscape(record.summary.IP),
		}
		payload, _ := json.Marshal(hostView)
		projectedHosts = append(projectedHosts, platformHostRecord{
			IP:              record.summary.IP,
			DisplayName:     hostView.DisplayName,
			OSName:          record.summary.OS,
			ExposureLabel:   record.summary.Exposure.Label,
			ExposureTone:    record.summary.Exposure.Tone,
			ExposureScore:   record.summary.Exposure.Score,
			CoverageLabel:   record.summary.Coverage.Label,
			SourceCount:     record.summary.SourceCount,
			OpenPortCount:   record.summary.OpenPortCount,
			FindingTotal:    record.summary.Findings.Total,
			FindingCritical: record.summary.Findings.Critical,
			FindingHigh:     record.summary.Findings.High,
			ZoneCount:       hostZoneCounts[record.summary.IP],
			UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
			Payload:         string(payload),
		})
		hostnames[record.summary.IP] = append(hostnames[record.summary.IP], record.summary.Hostnames...)

		hostLevelFindings := 0
		for _, finding := range record.detail.NucleiFindings {
			portNumber := extractTargetPort(finding.Target)
			if portNumber != "" {
				continue
			}
			hostLevelFindings++
		}
		if hostLevelFindings > 0 {
			payload, _ := json.Marshal(PortRow{
				Port:     "0",
				Protocol: "host",
				State:    "open",
				Service:  "Host-level",
				Product:  "Host-level",
			})
			projectedPorts = append(projectedPorts, platformPortRecord{
				HostIP:       record.summary.IP,
				Protocol:     "host",
				PortNumber:   0,
				Label:        "host/0",
				ServiceName:  "Host-level",
				State:        "open",
				FindingTotal: hostLevelFindings,
				UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
				Payload:      string(payload),
			})
		}
		for _, port := range record.detail.Ports {
			portNumber, _ := strconv.Atoi(port.Port)
			payload, _ := json.Marshal(port)
			projectedPorts = append(projectedPorts, platformPortRecord{
				HostIP:       record.summary.IP,
				Protocol:     port.Protocol,
				PortNumber:   portNumber,
				Label:        port.Protocol + "/" + port.Port,
				ServiceName:  chooseString(port.Service, port.Product, "unknown service"),
				State:        port.State,
				FindingTotal: countPortFindings(record.detail.NucleiFindings, record.summary.IP, port.Protocol, port.Port),
				UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
				Payload:      string(payload),
			})
		}
	}

	grouped := groupFindings(snapshot.records, scanTimes)
	for _, group := range findings {
		payload, _ := json.Marshal(group)
		projectedFindings = append(projectedFindings, platformFindingRecord{
			ID:          group.ID,
			TemplateID:  group.TemplateID,
			Name:        group.Name,
			Source:      group.Source,
			Severity:    group.Severity,
			Occurrences: group.Occurrences,
			Hosts:       group.Hosts,
			Ports:       group.Ports,
			FirstSeen:   reverseDisplayTimestamp(group.FirstSeen),
			LastSeen:    reverseDisplayTimestamp(group.LastSeen),
			UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
			Payload:     string(payload),
		})
		if accumulator := grouped[group.ID]; accumulator != nil {
			for _, occurrence := range accumulator.occurrences {
				portNumber := 0
				protocol := "host"
				if occurrence.Port != "" {
					portNumber, _ = strconv.Atoi(occurrence.Port)
					protocol = protocolForHostPort(snapshot.hostByIP[occurrence.HostIP], occurrence.Port)
				}
				payload, _ := json.Marshal(occurrence)
				projectedOccurrences = append(projectedOccurrences, platformFindingOccurrenceRecord{
					FindingID:  group.ID,
					HostIP:     occurrence.HostIP,
					Protocol:   protocol,
					PortNumber: portNumber,
					Target:     occurrence.Target,
					MatchedAt:  reverseDisplayTimestamp(occurrence.MatchedAt),
					Payload:    string(payload),
				})
			}
		}
	}

	if err := p.store.replaceEngagementProjection(
		engagement.ID,
		projectedSeeds,
		projectedTargets,
		projectedChunks,
		projectedApprovals,
		projectedSources,
		projectedRuns,
		projectedZones,
		zoneMemberships,
		projectedHosts,
		hostnames,
		projectedPorts,
		projectedFindings,
		projectedOccurrences,
	); err != nil {
		return err
	}
	scopeSummary := summarizeScopeSeeds(scopeSeeds)
	if scopeSummary != "" {
		_ = p.store.updateEngagementScopeSummary(engagement.ID, scopeSummary)
	}
	return p.heartbeatLocalWorker()
}

func deriveZones(engagement platformEngagementRecord, records []hostRecord, seeds []ScopeSeedView) ([]PlatformZoneView, map[string][]string) {
	type zone struct {
		view  PlatformZoneView
		hosts map[string]struct{}
	}
	zones := map[string]*zone{}
	addZone := func(id string, name string, kind string, scope string, hostIP string) {
		entry := zones[id]
		if entry == nil {
			entry = &zone{
				view:  PlatformZoneView{ID: id, Name: name, Kind: kind, Scope: scope},
				hosts: map[string]struct{}{},
			}
			zones[id] = entry
		}
		if strings.TrimSpace(hostIP) != "" {
			entry.hosts[hostIP] = struct{}{}
		}
	}

	for _, record := range records {
		addZone("all", "All hosts", "global", engagement.ScopeSummary, record.summary.IP)
		if addr, err := netip.ParseAddr(record.summary.IP); err == nil {
			if addr.Is4() {
				prefix := netip.PrefixFrom(addr, 24).Masked().String()
				addZone("subnet-"+prefix, prefix, "subnet", prefix, record.summary.IP)
			} else if addr.Is6() {
				prefix := netip.PrefixFrom(addr, 64).Masked().String()
				addZone("subnet-"+prefix, prefix, "subnet", prefix, record.summary.IP)
			}
		}
		for _, hostname := range record.summary.Hostnames {
			suffix := zoneDomainSuffix(hostname)
			if suffix != "" {
				addZone("dns-"+suffix, suffix, "dns", suffix, record.summary.IP)
			}
		}
	}

	for _, seed := range seeds {
		switch strings.ToLower(seed.Kind) {
		case "cidr":
			prefix, err := netip.ParsePrefix(seed.Value)
			if err != nil {
				continue
			}
			for _, record := range records {
				if addr, err := netip.ParseAddr(record.summary.IP); err == nil && prefix.Contains(addr) {
					addZone("scope-"+seed.Value, seed.Value, "scope", seed.Detail, record.summary.IP)
				}
			}
		case "domain", "hostname":
			value := strings.ToLower(strings.TrimSpace(seed.Value))
			for _, record := range records {
				for _, hostname := range record.summary.Hostnames {
					if strings.HasSuffix(strings.ToLower(hostname), value) {
						addZone("scope-"+value, value, "scope", seed.Detail, record.summary.IP)
						break
					}
				}
			}
		}
	}

	views := make([]PlatformZoneView, 0, len(zones))
	membership := map[string][]string{}
	for id, entry := range zones {
		entry.view.HostCount = len(entry.hosts)
		views = append(views, entry.view)
		for hostIP := range entry.hosts {
			membership[id] = append(membership[id], hostIP)
		}
	}
	sort.SliceStable(views, func(left, right int) bool {
		if views[left].HostCount != views[right].HostCount {
			return views[left].HostCount > views[right].HostCount
		}
		return views[left].Name < views[right].Name
	})
	return views, membership
}

func zoneDomainSuffix(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return ""
}

func summarizeScopeSeeds(seeds []ScopeSeedView) string {
	values := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		values = append(values, seed.Value)
	}
	return strings.Join(values, ", ")
}

func reverseDisplayTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "n/a" {
		return ""
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	return value
}

func protocolForHostPort(host HostDetail, port string) string {
	for _, item := range host.Ports {
		if item.Port == port && strings.EqualFold(item.State, "open") {
			return chooseString(item.Protocol, "tcp")
		}
	}
	return "host"
}

func randomToken(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}
