package main

import (
	"fmt"
	"io"
	"strings"
)

type platformCampaignActionInput struct {
	Action        string   `json:"action"`
	PolicyID      string   `json:"policyId"`
	StepID        string   `json:"stepId"`
	StepOrder     []string `json:"stepOrder"`
	Label         string   `json:"label"`
	Trigger       string   `json:"trigger"`
	PluginID      string   `json:"pluginId"`
	Stage         string   `json:"stage"`
	TargetSource  string   `json:"targetSource"`
	MatchKinds    []string `json:"matchKinds"`
	WhenPlugin    string   `json:"whenPlugin"`
	WhenProfile   string   `json:"whenProfile"`
	Summary       string   `json:"summary"`
	TargetMode    string   `json:"targetMode"`
	Targets       []string `json:"targets"`
	ProfileScope  string   `json:"profileScope"`
	Severity      string   `json:"severity"`
	Templates     string   `json:"templates"`
	Concurrency   string   `json:"concurrency"`
	Profile       string   `json:"profile"`
	Ports         string   `json:"ports"`
	TopPorts      string   `json:"topPorts"`
	CrawlDepth    string   `json:"crawlDepth"`
	Level         string   `json:"level"`
	Risk          string   `json:"risk"`
	APIBaseURL    string   `json:"apiBaseURL"`
	ScanID        string   `json:"scanId"`
	SiteID        string   `json:"siteId"`
	ParentID      string   `json:"parentId"`
	ScanConfigIDs string   `json:"scanConfigIds"`
	APIInsecure   bool     `json:"apiInsecure"`
	ExtraArgs     string   `json:"extraArgs"`
}

func (app *application) runEngagementCampaignAction(engagement platformEngagementRecord, role string, input platformCampaignActionInput) error {
	if role == "viewer" {
		return errPlatformForbidden
	}
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		return err
	}
	action := chooseString(strings.TrimSpace(input.Action), "queue_run")

	switch action {
	case "activate_policy":
		if err := workspace.setActivePolicy(strings.TrimSpace(input.PolicyID)); err != nil {
			return err
		}
		return app.platform.syncEngagement(engagement)
	case "add_policy_step":
		step := orchestrationStepRecord{
			Label:        strings.TrimSpace(input.Label),
			Trigger:      strings.TrimSpace(input.Trigger),
			PluginID:     strings.TrimSpace(input.PluginID),
			Stage:        strings.TrimSpace(input.Stage),
			TargetSource: strings.TrimSpace(input.TargetSource),
			MatchKinds:   input.MatchKinds,
			WhenPlugin:   strings.TrimSpace(input.WhenPlugin),
			WhenProfile:  strings.TrimSpace(input.WhenProfile),
			Summary:      strings.TrimSpace(input.Summary),
			Options: map[string]string{
				"profile":   strings.TrimSpace(input.Profile),
				"ports":     strings.TrimSpace(input.Ports),
				"top_ports": strings.TrimSpace(input.TopPorts),
			},
		}
		return workspace.addPolicyStep(strings.TrimSpace(input.PolicyID), step)
	case "reorder_policy":
		return workspace.reorderPolicySteps(strings.TrimSpace(input.PolicyID), input.StepOrder)
	case "remove_policy_step":
		return workspace.removePolicyStep(strings.TrimSpace(input.PolicyID), strings.TrimSpace(input.StepID))
	}

	pluginID := strings.TrimSpace(input.PluginID)
	targetMode := strings.TrimSpace(input.TargetMode)

	var (
		rawTargets []string
		hostIPs    []string
		summary    string
	)

	switch targetMode {
	case "manual":
		rawTargets = uniqueStrings(input.Targets)
		hostIPs = resolveKnownHosts(workspace.currentSnapshot(), rawTargets)
		summary = fmt.Sprintf("manual scope · %d targets", len(rawTargets))
	case "engagement":
		rawTargets, hostIPs, summary = workspace.profileTargets(pluginID, "all-hosts")
	default:
		rawTargets, hostIPs, summary = workspace.profileTargets(pluginID, strings.TrimSpace(input.ProfileScope))
	}

	options := map[string]string{
		"severity":        strings.TrimSpace(input.Severity),
		"templates":       strings.TrimSpace(input.Templates),
		"concurrency":     strings.TrimSpace(input.Concurrency),
		"profile":         strings.TrimSpace(input.Profile),
		"profile_scope":   strings.TrimSpace(input.ProfileScope),
		"ports":           strings.TrimSpace(input.Ports),
		"top_ports":       strings.TrimSpace(input.TopPorts),
		"crawl_depth":     strings.TrimSpace(input.CrawlDepth),
		"level":           strings.TrimSpace(input.Level),
		"risk":            strings.TrimSpace(input.Risk),
		"api_base_url":    strings.TrimSpace(input.APIBaseURL),
		"scan_id":         strings.TrimSpace(input.ScanID),
		"site_id":         strings.TrimSpace(input.SiteID),
		"parent_id":       strings.TrimSpace(input.ParentID),
		"scan_config_ids": strings.TrimSpace(input.ScanConfigIDs),
		"api_insecure":    boolString(input.APIInsecure),
		"extra_args":      strings.TrimSpace(input.ExtraArgs),
	}

	if _, err := workspace.plugins.submitDetailed(pluginSubmission{
		PluginID:   pluginID,
		RawTargets: rawTargets,
		HostIPs:    hostIPs,
		Summary:    summary,
		Options:    options,
		WorkerMode: "central",
	}); err != nil {
		return err
	}

	return app.platform.syncEngagement(engagement)
}

func (app *application) importEngagementSourceFile(engagement platformEngagementRecord, filename string, body io.Reader) error {
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		return err
	}
	if _, err := workspace.importUploadedScan(filename, body); err != nil {
		return err
	}
	return app.platform.syncEngagement(engagement)
}

func (app *application) addEngagementMembership(actor platformUserRecord, engagement platformEngagementRecord, username string, role string) error {
	return app.platform.addEngagementMember(actor, engagement, username, role)
}

func (app *application) approveEngagementApproval(engagement platformEngagementRecord, approvalID string) error {
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		return err
	}
	if err := workspace.approveKickoff(strings.TrimSpace(approvalID)); err != nil {
		return err
	}
	return app.platform.syncEngagement(engagement)
}

func (app *application) requestEngagementLLMRecommendations(engagement platformEngagementRecord, campaignID string) error {
	workspace, _, err := app.center.loadWorkspaceByID(engagement.LegacyWorkspaceID)
	if err != nil {
		return err
	}
	if _, err := workspace.generateLLMRecommendations(strings.TrimSpace(campaignID)); err != nil {
		return err
	}
	return app.platform.syncEngagement(engagement)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return ""
}
