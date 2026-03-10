package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	toolInstallSourceBuiltin = "builtin"
	toolInstallSourceCustom  = "custom"
)

type toolInstallRequest struct {
	ID             string                   `json:"id"`
	Label          string                   `json:"label"`
	Description    string                   `json:"description"`
	Family         string                   `json:"family"`
	BinaryName     string                   `json:"binary_name"`
	TargetStrategy string                   `json:"target_strategy"`
	Capabilities   []string                 `json:"capabilities"`
	SafetyClass    string                   `json:"safety_class"`
	CostProfile    string                   `json:"cost_profile"`
	Profiles       []ToolCommandProfileView `json:"profiles"`
}

func normalizeInstalledToolRequest(input toolInstallRequest) (PluginDefinitionView, error) {
	label := strings.TrimSpace(input.Label)
	if label == "" {
		return PluginDefinitionView{}, errors.New("tool label is required")
	}
	toolID := slugifyWorkspaceName(chooseString(strings.TrimSpace(input.ID), label))
	if toolID == "" {
		return PluginDefinitionView{}, errors.New("tool id is required")
	}
	binaryName := strings.TrimSpace(input.BinaryName)
	if binaryName == "" {
		return PluginDefinitionView{}, errors.New("binary_name is required")
	}

	profiles, err := normalizeToolProfiles(input.Profiles)
	if err != nil {
		return PluginDefinitionView{}, err
	}
	if len(profiles) == 0 {
		return PluginDefinitionView{}, errors.New("at least one command profile is required")
	}

	return normalizedPluginDefinition(PluginDefinitionView{
		ID:                     toolID,
		Label:                  label,
		Description:            chooseString(strings.TrimSpace(input.Description), label+" managed command"),
		Mode:                   "Managed command",
		Family:                 chooseString(strings.TrimSpace(input.Family), "Custom managed commands"),
		Kind:                   "managed-command",
		InstallSource:          toolInstallSourceCustom,
		BinaryName:             binaryName,
		TargetStrategy:         normalizeTargetStrategy(input.TargetStrategy),
		Capabilities:           normalizeCapabilities(input.Capabilities),
		Profiles:               profiles,
		SafetyClass:            normalizeSafetyClass(input.SafetyClass),
		CostProfile:            normalizeCostProfile(input.CostProfile),
		CommandEditable:        true,
		DefaultCommandTemplate: "{{binary}} {{args}}",
	}), nil
}

func normalizeCapabilities(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	items := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func normalizeSafetyClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "passive":
		return "passive"
	case "controlled":
		return "controlled"
	case "active":
		return "active"
	default:
		return "active"
	}
}

func normalizeCostProfile(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return "low"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "medium"
	}
}

func normalizeTargetStrategy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "web", "http", "http-targets":
		return "web"
	case "domain", "domains":
		return "domain"
	case "manual":
		return "manual"
	case "host", "hosts", "ip":
		return "host"
	default:
		return "host"
	}
}

func normalizeToolProfiles(values []ToolCommandProfileView) ([]ToolCommandProfileView, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	items := make([]ToolCommandProfileView, 0, len(values))
	defaultSeen := false
	for index, profile := range values {
		label := strings.TrimSpace(profile.Label)
		command := strings.TrimSpace(profile.Command)
		if label == "" {
			return nil, fmt.Errorf("profile %d label is required", index+1)
		}
		if command == "" {
			return nil, fmt.Errorf("profile %q command is required", label)
		}
		if !strings.Contains(command, "{{targets_file}}") {
			return nil, fmt.Errorf("profile %q command must include {{targets_file}}", label)
		}
		profileID := slugifyWorkspaceName(chooseString(strings.TrimSpace(profile.ID), label))
		if profileID == "" {
			return nil, fmt.Errorf("profile %q id is required", label)
		}
		if _, ok := seen[profileID]; ok {
			return nil, fmt.Errorf("duplicate profile id %q", profileID)
		}
		seen[profileID] = struct{}{}
		normalized := ToolCommandProfileView{
			ID:          profileID,
			Label:       label,
			Description: strings.TrimSpace(profile.Description),
			Command:     command,
			Default:     profile.Default,
		}
		if normalized.Default {
			if defaultSeen {
				return nil, errors.New("only one profile can be marked as default")
			}
			defaultSeen = true
		}
		items = append(items, normalized)
	}
	if len(items) > 0 && !defaultSeen {
		items[0].Default = true
	}
	return items, nil
}

func cloneToolProfiles(values []ToolCommandProfileView) []ToolCommandProfileView {
	if len(values) == 0 {
		return nil
	}
	items := make([]ToolCommandProfileView, 0, len(values))
	for _, value := range values {
		items = append(items, ToolCommandProfileView{
			ID:          strings.TrimSpace(value.ID),
			Label:       strings.TrimSpace(value.Label),
			Description: strings.TrimSpace(value.Description),
			Command:     strings.TrimSpace(value.Command),
			Default:     value.Default,
		})
	}
	return items
}

func defaultToolProfile(profiles []ToolCommandProfileView) ToolCommandProfileView {
	for _, profile := range profiles {
		if profile.Default {
			return profile
		}
	}
	if len(profiles) > 0 {
		return profiles[0]
	}
	return ToolCommandProfileView{}
}

func toolProfileByID(profiles []ToolCommandProfileView, profileID string) (ToolCommandProfileView, bool) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		profile := defaultToolProfile(profiles)
		return profile, profile.ID != ""
	}
	for _, profile := range profiles {
		if profile.ID == profileID {
			return profile, true
		}
	}
	return ToolCommandProfileView{}, false
}

func modeForPluginKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case "api-connector":
		return "API connector"
	case "importer":
		return "Import"
	default:
		return "Managed command"
	}
}

func pluginDefinitionFromToolView(item PlatformToolView) PluginDefinitionView {
	return normalizedPluginDefinition(PluginDefinitionView{
		ID:                     item.ID,
		Label:                  item.Label,
		Description:            item.Description,
		Mode:                   modeForPluginKind(item.Kind),
		Family:                 item.Family,
		Kind:                   item.Kind,
		InstallSource:          chooseString(strings.TrimSpace(item.InstallSource), toolInstallSourceBuiltin),
		BinaryName:             strings.TrimSpace(item.BinaryName),
		TargetStrategy:         normalizeTargetStrategy(item.TargetStrategy),
		Capabilities:           append([]string(nil), item.Capabilities...),
		Profiles:               cloneToolProfiles(item.Profiles),
		SafetyClass:            item.SafetyClass,
		CostProfile:            item.CostProfile,
		CommandEditable:        item.CommandEditable,
		DefaultCommandTemplate: item.DefaultCommandTemplate,
	})
}
