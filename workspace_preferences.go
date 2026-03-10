package main

type workspacePreferences struct {
	DefaultLanding string                      `json:"default_landing"`
	ActivePolicyID string                      `json:"active_policy_id,omitempty"`
	Policies       []orchestrationPolicyRecord `json:"policies,omitempty"`
}

func defaultWorkspacePreferences() workspacePreferences {
	return normalizePolicies(workspacePreferences{DefaultLanding: "overview"})
}

func normalizeLandingPreference(value string) string {
	switch value {
	case "workspace", "hosts":
		return value
	default:
		return "overview"
	}
}

func (w *workspace) preferences() workspacePreferences {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.preferencesLocked()
}

func (w *workspace) preferencesLocked() workspacePreferences {
	preferences := normalizePolicies(w.preferencesState)
	preferences.DefaultLanding = normalizeLandingPreference(preferences.DefaultLanding)
	return preferences
}

func (w *workspace) setDefaultLanding(mode string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	preferences := normalizePolicies(w.preferencesState)
	preferences.DefaultLanding = normalizeLandingPreference(mode)
	w.preferencesState = preferences
	return w.store.savePreferences(w.preferencesState)
}

func landingOptions(selected string) []SelectOption {
	selected = normalizeLandingPreference(selected)
	return []SelectOption{
		{Value: "overview", Label: "Overview", Selected: selected == "overview"},
		{Value: "workspace", Label: "Workspace", Selected: selected == "workspace"},
		{Value: "hosts", Label: "Hosts", Selected: selected == "hosts"},
	}
}
