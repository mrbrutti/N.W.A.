package main

type workspaceStateStore interface {
	loadState() (workspaceStoreState, error)
	saveState(scans []managedScan, enrichments map[string]hostEnrichment, savedViews []savedViewRecord, campaigns []campaignRecord, scopeSeeds []scopeSeedRecord, scopeTargets []scopeTargetRecord, targetChunks []targetChunkRecord, approvals []approvalRecord, recommendations []recommendationRecord) error
	loadEvents() ([]workspaceEvent, error)
	replaceEvents(events []workspaceEvent) error
	appendEvent(event workspaceEvent) error
	loadJobs() ([]*pluginJob, error)
	saveJobs(jobs []*pluginJob) error
	loadPreferences() (workspacePreferences, error)
	savePreferences(preferences workspacePreferences) error
	toolCommandTemplate(pluginID string) (string, error)
	customToolDefinitions() ([]PluginDefinitionView, error)
}
