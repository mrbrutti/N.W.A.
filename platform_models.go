package main

type PlatformPageMeta struct {
	Title       string
	Description string
	Section     string
}

type PlatformNavLink struct {
	Label       string
	Href        string
	Active      bool
	Description string
}

type PlatformNavGroup struct {
	Label       string
	Description string
	Active      bool
	Items       []PlatformNavLink
}

type PlatformPaginationLink struct {
	Label  string
	Href   string
	Active bool
}

type PlatformPaginationView struct {
	Key           string
	Page          int
	PageSize      int
	Total         int
	TotalPages    int
	Start         int
	End           int
	HasPrev       bool
	HasNext       bool
	PrevHref      string
	NextHref      string
	PageSizeHrefs []PlatformPaginationLink
}

type PlatformUserView struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	IsAdmin     bool   `json:"isAdmin"`
	CreatedAt   string `json:"createdAt"`
	LastLoginAt string `json:"lastLoginAt"`
}

type PlatformMembershipView struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	JoinedAt    string `json:"joinedAt"`
}

type PlatformEngagementView struct {
	ID            string `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Status        string `json:"status"`
	ScopeSummary  string `json:"scopeSummary"`
	WorkspaceID   string `json:"workspaceId"`
	MemberCount   int    `json:"memberCount"`
	HostCount     int    `json:"hostCount"`
	PortCount     int    `json:"portCount"`
	FindingCount  int    `json:"findingCount"`
	ZoneCount     int    `json:"zoneCount"`
	SourceCount   int    `json:"sourceCount"`
	RunningRuns   int    `json:"runningRuns"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	OverviewHref  string `json:"overviewHref"`
	ScopeHref     string `json:"scopeHref"`
	ZonesHref     string `json:"zonesHref"`
	HostsHref     string `json:"hostsHref"`
	PortsHref     string `json:"portsHref"`
	FindingsHref  string `json:"findingsHref"`
	SourcesHref   string `json:"sourcesHref"`
	CampaignsHref string `json:"campaignsHref"`
	SettingsHref  string `json:"settingsHref"`
}

type PlatformToolView struct {
	ID                      string                   `json:"id"`
	Label                   string                   `json:"label"`
	Kind                    string                   `json:"kind"`
	Family                  string                   `json:"family"`
	InstallSource           string                   `json:"installSource"`
	BinaryName              string                   `json:"binaryName"`
	TargetStrategy          string                   `json:"targetStrategy"`
	SafetyClass             string                   `json:"safetyClass"`
	CostProfile             string                   `json:"costProfile"`
	Description             string                   `json:"description"`
	Status                  string                   `json:"status"`
	StatusTone              string                   `json:"statusTone"`
	StatusDetail            string                   `json:"statusDetail"`
	Capabilities            []string                 `json:"capabilities"`
	Profiles                []ToolCommandProfileView `json:"profiles"`
	RequiredConfig          []string                 `json:"requiredConfig"`
	CommandEditable         bool                     `json:"commandEditable"`
	DefaultCommandTemplate  string                   `json:"defaultCommandTemplate"`
	CommandTemplate         string                   `json:"commandTemplate"`
	ResolvedCommandTemplate string                   `json:"resolvedCommandTemplate"`
}

type PlatformConnectorView struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Status       string `json:"status"`
	StatusTone   string `json:"statusTone"`
	StatusDetail string `json:"statusDetail"`
}

type PlatformWorkerView struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Mode       string `json:"mode"`
	Zone       string `json:"zone"`
	Status     string `json:"status"`
	StatusTone string `json:"statusTone"`
	LastSeenAt string `json:"lastSeenAt"`
	Detail     string `json:"detail"`
}

type PlatformAuditEventView struct {
	CreatedAt      string `json:"createdAt"`
	ActorLabel     string `json:"actorLabel"`
	Kind           string `json:"kind"`
	Summary        string `json:"summary"`
	EngagementName string `json:"engagementName"`
}

type PlatformSourceView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Scanner    string `json:"scanner"`
	LiveHosts  int    `json:"liveHosts"`
	ImportedAt string `json:"importedAt"`
	Href       string `json:"href"`
}

type PlatformRunView struct {
	ID             string `json:"id"`
	ToolID         string `json:"toolId"`
	ToolLabel      string `json:"toolLabel"`
	Status         string `json:"status"`
	StatusTone     string `json:"statusTone"`
	Stage          string `json:"stage"`
	ChunkName      string `json:"chunkName"`
	TargetCount    int    `json:"targetCount"`
	Summary        string `json:"summary"`
	Error          string `json:"error"`
	CreatedAt      string `json:"createdAt"`
	StartedAt      string `json:"startedAt"`
	FinishedAt     string `json:"finishedAt"`
	WorkerMode     string `json:"workerMode"`
	WorkerZone     string `json:"workerZone"`
	EngagementHref string `json:"engagementHref"`
}

type PlatformZoneView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Scope     string `json:"scope"`
	HostCount int    `json:"hostCount"`
	Href      string `json:"href"`
}

type PlatformHostView struct {
	IP           string `json:"ip"`
	DisplayName  string `json:"displayName"`
	OS           string `json:"os"`
	ZoneCount    int    `json:"zoneCount"`
	OpenPorts    int    `json:"openPorts"`
	Findings     int    `json:"findings"`
	Critical     int    `json:"critical"`
	High         int    `json:"high"`
	Exposure     string `json:"exposure"`
	ExposureTone string `json:"exposureTone"`
	Coverage     string `json:"coverage"`
	SourceCount  int    `json:"sourceCount"`
	Href         string `json:"href"`
}

type PlatformPortView struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Label    string `json:"label"`
	Service  string `json:"service"`
	Hosts    int    `json:"hosts"`
	Findings int    `json:"findings"`
	Href     string `json:"href"`
}

type PlatformFindingView struct {
	ID           string `json:"id"`
	TemplateID   string `json:"templateID"`
	Name         string `json:"name"`
	Source       string `json:"source"`
	Severity     string `json:"severity"`
	SeverityTone string `json:"severityTone"`
	Occurrences  int    `json:"occurrences"`
	Hosts        int    `json:"hosts"`
	Ports        int    `json:"ports"`
	FirstSeen    string `json:"firstSeen"`
	LastSeen     string `json:"lastSeen"`
	Href         string `json:"href"`
}

type PlatformHealthView struct {
	UserCount            int `json:"userCount"`
	EngagementCount      int `json:"engagementCount"`
	WorkerCount          int `json:"workerCount"`
	LiveWorkers          int `json:"liveWorkers"`
	ToolCount            int `json:"toolCount"`
	ReadyTools           int `json:"readyTools"`
	ConnectorCount       int `json:"connectorCount"`
	ConfiguredConnectors int `json:"configuredConnectors"`
	RunningRuns          int `json:"runningRuns"`
	QueuedRuns           int `json:"queuedRuns"`
}

type PlatformBasePage struct {
	Page             PlatformPageMeta
	CurrentUser      PlatformUserView
	AdminNav         []PlatformNavLink
	EngagementNav    []PlatformNavLink
	AdminGroups      []PlatformNavGroup
	EngagementGroups []PlatformNavGroup
	TopMenuGroups    []PlatformNavGroup
	PrimaryTabs      []PlatformNavLink
	EngagementSwitch []PlatformEngagementView
	Engagement       PlatformEngagementView
	Pagers           map[string]PlatformPaginationView
	IsAdminArea      bool
}

type LoginPageData struct {
	Page            PlatformPageMeta
	Error           string
	BootstrapHint   string
	DefaultUsername string
}

type AdminOverviewPageData struct {
	PlatformBasePage
	Health      PlatformHealthView
	Engagements []PlatformEngagementView
	Workers     []PlatformWorkerView
	Tools       []PlatformToolView
	RecentAudit []PlatformAuditEventView
}

type AdminUsersPageData struct {
	PlatformBasePage
	Users       []PlatformUserView
	Engagements []PlatformEngagementView
}

type AdminEngagementsPageData struct {
	PlatformBasePage
	Engagements []PlatformEngagementView
	Users       []PlatformUserView
}

type AdminToolsPageData struct {
	PlatformBasePage
	Tools      []PlatformToolView
	Connectors []PlatformConnectorView
	Workers    []PlatformWorkerView
}

type EngagementOverviewPageData struct {
	PlatformBasePage
	Stats         []StatCard
	SourceMix     []Bucket
	SeverityMix   []Bucket
	ZoneMix       []Bucket
	PortMix       []Bucket
	ServiceMix    []Bucket
	RunStatusMix  []Bucket
	RecentSources []PlatformSourceView
	RecentRuns    []PlatformRunView
	Zones         []PlatformZoneView
	TopHosts      []PlatformHostView
	TopPorts      []PlatformPortView
	TopFindings   []PlatformFindingView
	Memberships   []PlatformMembershipView
}

type EngagementScopePageData struct {
	PlatformBasePage
	Stats     []StatCard
	Seeds     []ScopeSeedView
	Targets   []ScopeTargetView
	Chunks    []TargetChunkView
	Approvals []ApprovalView
	Runs      []PlatformRunView
}

type EngagementZonesPageData struct {
	PlatformBasePage
	Stats        []StatCard
	ZoneMix      []Bucket
	SelectedZone string
	Zones        []PlatformZoneView
	Hosts        []PlatformHostView
}

type EngagementSourcesPageData struct {
	PlatformBasePage
	Stats        []StatCard
	ScannerMix   []Bucket
	RunStatusMix []Bucket
	ToolMix      []Bucket
	Sources      []PlatformSourceView
	Runs         []PlatformRunView
}

type EngagementHostsPageData struct {
	PlatformBasePage
	Stats       []StatCard
	ExposureMix []Bucket
	OSMix       []Bucket
	ZoneOptions []SelectOption
	ZoneFilter  string
	Query       string
	Hosts       []PlatformHostView
	Zones       []PlatformZoneView
}

type EngagementPortsPageData struct {
	PlatformBasePage
	Stats      []StatCard
	ServiceMix []Bucket
	PortMix    []Bucket
	Query      string
	Ports      []PlatformPortView
}

type EngagementFindingsPageData struct {
	PlatformBasePage
	Stats            []StatCard
	SeverityMix      []Bucket
	SourceMix        []Bucket
	Query            string
	SelectedSeverity string
	SeverityOptions  []SelectOption
	Findings         []PlatformFindingView
}

type EngagementCampaignsPageData struct {
	PlatformBasePage
	Stats       []StatCard
	StatusMix   []Bucket
	StageMix    []Bucket
	Runs        []PlatformRunView
	Chunks      []TargetChunkView
	Tools       []PluginDefinitionView
	RunProfiles []RunProfileView
	Readiness   []ToolReadinessGroup
	Policies    []OrchestrationPolicyView
	CanOperate  bool
}

type EngagementSettingsPageData struct {
	PlatformBasePage
	Memberships []PlatformMembershipView
	Tools       []PlatformToolView
	Connectors  []PlatformConnectorView
}

type EngagementHostDetailPageData struct {
	PlatformBasePage
	Host         HostDetail
	RelatedZones []PlatformZoneView
	RecentRuns   []PlatformRunView
	Findings     []FindingGroupView
	PortSummary  []PlatformPortView
}

type EngagementPortDetailPageData struct {
	PlatformBasePage
	Port       PortDetailView
	RecentRuns []PlatformRunView
}

type EngagementFindingDetailPageData struct {
	PlatformBasePage
	Finding    FindingDetailView
	RecentRuns []PlatformRunView
}

type EngagementTopologyPageData struct {
	PlatformBasePage
	Summary  TopologySummary
	TopNodes []TopologyNodeSummary
	TopEdges []TopologyEdgeSummary
	Exports  []ExportLink
}

type EngagementRecommendationsPageData struct {
	PlatformBasePage
	Recommendations []RecommendationQueueView
	Approvals       []ApprovalView
	RecentRuns      []PlatformRunView
}
