package main

type PageMeta struct {
	Title       string
	Description string
	ActiveNav   string
}

type WorkspaceStatusView struct {
	ID               string
	Name             string
	Slug             string
	Mode             string
	Root             string
	BundlePath       string
	ScanCount        int
	JobCount         int
	RunningJobs      int
	FindingHosts     int
	TotalFindings    int
	HasImportedScans bool
}

type CommonPageData struct {
	Page        PageMeta
	Scan        ScanMeta
	Workspace   WorkspaceStatusView
	Search      SearchState
	Nav         []NavItem
	NavGroups   []NavGroup
	ActiveGroup NavGroup
	Breadcrumbs []Breadcrumb
	Explorer    ExplorerView
}

type NavItem struct {
	Label       string
	Href        string
	Active      bool
	Description string
}

type NavGroup struct {
	Label       string
	Summary     string
	Active      bool
	ActiveLabel string
	Items       []NavItem
}

type Breadcrumb struct {
	Label string
	Href  string
}

type ExplorerView struct {
	Enabled    bool
	Endpoint   string
	Root       ExplorerNodeView
	ExpandPath []ExplorerPathStep
	Scans      []ExplorerJumpView
	Hosts      []ExplorerJumpView
	Ports      []ExplorerJumpView
	Findings   []ExplorerJumpView
}

type ExplorerPathStep struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type ExplorerNodeView struct {
	Kind       string             `json:"kind"`
	ID         string             `json:"id"`
	Label      string             `json:"label"`
	Meta       string             `json:"meta,omitempty"`
	Count      int                `json:"count"`
	Href       string             `json:"href"`
	Expandable bool               `json:"expandable"`
	Expanded   bool               `json:"expanded,omitempty"`
	Active     bool               `json:"active,omitempty"`
	Children   []ExplorerNodeView `json:"children,omitempty"`
}

type ExplorerJumpView struct {
	Label string
	Meta  string
	Count string
	Href  string
}

type SearchState struct {
	Query string
	Scope string
	Sort  string
}

type SelectOption struct {
	Value    string
	Label    string
	Selected bool
}

type WorkspacePreferenceView struct {
	DefaultLanding string
	LandingOptions []SelectOption
}

type WorkspaceDirectoryItem struct {
	ID          string
	Slug        string
	Name        string
	Description string
	BundlePath  string
	Mode        string
	Href        string
	Selected    bool
	Stats       []StatCard
}

type ScanMeta struct {
	SourceFile string
	Scanner    string
	Version    string
	StartedAt  string
	Command    string
	Type       string
	Protocol   string
	LiveHosts  int
	ScanCount  int
}

type StatCard struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
}

type Bucket struct {
	Label string
	Count int
	Scope string
	Query string
	Href  string
	Share string
}

type FindingSummary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

type FindingTemplateSummary struct {
	TemplateID string
	Name       string
	Source     string
	Severity   string
	Count      int
}

type CoverageView struct {
	Level           string
	Label           string
	Detail          string
	HasScripts      bool
	HasOS           bool
	HasTrace        bool
	NeedsEnrichment bool
}

type Exposure struct {
	Label         string
	Tone          string
	Detail        string
	Score         int
	CriticalPorts []string
}

type PortChip struct {
	Port    string
	Service string
}

type HostSummary struct {
	IP               string
	DisplayName      string
	Hostnames        []string
	OS               string
	SourceCount      int
	OpenPortCount    int
	ServiceCount     int
	ScriptCount      int
	Ports            []PortChip
	HiddenPortCount  int
	Exposure         Exposure
	CriticalServices []string
	Findings         FindingSummary
	Coverage         CoverageView
	HTTPTargets      int
}

type PortRow struct {
	Port        string
	Protocol    string
	State       string
	Service     string
	Product     string
	Version     string
	ExtraInfo   string
	OSType      string
	Method      string
	Confidence  string
	Fingerprint string
	CPEs        []string
	Scripts     []ScriptOutput
}

type ScriptOutput struct {
	ID     string
	Output string
}

type ScriptGroup struct {
	Port    string
	Service string
	Scripts []ScriptOutput
}

type FingerprintSection struct {
	Port        string
	Service     string
	Fingerprint string
}

type OSMatchView struct {
	Name     string
	Accuracy string
	Line     string
	Type     string
	Vendor   string
	Family   string
	Gen      string
	CPEs     []string
}

type PortUseView struct {
	Port     string
	Protocol string
	State    string
}

type TraceHopView struct {
	TTL       string
	Address   string
	Host      string
	RTT       string
	WeightPct int
}

type TimingView struct {
	SRTT    string
	RTTVar  string
	Timeout string
}

type NucleiFindingView struct {
	TemplateID   string
	Name         string
	Source       string
	Severity     string
	SeverityTone string
	Target       string
	MatchedAt    string
	Type         string
	Description  string
	Tags         []string
}

type RecommendationView struct {
	Title    string
	Detail   string
	Evidence string
	Tone     string
}

type VulnerabilityMatchView struct {
	ID             string
	Title          string
	Severity       string
	SeverityTone   string
	Detail         string
	Evidence       string
	Recommendation string
	ReferenceURL   string
}

type AnalystNoteView struct {
	ID        string
	Text      string
	CreatedAt string
}

type HostDetail struct {
	HostSummary
	Status          string
	Reason          string
	Distance        string
	ClosedPortCount int
	Ports           []PortRow
	ScriptGroups    []ScriptGroup
	Fingerprints    []FingerprintSection
	PortsUsed       []PortUseView
	OSFingerprint   string
	OSMatches       []OSMatchView
	Trace           []TraceHopView
	Timing          TimingView
	SourceScans     []string
	NucleiTargets   []string
	NucleiFindings  []NucleiFindingView
	Recommendations []RecommendationView
	Vulnerabilities []VulnerabilityMatchView
	Tags            []string
	Notes           []AnalystNoteView
	Observations    []ObservationView
}

type HostFilter struct {
	Query    string
	Scope    string
	Sort     string
	Page     int
	PageSize int
}

type PaginationLink struct {
	Label    string
	Href     string
	Active   bool
	Disabled bool
}

type HostPage struct {
	Items      []HostSummary
	Total      int
	Start      int
	End        int
	Page       int
	TotalPages int
	PrevLink   string
	NextLink   string
	HasPrev    bool
	HasNext    bool
	Links      []PaginationLink
}

type ExportLink struct {
	Label  string
	Detail string
	Href   string
}

type ScanCatalogItem struct {
	ID         string
	Name       string
	Kind       string
	Source     string
	Scanner    string
	Version    string
	StartedAt  string
	ImportedAt string
	Command    string
	LiveHosts  int
	Download   string
}

type PluginDefinitionView struct {
	ID                     string
	Label                  string
	Description            string
	Mode                   string
	Family                 string
	Kind                   string
	InstallSource          string
	BinaryName             string
	TargetStrategy         string
	Capabilities           []string
	Profiles               []ToolCommandProfileView
	SafetyClass            string
	CostProfile            string
	Availability           string
	AvailabilityTone       string
	AvailabilityDetail     string
	CommandEditable        bool
	DefaultCommandTemplate string
}

type ToolReadinessGroup struct {
	Label  string
	Detail string
	Ready  int
	Total  int
	Tone   string
	Tools  []PluginDefinitionView
}

type JobArtifactView struct {
	Label string
	Href  string
}

type PluginJobView struct {
	ID            string
	PluginID      string
	PluginLabel   string
	PluginKind    string
	SafetyClass   string
	CostProfile   string
	Capabilities  []string
	Status        string
	StatusTone    string
	TargetSummary string
	TargetCount   int
	CampaignID    string
	ChunkID       string
	Stage         string
	WorkerMode    string
	WorkerZone    string
	CreatedAt     string
	StartedAt     string
	FinishedAt    string
	Summary       string
	Error         string
	Artifacts     []JobArtifactView
	Findings      FindingSummary
}

type RunProfileView struct {
	Label        string
	PluginID     string
	ProfileScope string
	Detail       string
	Count        int
	CountLabel   string
	ModeLabel    string
	Severity     string
	Profile      string
	CrawlDepth   string
}

type IntegrationActionView struct {
	ID               string
	Label            string
	Mode             string
	Family           string
	Description      string
	Availability     string
	AvailabilityTone string
	ActionLabel      string
	Href             string
	PluginID         string
	TargetMode       string
	Targets          string
	ReturnTo         string
	Severity         string
	Profile          string
	CrawlDepth       string
	Disabled         bool
	Count            int
}

type IntegrationLaneView struct {
	Label   string
	Detail  string
	Actions []IntegrationActionView
}

type ToolCommandProfileView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Command     string `json:"command,omitempty"`
	Default     bool   `json:"default,omitempty"`
}

type SavedView struct {
	ID        string
	Name      string
	Href      string
	Query     string
	Scope     string
	Sort      string
	PageSize  int
	CreatedAt string
}

type CampaignView struct {
	ID          string
	Name        string
	PluginID    string
	PluginLabel string
	Scope       string
	Stage       string
	Status      string
	StatusTone  string
	Summary     string
	TargetCount int
	CreatedAt   string
	JobID       string
}

type ScopeSeedView struct {
	ID        string
	Kind      string
	Value     string
	Source    string
	Status    string
	Detail    string
	CreatedAt string
}

type ScopeTargetView struct {
	ID         string
	Kind       string
	Value      string
	Normalized string
	Status     string
	SeedID     string
	CreatedAt  string
}

type TargetChunkView struct {
	ID           string
	CampaignID   string
	Name         string
	Stage        string
	Kind         string
	Status       string
	StatusTone   string
	Detail       string
	Size         int
	CreatedAt    string
	StartedAt    string
	FinishedAt   string
	Values       []string
	RunIDs       []string
	ToolIDs      []string
	SkippedTools []string
}

type ApprovalView struct {
	ID             string
	CampaignID     string
	Scope          string
	Status         string
	StatusTone     string
	Summary        string
	Detail         string
	RequiredClass  string
	AllowedToolIDs []string
	CreatedAt      string
	DecidedAt      string
}

type RecommendationQueueView struct {
	ID               string
	CampaignID       string
	Type             string
	Status           string
	StatusTone       string
	Title            string
	Detail           string
	Rationale        string
	ExpectedValue    string
	RequiredApproval string
	Confidence       string
	ToolIDs          []string
	CreatedAt        string
	UpdatedAt        string
}

type ObservationView struct {
	ID       string `json:"id"`
	At       string `json:"at"`
	Kind     string `json:"kind"`
	KindTone string `json:"kind_tone"`
	Source   string `json:"source"`
	HostIP   string `json:"host_ip,omitempty"`
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	Severity string `json:"severity,omitempty"`
	Href     string `json:"href,omitempty"`
}

type DashboardPageData struct {
	CommonPageData
	ExecutiveSummary string
	Stats            []StatCard
	ScopeOptions     []SelectOption
	SortOptions      []SelectOption
	PageSizeOptions  []SelectOption
	Filter           HostFilter
	Results          HostPage
	TopPorts         []Bucket
	TopOS            []Bucket
	TopServices      []Bucket
	HighExposure     []HostSummary
	Exports          []ExportLink
	GraphSummary     TopologySummary
	FindingTotals    FindingSummary
	TopFindings      []FindingTemplateSummary
	Plugins          []PluginDefinitionView
	RecentJobs       []PluginJobView
	LatestDiff       WorkspaceDiffView
	HasLatestDiff    bool
	SavedViews       []SavedView
	Campaigns        []CampaignView
	Observations     []ObservationView
}

type OverviewPageData struct {
	CommonPageData
	ExecutiveSummary string
	Stats            []StatCard
	TopPorts         []Bucket
	TopOS            []Bucket
	TopServices      []Bucket
	FindingTotals    FindingSummary
	RecentScans      []ScanCatalogItem
	RecentFindings   []FindingGroupView
	LatestDiff       WorkspaceDiffView
	HasLatestDiff    bool
	PriorityHosts    []HostSummary
	Observations     []ObservationView
}

type HostPageData struct {
	CommonPageData
	Host    HostDetail
	Plugins []PluginDefinitionView
	Jobs    []PluginJobView
	Scope   *HostScopeView
}

type ListPageData struct {
	CommonPageData
	Heading string
	Kicker  string
	Items   []Bucket
}

type ScansPageData struct {
	CommonPageData
	Scans         []ScanCatalogItem
	Plugins       []PluginDefinitionView
	Jobs          []PluginJobView
	FindingTotals FindingSummary
	SavedViews    []SavedView
	Campaigns     []CampaignView
	Observations  []ObservationView
}

type WorkspacePageData struct {
	CommonPageData
	ExecutiveSummary string
	Preferences      WorkspacePreferenceView
	Scans            []ScanCatalogItem
	Plugins          []PluginDefinitionView
	RecentJobs       []PluginJobView
	Jobs             []PluginJobView
	FindingTotals    FindingSummary
	HighExposure     []HostSummary
	TopFindings      []FindingTemplateSummary
	SourceMix        []Bucket
	CoverageMix      []Bucket
	JobStatus        []Bucket
	RunProfiles      []RunProfileView
	SavedViews       []SavedView
	Campaigns        []CampaignView
	Observations     []ObservationView
	Readiness        []ToolReadinessGroup
	IsEmpty          bool
}

type WorkspacesPageData struct {
	CommonPageData
	Items []WorkspaceDirectoryItem
}

type ScopePageData struct {
	CommonPageData
	Stats           []StatCard
	Readiness       []ToolReadinessGroup
	Seeds           []ScopeSeedView
	Targets         []ScopeTargetView
	Chunks          []TargetChunkView
	Approvals       []ApprovalView
	Recommendations []RecommendationQueueView
}

type CampaignsPageData struct {
	CommonPageData
	Stats           []StatCard
	Readiness       []ToolReadinessGroup
	Campaigns       []CampaignView
	Chunks          []TargetChunkView
	Approvals       []ApprovalView
	Recommendations []RecommendationQueueView
	Jobs            []PluginJobView
}

type RecommendationsPageData struct {
	CommonPageData
	Stats           []StatCard
	Recommendations []RecommendationQueueView
	Approvals       []ApprovalView
	Campaigns       []CampaignView
}

type ScanIndexPageData struct {
	CommonPageData
	Scans []ScanCatalogItem
}

type ScanPageData struct {
	CommonPageData
	Scan    ScanDetailView
	Plugins []PluginDefinitionView
}

type HostsPageData struct {
	CommonPageData
	ExecutiveSummary string
	Stats            []StatCard
	SliceStats       []StatCard
	TopPorts         []Bucket
	TopOS            []Bucket
	TopServices      []Bucket
	FindingTotals    FindingSummary
	ScopeOptions     []SelectOption
	SortOptions      []SelectOption
	PageSizeOptions  []SelectOption
	Filter           HostFilter
	Results          HostPage
	SavedViews       []SavedView
	Exports          []ExportLink
	LatestDiff       WorkspaceDiffView
	HasLatestDiff    bool
}

type HostScopeView struct {
	Active            bool
	Scan              ScanCatalogItem
	ObservedOpenPorts int
	ObservedFindings  FindingSummary
	ObservedPorts     []PortRow
}

type PortSummaryView struct {
	Protocol string
	Port     string
	Label    string
	Service  string
	Hosts    int
	Findings int
	Scans    int
	Exposure string
	Href     string
}

type PortIndexPageData struct {
	CommonPageData
	Query           string
	Stats           []StatCard
	SortOptions     []SelectOption
	ServiceBuckets  []Bucket
	ExposureBuckets []Bucket
	HostBuckets     []Bucket
	Ports           []PortSummaryView
}

type PortHostView struct {
	IP          string
	DisplayName string
	OS          string
	Service     string
	Product     string
	Version     string
	Findings    int
	Scans       []string
	Href        string
}

type PortDetailView struct {
	Protocol        string
	Port            string
	Label           string
	Service         string
	HostCount       int
	FindingTotals   FindingSummary
	Hosts           []PortHostView
	RelatedScans    []ScanCatalogItem
	RelatedFindings []FindingGroupView
	HostTargets     []string
}

type PortPageData struct {
	CommonPageData
	Port             PortDetailView
	IntegrationLanes []IntegrationLaneView
}

type FindingGroupView struct {
	ID           string
	TemplateID   string
	Name         string
	Source       string
	Severity     string
	SeverityTone string
	Occurrences  int
	Hosts        int
	Ports        int
	RelatedScans int
	FirstSeen    string
	LastSeen     string
	Href         string
}

type FindingOccurrenceView struct {
	HostIP    string
	HostLabel string
	Target    string
	Port      string
	Scans     []string
	MatchedAt string
	Href      string
}

type FindingDetailView struct {
	Group        FindingGroupView
	Occurrences  []FindingOccurrenceView
	RelatedScans []ScanCatalogItem
	RelatedJobs  []PluginJobView
	Description  string
	Tags         []string
}

type FindingsPageData struct {
	CommonPageData
	Query            string
	SelectedSeverity string
	SelectedSource   string
	Stats            []StatCard
	SeverityOptions  []SelectOption
	SourceOptions    []SelectOption
	SortOptions      []SelectOption
	SeverityBuckets  []Bucket
	SourceBuckets    []Bucket
	PortBuckets      []Bucket
	Findings         []FindingGroupView
}

type FindingPageData struct {
	CommonPageData
	Finding          FindingDetailView
	HostTargets      []string
	IntegrationLanes []IntegrationLaneView
}

type ScanDetailView struct {
	Summary       ScanCatalogItem
	SourceLabel   string
	Description   string
	HostCount     int
	FindingTotals FindingSummary
	Hosts         []HostSummary
	Ports         []PortSummaryView
	Findings      []FindingGroupView
	Jobs          []PluginJobView
}

type CompareSelection struct {
	FromID      string
	ToID        string
	FromOptions []SelectOption
	ToOptions   []SelectOption
}

type ChangeCheckpointView struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Kind         string `json:"kind"`
	KindTone     string `json:"kind_tone"`
	At           string `json:"at"`
	Summary      string `json:"summary"`
	HostCount    int    `json:"host_count"`
	FindingCount int    `json:"finding_count"`
	RouteCount   int    `json:"route_count"`
}

type ChangeHostView struct {
	IP     string `json:"ip"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Href   string `json:"href,omitempty"`
}

type ChangePortView struct {
	HostIP  string `json:"host_ip"`
	Port    string `json:"port"`
	Service string `json:"service"`
	Detail  string `json:"detail"`
	Href    string `json:"href,omitempty"`
}

type ChangeServiceView struct {
	HostIP string `json:"host_ip"`
	Port   string `json:"port"`
	Before string `json:"before"`
	After  string `json:"after"`
	Href   string `json:"href,omitempty"`
}

type ChangeFindingView struct {
	HostIP    string `json:"host_ip"`
	Name      string `json:"name"`
	Source    string `json:"source,omitempty"`
	Severity  string `json:"severity"`
	Target    string `json:"target"`
	Href      string `json:"href,omitempty"`
	Inventory bool   `json:"inventory"`
}

type ChangeRouteView struct {
	Target   string `json:"target"`
	TargetIP string `json:"target_ip,omitempty"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
}

type ChangeOSView struct {
	IP     string `json:"ip"`
	Label  string `json:"label"`
	Before string `json:"before"`
	After  string `json:"after"`
	Href   string `json:"href,omitempty"`
}

type ChangeSummary struct {
	HostsAdded      int `json:"hosts_added"`
	HostsRemoved    int `json:"hosts_removed"`
	PortsOpened     int `json:"ports_opened"`
	PortsClosed     int `json:"ports_closed"`
	ServiceChanges  int `json:"service_changes"`
	OSChanges       int `json:"os_changes"`
	FindingsAdded   int `json:"findings_added"`
	FindingsRemoved int `json:"findings_removed"`
	RoutesAdded     int `json:"routes_added"`
	RoutesRemoved   int `json:"routes_removed"`
}

type WorkspaceDiffView struct {
	From            ChangeCheckpointView   `json:"from"`
	To              ChangeCheckpointView   `json:"to"`
	Summary         ChangeSummary          `json:"summary"`
	SummaryLine     string                 `json:"summary_line"`
	AddedHosts      []ChangeHostView       `json:"added_hosts,omitempty"`
	RemovedHosts    []ChangeHostView       `json:"removed_hosts,omitempty"`
	OpenedPorts     []ChangePortView       `json:"opened_ports,omitempty"`
	ClosedPorts     []ChangePortView       `json:"closed_ports,omitempty"`
	ServiceChanges  []ChangeServiceView    `json:"service_changes,omitempty"`
	OSChanges       []ChangeOSView         `json:"os_changes,omitempty"`
	AddedFindings   []ChangeFindingView    `json:"added_findings,omitempty"`
	RemovedFindings []ChangeFindingView    `json:"removed_findings,omitempty"`
	AddedRoutes     []ChangeRouteView      `json:"added_routes,omitempty"`
	RemovedRoutes   []ChangeRouteView      `json:"removed_routes,omitempty"`
	Events          []ChangeCheckpointView `json:"events,omitempty"`
}

type ChangesPageData struct {
	CommonPageData
	Compare              CompareSelection
	Diff                 WorkspaceDiffView
	Checkpoints          []ChangeCheckpointView
	HasHistory           bool
	Exports              []ExportLink
	Plugins              []PluginDefinitionView
	Campaigns            []CampaignView
	CampaignScopeOptions []SelectOption
}

type TraceGraph struct {
	Nodes []TraceNode `json:"nodes"`
	Links []TraceLink `json:"links"`
}

type TraceNode struct {
	Group int    `json:"group"`
	Name  string `json:"name"`
	RTT   string `json:"rtt"`
}

type TraceLink struct {
	Source int     `json:"source"`
	Target int     `json:"target"`
	Value  float64 `json:"value"`
}

type TopologySummary struct {
	TracedHosts int `json:"traced_hosts"`
	Nodes       int `json:"nodes"`
	Edges       int `json:"edges"`
	MaxDepth    int `json:"max_depth"`
}

type TopologyGraph struct {
	Summary TopologySummary     `json:"summary"`
	Nodes   []TopologyGraphNode `json:"nodes"`
	Edges   []TopologyGraphEdge `json:"edges"`
	Routes  []TopologyRoute     `json:"routes"`
}

type TopologyGraphNode struct {
	ID       string  `json:"id"`
	Label    string  `json:"label"`
	Count    int     `json:"count"`
	AvgTTL   float64 `json:"avg_ttl"`
	AvgRTT   float64 `json:"avg_rtt"`
	Role     string  `json:"role"`
	Targets  int     `json:"targets"`
	Icon     string  `json:"icon"`
	OSLabel  string  `json:"os_label"`
	Source   bool    `json:"source"`
	Hostname string  `json:"hostname"`
	Provider string  `json:"provider"`
}

type TopologyGraphEdge struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Count  int     `json:"count"`
	AvgRTT float64 `json:"avg_rtt"`
}

type TopologyRoute struct {
	ID          string   `json:"id"`
	TargetID    string   `json:"target_id"`
	TargetLabel string   `json:"target_label"`
	Count       int      `json:"count"`
	Depth       int      `json:"depth"`
	Hops        []string `json:"hops"`
}

type TopologyNodeSummary struct {
	Label   string
	Count   int
	AvgTTL  string
	AvgRTT  string
	Role    string
	Targets int
}

type TopologyEdgeSummary struct {
	Source string
	Target string
	Count  int
	AvgRTT string
}

type GraphPageData struct {
	CommonPageData
	Summary  TopologySummary
	TopNodes []TopologyNodeSummary
	TopEdges []TopologyEdgeSummary
	Exports  []ExportLink
}
