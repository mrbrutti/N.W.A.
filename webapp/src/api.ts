import { queryOptions } from "@tanstack/react-query";

export type PlatformUser = {
  id: string;
  username: string;
  email: string;
  displayName: string;
  role: string;
  status: string;
  isAdmin: boolean;
  createdAt: string;
  lastLoginAt: string;
};

export type PlatformPaginationLink = {
  label: string;
  href: string;
  active: boolean;
};

export type PlatformPagination = {
  key: string;
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  start: number;
  end: number;
  hasPrev: boolean;
  hasNext: boolean;
  prevHref: string;
  nextHref: string;
  pageSizeHrefs: PlatformPaginationLink[];
};

export type ListResponse<T> = {
  items: T[];
  pagination: PlatformPagination;
};

export type PlatformEngagement = {
  id: string;
  slug: string;
  name: string;
  description: string;
  status: string;
  scopeSummary: string;
  workspaceId: string;
  memberCount: number;
  hostCount: number;
  portCount: number;
  findingCount: number;
  zoneCount: number;
  sourceCount: number;
  runningRuns: number;
  createdAt: string;
  updatedAt: string;
  overviewHref: string;
  scopeHref: string;
  zonesHref: string;
  hostsHref: string;
  portsHref: string;
  findingsHref: string;
  sourcesHref: string;
  campaignsHref: string;
  settingsHref: string;
};

export type PlatformHost = {
  ip: string;
  displayName: string;
  os: string;
  zoneCount: number;
  openPorts: number;
  findings: number;
  critical: number;
  high: number;
  exposure: string;
  exposureTone: string;
  coverage: string;
  sourceCount: number;
  href: string;
};

export type PlatformZone = {
  id: string;
  name: string;
  kind: string;
  scope: string;
  hostCount: number;
  href: string;
};

export type PlatformPort = {
  protocol: string;
  port: string;
  label: string;
  service: string;
  hosts: number;
  findings: number;
  href: string;
};

export type PlatformFinding = {
  id: string;
  templateID: string;
  name: string;
  source: string;
  severity: string;
  severityTone: string;
  occurrences: number;
  hosts: number;
  ports: number;
  firstSeen: string;
  lastSeen: string;
  href: string;
};

export type ExposureSummary = {
  label: string;
  tone: string;
  detail: string;
  score: number;
  criticalPorts: string[];
};

export type CoverageSummary = {
  level: string;
  label: string;
  detail: string;
  hasScripts: boolean;
  hasOS: boolean;
  hasTrace: boolean;
  needsEnrichment: boolean;
};

export type HostSummary = {
  ip: string;
  displayName: string;
  hostnames: string[];
  os: string;
  sourceCount: number;
  openPortCount: number;
  serviceCount: number;
  scriptCount: number;
  ports: Array<{ port: string; service: string }>;
  hiddenPortCount: number;
  exposure: ExposureSummary;
  criticalServices: string[];
  findings: FindingSummary;
  coverage: CoverageSummary;
  httpTargets: number;
};

export type HostPortRow = {
  port: string;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  extraInfo: string;
  osType: string;
  method: string;
  confidence: string;
  fingerprint: string;
  cpes: string[];
  scripts: Array<{ id: string; output: string }>;
};

export type FindingSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type FindingGroup = {
  id: string;
  templateId: string;
  name: string;
  source: string;
  severity: string;
  severityTone: string;
  occurrences: number;
  hosts: number;
  ports: number;
  relatedScans: number;
  firstSeen: string;
  lastSeen: string;
  href: string;
};

export type HostDetailPayload = {
  host: {
    summary: HostSummary;
    status: string;
    reason: string;
    distance: string;
    closedPortCount: number;
    ports: HostPortRow[];
    scriptGroups: Array<{ port: string; service: string; scripts: Array<{ id: string; output: string }> }>;
    fingerprints: Array<{ port: string; service: string; fingerprint: string }>;
    portsUsed: Array<{ port: string; protocol: string; state: string }>;
    osFingerprint: string;
    osMatches: Array<{
      name: string;
      accuracy: string;
      line: string;
      type: string;
      vendor: string;
      family: string;
      gen: string;
      cpes: string[];
    }>;
    trace: Array<{ ttl: string; address: string; host: string; rtt: string; weightPct: number }>;
    timing: { srtt: string; rttVar: string; timeout: string };
    sourceScans: string[];
    nucleiTargets: string[];
    nucleiFindings: Array<{
      templateId: string;
      name: string;
      source: string;
      severity: string;
      severityTone: string;
      target: string;
      matchedAt: string;
      type: string;
      description: string;
      tags: string[];
    }>;
    recommendations: Array<{ title: string; detail: string; evidence: string; tone: string }>;
    vulnerabilities: Array<{
      id: string;
      title: string;
      severity: string;
      severityTone: string;
      detail: string;
      evidence: string;
      recommendation: string;
      referenceUrl: string;
    }>;
    tags: string[];
    notes: Array<{ id: string; text: string; createdAt: string }>;
    observations: Array<{
      id: string;
      at: string;
      kind: string;
      kind_tone: string;
      source: string;
      host_ip?: string;
      label: string;
      detail?: string;
      severity?: string;
      href?: string;
    }>;
  };
  relatedZones: PlatformZone[];
  recentRuns: PlatformRun[];
  findings: FindingGroup[];
  portSummary: PlatformPort[];
};

export type PortHost = {
  ip: string;
  displayName: string;
  os: string;
  service: string;
  product: string;
  version: string;
  findings: number;
  scans: string[];
  href: string;
};

export type PortDetailPayload = {
  port: {
    protocol: string;
    port: string;
    label: string;
    service: string;
    hostCount: number;
    findingTotals: FindingSummary;
    hosts: PortHost[];
    relatedScans: PlatformSource[];
    relatedFindings: FindingGroup[];
    hostTargets: string[];
  };
  recentRuns: PlatformRun[];
};

export type FindingDetailPayload = {
  finding: {
    group: FindingGroup;
    occurrences: Array<{
      hostIp: string;
      hostLabel: string;
      target: string;
      port: string;
      scans: string[];
      matchedAt: string;
      href: string;
    }>;
    relatedScans: PlatformSource[];
    relatedJobs: PlatformRun[];
    description: string;
    tags: string[];
  };
  recentRuns: PlatformRun[];
};

export type PlatformTool = {
  id: string;
  label: string;
  status: string;
  kind: string;
  family: string;
  installSource: string;
  binaryName: string;
  targetStrategy: string;
  safetyClass: string;
  costProfile: string;
  description: string;
  statusTone: string;
  statusDetail: string;
  capabilities: string[];
  requiredConfig: string[];
  commandEditable: boolean;
  defaultCommandTemplate: string;
  commandTemplate: string;
  resolvedCommandTemplate: string;
};

export type PlatformWorker = {
  id: string;
  label: string;
  mode: string;
  zone: string;
  status: string;
  statusTone: string;
  lastSeenAt: string;
  detail: string;
};

export type PlatformConnector = {
  id: string;
  label: string;
  status: string;
  statusTone: string;
  statusDetail: string;
};

export type PlatformAuditEvent = {
  createdAt: string;
  actorLabel: string;
  kind: string;
  summary: string;
  engagementName: string;
};

export type PlatformSource = {
  id: string;
  name: string;
  kind: string;
  scanner: string;
  liveHosts: number;
  importedAt: string;
  href: string;
};

export type PlatformRun = {
  id: string;
  toolId: string;
  toolLabel: string;
  status: string;
  statusTone: string;
  stage: string;
  chunkName: string;
  targetCount: number;
  summary: string;
  error: string;
  createdAt: string;
  startedAt: string;
  finishedAt: string;
  workerMode: string;
  workerZone: string;
  engagementHref: string;
};

export type ScopeSeed = {
  id: string;
  kind: string;
  value: string;
  source: string;
  status: string;
  detail: string;
  createdAt: string;
};

export type ScopeTarget = {
  id: string;
  kind: string;
  value: string;
  normalized: string;
  status: string;
  seedId: string;
  createdAt: string;
};

export type TargetChunk = {
  id: string;
  campaignId: string;
  name: string;
  stage: string;
  kind: string;
  status: string;
  statusTone: string;
  detail: string;
  size: number;
  createdAt: string;
  startedAt: string;
  finishedAt: string;
  values: string[];
  runIds: string[];
  toolIds: string[];
  skippedTools: string[];
};

export type PlatformApproval = {
  id: string;
  campaignId: string;
  scope: string;
  status: string;
  statusTone: string;
  summary: string;
  detail: string;
  requiredClass: string;
  allowedToolIds: string[];
  createdAt: string;
  decidedAt: string;
};

export type PlatformRecommendation = {
  id: string;
  campaignId: string;
  type: string;
  status: string;
  statusTone: string;
  title: string;
  detail: string;
  rationale: string;
  expectedValue: string;
  requiredApproval: string;
  confidence: string;
  toolIds: string[];
  createdAt: string;
  updatedAt: string;
};

export type ToolReadinessGroup = {
  label: string;
  detail: string;
  ready: number;
  total: number;
  tone: string;
  tools: PlatformTool[];
};

export type RunProfile = {
  label: string;
  pluginId: string;
  profileScope: string;
  detail: string;
  count: number;
  countLabel: string;
  modeLabel: string;
  severity: string;
  profile: string;
  crawlDepth: string;
};

export type OrchestrationStep = {
  id: string;
  label: string;
  trigger: string;
  pluginId: string;
  stage: string;
  targetSource: string;
  matchKinds: string[];
  whenPlugin: string;
  whenProfile: string;
  summary: string;
  options: Record<string, string>;
  enabled: boolean;
};

export type OrchestrationPolicy = {
  id: string;
  name: string;
  description: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
  steps: OrchestrationStep[];
};

export type PlatformHealth = {
  userCount: number;
  engagementCount: number;
  workerCount: number;
  liveWorkers: number;
  toolCount: number;
  readyTools: number;
  connectorCount: number;
  configuredConnectors: number;
  runningRuns: number;
  queuedRuns: number;
};

export type AdminOverviewPayload = {
  health: PlatformHealth;
  engagements: ListResponse<PlatformEngagement>;
  workers: ListResponse<PlatformWorker>;
  tools: ListResponse<PlatformTool>;
  audit: ListResponse<PlatformAuditEvent>;
};

export type EngagementScopePayload = {
  stats: StatCard[];
  seeds: ListResponse<ScopeSeed>;
  targets: ListResponse<ScopeTarget>;
  chunks: ListResponse<TargetChunk>;
  approvals: ListResponse<PlatformApproval>;
  runs: ListResponse<PlatformRun>;
};

export type EngagementCampaignsPayload = {
  stats: StatCard[];
  statusMix: Array<{ label: string; count: number; scope: string; query: string; href: string; share: string }>;
  stageMix: Array<{ label: string; count: number; scope: string; query: string; href: string; share: string }>;
  runs: ListResponse<PlatformRun>;
  chunks: ListResponse<TargetChunk>;
  tools: ListResponse<PlatformTool>;
  runProfiles: RunProfile[];
  readiness: ToolReadinessGroup[];
  policies: OrchestrationPolicy[];
};

export type EngagementRecommendationsPayload = {
  recommendations: ListResponse<PlatformRecommendation>;
  approvals: ListResponse<PlatformApproval>;
  runs: ListResponse<PlatformRun>;
};

export type EngagementSettingsPayload = {
  memberships: ListResponse<{
    userId: string;
    username: string;
    displayName: string;
    email: string;
    role: string;
    joinedAt: string;
  }>;
  users: ListResponse<PlatformUser>;
  tools: ListResponse<PlatformTool>;
  connectors: ListResponse<PlatformConnector>;
};

export type TopologySummary = {
  traced_hosts: number;
  nodes: number;
  edges: number;
  max_depth: number;
};

export type TopologyGraphNode = {
  id: string;
  label: string;
  count: number;
  avg_ttl: number;
  avg_rtt: number;
  role: string;
  targets: number;
  icon: string;
  os_label: string;
  source: boolean;
  hostname: string;
  provider: string;
};

export type TopologyGraphEdge = {
  source: string;
  target: string;
  count: number;
  avg_rtt: number;
};

export type TopologyRoute = {
  id: string;
  target_id: string;
  target_label: string;
  count: number;
  depth: number;
  hops: string[];
};

export type TopologyGraph = {
  summary: TopologySummary;
  nodes: TopologyGraphNode[];
  edges: TopologyGraphEdge[];
  routes: TopologyRoute[];
};

export type StatCard = {
  label: string;
  value: string;
  detail: string;
  tone: string;
};

export type SessionPayload = {
  authenticated: boolean;
  user?: PlatformUser;
  engagements?: PlatformEngagement[];
  redirectTo?: string;
  bootstrapHint?: string;
};

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function requestJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const hasJSONBody = init?.body && !(init.body instanceof FormData);
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(hasJSONBody ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
    ...init,
  });

  const contentType = response.headers.get("Content-Type") || "";
  const isJSON = contentType.includes("application/json");
  const payload = isJSON ? await response.json() : null;

  if (!response.ok) {
    const message =
      (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : response.statusText) || "Request failed";
    throw new ApiError(response.status, message);
  }

  return payload as T;
}

type MutationStatus = {
  status: string;
};

function withSearchParams(
  path: string,
  search: Record<string, string | number | undefined>,
) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    if (value === undefined || value === "" || Number.isNaN(value)) {
      continue;
    }
    params.set(key, String(value));
  }
  const suffix = params.toString();
  return suffix ? `${path}?${suffix}` : path;
}

export function sessionQuery() {
  return queryOptions({
    queryKey: ["session"],
    queryFn: () => requestJSON<SessionPayload>("/api/v1/session"),
    staleTime: 30_000,
  });
}

export function engagementsQuery() {
  return queryOptions({
    queryKey: ["engagements"],
    queryFn: () => requestJSON<ListResponse<PlatformEngagement>>("/api/v1/engagements"),
    staleTime: 30_000,
  });
}

export function adminOverviewQuery() {
  return queryOptions({
    queryKey: ["admin-overview"],
    queryFn: () => requestJSON<AdminOverviewPayload>("/api/v1/admin/overview"),
    staleTime: 15_000,
  });
}

export function adminHealthQuery() {
  return queryOptions({
    queryKey: ["admin-health"],
    queryFn: () => requestJSON<PlatformHealth>("/api/v1/admin/health"),
    staleTime: 15_000,
  });
}

export function adminToolsQuery() {
  return queryOptions({
    queryKey: ["admin-tools"],
    queryFn: () => requestJSON<ListResponse<PlatformTool>>("/api/v1/admin/tools"),
    staleTime: 30_000,
  });
}

export function adminUsersQuery() {
  return queryOptions({
    queryKey: ["admin-users"],
    queryFn: () => requestJSON<ListResponse<PlatformUser>>("/api/v1/admin/users"),
    staleTime: 30_000,
  });
}

export function adminEngagementsQuery() {
  return queryOptions({
    queryKey: ["admin-engagements"],
    queryFn: () => requestJSON<ListResponse<PlatformEngagement>>("/api/v1/admin/engagements"),
    staleTime: 30_000,
  });
}

export function adminWorkersQuery() {
  return queryOptions({
    queryKey: ["admin-workers"],
    queryFn: () => requestJSON<ListResponse<PlatformWorker>>("/api/v1/admin/workers"),
    staleTime: 15_000,
  });
}

export function adminConnectorsQuery() {
  return queryOptions({
    queryKey: ["admin-connectors"],
    queryFn: () => requestJSON<ListResponse<PlatformConnector>>("/api/v1/admin/connectors"),
    staleTime: 15_000,
  });
}

export function adminAuditQuery() {
  return queryOptions({
    queryKey: ["admin-audit"],
    queryFn: () => requestJSON<ListResponse<PlatformAuditEvent>>("/api/v1/admin/audit"),
    staleTime: 15_000,
  });
}

export function engagementSummaryQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-summary", slug],
    queryFn: () => requestJSON<StatCard[]>(`/api/v1/engagements/${slug}/summary`),
    staleTime: 15_000,
  });
}

export function engagementHostsQuery(
  slug: string,
  search: { query?: string; zone?: string; sort?: string; page?: number; pageSize?: number },
) {
  return queryOptions({
    queryKey: ["engagement-hosts", slug, search.query || "", search.zone || "", search.sort || "", search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<ListResponse<PlatformHost>>(
        withSearchParams(`/api/v1/engagements/${slug}/hosts`, {
          query: search.query,
          zone: search.zone,
          sort: search.sort,
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 15_000,
  });
}

export function engagementHostDetailQuery(slug: string, ip: string) {
  return queryOptions({
    queryKey: ["engagement-host-detail", slug, ip],
    queryFn: () => requestJSON<HostDetailPayload>(`/api/v1/engagements/${slug}/hosts/${encodeURIComponent(ip)}`),
    staleTime: 15_000,
  });
}

export function engagementZonesQuery(slug: string, search: { sort?: string; page?: number; pageSize?: number } = {}) {
  return queryOptions({
    queryKey: ["engagement-zones", slug, search.sort || "", search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<ListResponse<PlatformZone>>(
        withSearchParams(`/api/v1/engagements/${slug}/zones`, {
          sort: search.sort,
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 30_000,
  });
}

export function engagementPortsQuery(
  slug: string,
  search: { query?: string; sort?: string; page?: number; pageSize?: number } = {},
) {
  return queryOptions({
    queryKey: ["engagement-ports", slug, search.query || "", search.sort || "", search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<ListResponse<PlatformPort>>(
        withSearchParams(`/api/v1/engagements/${slug}/ports`, {
          query: search.query,
          sort: search.sort,
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 15_000,
  });
}

export function engagementPortDetailQuery(slug: string, protocol: string, port: string) {
  return queryOptions({
    queryKey: ["engagement-port-detail", slug, protocol, port],
    queryFn: () =>
      requestJSON<PortDetailPayload>(
        `/api/v1/engagements/${slug}/ports/${encodeURIComponent(protocol)}/${encodeURIComponent(port)}`,
      ),
    staleTime: 15_000,
  });
}

export function engagementFindingsQuery(
  slug: string,
  search: { query?: string; severity?: string; sort?: string; page?: number; pageSize?: number } = {},
) {
  return queryOptions({
    queryKey: [
      "engagement-findings",
      slug,
      search.query || "",
      search.severity || "",
      search.sort || "",
      search.page || 1,
      search.pageSize || 20,
    ],
    queryFn: () =>
      requestJSON<ListResponse<PlatformFinding>>(
        withSearchParams(`/api/v1/engagements/${slug}/findings`, {
          query: search.query,
          severity: search.severity,
          sort: search.sort,
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 15_000,
  });
}

export function engagementFindingDetailQuery(slug: string, groupID: string) {
  return queryOptions({
    queryKey: ["engagement-finding-detail", slug, groupID],
    queryFn: () => requestJSON<FindingDetailPayload>(`/api/v1/engagements/${slug}/findings/${encodeURIComponent(groupID)}`),
    staleTime: 15_000,
  });
}

export function engagementSourcesQuery(slug: string, search: { page?: number; pageSize?: number } = {}) {
  return queryOptions({
    queryKey: ["engagement-sources", slug, search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<ListResponse<PlatformSource>>(
        withSearchParams(`/api/v1/engagements/${slug}/sources`, {
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 30_000,
  });
}

export function engagementRunsQuery(slug: string, search: { page?: number; pageSize?: number } = {}) {
  return queryOptions({
    queryKey: ["engagement-runs", slug, search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<ListResponse<PlatformRun>>(
        withSearchParams(`/api/v1/engagements/${slug}/runs`, {
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 15_000,
  });
}

export function engagementScopeQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-scope", slug],
    queryFn: () => requestJSON<EngagementScopePayload>(`/api/v1/engagements/${slug}/scope`),
    staleTime: 15_000,
  });
}

export function engagementCampaignsQuery(slug: string, search: { page?: number; pageSize?: number } = {}) {
  return queryOptions({
    queryKey: ["engagement-campaigns", slug, search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<EngagementCampaignsPayload>(
        withSearchParams(`/api/v1/engagements/${slug}/campaigns`, {
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 15_000,
  });
}

export function engagementRecommendationsQuery(slug: string, search: { page?: number; pageSize?: number } = {}) {
  return queryOptions({
    queryKey: ["engagement-recommendations", slug, search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<EngagementRecommendationsPayload>(
        withSearchParams(`/api/v1/engagements/${slug}/recommendations`, {
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 15_000,
  });
}

export function engagementSettingsQuery(slug: string, search: { page?: number; pageSize?: number } = {}) {
  return queryOptions({
    queryKey: ["engagement-settings", slug, search.page || 1, search.pageSize || 20],
    queryFn: () =>
      requestJSON<EngagementSettingsPayload>(
        withSearchParams(`/api/v1/engagements/${slug}/settings`, {
          page: search.page,
          page_size: search.pageSize,
        }),
      ),
    staleTime: 30_000,
  });
}

export function engagementTopologyQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-topology", slug],
    queryFn: () => requestJSON<TopologyGraph>(`/api/v1/engagements/${slug}/topology`),
    staleTime: 15_000,
  });
}

export async function login(loginValue: string, password: string) {
  return requestJSON<SessionPayload>("/api/v1/session/login", {
    method: "POST",
    body: JSON.stringify({ login: loginValue, password }),
  });
}

export async function logout() {
  return requestJSON<SessionPayload>("/api/v1/session/logout", {
    method: "POST",
  });
}

export async function updateToolCommandTemplate(
  toolID: string,
  payload: { commandTemplate?: string; reset?: boolean },
) {
  return requestJSON<PlatformTool>(`/api/v1/admin/tools/${toolID}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function importEngagementSource(slug: string, file: File) {
  const form = new FormData();
  form.set("scan_file", file);
  return requestJSON<MutationStatus>(`/api/v1/engagements/${slug}/sources/import`, {
    method: "POST",
    body: form,
    headers: {
      Accept: "application/json",
    },
  });
}

export async function runEngagementCampaignAction(slug: string, payload: Record<string, unknown>) {
  return requestJSON<MutationStatus>(`/api/v1/engagements/${slug}/campaigns/run`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function approveEngagementApproval(slug: string, approvalID: string) {
  return requestJSON<MutationStatus>(`/api/v1/engagements/${slug}/approvals/${encodeURIComponent(approvalID)}/approve`, {
    method: "POST",
  });
}

export async function requestEngagementRecommendations(slug: string, campaignId = "") {
  return requestJSON<MutationStatus>(`/api/v1/engagements/${slug}/recommendations/llm`, {
    method: "POST",
    body: JSON.stringify({ campaignId }),
  });
}

export async function addEngagementMember(slug: string, payload: { user: string; role: string }) {
  return requestJSON<MutationStatus>(`/api/v1/engagements/${slug}/settings/members`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
