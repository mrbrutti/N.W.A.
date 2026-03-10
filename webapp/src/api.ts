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
  tools: ListResponse<PlatformTool>;
  connectors: ListResponse<PlatformConnector>;
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
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
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

export function engagementHostsQuery(slug: string, search: { query?: string; zone?: string }) {
  const params = new URLSearchParams();
  if (search.query) {
    params.set("query", search.query);
  }
  if (search.zone) {
    params.set("zone", search.zone);
  }
  const suffix = params.toString() ? `?${params.toString()}` : "";
  return queryOptions({
    queryKey: ["engagement-hosts", slug, search.query || "", search.zone || ""],
    queryFn: () => requestJSON<ListResponse<PlatformHost>>(`/api/v1/engagements/${slug}/hosts${suffix}`),
    staleTime: 15_000,
  });
}

export function engagementZonesQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-zones", slug],
    queryFn: () => requestJSON<ListResponse<PlatformZone>>(`/api/v1/engagements/${slug}/zones`),
    staleTime: 30_000,
  });
}

export function engagementPortsQuery(slug: string, query = "") {
  const params = new URLSearchParams();
  if (query) {
    params.set("query", query);
  }
  const suffix = params.toString() ? `?${params.toString()}` : "";
  return queryOptions({
    queryKey: ["engagement-ports", slug, query],
    queryFn: () => requestJSON<ListResponse<PlatformPort>>(`/api/v1/engagements/${slug}/ports${suffix}`),
    staleTime: 15_000,
  });
}

export function engagementFindingsQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-findings", slug],
    queryFn: () => requestJSON<ListResponse<PlatformFinding>>(`/api/v1/engagements/${slug}/findings`),
    staleTime: 15_000,
  });
}

export function engagementSourcesQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-sources", slug],
    queryFn: () => requestJSON<ListResponse<PlatformSource>>(`/api/v1/engagements/${slug}/sources`),
    staleTime: 30_000,
  });
}

export function engagementRunsQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-runs", slug],
    queryFn: () => requestJSON<ListResponse<PlatformRun>>(`/api/v1/engagements/${slug}/runs`),
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

export function engagementCampaignsQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-campaigns", slug],
    queryFn: () => requestJSON<EngagementCampaignsPayload>(`/api/v1/engagements/${slug}/campaigns`),
    staleTime: 15_000,
  });
}

export function engagementRecommendationsQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-recommendations", slug],
    queryFn: () => requestJSON<EngagementRecommendationsPayload>(`/api/v1/engagements/${slug}/recommendations`),
    staleTime: 15_000,
  });
}

export function engagementSettingsQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-settings", slug],
    queryFn: () => requestJSON<EngagementSettingsPayload>(`/api/v1/engagements/${slug}/settings`),
    staleTime: 30_000,
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
