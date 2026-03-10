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

export type PlatformEngagement = {
  id: string;
  slug: string;
  name: string;
  description: string;
  status: string;
  scopeSummary: string;
  workspaceID: string;
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
    queryFn: () => requestJSON<PlatformEngagement[]>("/api/v1/engagements"),
    staleTime: 30_000,
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
    queryFn: () => requestJSON<{ tools: Array<{ id: string; label: string; status: string; kind: string }> }>("/api/v1/admin/tools"),
    staleTime: 30_000,
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
    queryFn: () => requestJSON<PlatformHost[]>(`/api/v1/engagements/${slug}/hosts${suffix}`),
    staleTime: 15_000,
  });
}

export function engagementZonesQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-zones", slug],
    queryFn: () => requestJSON<PlatformZone[]>(`/api/v1/engagements/${slug}/zones`),
    staleTime: 30_000,
  });
}

export function engagementFindingsQuery(slug: string) {
  return queryOptions({
    queryKey: ["engagement-findings", slug],
    queryFn: () => requestJSON<PlatformFinding[]>(`/api/v1/engagements/${slug}/findings`),
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
