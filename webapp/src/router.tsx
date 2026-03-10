import {
  Outlet,
  RouterProvider,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  redirect,
  useNavigate,
  useRouterState,
} from "@tanstack/react-router";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
  useSuspenseQuery,
} from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  type FormEvent,
  type ReactNode,
  Suspense,
  lazy,
  startTransition,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  adminHealthQuery,
  adminAuditQuery,
  adminConnectorsQuery,
  adminEngagementsQuery,
  adminOverviewQuery,
  adminToolsQuery,
  adminUsersQuery,
  adminWorkersQuery,
  addEngagementMember,
  approveEngagementApproval,
  engagementCampaignsQuery,
  engagementFindingDetailQuery,
  engagementFindingsQuery,
  engagementHostDetailQuery,
  engagementHostsQuery,
  engagementPortDetailQuery,
  engagementPortsQuery,
  engagementRecommendationsQuery,
  engagementRunsQuery,
  engagementSettingsQuery,
  engagementSourcesQuery,
  engagementSummaryQuery,
  engagementTopologyQuery,
  engagementZonesQuery,
  engagementsQuery,
  importEngagementSource,
  login,
  logout,
  type FindingGroup,
  type HostPortRow,
  type PlatformFinding,
  sessionQuery,
  type PlatformHost,
  type PlatformAuditEvent,
  type PlatformPagination,
  type PlatformPort,
  type SessionPayload,
  type OrchestrationPolicy,
  type OrchestrationStep,
  requestEngagementRecommendations,
  runEngagementCampaignAction,
  updateToolCommandTemplate,
} from "./api";

const PolicyFlowCanvas = lazy(async () => {
  const module = await import("./flowViews");
  return { default: module.PolicyFlowCanvas };
});

const TopologyFlowCanvas = lazy(async () => {
  const module = await import("./flowViews");
  return { default: module.TopologyFlowCanvas };
});

type RouterContext = {
  queryClient: QueryClient;
};

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

const pageSizes = [20, 50, 100] as const;

function readString(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function readInt(value: unknown, fallback: number) {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return fallback;
}

function readPageSize(value: unknown, fallback = 20) {
  const parsed = readInt(value, fallback);
  return pageSizes.includes(parsed as (typeof pageSizes)[number]) ? parsed : fallback;
}

function zoneSearchState(
  current: {
    zone: string;
    zoneSort: string;
    zonesPage: number;
    zonesPageSize: number;
    hostSort: string;
    hostsPage: number;
    hostsPageSize: number;
  },
  next: Partial<{
    zone: string;
    zoneSort: string;
    zonesPage: number;
    zonesPageSize: number;
    hostSort: string;
    hostsPage: number;
    hostsPageSize: number;
  }>,
) {
  return {
    zone: next.zone ?? current.zone,
    zoneSort: next.zoneSort ?? current.zoneSort,
    zonesPage: next.zonesPage ?? current.zonesPage,
    zonesPageSize: next.zonesPageSize ?? current.zonesPageSize,
    hostSort: next.hostSort ?? current.hostSort,
    hostsPage: next.hostsPage ?? current.hostsPage,
    hostsPageSize: next.hostsPageSize ?? current.hostsPageSize,
  };
}

function hostsSearchState(
  current: {
    query: string;
    zone: string;
    sort: string;
    page: number;
    pageSize: number;
  },
  next: Partial<{
    query: string;
    zone: string;
    sort: string;
    page: number;
    pageSize: number;
  }>,
) {
  return {
    query: next.query ?? current.query,
    zone: next.zone ?? current.zone,
    sort: next.sort ?? current.sort,
    page: next.page ?? current.page,
    pageSize: next.pageSize ?? current.pageSize,
  };
}

function portsSearchState(
  current: {
    query: string;
    sort: string;
    page: number;
    pageSize: number;
  },
  next: Partial<{
    query: string;
    sort: string;
    page: number;
    pageSize: number;
  }>,
) {
  return {
    query: next.query ?? current.query,
    sort: next.sort ?? current.sort,
    page: next.page ?? current.page,
    pageSize: next.pageSize ?? current.pageSize,
  };
}

function findingsSearchState(
  current: {
    query: string;
    severity: string;
    sort: string;
    page: number;
    pageSize: number;
  },
  next: Partial<{
    query: string;
    severity: string;
    sort: string;
    page: number;
    pageSize: number;
  }>,
) {
  return {
    query: next.query ?? current.query,
    severity: next.severity ?? current.severity,
    sort: next.sort ?? current.sort,
    page: next.page ?? current.page,
    pageSize: next.pageSize ?? current.pageSize,
  };
}

function dualListSearchState(
  current: {
    primaryPage: number;
    primaryPageSize: number;
    secondaryPage: number;
    secondaryPageSize: number;
  },
  next: Partial<{
    primaryPage: number;
    primaryPageSize: number;
    secondaryPage: number;
    secondaryPageSize: number;
  }>,
) {
  return {
    primaryPage: next.primaryPage ?? current.primaryPage,
    primaryPageSize: next.primaryPageSize ?? current.primaryPageSize,
    secondaryPage: next.secondaryPage ?? current.secondaryPage,
    secondaryPageSize: next.secondaryPageSize ?? current.secondaryPageSize,
  };
}

function singlePageSearchState(
  current: {
    page: number;
    pageSize: number;
  },
  next: Partial<{
    page: number;
    pageSize: number;
  }>,
) {
  return {
    page: next.page ?? current.page,
    pageSize: next.pageSize ?? current.pageSize,
  };
}

function campaignsSearchState(
  current: {
    page: number;
    pageSize: number;
    policyId: string;
  },
  next: Partial<{
    page: number;
    pageSize: number;
    policyId: string;
  }>,
) {
  return {
    page: next.page ?? current.page,
    pageSize: next.pageSize ?? current.pageSize,
    policyId: next.policyId ?? current.policyId,
  };
}

function topologySearchState(
  current: {
    focusRouteId: string;
    minEdgeCount: number;
    role: string;
    selectedNode: string;
  },
  next: Partial<{
    focusRouteId: string;
    minEdgeCount: number;
    role: string;
    selectedNode: string;
  }>,
) {
  return {
    focusRouteId: next.focusRouteId ?? current.focusRouteId,
    minEdgeCount: next.minEdgeCount ?? current.minEdgeCount,
    role: next.role ?? current.role,
    selectedNode: next.selectedNode ?? current.selectedNode,
  };
}

async function requireSession(context: RouterContext) {
  const session = await context.queryClient.ensureQueryData(sessionQuery());
  if (!session.authenticated || !session.user) {
    throw redirect({ to: "/login" });
  }
  return session;
}

async function requireAdmin(context: RouterContext) {
  const session = await requireSession(context);
  if (!session.user?.isAdmin) {
    throw redirect({ to: "/engagements" });
  }
  return session;
}

const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
  errorComponent: ({ error }) => (
    <FullState
      tone="danger"
      title="Command center failed to load"
      body={error instanceof Error ? error.message : "Unexpected application error."}
    />
  ),
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: async ({ context }) => {
    const session = await context.queryClient.ensureQueryData(sessionQuery());
    throw redirect({
      to: session.authenticated ? session.redirectTo || "/engagements" : "/login",
    });
  },
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  beforeLoad: async ({ context }) => {
    const session = await context.queryClient.ensureQueryData(sessionQuery());
    if (session.authenticated) {
      throw redirect({ to: session.redirectTo || "/engagements" });
    }
  },
  component: LoginPage,
});

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/admin",
  beforeLoad: async ({ context }) => {
    await requireAdmin(context);
  },
  component: AdminLayout,
});

const adminOverviewRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/",
  component: AdminOverviewPage,
});

const adminUsersRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/users",
  component: AdminUsersPage,
});

const adminEngagementsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/engagements",
  component: AdminEngagementRegistryPage,
});

const adminWorkersRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/workers",
  component: AdminWorkersPage,
});

const adminConnectorsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/connectors",
  component: AdminConnectorsPage,
});

const adminToolsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/tools",
  component: AdminToolsPage,
});

const adminAuditRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: "/audit",
  component: AdminAuditPage,
});

const engagementsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements",
  beforeLoad: async ({ context }) => {
    await requireSession(context);
  },
  component: EngagementsPage,
});

const engagementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements/$slug",
  beforeLoad: async ({ context }) => {
    await requireSession(context);
  },
  component: EngagementLayout,
});

const engagementOverviewRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/",
  component: EngagementOverviewPage,
});

const engagementZonesRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/zones",
  validateSearch: (search: Record<string, unknown>) => ({
    zone: readString(search.zone),
    zoneSort: readString(search.zoneSort, "hosts"),
    zonesPage: readInt(search.zonesPage, 1),
    zonesPageSize: readPageSize(search.zonesPageSize),
    hostSort: readString(search.hostSort, "findings"),
    hostsPage: readInt(search.hostsPage, 1),
    hostsPageSize: readPageSize(search.hostsPageSize),
  }),
  component: EngagementZonesPage,
});

const engagementHostsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/hosts",
  validateSearch: (search: Record<string, unknown>) => ({
    query: readString(search.query),
    zone: readString(search.zone),
    sort: readString(search.sort, "findings"),
    page: readInt(search.page, 1),
    pageSize: readPageSize(search.pageSize),
  }),
  component: EngagementHostsPage,
});

const engagementHostDetailRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/hosts/$ip",
  component: EngagementHostDetailPage,
});

const engagementPortsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/ports",
  validateSearch: (search: Record<string, unknown>) => ({
    query: readString(search.query),
    sort: readString(search.sort, "hosts"),
    page: readInt(search.page, 1),
    pageSize: readPageSize(search.pageSize),
  }),
  component: EngagementPortsPage,
});

const engagementPortDetailRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/ports/$protocol/$port",
  component: EngagementPortDetailPage,
});

const engagementFindingsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/findings",
  validateSearch: (search: Record<string, unknown>) => ({
    query: readString(search.query),
    severity: readString(search.severity, "all"),
    sort: readString(search.sort, "severity"),
    page: readInt(search.page, 1),
    pageSize: readPageSize(search.pageSize),
  }),
  component: EngagementFindingsPage,
});

const engagementFindingDetailRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/findings/$groupID",
  component: EngagementFindingDetailPage,
});

const engagementSourcesRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/sources",
  validateSearch: (search: Record<string, unknown>) => ({
    primaryPage: readInt(search.primaryPage, 1),
    primaryPageSize: readPageSize(search.primaryPageSize),
    secondaryPage: readInt(search.secondaryPage, 1),
    secondaryPageSize: readPageSize(search.secondaryPageSize),
  }),
  component: EngagementSourcesPage,
});

const engagementCampaignsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/campaigns",
  validateSearch: (search: Record<string, unknown>) => ({
    page: readInt(search.page, 1),
    pageSize: readPageSize(search.pageSize),
    policyId: readString(search.policyId),
  }),
  component: EngagementCampaignsPage,
});

const engagementTopologyRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/topology",
  validateSearch: (search: Record<string, unknown>) => ({
    focusRouteId: readString(search.focusRouteId),
    minEdgeCount: readInt(search.minEdgeCount, 1),
    role: readString(search.role, "all"),
    selectedNode: readString(search.selectedNode),
  }),
  component: EngagementTopologyPage,
});

const engagementRecommendationsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/recommendations",
  validateSearch: (search: Record<string, unknown>) => ({
    page: readInt(search.page, 1),
    pageSize: readPageSize(search.pageSize),
  }),
  component: EngagementRecommendationsPage,
});

const engagementSettingsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/settings",
  validateSearch: (search: Record<string, unknown>) => ({
    page: readInt(search.page, 1),
    pageSize: readPageSize(search.pageSize),
  }),
  component: EngagementSettingsPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  adminRoute.addChildren([
    adminOverviewRoute,
    adminUsersRoute,
    adminEngagementsRoute,
    adminWorkersRoute,
    adminConnectorsRoute,
    adminToolsRoute,
    adminAuditRoute,
  ]),
  engagementsRoute,
  engagementRoute.addChildren([
    engagementOverviewRoute,
    engagementZonesRoute,
    engagementHostsRoute,
    engagementHostDetailRoute,
    engagementPortsRoute,
    engagementPortDetailRoute,
    engagementFindingsRoute,
    engagementFindingDetailRoute,
    engagementSourcesRoute,
    engagementCampaignsRoute,
    engagementTopologyRoute,
    engagementRecommendationsRoute,
    engagementSettingsRoute,
  ]),
]);

const router = createRouter({
  routeTree,
  basepath: "/app",
  context: {
    queryClient,
  },
  defaultPendingComponent: () => (
    <ShellScaffold>
      <FullState tone="muted" title="Loading" body="Preparing the command center shell." />
    </ShellScaffold>
  ),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

export function AppRouter() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

function RootLayout() {
  const session = useQuery(sessionQuery());

  return (
    <ShellScaffold>
      <Suspense fallback={<FullState tone="muted" title="Loading" body="Loading platform state." />}>
        <PlatformShell session={session.data}>
          <Outlet />
        </PlatformShell>
      </Suspense>
    </ShellScaffold>
  );
}

function PlatformShell({
  session,
  children,
}: {
  session?: SessionPayload;
  children: ReactNode;
}) {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });

  return (
    <div className="cc-shell">
      <header className="cc-topbar">
        <div className="cc-brand">
          <span className="cc-brand__mark">NWA</span>
          <div>
            <strong>Network Operations Workbench</strong>
            <small>Multi-user engagement command center</small>
          </div>
        </div>
        {session?.authenticated ? (
          <nav className="cc-menubar">
            <MenuGroup
              label="Platform"
              active={pathname.startsWith("/admin")}
              items={[
                { href: "/app/admin", label: "Overview", detail: "System health and queue posture" },
                { href: "/app/admin/users", label: "Users", detail: "Accounts and platform roles" },
                { href: "/app/admin/engagements", label: "Engagements", detail: "Mission registry and ownership" },
                { href: "/app/admin/workers", label: "Workers", detail: "Workers, queue, and execution posture" },
                { href: "/app/admin/tools", label: "Tools", detail: "CLI tools and command templates" },
                { href: "/app/admin/connectors", label: "Connectors", detail: "External scanner readiness" },
                { href: "/app/admin/audit", label: "Audit", detail: "Recent platform events" },
              ]}
            />
            <MenuGroup
              label="Engagements"
              active={pathname.startsWith("/engagements")}
              items={(session.engagements || []).slice(0, 8).map((engagement) => ({
                href: `/app/engagements/${engagement.slug}`,
                label: engagement.name,
                detail: `${engagement.hostCount} hosts · ${engagement.findingCount} findings`,
              }))}
              footerHref="/app/engagements"
              footerLabel="Open registry"
            />
            <MenuGroup
              label="Account"
              items={[
                {
                  href: session.user?.isAdmin ? "/app/admin" : "/app/engagements",
                  label: session.user?.displayName || session.user?.username || "User",
                  detail: session.user?.isAdmin ? "Platform administrator" : "Operator session",
                },
              ]}
              footer={<LogoutButton />}
            />
          </nav>
        ) : null}
      </header>
      <div className="cc-body">{children}</div>
    </div>
  );
}

function MenuGroup({
  label,
  items,
  active,
  footer,
  footerHref,
  footerLabel,
}: {
  label: string;
  items: Array<{ href: string; label: string; detail: string }>;
  active?: boolean;
  footer?: ReactNode;
  footerHref?: string;
  footerLabel?: string;
}) {
  return (
    <details className={`cc-menu ${active ? "is-active" : ""}`}>
      <summary>{label}</summary>
      <div className="cc-menu__panel">
        <div className="cc-menu__list">
          {items.length === 0 ? (
            <span className="cc-menu__empty">Nothing available yet.</span>
          ) : (
            items.map((item) => (
              <a className="cc-menu__item" href={item.href} key={item.href}>
                <strong>{item.label}</strong>
                <small>{item.detail}</small>
              </a>
            ))
          )}
        </div>
        {footerHref && footerLabel ? (
          <a className="cc-menu__footer" href={footerHref}>
            {footerLabel}
          </a>
        ) : null}
        {footer}
      </div>
    </details>
  );
}

function LoginPage() {
  const queryClient = useQueryClient();
  const [loginValue, setLoginValue] = useState("admin");
  const [password, setPassword] = useState("");

  const mutation = useMutation({
    mutationFn: () => login(loginValue, password),
    onSuccess: async (payload) => {
      await queryClient.setQueryData(sessionQuery().queryKey, payload);
      startTransition(() => {
        window.location.assign(payload.redirectTo || "/app/engagements");
      });
    },
  });

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    mutation.mutate();
  }

  return (
    <div className="cc-login">
      <section className="cc-card cc-card--hero">
        <p className="cc-kicker">Access</p>
        <h1>Operate the command center from one control surface.</h1>
        <p className="cc-copy">
          React now owns the admin deck, engagement registry, and the first inventory surfaces. This shell is tuned for
          shared operations, not static reports.
        </p>
      </section>

      <section className="cc-card">
        <form className="cc-form" onSubmit={handleSubmit}>
          <label>
            <span>Login</span>
            <input value={loginValue} onChange={(event) => setLoginValue(event.target.value)} />
          </label>
          <label>
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          <button className="cc-button cc-button--primary" disabled={mutation.isPending}>
            {mutation.isPending ? "Signing in" : "Sign in"}
          </button>
        </form>
        {mutation.isError ? (
          <InlineState tone="danger" title="Login failed" body={mutation.error.message} />
        ) : null}
      </section>
    </div>
  );
}

function AdminLayout() {
  const overview = useSuspenseQuery(adminOverviewQuery());

  return (
    <div className="cc-page">
      <PageHeader
        kicker="Platform"
        title="Admin Control Deck"
        subtitle="System health, operators, engagements, tooling, and queue posture from the React admin surface."
        actions={<AdminTabs />}
      />
      <StatGrid
        items={[
          {
            label: "Users",
            value: overview.data.health.userCount.toString(),
            detail: "Active platform accounts",
          },
          {
            label: "Engagements",
            value: overview.data.health.engagementCount.toString(),
            detail: "Registered missions",
          },
          {
            label: "Workers",
            value: `${overview.data.health.liveWorkers}/${overview.data.health.workerCount}`,
            detail: "Live versus configured workers",
          },
          {
            label: "Queue",
            value: `${overview.data.health.runningRuns} / ${overview.data.health.queuedRuns}`,
            detail: "Running and queued runs",
          },
        ]}
      />
      <Outlet />
    </div>
  );
}

function AdminTabs() {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });

  const items = [
    { href: "/app/admin", label: "Overview" },
    { href: "/app/admin/users", label: "Users" },
    { href: "/app/admin/engagements", label: "Engagements" },
    { href: "/app/admin/workers", label: "Workers" },
    { href: "/app/admin/connectors", label: "Connectors" },
    { href: "/app/admin/tools", label: "Tools" },
    { href: "/app/admin/audit", label: "Audit" },
  ];

  return (
    <div className="cc-subnav">
      {items.map((item) => (
        <a className={pathname === item.href ? "is-active" : ""} href={item.href} key={item.href}>
          {item.label}
        </a>
      ))}
    </div>
  );
}

function AdminOverviewPage() {
  const overview = useSuspenseQuery(adminOverviewQuery());

  return (
    <div className="cc-stack">
      <div className="cc-grid cc-grid--two">
        <Panel title="Queue posture" meta="Execution health at a glance">
          <Table
            columns={["Signal", "Value", "Interpretation"]}
            rows={[
              ["Running runs", overview.data.health.runningRuns.toString(), "Active work across all engagements"],
              ["Queued runs", overview.data.health.queuedRuns.toString(), "Backlog waiting for workers"],
              ["Configured connectors", overview.data.health.configuredConnectors.toString(), "Reachable external integrations"],
              ["Ready tools", overview.data.health.readyTools.toString(), "Usable built-in or custom tooling"],
            ]}
            empty="No queue posture available."
          />
        </Panel>
        <Panel title="Recent audit" meta={`${overview.data.audit.pagination.total} events`}>
          <List
            items={overview.data.audit.items.slice(0, 6).map((item) => ({
              key: `${item.createdAt}-${item.kind}-${item.summary}`,
              label: item.summary,
              detail: `${item.kind} · ${item.actorLabel} · ${item.createdAt}`,
            }))}
            empty="No audit events recorded."
          />
        </Panel>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Workers" meta={`${overview.data.workers.pagination.total} registered`}>
          <Table
            columns={["Worker", "Mode", "Zone", "Status", "Last seen"]}
            rows={overview.data.workers.items.map((worker) => [
              worker.label,
              worker.mode,
              worker.zone || "default",
              <StatusBadge key={`${worker.id}-status`} tone={worker.statusTone} label={worker.status} />,
              worker.lastSeenAt || "Never",
            ])}
            empty="No workers registered."
          />
        </Panel>

        <Panel title="Engagement registry" meta={`${overview.data.engagements.pagination.total} engagements`}>
          <Table
            columns={["Engagement", "Scope", "Hosts", "Findings"]}
            rows={overview.data.engagements.items.map((item) => [
              <a key={item.id} href={`/app/engagements/${item.slug}`}>
                {item.name}
              </a>,
              item.scopeSummary || item.description || "No scope summary",
              item.hostCount.toString(),
              item.findingCount.toString(),
            ])}
            empty="No engagements available."
          />
        </Panel>
      </div>
    </div>
  );
}

function AdminUsersPage() {
  const users = useSuspenseQuery(adminUsersQuery());

  return (
    <Panel title="Users" meta={`${users.data.pagination.total} accounts`}>
      <Table
        columns={["User", "Role", "Status", "Created", "Last login"]}
        rows={users.data.items.map((user) => [
          <div key={user.id}>
            <strong>{user.displayName}</strong>
            <small>
              {user.username} · {user.email}
            </small>
          </div>,
          user.isAdmin ? "Admin" : user.role || "User",
          user.status,
          user.createdAt,
          user.lastLoginAt || "Never",
        ])}
        empty="No users available."
        pagination={users.data.pagination}
      />
    </Panel>
  );
}

function AdminEngagementRegistryPage() {
  const engagements = useSuspenseQuery(adminEngagementsQuery());

  return (
    <Panel title="Engagement registry" meta={`${engagements.data.pagination.total} missions`}>
      <Table
        columns={["Name", "Scope", "Members", "Hosts", "Findings", "Updated"]}
        rows={engagements.data.items.map((item) => [
          <div key={item.id}>
            <a href={`/app/engagements/${item.slug}`}>{item.name}</a>
            <small>{item.slug}</small>
          </div>,
          item.scopeSummary || item.description || "No summary",
          item.memberCount.toString(),
          item.hostCount.toString(),
          item.findingCount.toString(),
          item.updatedAt,
        ])}
        empty="No engagements available."
        pagination={engagements.data.pagination}
      />
    </Panel>
  );
}

function AdminWorkersPage() {
  const health = useSuspenseQuery(adminHealthQuery());
  const workers = useSuspenseQuery(adminWorkersQuery());

  return (
    <div className="cc-stack">
      <section className="cc-stat-grid cc-stat-grid--compact">
        <article className="cc-stat-card">
          <p>Running</p>
          <strong>{health.data.runningRuns}</strong>
          <span>Active runs across all engagements</span>
        </article>
        <article className="cc-stat-card">
          <p>Queued</p>
          <strong>{health.data.queuedRuns}</strong>
          <span>Runs waiting for capacity</span>
        </article>
        <article className="cc-stat-card">
          <p>Workers</p>
          <strong>{health.data.workerCount}</strong>
          <span>Total worker definitions</span>
        </article>
        <article className="cc-stat-card">
          <p>Live workers</p>
          <strong>{health.data.liveWorkers}</strong>
          <span>Workers currently online</span>
        </article>
      </section>

      <Panel title="Worker registry" meta={`${workers.data.pagination.total} workers`}>
        <Table
          columns={["Worker", "Mode", "Zone", "Status", "Detail", "Last seen"]}
          rows={workers.data.items.map((worker) => [
            worker.label,
            worker.mode,
            worker.zone || "default",
            <StatusBadge key={`${worker.id}-status`} tone={worker.statusTone} label={worker.status} />,
            worker.detail || "No detail",
            worker.lastSeenAt || "Never",
          ])}
          empty="No workers configured."
          pagination={workers.data.pagination}
        />
      </Panel>
    </div>
  );
}

function AdminConnectorsPage() {
  const connectors = useSuspenseQuery(adminConnectorsQuery());

  return (
    <Panel title="Connectors" meta={`${connectors.data.pagination.total} configured`}>
      <Table
        columns={["Connector", "Status", "Detail"]}
        rows={connectors.data.items.map((connector) => [
          connector.label,
          <StatusBadge key={`${connector.id}-status`} tone={connector.statusTone} label={connector.status} />,
          connector.statusDetail || "No detail",
        ])}
        empty="No connectors registered."
        pagination={connectors.data.pagination}
      />
    </Panel>
  );
}

function AdminToolsPage() {
  const queryClient = useQueryClient();
  const tools = useSuspenseQuery(adminToolsQuery());
  const [drafts, setDrafts] = useState<Record<string, string>>({});

  useEffect(() => {
    setDrafts((current) => {
      const next = { ...current };
      for (const tool of tools.data.items) {
        if (!(tool.id in next)) {
          next[tool.id] = tool.commandTemplate || tool.resolvedCommandTemplate || tool.defaultCommandTemplate || "";
        }
      }
      return next;
    });
  }, [tools.data.items]);

  const mutation = useMutation({
    mutationFn: ({ toolID, commandTemplate, reset }: { toolID: string; commandTemplate?: string; reset?: boolean }) =>
      updateToolCommandTemplate(toolID, { commandTemplate, reset }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: adminToolsQuery().queryKey }),
        queryClient.invalidateQueries({ queryKey: adminOverviewQuery().queryKey }),
      ]);
    },
  });

  const editableTools = tools.data.items.filter((tool) => tool.commandEditable);

  return (
    <div className="cc-stack">
      <Panel title="Tool registry" meta={`${tools.data.pagination.total} tools`}>
        <Table
          columns={["Tool", "Kind", "Strategy", "Status", "Safety", "Cost"]}
          rows={tools.data.items.map((tool) => [
            <div key={tool.id}>
              <strong>{tool.label}</strong>
              <small>{tool.id}</small>
            </div>,
            tool.kind,
            tool.targetStrategy,
            <StatusBadge key={`${tool.id}-status`} tone={tool.statusTone} label={tool.status} />,
            tool.safetyClass,
            tool.costProfile,
          ])}
          empty="No tools registered."
          pagination={tools.data.pagination}
        />
      </Panel>

      <Panel title="CLI command templates" meta={`${editableTools.length} editable`}>
        {editableTools.length === 0 ? (
          <InlineState tone="muted" title="No editable tools" body="Built-in API connectors do not expose CLI templates." />
        ) : (
          <div className="cc-editor-list">
            {editableTools.map((tool) => (
              <form
                className="cc-editor"
                key={tool.id}
                onSubmit={(event) => {
                  event.preventDefault();
                  mutation.mutate({
                    toolID: tool.id,
                    commandTemplate: drafts[tool.id],
                  });
                }}
              >
                <div className="cc-editor__head">
                  <div>
                    <strong>{tool.label}</strong>
                    <small>
                      {tool.binaryName || tool.id} · {tool.family}
                    </small>
                  </div>
                  <StatusBadge tone={tool.statusTone} label={tool.status} />
                </div>
                <p className="cc-copy cc-copy--tight">{tool.description}</p>
                <label className="cc-field">
                  <span>Command template</span>
                  <textarea
                    value={drafts[tool.id] ?? ""}
                    onChange={(event) =>
                      setDrafts((current) => ({
                        ...current,
                        [tool.id]: event.target.value,
                      }))
                    }
                    rows={3}
                  />
                </label>
                <div className="cc-inline-note">
                  <span>Default</span>
                  <code>{tool.defaultCommandTemplate || "{{binary}} {{args}}"}</code>
                </div>
                <div className="cc-editor__actions">
                  <button className="cc-button cc-button--primary" disabled={mutation.isPending} type="submit">
                    Save template
                  </button>
                  <button
                    className="cc-button"
                    disabled={mutation.isPending}
                    onClick={() => {
                      setDrafts((current) => ({
                        ...current,
                        [tool.id]: tool.defaultCommandTemplate || "",
                      }));
                      mutation.mutate({
                        toolID: tool.id,
                        reset: true,
                      });
                    }}
                    type="button"
                  >
                    Reset
                  </button>
                </div>
              </form>
            ))}
          </div>
        )}
        {mutation.isError ? (
          <InlineState tone="danger" title="Tool update failed" body={mutation.error.message} />
        ) : null}
      </Panel>
    </div>
  );
}

function AdminAuditPage() {
  const audit = useSuspenseQuery(adminAuditQuery());

  return (
    <Panel title="Audit events" meta={`${audit.data.pagination.total} events`}>
      <Table
        columns={["Timestamp", "Actor", "Kind", "Summary", "Engagement"]}
        rows={audit.data.items.map((item: PlatformAuditEvent) => [
          item.createdAt,
          item.actorLabel,
          item.kind,
          item.summary,
          item.engagementName || "Platform",
        ])}
        empty="No audit events recorded."
        pagination={audit.data.pagination}
      />
    </Panel>
  );
}

function EngagementsPage() {
  const engagements = useSuspenseQuery(engagementsQuery());

  return (
    <div className="cc-page">
      <PageHeader
        kicker="Engagements"
        title="Registry"
        subtitle="Shared mission index for operators and analysts."
      />
      <Panel title="Available engagements" meta={`${engagements.data.pagination.total} total`}>
        <div className="cc-stack">
          {engagements.data.items.length === 0 ? (
            <InlineState tone="muted" title="No engagements" body="Create an engagement from the admin control deck." />
          ) : (
            engagements.data.items.map((item) => (
              <a className="cc-list-row" href={`/app/engagements/${item.slug}`} key={item.id}>
                <div>
                  <strong>{item.name}</strong>
                  <small>{item.scopeSummary || item.description}</small>
                </div>
                <span>
                  {item.hostCount} hosts · {item.findingCount} findings
                </span>
              </a>
            ))
          )}
        </div>
      </Panel>
    </div>
  );
}

function EngagementLayout() {
  const { slug } = engagementRoute.useParams();
  const engagements = useSuspenseQuery(engagementsQuery());
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });
  const engagement = engagements.data.items.find((item) => item.slug === slug);

  if (!engagement) {
    return <FullState tone="danger" title="Unknown engagement" body="This engagement is not visible in the current session." />;
  }

  return (
    <div className="cc-page">
      <PageHeader
        kicker="Engagement"
        title={engagement.name}
        subtitle={engagement.scopeSummary || engagement.description}
        actions={
          <div className="cc-subnav">
            <a
              href={`/app/engagements/${engagement.slug}`}
              className={pathname === `/engagements/${engagement.slug}` ? "is-active" : ""}
            >
              Overview
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/zones`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/zones`) ? "is-active" : ""}
            >
              Zones
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/hosts`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/hosts`) ? "is-active" : ""}
            >
              Hosts
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/ports`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/ports`) ? "is-active" : ""}
            >
              Ports
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/findings`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/findings`) ? "is-active" : ""}
            >
              Findings
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/sources`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/sources`) ? "is-active" : ""}
            >
              Sources
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/campaigns`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/campaigns`) ? "is-active" : ""}
            >
              Campaigns
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/topology`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/topology`) ? "is-active" : ""}
            >
              Topology
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/recommendations`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/recommendations`) ? "is-active" : ""}
            >
              Recommendations
            </a>
            <a
              href={`/app/engagements/${engagement.slug}/settings`}
              className={pathname.startsWith(`/engagements/${engagement.slug}/settings`) ? "is-active" : ""}
            >
              Settings
            </a>
          </div>
        }
      />
      <Outlet />
    </div>
  );
}

function EngagementOverviewPage() {
  const { slug } = engagementRoute.useParams();
  const stats = useSuspenseQuery(engagementSummaryQuery(slug));
  const zones = useSuspenseQuery(engagementZonesQuery(slug, { pageSize: 20 }));
  const hosts = useSuspenseQuery(engagementHostsQuery(slug, { sort: "findings", pageSize: 20 }));
  const ports = useSuspenseQuery(engagementPortsQuery(slug, { sort: "hosts", pageSize: 20 }));
  const findings = useSuspenseQuery(engagementFindingsQuery(slug, { sort: "severity", pageSize: 20 }));

  return (
    <div className="cc-stack">
      <StatGrid
        items={stats.data.map((item) => ({
          label: item.label,
          value: item.value,
          detail: item.detail,
        }))}
      />
      <div className="cc-grid cc-grid--two">
        <Panel title="Zone map" meta={`${zones.data.pagination.total} zones`}>
          <List
            items={zones.data.items.slice(0, 8).map((zone) => ({
              key: zone.id,
              label: zone.name,
              detail: `${zone.kind} · ${zone.hostCount} hosts`,
              href: `/app/engagements/${slug}/zones?zone=${encodeURIComponent(zone.id)}`,
            }))}
            empty="No zones derived yet."
          />
        </Panel>
        <Panel title="Priority hosts" meta="Top of current slice">
          <List
            items={hosts.data.items.slice(0, 8).map((host) => ({
              key: host.ip,
              label: host.displayName,
              detail: `${host.ip} · ${host.openPorts} ports · ${host.findings} findings`,
              href: `/app/engagements/${slug}/hosts/${encodeURIComponent(host.ip)}`,
            }))}
            empty="No host inventory yet."
          />
        </Panel>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Service surface" meta="Most exposed ports">
          <List
            items={ports.data.items.slice(0, 8).map((port) => ({
              key: `${port.protocol}-${port.port}`,
              label: port.label,
              detail: `${port.hosts} hosts · ${port.findings} findings · ${port.service || "unknown service"}`,
              href: `/app/engagements/${slug}/ports/${encodeURIComponent(port.protocol)}/${encodeURIComponent(port.port)}`,
            }))}
            empty="No ports observed yet."
          />
        </Panel>
        <Panel title="Finding groups" meta="Highest-signal definitions">
          <List
            items={findings.data.items.slice(0, 8).map((finding) => ({
              key: finding.id,
              label: finding.name,
              detail: `${finding.severity} · ${finding.occurrences} occurrences`,
              href: `/app/engagements/${slug}/findings/${encodeURIComponent(finding.id)}`,
            }))}
            empty="No finding groups yet."
          />
        </Panel>
      </div>
    </div>
  );
}

function EngagementZonesPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementZonesRoute.useSearch();
  const navigate = useNavigate();
  const zones = useSuspenseQuery(
    engagementZonesQuery(slug, {
      sort: search.zoneSort,
      page: search.zonesPage,
      pageSize: search.zonesPageSize,
    }),
  );

  useEffect(() => {
    if (search.zone || zones.data.items.length === 0) {
      return;
    }
    startTransition(() => {
      void navigate({
        to: "/engagements/$slug/zones",
        params: { slug },
        search: () =>
          zoneSearchState(search, {
            zone: zones.data.items[0]?.id || "",
          }),
        replace: true,
      });
    });
  }, [navigate, search.zone, slug, zones.data.items]);

  const hosts = useSuspenseQuery(
    engagementHostsQuery(slug, {
      zone: search.zone,
      sort: search.hostSort,
      page: search.hostsPage,
      pageSize: search.hostsPageSize,
    }),
  );

  const selectedZone = zones.data.items.find((zone) => zone.id === search.zone);

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          {
            label: "Zones",
            value: zones.data.pagination.total.toString(),
            detail: "Derived network and scope groupings",
          },
          {
            label: "Selected",
            value: selectedZone?.name || "All",
            detail: selectedZone ? `${selectedZone.kind} scope` : "Choose a zone to focus triage",
          },
          {
            label: "Hosts in slice",
            value: hosts.data.pagination.total.toString(),
            detail: "Host inventory under the current zone filter",
          },
        ]}
      />

      <div className="cc-grid cc-grid--sidebar">
        <Panel title="Zone navigator" meta={`${zones.data.pagination.total} zones`}>
          <section className="cc-toolbar cc-toolbar--compact">
            <label className="cc-field">
              <span>Order</span>
              <select
                value={search.zoneSort}
                onChange={(event) => {
                  const zoneSort = event.target.value;
                  startTransition(() => {
                    void navigate({
                      to: "/engagements/$slug/zones",
                      params: { slug },
                      search: () =>
                        zoneSearchState(search, {
                          zoneSort,
                          zonesPage: 1,
                        }),
                      replace: true,
                    });
                  });
                }}
              >
                <option value="hosts">Largest first</option>
                <option value="name">Name</option>
              </select>
            </label>
          </section>
          <VirtualTable
            columns={[
              { key: "zone", label: "Zone", width: "1.25fr" },
              { key: "kind", label: "Kind", width: "0.7fr" },
              { key: "hosts", label: "Hosts", width: "0.55fr", align: "right" },
            ]}
            items={zones.data.items}
            getKey={(zone) => zone.id}
            empty="No zones derived yet."
            pagination={zones.data.pagination}
            onPageChange={(page) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/zones",
                  params: { slug },
                  search: () => zoneSearchState(search, { zonesPage: page }),
                  replace: true,
                });
              });
            }}
            onPageSizeChange={(pageSize) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/zones",
                  params: { slug },
                  search: () => zoneSearchState(search, { zonesPage: 1, zonesPageSize: pageSize }),
                  replace: true,
                });
              });
            }}
            renderRow={(zone) => [
              <button
                className={`cc-table-link ${search.zone === zone.id ? "is-active" : ""}`}
                key={`${zone.id}-select`}
                onClick={() => {
                  startTransition(() => {
                    void navigate({
                      to: "/engagements/$slug/zones",
                      params: { slug },
                      search: () =>
                        zoneSearchState(search, {
                          zone: zone.id,
                          hostsPage: 1,
                        }),
                      replace: true,
                    });
                  });
                }}
                type="button"
              >
                <strong>{zone.name}</strong>
                <small>{zone.scope || "Derived grouping"}</small>
              </button>,
              <span key={`${zone.id}-kind`} className="cc-cell-meta">
                {zone.kind}
              </span>,
              <strong key={`${zone.id}-hosts`} className="cc-cell-strong cc-cell-strong--right">
                {zone.hostCount}
              </strong>,
            ]}
          />
        </Panel>

        <Panel title="Zone hosts" meta={selectedZone ? selectedZone.name : "All hosts"}>
          <section className="cc-toolbar cc-toolbar--compact">
            <label className="cc-field">
              <span>Order</span>
              <select
                value={search.hostSort}
                onChange={(event) => {
                  const hostSort = event.target.value;
                  startTransition(() => {
                    void navigate({
                      to: "/engagements/$slug/zones",
                      params: { slug },
                      search: () =>
                        zoneSearchState(search, {
                          hostSort,
                          hostsPage: 1,
                        }),
                      replace: true,
                    });
                  });
                }}
              >
                <option value="findings">Findings</option>
                <option value="ports">Ports</option>
                <option value="critical">Critical</option>
                <option value="sources">Sources</option>
                <option value="name">Name</option>
              </select>
            </label>
          </section>
          <HostInventoryTable
            hosts={hosts.data.items}
            empty="No hosts match the current zone slice."
            pagination={hosts.data.pagination}
            onPageChange={(page) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/zones",
                  params: { slug },
                  search: () => zoneSearchState(search, { hostsPage: page }),
                  replace: true,
                });
              });
            }}
            onPageSizeChange={(pageSize) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/zones",
                  params: { slug },
                  search: () => zoneSearchState(search, { hostsPage: 1, hostsPageSize: pageSize }),
                  replace: true,
                });
              });
            }}
          />
        </Panel>
      </div>
    </div>
  );
}

function EngagementHostsPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementHostsRoute.useSearch();
  const navigate = useNavigate();
  const zones = useSuspenseQuery(engagementZonesQuery(slug, { sort: "name", pageSize: 100 }));
  const [queryInput, setQueryInput] = useState(search.query);
  const deferredQuery = useDeferredValue(queryInput);

  useEffect(() => {
    setQueryInput(search.query);
  }, [search.query]);

  useEffect(() => {
    if (deferredQuery === search.query) {
      return;
    }
    startTransition(() => {
      void navigate({
        to: "/engagements/$slug/hosts",
        params: { slug },
        search: () => hostsSearchState(search, { query: deferredQuery, page: 1 }),
        replace: true,
      });
    });
  }, [deferredQuery, navigate, search.query, slug]);

  const hosts = useSuspenseQuery(
    engagementHostsQuery(slug, {
      query: search.query,
      zone: search.zone,
      sort: search.sort,
      page: search.page,
      pageSize: search.pageSize,
    }),
  );

  const selectedZone = useMemo(
    () => zones.data.items.find((zone) => zone.id === search.zone),
    [search.zone, zones.data.items],
  );

  const sliceStats = useMemo(() => {
    const criticalHosts = hosts.data.items.filter((host) => host.critical > 0).length;
    const exposedHosts = hosts.data.items.filter((host) => host.exposureTone === "risk" || host.exposureTone === "warning").length;
    const findings = hosts.data.items.reduce((total, host) => total + host.findings, 0);
    return [
      { label: "Slice hosts", value: hosts.data.pagination.total.toString(), detail: "Hosts matching current filters" },
      { label: "Critical hosts", value: criticalHosts.toString(), detail: "Hosts with critical findings on this page" },
      { label: "Exposed", value: exposedHosts.toString(), detail: "High- or medium-exposure hosts in the current page" },
      { label: "Findings", value: findings.toString(), detail: "Grouped finding hits across the visible rows" },
    ];
  }, [hosts.data.items, hosts.data.pagination.total]);

  return (
    <div className="cc-stack">
      <StatGrid items={sliceStats} />

      <section className="cc-toolbar">
        <label className="cc-field">
          <span>Search</span>
          <input
            placeholder="IP, hostname, or OS"
            value={queryInput}
            onChange={(event) => setQueryInput(event.target.value)}
          />
        </label>
        <label className="cc-field">
          <span>Zone</span>
          <select
            value={search.zone}
            onChange={(event) => {
              const zone = event.target.value;
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/hosts",
                  params: { slug },
                  search: () => hostsSearchState(search, { zone, page: 1 }),
                  replace: true,
                });
              });
            }}
          >
            <option value="">All zones</option>
            {zones.data.items.map((zone) => (
              <option key={zone.id} value={zone.id}>
                {zone.name}
              </option>
            ))}
          </select>
        </label>
        <label className="cc-field">
          <span>Order</span>
          <select
            value={search.sort}
            onChange={(event) => {
              const sort = event.target.value;
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/hosts",
                  params: { slug },
                  search: () => hostsSearchState(search, { sort, page: 1 }),
                  replace: true,
                });
              });
            }}
          >
            <option value="findings">Findings</option>
            <option value="ports">Ports</option>
            <option value="critical">Critical</option>
            <option value="sources">Sources</option>
            <option value="name">Name</option>
          </select>
        </label>
      </section>

      <div className="cc-grid cc-grid--sidebar">
        <Panel
          title="Zone navigator"
          meta={selectedZone ? `${selectedZone.name} selected` : `${zones.data.pagination.total} zones`}
        >
          <List
            items={zones.data.items.map((zone) => ({
              key: zone.id,
              label: zone.name,
              detail: `${zone.kind} · ${zone.hostCount} hosts`,
              active: search.zone === zone.id,
              href: `/app/engagements/${slug}/hosts?zone=${encodeURIComponent(zone.id)}`,
            }))}
            empty="No zones derived yet."
          />
        </Panel>

        <Panel title="Host inventory" meta={`${hosts.data.pagination.total} hosts`}>
          <HostInventoryTable
            hosts={hosts.data.items}
            empty="No hosts match the current slice."
            pagination={hosts.data.pagination}
            onPageChange={(page) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/hosts",
                  params: { slug },
                  search: () => hostsSearchState(search, { page }),
                  replace: true,
                });
              });
            }}
            onPageSizeChange={(pageSize) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/hosts",
                  params: { slug },
                  search: () => hostsSearchState(search, { page: 1, pageSize }),
                  replace: true,
                });
              });
            }}
          />
        </Panel>
      </div>
    </div>
  );
}

function EngagementHostDetailPage() {
  const { slug, ip } = engagementHostDetailRoute.useParams();
  const detail = useSuspenseQuery(engagementHostDetailQuery(slug, ip));
  const host = detail.data.host;

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          { label: "Host", value: host.summary.displayName, detail: host.summary.ip },
          { label: "Open ports", value: host.summary.openPortCount.toString(), detail: `${host.closedPortCount} closed observed` },
          { label: "Findings", value: host.summary.findings.total.toString(), detail: `${host.summary.findings.critical} critical · ${host.summary.findings.high} high` },
          { label: "Coverage", value: host.summary.coverage.label, detail: host.summary.coverage.detail },
        ]}
      />

      <div className="cc-grid cc-grid--two">
        <Panel title="Host posture" meta={host.status || "Observed"}>
          <div className="cc-detail-grid">
            <InfoPair label="IP" value={host.summary.ip} />
            <InfoPair label="Hostnames" value={host.summary.hostnames.join(", ") || "No resolved names"} />
            <InfoPair label="Operating system" value={host.summary.os || "Unknown fingerprint"} />
            <InfoPair label="Exposure" value={`${host.summary.exposure.label} · ${host.summary.exposure.detail}`} />
            <InfoPair label="Source scans" value={host.sourceScans.join(", ") || "No provenance"} />
            <InfoPair label="HTTP targets" value={host.summary.httpTargets.toString()} />
          </div>
        </Panel>

        <Panel title="Related zones" meta={`${detail.data.relatedZones.length} memberships`}>
          <List
            items={detail.data.relatedZones.map((zone) => ({
              key: zone.id,
              label: zone.name,
              detail: `${zone.kind} · ${zone.hostCount} hosts`,
              href: `/app/engagements/${slug}/zones?zone=${encodeURIComponent(zone.id)}`,
            }))}
            empty="This host is not attached to any zone."
          />
        </Panel>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Port inventory" meta={`${host.ports.length} observed ports`}>
          <HostPortInventoryTable ports={host.ports} />
        </Panel>

        <Panel title="Grouped findings" meta={`${detail.data.findings.length} definitions`}>
          <FindingGroupTable
            findings={detail.data.findings}
            slug={slug}
            empty="No grouped findings tied to this host."
          />
        </Panel>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Recent runs" meta={`${detail.data.recentRuns.length} related jobs`}>
          <RunList runs={detail.data.recentRuns} empty="No recent jobs for this host." />
        </Panel>

        <Panel title="Recommendations" meta={`${host.recommendations.length} suggested actions`}>
          <List
            items={host.recommendations.map((item, index) => ({
              key: `${item.title}-${index}`,
              label: item.title,
              detail: `${item.detail} · ${item.evidence}`,
            }))}
            empty="No recommendations generated."
          />
        </Panel>
      </div>
    </div>
  );
}

function EngagementPortsPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementPortsRoute.useSearch();
  const navigate = useNavigate();
  const [queryInput, setQueryInput] = useState(search.query);
  const deferredQuery = useDeferredValue(queryInput);

  useEffect(() => {
    setQueryInput(search.query);
  }, [search.query]);

  useEffect(() => {
    if (deferredQuery === search.query) {
      return;
    }
    startTransition(() => {
      void navigate({
        to: "/engagements/$slug/ports",
        params: { slug },
        search: () => portsSearchState(search, { query: deferredQuery, page: 1 }),
        replace: true,
      });
    });
  }, [deferredQuery, navigate, search.query, slug]);

  const ports = useSuspenseQuery(
    engagementPortsQuery(slug, {
      query: search.query,
      sort: search.sort,
      page: search.page,
      pageSize: search.pageSize,
    }),
  );

  const sliceStats = useMemo(() => {
    const findingHits = ports.data.items.reduce((total, item) => total + item.findings, 0);
    const hostSurface = ports.data.items.reduce((total, item) => total + item.hosts, 0);
    return [
      { label: "Ports", value: ports.data.pagination.total.toString(), detail: "Distinct protocol and port combinations" },
      { label: "Host memberships", value: hostSurface.toString(), detail: "Hosts represented across the current page" },
      { label: "Finding hits", value: findingHits.toString(), detail: "Finding counts across the visible service rows" },
    ];
  }, [ports.data.items, ports.data.pagination.total]);

  return (
    <div className="cc-stack">
      <StatGrid items={sliceStats} />

      <section className="cc-toolbar">
        <label className="cc-field">
          <span>Search</span>
          <input
            placeholder="Port label or service"
            value={queryInput}
            onChange={(event) => setQueryInput(event.target.value)}
          />
        </label>
        <label className="cc-field">
          <span>Order</span>
          <select
            value={search.sort}
            onChange={(event) => {
              const sort = event.target.value;
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/ports",
                  params: { slug },
                  search: () => portsSearchState(search, { sort, page: 1 }),
                  replace: true,
                });
              });
            }}
          >
            <option value="hosts">Hosts</option>
            <option value="service">Service</option>
            <option value="port">Port</option>
          </select>
        </label>
      </section>

      <Panel title="Port inventory" meta={`${ports.data.pagination.total} rows`}>
        <PortInventoryTable
          ports={ports.data.items}
          empty="No ports match the current filters."
          pagination={ports.data.pagination}
          onPageChange={(page) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/ports",
                params: { slug },
                search: () => portsSearchState(search, { page }),
                replace: true,
              });
            });
          }}
          onPageSizeChange={(pageSize) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/ports",
                params: { slug },
                search: () => portsSearchState(search, { page: 1, pageSize }),
                replace: true,
              });
            });
          }}
        />
      </Panel>
    </div>
  );
}

function EngagementPortDetailPage() {
  const { slug, protocol, port } = engagementPortDetailRoute.useParams();
  const detail = useSuspenseQuery(engagementPortDetailQuery(slug, protocol, port));

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          { label: "Port", value: detail.data.port.label, detail: detail.data.port.service || "Unknown service" },
          { label: "Hosts", value: detail.data.port.hostCount.toString(), detail: "Hosts exposing this port" },
          { label: "Findings", value: detail.data.port.findingTotals.total.toString(), detail: `${detail.data.port.findingTotals.critical} critical · ${detail.data.port.findingTotals.high} high` },
        ]}
      />

      <div className="cc-grid cc-grid--two">
        <Panel title="Affected hosts" meta={`${detail.data.port.hosts.length} hosts`}>
          <VirtualTable
            columns={[
              { key: "host", label: "Host", width: "1.2fr" },
              { key: "service", label: "Service", width: "0.9fr" },
              { key: "version", label: "Version", width: "0.9fr" },
              { key: "findings", label: "Findings", width: "0.55fr", align: "right" },
            ]}
            items={detail.data.port.hosts}
            getKey={(host) => `${host.ip}-${host.service}`}
            empty="No hosts available for this port."
            renderRow={(host) => [
              <a className="cc-table-link" href={`/app/engagements/${slug}/hosts/${encodeURIComponent(host.ip)}`} key={`${host.ip}-host`}>
                <strong>{host.displayName}</strong>
                <small>{host.ip} · {host.os || "Unknown OS"}</small>
              </a>,
              <span key={`${host.ip}-service`} className="cc-cell-meta">
                {host.service || "Unknown"}
              </span>,
              <span key={`${host.ip}-version`} className="cc-cell-meta">
                {[host.product, host.version].filter(Boolean).join(" ") || "No version data"}
              </span>,
              <strong key={`${host.ip}-findings`} className="cc-cell-strong cc-cell-strong--right">
                {host.findings}
              </strong>,
            ]}
          />
        </Panel>

        <Panel title="Related findings" meta={`${detail.data.port.relatedFindings.length} grouped definitions`}>
          <FindingGroupTable
            findings={detail.data.port.relatedFindings}
            slug={slug}
            empty="No grouped findings tied to this port."
          />
        </Panel>
      </div>

      <Panel title="Recent runs" meta={`${detail.data.recentRuns.length} jobs`}>
        <RunList runs={detail.data.recentRuns} empty="No related runs recorded." />
      </Panel>
    </div>
  );
}

function EngagementFindingsPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementFindingsRoute.useSearch();
  const navigate = useNavigate();
  const [queryInput, setQueryInput] = useState(search.query);
  const deferredQuery = useDeferredValue(queryInput);

  useEffect(() => {
    setQueryInput(search.query);
  }, [search.query]);

  useEffect(() => {
    if (deferredQuery === search.query) {
      return;
    }
    startTransition(() => {
      void navigate({
        to: "/engagements/$slug/findings",
        params: { slug },
        search: () => findingsSearchState(search, { query: deferredQuery, page: 1 }),
        replace: true,
      });
    });
  }, [deferredQuery, navigate, search.query, slug]);

  const findings = useSuspenseQuery(
    engagementFindingsQuery(slug, {
      query: search.query,
      severity: search.severity,
      sort: search.sort,
      page: search.page,
      pageSize: search.pageSize,
    }),
  );

  const sliceStats = useMemo(() => {
    const critical = findings.data.items.filter((item) => item.severity === "critical").length;
    const high = findings.data.items.filter((item) => item.severity === "high").length;
    const occurrences = findings.data.items.reduce((total, item) => total + item.occurrences, 0);
    return [
      { label: "Definitions", value: findings.data.pagination.total.toString(), detail: "Grouped finding definitions in the current slice" },
      { label: "Occurrences", value: occurrences.toString(), detail: "Occurrence count across the visible rows" },
      { label: "Critical/high", value: `${critical + high}`, detail: `${critical} critical · ${high} high on this page` },
    ];
  }, [findings.data.items, findings.data.pagination.total]);

  return (
    <div className="cc-stack">
      <StatGrid items={sliceStats} />

      <section className="cc-toolbar">
        <label className="cc-field">
          <span>Search</span>
          <input
            placeholder="Finding name, source, or template"
            value={queryInput}
            onChange={(event) => setQueryInput(event.target.value)}
          />
        </label>
        <label className="cc-field">
          <span>Severity</span>
          <select
            value={search.severity}
            onChange={(event) => {
              const severity = event.target.value;
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/findings",
                  params: { slug },
                  search: () => findingsSearchState(search, { severity, page: 1 }),
                  replace: true,
                });
              });
            }}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label className="cc-field">
          <span>Order</span>
          <select
            value={search.sort}
            onChange={(event) => {
              const sort = event.target.value;
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/findings",
                  params: { slug },
                  search: () => findingsSearchState(search, { sort, page: 1 }),
                  replace: true,
                });
              });
            }}
          >
            <option value="severity">Severity</option>
            <option value="hosts">Hosts</option>
            <option value="recent">Recent</option>
            <option value="name">Name</option>
          </select>
        </label>
      </section>

      <Panel title="Finding inventory" meta={`${findings.data.pagination.total} rows`}>
        <FindingInventoryTable
          findings={findings.data.items}
          slug={slug}
          empty="No findings match the current filters."
          pagination={findings.data.pagination}
          onPageChange={(page) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/findings",
                params: { slug },
                search: () => findingsSearchState(search, { page }),
                replace: true,
              });
            });
          }}
          onPageSizeChange={(pageSize) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/findings",
                params: { slug },
                search: () => findingsSearchState(search, { page: 1, pageSize }),
                replace: true,
              });
            });
          }}
        />
      </Panel>
    </div>
  );
}

function EngagementFindingDetailPage() {
  const { slug, groupID } = engagementFindingDetailRoute.useParams();
  const detail = useSuspenseQuery(engagementFindingDetailQuery(slug, groupID));

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          { label: "Finding", value: detail.data.finding.group.name, detail: detail.data.finding.group.templateId || detail.data.finding.group.source },
          { label: "Severity", value: detail.data.finding.group.severity, detail: `${detail.data.finding.group.occurrences} occurrences` },
          { label: "Hosts", value: detail.data.finding.group.hosts.toString(), detail: `${detail.data.finding.group.ports} distinct ports` },
        ]}
      />

      <div className="cc-grid cc-grid--two">
        <Panel title="Definition" meta={detail.data.finding.group.source}>
          <div className="cc-detail-grid">
            <InfoPair label="Template" value={detail.data.finding.group.templateId || "No template ID"} />
            <InfoPair label="First seen" value={detail.data.finding.group.firstSeen || "Unknown"} />
            <InfoPair label="Last seen" value={detail.data.finding.group.lastSeen || "Unknown"} />
            <InfoPair label="Tags" value={detail.data.finding.tags.join(", ") || "No tags"} />
            <InfoPair label="Description" value={detail.data.finding.description || "No long-form description"} />
          </div>
        </Panel>

        <Panel title="Recent runs" meta={`${detail.data.recentRuns.length} jobs`}>
          <RunList runs={detail.data.recentRuns} empty="No related runs recorded." />
        </Panel>
      </div>

      <Panel title="Occurrences" meta={`${detail.data.finding.occurrences.length} hits`}>
        <VirtualTable
          columns={[
            { key: "host", label: "Host", width: "1fr" },
            { key: "target", label: "Target", width: "1.1fr" },
            { key: "port", label: "Port", width: "0.5fr" },
            { key: "scans", label: "Scans", width: "1fr" },
          ]}
          items={detail.data.finding.occurrences}
          getKey={(occurrence) => `${occurrence.hostIp}-${occurrence.target}-${occurrence.matchedAt}`}
          empty="No finding occurrences available."
          renderRow={(occurrence) => [
            <a className="cc-table-link" href={`/app/engagements/${slug}/hosts/${encodeURIComponent(occurrence.hostIp)}`} key={`${occurrence.hostIp}-host`}>
              <strong>{occurrence.hostLabel}</strong>
              <small>{occurrence.hostIp}</small>
            </a>,
            <span key={`${occurrence.hostIp}-target`} className="cc-cell-meta">
              {occurrence.target || "No target"}
            </span>,
            <span key={`${occurrence.hostIp}-port`} className="cc-cell-meta">
              {occurrence.port || "0"}
            </span>,
            <span key={`${occurrence.hostIp}-scans`} className="cc-cell-meta">
              {occurrence.scans.join(", ") || "No scan provenance"}
            </span>,
          ]}
        />
      </Panel>
    </div>
  );
}

function EngagementSourcesPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementSourcesRoute.useSearch();
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const sources = useSuspenseQuery(
    engagementSourcesQuery(slug, {
      page: search.primaryPage,
      pageSize: search.primaryPageSize,
    }),
  );
  const runs = useSuspenseQuery(
    engagementRunsQuery(slug, {
      page: search.secondaryPage,
      pageSize: search.secondaryPageSize,
    }),
  );
  const navigate = useNavigate();
  const mutation = useMutation({
    mutationFn: () => {
      if (!file) {
        throw new Error("Choose a file before importing.");
      }
      return importEngagementSource(slug, file);
    },
    onSuccess: async () => {
      setFile(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["engagement-sources", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagement-runs", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagements"] }),
        queryClient.invalidateQueries({ queryKey: ["engagement-summary", slug] }),
      ]);
    },
  });

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          { label: "Sources", value: sources.data.pagination.total.toString(), detail: "Imported source packages in this engagement" },
          { label: "Runs", value: runs.data.pagination.total.toString(), detail: "Execution history and connector activity" },
        ]}
      />

      <div className="cc-grid cc-grid--two">
        <Panel title="Import source material" meta="Nmap, Nessus, Masscan, ZMap, Naabu and related reports">
          <form
            className="cc-form"
            onSubmit={(event) => {
              event.preventDefault();
              mutation.mutate();
            }}
          >
            <label className="cc-field">
              <span>Scan file</span>
              <input
                type="file"
                onChange={(event) => {
                  setFile(event.target.files?.[0] || null);
                }}
              />
            </label>
            <button className="cc-button cc-button--primary" disabled={mutation.isPending || !file} type="submit">
              {mutation.isPending ? "Importing" : "Import into engagement"}
            </button>
          </form>
          {mutation.isError ? (
            <InlineState tone="danger" title="Import failed" body={mutation.error.message} />
          ) : null}
        </Panel>

        <Panel title="Recent execution" meta={`${runs.data.pagination.total} runs`}>
          <RunList runs={runs.data.items} empty="No runs recorded for this engagement." />
        </Panel>
      </div>

      <Panel title="Source catalog" meta={`${sources.data.pagination.total} sources`}>
        <VirtualTable
          columns={[
            { key: "source", label: "Source", width: "1.2fr" },
            { key: "scanner", label: "Scanner", width: "0.7fr" },
            { key: "hosts", label: "Hosts", width: "0.5fr", align: "right" },
            { key: "imported", label: "Imported", width: "0.8fr" },
          ]}
          items={sources.data.items}
          getKey={(source) => source.id}
          empty="No sources imported yet."
          pagination={sources.data.pagination}
          onPageChange={(page) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/sources",
                params: { slug },
                search: () => dualListSearchState(search, { primaryPage: page }),
                replace: true,
              });
            });
          }}
          onPageSizeChange={(pageSize) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/sources",
                params: { slug },
                search: () => dualListSearchState(search, { primaryPage: 1, primaryPageSize: pageSize }),
                replace: true,
              });
            });
          }}
          renderRow={(source) => [
            <div key={`${source.id}-name`}>
              <strong>{source.name}</strong>
              <small>{source.kind}</small>
            </div>,
            <span key={`${source.id}-scanner`} className="cc-cell-meta">
              {source.scanner || "Unknown"}
            </span>,
            <strong key={`${source.id}-hosts`} className="cc-cell-strong cc-cell-strong--right">
              {source.liveHosts}
            </strong>,
            <span key={`${source.id}-imported`} className="cc-cell-meta">
              {source.importedAt}
            </span>,
          ]}
        />
      </Panel>
    </div>
  );
}

type PolicyStepDraft = {
  label: string;
  trigger: string;
  pluginId: string;
  stage: string;
  targetSource: string;
  matchKinds: string;
  whenPlugin: string;
  whenProfile: string;
  summary: string;
  profile: string;
  ports: string;
  topPorts: string;
  enabled: boolean;
};

function emptyPolicyStepDraft(): PolicyStepDraft {
  return {
    label: "",
    trigger: "kickoff",
    pluginId: "nmap-enrich",
    stage: "discovery",
    targetSource: "chunk-values",
    matchKinds: "ip,cidr,hostname",
    whenPlugin: "",
    whenProfile: "",
    summary: "",
    profile: "",
    ports: "",
    topPorts: "",
    enabled: true,
  };
}

function policyStepDraftFromStep(step: OrchestrationStep | null | undefined): PolicyStepDraft {
  if (!step) {
    return emptyPolicyStepDraft();
  }
  return {
    label: step.label,
    trigger: step.trigger,
    pluginId: step.pluginId,
    stage: step.stage,
    targetSource: step.targetSource,
    matchKinds: step.matchKinds.join(","),
    whenPlugin: step.whenPlugin,
    whenProfile: step.whenProfile,
    summary: step.summary,
    profile: step.options.profile || "",
    ports: step.options.ports || "",
    topPorts: step.options.top_ports || "",
    enabled: step.enabled,
  };
}

function EngagementCampaignsPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementCampaignsRoute.useSearch();
  const queryClient = useQueryClient();
  const [pluginId, setPluginId] = useState("");
  const [targetMode, setTargetMode] = useState("profile");
  const [targets, setTargets] = useState("");
  const [profileScope, setProfileScope] = useState("all-hosts");
  const [policyName, setPolicyName] = useState("");
  const [policyDescription, setPolicyDescription] = useState("");
  const [selectedStepId, setSelectedStepId] = useState("");
  const [newStepDraft, setNewStepDraft] = useState<PolicyStepDraft>(emptyPolicyStepDraft);
  const [stepDraft, setStepDraft] = useState<PolicyStepDraft>(emptyPolicyStepDraft);
  const campaigns = useSuspenseQuery(
    engagementCampaignsQuery(slug, {
      page: search.page,
      pageSize: search.pageSize,
    }),
  );
  const navigate = useNavigate();

  useEffect(() => {
    if (pluginId || campaigns.data.tools.items.length === 0) {
      return;
    }
    setPluginId(campaigns.data.tools.items[0]?.id || "");
  }, [campaigns.data.tools.items, pluginId]);

  const mutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => runEngagementCampaignAction(slug, payload),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["engagement-campaigns", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagement-runs", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagement-recommendations", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagement-summary", slug] }),
      ]);
    },
  });

  const selectedPolicy = useMemo<OrchestrationPolicy | null>(() => {
    const explicit = campaigns.data.policies.find((policy) => policy.id === search.policyId);
    if (explicit) {
      return explicit;
    }
    return campaigns.data.policies.find((policy) => policy.active) || campaigns.data.policies[0] || null;
  }, [campaigns.data.policies, search.policyId]);

  const selectedStep = useMemo<OrchestrationStep | null>(() => {
    if (!selectedPolicy) {
      return null;
    }
    return selectedPolicy.steps.find((step) => step.id === selectedStepId) || selectedPolicy.steps[0] || null;
  }, [selectedPolicy, selectedStepId]);

  useEffect(() => {
    if (!selectedPolicy) {
      setPolicyName("");
      setPolicyDescription("");
      setSelectedStepId("");
      return;
    }
    setPolicyName(selectedPolicy.name);
    setPolicyDescription(selectedPolicy.description);
    if (!selectedStepId || !selectedPolicy.steps.some((step) => step.id === selectedStepId)) {
      setSelectedStepId(selectedPolicy.steps[0]?.id || "");
    }
  }, [selectedPolicy, selectedStepId]);

  useEffect(() => {
    setStepDraft(policyStepDraftFromStep(selectedStep));
  }, [selectedStep]);

  return (
    <div className="cc-stack">
      <StatGrid
        items={campaigns.data.stats.map((item) => ({
          label: item.label,
          value: item.value,
          detail: item.detail,
        }))}
      />

      <div className="cc-grid cc-grid--two">
        <Panel title="Quick launch" meta={`${campaigns.data.runProfiles.length} profile shortcuts`}>
          <div className="cc-chip-grid">
            {campaigns.data.runProfiles.map((profile) => (
              <button
                className="cc-button"
                disabled={mutation.isPending}
                key={`${profile.pluginId}-${profile.profileScope}`}
                onClick={() =>
                  mutation.mutate({
                    action: "queue_run",
                    pluginId: profile.pluginId,
                    targetMode: "profile",
                    profileScope: profile.profileScope,
                    profile: profile.profile,
                    severity: profile.severity,
                    crawlDepth: profile.crawlDepth,
                  })
                }
                type="button"
              >
                {profile.label}
              </button>
            ))}
          </div>
        </Panel>

        <Panel title="Manual run" meta="Queue any registered managed command or connector">
          <form
            className="cc-form"
            onSubmit={(event) => {
              event.preventDefault();
              mutation.mutate({
                action: "queue_run",
                pluginId,
                targetMode,
                targets: targets
                  .split("\n")
                  .map((value) => value.trim())
                  .filter(Boolean),
                profileScope,
              });
            }}
          >
            <label className="cc-field">
              <span>Tool</span>
              <select value={pluginId} onChange={(event) => setPluginId(event.target.value)}>
                {campaigns.data.tools.items.map((tool) => (
                  <option key={tool.id} value={tool.id}>
                    {tool.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="cc-field">
              <span>Target mode</span>
              <select value={targetMode} onChange={(event) => setTargetMode(event.target.value)}>
                <option value="profile">Profile</option>
                <option value="engagement">Entire engagement</option>
                <option value="manual">Manual targets</option>
              </select>
            </label>
            <label className="cc-field">
              <span>Profile scope</span>
              <select value={profileScope} onChange={(event) => setProfileScope(event.target.value)}>
                <option value="all-hosts">All hosts</option>
                <option value="high-exposure">High exposure</option>
                <option value="web">Web surfaces</option>
                <option value="coverage-gap">Coverage gap</option>
              </select>
            </label>
            {targetMode === "manual" ? (
              <label className="cc-field">
                <span>Targets</span>
                <textarea
                  value={targets}
                  onChange={(event) => setTargets(event.target.value)}
                  placeholder="One IP, CIDR, hostname, or URL per line"
                />
              </label>
            ) : null}
            <button className="cc-button cc-button--primary" disabled={mutation.isPending || !pluginId} type="submit">
              {mutation.isPending ? "Queueing" : "Queue run"}
            </button>
          </form>
          {mutation.isError ? (
            <InlineState tone="danger" title="Run request failed" body={mutation.error.message} />
          ) : null}
        </Panel>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Policies" meta={`${campaigns.data.policies.length} orchestration policies`}>
          <div className="cc-stack">
            <List
              items={campaigns.data.policies.map((policy) => ({
                key: policy.id,
                label: policy.name,
                detail: `${policy.steps.length} steps · ${policy.active ? "active" : "inactive"}`,
                active: selectedPolicy?.id === policy.id,
                onClick: () => {
                  startTransition(() => {
                    void navigate({
                      to: "/engagements/$slug/campaigns",
                      params: { slug },
                      search: () => campaignsSearchState(search, { policyId: policy.id }),
                      replace: true,
                    });
                  });
                },
              }))}
              empty="No orchestration policies defined."
            />

            <form
              className="cc-form"
              onSubmit={(event) => {
                event.preventDefault();
                mutation.mutate(
                  {
                    action: "create_policy",
                    policyName,
                    policyDescription,
                  },
                  {
                    onSuccess: async () => {
                      startTransition(() => {
                        void navigate({
                          to: "/engagements/$slug/campaigns",
                          params: { slug },
                          search: () => campaignsSearchState(search, { policyId: "", page: 1 }),
                          replace: true,
                        });
                      });
                    },
                  },
                );
              }}
            >
              <label className="cc-field">
                <span>Policy name</span>
                <input value={policyName} onChange={(event) => setPolicyName(event.target.value)} />
              </label>
              <label className="cc-field">
                <span>Description</span>
                <textarea
                  rows={3}
                  value={policyDescription}
                  onChange={(event) => setPolicyDescription(event.target.value)}
                />
              </label>
              <div className="cc-button-row">
                <button className="cc-button cc-button--primary" disabled={mutation.isPending || !policyName.trim()} type="submit">
                  Create policy
                </button>
                <button className="cc-button" disabled={mutation.isPending || !selectedPolicy} type="button" onClick={() => selectedPolicy && mutation.mutate({ action: "update_policy", policyId: selectedPolicy.id, policyName, policyDescription })}>
                  Save policy
                </button>
                <button
                  className="cc-button"
                  disabled={mutation.isPending || !selectedPolicy}
                  type="button"
                  onClick={() => selectedPolicy && mutation.mutate({ action: "activate_policy", policyId: selectedPolicy.id })}
                >
                  Activate
                </button>
                <button
                  className="cc-button"
                  disabled={mutation.isPending || !selectedPolicy || campaigns.data.policies.length <= 1}
                  type="button"
                  onClick={() =>
                    selectedPolicy &&
                    mutation.mutate(
                      {
                        action: "delete_policy",
                        policyId: selectedPolicy.id,
                      },
                      {
                        onSuccess: async () => {
                          startTransition(() => {
                            void navigate({
                              to: "/engagements/$slug/campaigns",
                              params: { slug },
                              search: () => campaignsSearchState(search, { policyId: "", page: 1 }),
                              replace: true,
                            });
                          });
                        },
                      },
                    )
                  }
                >
                  Delete
                </button>
              </div>
            </form>
          </div>
        </Panel>

        <Panel title="Tool readiness" meta={`${campaigns.data.readiness.length} readiness groups`}>
          <List
            items={campaigns.data.readiness.map((group) => ({
              key: group.label,
              label: `${group.label} · ${group.ready}/${group.total}`,
              detail: group.detail,
            }))}
            empty="No readiness data available."
          />
        </Panel>
      </div>

      <div className="cc-grid cc-grid--flow">
        <Panel title="Policy graph" meta={selectedPolicy ? `${selectedPolicy.steps.length} steps in ${selectedPolicy.name}` : "No policy selected"}>
          {selectedPolicy ? (
            <Suspense fallback={<InlineState tone="muted" title="Loading policy graph" body="Preparing the orchestration canvas." />}>
              <PolicyFlowCanvas
                onReorder={(stepOrder) =>
                  mutation.mutate({
                    action: "reorder_policy",
                    policyId: selectedPolicy.id,
                    stepOrder,
                  })
                }
                onSelectStep={setSelectedStepId}
                policy={selectedPolicy}
                selectedStepId={selectedStep?.id || ""}
              />
            </Suspense>
          ) : (
            <InlineState tone="muted" title="No policy selected" body="Create or choose an orchestration policy to start building flow steps." />
          )}
        </Panel>

        <div className="cc-stack">
          <Panel title="Selected step" meta={selectedStep ? selectedStep.label : "Choose a step node"}>
            {selectedPolicy && selectedStep ? (
              <form
                className="cc-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  mutation.mutate({
                    action: "update_policy_step",
                    policyId: selectedPolicy.id,
                    stepId: selectedStep.id,
                    label: stepDraft.label,
                    trigger: stepDraft.trigger,
                    pluginId: stepDraft.pluginId,
                    stage: stepDraft.stage,
                    targetSource: stepDraft.targetSource,
                    matchKinds: stepDraft.matchKinds.split(",").map((value) => value.trim()).filter(Boolean),
                    whenPlugin: stepDraft.whenPlugin,
                    whenProfile: stepDraft.whenProfile,
                    summary: stepDraft.summary,
                    profile: stepDraft.profile,
                    ports: stepDraft.ports,
                    topPorts: stepDraft.topPorts,
                    enabled: stepDraft.enabled,
                  });
                }}
              >
                <label className="cc-field">
                  <span>Label</span>
                  <input value={stepDraft.label} onChange={(event) => setStepDraft((current) => ({ ...current, label: event.target.value }))} />
                </label>
                <div className="cc-grid cc-grid--two">
                  <label className="cc-field">
                    <span>Tool</span>
                    <select value={stepDraft.pluginId} onChange={(event) => setStepDraft((current) => ({ ...current, pluginId: event.target.value }))}>
                      {campaigns.data.tools.items.map((tool) => (
                        <option key={tool.id} value={tool.id}>
                          {tool.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="cc-field">
                    <span>Stage</span>
                    <input value={stepDraft.stage} onChange={(event) => setStepDraft((current) => ({ ...current, stage: event.target.value }))} />
                  </label>
                </div>
                <div className="cc-grid cc-grid--two">
                  <label className="cc-field">
                    <span>Trigger</span>
                    <select value={stepDraft.trigger} onChange={(event) => setStepDraft((current) => ({ ...current, trigger: event.target.value }))}>
                      <option value="kickoff">Kickoff</option>
                      <option value="after-job">After job</option>
                    </select>
                  </label>
                  <label className="cc-field">
                    <span>Target source</span>
                    <select value={stepDraft.targetSource} onChange={(event) => setStepDraft((current) => ({ ...current, targetSource: event.target.value }))}>
                      <option value="chunk-values">Chunk values</option>
                      <option value="live-hosts">Live hosts</option>
                      <option value="derived-targets">Derived targets</option>
                    </select>
                  </label>
                </div>
                <label className="cc-field">
                  <span>Match kinds</span>
                  <input value={stepDraft.matchKinds} onChange={(event) => setStepDraft((current) => ({ ...current, matchKinds: event.target.value }))} />
                </label>
                <div className="cc-grid cc-grid--two">
                  <label className="cc-field">
                    <span>When plugin</span>
                    <input value={stepDraft.whenPlugin} onChange={(event) => setStepDraft((current) => ({ ...current, whenPlugin: event.target.value }))} />
                  </label>
                  <label className="cc-field">
                    <span>When profile</span>
                    <input value={stepDraft.whenProfile} onChange={(event) => setStepDraft((current) => ({ ...current, whenProfile: event.target.value }))} />
                  </label>
                </div>
                <div className="cc-grid cc-grid--two">
                  <label className="cc-field">
                    <span>Profile</span>
                    <input value={stepDraft.profile} onChange={(event) => setStepDraft((current) => ({ ...current, profile: event.target.value }))} />
                  </label>
                  <label className="cc-field">
                    <span>Ports</span>
                    <input value={stepDraft.ports} onChange={(event) => setStepDraft((current) => ({ ...current, ports: event.target.value }))} />
                  </label>
                </div>
                <label className="cc-field">
                  <span>Summary</span>
                  <textarea rows={3} value={stepDraft.summary} onChange={(event) => setStepDraft((current) => ({ ...current, summary: event.target.value }))} />
                </label>
                <label className="cc-checkbox">
                  <input checked={stepDraft.enabled} onChange={(event) => setStepDraft((current) => ({ ...current, enabled: event.target.checked }))} type="checkbox" />
                  <span>Step enabled</span>
                </label>
                <div className="cc-button-row">
                  <button className="cc-button cc-button--primary" disabled={mutation.isPending} type="submit">
                    Save step
                  </button>
                  <button
                    className="cc-button"
                    disabled={mutation.isPending}
                    type="button"
                    onClick={() => {
                      setSelectedStepId("");
                      mutation.mutate({ action: "remove_policy_step", policyId: selectedPolicy.id, stepId: selectedStep.id });
                    }}
                  >
                    Remove step
                  </button>
                </div>
              </form>
            ) : (
              <InlineState tone="muted" title="No step selected" body="Select a node in the policy graph to edit the step definition." />
            )}
          </Panel>

          <Panel title="Add policy step" meta={selectedPolicy ? selectedPolicy.name : "Choose a policy"}>
            {selectedPolicy ? (
              <form
                className="cc-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  mutation.mutate({
                    action: "add_policy_step",
                    policyId: selectedPolicy.id,
                    label: newStepDraft.label,
                    trigger: newStepDraft.trigger,
                    pluginId: newStepDraft.pluginId,
                    stage: newStepDraft.stage,
                    targetSource: newStepDraft.targetSource,
                    matchKinds: newStepDraft.matchKinds.split(",").map((value) => value.trim()).filter(Boolean),
                    whenPlugin: newStepDraft.whenPlugin,
                    whenProfile: newStepDraft.whenProfile,
                    summary: newStepDraft.summary,
                    profile: newStepDraft.profile,
                    ports: newStepDraft.ports,
                    topPorts: newStepDraft.topPorts,
                  });
                  setNewStepDraft(emptyPolicyStepDraft);
                }}
              >
                <label className="cc-field">
                  <span>Label</span>
                  <input value={newStepDraft.label} onChange={(event) => setNewStepDraft((current) => ({ ...current, label: event.target.value }))} />
                </label>
                <div className="cc-grid cc-grid--two">
                  <label className="cc-field">
                    <span>Tool</span>
                    <select value={newStepDraft.pluginId} onChange={(event) => setNewStepDraft((current) => ({ ...current, pluginId: event.target.value }))}>
                      {campaigns.data.tools.items.map((tool) => (
                        <option key={tool.id} value={tool.id}>
                          {tool.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="cc-field">
                    <span>Trigger</span>
                    <select value={newStepDraft.trigger} onChange={(event) => setNewStepDraft((current) => ({ ...current, trigger: event.target.value }))}>
                      <option value="kickoff">Kickoff</option>
                      <option value="after-job">After job</option>
                    </select>
                  </label>
                </div>
                <div className="cc-grid cc-grid--two">
                  <label className="cc-field">
                    <span>Stage</span>
                    <input value={newStepDraft.stage} onChange={(event) => setNewStepDraft((current) => ({ ...current, stage: event.target.value }))} />
                  </label>
                  <label className="cc-field">
                    <span>Target source</span>
                    <select value={newStepDraft.targetSource} onChange={(event) => setNewStepDraft((current) => ({ ...current, targetSource: event.target.value }))}>
                      <option value="chunk-values">Chunk values</option>
                      <option value="live-hosts">Live hosts</option>
                      <option value="derived-targets">Derived targets</option>
                    </select>
                  </label>
                </div>
                <button className="cc-button cc-button--primary" disabled={mutation.isPending} type="submit">
                  Add step
                </button>
              </form>
            ) : (
              <InlineState tone="muted" title="No active policy" body="Create or select a policy before adding steps." />
            )}
          </Panel>
        </div>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Run queue" meta={`${campaigns.data.runs.pagination.total} runs`}>
          <VirtualTable
            columns={[
              { key: "tool", label: "Tool", width: "0.95fr" },
              { key: "chunk", label: "Chunk", width: "1.1fr" },
              { key: "status", label: "Status", width: "0.6fr" },
              { key: "targets", label: "Targets", width: "0.45fr", align: "right" },
            ]}
            items={campaigns.data.runs.items}
            getKey={(run) => run.id}
            empty="No runs queued for this engagement."
            pagination={campaigns.data.runs.pagination}
            onPageChange={(page) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/campaigns",
                  params: { slug },
                  search: () => campaignsSearchState(search, { page }),
                  replace: true,
                });
              });
            }}
            onPageSizeChange={(pageSize) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/campaigns",
                  params: { slug },
                  search: () => campaignsSearchState(search, { page: 1, pageSize }),
                  replace: true,
                });
              });
            }}
            renderRow={(run) => [
              <div key={`${run.id}-tool`}>
                <strong>{run.toolLabel}</strong>
                <small>{run.stage}</small>
              </div>,
              <span key={`${run.id}-chunk`} className="cc-cell-meta">
                {run.chunkName || run.summary}
              </span>,
              <StatusBadge key={`${run.id}-status`} tone={run.statusTone} label={run.status} />,
              <strong key={`${run.id}-targets`} className="cc-cell-strong cc-cell-strong--right">
                {run.targetCount}
              </strong>,
            ]}
          />
        </Panel>

        <Panel title="Execution chunks" meta={`${campaigns.data.chunks.pagination.total} chunks`}>
          <List
            items={campaigns.data.chunks.items.map((chunk) => ({
              key: chunk.id,
              label: `${chunk.name} · ${chunk.status}`,
              detail: `${chunk.stage} · ${chunk.kind} · ${chunk.size} targets`,
            }))}
            empty="No execution chunks staged yet."
          />
        </Panel>
      </div>
    </div>
  );
}

function EngagementTopologyPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementTopologyRoute.useSearch();
  const navigate = useNavigate();
  const topology = useSuspenseQuery(engagementTopologyQuery(slug));

  const selectedNode = useMemo(
    () => topology.data.nodes.find((node) => node.id === search.selectedNode) || null,
    [search.selectedNode, topology.data.nodes],
  );
  const selectedRoute = useMemo(
    () => topology.data.routes.find((route) => route.id === search.focusRouteId) || null,
    [search.focusRouteId, topology.data.routes],
  );
  const leadingNodes = useMemo(
    () => topology.data.nodes.slice().sort((left, right) => right.count - left.count || left.label.localeCompare(right.label)).slice(0, 12),
    [topology.data.nodes],
  );

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          { label: "Traced hosts", value: topology.data.summary.traced_hosts.toString(), detail: "Targets with route evidence" },
          { label: "Nodes", value: topology.data.summary.nodes.toString(), detail: "Topology vertices in the workspace graph" },
          { label: "Edges", value: topology.data.summary.edges.toString(), detail: "Observed path connections" },
          { label: "Focus", value: selectedRoute?.target_label || "Backbone", detail: selectedRoute ? `${selectedRoute.depth} hops` : "All routes" },
        ]}
      />

      <section className="cc-toolbar">
        <label className="cc-field">
          <span>Role filter</span>
          <select
            value={search.role}
            onChange={(event) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/topology",
                  params: { slug },
                  search: () => topologySearchState(search, { role: event.target.value, selectedNode: "" }),
                  replace: true,
                });
              });
            }}
          >
            <option value="all">All nodes</option>
            <option value="source">Source</option>
            <option value="transit">Transit</option>
            <option value="mixed">Mixed</option>
            <option value="target">Target</option>
          </select>
        </label>
        <label className="cc-field">
          <span>Min edge weight</span>
          <select
            value={search.minEdgeCount}
            onChange={(event) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/topology",
                  params: { slug },
                  search: () => topologySearchState(search, { minEdgeCount: Number.parseInt(event.target.value, 10), selectedNode: "" }),
                  replace: true,
                });
              });
            }}
          >
            {[1, 2, 3, 5, 10].map((value) => (
              <option key={value} value={value}>
                {value}+
              </option>
            ))}
          </select>
        </label>
        <button
          className="cc-button"
          type="button"
          onClick={() => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/topology",
                params: { slug },
                search: () => topologySearchState(search, { focusRouteId: "", selectedNode: "" }),
                replace: true,
              });
            });
          }}
        >
          Clear focus
        </button>
      </section>

      <div className="cc-grid cc-grid--flow">
        <Panel title="Topology explorer" meta={selectedRoute ? selectedRoute.target_label : "Workspace backbone"}>
          <Suspense fallback={<InlineState tone="muted" title="Loading topology graph" body="Preparing the route explorer canvas." />}>
            <TopologyFlowCanvas
              focusRouteId={search.focusRouteId}
              minEdgeCount={search.minEdgeCount}
              onSelectNode={(nodeId) => {
                startTransition(() => {
                  void navigate({
                    to: "/engagements/$slug/topology",
                    params: { slug },
                    search: () => topologySearchState(search, { selectedNode: nodeId }),
                    replace: true,
                  });
                });
              }}
              roleFilter={search.role}
              selectedNodeId={search.selectedNode}
              topology={topology.data}
            />
          </Suspense>
        </Panel>

        <div className="cc-stack">
          <Panel title="Route focus" meta={`${topology.data.routes.length} traced routes`}>
            <List
              items={topology.data.routes.slice(0, 16).map((route) => ({
                key: route.id,
                label: route.target_label,
                detail: `${route.count} observations · ${route.depth} hops`,
                active: search.focusRouteId === route.id,
                onClick: () => {
                  startTransition(() => {
                    void navigate({
                      to: "/engagements/$slug/topology",
                      params: { slug },
                      search: () => topologySearchState(search, { focusRouteId: route.id, selectedNode: route.hops[0] || "" }),
                      replace: true,
                    });
                  });
                },
              }))}
              empty="No traced routes are available yet."
            />
          </Panel>

          <Panel title="Selected node" meta={selectedNode ? selectedNode.role : "Choose a node"}>
            {selectedNode ? (
              <div className="cc-detail-grid">
                <InfoPair label="Label" value={selectedNode.label} />
                <InfoPair label="Role" value={selectedNode.role} />
                <InfoPair label="Hostname" value={selectedNode.hostname || "No hostname"} />
                <InfoPair label="Provider" value={selectedNode.provider || "No provider"} />
                <InfoPair label="Average TTL" value={selectedNode.avg_ttl.toFixed(1)} />
                <InfoPair label="Average RTT" value={`${selectedNode.avg_rtt.toFixed(1)} ms`} />
              </div>
            ) : (
              <InlineState tone="muted" title="No node selected" body="Select a node in the topology graph to inspect its route context." />
            )}
          </Panel>

          <Panel title="Leading transit nodes" meta="Highest-frequency infrastructure">
            <List
              items={leadingNodes.map((node) => ({
                key: node.id,
                label: node.label,
                detail: `${node.count} observations · ${node.role}`,
                active: search.selectedNode === node.id,
                onClick: () => {
                  startTransition(() => {
                    void navigate({
                      to: "/engagements/$slug/topology",
                      params: { slug },
                      search: () => topologySearchState(search, { selectedNode: node.id }),
                      replace: true,
                    });
                  });
                },
              }))}
              empty="No topology nodes available."
            />
          </Panel>
        </div>
      </div>
    </div>
  );
}

function EngagementRecommendationsPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementRecommendationsRoute.useSearch();
  const queryClient = useQueryClient();
  const [campaignId, setCampaignId] = useState("");
  const recommendations = useSuspenseQuery(
    engagementRecommendationsQuery(slug, {
      page: search.page,
      pageSize: search.pageSize,
    }),
  );
  const navigate = useNavigate();
  const llmMutation = useMutation({
    mutationFn: () => requestEngagementRecommendations(slug, campaignId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["engagement-recommendations", slug] });
    },
  });
  const approvalMutation = useMutation({
    mutationFn: (approvalID: string) => approveEngagementApproval(slug, approvalID),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["engagement-recommendations", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagement-campaigns", slug] }),
      ]);
    },
  });

  return (
    <div className="cc-stack">
      <StatGrid
        items={[
          { label: "Recommendations", value: recommendations.data.recommendations.pagination.total.toString(), detail: "Queued next-step suggestions" },
          { label: "Approvals", value: recommendations.data.approvals.pagination.total.toString(), detail: "Operator gates waiting for action" },
        ]}
      />

      <div className="cc-grid cc-grid--two">
        <Panel title="Refresh recommendation queue" meta="Planner-backed suggestions">
          <form
            className="cc-form"
            onSubmit={(event) => {
              event.preventDefault();
              llmMutation.mutate();
            }}
          >
            <label className="cc-field">
              <span>Campaign ID</span>
              <input
                placeholder="Optional campaign scope"
                value={campaignId}
                onChange={(event) => setCampaignId(event.target.value)}
              />
            </label>
            <button className="cc-button cc-button--primary" disabled={llmMutation.isPending} type="submit">
              {llmMutation.isPending ? "Requesting" : "Generate recommendations"}
            </button>
          </form>
          {llmMutation.isError ? (
            <InlineState tone="danger" title="Planner request failed" body={llmMutation.error.message} />
          ) : null}
        </Panel>

        <Panel title="Approvals" meta={`${recommendations.data.approvals.pagination.total} pending`}>
          <List
            items={recommendations.data.approvals.items.map((approval) => ({
              key: approval.id,
              label: approval.summary,
              detail: `${approval.scope} · ${approval.requiredClass}`,
              onClick: () => approvalMutation.mutate(approval.id),
            }))}
            empty="No approvals are waiting."
          />
          {approvalMutation.isError ? (
            <InlineState tone="danger" title="Approval failed" body={approvalMutation.error.message} />
          ) : null}
        </Panel>
      </div>

      <Panel title="Recommendation queue" meta={`${recommendations.data.recommendations.pagination.total} items`}>
        <VirtualTable
          columns={[
            { key: "title", label: "Recommendation", width: "1.2fr" },
            { key: "type", label: "Type", width: "0.55fr" },
            { key: "status", label: "Status", width: "0.55fr" },
            { key: "confidence", label: "Confidence", width: "0.55fr" },
          ]}
          items={recommendations.data.recommendations.items}
          getKey={(recommendation) => recommendation.id}
          empty="No recommendations queued."
          pagination={recommendations.data.recommendations.pagination}
          onPageChange={(page) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/recommendations",
                params: { slug },
                search: () => singlePageSearchState(search, { page }),
                replace: true,
              });
            });
          }}
          onPageSizeChange={(pageSize) => {
            startTransition(() => {
              void navigate({
                to: "/engagements/$slug/recommendations",
                params: { slug },
                search: () => singlePageSearchState(search, { page: 1, pageSize }),
                replace: true,
              });
            });
          }}
          renderRow={(recommendation) => [
            <div key={`${recommendation.id}-title`}>
              <strong>{recommendation.title}</strong>
              <small>{recommendation.detail}</small>
            </div>,
            <span key={`${recommendation.id}-type`} className="cc-cell-meta">
              {recommendation.type}
            </span>,
            <StatusBadge key={`${recommendation.id}-status`} tone={recommendation.statusTone} label={recommendation.status} />,
            <span key={`${recommendation.id}-confidence`} className="cc-cell-meta">
              {recommendation.confidence || "n/a"}
            </span>,
          ]}
        />
      </Panel>
    </div>
  );
}

function EngagementSettingsPage() {
  const { slug } = engagementRoute.useParams();
  const search = engagementSettingsRoute.useSearch();
  const queryClient = useQueryClient();
  const [selectedUser, setSelectedUser] = useState("");
  const [selectedRole, setSelectedRole] = useState("viewer");
  const settings = useSuspenseQuery(
    engagementSettingsQuery(slug, {
      page: search.page,
      pageSize: search.pageSize,
    }),
  );
  const navigate = useNavigate();
  const mutation = useMutation({
    mutationFn: () => addEngagementMember(slug, { user: selectedUser, role: selectedRole }),
    onSuccess: async () => {
      setSelectedUser("");
      setSelectedRole("viewer");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["engagement-settings", slug] }),
        queryClient.invalidateQueries({ queryKey: ["engagements"] }),
      ]);
    },
  });

  return (
    <div className="cc-stack">
      <div className="cc-grid cc-grid--two">
        <Panel title="Memberships" meta={`${settings.data.memberships.pagination.total} members`}>
          <VirtualTable
            columns={[
              { key: "user", label: "User", width: "1fr" },
              { key: "role", label: "Role", width: "0.6fr" },
              { key: "joined", label: "Joined", width: "0.8fr" },
            ]}
            items={settings.data.memberships.items}
            getKey={(member) => member.userId}
            empty="No engagement members configured."
            pagination={settings.data.memberships.pagination}
            onPageChange={(page) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/settings",
                  params: { slug },
                  search: () => singlePageSearchState(search, { page }),
                  replace: true,
                });
              });
            }}
            onPageSizeChange={(pageSize) => {
              startTransition(() => {
                void navigate({
                  to: "/engagements/$slug/settings",
                  params: { slug },
                  search: () => singlePageSearchState(search, { page: 1, pageSize }),
                  replace: true,
                });
              });
            }}
            renderRow={(member) => [
              <div key={`${member.userId}-user`}>
                <strong>{member.displayName}</strong>
                <small>{member.username} · {member.email}</small>
              </div>,
              <span key={`${member.userId}-role`} className="cc-cell-meta">
                {member.role}
              </span>,
              <span key={`${member.userId}-joined`} className="cc-cell-meta">
                {member.joinedAt}
              </span>,
            ]}
          />
        </Panel>

        <Panel title="Add member" meta="Owners and admins can share the engagement">
          <form
            className="cc-form"
            onSubmit={(event) => {
              event.preventDefault();
              mutation.mutate();
            }}
          >
            <label className="cc-field">
              <span>User</span>
              <select value={selectedUser} onChange={(event) => setSelectedUser(event.target.value)}>
                <option value="">Select a user</option>
                {settings.data.users.items.map((user) => (
                  <option key={user.id} value={user.username}>
                    {user.displayName} ({user.username})
                  </option>
                ))}
              </select>
            </label>
            <label className="cc-field">
              <span>Role</span>
              <select value={selectedRole} onChange={(event) => setSelectedRole(event.target.value)}>
                <option value="viewer">Viewer</option>
                <option value="editor">Editor</option>
                <option value="owner">Owner</option>
              </select>
            </label>
            <button className="cc-button cc-button--primary" disabled={mutation.isPending || !selectedUser} type="submit">
              {mutation.isPending ? "Adding" : "Add member"}
            </button>
          </form>
          {mutation.isError ? (
            <InlineState tone="danger" title="Membership update failed" body={mutation.error.message} />
          ) : null}
        </Panel>
      </div>

      <div className="cc-grid cc-grid--two">
        <Panel title="Tool posture" meta={`${settings.data.tools.pagination.total} tools`}>
          <List
            items={settings.data.tools.items.map((tool) => ({
              key: tool.id,
              label: tool.label,
              detail: `${tool.kind} · ${tool.status} · ${tool.statusDetail}`,
            }))}
            empty="No tools registered."
          />
        </Panel>

        <Panel title="Connector posture" meta={`${settings.data.connectors.pagination.total} connectors`}>
          <List
            items={settings.data.connectors.items.map((connector) => ({
              key: connector.id,
              label: connector.label,
              detail: `${connector.status} · ${connector.statusDetail}`,
            }))}
            empty="No connectors registered."
          />
        </Panel>
      </div>
    </div>
  );
}

function HostInventoryTable({
  hosts,
  empty,
  pagination,
  onPageChange,
  onPageSizeChange,
}: {
  hosts: PlatformHost[];
  empty: string;
  pagination?: PlatformPagination;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
}) {
  return (
    <VirtualTable
      columns={[
        { key: "host", label: "Host", width: "1.3fr" },
        { key: "os", label: "OS", width: "0.9fr" },
        { key: "ports", label: "Ports", width: "0.5fr", align: "right" },
        { key: "findings", label: "Findings", width: "0.6fr", align: "right" },
        { key: "exposure", label: "Exposure", width: "0.6fr" },
      ]}
      items={hosts}
      getKey={(host) => host.ip}
      empty={empty}
      pagination={pagination}
      onPageChange={onPageChange}
      onPageSizeChange={onPageSizeChange}
      renderRow={(host) => [
        <a className="cc-table-link" href={`/app${host.href}`} key={`${host.ip}-host`}>
          <strong>{host.displayName}</strong>
          <small>{host.ip} · {host.sourceCount} sources</small>
        </a>,
        <span key={`${host.ip}-os`} className="cc-cell-meta">
          {host.os || "Unknown"}
        </span>,
        <strong key={`${host.ip}-ports`} className="cc-cell-strong cc-cell-strong--right">
          {host.openPorts}
        </strong>,
        <strong key={`${host.ip}-findings`} className="cc-cell-strong cc-cell-strong--right">
          {host.findings}
        </strong>,
        <StatusBadge key={`${host.ip}-exposure`} tone={host.exposureTone || "muted"} label={host.exposure} />,
      ]}
    />
  );
}

function HostPortInventoryTable({ ports }: { ports: HostPortRow[] }) {
  return (
    <VirtualTable
      columns={[
        { key: "port", label: "Port", width: "0.6fr" },
        { key: "service", label: "Service", width: "0.9fr" },
        { key: "product", label: "Product", width: "1fr" },
        { key: "version", label: "Version", width: "0.8fr" },
      ]}
      items={ports}
      getKey={(port) => `${port.protocol}-${port.port}`}
      empty="No ports were observed for this host."
      renderRow={(port) => [
        <div key={`${port.protocol}-${port.port}-label`}>
          <strong>{`${port.protocol}/${port.port}`}</strong>
          <small>{port.state || "observed"}</small>
        </div>,
        <span key={`${port.protocol}-${port.port}-service`} className="cc-cell-meta">
          {port.service || "Unknown"}
        </span>,
        <span key={`${port.protocol}-${port.port}-product`} className="cc-cell-meta">
          {port.product || port.extraInfo || "No product fingerprint"}
        </span>,
        <span key={`${port.protocol}-${port.port}-version`} className="cc-cell-meta">
          {port.version || "No version"}
        </span>,
      ]}
    />
  );
}

function PortInventoryTable({
  ports,
  empty,
  pagination,
  onPageChange,
  onPageSizeChange,
}: {
  ports: PlatformPort[];
  empty: string;
  pagination?: PlatformPagination;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
}) {
  return (
    <VirtualTable
      columns={[
        { key: "port", label: "Port", width: "0.65fr" },
        { key: "service", label: "Service", width: "1fr" },
        { key: "hosts", label: "Hosts", width: "0.55fr", align: "right" },
        { key: "findings", label: "Findings", width: "0.65fr", align: "right" },
      ]}
      items={ports}
      getKey={(port) => `${port.protocol}-${port.port}`}
      empty={empty}
      pagination={pagination}
      onPageChange={onPageChange}
      onPageSizeChange={onPageSizeChange}
      renderRow={(port) => [
        <a className="cc-table-link" href={`/app${port.href}`} key={`${port.protocol}-${port.port}-label`}>
          <strong>{port.label}</strong>
          <small>{port.protocol}</small>
        </a>,
        <span key={`${port.protocol}-${port.port}-service`} className="cc-cell-meta">
          {port.service || "Unknown service"}
        </span>,
        <strong key={`${port.protocol}-${port.port}-hosts`} className="cc-cell-strong cc-cell-strong--right">
          {port.hosts}
        </strong>,
        <strong key={`${port.protocol}-${port.port}-findings`} className="cc-cell-strong cc-cell-strong--right">
          {port.findings}
        </strong>,
      ]}
    />
  );
}

function FindingGroupTable({
  findings,
  slug,
  empty,
}: {
  findings: FindingGroup[];
  slug: string;
  empty: string;
}) {
  return (
    <VirtualTable
      columns={[
        { key: "finding", label: "Finding", width: "1.15fr" },
        { key: "severity", label: "Severity", width: "0.55fr" },
        { key: "hosts", label: "Hosts", width: "0.45fr", align: "right" },
        { key: "occurrences", label: "Hits", width: "0.45fr", align: "right" },
      ]}
      items={findings}
      getKey={(finding) => finding.id}
      empty={empty}
      renderRow={(finding) => [
        <a className="cc-table-link" href={`/app/engagements/${slug}/findings/${encodeURIComponent(finding.id)}`} key={`${finding.id}-label`}>
          <strong>{finding.name}</strong>
          <small>{finding.source} · {finding.templateId || "No template ID"}</small>
        </a>,
        <StatusBadge key={`${finding.id}-severity`} tone={finding.severityTone || "muted"} label={finding.severity} />,
        <strong key={`${finding.id}-hosts`} className="cc-cell-strong cc-cell-strong--right">
          {finding.hosts}
        </strong>,
        <strong key={`${finding.id}-occurrences`} className="cc-cell-strong cc-cell-strong--right">
          {finding.occurrences}
        </strong>,
      ]}
    />
  );
}

function FindingInventoryTable({
  findings,
  slug,
  empty,
  pagination,
  onPageChange,
  onPageSizeChange,
}: {
  findings: PlatformFinding[];
  slug: string;
  empty: string;
  pagination?: PlatformPagination;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
}) {
  return (
    <VirtualTable
      columns={[
        { key: "finding", label: "Finding", width: "1.2fr" },
        { key: "severity", label: "Severity", width: "0.55fr" },
        { key: "hosts", label: "Hosts", width: "0.45fr", align: "right" },
        { key: "occurrences", label: "Hits", width: "0.45fr", align: "right" },
        { key: "lastSeen", label: "Last seen", width: "0.7fr" },
      ]}
      items={findings}
      getKey={(finding) => finding.id}
      empty={empty}
      pagination={pagination}
      onPageChange={onPageChange}
      onPageSizeChange={onPageSizeChange}
      renderRow={(finding) => [
        <a className="cc-table-link" href={`/app/engagements/${slug}/findings/${encodeURIComponent(finding.id)}`} key={`${finding.id}-label`}>
          <strong>{finding.name}</strong>
          <small>{finding.source} · {finding.templateID || "No template ID"}</small>
        </a>,
        <StatusBadge key={`${finding.id}-severity`} tone={finding.severityTone || "muted"} label={finding.severity} />,
        <strong key={`${finding.id}-hosts`} className="cc-cell-strong cc-cell-strong--right">
          {finding.hosts}
        </strong>,
        <strong key={`${finding.id}-occurrences`} className="cc-cell-strong cc-cell-strong--right">
          {finding.occurrences}
        </strong>,
        <span key={`${finding.id}-lastSeen`} className="cc-cell-meta">
          {finding.lastSeen || "Unknown"}
        </span>,
      ]}
    />
  );
}

function RunList({ runs, empty }: { runs: { id: string; toolLabel: string; status: string; statusTone: string; summary: string; createdAt: string; error: string }[]; empty: string }) {
  return (
    <List
      items={runs.map((run) => ({
        key: run.id,
        label: `${run.toolLabel} · ${run.status}`,
        detail: [run.summary || "No summary", run.error || "", run.createdAt].filter(Boolean).join(" · "),
      }))}
      empty={empty}
    />
  );
}

function InfoPair({ label, value }: { label: string; value: string }) {
  return (
    <div className="cc-info-pair">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function VirtualTable<T>({
  columns,
  items,
  getKey,
  renderRow,
  empty,
  pagination,
  onPageChange,
  onPageSizeChange,
  height = 440,
  rowHeight = 72,
}: {
  columns: Array<{ key: string; label: string; width: string; align?: "left" | "right" }>;
  items: T[];
  getKey: (item: T) => string;
  renderRow: (item: T) => ReactNode[];
  empty: string;
  pagination?: PlatformPagination;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  height?: number;
  rowHeight?: number;
}) {
  const parentRef = useRef<HTMLDivElement | null>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 8,
  });

  if (items.length === 0) {
    return <InlineState tone="muted" title="Nothing to show" body={empty} />;
  }

  const templateColumns = columns.map((column) => column.width).join(" ");

  return (
    <div className="cc-vtable">
      <div className="cc-vtable__head" style={{ gridTemplateColumns: templateColumns }}>
        {columns.map((column) => (
          <span
            key={column.key}
            className={column.align === "right" ? "is-right" : undefined}
          >
            {column.label}
          </span>
        ))}
      </div>

      <div className="cc-vtable__body" ref={parentRef} style={{ height }}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const item = items[virtualRow.index];
            const cells = renderRow(item);
            return (
              <div
                className="cc-vtable__row"
                key={getKey(item)}
                style={{
                  gridTemplateColumns: templateColumns,
                  height: virtualRow.size,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                {cells.map((cell, index) => (
                  <div
                    className={columns[index]?.align === "right" ? "is-right" : undefined}
                    key={index}
                  >
                    {cell}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>

      {pagination ? (
        <PaginationControls
          pagination={pagination}
          onPageChange={onPageChange}
          onPageSizeChange={onPageSizeChange}
        />
      ) : null}
    </div>
  );
}

function PaginationControls({
  pagination,
  onPageChange,
  onPageSizeChange,
}: {
  pagination: PlatformPagination;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
}) {
  const pageWindow = useMemo(() => {
    const start = Math.max(1, pagination.page - 2);
    const end = Math.min(pagination.totalPages, start + 4);
    const pages: number[] = [];
    for (let page = start; page <= end; page += 1) {
      pages.push(page);
    }
    return pages;
  }, [pagination.page, pagination.totalPages]);

  return (
    <div className="cc-pagination">
      <span>
        Showing {pagination.start}-{pagination.end} of {pagination.total}
      </span>
      <div className="cc-pagination__controls">
        <button
          className="cc-button"
          disabled={!pagination.hasPrev || !onPageChange}
          onClick={() => onPageChange?.(pagination.page - 1)}
          type="button"
        >
          Previous
        </button>
        {pageWindow.map((page) => (
          <button
            className={`cc-button ${page === pagination.page ? "cc-button--primary" : ""}`}
            key={page}
            disabled={!onPageChange}
            onClick={() => onPageChange?.(page)}
            type="button"
          >
            {page}
          </button>
        ))}
        <button
          className="cc-button"
          disabled={!pagination.hasNext || !onPageChange}
          onClick={() => onPageChange?.(pagination.page + 1)}
          type="button"
        >
          Next
        </button>
        <label className="cc-page-size">
          <span>Rows</span>
          <select
            value={pagination.pageSize}
            onChange={(event) => onPageSizeChange?.(Number.parseInt(event.target.value, 10))}
          >
            {pageSizes.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
      </div>
    </div>
  );
}

function LogoutButton() {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: logout,
    onSuccess: async (payload) => {
      queryClient.setQueryData(sessionQuery().queryKey, payload);
      startTransition(() => {
        window.location.assign("/app/login");
      });
    },
  });

  return (
    <button className="cc-button" onClick={() => mutation.mutate()} disabled={mutation.isPending} type="button">
      {mutation.isPending ? "Signing out" : "Logout"}
    </button>
  );
}

function ShellScaffold({ children }: { children: ReactNode }) {
  return <div className="cc-root">{children}</div>;
}

function PageHeader({
  kicker,
  title,
  subtitle,
  actions,
}: {
  kicker: string;
  title: string;
  subtitle: string;
  actions?: ReactNode;
}) {
  return (
    <header className="cc-header">
      <div>
        <p className="cc-kicker">{kicker}</p>
        <h1>{title}</h1>
        <p className="cc-copy">{subtitle}</p>
      </div>
      {actions ? <div>{actions}</div> : null}
    </header>
  );
}

function StatGrid({
  items,
}: {
  items: Array<{ label: string; value: string; detail: string }>;
}) {
  return (
    <section className="cc-stat-grid">
      {items.map((item) => (
        <article className="cc-stat-card" key={`${item.label}-${item.value}`}>
          <p>{item.label}</p>
          <strong>{item.value}</strong>
          <span>{item.detail}</span>
        </article>
      ))}
    </section>
  );
}

function Panel({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: string;
  children: ReactNode;
}) {
  return (
    <section className="cc-card">
      <div className="cc-card__head">
        <h2>{title}</h2>
        {meta ? <span>{meta}</span> : null}
      </div>
      {children}
    </section>
  );
}

function Table({
  columns,
  rows,
  empty,
  pagination,
}: {
  columns: string[];
  rows: ReactNode[][];
  empty: string;
  pagination?: PlatformPagination;
}) {
  if (rows.length === 0) {
    return <InlineState tone="muted" title="Nothing to show" body={empty} />;
  }
  return (
    <div className="cc-table-wrap">
      <table className="cc-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {pagination ? <PaginationMeta pagination={pagination} /> : null}
    </div>
  );
}

function PaginationMeta({ pagination }: { pagination: PlatformPagination }) {
  return (
    <div className="cc-pagination">
      <span>
        Showing {pagination.start}-{pagination.end} of {pagination.total}
      </span>
      <span>{pagination.pageSize} per page</span>
    </div>
  );
}

function List({
  items,
  empty,
}: {
  items: Array<{
    key: string;
    label: string;
    detail: string;
    href?: string;
    active?: boolean;
    onClick?: () => void;
  }>;
  empty: string;
}) {
  if (items.length === 0) {
    return <InlineState tone="muted" title="Nothing to show" body={empty} />;
  }
  return (
    <div className="cc-list">
      {items.map((item) =>
        item.href ? (
          <a className={`cc-list-row ${item.active ? "is-active" : ""}`} href={item.href} key={item.key}>
            <div>
              <strong>{item.label}</strong>
              <small>{item.detail}</small>
            </div>
          </a>
        ) : (
          <button
            className={`cc-list-row cc-list-row--button ${item.active ? "is-active" : ""}`}
            key={item.key}
            onClick={item.onClick}
            type="button"
          >
            <div>
              <strong>{item.label}</strong>
              <small>{item.detail}</small>
            </div>
          </button>
        ),
      )}
    </div>
  );
}

function StatusBadge({ tone, label }: { tone: string; label: string }) {
  return <span className={`cc-badge cc-badge--${tone || "muted"}`}>{label}</span>;
}

function FullState({
  tone,
  title,
  body,
}: {
  tone: "muted" | "danger";
  title: string;
  body: string;
}) {
  return (
    <section className={`cc-state cc-state--${tone}`}>
      <h2>{title}</h2>
      <p>{body}</p>
    </section>
  );
}

function InlineState({
  tone,
  title,
  body,
}: {
  tone: "muted" | "danger";
  title: string;
  body: string;
}) {
  return (
    <div className={`cc-inline-state cc-inline-state--${tone}`}>
      <strong>{title}</strong>
      <span>{body}</span>
    </div>
  );
}
