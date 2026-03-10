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
import {
  type FormEvent,
  type ReactNode,
  Suspense,
  startTransition,
  useDeferredValue,
  useEffect,
  useMemo,
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
  engagementFindingsQuery,
  engagementHostsQuery,
  engagementSummaryQuery,
  engagementZonesQuery,
  engagementsQuery,
  login,
  logout,
  sessionQuery,
  type PlatformAuditEvent,
  type PlatformPagination,
  type SessionPayload,
  updateToolCommandTemplate,
} from "./api";

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

const engagementHostsRoute = createRoute({
  getParentRoute: () => engagementRoute,
  path: "/hosts",
  validateSearch: (search: Record<string, unknown>) => ({
    query: typeof search.query === "string" ? search.query : "",
    zone: typeof search.zone === "string" ? search.zone : "",
  }),
  component: EngagementHostsPage,
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
  engagementRoute.addChildren([engagementOverviewRoute, engagementHostsRoute]),
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
            <a href={`/app/engagements/${engagement.slug}`} className="is-active">
              Overview
            </a>
            <a href={`/app/engagements/${engagement.slug}/hosts`}>Hosts</a>
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
  const hosts = useSuspenseQuery(engagementHostsQuery(slug, {}));
  const findings = useSuspenseQuery(engagementFindingsQuery(slug));

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
        <Panel title="Priority hosts" meta="Top of current slice">
          <List
            items={hosts.data.items.slice(0, 8).map((host) => ({
              key: host.ip,
              label: host.displayName,
              detail: `${host.ip} · ${host.openPorts} ports · ${host.findings} findings`,
              href: `/app/engagements/${slug}/hosts?query=${encodeURIComponent(host.ip)}`,
            }))}
            empty="No host inventory yet."
          />
        </Panel>
        <Panel title="Finding groups" meta="Highest-signal definitions">
          <List
            items={findings.data.items.slice(0, 8).map((finding) => ({
              key: finding.id,
              label: finding.name,
              detail: `${finding.severity} · ${finding.occurrences} occurrences`,
            }))}
            empty="No finding groups yet."
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
  const zones = useSuspenseQuery(engagementZonesQuery(slug));
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
        search: (previous: { query?: string; zone?: string }) => ({
          query: deferredQuery,
          zone: previous.zone ?? "",
        }),
        replace: true,
      });
    });
  }, [deferredQuery, navigate, search.query, slug]);

  const hosts = useSuspenseQuery(
    engagementHostsQuery(slug, {
      query: search.query,
      zone: search.zone,
    }),
  );

  const selectedZone = useMemo(
    () => zones.data.items.find((zone) => zone.id === search.zone),
    [search.zone, zones.data.items],
  );

  return (
    <div className="cc-stack">
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
                  search: (previous: { query?: string; zone?: string }) => ({
                    query: previous.query ?? "",
                    zone,
                  }),
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
              onClick: () => {
                startTransition(() => {
                  void navigate({
                    to: "/engagements/$slug/hosts",
                    params: { slug },
                    search: (previous: { query?: string; zone?: string }) => ({
                      query: previous.query ?? "",
                      zone: zone.id,
                    }),
                    replace: true,
                  });
                });
              },
            }))}
            empty="No zones derived yet."
          />
        </Panel>

        <Panel title="Host inventory" meta={`${hosts.data.pagination.total} hosts`}>
          <Table
            columns={["Host", "OS", "Ports", "Findings", "Exposure"]}
            rows={hosts.data.items.map((host) => [
              <div key={host.ip}>
                <strong>{host.displayName}</strong>
                <small>{host.ip}</small>
              </div>,
              host.os || "Unknown",
              host.openPorts.toString(),
              host.findings.toString(),
              host.exposure,
            ])}
            empty="No hosts match the current slice."
            pagination={hosts.data.pagination}
          />
        </Panel>
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
