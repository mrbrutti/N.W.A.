import {
  Outlet,
  RouterProvider,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  redirect,
  useNavigate,
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
  adminToolsQuery,
  engagementFindingsQuery,
  engagementHostsQuery,
  engagementSummaryQuery,
  engagementZonesQuery,
  engagementsQuery,
  login,
  logout,
  sessionQuery,
  type SessionPayload,
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
  component: AdminPage,
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
  adminRoute,
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
      <Suspense fallback={<FullState tone="muted" title="Loading" body="Loading workspace state." />}>
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
  return (
    <div className="cc-shell">
      <header className="cc-topbar">
        <div className="cc-brand">
          <span className="cc-brand__mark">NWA</span>
          <div>
            <strong>Network Workbench</strong>
            <small>React migration shell</small>
          </div>
        </div>
        <nav className="cc-menu">
          <details>
            <summary>Platform</summary>
            <div className="cc-menu__panel">
              <a href="/app/admin">Admin</a>
              <a href="/app/engagements">Engagements</a>
            </div>
          </details>
          {session?.authenticated ? (
            <details>
              <summary>Account</summary>
              <div className="cc-menu__panel">
                <span>{session.user?.displayName}</span>
                <LogoutButton />
              </div>
            </details>
          ) : null}
        </nav>
      </header>
      <div className="cc-body">{children}</div>
    </div>
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
        <p className="cc-kicker">Platform access</p>
        <h1>Sign in to the React shell</h1>
        <p className="cc-copy">
          This is the first migration slice: login, admin overview, engagement registry, and host inventory now have a typed React surface.
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

function AdminPage() {
  const health = useSuspenseQuery(adminHealthQuery());
  const engagements = useSuspenseQuery(engagementsQuery());
  const tools = useSuspenseQuery(adminToolsQuery());

  return (
    <div className="cc-page">
      <PageHeader
        kicker="Admin"
        title="System overview"
        subtitle="Health, engagement registry, and tool posture from the new React shell."
      />
      <StatGrid
        items={[
          { label: "Users", value: health.data.userCount.toString(), detail: "Platform accounts" },
          { label: "Engagements", value: health.data.engagementCount.toString(), detail: "Tracked missions" },
          { label: "Workers", value: `${health.data.liveWorkers}/${health.data.workerCount}`, detail: "Live execution workers" },
          { label: "Queue", value: `${health.data.runningRuns} / ${health.data.queuedRuns}`, detail: "Running / queued" },
        ]}
      />
      <div className="cc-grid cc-grid--two">
        <Panel title="Engagement registry" meta={`${engagements.data.length} engagements`}>
          <Table
            columns={["Name", "Scope", "Hosts", "Findings"]}
            rows={engagements.data.map((item) => [
              <a key={item.id} href={`/app/engagements/${item.slug}`}>
                {item.name}
              </a>,
              item.scopeSummary,
              item.hostCount.toString(),
              item.findingCount.toString(),
            ])}
            empty="No engagements available."
          />
        </Panel>
        <Panel title="Tool posture" meta={`${tools.data.tools.length} tools`}>
          <Table
            columns={["Tool", "Kind", "Status"]}
            rows={tools.data.tools.map((item) => [item.label, item.kind, item.status])}
            empty="No tools registered."
          />
        </Panel>
      </div>
    </div>
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
      <Panel title="Available engagements" meta={`${engagements.data.length} total`}>
        <div className="cc-stack">
          {engagements.data.length === 0 ? (
            <InlineState tone="muted" title="No engagements" body="Create an engagement from the admin surface." />
          ) : (
            engagements.data.map((item) => (
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
  const engagement = engagements.data.find((item) => item.slug === slug);

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
            <a href={`/app/engagements/${engagement.slug}`}>Overview</a>
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
            items={hosts.data.slice(0, 8).map((host) => ({
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
            items={findings.data.slice(0, 8).map((finding) => ({
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
  }, [deferredQuery, navigate, search.query]);

  const hosts = useSuspenseQuery(
    engagementHostsQuery(slug, {
      query: search.query,
      zone: search.zone,
    }),
  );

  const selectedZone = useMemo(
    () => zones.data.find((zone) => zone.id === search.zone),
    [search.zone, zones.data],
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
            {zones.data.map((zone) => (
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
          meta={selectedZone ? `${selectedZone.name} selected` : `${zones.data.length} zones`}
        >
          <List
            items={zones.data.map((zone) => ({
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

        <Panel title="Host inventory" meta={`${hosts.data.length} hosts`}>
          <Table
            columns={["Host", "OS", "Ports", "Findings", "Exposure"]}
            rows={hosts.data.map((host) => [
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
    <button className="cc-button" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
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
}: {
  columns: string[];
  rows: ReactNode[][];
  empty: string;
}) {
  if (rows.length === 0) {
    return <InlineState tone="muted" title="Nothing to show" body={empty} />;
  }
  return (
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
