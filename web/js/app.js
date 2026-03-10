document.addEventListener("DOMContentLoaded", () => {
  initializeNavMenus();
  initializePlatformMenus();
  initializeSidebar();
  document.querySelectorAll("[data-submit-on-change]").forEach((element) => {
    element.addEventListener("change", () => {
      const form = element.closest("form");
      if (form) {
        form.requestSubmit();
      }
    });
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.getAttribute("data-copy");
      if (!value) {
        return;
      }

      const originalLabel = button.textContent;
      try {
        await navigator.clipboard.writeText(value);
        button.textContent = "Copied";
      } catch (_error) {
        button.textContent = "Copy failed";
      }

      window.setTimeout(() => {
        button.textContent = originalLabel;
      }, 1200);
    });
  });

  initializeHashDisclosure();
  initializeBucketCharts();
  initializeNavigator();
  initializeExplorer();
  initializeLiveRefresh();
  initializeTopologyGraph();
  initializePolicyEditors();
});

function initializePlatformMenus() {
  const menus = Array.from(document.querySelectorAll("[data-platform-menu]"));
  if (!menus.length) {
    return;
  }

  const closeAll = (except) => {
    menus.forEach((menu) => {
      if (menu === except) {
        return;
      }
      if (menu instanceof HTMLDetailsElement) {
        menu.open = false;
      }
    });
  };

  menus.forEach((menu) => {
    if (!(menu instanceof HTMLDetailsElement)) {
      return;
    }
    menu.addEventListener("toggle", () => {
      if (menu.open) {
        closeAll(menu);
      }
    });
  });

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      closeAll(null);
      return;
    }
    if (!target.closest("[data-platform-menu]")) {
      closeAll(null);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeAll(null);
    }
  });
}

function initializeNavMenus() {
  const menus = Array.from(document.querySelectorAll("[data-nav-menu]"));
  if (!menus.length) {
    return;
  }

  const closeAll = (except) => {
    menus.forEach((menu) => {
      if (menu === except) {
        return;
      }
      const toggle = menu.querySelector("[data-nav-toggle]");
      const panel = menu.querySelector(".nav-menu__panel");
      menu.classList.remove("is-open");
      if (toggle) {
        toggle.setAttribute("aria-expanded", "false");
      }
      if (panel) {
        panel.hidden = true;
      }
    });
  };

  menus.forEach((menu) => {
    const toggle = menu.querySelector("[data-nav-toggle]");
    const panel = menu.querySelector(".nav-menu__panel");
    if (!toggle || !panel) {
      return;
    }

    toggle.addEventListener("click", (event) => {
      event.preventDefault();
      const open = menu.classList.contains("is-open");
      closeAll(menu);
      if (open) {
        menu.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
        panel.hidden = true;
        return;
      }
      menu.classList.add("is-open");
      toggle.setAttribute("aria-expanded", "true");
      panel.hidden = false;
    });
  });

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      closeAll(null);
      return;
    }
    if (!target.closest("[data-nav-menu]")) {
      closeAll(null);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeAll(null);
    }
  });
}

function initializeSidebar() {
  const layout = document.querySelector("[data-sidebar-layout]");
  const panel = document.querySelector("[data-sidebar-panel]");
  const toggle = document.querySelector("[data-sidebar-toggle]");
  if (!layout || !panel || !toggle) {
    return;
  }

  const storageKey = "nwa.sidebar.collapsed";
  const media = window.matchMedia("(max-width: 1180px)");
  const label = toggle.querySelector(".sidebar-toggle__label");

  const apply = (collapsed, persist) => {
    layout.classList.toggle("is-sidebar-collapsed", collapsed);
    panel.hidden = collapsed;
    toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");

    const nextLabel =
      toggle.getAttribute(collapsed ? "data-sidebar-label-closed" : "data-sidebar-label-open") || "Sidebar";
    if (label) {
      label.textContent = nextLabel;
    }
    toggle.setAttribute("aria-label", nextLabel);
    toggle.title = nextLabel;

    if (persist) {
      hasStoredPreference = true;
      try {
        window.localStorage.setItem(storageKey, collapsed ? "true" : "false");
      } catch (_error) {
        // Ignore storage failures and keep the in-memory state only.
      }
    }
  };

  let collapsed = media.matches;
  let hasStoredPreference = false;
  try {
    const stored = window.localStorage.getItem(storageKey);
    if (stored === "true" || stored === "false") {
      hasStoredPreference = true;
      collapsed = stored === "true";
    }
  } catch (_error) {
    hasStoredPreference = false;
  }

  apply(collapsed, false);

  toggle.addEventListener("click", () => {
    apply(!layout.classList.contains("is-sidebar-collapsed"), true);
  });

  media.addEventListener("change", (event) => {
    if (hasStoredPreference) {
      return;
    }
    apply(event.matches, false);
  });
}

function initializeLiveRefresh() {
  const runningJobs = Number(document.body.getAttribute("data-running-jobs") || "0");
  if (!runningJobs) {
    return;
  }

  window.setTimeout(() => {
    window.location.reload();
  }, 8000);
}

function initializeHashDisclosure() {
  const sync = () => {
    const id = window.location.hash.replace(/^#/, "");
    if (!id) {
      return;
    }
    const target = document.getElementById(id);
    if (target && target.tagName.toLowerCase() === "details") {
      target.open = true;
    }
  };

  window.addEventListener("hashchange", sync);
  sync();
}

function initializeBucketCharts() {
  const charts = Array.from(document.querySelectorAll("[data-bucket-chart]"));
  if (!charts.length) {
    return;
  }

  const render = () => {
    charts.forEach((root) => renderBucketChart(root));
  };

  let frame = 0;
  window.addEventListener("resize", () => {
    window.cancelAnimationFrame(frame);
    frame = window.requestAnimationFrame(render);
  });

  render();
}

function initializePolicyEditors() {
  const editors = Array.from(document.querySelectorAll("[data-policy-editor]"));
  if (!editors.length) {
    return;
  }

  editors.forEach((editor) => {
    const list = editor.querySelector("[data-policy-steps]");
    const orderField = editor.querySelector("[data-policy-order]");
    if (!(list instanceof HTMLElement) || !(orderField instanceof HTMLInputElement)) {
      return;
    }

    const updateOrder = () => {
      const ids = Array.from(list.querySelectorAll("[data-step-id]"))
        .map((item) => item.getAttribute("data-step-id"))
        .filter(Boolean);
      orderField.value = ids.join("|");
    };

    let dragged = null;

    list.querySelectorAll("[data-step-id]").forEach((item) => {
      if (!(item instanceof HTMLElement)) {
        return;
      }

      item.addEventListener("dragstart", () => {
        dragged = item;
        item.classList.add("is-dragging");
      });

      item.addEventListener("dragend", () => {
        item.classList.remove("is-dragging");
        list.querySelectorAll(".is-drop-target").forEach((target) => target.classList.remove("is-drop-target"));
        dragged = null;
        updateOrder();
      });

      item.addEventListener("dragover", (event) => {
        event.preventDefault();
        if (!dragged || dragged === item) {
          return;
        }
        item.classList.add("is-drop-target");
      });

      item.addEventListener("dragleave", () => {
        item.classList.remove("is-drop-target");
      });

      item.addEventListener("drop", (event) => {
        event.preventDefault();
        item.classList.remove("is-drop-target");
        if (!dragged || dragged === item) {
          return;
        }
        const rect = item.getBoundingClientRect();
        const before = event.clientY < rect.top + rect.height / 2;
        list.insertBefore(dragged, before ? item : item.nextSibling);
        updateOrder();
      });
    });

    updateOrder();
  });
}

function renderBucketChart(root) {
  let items = [];
  try {
    items = JSON.parse(root.getAttribute("data-bucket-chart") || "[]");
  } catch (_error) {
    items = [];
  }

  root.innerHTML = "";
  const emptyMessage = root.getAttribute("data-chart-empty") || "No chart data is available.";
  if (!Array.isArray(items) || !items.length) {
    const empty = document.createElement("p");
    empty.className = "bucket-chart__empty";
    empty.textContent = emptyMessage;
    root.append(empty);
    return;
  }

  const tone = root.getAttribute("data-chart-tone") || "accent";
  const max = Math.max(...items.map((item) => Number(bucketCount(item))), 1);

  items.forEach((item) => {
    const labelText = bucketLabel(item);
    const count = bucketCount(item);
    const href = bucketHref(item);
    const row = document.createElement("div");
    row.className = "bucket-chart__row";

    const label = href ? document.createElement("a") : document.createElement("span");
    label.className = "bucket-chart__label";
    label.textContent = labelText;
    if (href) {
      label.href = href;
    }

    const value = document.createElement("span");
    value.className = "bucket-chart__value";
    value.textContent = String(count);

    const track = href ? document.createElement("button") : document.createElement("div");
    track.className = `bucket-chart__track bucket-chart__track--${resolveChartTone(tone, labelText)}`;
    if (href) {
      track.type = "button";
      track.addEventListener("click", () => {
        window.location.href = href;
      });
      track.setAttribute("aria-label", `${labelText} (${count})`);
    }

    const fill = document.createElement("span");
    fill.className = `bucket-chart__fill bucket-chart__fill--${resolveChartTone(tone, labelText)}`;
    fill.style.width = `${Math.max(8, Math.round((count / max) * 100))}%`;
    track.append(fill);

    row.append(label, value, track);
    root.append(row);
  });
}

function bucketLabel(item) {
  return item.label || item.Label || "Unlabeled";
}

function bucketCount(item) {
  return Number(item.count ?? item.Count ?? 0);
}

function bucketHref(item) {
  return item.href || item.Href || "";
}

function resolveChartTone(tone, label) {
  if (tone !== "severity") {
    return tone;
  }

  switch ((label || "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "low":
      return "low";
    case "info":
      return "alt";
    default:
      return "accent";
  }
}

function initializeExplorer() {
  const explorer = document.querySelector("[data-explorer]");
  if (!explorer) {
    return;
  }

  const endpoint = explorer.getAttribute("data-explorer-endpoint");
  if (!endpoint) {
    return;
  }

  wireExplorerNodes(explorer, endpoint);
  syncExplorerActive(explorer);

  const pathScript = explorer.querySelector("[data-explorer-path]");
  if (!pathScript) {
    return;
  }

  let steps = [];
  try {
    steps = JSON.parse(pathScript.textContent || "[]");
  } catch (_error) {
    steps = [];
  }
  if (!Array.isArray(steps) || !steps.length) {
    return;
  }

  expandExplorerPath(explorer, endpoint, steps);
}

function initializeNavigator() {
  const input = document.querySelector("[data-navigator-filter]");
  const empty = document.querySelector("[data-navigator-empty]");
  const items = Array.from(document.querySelectorAll("[data-navigator-item]"));
  const groups = Array.from(document.querySelectorAll("[data-navigator-group]"));
  const current = `${window.location.pathname}${window.location.search}`;

  document.querySelectorAll(".navigator-link").forEach((link) => {
    const href = link.getAttribute("href") || "";
    const active = href === current || href === window.location.pathname;
    link.classList.toggle("is-active", active);
  });

  if (!input || !items.length) {
    return;
  }

  const applyFilter = () => {
    const query = input.value.trim().toLowerCase();
    let visibleItems = 0;

    items.forEach((item) => {
      const haystack = (item.getAttribute("data-navigator-item") || "").toLowerCase();
      const visible = !query || haystack.includes(query);
      item.hidden = !visible;
      if (visible) {
        visibleItems += 1;
      }
    });

    groups.forEach((group) => {
      const hasVisible = Array.from(group.querySelectorAll("[data-navigator-item]")).some((item) => !item.hidden);
      group.hidden = !hasVisible;
    });

    if (empty) {
      empty.hidden = visibleItems > 0;
    }
  };

  input.addEventListener("input", applyFilter);
  applyFilter();
}

function wireExplorerNodes(root, endpoint) {
  root.querySelectorAll(".explorer-node").forEach((node) => {
    if (node.dataset.bound === "true") {
      return;
    }
    node.dataset.bound = "true";

    const row = node.querySelector(":scope > .explorer-node__row");
    if (!row) {
      return;
    }
    const toggle = row.querySelector("[data-explorer-toggle]");
    if (!toggle) {
      return;
    }
    toggle.addEventListener("click", async () => {
      await toggleExplorerNode(node, endpoint, false);
    });
  });
}

async function expandExplorerPath(explorer, endpoint, steps) {
  for (const step of steps) {
    const node = findExplorerNode(explorer, step.kind, step.id);
    if (!node) {
      continue;
    }
    await toggleExplorerNode(node, endpoint, true);
  }
  syncExplorerActive(explorer);
}

function findExplorerNode(explorer, kind, id) {
  return Array.from(explorer.querySelectorAll(".explorer-node")).find(
    (node) => node.dataset.nodeKind === kind && node.dataset.nodeId === id,
  );
}

async function toggleExplorerNode(node, endpoint, forceOpen) {
  const toggle = node.querySelector(":scope > .explorer-node__row [data-explorer-toggle]");
  const list = node.querySelector(":scope > .explorer-list--nested");
  if (!toggle || !list) {
    return;
  }

  const open = toggle.getAttribute("aria-expanded") === "true";
  if (open && !forceOpen) {
    toggle.setAttribute("aria-expanded", "false");
    list.hidden = true;
    return;
  }

  if (node.dataset.loaded !== "true") {
    const kind = node.dataset.nodeKind || "";
    const id = node.dataset.nodeId || "";
    const params = new URLSearchParams({ kind, id });
    const response = await fetch(`${endpoint}?${params.toString()}`);
    if (!response.ok) {
      return;
    }
    const children = await response.json();
    list.innerHTML = "";
    (children || []).forEach((child) => {
      list.append(createExplorerNode(child));
    });
    wireExplorerNodes(list, endpoint);
    node.dataset.loaded = "true";
  }

  toggle.setAttribute("aria-expanded", "true");
  list.hidden = false;
}

function createExplorerNode(node) {
  const item = document.createElement("li");
  item.className = "explorer-node";
  item.dataset.nodeKind = node.kind || "";
  item.dataset.nodeId = node.id || "";
  item.dataset.nodeExpandable = node.expandable ? "true" : "false";

  const row = document.createElement("div");
  row.className = "explorer-node__row";

  if (node.expandable) {
    const toggle = document.createElement("button");
    toggle.className = "explorer-node__toggle";
    toggle.type = "button";
    toggle.setAttribute("data-explorer-toggle", "");
    toggle.setAttribute("aria-expanded", "false");
    const bar = document.createElement("span");
    toggle.append(bar);
    row.append(toggle);
  } else {
    const stub = document.createElement("span");
    stub.className = "explorer-node__stub";
    row.append(stub);
  }

  const link = document.createElement("a");
  link.className = "explorer-node__link";
  link.href = node.href || "#";
  const label = document.createElement("span");
  label.className = "explorer-node__label";
  label.textContent = node.label || "Node";
  link.append(label);
  if (node.meta) {
    const meta = document.createElement("span");
    meta.className = "explorer-node__meta";
    meta.textContent = node.meta;
    link.append(meta);
  }
  row.append(link);

  if (Number(node.count || 0) > 0) {
    const count = document.createElement("span");
    count.className = "explorer-node__count";
    count.textContent = String(node.count);
    row.append(count);
  }

  item.append(row);

  const children = document.createElement("ul");
  children.className = "explorer-list explorer-list--nested";
  children.hidden = true;
  item.append(children);
  return item;
}

function syncExplorerActive(explorer) {
  const current = `${window.location.pathname}${window.location.search}`;
  explorer.querySelectorAll(".explorer-node__link").forEach((link) => {
    const node = link.closest(".explorer-node");
    if (!node) {
      return;
    }
    const href = link.getAttribute("href") || "";
    const active = href === current || href === window.location.pathname;
    node.classList.toggle("is-active", active);
  });
}

async function initializeTopologyGraph() {
  const root = document.querySelector("[data-graph-root]");
  if (!root) {
    return;
  }

  const refs = {
    endpoint: root.getAttribute("data-graph-endpoint"),
    status: document.querySelector("[data-graph-status]"),
    detail: document.querySelector("[data-graph-detail]"),
    mode: document.querySelector("[data-graph-mode]"),
    target: document.querySelector("[data-graph-target]"),
    threshold: document.querySelector("[data-graph-threshold]"),
    spacing: document.querySelector("[data-graph-spacing]"),
    bend: document.querySelector("[data-graph-bend]"),
    search: document.querySelector("[data-graph-search]"),
    shared: document.querySelector("[data-graph-shared]"),
    collapse: document.querySelector("[data-graph-collapse]"),
    prune: document.querySelector("[data-graph-prune]"),
    labels: document.querySelector("[data-graph-labels]"),
  };

  if (
    !refs.endpoint
    || !refs.status
    || !refs.detail
    || !refs.mode
    || !refs.target
    || !refs.threshold
    || !refs.spacing
    || !refs.bend
    || !refs.search
    || !refs.shared
    || !refs.collapse
    || !refs.prune
    || !refs.labels
  ) {
    return;
  }

  if (!window.d3 || !window.d3.behavior || !window.d3.select || !window.d3.layout) {
    refs.status.textContent = "D3 graph support is unavailable.";
    return;
  }

  try {
    const response = await fetch(refs.endpoint);
    const graph = await response.json();
    const context = buildTopologyContext(graph);
    populateTargetOptions(refs.target, context.targets);

    const thresholdMax = Math.max(
      1,
      ...context.edges.map((edge) => edge.count || 1),
      ...context.routes.map((route) => route.count || 1),
    );
    refs.threshold.max = String(thresholdMax);
    refs.threshold.value = String(Math.min(2, thresholdMax));

    const state = {
      mode: refs.mode.value || "backbone",
      target: refs.target.value || "",
      minCount: Number(refs.threshold.value || "1"),
      verticalSpacing: Number(refs.spacing.value || "72"),
      curveBend: Number(refs.bend.value || "26"),
      search: "",
      sharedOnly: refs.shared.checked,
      collapseProviders: refs.collapse.checked,
      pruneSingleUse: refs.prune.checked,
      pinLabels: refs.labels.checked,
      selected: null,
      zoomTranslate: [0, 0],
      zoomScale: 1,
    };

    const render = () => {
      syncGraphState(refs, state, context.targets);
      updateGraphControlState(refs, state, context.targets);
      const width = Math.max(root.clientWidth, 960);
      const view = buildTopologyView(context, state, width);
      renderTopologyGraph(root, refs.status, refs.detail, view, state);
    };

    [
      refs.mode,
      refs.target,
      refs.threshold,
      refs.spacing,
      refs.bend,
      refs.search,
      refs.shared,
      refs.collapse,
      refs.prune,
      refs.labels,
    ].forEach((element) => {
      element.addEventListener("input", render);
      element.addEventListener("change", render);
    });

    window.addEventListener("resize", render);
    render();
  } catch (_error) {
    refs.status.textContent = "Graph data could not be loaded.";
  }
}

function buildTopologyContext(graph) {
  const nodes = new Map();
  (graph.nodes || []).forEach((node) => {
    nodes.set(node.id, {
      id: node.id,
      label: String(node.label || node.id || "Unknown node"),
      count: Number(node.count || 1),
      avg_ttl: Number(node.avg_ttl || 1),
      ttl_level: Math.max(1, Math.round(Number(node.avg_ttl || 1))),
      avg_rtt: Number(node.avg_rtt || 0),
      role: node.role || "transit",
      targets: Number(node.targets || 0),
      icon: node.icon || "unknown",
      os_label: node.os_label || "",
      source: Boolean(node.source),
      hostname: node.hostname || "",
      provider: node.provider || "",
    });
  });

  const edges = (graph.edges || []).map((edge) => ({
    id: `${edge.source}->${edge.target}`,
    source: edge.source,
    target: edge.target,
    count: Number(edge.count || 1),
    avg_rtt: Number(edge.avg_rtt || 0),
  }));
  const edgeByID = new Map(edges.map((edge) => [edge.id, edge]));

  const routes = (graph.routes || [])
    .map((route) => ({
      id: route.id || `${route.target_id}|${(route.hops || []).join(">")}`,
      target_id: route.target_id || "",
      target_label: route.target_label || route.target_id || "Unknown target",
      count: Number(route.count || 1),
      depth: Number(route.depth || (route.hops || []).length || 0),
      hops: Array.isArray(route.hops) ? route.hops.filter(Boolean) : [],
    }))
    .filter((route) => route.hops.length > 0);

  const targetByID = new Map();
  routes.forEach((route) => {
    if (!targetByID.has(route.target_id)) {
      targetByID.set(route.target_id, {
        id: route.target_id,
        label: route.target_label,
        count: 0,
        variants: 0,
        depth: 0,
      });
    }
    const entry = targetByID.get(route.target_id);
    entry.count += route.count;
    entry.variants += 1;
    entry.depth = Math.max(entry.depth, route.depth);
  });

  const targets = Array.from(targetByID.values()).sort((left, right) => {
    if (left.count !== right.count) {
      return right.count - left.count;
    }
    return left.label.localeCompare(right.label);
  });

  return {
    summary: graph.summary || {},
    nodes,
    edges,
    edgeByID,
    routes,
    targets,
  };
}

function populateTargetOptions(select, targets) {
  const current = select.value;
  select.innerHTML = "";

  const defaultOption = document.createElement("option");
  defaultOption.value = "";
  defaultOption.textContent = "All traced targets";
  select.append(defaultOption);

  targets.forEach((target) => {
    const option = document.createElement("option");
    option.value = target.id;
    option.textContent = `${target.label} (${target.count})`;
    select.append(option);
  });

  select.value = targets.some((target) => target.id === current) ? current : "";
}

function syncGraphState(refs, state, targets) {
  state.mode = refs.mode.value || "backbone";
  state.target = refs.target.value || "";
  state.minCount = Number(refs.threshold.value || "1");
  state.verticalSpacing = Number(refs.spacing.value || "72");
  state.curveBend = Number(refs.bend.value || "26");
  state.search = refs.search.value.trim().toLowerCase();
  state.sharedOnly = state.mode === "route" ? false : refs.shared.checked;
  state.collapseProviders = state.mode === "route" ? false : refs.collapse.checked;
  state.pruneSingleUse = state.mode === "route" ? false : refs.prune.checked;
  state.pinLabels = refs.labels.checked;

  if (state.mode === "route" && !state.target && targets.length > 0) {
    state.target = targets[0].id;
    refs.target.value = state.target;
  }
}

function updateGraphControlState(refs, state, targets) {
  refs.target.disabled = targets.length === 0;
  refs.shared.disabled = state.mode === "route";
  refs.collapse.disabled = state.mode === "route";
  refs.prune.disabled = state.mode === "route";
}

function buildTopologyView(context, state, width) {
  if (state.mode === "route") {
    return buildRouteTreeView(context, state, width);
  }
  return buildBackboneView(context, state, width);
}

function buildBackboneView(context, state, width) {
  const routes = filterRoutesByState(context, state);
  if (!routes.length) {
    return emptyTopologyView("No traceroute paths match the current filters.");
  }

  const routeStats = accumulateRouteStats(routes, context);
  const rawDegrees = buildDegreeMap(routeStats.edges);
  const providerGroups = buildProviderGroupSizes(routeStats, context);
  const groupedNodes = new Map();
  const groupedEdges = new Map();

  routeStats.edges.forEach((edge) => {
    const sourceKey = resolveBackboneNodeKey(edge.source, context, routeStats, rawDegrees, providerGroups, state);
    const targetKey = resolveBackboneNodeKey(edge.target, context, routeStats, rawDegrees, providerGroups, state);
    if (!sourceKey || !targetKey || sourceKey === targetKey) {
      return;
    }

    const sourceNode = ensureBackboneNode(groupedNodes, sourceKey, edge.source, context, routeStats);
    const targetNode = ensureBackboneNode(groupedNodes, targetKey, edge.target, context, routeStats);
    if (!sourceNode || !targetNode) {
      return;
    }

    const edgeKey = `${sourceNode.id}->${targetNode.id}`;
    if (!groupedEdges.has(edgeKey)) {
      groupedEdges.set(edgeKey, {
        id: edgeKey,
        source: sourceNode.id,
        target: targetNode.id,
        count: 0,
        rtt_sum: 0,
      });
    }
    const groupedEdge = groupedEdges.get(edgeKey);
    groupedEdge.count += edge.count;
    groupedEdge.rtt_sum += edge.avg_rtt * edge.count;
  });

  if (state.target) {
    routeStats.nodes.forEach((_count, nodeID) => {
      const key = resolveBackboneNodeKey(nodeID, context, routeStats, rawDegrees, providerGroups, state);
      if (key) {
        ensureBackboneNode(groupedNodes, key, nodeID, context, routeStats);
      }
    });
  }

  const links = Array.from(groupedEdges.values())
    .filter((edge) => edge.count >= state.minCount || state.target)
    .map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      count: edge.count,
      avg_rtt: edge.count > 0 ? edge.rtt_sum / edge.count : 0,
    }));

  const connectedNodeIDs = new Set();
  links.forEach((edge) => {
    connectedNodeIDs.add(edge.source);
    connectedNodeIDs.add(edge.target);
  });
  if (state.target && !links.length) {
    groupedNodes.forEach((_node, nodeID) => connectedNodeIDs.add(nodeID));
  }

  const nodes = Array.from(groupedNodes.values())
    .filter((node) => connectedNodeIDs.has(node.id))
    .map((node) => finalizeBackboneNode(node));

  if (!nodes.length) {
    return emptyTopologyView("No backbone nodes remain after the current filters.");
  }

  const degrees = buildDegreeMap(links);
  const nodeByID = new Map(nodes.map((node) => [node.id, node]));
  nodes.forEach((node) => {
    node.degree = degrees.get(node.id) || 0;
  });

  const maxNodeCount = Math.max(1, ...nodes.map((node) => node.count || 1));
  nodes.forEach((node) => {
    node.radius = 6 + (node.count / maxNodeCount) * 11;
  });

  const levels = Array.from(new Set(nodes.map((node) => node.ttl_level))).sort((left, right) => left - right);
  const renderedLinks = links
    .filter((edge) => nodeByID.has(edge.source) && nodeByID.has(edge.target))
    .map((edge) => ({
      id: edge.id,
      source: nodeByID.get(edge.source),
      target: nodeByID.get(edge.target),
      count: edge.count,
      avg_rtt: edge.avg_rtt,
    }));
  const orderedLayers = orderGraphLayers(levels, nodes, renderedLinks);
  const maxLayerSize = Math.max(1, ...orderedLayers.map((layer) => layer.length));
  const height = Math.max(620, Math.min(1680, 150 + Math.max(maxLayerSize - 1, 0) * state.verticalSpacing));

  applyLayeredPositions(width, height, levels, orderedLayers, state.verticalSpacing);

  return {
    mode: "backbone",
    title: state.target ? "Focused backbone" : "Shared backbone",
    width,
    height,
    nodes,
    links: renderedLinks.map((edge) => ({
      id: edge.id,
      source: edge.source.id,
      target: edge.target.id,
      count: edge.count,
      avg_rtt: edge.avg_rtt,
    })),
    laneLevels: levels,
    routeCount: routes.length,
    routeObservations: sumObservations(routes),
    collapsedGroups: nodes.filter((node) => node.grouped).length,
    targetLabel: state.target ? lookupTargetLabel(context.targets, state.target) : "",
    search: state.search,
    status: `${nodes.length} nodes, ${renderedLinks.length} links, ${routes.length} route patterns in scope.`,
    crossings: estimateLayerCrossings(renderedLinks),
  };
}

function buildRouteTreeView(context, state, width) {
  const targetID = state.target || (context.targets[0] ? context.targets[0].id : "");
  if (!targetID) {
    return emptyTopologyView("No traced targets are available for route view.");
  }

  const routes = filterRoutesByState(context, { ...state, target: targetID })
    .filter((route) => route.count >= state.minCount);
  if (!routes.length) {
    return emptyTopologyView("No route variants match the current target and threshold.");
  }

  const root = {
    id: `root:${targetID}`,
    label: "Observed sources",
    virtual: true,
    count: 0,
    path: [],
    children: [],
  };
  const childByKey = new Map();

  routes.forEach((route) => {
    let parent = root;
    route.hops.forEach((hopID, index) => {
      const pathKey = `${parent.id}>${hopID}`;
      if (!childByKey.has(pathKey)) {
        const meta = context.nodes.get(hopID) || fallbackTopologyNode(hopID, index === route.hops.length - 1);
        childByKey.set(pathKey, {
          id: pathKey,
          node_id: hopID,
          label: meta.label,
          count: 0,
          avg_ttl: meta.avg_ttl || (index + 1),
          ttl_level: Math.max(1, index + 1),
          avg_rtt: meta.avg_rtt || 0,
          role: meta.role || (index === route.hops.length - 1 ? "target" : "transit"),
          targets: meta.targets || 0,
          icon: meta.icon || "unknown",
          os_label: meta.os_label || "",
          source: meta.source || index === 0,
          hostname: meta.hostname || "",
          provider: meta.provider || "",
          radius: 0,
          grouped: false,
          members: [hopID],
          path: parent.path.concat(hopID),
          children: [],
        });
        parent.children.push(childByKey.get(pathKey));
      }

      const child = childByKey.get(pathKey);
      child.count += route.count;
      parent = child;
    });
    root.count += route.count;
  });

  const tree = window.d3.layout.tree().children((node) => node.children).nodeSize([
    Math.max(34, state.verticalSpacing * 0.72),
    180,
  ]);
  const treeNodes = tree.nodes(root);
  const treeLinks = tree.links(treeNodes);

  const renderedNodes = treeNodes.filter((node) => !node.virtual);
  const minX = Math.min(...treeNodes.map((node) => node.x));
  const maxX = Math.max(...treeNodes.map((node) => node.x));
  const minY = Math.min(...renderedNodes.map((node) => node.y));
  const maxY = Math.max(...treeNodes.map((node) => node.y));
  const height = Math.max(540, Math.ceil(130 + (maxX - minX)));
  const viewWidth = Math.max(width, Math.ceil(280 + Math.max(maxY - minY, 0)));

  const maxNodeCount = Math.max(1, ...renderedNodes.map((node) => node.count || 1));
  const normalizedNodes = renderedNodes.map((node) => ({
    id: node.id,
    node_id: node.node_id,
    label: node.label,
    count: node.count,
    avg_ttl: node.avg_ttl,
    ttl_level: node.ttl_level,
    avg_rtt: node.avg_rtt,
    role: node.role,
    targets: node.targets,
    icon: node.icon,
    os_label: node.os_label,
    source: node.source,
    hostname: node.hostname,
    provider: node.provider,
    grouped: false,
    members: node.members,
    path: node.path,
    path_labels: node.path.map((hopID) => {
      const entry = context.nodes.get(hopID) || fallbackTopologyNode(hopID, false);
      return entry.label;
    }),
    branching: Boolean(node.children && node.children.length > 1),
    degree: (node.children ? node.children.length : 0) + (node.parent && !node.parent.virtual ? 1 : 0),
    radius: 6 + ((node.count || 1) / maxNodeCount) * 11,
    x: 96 + (node.y - minY),
    y: 58 + (node.x - minX),
  }));

  const normalizedNodeByID = new Map(normalizedNodes.map((node) => [node.id, node]));
  const normalizedLinks = treeLinks
    .filter((edge) => !edge.source.virtual && !edge.target.virtual)
    .map((edge) => ({
      id: `${edge.source.id}->${edge.target.id}`,
      source: edge.source.id,
      target: edge.target.id,
      count: normalizedNodeByID.get(edge.target.id).count,
      avg_rtt: normalizedNodeByID.get(edge.target.id).avg_rtt,
    }));

  return {
    mode: "route",
    title: "Route tree",
    width: viewWidth,
    height,
    nodes: normalizedNodes,
    links: normalizedLinks,
    routeCount: routes.length,
    routeObservations: sumObservations(routes),
    collapsedGroups: 0,
    targetLabel: lookupTargetLabel(context.targets, targetID),
    search: state.search,
    status: `${routes.length} route variants to ${lookupTargetLabel(context.targets, targetID)}.`,
    crossings: 0,
  };
}

function filterRoutesByState(context, state) {
  return context.routes.filter((route) => {
    if (state.target && route.target_id !== state.target) {
      return false;
    }
    if (!state.search) {
      return true;
    }
    return routeMatchesSearch(route, context, state.search);
  });
}

function routeMatchesSearch(route, context, search) {
  if (String(route.target_label || "").toLowerCase().includes(search)) {
    return true;
  }
  return route.hops.some((hopID) => matchesNodeSearch(context.nodes.get(hopID), search));
}

function matchesNodeSearch(node, search) {
  if (!node) {
    return false;
  }
  return [
    node.id,
    node.label,
    node.hostname,
    node.provider,
    node.os_label,
  ].some((value) => String(value || "").toLowerCase().includes(search));
}

function accumulateRouteStats(routes, context) {
  const nodes = new Map();
  const edges = new Map();

  routes.forEach((route) => {
    route.hops.forEach((hopID) => {
      incrementMap(nodes, hopID, route.count);
    });
    for (let index = 0; index < route.hops.length - 1; index += 1) {
      const source = route.hops[index];
      const target = route.hops[index + 1];
      const edgeID = `${source}->${target}`;
      if (!edges.has(edgeID)) {
        const baseEdge = context.edgeByID.get(edgeID);
        edges.set(edgeID, {
          id: edgeID,
          source,
          target,
          count: 0,
          avg_rtt: baseEdge ? Number(baseEdge.avg_rtt || 0) : 0,
        });
      }
      edges.get(edgeID).count += route.count;
    }
  });

  return {
    nodes,
    edges: Array.from(edges.values()),
  };
}

function buildDegreeMap(edges) {
  const degrees = new Map();
  edges.forEach((edge) => {
    incrementMap(degrees, edge.source, 1);
    incrementMap(degrees, edge.target, 1);
  });
  return degrees;
}

function buildProviderGroupSizes(routeStats, context) {
  const groups = new Map();
  routeStats.nodes.forEach((_count, nodeID) => {
    const node = context.nodes.get(nodeID);
    if (!node || node.source || node.role !== "transit" || !node.provider) {
      return;
    }
    const key = `${node.ttl_level}|${node.provider}`;
    incrementMap(groups, key, 1);
  });
  return groups;
}

function resolveBackboneNodeKey(nodeID, context, routeStats, rawDegrees, providerGroups, state) {
  const meta = context.nodes.get(nodeID);
  if (!meta) {
    return "";
  }
  if (!shouldIncludeBackboneNode(nodeID, meta, routeStats, rawDegrees, state)) {
    return "";
  }
  if (!state.collapseProviders || state.target || meta.source || meta.role !== "transit" || !meta.provider) {
    return nodeID;
  }
  const groupKey = `${meta.ttl_level}|${meta.provider}`;
  if ((providerGroups.get(groupKey) || 0) < 2) {
    return nodeID;
  }
  return `group:${groupKey}`;
}

function shouldIncludeBackboneNode(nodeID, meta, routeStats, rawDegrees, state) {
  if (state.target) {
    return routeStats.nodes.has(nodeID);
  }

  const count = routeStats.nodes.get(nodeID) || 0;
  const degree = rawDegrees.get(nodeID) || 0;
  if (meta.source) {
    return true;
  }
  if (meta.role === "target" || meta.role === "mixed") {
    if (!state.sharedOnly) {
      return count >= state.minCount;
    }
    return count >= Math.max(2, state.minCount);
  }
  if (count < state.minCount) {
    return false;
  }
  if (state.pruneSingleUse && count <= 1 && degree <= 2) {
    return false;
  }
  if (state.sharedOnly && count < 2 && degree < 3) {
    return false;
  }
  return true;
}

function ensureBackboneNode(groupedNodes, key, rawNodeID, context, routeStats) {
  const meta = context.nodes.get(rawNodeID);
  if (!meta) {
    return null;
  }
  if (!groupedNodes.has(key)) {
    groupedNodes.set(key, {
      id: key,
      node_id: rawNodeID,
      label: key.startsWith("group:")
        ? `${formatProviderLabel(meta.provider)} transit`
        : meta.label,
      count: 0,
      ttl_sum: 0,
      rtt_sum: 0,
      targets: 0,
      icon: key.startsWith("group:") ? guessProviderIcon(meta.provider, meta.icon) : meta.icon,
      os_label: key.startsWith("group:") ? "Collapsed provider transit" : meta.os_label,
      source: meta.source,
      role: meta.role,
      hostname: key.startsWith("group:") ? "" : meta.hostname,
      provider: meta.provider,
      grouped: key.startsWith("group:"),
      members: [],
    });
  }

  const node = groupedNodes.get(key);
  const weight = routeStats.nodes.get(rawNodeID) || meta.count || 1;
  node.count += weight;
  node.ttl_sum += (meta.avg_ttl || 1) * weight;
  node.rtt_sum += (meta.avg_rtt || 0) * weight;
  node.targets += Number(meta.targets || 0);
  node.source = node.source || meta.source;
  node.role = mergeNodeRole(node.role, meta.role);
  if (!node.members.includes(rawNodeID)) {
    node.members.push(rawNodeID);
  }
  if (!node.hostname && meta.hostname && !node.grouped) {
    node.hostname = meta.hostname;
  }
  return node;
}

function finalizeBackboneNode(node) {
  const avgCount = Math.max(node.count, 1);
  return {
    id: node.id,
    node_id: node.node_id,
    label: node.label,
    count: node.count,
    avg_ttl: node.ttl_sum / avgCount,
    ttl_level: Math.max(1, Math.round(node.ttl_sum / avgCount)),
    avg_rtt: node.rtt_sum / avgCount,
    role: node.source ? "source" : node.role,
    targets: node.targets,
    icon: node.icon,
    os_label: node.os_label,
    source: node.source,
    hostname: node.hostname,
    provider: node.provider,
    grouped: node.grouped,
    members: node.members,
  };
}

function mergeNodeRole(current, incoming) {
  if (current === "source" || incoming === "source") {
    return "source";
  }
  if (!current) {
    return incoming || "transit";
  }
  if (!incoming || current === incoming) {
    return current;
  }
  if (current === "transit") {
    return incoming;
  }
  if (incoming === "transit") {
    return current;
  }
  return "mixed";
}

function fallbackTopologyNode(hopID, target) {
  return {
    id: hopID,
    label: hopID,
    count: 1,
    avg_ttl: 1,
    avg_rtt: 0,
    role: target ? "target" : "transit",
    targets: target ? 1 : 0,
    icon: "unknown",
    os_label: "",
    source: false,
    hostname: "",
    provider: "",
  };
}

function renderTopologyGraph(root, status, detail, view, state) {
  root.innerHTML = "";

  if (!view.nodes || view.nodes.length === 0) {
    status.textContent = view.status || "No graph elements match the current filters.";
    renderGraphInspector(detail, view, null, null, null);
    return;
  }

  const svg = window.d3
    .select(root)
    .append("svg")
    .attr("class", "graph-svg")
    .attr("viewBox", `0 0 ${view.width} ${view.height}`);

  const viewport = svg.append("g").attr("class", "graph-viewport");
  const zoom = window.d3.behavior.zoom().scaleExtent([0.35, 2.5]).on("zoom", () => {
    state.zoomTranslate = window.d3.event.translate.slice();
    state.zoomScale = window.d3.event.scale;
    viewport.attr(
      "transform",
      `translate(${state.zoomTranslate[0]},${state.zoomTranslate[1]}) scale(${state.zoomScale})`,
    );
  });

  svg.call(zoom).on("dblclick.zoom", null);
  if (state.zoomTranslate && state.zoomScale) {
    zoom.translate(state.zoomTranslate);
    zoom.scale(state.zoomScale);
    viewport.attr(
      "transform",
      `translate(${state.zoomTranslate[0]},${state.zoomTranslate[1]}) scale(${state.zoomScale})`,
    );
  }

  viewport
    .append("rect")
    .attr("x", -view.width)
    .attr("y", -view.height)
    .attr("width", view.width * 3)
    .attr("height", view.height * 3)
    .style("fill", "transparent");

  if (view.mode === "backbone") {
    renderBackboneGuides(viewport, view, view.width, view.height);
  }

  const nodeByID = new Map(view.nodes.map((node) => [node.id, node]));
  const links = view.links
    .filter((edge) => nodeByID.has(edge.source) && nodeByID.has(edge.target))
    .map((edge) => ({
      id: edge.id,
      source: nodeByID.get(edge.source),
      target: nodeByID.get(edge.target),
      count: edge.count,
      avg_rtt: edge.avg_rtt,
    }));

  const adjacency = buildAdjacencyMap(links);
  const maxEdgeCount = Math.max(1, ...links.map((edge) => edge.count || 1));
  const routeState = view.mode === "backbone" ? buildLinkRouteState(links) : null;

  const linkLayer = viewport.append("g").attr("class", "graph-links");
  const labelLayer = viewport.append("g").attr("class", "graph-labels");
  const nodeLayer = viewport.append("g").attr("class", "graph-nodes");

  const link = linkLayer
    .selectAll("path")
    .data(links)
    .enter()
    .append("path")
    .attr("class", "graph-link")
    .attr("fill", "none")
    .attr("stroke", "rgba(119, 198, 255, 0.34)")
    .attr("stroke-linecap", "round")
    .attr("stroke-width", (edge) => 1 + (edge.count / maxEdgeCount) * 3.4)
    .attr("d", (edge) => (view.mode === "backbone"
      ? buildLinkPath(edge, routeState, state.curveBend)
      : buildTreeLinkPath(edge)));

  link
    .append("title")
    .text((edge) => `${edge.source.label} -> ${edge.target.label} | seen ${edge.count} times | avg RTT ${formatFloat(edge.avg_rtt)} ms`);

  const node = nodeLayer
    .selectAll("g")
    .data(view.nodes)
    .enter()
    .append("g")
    .attr("class", (entry) => `graph-node${entry.grouped ? " graph-node--group" : ""}`)
    .attr("transform", (entry) => `translate(${entry.x},${entry.y})`);

  node
    .append("circle")
    .attr("class", "graph-node-shell")
    .attr("r", (entry) => entry.radius)
    .attr("fill", "#11181d")
    .attr("stroke", (entry) => graphNodeStrokeColor(entry))
    .attr("stroke-width", 1.6);

  node
    .append("image")
    .attr("class", "graph-node-icon")
    .attr("xlink:href", (entry) => graphNodeIconHref(entry.icon))
    .attr("width", (entry) => graphNodeIconSize(entry))
    .attr("height", (entry) => graphNodeIconSize(entry))
    .attr("x", (entry) => -(graphNodeIconSize(entry) / 2))
    .attr("y", (entry) => -(graphNodeIconSize(entry) / 2));

  node
    .append("title")
    .text((entry) => `${entry.label} | seen ${entry.count} times | avg RTT ${formatFloat(entry.avg_rtt)} ms`);

  const labels = labelLayer
    .selectAll("text")
    .data(view.nodes)
    .enter()
    .append("text")
    .attr("class", "graph-node-label")
    .attr("x", (entry) => entry.x + entry.radius + 6)
    .attr("y", (entry) => entry.y + 4)
    .text((entry) => entry.grouped ? `${entry.label} (${entry.members.length})` : entry.label);

  const visibleNodeIDs = new Set(view.nodes.map((entry) => entry.id));
  if (state.selected) {
    if (state.selected.type === "node" && !visibleNodeIDs.has(state.selected.id)) {
      state.selected = null;
    }
    if (state.selected.type === "edge" && !links.some((edge) => edge.id === state.selected.id)) {
      state.selected = null;
    }
  }

  function isSameSelection(left, right) {
    return Boolean(left && right && left.type === right.type && left.id === right.id);
  }

  function applyFocus(hovered) {
    const focus = state.selected || hovered;
    const activeNodeIDs = new Set();
    const activeEdgeIDs = new Set();

    if (focus) {
      if (focus.type === "node") {
        activeNodeIDs.add(focus.id);
        (adjacency.get(focus.id) || []).forEach((neighborID) => activeNodeIDs.add(neighborID));
        links.forEach((edge) => {
          if (edge.source.id === focus.id || edge.target.id === focus.id) {
            activeEdgeIDs.add(edge.id);
          }
        });
      } else if (focus.type === "edge") {
        const selectedEdge = links.find((edge) => edge.id === focus.id);
        if (selectedEdge) {
          activeEdgeIDs.add(selectedEdge.id);
          activeNodeIDs.add(selectedEdge.source.id);
          activeNodeIDs.add(selectedEdge.target.id);
        }
      }
    }

    node
      .classed("is-muted", (entry) => Boolean(focus) && !activeNodeIDs.has(entry.id))
      .classed("is-selected", (entry) => isSameSelection(state.selected, { type: "node", id: entry.id }))
      .classed("is-hovered", (entry) => !state.selected && isSameSelection(hovered, { type: "node", id: entry.id }));

    link
      .classed("is-muted", (edge) => Boolean(focus) && !activeEdgeIDs.has(edge.id))
      .classed("is-selected", (edge) => isSameSelection(state.selected, { type: "edge", id: edge.id }))
      .classed("is-adjacent", (edge) => {
        if (state.selected && state.selected.type === "node") {
          return edge.source.id === state.selected.id || edge.target.id === state.selected.id;
        }
        if (!state.selected && hovered && hovered.type === "node") {
          return edge.source.id === hovered.id || edge.target.id === hovered.id;
        }
        return false;
      });

    labels
      .classed("is-muted", (entry) => Boolean(focus) && !activeNodeIDs.has(entry.id))
      .style("display", (entry) => (shouldShowNodeLabel(entry, state, view, focus) ? "block" : "none"));

    renderGraphInspector(detail, view, focus, nodeByID, links);
  }

  node
    .on("mouseenter", function handleNodeEnter(entry) {
      applyFocus({ type: "node", id: entry.id });
    })
    .on("mouseleave", function handleNodeLeave() {
      applyFocus(null);
    })
    .on("click", function handleNodeClick(entry) {
      window.d3.event.stopPropagation();
      state.selected = isSameSelection(state.selected, { type: "node", id: entry.id })
        ? null
        : { type: "node", id: entry.id };
      applyFocus(null);
    });

  link
    .on("mouseenter", function handleEdgeEnter(edge) {
      applyFocus({ type: "edge", id: edge.id });
    })
    .on("mouseleave", function handleEdgeLeave() {
      applyFocus(null);
    })
    .on("click", function handleEdgeClick(edge) {
      window.d3.event.stopPropagation();
      state.selected = isSameSelection(state.selected, { type: "edge", id: edge.id })
        ? null
        : { type: "edge", id: edge.id };
      applyFocus(null);
    });

  svg.on("click", () => {
    state.selected = null;
    applyFocus(null);
  });

  applyFocus(null);

  if (view.mode === "backbone") {
    status.textContent = `${view.status} ${view.collapsedGroups} provider groups collapsed. ${view.crossings} estimated crossings after ordering.`;
  } else {
    status.textContent = `${view.status} Hover to inspect a branch; click to pin it.`;
  }
}

function renderBackboneGuides(viewport, view, width, height) {
  const laneGuides = viewport.append("g").attr("class", "graph-guides");
  const maxTTL = Math.max(1, ...view.laneLevels);

  for (let ttl = 1; ttl <= maxTTL; ttl += 1) {
    const guideX = width * (0.12 + 0.76 * ((ttl - 1) / Math.max(maxTTL - 1, 1)));
    laneGuides
      .append("line")
      .attr("x1", guideX)
      .attr("x2", guideX)
      .attr("y1", 36)
      .attr("y2", height - 28)
      .attr("stroke", "rgba(255,255,255,0.05)")
      .attr("stroke-dasharray", "2,6");

    laneGuides
      .append("text")
      .attr("x", guideX)
      .attr("y", 20)
      .attr("text-anchor", "middle")
      .attr("class", "graph-legend")
      .text(`TTL ${ttl}`);
  }
}

function renderGraphInspector(detail, view, focus, nodeByID, links) {
  if (!detail) {
    return;
  }

  if (!focus || !nodeByID || !links) {
    detail.innerHTML = [
      `<div class="graph-detail__section">`,
      `<p class="eyebrow">${escapeHTML(view.mode === "route" ? "Route tree" : "Backbone")}</p>`,
      `<h3 class="graph-detail__title">${escapeHTML(view.title || "Topology view")}</h3>`,
      `<div class="graph-detail__meta">`,
      inspectorRow("Visible nodes", formatNumber(view.nodes ? view.nodes.length : 0)),
      inspectorRow("Visible links", formatNumber(view.links ? view.links.length : 0)),
      inspectorRow("Route patterns", formatNumber(view.routeCount || 0)),
      inspectorRow("Observed paths", formatNumber(view.routeObservations || 0)),
      view.targetLabel ? inspectorRow("Target", escapeHTML(view.targetLabel)) : "",
      view.collapsedGroups ? inspectorRow("Collapsed groups", formatNumber(view.collapsedGroups)) : "",
      `</div>`,
      `<p class="graph-detail__note">Hover to inspect route context. Click a node or edge to pin it while you pan or zoom.</p>`,
      `</div>`,
    ].join("");
    return;
  }

  if (focus.type === "node") {
    const node = nodeByID.get(focus.id);
    if (!node) {
      renderGraphInspector(detail, view, null, null, null);
      return;
    }

    const connected = links
      .filter((edge) => edge.source.id === node.id || edge.target.id === node.id)
      .map((edge) => (edge.source.id === node.id ? edge.target.label : edge.source.label))
      .slice(0, 6);

    const pathMarkup = Array.isArray(node.path_labels) && node.path_labels.length > 0
      ? [
        `<ol class="graph-detail__path">`,
        ...node.path_labels.map((label) => `<li>${escapeHTML(label)}</li>`),
        `</ol>`,
      ].join("")
      : "";

    const memberMarkup = node.members && node.members.length > 1
      ? `<p class="graph-detail__pill">${escapeHTML(`${node.members.length} grouped nodes`)}</p>`
      : "";

    detail.innerHTML = [
      `<div class="graph-detail__section">`,
      `<p class="eyebrow">${escapeHTML(prettyRole(node.role))}</p>`,
      `<h3 class="graph-detail__title">${escapeHTML(node.label)}</h3>`,
      memberMarkup,
      `<div class="graph-detail__meta">`,
      inspectorRow("Seen", formatNumber(node.count)),
      inspectorRow("Avg RTT", `${formatFloat(node.avg_rtt)} ms`),
      inspectorRow("Avg TTL", formatFloat(node.avg_ttl)),
      inspectorRow("Provider", escapeHTML(node.provider || "Unclassified")),
      inspectorRow("OS", escapeHTML(node.os_label || "Unknown")),
      inspectorRow("Connected", formatNumber(connected.length)),
      `</div>`,
      pathMarkup,
      connected.length ? `<p class="graph-detail__note">Adjacent: ${escapeHTML(connected.join(", "))}</p>` : "",
      `</div>`,
    ].join("");
    return;
  }

  const edge = links.find((entry) => entry.id === focus.id);
  if (!edge) {
    renderGraphInspector(detail, view, null, null, null);
    return;
  }

  detail.innerHTML = [
    `<div class="graph-detail__section">`,
    `<p class="eyebrow">Edge</p>`,
    `<h3 class="graph-detail__title">${escapeHTML(edge.source.label)} &rarr; ${escapeHTML(edge.target.label)}</h3>`,
    `<div class="graph-detail__meta">`,
    inspectorRow("Seen", formatNumber(edge.count)),
    inspectorRow("Avg RTT", `${formatFloat(edge.avg_rtt)} ms`),
    inspectorRow("Source", escapeHTML(edge.source.label)),
    inspectorRow("Target", escapeHTML(edge.target.label)),
    `</div>`,
    `<p class="graph-detail__note">Use pinned edges to inspect repeated transit links without losing your zoom state.</p>`,
    `</div>`,
  ].join("");
}

function inspectorRow(label, value) {
  return `<div class="graph-detail__row"><span>${escapeHTML(label)}</span><span>${value}</span></div>`;
}

function shouldShowNodeLabel(node, state, view, focus) {
  if (state.pinLabels) {
    return true;
  }
  if (focus && focus.type === "node") {
    return node.id === focus.id;
  }
  if (focus && focus.type === "edge") {
    return false;
  }
  if (state.search && matchesNodeSearch(node, state.search)) {
    return true;
  }
  if (view.mode === "route") {
    return node.source || node.role === "target" || node.branching;
  }
  return node.source || node.role === "target" || node.degree >= 4 || node.grouped;
}

function graphNodeStrokeColor(node) {
  if (node.role === "source" || node.source) {
    return "#9fe3bf";
  }
  if (node.role === "target") {
    return "#ff8b73";
  }
  if (node.role === "mixed") {
    return "#ffc766";
  }
  return "#77c6ff";
}

function graphNodeIconHref(icon) {
  switch (icon) {
    case "home":
      return "/images/graph_home.svg";
    case "windows":
      return "/images/graph_windows.svg";
    case "linux":
      return "/images/graph_linux.svg";
    case "cisco":
      return "/images/graph_cisco.svg";
    case "linksys":
      return "/images/graph_linksys.svg";
    default:
      return "/images/graph_unknown.svg";
  }
}

function graphNodeIconSize(node) {
  return Math.max(16, node.radius * 1.55);
}

function buildAdjacencyMap(links) {
  const adjacency = new Map();
  links.forEach((edge) => {
    if (!adjacency.has(edge.source.id)) {
      adjacency.set(edge.source.id, []);
    }
    if (!adjacency.has(edge.target.id)) {
      adjacency.set(edge.target.id, []);
    }
    adjacency.get(edge.source.id).push(edge.target.id);
    adjacency.get(edge.target.id).push(edge.source.id);
  });
  return adjacency;
}

function buildLinkRouteState(links) {
  const byNode = new Map();
  links.forEach((edge) => {
    const key = graphEdgeKey(edge);
    registerNodeRoute(byNode, edge.source, edge.target, key);
    registerNodeRoute(byNode, edge.target, edge.source, key);
  });

  const slots = new Map();
  byNode.forEach((entries, nodeID) => {
    entries.sort((left, right) => left.angle - right.angle);
    const midpoint = (entries.length - 1) / 2;
    entries.forEach((entry, index) => {
      slots.set(`${nodeID}|${entry.key}`, index - midpoint);
    });
  });
  return slots;
}

function registerNodeRoute(byNode, node, other, key) {
  if (!byNode.has(node.id)) {
    byNode.set(node.id, []);
  }
  byNode.get(node.id).push({
    key,
    angle: other.y - node.y,
  });
}

function buildLinkPath(edge, routeState, bend) {
  const key = graphEdgeKey(edge);
  const sourceSlot = routeState.get(`${edge.source.id}|${key}`) || 0;
  const targetSlot = routeState.get(`${edge.target.id}|${key}`) || 0;

  const dx = edge.target.x - edge.source.x;
  const dy = edge.target.y - edge.source.y;
  const distance = Math.max(Math.sqrt(dx * dx + dy * dy), 0.01);
  const ux = dx / distance;
  const uy = dy / distance;
  const tx = -uy;
  const ty = ux;

  const sourceAnchor = edgeAnchor(edge.source, ux, uy, tx, ty, sourceSlot);
  const targetAnchor = edgeAnchor(edge.target, -ux, -uy, tx, ty, targetSlot);
  const curvatureBase = Math.min(bend, Math.max(10, distance * 0.12));
  const curvatureBias = ((sourceSlot - targetSlot) * 7) + (graphEdgeSign(key) * curvatureBase);
  const c1 = {
    x: sourceAnchor.x + (ux * distance * 0.26) + (tx * (sourceSlot * 9 + curvatureBias * 0.45)),
    y: sourceAnchor.y + (uy * distance * 0.26) + (ty * (sourceSlot * 9 + curvatureBias * 0.45)),
  };
  const c2 = {
    x: targetAnchor.x - (ux * distance * 0.26) + (tx * (targetSlot * 9 + curvatureBias * 0.45)),
    y: targetAnchor.y - (uy * distance * 0.26) + (ty * (targetSlot * 9 + curvatureBias * 0.45)),
  };

  return `M ${sourceAnchor.x} ${sourceAnchor.y} C ${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${targetAnchor.x} ${targetAnchor.y}`;
}

function buildTreeLinkPath(edge) {
  const sourceX = edge.source.x;
  const sourceY = edge.source.y;
  const targetX = edge.target.x;
  const targetY = edge.target.y;
  const midX = sourceX + ((targetX - sourceX) * 0.52);

  return `M ${sourceX} ${sourceY} C ${midX} ${sourceY}, ${midX} ${targetY}, ${targetX} ${targetY}`;
}

function edgeAnchor(node, ux, uy, tx, ty, slot) {
  const radial = node.radius + 4;
  const tangentOffset = slot * Math.max(4, Math.min(9, node.radius * 0.5));
  return {
    x: node.x + (ux * radial) + (tx * tangentOffset),
    y: node.y + (uy * radial) + (ty * tangentOffset),
  };
}

function graphEdgeKey(edge) {
  return `${edge.source.id}->${edge.target.id}`;
}

function graphEdgeSign(key) {
  let hash = 0;
  for (let index = 0; index < key.length; index += 1) {
    hash = ((hash << 5) - hash) + key.charCodeAt(index);
    hash |= 0;
  }
  return Math.abs(hash) % 2 === 0 ? 1 : -1;
}

function orderGraphLayers(levels, nodes, links) {
  const layers = levels.map((level) =>
    nodes
      .filter((node) => node.ttl_level === level)
      .sort((left, right) => {
        if (left.role !== right.role) {
          return roleOrder(left.role) - roleOrder(right.role);
        }
        return left.label.localeCompare(right.label);
      }),
  );

  const predecessors = new Map();
  const successors = new Map();
  links.forEach((edge) => {
    if (!predecessors.has(edge.target.id)) {
      predecessors.set(edge.target.id, []);
    }
    if (!successors.has(edge.source.id)) {
      successors.set(edge.source.id, []);
    }
    predecessors.get(edge.target.id).push(edge.source.id);
    successors.get(edge.source.id).push(edge.target.id);
  });

  for (let pass = 0; pass < 8; pass += 1) {
    for (let index = 1; index < layers.length; index += 1) {
      sortLayerByNeighbors(layers[index], predecessors, indexPositions(layers[index - 1]));
    }
    for (let index = layers.length - 2; index >= 0; index -= 1) {
      sortLayerByNeighbors(layers[index], successors, indexPositions(layers[index + 1]));
    }
  }

  return layers;
}

function sortLayerByNeighbors(layer, neighborMap, referencePositions) {
  const decorated = layer.map((node, index) => {
    const neighbors = (neighborMap.get(node.id) || []).filter((id) => referencePositions.has(id));
    if (!neighbors.length) {
      return { node, barycenter: Number.POSITIVE_INFINITY, index };
    }

    const total = neighbors.reduce((sum, id) => sum + referencePositions.get(id), 0);
    return { node, barycenter: total / neighbors.length, index };
  });

  decorated.sort((left, right) => {
    if (left.barycenter !== right.barycenter) {
      return left.barycenter - right.barycenter;
    }
    if (left.node.role !== right.node.role) {
      return roleOrder(left.node.role) - roleOrder(right.node.role);
    }
    if (left.node.label !== right.node.label) {
      return left.node.label.localeCompare(right.node.label);
    }
    return left.index - right.index;
  });

  for (let index = 0; index < layer.length; index += 1) {
    layer[index] = decorated[index].node;
  }
}

function indexPositions(layer) {
  const positions = new Map();
  layer.forEach((node, index) => {
    positions.set(node.id, index);
  });
  return positions;
}

function roleOrder(role) {
  switch (role) {
    case "source":
      return 0;
    case "mixed":
      return 1;
    case "target":
      return 2;
    default:
      return 3;
  }
}

function applyLayeredPositions(width, height, levels, layers, verticalSpacing) {
  const leftMargin = 90;
  const rightMargin = 110;
  const topMargin = 50;
  const bottomMargin = 40;
  const layerGap = levels.length <= 1 ? 0 : (width - leftMargin - rightMargin) / Math.max(levels.length - 1, 1);

  layers.forEach((layer, layerIndex) => {
    const totalSpan = Math.max((layer.length - 1) * verticalSpacing, 0);
    const startY = topMargin + Math.max(((height - topMargin - bottomMargin) - totalSpan) / 2, 0);
    layer.forEach((node, nodeIndex) => {
      node.x = leftMargin + layerIndex * layerGap;
      node.y = startY + nodeIndex * verticalSpacing;
    });
  });
}

function estimateLayerCrossings(links) {
  let crossings = 0;
  for (let left = 0; left < links.length; left += 1) {
    for (let right = left + 1; right < links.length; right += 1) {
      const a = links[left];
      const b = links[right];
      if (a.source.ttl_level !== b.source.ttl_level || a.target.ttl_level !== b.target.ttl_level) {
        continue;
      }
      const sourceOrder = Math.sign(a.source.y - b.source.y);
      const targetOrder = Math.sign(a.target.y - b.target.y);
      if (sourceOrder !== 0 && targetOrder !== 0 && sourceOrder !== targetOrder) {
        crossings += 1;
      }
    }
  }
  return crossings;
}

function incrementMap(map, key, value) {
  map.set(key, (map.get(key) || 0) + value);
}

function sumObservations(routes) {
  return routes.reduce((sum, route) => sum + (route.count || 0), 0);
}

function formatProviderLabel(provider) {
  return String(provider || "Unclassified").replace(/\b[a-z]/g, (match) => match.toUpperCase());
}

function guessProviderIcon(provider, fallback) {
  const label = String(provider || "").toLowerCase();
  if (label.includes("cisco")) {
    return "cisco";
  }
  if (label.includes("linksys")) {
    return "linksys";
  }
  return fallback || "unknown";
}

function lookupTargetLabel(targets, targetID) {
  const target = targets.find((entry) => entry.id === targetID);
  return target ? target.label : targetID;
}

function prettyRole(role) {
  switch (role) {
    case "source":
      return "Source-side node";
    case "target":
      return "Target node";
    case "mixed":
      return "Transit and target";
    default:
      return "Transit node";
  }
}

function emptyTopologyView(message) {
  return {
    mode: "backbone",
    title: "Topology",
    width: 960,
    height: 620,
    nodes: [],
    links: [],
    routeCount: 0,
    routeObservations: 0,
    collapsedGroups: 0,
    targetLabel: "",
    search: "",
    status: message,
    crossings: 0,
  };
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatFloat(value) {
  return Number(value || 0).toFixed(2);
}

function escapeHTML(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-live-stream]").forEach((element) => {
    const endpoint = element.getAttribute("data-live-stream");
    if (!endpoint || typeof EventSource === "undefined") {
      return;
    }
    const source = new EventSource(endpoint);
    source.addEventListener("stats", (event) => {
      try {
        const stats = JSON.parse(event.data);
        const cards = document.querySelectorAll(".platform-stat-card strong");
        stats.forEach((item, index) => {
          if (cards[index]) {
            cards[index].textContent = item.value;
          }
        });
      } catch (error) {
        console.error("platform stream parse failed", error);
      }
    });
    source.onerror = () => {
      source.close();
    };
  });
});
