import { memo, useEffect, useMemo } from "react";
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  type Edge,
  type Node,
  type NodeProps,
  useEdgesState,
  useNodesState,
} from "reactflow";

import type { OrchestrationPolicy, TopologyGraph } from "./api";

type TopologyNodeData = {
  label: string;
  role: string;
  count: number;
  detail: string;
  focused: boolean;
  selected: boolean;
};

type PolicyTriggerData = {
  label: string;
  detail: string;
};

type PolicyStepData = {
  stepId: string;
  label: string;
  pluginId: string;
  stage: string;
  summary: string;
  enabled: boolean;
  laneKey: string;
  selected: boolean;
};

const topologyNodeTypes = {
  topology: memo(function TopologyNodeCard({ data }: NodeProps<TopologyNodeData>) {
    return (
      <div className={`cc-flow-node cc-flow-node--topology ${data.focused ? "is-focused" : "is-dimmed"} ${data.selected ? "is-selected" : ""}`}>
        <Handle position={Position.Left} type="target" />
        <div className="cc-flow-node__eyebrow">{data.role}</div>
        <strong>{data.label}</strong>
        <small>{data.detail}</small>
        <span>{data.count} observations</span>
        <Handle position={Position.Right} type="source" />
      </div>
    );
  }),
};

const policyNodeTypes = {
  trigger: memo(function PolicyTriggerNode({ data }: NodeProps<PolicyTriggerData>) {
    return (
      <div className="cc-flow-node cc-flow-node--trigger">
        <Handle position={Position.Right} type="source" />
        <div className="cc-flow-node__eyebrow">Trigger</div>
        <strong>{data.label}</strong>
        <small>{data.detail}</small>
      </div>
    );
  }),
  step: memo(function PolicyStepNode({ data }: NodeProps<PolicyStepData>) {
    return (
      <div className={`cc-flow-node cc-flow-node--step ${data.enabled ? "" : "is-disabled"} ${data.selected ? "is-selected" : ""}`}>
        <Handle position={Position.Left} type="target" />
        <div className="cc-flow-node__eyebrow">{data.pluginId}</div>
        <strong>{data.label}</strong>
        <small>{data.stage}</small>
        <span>{data.summary || "No step summary"}</span>
        <Handle position={Position.Right} type="source" />
      </div>
    );
  }),
};

function laneKeyForStep(step: OrchestrationPolicy["steps"][number]) {
  if (step.trigger === "kickoff") {
    return "kickoff";
  }
  const parts = ["after-job", step.whenPlugin || "any"];
  if (step.whenProfile) {
    parts.push(step.whenProfile);
  }
  return parts.join(":");
}

function laneLabelForStep(step: OrchestrationPolicy["steps"][number]) {
  if (step.trigger === "kickoff") {
    return "Kickoff";
  }
  const condition = [step.whenPlugin || "any tool", step.whenProfile || ""].filter(Boolean).join(" / ");
  return `After ${condition}`;
}

function roleTone(role: string) {
  switch (role) {
    case "source":
      return "#7ee0c8";
    case "target":
      return "#f0b85a";
    case "mixed":
      return "#7db2ff";
    default:
      return "#8ea0a8";
  }
}

function buildTopologyElements(
  topology: TopologyGraph,
  focusRouteId: string,
  minEdgeCount: number,
  roleFilter: string,
  selectedNodeId: string,
) {
  const focusRoute = topology.routes.find((route) => route.id === focusRouteId);
  const focusNodeIDs = new Set(focusRoute ? focusRoute.hops : []);
  const focusEdgeIDs = new Set<string>();
  if (focusRoute) {
    for (let index = 1; index < focusRoute.hops.length; index += 1) {
      focusEdgeIDs.add(`${focusRoute.hops[index - 1]}->${focusRoute.hops[index]}`);
    }
  }

  let visibleNodes = topology.nodes.filter((node) => {
    if (focusRoute) {
      return focusNodeIDs.has(node.id);
    }
    if (roleFilter !== "all" && node.role !== roleFilter) {
      return false;
    }
    return true;
  });

  let visibleEdges = topology.edges.filter((edge) => {
    const id = `${edge.source}->${edge.target}`;
    if (focusRoute) {
      return focusEdgeIDs.has(id);
    }
    if (edge.count < minEdgeCount) {
      return false;
    }
    return true;
  });

  if (!focusRoute) {
    const edgeNodeIDs = new Set<string>();
    for (const edge of visibleEdges) {
      edgeNodeIDs.add(edge.source);
      edgeNodeIDs.add(edge.target);
    }
    visibleNodes = visibleNodes.filter((node) => edgeNodeIDs.has(node.id));
  }

  const cappedNodes = visibleNodes
    .slice()
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
    .slice(0, focusRoute ? visibleNodes.length : 260);
  const cappedIDs = new Set(cappedNodes.map((node) => node.id));
  visibleEdges = visibleEdges.filter((edge) => cappedIDs.has(edge.source) && cappedIDs.has(edge.target));

  const laneMap = new Map<number, typeof cappedNodes>();
  for (const node of cappedNodes) {
    const lane = focusRoute ? focusRoute.hops.indexOf(node.id) : Math.max(0, Math.round(node.avg_ttl));
    const items = laneMap.get(lane) || [];
    items.push(node);
    laneMap.set(lane, items);
  }

  const nodes: Node<TopologyNodeData>[] = [];
  const edges: Edge[] = [];
  const laneEntries = Array.from(laneMap.entries()).sort((left, right) => left[0] - right[0]);
  for (const [lane, items] of laneEntries) {
    items
      .slice()
      .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
      .forEach((node, index) => {
        nodes.push({
          id: node.id,
          type: "topology",
          position: { x: lane * 230, y: index * 120 },
          data: {
            label: node.label,
            role: node.role,
            count: node.count,
            detail: `${node.hostname || node.provider || "unclassified"} · ${node.avg_rtt.toFixed(1)} ms`,
            focused: !focusRoute || focusNodeIDs.has(node.id),
            selected: selectedNodeId === node.id,
          },
          draggable: false,
          selectable: true,
        });
      });
  }

  for (const edge of visibleEdges) {
    const id = `${edge.source}->${edge.target}`;
    edges.push({
      id,
      source: edge.source,
      target: edge.target,
      type: "smoothstep",
      animated: focusEdgeIDs.has(id),
      markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 },
      style: {
        stroke: focusRoute && !focusEdgeIDs.has(id) ? "rgba(142, 160, 168, 0.2)" : "rgba(126, 224, 200, 0.55)",
        strokeWidth: focusEdgeIDs.has(id) ? 2.8 : Math.min(4, 1 + edge.count / 5),
      },
    });
  }

  return { nodes, edges };
}

function buildPolicyElements(policy: OrchestrationPolicy | null, selectedStepId: string) {
  if (!policy) {
    return { nodes: [] as Node[], edges: [] as Edge[] };
  }

  const lanes = new Map<string, { label: string; steps: OrchestrationPolicy["steps"] }>();
  for (const step of policy.steps) {
    const laneKey = laneKeyForStep(step);
    if (!lanes.has(laneKey)) {
      lanes.set(laneKey, { label: laneLabelForStep(step), steps: [] });
    }
    lanes.get(laneKey)!.steps.push(step);
  }

  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const laneEntries = Array.from(lanes.entries());
  laneEntries.forEach(([laneKey, lane], laneIndex) => {
    const triggerID = `trigger:${laneKey}`;
    nodes.push({
      id: triggerID,
      type: "trigger",
      draggable: false,
      position: { x: laneIndex * 320, y: 0 },
      data: {
        label: lane.label,
        detail: `${lane.steps.length} step${lane.steps.length === 1 ? "" : "s"}`,
      } satisfies PolicyTriggerData,
    });

    lane.steps.forEach((step, stepIndex) => {
      const nodeID = `step:${step.id}`;
      const sourceID = stepIndex === 0 ? triggerID : `step:${lane.steps[stepIndex - 1].id}`;
      nodes.push({
        id: nodeID,
        type: "step",
        position: { x: laneIndex * 320, y: 120 + stepIndex * 150 },
        data: {
          stepId: step.id,
          label: step.label,
          pluginId: step.pluginId,
          stage: step.stage,
          summary: step.summary,
          enabled: step.enabled,
          laneKey,
          selected: selectedStepId === step.id,
        } satisfies PolicyStepData,
      });

      edges.push({
        id: `${sourceID}->${nodeID}`,
        source: sourceID,
        target: nodeID,
        type: "smoothstep",
        markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 },
        style: {
          stroke: step.enabled ? "rgba(126, 224, 200, 0.5)" : "rgba(142, 160, 168, 0.25)",
          strokeWidth: 2,
        },
      });
    });
  });

  return { nodes, edges };
}

export function TopologyFlowCanvas({
  topology,
  focusRouteId,
  minEdgeCount,
  roleFilter,
  selectedNodeId,
  onSelectNode,
}: {
  topology: TopologyGraph;
  focusRouteId: string;
  minEdgeCount: number;
  roleFilter: string;
  selectedNodeId: string;
  onSelectNode: (nodeId: string) => void;
}) {
  const { nodes, edges } = useMemo(
    () => buildTopologyElements(topology, focusRouteId, minEdgeCount, roleFilter, selectedNodeId),
    [focusRouteId, minEdgeCount, roleFilter, selectedNodeId, topology],
  );

  return (
    <div className="cc-flow">
      <ReactFlow
        fitView
        defaultEdgeOptions={{ type: "smoothstep" }}
        edges={edges}
        minZoom={0.25}
        nodeTypes={topologyNodeTypes}
        nodes={nodes}
        onNodeClick={(_, node) => onSelectNode(node.id)}
        proOptions={{ hideAttribution: true }}
      >
        <MiniMap nodeColor={(node) => roleTone((node.data as TopologyNodeData).role)} />
        <Controls />
        <Background color="rgba(166, 185, 194, 0.1)" gap={20} />
      </ReactFlow>
    </div>
  );
}

export function PolicyFlowCanvas({
  policy,
  selectedStepId,
  onSelectStep,
  onReorder,
}: {
  policy: OrchestrationPolicy | null;
  selectedStepId: string;
  onSelectStep: (stepId: string) => void;
  onReorder: (orderedStepIDs: string[]) => void;
}) {
  const baseGraph = useMemo(() => buildPolicyElements(policy, selectedStepId), [policy, selectedStepId]);
  const [nodes, setNodes, onNodesChange] = useNodesState(baseGraph.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(baseGraph.edges);

  useEffect(() => {
    setNodes(baseGraph.nodes);
    setEdges(baseGraph.edges);
  }, [baseGraph.edges, baseGraph.nodes, setEdges, setNodes]);

  return (
    <div className="cc-flow">
      <ReactFlow
        fitView
        edges={edges}
        nodes={nodes}
        nodeTypes={policyNodeTypes}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => {
          const stepId = (node.data as Partial<PolicyStepData>).stepId;
          if (stepId) {
            onSelectStep(stepId);
          }
        }}
        onNodeDragStop={(_, draggedNode, currentNodes) => {
          const laneKey = (draggedNode.data as Partial<PolicyStepData>).laneKey;
          if (!laneKey || !policy) {
            return;
          }
          const laneNodes = currentNodes
            .filter((node) => (node.data as Partial<PolicyStepData>).laneKey === laneKey)
            .sort((left, right) => left.position.y - right.position.y);
          const reorderedSteps = laneNodes
            .map((node) => (node.data as Partial<PolicyStepData>).stepId || "")
            .filter(Boolean);
          const laneStepIDs = new Set(policy.steps.filter((step) => laneKeyForStep(step) === laneKey).map((step) => step.id));
          let laneIndex = 0;
          onReorder(
            policy.steps.map((step) => {
              if (!laneStepIDs.has(step.id)) {
                return step.id;
              }
              const replacement = reorderedSteps[laneIndex] || step.id;
              laneIndex += 1;
              return replacement;
            }),
          );
        }}
        onNodesChange={onNodesChange}
        proOptions={{ hideAttribution: true }}
      >
        <MiniMap nodeColor={(node) => ((node.data as Partial<PolicyStepData>).enabled === false ? "#8ea0a8" : "#7ee0c8")} />
        <Controls />
        <Background color="rgba(166, 185, 194, 0.1)" gap={20} />
      </ReactFlow>
    </div>
  );
}
