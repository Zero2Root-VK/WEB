import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Doc } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { ArrowDown, Zap } from "lucide-react";
import { EmptyState, PanelHeader, SEVERITY_CLASS, Tag } from "./shared";

interface DeltaEntry {
  field: string;
  before: unknown;
  after: unknown;
}

function deltasOf(test: Doc<"tests">): DeltaEntry[] {
  return (test.stateDelta as DeltaEntry[] | undefined) ?? [];
}

function resourceOf(
  path: string,
  endpointKey: string,
  objectTypeByEndpoint: Map<string, string>,
): string {
  if (objectTypeByEndpoint.has(endpointKey)) {
    return objectTypeByEndpoint.get(endpointKey) as string;
  }
  const segments = path.split("/").filter(Boolean);
  return segments.length >= 2 ? segments[segments.length - 2] : (segments[0] ?? "resource");
}

const EDGE_COLOR: Record<string, string> = {
  fail: "#ef4444",
  pass: "#2dd4bf",
  inconclusive: "#94a3b8",
  blocked: "#f59e0b",
};

export function AuthzGraph({
  tests,
  endpoints,
}: {
  tests: Doc<"tests">[];
  endpoints?: Doc<"endpoints">[];
}) {
  const objectTypeByEndpoint = new Map<string, string>();
  for (const endpoint of endpoints ?? []) {
    if (endpoint.objectType) objectTypeByEndpoint.set(endpoint.key, endpoint.objectType);
  }

  const scoped = tests.filter((t) => t.objectRef || t.category === "bfla");

  const actorKeys = Array.from(new Set(scoped.map((t) => t.actorKey)));
  const nodes = new Map<string, { label: string; kind: string }>();
  for (const test of scoped) {
    const key = test.objectRef
      ? `${resourceOf(test.path, test.endpointKey, objectTypeByEndpoint)}/${test.objectRef}`
      : test.path;
    if (!nodes.has(key)) {
      nodes.set(key, {
        label: key,
        kind: test.objectRef ? "object" : "function",
      });
    }
  }
  const nodeKeys = Array.from(nodes.keys());

  // keep the strongest evidence per (actor, node) pair
  const rank: Record<string, number> = { fail: 3, inconclusive: 2, blocked: 2, pass: 1 };
  const edges = new Map<string, { actor: string; node: string; outcome: string; label: string }>();
  for (const test of scoped) {
    const nodeKey = test.objectRef
      ? `${resourceOf(test.path, test.endpointKey, objectTypeByEndpoint)}/${test.objectRef}`
      : test.path;
    const id = `${test.actorKey}->${nodeKey}`;
    const existing = edges.get(id);
    if (!existing || (rank[test.outcome] ?? 0) > (rank[existing.outcome] ?? 0)) {
      edges.set(id, {
        actor: test.actorKey,
        node: nodeKey,
        outcome: test.outcome,
        label: `${test.method} ${test.category}`,
      });
    }
  }

  if (nodeKeys.length === 0) {
    return (
      <EmptyState
        title="No authorization graph yet"
        description="The graph is built from executed probes once the engagement has run."
      />
    );
  }

  const rowHeight = 62;
  const height = Math.max(actorKeys.length * rowHeight, nodeKeys.length * rowHeight, 260);
  const width = 940;
  const leftX = 30;
  const rightX = width - 250;
  const actorY = (i: number) =>
    40 + (i * (height - 80)) / Math.max(1, actorKeys.length - 1);
  const nodeY = (i: number) => 40 + (i * (height - 80)) / Math.max(1, nodeKeys.length - 1);

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Authorization graph"
        description="Every edge is one executed decision. A red edge means the target allowed what the reference policy denies."
        actions={
          <div className="flex flex-wrap gap-1.5">
            <Tag className="border-red-500/40 text-red-300">violated</Tag>
            <Tag className="border-teal-400/40 text-teal-300">enforced</Tag>
            <Tag className="border-border/60 text-muted-foreground">inconclusive</Tag>
          </div>
        }
      />

      <AttackPaths tests={tests} />

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardContent className="px-3 py-4">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="h-auto w-full"
            style={{ minHeight: 240 }}
          >
            <defs>
              <marker id="arrow" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 z" fill="#94a3b8" />
              </marker>
            </defs>

            {Array.from(edges.values()).map((edge) => {
              const ai = actorKeys.indexOf(edge.actor);
              const ni = nodeKeys.indexOf(edge.node);
              const y1 = actorY(ai);
              const y2 = nodeY(ni);
              const midX = (leftX + 170 + rightX) / 2;
              const path = `M ${leftX + 168} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${rightX} ${y2}`;
              const color = EDGE_COLOR[edge.outcome] ?? "#94a3b8";
              return (
                <g key={`${edge.actor}-${edge.node}`}>
                  <path
                    d={path}
                    fill="none"
                    stroke={color}
                    strokeWidth={edge.outcome === "fail" ? 2 : 1.25}
                    strokeDasharray={edge.outcome === "blocked" ? "5 4" : undefined}
                    opacity={edge.outcome === "fail" ? 0.95 : 0.6}
                  />
                  <text
                    x={midX}
                    y={(y1 + y2) / 2 - 3}
                    textAnchor="middle"
                    className="fill-muted-foreground"
                    style={{ fontSize: 9, fontFamily: "ui-monospace, monospace" }}
                  >
                    {edge.label}
                  </text>
                </g>
              );
            })}

            {actorKeys.map((key, i) => {
              const test = scoped.find((t) => t.actorKey === key);
              const y = actorY(i);
              return (
                <g key={key}>
                  <rect
                    x={leftX}
                    y={y - 17}
                    width={168}
                    height={34}
                    rx={6}
                    fill="oklch(0.245 0.014 255)"
                    stroke="oklch(1 0 0 / 12%)"
                  />
                  <text
                    x={leftX + 14}
                    y={y + 1}
                    className="fill-foreground"
                    style={{ fontSize: 11, fontFamily: "ui-monospace, monospace" }}
                  >
                    {test?.actorLabel ?? key}
                  </text>
                  <text
                    x={leftX + 14}
                    y={y + 12}
                    className="fill-muted-foreground"
                    style={{ fontSize: 8, fontFamily: "ui-monospace, monospace" }}
                  >
                    {key}
                  </text>
                </g>
              );
            })}

            {nodeKeys.map((key, i) => {
              const node = nodes.get(key);
              const y = nodeY(i);
              const isFunction = node?.kind === "function";
              return (
                <g key={key}>
                  <rect
                    x={rightX}
                    y={y - 16}
                    width={220}
                    height={32}
                    rx={6}
                    fill={isFunction ? "oklch(0.28 0.02 250)" : "oklch(0.245 0.014 255)"}
                    stroke="oklch(1 0 0 / 12%)"
                  />
                  <text
                    x={rightX + 12}
                    y={y + 4}
                    className="fill-foreground"
                    style={{ fontSize: 10, fontFamily: "ui-monospace, monospace" }}
                  >
                    {node?.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </CardContent>
      </Card>
    </div>
  );
}

const ACTION_LABEL: Record<string, string> = {
  disclose: "Object disclosed",
  modify: "State modified",
  destroy: "Record destroyed",
};

/**
 * Chain the confirmed violations that land on the same object into the
 * disclosure -> modification -> destruction path a tester actually reports.
 */
export function AttackPaths({ tests }: { tests: Doc<"tests">[] }) {
  const failing = tests.filter((t) => t.outcome === "fail");
  const groups = new Map<string, Doc<"tests">[]>();
  for (const test of failing) {
    const key = test.objectRef ? `${test.path.split("/").filter(Boolean)[1] ?? "object"} ${test.objectRef}` : test.path;
    const list = groups.get(key) ?? [];
    list.push(test);
    groups.set(key, list);
  }

  const paths = Array.from(groups.entries())
    .map(([object, group]) => {
      const steps = new Map<string, { action: string; test: Doc<"tests"> }>();
      for (const test of group) {
        const action = test.method === "GET"
          ? "disclose"
          : test.signals.includes("destructive_effect")
            ? "destroy"
            : "modify";
        if (!steps.has(action)) steps.set(action, { action, test });
      }
      const ordered = ["disclose", "modify", "destroy"]
        .filter((action) => steps.has(action))
        .map((action) => steps.get(action) as { action: string; test: Doc<"tests"> });
      return { object, steps: ordered, victim: group.find((t) => t.victimLabel)?.victimLabel };
    })
    .filter((path) => path.steps.length > 0)
    .sort((a, b) => b.steps.length - a.steps.length);

  if (paths.length === 0) return null;

  return (
    <div className="space-y-3">
      <PanelHeader
        title="Attack paths"
        description="Confirmed violations chained per object. A path that escalates from disclosure to modification is materially more severe than a single probe, which is what a tester needs to report."
      />
      <div className="grid gap-3 lg:grid-cols-2">
        {paths.map((path) => {
          const weakest = path.steps[path.steps.length - 1].test;
          // Chain length drives severity: escalation from disclosure to
          // modification is materially worse than a single read.
          const severity =
            path.steps.length >= 3
              ? "critical"
              : path.steps.length === 2
                ? "high"
                : weakest.risk;
          return (
            <Card key={path.object} className="border-border/60 bg-card/40 py-0 shadow-none">
              <CardHeader className="flex-row items-center justify-between gap-2 px-5 py-4">
                <CardTitle className="flex items-center gap-2 font-mono text-xs tracking-wide">
                  <Zap className="size-3.5 text-primary" />
                  {path.object}
                </CardTitle>
                <Tag className={SEVERITY_CLASS[severity]}>{severity}</Tag>
              </CardHeader>
              <CardContent className="px-5 pb-5">
                <div className="space-y-1.5">
                  {path.steps.map((step, index) => (
                    <div key={step.action}>
                      <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[11px] text-foreground/85">
                            {step.test.actorLabel} → {step.test.method} {step.test.path}
                          </span>
                          <Tag className="border-red-500/40 text-red-300">
                            {ACTION_LABEL[step.action]}
                          </Tag>
                        </div>
                        {step.test.stateDelta ? (
                          <p className="mt-1 font-mono text-[10px] text-amber-300">
                            {(step.test.stateDelta as Array<{ field: string; before: unknown; after: unknown }>)
                              .map((d) => `${d.field}: ${String(d.before)} → ${String(d.after)}`)
                              .join("  ·  ")}
                          </p>
                        ) : null}
                      </div>
                      {index < path.steps.length - 1 ? (
                        <div className="flex justify-center py-1">
                          <ArrowDown className="size-3 text-red-400" />
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
                <p className="mt-3 font-mono text-[10px] text-muted-foreground">
                  {path.steps.length} confirmed step(s) on this object
                  {path.victim ? ` · victim ${path.victim}` : ""}
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

const LIFECYCLE = ["CREATED", "PAID", "SHIPPED", "DELIVERED", "REFUNDED"];

interface Transition {
  from: string;
  to: string;
  outcome: string;
  actor: string;
  reference: string;
  id: string;
}

export function WorkflowPanel({ tests }: { tests: Doc<"tests">[] }) {
  const workflowTests = tests.filter((t) => t.category === "workflow");

  const transitions: Transition[] = workflowTests.map((test) => {
    const delta = deltasOf(test).find((d) => d.field === "status");
    return {
      from: String(delta?.before ?? "?"),
      to: String(delta?.after ?? "?"),
      outcome: test.outcome,
      actor: test.actorLabel,
      reference: test.expectation,
      id: test._id,
    };
  });

  const merge = new Map<string, Transition>();
  for (const transition of transitions) {
    const key = `${transition.from}->${transition.to}`;
    const existing = merge.get(key);
    if (!existing || transition.outcome === "fail") merge.set(key, transition);
  }
  const unique = Array.from(merge.values());
  const violations = unique.filter((t) => t.outcome === "fail");

  const width = 1080;
  const height = 260;
  const nodeW = 150;
  const nodeH = 52;
  const gap = 42;
  const y = 96;

  const xFor = (index: number) => 40 + index * (nodeW + gap);

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Workflow graph"
        description="The order lifecycle as a state machine. Transitions the engine attempted are drawn as edges; dashed red edges are transitions the target accepted but the reference policy forbids."
        actions={
          <div className="flex gap-1.5">
            <Tag className="border-border/60 text-muted-foreground">declared</Tag>
            <Tag className="border-teal-400/40 text-teal-300">enforced</Tag>
            <Tag className="border-red-500/40 text-red-300">violated</Tag>
          </div>
        }
      />

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardContent className="px-3 py-4">
          <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full">
            <defs>
              <marker id="wf-arrow" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 z" fill="#94a3b8" />
              </marker>
              <marker id="wf-arrow-bad" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 z" fill="#ef4444" />
              </marker>
            </defs>

            {/* declared lifecycle */}
            {LIFECYCLE.slice(0, -1).map((state, i) => {
              const x1 = xFor(i) + nodeW;
              const x2 = xFor(i + 1);
              return (
                <g key={`declared-${state}`}>
                  <line
                    x1={x1}
                    y1={y + nodeH / 2}
                    x2={x2 - 8}
                    y2={y + nodeH / 2}
                    stroke="oklch(1 0 0 / 22%)"
                    strokeWidth={1.5}
                    markerEnd="url(#wf-arrow)"
                  />
                </g>
              );
            })}

            {/* observed transitions */}
            {unique.map((transition) => {
              const fromIndex = LIFECYCLE.indexOf(transition.from);
              const toIndex = LIFECYCLE.indexOf(transition.to);
              if (fromIndex < 0 || toIndex < 0) return null;
              const violated = transition.outcome === "fail";
              const x1 = xFor(fromIndex) + nodeW / 2;
              const x2 = xFor(toIndex) + nodeW / 2;
              if (toIndex === fromIndex + 1 && !violated) {
                return (
                  <line
                    key={transition.id}
                    x1={x1 + nodeW / 2 - 4}
                    y1={y - 16}
                    x2={x2 - nodeW / 2 + 8}
                    y2={y - 16}
                    stroke="#2dd4bf"
                    strokeWidth={2.5}
                    markerEnd="url(#wf-arrow)"
                    opacity={0.9}
                  />
                );
              }
              const arcY = violated ? y + nodeH + 58 : y - 46;
              const label =
                toIndex > fromIndex
                  ? "bypass"
                  : "replay";
              return (
                <g key={transition.id}>
                  <path
                    d={`M ${x1} ${y + nodeH * (violated ? 1 : 0)} C ${x1} ${arcY}, ${x2} ${arcY}, ${x2} ${y + nodeH * (violated ? 1 : 0)}`}
                    fill="none"
                    stroke={violated ? "#ef4444" : "#2dd4bf"}
                    strokeWidth={2}
                    strokeDasharray={violated ? "7 5" : undefined}
                    markerEnd={violated ? "url(#wf-arrow-bad)" : "url(#wf-arrow)"}
                  />
                  <text
                    x={(x1 + x2) / 2}
                    y={violated ? arcY + 16 : arcY - 8}
                    textAnchor="middle"
                    style={{ fontSize: 10, fontFamily: "ui-monospace, monospace" }}
                    className={violated ? "fill-red-400" : "fill-teal-300"}
                  >
                    {violated ? `⚠ ${transition.from} → ${transition.to} (${label})` : "refund"}
                  </text>
                </g>
              );
            })}

            {LIFECYCLE.map((state, i) => (
              <g key={state}>
                <rect
                  x={xFor(i)}
                  y={y}
                  width={nodeW}
                  height={nodeH}
                  rx={8}
                  fill="oklch(0.245 0.014 255)"
                  stroke="oklch(1 0 0 / 14%)"
                />
                <text
                  x={xFor(i) + nodeW / 2}
                  y={y + nodeH / 2 + 4}
                  textAnchor="middle"
                  className="fill-foreground"
                  style={{ fontSize: 12, fontFamily: "ui-monospace, monospace", letterSpacing: 1 }}
                >
                  {state}
                </text>
              </g>
            ))}
          </svg>
        </CardContent>
      </Card>

      {workflowTests.length === 0 ? (
        <EmptyState
          title="No workflow probes were executed"
          description="Workflow transitions are exercised once the engagement has run."
        />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {unique.map((transition) => (
            <Card
              key={transition.id}
              className={cn(
                "border-border/60 bg-card/40 py-0 shadow-none",
                transition.outcome === "fail" && "border-red-500/30 bg-red-500/[0.04]",
              )}
            >
              <CardHeader className="px-5 py-3.5">
                <CardTitle className="font-mono text-xs tracking-wide">
                  {transition.from} → {transition.to}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 px-5 pb-4 font-mono text-[11px] text-muted-foreground">
                <p>observed as {transition.actor}</p>
                <p>reference policy: {transition.reference}</p>
                <p className={transition.outcome === "fail" ? "text-red-400" : "text-teal-300"}>
                  verdict: {transition.outcome}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {violations.length > 0 ? (
        <p className="font-mono text-[11px] text-red-400">
          {violations.length} unauthorized transition(s) accepted by the target.
        </p>
      ) : null}
    </div>
  );
}
