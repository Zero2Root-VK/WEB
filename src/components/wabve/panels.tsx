import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Doc } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Fingerprint,
  Layers,
  ShieldAlert,
  Route,
} from "lucide-react";
import type { ReactNode } from "react";
import {
  CATEGORY_LABEL,
  EmptyState,
  Meter,
  PanelHeader,
  ProtocolBadge,
  RISK_CLASS,
  SEVERITY_CLASS,
  SEVERITY_ORDER,
  StatCard,
  Tag,
} from "./shared";

export interface CoverageShape {
  endpointsDiscovered: number;
  endpointsInScope: number;
  blockedOutOfScope: number;
  authenticatedEndpoints: number;
  objectsIdentified: number;
  rolesIdentified: number;
  authorizationTests: number;
  businessLogicTests: number;
  totalTests: number;
  passed: number;
  failed: number;
  inconclusive: number;
  blocked: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  requestsUsed: number;
  requestBudget: number;
  safetyBlocks: number;
}

export function readCoverage(engagement: Doc<"engagements">): CoverageShape | null {
  return (engagement.coverage as CoverageShape | undefined) ?? null;
}

const CATEGORY_ORDER = [
  "authorization",
  "tenant",
  "bfla",
  "method",
  "property",
  "workflow",
  "business",
  "session",
];

export function OverviewPanel({
  engagement,
  endpoints,
  identities,
  tests,
  findings,
}: {
  engagement: Doc<"engagements">;
  endpoints: Doc<"endpoints">[];
  identities: Doc<"identities">[];
  tests: Doc<"tests">[];
  findings: Doc<"findings">[];
}) {
  const coverage = readCoverage(engagement);
  const violations = tests.filter((t) => t.outcome === "fail");

  const severityCounts = (["critical", "high", "medium", "low"] as const).map((severity) => ({
    severity,
    count: findings.filter((f) => f.severity === severity).length,
  }));

  const byCategory = CATEGORY_ORDER.map((category) => ({
    category,
    total: tests.filter((t) => t.category === category).length,
    failed: tests.filter((t) => t.category === category && t.outcome === "fail").length,
  })).filter((c) => c.total > 0);

  const coveragePct =
    coverage && coverage.totalTests > 0
      ? Math.round(((coverage.totalTests - coverage.blocked) / coverage.totalTests) * 100)
      : 0;

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Engagement overview"
        description={`${engagement.target} · profile ${engagement.profile} · ${engagement.status}`}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Endpoints" value={endpoints.length} hint={`${coverage?.authenticatedEndpoints ?? 0} require auth`} />
        <StatCard label="Identities" value={identities.length} hint={`${coverage?.objectsIdentified ?? 0} objects modelled`} />
        <StatCard label="Probes executed" value={tests.length} hint={`${coverage?.blocked ?? 0} blocked by safety controls`} />
        <StatCard
          label="Findings"
          value={findings.length}
          tone={findings.length > 0 ? "danger" : "default"}
          hint={`${coverage?.critical ?? 0} critical · ${coverage?.high ?? 0} high`}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <Card className="border-border/60 bg-card/40 py-0 shadow-none">
          <CardHeader className="px-5 py-4">
            <CardTitle className="text-sm">Risk distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 px-5 pb-5">
            {severityCounts.map(({ severity, count }) => (
              <div key={severity} className="flex items-center gap-3">
                <span className={cn("w-20 rounded border px-2 py-0.5 text-center font-mono text-[10px] uppercase", SEVERITY_CLASS[severity])}>
                  {severity}
                </span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/50">
                  <div
                    className={cn(
                      "h-full rounded-full",
                      severity === "critical"
                        ? "bg-red-500"
                        : severity === "high"
                          ? "bg-orange-500"
                          : severity === "medium"
                            ? "bg-amber-500"
                            : "bg-sky-500",
                    )}
                    style={{
                      width: `${findings.length ? (count / findings.length) * 100 : 0}%`,
                    }}
                  />
                </div>
                <span className="w-8 text-right font-mono text-xs tabular-nums">{count}</span>
              </div>
            ))}
            <div className="mt-4 border-t border-border/50 pt-4">
              <Meter
                label="Evidence coverage"
                value={coveragePct}
                max={100}
                suffix={`${coveragePct}%`}
              />
              <p className="mt-2 font-mono text-[10px] text-muted-foreground">
                {coverage?.passed ?? 0} passed · {coverage?.failed ?? 0} violated ·{" "}
                {coverage?.inconclusive ?? 0} inconclusive
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/60 bg-card/40 py-0 shadow-none">
          <CardHeader className="px-5 py-4">
            <CardTitle className="text-sm">Test classes</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 px-5 pb-5">
            {byCategory.length === 0 ? (
              <p className="text-xs text-muted-foreground">No probes have run yet.</p>
            ) : (
              byCategory.map((row) => (
                <div key={row.category} className="space-y-1.5">
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-muted-foreground">
                      {CATEGORY_LABEL[row.category] ?? row.category}
                    </span>
                    <span className="tabular-nums">
                      {row.total}
                      {row.failed > 0 ? (
                        <span className="ml-2 text-red-400">{row.failed} violated</span>
                      ) : null}
                    </span>
                  </div>
                  <Progress
                    value={row.total ? (row.failed / row.total) * 100 : 0}
                    className="h-1 bg-muted/50 [&>[data-slot=progress-indicator]]:bg-red-500"
                  />
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardHeader className="flex-row items-center justify-between px-5 py-4">
          <CardTitle className="text-sm">Latest confirmed findings</CardTitle>
          <Badge variant="outline" className="border-border/60 font-mono text-[10px] text-muted-foreground">
            {findings.length} total
          </Badge>
        </CardHeader>
        <CardContent className="px-5 pb-5">
          {findings.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No violations confirmed for this engagement yet.
            </p>
          ) : (
            <div className="space-y-2">
              {findings
                .slice()
                .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
                .slice(0, 5)
                .map((finding) => (
                  <div
                    key={finding._id}
                    className="flex flex-wrap items-center gap-2 rounded-md border border-border/60 bg-background/40 px-3 py-2.5"
                  >
                    <span className="font-mono text-[10px] text-muted-foreground">{finding.code}</span>
                    <span className="text-sm">{finding.title}</span>
                    <span className="ml-auto flex items-center gap-2">
                      <Tag className="border-border/60 text-muted-foreground">{finding.classification}</Tag>
                      <Tag className={SEVERITY_CLASS[finding.severity]}>{finding.severity}</Tag>
                    </span>
                  </div>
                ))}
            </div>
          )}
        </CardContent>
      </Card>

      {violations.length > 0 ? (
        <Card className="border-border/60 bg-card/40 py-0 shadow-none">
          <CardHeader className="px-5 py-4">
            <CardTitle className="text-sm">Differential mismatches</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-5">
            <div className="grid gap-2 sm:grid-cols-2">
              {violations.slice(0, 6).map((test) => (
                <div
                  key={test._id}
                  className="rounded-md border border-red-500/25 bg-red-500/[0.05] px-3 py-2.5 font-mono text-[11px]"
                >
                  <p className="text-foreground/85">
                    {test.actorLabel} → {test.method} {test.path}
                  </p>
                  <p className="mt-1 text-muted-foreground">
                    reference={test.expectation} target={test.actual}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export function IdentitiesPanel({ identities }: { identities: Doc<"identities">[] }) {
  return (
    <div className="space-y-6">
      <PanelHeader
        title="Identity manager"
        description="Each identity is an authenticated (or deliberately anonymous) actor used to prove the authorization model."
      />
      {identities.length === 0 ? (
        <EmptyState title="No identities" description="Add identities through the engagement wizard." />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {identities.map((identity) => (
            <Card key={identity._id} className="border-border/60 bg-card/40 py-0 shadow-none">
              <CardContent className="px-5 py-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="flex size-9 items-center justify-center rounded-md border border-border/60 bg-background/50">
                      <Fingerprint className="size-4 text-primary" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">{identity.label}</p>
                      <p className="font-mono text-[10px] text-muted-foreground">{identity.key}</p>
                    </div>
                  </div>
                  <Tag
                    className={
                      identity.status === "authenticated"
                        ? "border-teal-400/40 text-teal-300"
                        : "border-border/60 text-muted-foreground"
                    }
                  >
                    {identity.status}
                  </Tag>
                </div>
                <dl className="mt-4 grid grid-cols-2 gap-2 font-mono text-[11px]">
                  <div>
                    <dt className="text-muted-foreground uppercase">Role</dt>
                    <dd className="text-foreground/85">{identity.role}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground uppercase">Tenant</dt>
                    <dd className="text-foreground/85">{identity.tenant}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground uppercase">Auth</dt>
                    <dd className="text-foreground/85">{identity.authMethod}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground uppercase">Secret</dt>
                    <dd className="text-foreground/85">{identity.secretHint ?? "redacted"}</dd>
                  </div>
                </dl>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export function AttackSurfacePanel({
  endpoints,
  tests,
}: {
  endpoints: Doc<"endpoints">[];
  tests: Doc<"tests">[];
}) {
  const failsByEndpoint = new Map<string, number>();
  for (const test of tests) {
    if (test.outcome === "fail") {
      failsByEndpoint.set(test.endpointKey, (failsByEndpoint.get(test.endpointKey) ?? 0) + 1);
    }
  }

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Attack surface"
        description="Unified endpoint registry produced by the discovery stage, enriched with observed roles and risk."
      />
      {endpoints.length === 0 ? (
        <EmptyState
          title="No endpoints discovered yet"
          description="Run the engagement to build the endpoint registry."
        />
      ) : (
        <Card className="border-border/60 bg-card/40 py-0 shadow-none">
          <CardContent className="px-0 py-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-5">Method</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead>Object</TableHead>
                  <TableHead>Params</TableHead>
                  <TableHead>Roles</TableHead>
                  <TableHead>Via</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead className="pr-5 text-right">Violations</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {endpoints.map((endpoint) => (
                  <TableRow key={endpoint._id} className={cn(!endpoint.inScope && "opacity-50")}>
                    <TableCell className="pl-5">
                      <ProtocolBadge method={endpoint.method} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {endpoint.path}
                      {!endpoint.inScope ? (
                        <Badge
                          variant="outline"
                          className="ml-2 border-amber-500/40 font-mono text-[9px] text-amber-300 uppercase"
                        >
                          out of scope
                        </Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {endpoint.objectType ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {endpoint.parameters.length ? endpoint.parameters.join(", ") : "—"}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {endpoint.rolesObserved.map((role) => (
                          <Tag key={role} className="border-border/60 text-muted-foreground">
                            {role}
                          </Tag>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-[10px] text-muted-foreground">
                      {endpoint.discoveredVia}
                    </TableCell>
                    <TableCell>
                      <Tag className={RISK_CLASS[endpoint.risk] ?? ""}>{endpoint.risk}</Tag>
                    </TableCell>
                    <TableCell className="pr-5 text-right">
                      {failsByEndpoint.get(endpoint.key) ? (
                        <span className="font-mono text-xs text-red-400">
                          {failsByEndpoint.get(endpoint.key)}
                        </span>
                      ) : (
                        <span className="font-mono text-xs text-muted-foreground">0</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      <div className="grid gap-3 sm:grid-cols-3">
        <InfoTile icon={<Route className="size-4" />} label="Categories" value={`${new Set(endpoints.map((e) => e.category)).size}`} />
        <InfoTile icon={<Boxes className="size-4" />} label="Object types" value={`${new Set(endpoints.map((e) => e.objectType).filter(Boolean)).size}`} />
        <InfoTile icon={<Layers className="size-4" />} label="Out of scope" value={`${endpoints.filter((e) => !e.inScope).length}`} />
      </div>
    </div>
  );
}

export function CoveragePanel({
  engagement,
  tests,
  findings,
}: {
  engagement: Doc<"engagements">;
  tests: Doc<"tests">[];
  findings: Doc<"findings">[];
}) {
  const coverage = readCoverage(engagement);
  const blocked = tests.filter((t) => t.outcome === "blocked");
  const inconclusive = tests.filter((t) => t.outcome === "inconclusive");

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Test coverage"
        description="What the engine exercised, what it deliberately refused to run, and what remains inconclusive."
      />
      {!coverage ? (
        <EmptyState
          title="Coverage is not available yet"
          description="Coverage is computed at the reporting stage of the pipeline."
        />
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Endpoints discovered" value={coverage.endpointsDiscovered} hint={`${coverage.endpointsInScope} in scope`} />
            <StatCard label="Authenticated endpoints" value={coverage.authenticatedEndpoints} />
            <StatCard label="Objects identified" value={coverage.objectsIdentified} hint={`${coverage.rolesIdentified} identities exercised`} />
            <StatCard label="Confirmed findings" value={coverage.findings} tone="danger" hint={`${coverage.critical} critical`} />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="border-border/60 bg-card/40 py-0 shadow-none">
              <CardHeader className="px-5 py-4">
                <CardTitle className="text-sm">Probe outcomes</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 px-5 pb-5">
                <Meter label="Passed" value={coverage.passed} max={coverage.totalTests} />
                <Meter label="Violated" value={coverage.failed} max={coverage.totalTests} tone="danger" />
                <Meter label="Blocked by safety controls" value={coverage.blocked} max={coverage.totalTests} tone="warning" />
                <Meter label="Inconclusive" value={coverage.inconclusive} max={coverage.totalTests} />
              </CardContent>
            </Card>
            <Card className="border-border/60 bg-card/40 py-0 shadow-none">
              <CardHeader className="px-5 py-4">
                <CardTitle className="text-sm">Request accounting</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 px-5 pb-5">
                <Meter
                  label="Request budget used"
                  value={coverage.requestsUsed}
                  max={coverage.requestBudget}
                  suffix={`${coverage.requestsUsed}/${coverage.requestBudget}`}
                />
                <Meter label="Authorization probes" value={coverage.authorizationTests} max={coverage.totalTests} />
                <Meter label="Business-logic probes" value={coverage.businessLogicTests} max={coverage.totalTests} />
                <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2.5 font-mono text-[11px] text-muted-foreground">
                  {coverage.safetyBlocks} probe(s) never left the engine because of scope or
                  destructive-testing policy.
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <OutcomeList
          title="Blocked probes"
          icon={<AlertTriangle className="size-4 text-amber-400" />}
          items={blocked.map((t) => `${t.method} ${t.path} — ${t.signals[0] ?? "blocked"}`)}
          empty="Nothing was blocked. Consider approving destructive testing for deeper coverage."
        />
        <OutcomeList
          title="Inconclusive probes"
          icon={<CheckCircle2 className="size-4 text-slate-400" />}
          items={inconclusive.map((t) => `${t.actorLabel} → ${t.method} ${t.path}`)}
          empty="Every executed probe reached a verdict."
        />
      </div>

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardHeader className="px-5 py-4">
          <CardTitle className="text-sm">Severity roll-up</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 px-5 pb-5 sm:grid-cols-4">
          {(["critical", "high", "medium", "low"] as const).map((severity) => (
            <div key={severity} className={cn("rounded-md border px-4 py-3", SEVERITY_CLASS[severity])}>
              <p className="font-mono text-[10px] uppercase">{severity}</p>
              <p className="mt-1 text-xl font-semibold tabular-nums">
                {findings.filter((f) => f.severity === severity).length}
              </p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function OutcomeList({
  title,
  icon,
  items,
  empty,
}: {
  title: string;
  icon: ReactNode;
  items: string[];
  empty: string;
}) {
  return (
    <Card className="border-border/60 bg-card/40 py-0 shadow-none">
      <CardHeader className="flex-row items-center gap-2 px-5 py-4">
        {icon}
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-5">
        {items.length === 0 ? (
          <p className="text-xs text-muted-foreground">{empty}</p>
        ) : (
          <ul className="space-y-1.5 font-mono text-[11px] text-muted-foreground">
            {items.slice(0, 8).map((item) => (
              <li key={item} className="truncate">
                {item}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function InfoTile({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <Card className="border-border/60 bg-card/40 py-0 shadow-none">
      <CardContent className="flex items-center gap-3 px-5 py-4">
        <div className="flex size-9 items-center justify-center rounded-md border border-border/60 bg-background/50">
          {icon}
        </div>
        <div>
          <p className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
            {label}
          </p>
          <p className="text-lg font-semibold tabular-nums">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

export function SeverityLegend() {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {(["critical", "high", "medium", "low"] as const).map((severity) => (
        <Tag key={severity} className={SEVERITY_CLASS[severity]}>
          {severity}
        </Tag>
      ))}
    </div>
  );
}

export const OVERVIEW_ICONS = { ShieldAlert };
