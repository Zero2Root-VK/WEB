import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Doc } from "@/convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { Code2, Download, FileText, Printer } from "lucide-react";
import { useMemo } from "react";
import { toast } from "sonner";
import { CATEGORY_LABEL, CodeBlock, PanelHeader, SEVERITY_CLASS, Tag } from "./shared";

type Engagement = Doc<"engagements">;
type Finding = Doc<"findings">;
type Test = Doc<"tests">;
type Endpoint = Doc<"endpoints">;
type Identity = Doc<"identities">;
type Event = Doc<"events">;

interface ReportInput {
  engagement: Engagement;
  findings: Finding[];
  tests: Test[];
  endpoints: Endpoint[];
  identities: Identity[];
  events: Event[];
}

function severityRank(severity: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 9;
}

function buildJson(input: ReportInput) {
  const { engagement, findings, tests, endpoints, identities } = input;
  return {
    report: "WABVE Authorization & Business Logic Verification Report",
    generatedAt: new Date().toISOString(),
    engagement: {
      name: engagement.name,
      target: engagement.target,
      profile: engagement.profile,
      status: engagement.status,
      scope: {
        allowedHosts: engagement.allowedHosts,
        allowedPaths: engagement.allowedPaths,
        rateLimit: engagement.rateLimit,
        requestBudget: engagement.requestBudget,
        destructiveTesting: engagement.destructiveTesting,
        dryRun: engagement.dryRun,
      },
    },
    methodology: [
      "Discovery builds a unified endpoint registry from browser, OpenAPI, HAR, passive JS and forced-browsing sources.",
      "The application model maps identities, roles, tenants and objects.",
      "The authorization test matrix assigns one actor, one object and one endpoint to every probe.",
      "Each probe is executed by the deterministic engine; the scope guard and safety controls run before dispatch.",
      "Every request is evaluated against a reference policy and an actual policy, then diffed against a before/after state snapshot.",
      "Findings are only raised when the two policies disagree and the evidence is reproducible.",
    ],
    authenticationMatrix: identities.map((identity) => ({
      identity: identity.label,
      key: identity.key,
      role: identity.role,
      tenant: identity.tenant,
      authMethod: identity.authMethod,
      status: identity.status,
    })),
    attackSurface: endpoints.map((endpoint) => ({
      method: endpoint.method,
      path: endpoint.path,
      object: endpoint.objectType ?? null,
      parameters: endpoint.parameters,
      authRequired: endpoint.authRequired,
      rolesObserved: endpoint.rolesObserved,
      category: endpoint.category,
      risk: endpoint.risk,
      inScope: endpoint.inScope,
      discoveredVia: endpoint.discoveredVia,
    })),
    coverage: engagement.coverage ?? null,
    tests: tests.map((test) => ({
      endpoint: test.endpointKey,
      method: test.method,
      path: test.path,
      category: test.category,
      probe: test.probe,
      actor: test.actorLabel,
      victim: test.victimLabel ?? null,
      referenceExpectation: test.expectation,
      targetDecision: test.actual,
      outcome: test.outcome,
      confidence: test.confidence,
      signals: test.signals,
      stateDelta: test.stateDelta ?? null,
    })),
    findings: findings.map((finding) => ({
      code: finding.code,
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
      score: finding.score,
      classification: finding.classification,
      cwe: finding.cwe,
      owasp: finding.owasp,
      endpoint: finding.endpoint,
      parameter: finding.parameter ?? null,
      attacker: finding.attacker,
      victim: finding.victim ?? null,
      expected: finding.expected,
      actual: finding.actual,
      request: finding.request,
      response: finding.response,
      beforeState: finding.beforeState ?? null,
      afterState: finding.afterState ?? null,
      stateDelta: finding.stateDelta ?? null,
      signals: finding.signals,
      reproduction: finding.reproduction,
      impact: finding.impact,
      remediation: finding.remediation,
    })),
  };
}

function buildMarkdown(input: ReportInput): string {
  const { engagement, findings, tests, endpoints, identities } = input;
  const coverage = engagement.coverage as Record<string, number> | undefined;
  const lines: string[] = [];
  lines.push(`# WABVE Report — ${engagement.name}`);
  lines.push("");
  lines.push(`- **Target:** ${engagement.target}`);
  lines.push(`- **Profile:** ${engagement.profile}`);
  lines.push(`- **Generated:** ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Scope");
  lines.push("");
  lines.push(`- Allowed hosts: ${engagement.allowedHosts.join(", ") || "—"}`);
  lines.push(`- Allowed paths: ${engagement.allowedPaths.join(", ") || "any"}`);
  lines.push(`- Rate limit: ${engagement.rateLimit} req/s`);
  lines.push(`- Request budget: ${engagement.requestBudget}`);
  lines.push(`- Destructive testing: ${engagement.destructiveTesting ? "approved" : "blocked"}`);
  lines.push("");
  lines.push("## Authentication matrix");
  lines.push("");
  lines.push("| Identity | Role | Tenant | Method | Status |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const identity of identities) {
    lines.push(
      `| ${identity.label} | ${identity.role} | ${identity.tenant} | ${identity.authMethod} | ${identity.status} |`,
    );
  }
  lines.push("");
  lines.push("## Attack surface");
  lines.push("");
  lines.push("| Method | Path | Object | Risk | In scope |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const endpoint of endpoints) {
    lines.push(
      `| ${endpoint.method} | ${endpoint.path} | ${endpoint.objectType ?? "—"} | ${endpoint.risk} | ${endpoint.inScope ? "yes" : "no"} |`,
    );
  }
  lines.push("");
  if (coverage) {
    lines.push("## Coverage");
    lines.push("");
    for (const [key, value] of Object.entries(coverage)) {
      lines.push(`- ${key}: ${value}`);
    }
    lines.push("");
  }
  lines.push("## Findings");
  lines.push("");
  for (const finding of findings) {
    lines.push(`### ${finding.code} — ${finding.title}`);
    lines.push("");
    lines.push(`- **Severity:** ${finding.severity}`);
    lines.push(`- **Confidence:** ${finding.confidence} (${finding.score}/100)`);
    lines.push(`- **Classification:** ${finding.classification}`);
    lines.push(`- **CWE / OWASP:** ${finding.cwe} · ${finding.owasp}`);
    lines.push(`- **Endpoint:** ${finding.endpoint}`);
    lines.push(`- **Attacker:** ${finding.attacker}`);
    lines.push(`- **Victim:** ${finding.victim ?? "—"}`);
    lines.push(`- **Expected:** ${finding.expected}`);
    lines.push(`- **Actual:** ${finding.actual}`);
    lines.push("");
    lines.push("```http");
    lines.push(finding.request);
    lines.push("```");
    lines.push("");
    lines.push("**Response**");
    lines.push("");
    lines.push("```http");
    lines.push(finding.response);
    lines.push("```");
    lines.push("");
    const delta = (finding.stateDelta as Array<{ field: string; before: unknown; after: unknown }> | undefined) ?? [];
    if (delta.length > 0) {
      lines.push("**State delta**");
      lines.push("");
      for (const entry of delta) {
        lines.push(`- \`${entry.field}\`: ${String(entry.before)} → ${String(entry.after)}`);
      }
      lines.push("");
    }
    lines.push(`**Impact:** ${finding.impact}`);
    lines.push("");
    lines.push(`**Remediation:** ${finding.remediation}`);
    lines.push("");
    lines.push("**Reproduction**");
    lines.push("");
    finding.reproduction.forEach((step, i) => lines.push(`${i + 1}. ${step}`));
    lines.push("");
  }
  const inconclusive = tests.filter((t) => t.outcome === "inconclusive");
  lines.push("## Inconclusive tests");
  lines.push("");
  if (inconclusive.length === 0) {
    lines.push("None.");
  } else {
    for (const test of inconclusive) {
      lines.push(`- ${test.actorLabel} → ${test.method} ${test.path} (${test.probe})`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

function buildCsv(findings: Finding[]): string {
  const header = [
    "code",
    "title",
    "severity",
    "confidence",
    "score",
    "classification",
    "cwe",
    "owasp",
    "endpoint",
    "attacker",
    "victim",
    "expected",
    "actual",
    "parameter",
    "impact",
    "remediation",
  ];
  const esc = (value: string) => `"${value.replace(/"/g, '""')}"`;
  const rows = findings.map((f) =>
    [
      f.code,
      f.title,
      f.severity,
      f.confidence,
      String(f.score),
      f.classification,
      f.cwe,
      f.owasp,
      f.endpoint,
      f.attacker,
      f.victim ?? "",
      f.expected,
      f.actual,
      f.parameter ?? "",
      f.impact,
      f.remediation,
    ]
      .map(esc)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

function buildSarif(findings: Finding[]): string {
  const rules = Array.from(new Set(findings.map((f) => f.cwe))).map((cwe) => ({
    id: cwe,
    name: cwe,
    shortDescription: { text: cwe },
    properties: { tags: ["security", "authorization"] },
  }));
  const results = findings.map((f) => ({
    ruleId: f.cwe,
    level: f.severity === "critical" || f.severity === "high" ? "error" : "warning",
    message: {
      text: `${f.code} ${f.title}: ${f.expected} but observed ${f.actual}. ${f.impact}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.endpoint },
        },
      },
    ],
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      score: f.score,
      classification: f.classification,
      owasp: f.owasp,
      attacker: f.attacker,
      victim: f.victim ?? null,
    },
  }));
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "WABVE",
              version: "1.0.0",
              informationUri: "https://wabve.local",
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}

function buildHtml(input: ReportInput): string {
  const { engagement, findings, endpoints, identities } = input;
  const coverage = engagement.coverage as Record<string, number> | undefined;
  const rows = findings
    .map(
      (f) => `
      <section class="finding">
        <h3>${f.code} — ${escapeHtml(f.title)} <span class="sev ${f.severity}">${f.severity}</span></h3>
        <p class="meta">${escapeHtml(f.classification)} · ${escapeHtml(f.cwe)} · ${escapeHtml(f.owasp)} · confidence ${f.confidence} (${f.score}/100)</p>
        <table>
          <tr><th>Endpoint</th><td>${escapeHtml(f.endpoint)}</td></tr>
          <tr><th>Attacker</th><td>${escapeHtml(f.attacker)}</td></tr>
          <tr><th>Victim</th><td>${escapeHtml(f.victim ?? "—")}</td></tr>
          <tr><th>Expected</th><td>${escapeHtml(f.expected)}</td></tr>
          <tr><th>Actual</th><td>${escapeHtml(f.actual)}</td></tr>
        </table>
        <pre>${escapeHtml(f.request)}</pre>
        <pre>${escapeHtml(f.response)}</pre>
        ${renderDelta(f)}
        <p><strong>Impact.</strong> ${escapeHtml(f.impact)}</p>
        <p><strong>Remediation.</strong> ${escapeHtml(f.remediation)}</p>
      </section>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<title>WABVE Report — ${escapeHtml(engagement.name)}</title>
<style>
  :root { color-scheme: light; }
  body { font: 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 40px auto; max-width: 900px; color: #111827; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  h2 { font-size: 16px; margin-top: 32px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
  h3 { font-size: 15px; margin-bottom: 4px; }
  .meta { color: #6b7280; font-size: 12px; margin: 0 0 10px; }
  .sev { text-transform: uppercase; font-size: 10px; padding: 2px 8px; border-radius: 999px; letter-spacing: .08em; }
  .sev.critical { background: #fee2e2; color: #991b1b; }
  .sev.high { background: #ffedd5; color: #9a3412; }
  .sev.medium { background: #fef3c7; color: #92400e; }
  .sev.low { background: #e0f2fe; color: #075985; }
  .finding { border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin: 16px 0; page-break-inside: avoid; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }
  th, td { border: 1px solid #e5e7eb; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f9fafb; width: 130px; }
  pre { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; }
  .delta { color: #991b1b; }
  .muted { color: #6b7280; }
</style></head>
<body>
  <h1>WABVE Authorization &amp; Business Logic Verification Report</h1>
  <p class="meta">${escapeHtml(engagement.name)} · ${escapeHtml(engagement.target)} · generated ${new Date().toISOString()}</p>

  <h2>Scope</h2>
  <table>
    <tr><th>Allowed hosts</th><td>${escapeHtml(engagement.allowedHosts.join(", ") || "—")}</td></tr>
    <tr><th>Allowed paths</th><td>${escapeHtml(engagement.allowedPaths.join(", ") || "any")}</td></tr>
    <tr><th>Rate limit</th><td>${engagement.rateLimit} req/s</td></tr>
    <tr><th>Request budget</th><td>${engagement.requestBudget}</td></tr>
    <tr><th>Destructive</th><td>${engagement.destructiveTesting ? "approved" : "blocked"}</td></tr>
  </table>

  <h2>Authentication matrix</h2>
  <table><tr><th>Identity</th><th>Role</th><th>Tenant</th><th>Method</th><th>Status</th></tr>
  ${identities
    .map(
      (i) =>
        `<tr><td>${escapeHtml(i.label)}</td><td>${escapeHtml(i.role)}</td><td>${escapeHtml(i.tenant)}</td><td>${escapeHtml(i.authMethod)}</td><td>${escapeHtml(i.status)}</td></tr>`,
    )
    .join("")}
  </table>

  <h2>Attack surface</h2>
  <table><tr><th>Method</th><th>Path</th><th>Object</th><th>Risk</th><th>In scope</th></tr>
  ${endpoints
    .map(
      (e) =>
        `<tr><td>${escapeHtml(e.method)}</td><td>${escapeHtml(e.path)}</td><td>${escapeHtml(e.objectType ?? "—")}</td><td>${escapeHtml(e.risk)}</td><td>${e.inScope ? "yes" : "no"}</td></tr>`,
    )
    .join("")}
  </table>

  ${coverage ? `<h2>Coverage</h2><table>${Object.entries(coverage).map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(String(v))}</td></tr>`).join("")}</table>` : ""}

  <h2>Findings (${findings.length})</h2>
  ${rows || '<p class="muted">No findings were confirmed.</p>'}
</body></html>`;
}

function renderDelta(f: Finding): string {
  const delta = (f.stateDelta as Array<{ field: string; before: unknown; after: unknown }> | undefined) ?? [];
  if (delta.length === 0) return "";
  return `<p class="delta"><strong>State delta</strong></p><ul class="delta">${delta
    .map((d) => `<li>${escapeHtml(d.field)}: ${escapeHtml(String(d.before))} → ${escapeHtml(String(d.after))}</li>`)
    .join("")}</ul>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

const FORMATS = [
  { key: "html", label: "HTML", hint: "full report, styled" },
  { key: "pdf", label: "PDF", hint: "print to PDF" },
  { key: "json", label: "JSON", hint: "machine readable" },
  { key: "md", label: "Markdown", hint: "docs & tickets" },
  { key: "sarif", label: "SARIF", hint: "CI ingestion" },
  { key: "csv", label: "CSV", hint: "spreadsheet" },
];

export function ReportsPanel(input: ReportInput) {
  const { engagement, findings, tests } = input;
  const slug = engagement.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

  const preview = useMemo(() => buildMarkdown(input), [input]);

  const exportAs = (format: string) => {
    try {
      if (format === "html") {
        download(`${slug}-wabve-report.html`, buildHtml(input), "text/html");
      } else if (format === "json") {
        download(`${slug}-wabve-report.json`, JSON.stringify(buildJson(input), null, 2), "application/json");
      } else if (format === "md") {
        download(`${slug}-wabve-report.md`, preview, "text/markdown");
      } else if (format === "sarif") {
        download(`${slug}-wabve-report.sarif`, buildSarif(findings), "application/json");
      } else if (format === "csv") {
        download(`${slug}-findings.csv`, buildCsv(findings), "text/csv");
      } else if (format === "pdf") {
        const win = window.open("", "_blank");
        if (!win) {
          toast.error("Allow pop-ups to render the PDF.");
          return;
        }
        win.document.write(buildHtml(input));
        win.document.close();
        win.focus();
        win.print();
      }
      toast.success(`${format.toUpperCase()} export generated`);
    } catch {
      toast.error("Could not generate the export");
    }
  };

  const coverage = engagement.coverage as Record<string, number> | undefined;
  const inconclusive = tests.filter((t) => t.outcome === "inconclusive");

  return (
    <div className="space-y-6">
      <PanelHeader
        title="Reports"
        description="Every artefact is generated from the persisted evidence for this engagement — nothing is recomputed or invented at export time."
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {FORMATS.map((format) => (
          <Card key={format.key} className="border-border/60 bg-card/40 py-0 shadow-none">
            <CardContent className="flex items-center justify-between gap-3 px-4 py-4">
              <div className="flex items-center gap-3">
                <div className="flex size-9 items-center justify-center rounded-md border border-border/60 bg-background/50">
                  {format.key === "pdf" ? (
                    <Printer className="size-4 text-primary" />
                  ) : format.key === "json" || format.key === "sarif" ? (
                    <Code2 className="size-4 text-primary" />
                  ) : (
                    <FileText className="size-4 text-primary" />
                  )}
                </div>
                <div>
                  <p className="text-sm font-medium">{format.label}</p>
                  <p className="font-mono text-[10px] text-muted-foreground">{format.hint}</p>
                </div>
              </div>
              <Button size="sm" variant="outline" className="gap-1.5" onClick={() => exportAs(format.key)}>
                <Download className="size-3.5" />
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        {[
          ["Findings", String(findings.length)],
          ["Critical", String(coverage?.critical ?? 0)],
          ["High", String(coverage?.high ?? 0)],
          ["Inconclusive", String(inconclusive.length)],
        ].map(([label, value]) => (
          <div key={label} className="rounded-md border border-border/60 bg-card/40 px-4 py-3">
            <p className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
              {label}
            </p>
            <p className="mt-1 text-xl font-semibold tabular-nums">{value}</p>
          </div>
        ))}
      </div>

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardHeader className="flex-row items-center justify-between px-5 py-4">
          <CardTitle className="text-sm">Executive summary preview</CardTitle>
          <div className="flex flex-wrap gap-1.5">
            {findings.slice(0, 4).map((finding) => (
              <Tag key={finding._id} className={cn("font-mono", SEVERITY_CLASS[finding.severity])}>
                {finding.code} {finding.severity}
              </Tag>
            ))}
          </div>
        </CardHeader>
        <CardContent className="px-5 pb-5">
          <p className="text-xs leading-6 text-muted-foreground">
            WABVE verified <strong className="text-foreground/85">{tests.length}</strong> probes against{" "}
            <strong className="text-foreground/85">{input.endpoints.length}</strong> discovered endpoints
            using <strong className="text-foreground/85">{input.identities.length}</strong> identities.{" "}
            {findings.length === 0
              ? "No authorization or business-logic violation was confirmed."
              : `${findings.length} finding(s) were confirmed with evidence: ${
                  findings.filter((f) => f.severity === "critical").length
                } critical, ${findings.filter((f) => f.severity === "high").length} high, ${
                  findings.filter((f) => f.severity === "medium").length
                } medium.`}{" "}
            Categories exercised:{" "}
            <strong className="text-foreground/85">
              {Array.from(new Set(tests.map((t) => CATEGORY_LABEL[t.category] ?? t.category))).join(", ")}
            </strong>
            .
          </p>
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-card/40 py-0 shadow-none">
        <CardHeader className="px-5 py-4">
          <CardTitle className="text-sm">Markdown source</CardTitle>
        </CardHeader>
        <CardContent className="px-5 pb-5">
          <CodeBlock className="max-h-96">{preview.slice(0, 4000)}</CodeBlock>
        </CardContent>
      </Card>
    </div>
  );
}

export function topSeverity(findings: Finding[]): string | null {
  if (findings.length === 0) return null;
  return findings.slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0]
    .severity;
}
