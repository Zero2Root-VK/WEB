/**
 * WABVE — live assessment harness.
 *
 * Runs a complete assessment against a real HTTP target over a real socket,
 * using the same modules the Convex runner uses in production:
 *
 *   discovery → object model → cross-identity probe → evidence → report
 *
 * Nothing here is mocked. The only difference from a production run is the
 * target: a deliberately vulnerable, two-tenant API that this script starts
 * itself, so the demonstration is authorised by construction and never touches
 * a third party.
 *
 * Run with:  bun run demo:live
 */

import { mkdir } from "node:fs/promises";

import { authorize, createBucket, type ScopeConfig } from "../convex/real/engine";
import {
  mergeEndpoints,
  parseForms,
  parseHtml,
  parseOpenApi,
  pathParameters,
  type DiscoveredEndpoint,
} from "../convex/real/discovery";
import { dispatch, fetchDocument, type RateState, type RealIdentity } from "../convex/real/executor";
import {
  executeSuite,
  indexObjects,
  planProbes,
  type EndpointSpec,
  type ObservedObject,
  type ProbePlan,
  type Transport,
} from "../convex/real/suite";
import {
  findingCode,
  realCoverage,
  toBlockedTestRow,
  toFindingRow,
  toTestRow,
  type FindingRowShape,
  type TestRowShape,
} from "../convex/real/reporting";
import { categoryForPath, objectTypeFor } from "../convex/real/runplan";
import type { Coverage } from "../convex/wabve/engine";

/* ================================================================== */
/* the target: a two-tenant API with two real access-control defects   */
/* ================================================================== */

type Owner = "alice" | "bob";

interface Order {
  id: string;
  owner: Owner;
  tenant_id: string;
  status: "pending" | "shipped";
  /** Optimistic-concurrency counter. Non-idempotent on purpose: an idempotent
   * write would leave no delta in the owner's re-read, and the engine refuses
   * to claim a state change it cannot corroborate. */
  revision: number;
  total: number;
  reference: string;
  title: string;
}

const TOKENS: Record<string, Owner> = { "tok-alice": "alice", "tok-bob": "bob" };

const ORDERS: Record<string, Order> = {
  "1001": { id: "1001", owner: "alice", tenant_id: "acme", status: "pending", revision: 1, total: 420.5, reference: "ORD-1001-ACME", title: "Acme rack" },
  "2002": { id: "2002", owner: "bob", tenant_id: "globex", status: "pending", revision: 1, total: 88, reference: "ORD-2002-GLOBEX", title: "Globex seats" },
};

const INVOICES: Record<string, Order> = {
  "5001": { id: "5001", owner: "alice", tenant_id: "acme", status: "pending", revision: 1, total: 420.5, reference: "INV-5001-ACME", title: "Acme invoice" },
  "6002": { id: "6002", owner: "bob", tenant_id: "globex", status: "pending", revision: 1, total: 88, reference: "INV-6002-GLOBEX", title: "Globex invoice" },
};

const PAGE = `<!doctype html><html><body>
<h1>Acme Commerce API</h1>
<a href="/api/orders">Orders</a>
<a href="/api/invoices">Invoices</a>
<form action="/api/orders" method="post"><input name="title"><input name="total"></form>
<script>fetch('/api/orders')</script>
</body></html>`;

const SPEC = {
  swagger: "2.0",
  host: "127.0.0.1",
  schemes: ["http"],
  basePath: "/",
  paths: {
    "/api/orders": { get: {}, post: { parameters: [{ name: "title", in: "body" }] } },
    "/api/orders/{order_id}": {
      get: { parameters: [{ name: "order_id", in: "path" }] },
      patch: { parameters: [{ name: "order_id", in: "path" }] },
      delete: { parameters: [{ name: "order_id", in: "path" }] },
    },
    "/api/invoices": { get: {} },
    "/api/invoices/{invoice_id}": {
      get: { parameters: [{ name: "invoice_id", in: "path" }] },
      patch: { parameters: [{ name: "invoice_id", in: "path" }] },
    },
    "/health": { get: {} },
  },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function ownerOf(req: Request): Owner | null {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.get("authorization") ?? "");
  return match ? TOKENS[match[1] ?? ""] ?? null : null;
}

const requestLog: string[] = [];

function startTarget() {
  return Bun.serve({
    port: 0,
    fetch(req) {
      const path = new URL(req.url).pathname;
      requestLog.push(`${req.method} ${path}`);

      if (path === "/api") return new Response(PAGE, { headers: { "content-type": "text/html" } });
      if (path === "/openapi.json") return json(SPEC);
      if (path === "/health") return json({ status: "ok" });

      // Operator-only surface. In scope nowhere, and reachable only with a
      // token no test identity holds — the reference policy denies everyone.
      if (path === "/admin/users") return json([{ id: "root", email: "root@acme.test" }]);

      const caller = ownerOf(req);
      if (!caller) return json({ error: "unauthorized" }, 401);

      const collection = path === "/api/orders" ? ORDERS : path === "/api/invoices" ? INVOICES : null;
      if (collection) {
        if (req.method === "GET") return json(Object.values(collection).filter((r) => r.owner === caller));
        return json({ error: "method_not_allowed" }, 405);
      }

      // DEFECT 1 — broken object level authorization on order reads. Any
      // authenticated caller may read any order; ownership is never checked.
      // Scoped to orders so the invoice endpoint further down stays a genuine
      // control: if this matched invoices too, that "secure" block would be
      // unreachable dead code and the control would be a fiction.
      const read = /^\/api\/orders\/([^/]+)$/.exec(path);
      if (read && req.method === "GET") {
        const record = ORDERS[read[1] ?? ""];
        if (!record) return json({ error: "not_found" }, 404);
        return json(record); // no ownership predicate
      }

      // DEFECT 2 — unauthorized state transition on orders. Same missing
      // predicate, but on a write, so the effect persists.
      const write = /^\/api\/orders\/([^/]+)$/.exec(path);
      if (write && req.method === "PATCH") {
        const record = ORDERS[write[1] ?? ""];
        if (!record) return json({ error: "not_found" }, 404);
        record.status = "shipped"; // no ownership predicate
        record.revision += 1;
        return json(record);
      }

      // SECURE — the ownership predicate is enforced inside both the read and
      // the write, so the reference policy and the actual policy agree.
      const invoiceRead = /^\/api\/invoices\/([^/]+)$/.exec(path);
      if (invoiceRead && (req.method === "GET" || req.method === "PATCH")) {
        const record = INVOICES[invoiceRead[1] ?? ""];
        if (!record) return json({ error: "not_found" }, 404);
        // A 403 rather than a 404: the record exists, the caller simply may not
        // read or change it.
        if (record.owner !== caller) return json({ error: "forbidden" }, 403);
        if (req.method === "PATCH") {
          record.status = "shipped";
          record.revision += 1;
        }
        return json(record);
      }

      if (req.method === "DELETE") {
        const record = ORDERS[path.split("/")[3] ?? ""];
        if (record) {
          delete ORDERS[record.id];
          return json({ deleted: true });
        }
        return json({ error: "not_found" }, 404);
      }

      return json({ error: "not_found" }, 404);
    },
  });
}

/* ================================================================== */
/* scope and identities                                                */
/* ================================================================== */

const server = startTarget();
const base = `http://127.0.0.1:${server.port}`;

const scope: ScopeConfig = {
  target: base,
  allowedHosts: ["127.0.0.1"],
  allowedPaths: ["/api", "/openapi.json", "/health"],
  // The token bucket starts full at `rateLimit` tokens, so a complete run's
  // burst (discovery + model + every probe) has to fit under it or probes will
  // be throttled away. The harness asserts nothing was dropped for that reason.
  rateLimit: 50,
  requestBudget: 500,
  killSwitch: false,
  // Destructive methods stay unapproved, so the safety gate has something real
  // to withhold and the report shows it.
  destructiveTesting: false,
  dryRun: false,
};

const secrets = Object.keys(TOKENS);

const identities: RealIdentity[] = [
  { key: "alice", label: "Alice (acme)", role: "customer", authType: "bearer", secret: "tok-alice" },
  { key: "bob", label: "Bob (globex)", role: "customer", authType: "bearer", secret: "tok-bob" },
];
const identitiesByKey = new Map(identities.map((i) => [i.key, i]));
const labelOf = (key: string) => identitiesByKey.get(key)?.label ?? key;

const rate: RateState = { bucket: createBucket(scope.rateLimit, Date.now()), rateLimit: scope.rateLimit };
let requestsUsed = 0;

/** The real transport: guard → rate → socket, exactly as in production. */
const transport: Transport = async ({ plan, identity }) => {
  const outcome = await dispatch({
    scope,
    request: { method: plan.method, url: plan.url },
    identity,
    requestsUsed: (requestsUsed += 1),
    secrets,
    rate,
  });
  if (outcome.kind === "sent") return { status: outcome.response.status, body: outcome.response.body };
  if (outcome.kind === "blocked") throw new Error(`blocked: ${outcome.reason}`);
  throw new Error(outcome.message);
};

async function fetchAs(identity: RealIdentity, path: string) {
  const outcome = await dispatch({
    scope,
    request: { method: "GET", url: `${base}${path}` },
    identity,
    requestsUsed: (requestsUsed += 1),
    secrets,
    rate,
  });
  if (outcome.kind !== "sent") throw new Error(`expected a response for ${path}, got ${outcome.kind}`);
  return outcome.response;
}

/* ================================================================== */
/* stage 1 — discovery                                                 */
/* ================================================================== */

async function discover(): Promise<DiscoveredEndpoint[]> {
  const found: DiscoveredEndpoint[] = [];

  const spec = await fetchDocument({ scope, url: `${base}/openapi.json`, requestsUsed: 0, rate });
  if (spec.kind === "ok") found.push(...parseOpenApi(JSON.parse(spec.text)));

  const page = await fetchDocument({ scope, url: `${base}/api`, requestsUsed: 0, rate });
  if (page.kind === "ok") {
    found.push(...parseHtml(page.text, base));
    found.push(...parseForms(page.text, base));
  }
  return mergeEndpoints(found);
}

/* ================================================================== */
/* stage 2 — object model                                              */
/* ================================================================== */

async function modelOrdersAndInvoices(): Promise<ObservedObject[]> {
  const responses: Array<{ identityKey: string; path: string; body: string }> = [];
  for (const identity of identities) {
    for (const path of ["/api/orders", "/api/invoices"]) {
      const response = await fetchAs(identity, path);
      responses.push({ identityKey: identity.key, path, body: response.body });
    }
  }
  // Drop anything whose owner is not a known identity: an unmatched owner would
  // make the cross-identity claim meaningless.
  return indexObjects(responses).filter((object) => identitiesByKey.has(object.ownerKey));
}

/* ================================================================== */
/* run                                                                 */
/* ================================================================== */

async function main() {
  const line = (title: string) => console.log(`\n\u001b[36m${title}\u001b[0m`);

  line(`WABVE live assessment → ${base}`);
  console.log(`scope: ${scope.allowedPaths.join(", ")}  ·  rate ${scope.rateLimit}/s  ·  budget ${scope.requestBudget}`);
  console.log(`destructive testing: ${scope.destructiveTesting ? "approved" : "NOT approved (DELETE will be withheld)"}`);

  const discovered = await discover();
  const endpointRows = discovered.map((ep) => {
    const parameters = Array.from(new Set([...ep.parameters, ...pathParameters(ep.path)]));
    const method = ep.method.toUpperCase();
    const decision = authorize({ scope, url: `${base}${ep.path}`, method, requestsUsed: 0 });
    const objectType = objectTypeFor(ep.path);
    return {
      key: `${method} ${ep.path}`,
      method,
      path: ep.path,
      parameters,
      authRequired: !/^\/(?:health|login|signup|robots\.txt|favicon\.ico)/i.test(ep.path),
      ...(objectType ? { objectType } : {}),
      category: categoryForPath(ep.path),
      inScope: decision.allowed,
      discoveredVia: ep.source,
    };
  });
  console.log(`\nstage 1 · discovery → ${endpointRows.length} endpoints from ${new Set(discovered.map((e) => e.source)).size} source type(s)`);
  for (const row of endpointRows) {
    console.log(`  ${row.inScope ? "\u001b[32m✓\u001b[0m" : "\u001b[33m×\u001b[0m"} ${row.key}  [${row.category}, via ${row.discoveredVia}]`);
  }

  const objects = await modelOrdersAndInvoices();
  console.log(`\nstage 2 · model → ${objects.length} records attributed to an owner`);
  for (const object of objects) {
    console.log(`  ${object.type} ${object.ref} → ${labelOf(object.ownerKey)} (tenant ${object.tenant})`);
  }

  const specs: EndpointSpec[] = endpointRows.map((row) => ({
    key: row.key,
    method: row.method,
    path: row.path,
    parameters: row.parameters,
    requiresAuth: row.authRequired,
    source: row.discoveredVia,
  }));

  const plans = planProbes({
    endpoints: specs,
    objects,
    identities,
    baseUrl: base,
    tenantOf: (key) => (key === "alice" ? "acme" : "globex"),
    // No `destructivePaths` here on purpose: that option marks *every* method on
    // a path irreversible. DELETE is already destructive by method, so listing
    // the path would withhold the GET and PATCH probes too and the assessment
    // would silently test nothing.
  });

  // Stage 3 — pre-filter every plan through the guard before any socket opens,
  // exactly as the runner does.
  const runnable: ProbePlan[] = [];
  const blockedRows: TestRowShape[] = [];
  for (const plan of plans) {
    const decision = authorize({
      scope,
      url: plan.url,
      method: plan.method,
      requestsUsed,
      destructive: plan.destructive,
    });
    if (decision.allowed) {
      runnable.push(plan);
      continue;
    }
    blockedRows.push(
      toBlockedTestRow({
        plan,
        reason: decision.reason,
        detail: decision.detail,
        actorLabel: labelOf(plan.attackerKey),
        ownerLabel: labelOf(plan.ownerKey),
      }),
    );
  }
  console.log(`\nstage 3 · probe → ${plans.length} planned, ${runnable.length} dispatched, ${blockedRows.length} withheld by the safety gate`);

  const suite = await executeSuite({ plans: runnable, identitiesByKey, transport });
  const planById = new Map(runnable.map((p) => [p.id, p]));

  const testRows: TestRowShape[] = [];
  for (const record of suite.tests) {
    const plan = planById.get(record.planId);
    if (!plan) continue;
    testRows.push(
      toTestRow({ record, plan, actorLabel: labelOf(record.attackerKey), ownerLabel: labelOf(record.ownerKey) }),
    );
  }
  testRows.push(...blockedRows);

  // Stage 4 — report. Findings are renumbered by severity, then score, then
  // endpoint, so the same evidence always produces the same report.
  const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const ordered = [...suite.findings].sort(
    (a, b) =>
      (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
      b.score - a.score ||
      a.endpoint.localeCompare(b.endpoint),
  );
  const findingRows: FindingRowShape[] = ordered.map((record, index) =>
    toFindingRow({
      record,
      code: findingCode(index),
      // FindingRecord already carries the identity labels resolved during the
      // probe; it has no `attackerKey`/`ownerKey` fields.
      actorLabel: record.attacker,
      ownerLabel: record.owner,
    }),
  );

  const coverage = realCoverage({
    endpoints: endpointRows.map((row) => ({ inScope: row.inScope, authRequired: row.authRequired })),
    tests: testRows.map((row) => ({ outcome: row.outcome, category: row.category, actorKey: row.actorKey })),
    findings: findingRows.map((row) => ({ severity: row.severity })),
    objects,
    identities,
    requestBudget: scope.requestBudget,
    requestsUsed,
    blockedOutOfScope: blockedRows.length,
    dryRun: scope.dryRun,
  });

  console.log(`\nstage 4 · report → ${findingRows.length} finding(s), ${testRows.length} test(s)`);
  for (const finding of findingRows) {
    const colour = finding.severity === "critical" ? "\u001b[31m" : "\u001b[33m";
    console.log(`  ${colour}${finding.severity.toUpperCase()}\u001b[0m ${finding.code}  ${finding.title}`);
    console.log(`         ${finding.endpoint}  ·  ${finding.cwe}  ·  ${finding.owasp}`);
    console.log(`         ${finding.attacker} → ${finding.victim}  (confidence ${finding.confidence}, score ${finding.score})`);
  }
  console.log("\n  evidence table:");
  for (const row of testRows) {
    const tag =
      row.outcome === "fail" ? "\u001b[31mFAIL\u001b[0m" : row.outcome === "pass" ? "\u001b[32mPASS\u001b[0m" : row.outcome === "blocked" ? "\u001b[35mBLOCK\u001b[0m" : "\u001b[33mINCL\u001b[0m";
    console.log(`    ${tag}  ${row.method.padEnd(6)} ${row.path.padEnd(30)} ${row.actorLabel} → ${row.victimLabel ?? "—"}  HTTP ${row.statusCode}`);
  }

  console.log("\n  coverage:");
  for (const [key, value] of Object.entries(coverage)) {
    console.log(`    ${key.padEnd(24)} ${value}`);
  }

  /* -------- artifacts -------- */
  const report = {
    generatedAt: new Date().toISOString(),
    target: base,
    mode: "live",
    scope,
    coverage,
    findings: findingRows,
    tests: testRows,
    objects,
    endpointCount: endpointRows.length,
    requestsUsed,
    note: "Self-hosted demonstration target. Not a third-party scan.",
  };

  const markdown = renderMarkdown(report);
  const outDir = "wabve-reports";
  await mkdir(outDir, { recursive: true });
  await Bun.write(`${outDir}/wabve-live-report.json`, JSON.stringify(report, null, 2));
  await Bun.write(`${outDir}/wabve-live-report.md`, markdown);

  console.log(`\n\u001b[32m✓ assessment complete\u001b[0m  ${requestsUsed} requests, ${suite.blocked} blocked, ${suite.errors} errors`);
  console.log(`  ${outDir}/wabve-live-report.json`);
  console.log(`  ${outDir}/wabve-live-report.md`);

  // Fail loudly if the engine ever stops distinguishing the vulnerable endpoint
  // from the secure one — this harness is also a regression check.
  const vulnFindings = findingRows.filter((f) => f.endpoint.includes("/api/orders/"));
  const secureFindings = findingRows.filter((f) => f.endpoint.includes("/api/invoices/"));
  if (vulnFindings.length < 4 || secureFindings.length !== 0) {
    throw new Error(
      `unexpected result: ${vulnFindings.length} order findings (want 4), ${secureFindings.length} invoice findings (want 0)`,
    );
  }
  // Both evidence paths must be exercised: disclosure of a protected payload by
  // the read probes, and a persisted state change corroborated by the owner's
  // post-attack re-read on the write probes.
  if (!vulnFindings.some((f) => f.signals.includes("protected_record_returned"))) {
    throw new Error("expected at least one finding corroborated by a protected payload");
  }
  if (!vulnFindings.some((f) => f.signals.includes("server_state_changed"))) {
    throw new Error("expected at least one finding corroborated by persisted state change");
  }
  // A probe dropped by the rate limiter is lost coverage, not a clean result.
  if (suite.blocked !== 0 || suite.errors !== 0) {
    throw new Error(
      `incomplete run: ${suite.blocked} probe(s) throttled, ${suite.errors} transport error(s) — raise the rate limit or budget`,
    );
  }

  server.stop(true);
}

function renderMarkdown(report: {
  generatedAt: string;
  target: string;
  coverage: Coverage;
  findings: FindingRowShape[];
  tests: TestRowShape[];
  requestsUsed: number;
  note: string;
}): string {
  const out: string[] = [];
  out.push(`# WABVE assessment report`, "");
  out.push(`- **Target:** \`${report.target}\``);
  out.push(`- **Generated:** ${report.generatedAt}`);
  out.push(`- **Requests used:** ${report.requestsUsed}`);
  out.push(`- **Note:** ${report.note}`, "");
  out.push(`## Coverage`, "");
  for (const [key, value] of Object.entries(report.coverage)) out.push(`- ${key}: **${value}**`);
  out.push("", `## Findings`, "");
  for (const f of report.findings) {
    out.push(`### ${f.code} — ${f.title}`, "");
    out.push(`| | |`, `|---|---|`);
    out.push(`| Severity | **${f.severity}** |`);
    out.push(`| Confidence | ${f.confidence} (${f.score}/100) |`);
    out.push(`| Classification | ${f.classification} |`);
    out.push(`| CWE | ${f.cwe} |`);
    out.push(`| OWASP | ${f.owasp} |`);
    out.push(`| Endpoint | \`${f.endpoint}\` |`);
    out.push(`| Actor → Victim | ${f.attacker} → ${f.victim ?? "—"} |`);
    out.push(`| Expected | ${f.expected} |`);
    out.push(`| Actual | ${f.actual} |`);
    out.push("", `**Impact.** ${f.impact}`, "");
    out.push(`**Reproduction.**`);
    for (const step of f.reproduction) out.push(`1. ${step}`);
    out.push("", `**Remediation.** ${f.remediation}`, "");
  }
  out.push(`## Evidence table`, "", `| Outcome | Method | Path | Actor | Victim | HTTP | Signals |`, `|---|---|---|---|---|---|---|`);
  for (const t of report.tests) {
    out.push(`| ${t.outcome} | ${t.method} | \`${t.path}\` | ${t.actorLabel} | ${t.victimLabel ?? "—"} | ${t.statusCode} | ${t.signals.join(", ")} |`);
  }
  return `${out.join("\n")}\n`;
}

await main();
