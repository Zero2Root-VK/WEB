/**
 * WABVE — evidence → report mapping for real (non-modelled) runs.
 *
 * Everything here is pure: the runner executes network probes and hands the
 * records to these functions, which turn them into the exact rows the
 * dashboard, the console and the report exporters render. Keeping the mapping
 * separate from the I/O means the classification rules (category, CWE, OWASP,
 * severity, coverage) are unit-testable without a socket.
 */

import type { Coverage } from "../wabve/engine";
import type { FindingRecord, ProbePlan, TestRecord } from "./suite";

export type TestOutcome = "pass" | "fail" | "inconclusive" | "blocked";
export type Severity = "critical" | "high" | "medium" | "low";

/** Evidence bodies are clipped before persistence — a document has a size cap
 * and a 4 MB HTML error page is not evidence anyway. */
const BODY_CLIP = 20_000;

export function clip(text: string, limit = BODY_CLIP): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n… [truncated ${text.length - limit} characters]`;
}

/** Oracle verdict → the outcome vocabulary the UI already understands. */
export function outcomeFor(verdict: string): TestOutcome {
  if (verdict === "confirmed" || verdict === "likely") return "fail";
  if (verdict === "inconclusive") return "inconclusive";
  return "pass";
}

/* ------------------------------------------------------------------ */
/* classification                                                      */
/* ------------------------------------------------------------------ */

const OWASP_BY_CATEGORY: Record<string, string> = {
  authorization: "A01:2021 - Broken Access Control",
  tenant: "A01:2021 - Broken Access Control",
  bfla: "A01:2021 - Broken Access Control",
  method: "A01:2021 - Broken Access Control",
  property: "A08:2021 - Software and Data Integrity Failures",
  workflow: "A04:2021 - Insecure Design",
  business: "A04:2021 - Insecure Design",
  session: "A07:2021 - Identification and Authentication Failures",
};

/**
 * Which test class a probe belongs to, derived from the corroborating signals
 * the oracle actually produced — never from the endpoint alone.
 */
export function categoryFor(signals: string[]): string {
  if (signals.includes("privilege_boundary_crossed")) return "bfla";
  if (signals.includes("tenant_boundary_crossed")) return "tenant";
  if (signals.includes("protected_property_accepted")) return "property";
  if (signals.includes("workflow_transition_violated")) return "workflow";
  if (signals.includes("replay_accepted")) return "business";
  return "authorization";
}

export function owaspForCategory(category: string): string {
  return OWASP_BY_CATEGORY[category] ?? OWASP_BY_CATEGORY.authorization;
}

export function cweFor(signals: string[]): string {
  if (signals.includes("protected_property_accepted")) return "CWE-915";
  if (signals.includes("privilege_boundary_crossed")) return "CWE-285";
  if (signals.includes("server_state_changed")) return "CWE-862";
  if (signals.includes("protected_record_returned")) return "CWE-639";
  if (signals.includes("tenant_boundary_crossed")) return "CWE-639";
  return "CWE-639";
}

export function classificationFor(signals: string[]): string {
  if (signals.includes("protected_property_accepted")) return "Mass Assignment";
  if (signals.includes("privilege_boundary_crossed")) return "BFLA";
  if (signals.includes("tenant_boundary_crossed")) return "Tenant Isolation";
  if (signals.includes("replay_accepted")) return "Business Logic / Replay";
  if (signals.includes("workflow_transition_violated")) return "Workflow Bypass";
  return "BOLA / IDOR";
}

/** Severity of the evidence itself (used for a test's `risk` column). */
export function riskFor(signals: string[]): Severity {
  if (signals.includes("ownership_reassigned")) return "critical";
  if (signals.includes("privilege_boundary_crossed")) return "critical";
  if (signals.includes("tenant_boundary_crossed")) return "critical";
  if (signals.includes("server_state_changed")) return "high";
  if (signals.includes("protected_record_returned")) return "high";
  if (signals.includes("protected_property_accepted")) return "high";
  if (signals.includes("destructive_effect")) return "high";
  return "medium";
}

/** Snake-case probe name consistent with the modelled engine's vocabulary. */
export function probeNameFor(method: string): string {
  const upper = method.toUpperCase();
  if (upper === "DELETE") return "cross_identity_destructive_write";
  if (upper === "GET" || upper === "HEAD" || upper === "OPTIONS") return "cross_identity_read";
  return "cross_identity_write";
}

function endpointLabel(record: { method: string; path: string }): string {
  return `${record.method.toUpperCase()} ${record.path}`;
}

/* ------------------------------------------------------------------ */
/* findings                                                            */
/* ------------------------------------------------------------------ */

export function titleFor(finding: FindingRecord): string {
  const endpoint = finding.endpoint;
  const object = finding.objectRef ?? "a protected record";
  if (finding.signals.includes("ownership_reassigned")) {
    return `Ownership of ${object} reassigned through ${endpoint}`;
  }
  if (finding.signals.includes("protected_property_accepted")) {
    return `Protected property accepted by ${endpoint}`;
  }
  if (finding.signals.includes("privilege_boundary_crossed")) {
    return `Privilege boundary crossed on ${endpoint}`;
  }
  if (finding.signals.includes("tenant_boundary_crossed")) {
    return `Tenant boundary crossed on ${endpoint}`;
  }
  if (finding.signals.includes("server_state_changed")) {
    return `Unauthorized state change on ${endpoint}`;
  }
  return `Cross-identity read of ${object} through ${endpoint}`;
}

export function impactFor(finding: FindingRecord): string {
  const attacker = finding.attacker;
  const owner = finding.owner;
  if (finding.signals.includes("ownership_reassigned")) {
    return `${attacker} transferred ownership of ${finding.objectRef ?? "the object"} away from ${owner}. The server accepted an ownership field supplied by the client, so any authenticated user can take over another user's records.`;
  }
  if (finding.signals.includes("protected_property_accepted")) {
    return `${attacker} caused the server to persist a field the reference policy forbids the client from setting. This is the mass-assignment class of flaw and usually escalates straight to privilege or ownership takeover.`;
  }
  if (finding.signals.includes("privilege_boundary_crossed")) {
    return `${attacker} reached a function the reference policy reserves for a higher role. Function-level authorization failures expose administrative capability to ordinary sessions.`;
  }
  if (finding.signals.includes("tenant_boundary_crossed")) {
    return `${attacker} accessed a record belonging to another tenant. Tenant isolation failed, which is a full cross-customer data disclosure.`;
  }
  if (finding.signals.includes("server_state_changed")) {
    return `${attacker} changed persisted state on an object owned by ${owner}. The change survived a re-read by the owner, proving the write was committed rather than merely acknowledged.`;
  }
  return `${attacker} received protected data belonging to ${owner} that the reference policy forbids. Any authenticated user can enumerate other users' records by varying the identifier.`;
}

export function reproductionFor(
  finding: FindingRecord,
  labels: { attacker: string; owner: string },
): string[] {
  const steps = [
    `Authenticate as ${labels.attacker}.`,
    `Send ${finding.endpoint} referencing object ${finding.objectRef ?? "(observed id)"} (owner: ${labels.owner}).`,
    finding.delta.length > 0
      ? `Re-read the object as ${labels.owner} and confirm the listed field delta persists.`
      : `Confirm the protected payload is returned to ${labels.attacker}.`,
    `The reference policy requires 403/404; the target returned: ${finding.actual}.`,
    `Evidence: ${finding.reason}`,
  ];
  return steps;
}

/* ------------------------------------------------------------------ */
/* row builders                                                        */
/* ------------------------------------------------------------------ */

export interface TestRowShape {
  endpointKey: string;
  method: string;
  path: string;
  category: string;
  probe: string;
  actorKey: string;
  actorLabel: string;
  victimKey?: string;
  victimLabel?: string;
  objectRef?: string;
  parameter?: string;
  expectation: string;
  actual: string;
  outcome: TestOutcome;
  risk: Severity;
  statusCode: number;
  signals: string[];
  confidence: number;
  request: string;
  response: string;
  beforeState?: unknown;
  afterState?: unknown;
  stateDelta?: unknown;
}

function parseIfJson(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return text;
  try {
    return JSON.parse(trimmed);
  } catch {
    return text;
  }
}

export function toTestRow(input: {
  record: TestRecord;
  plan: ProbePlan;
  actorLabel: string;
  ownerLabel: string;
}): TestRowShape {
  const { record, plan, actorLabel, ownerLabel } = input;
  const outcome = outcomeFor(record.verdict);
  const signals = record.signals;
  return {
    endpointKey: record.endpointKey,
    method: record.method,
    path: record.path,
    category: categoryFor(signals),
    probe: probeNameFor(record.method),
    actorKey: record.attackerKey,
    actorLabel,
    victimKey: record.ownerKey,
    victimLabel: ownerLabel,
    ...(record.objectRef ? { objectRef: record.objectRef } : {}),
    ...(plan.objectRef ? { parameter: `${record.method === "GET" ? "path" : "body"}:${record.objectRef}` } : {}),
    expectation: record.expectation,
    actual: record.actual,
    outcome,
    risk: outcome === "fail" ? riskFor(signals) : "low",
    statusCode: record.attackerStatus,
    signals,
    confidence: record.confidence,
    request: [
      `${record.method} ${record.path}`,
      `reference (as ${ownerLabel}): HTTP ${record.ownerStatus}`,
      `attack (as ${actorLabel}): HTTP ${record.attackerStatus}`,
      plan.rationale ? `rationale: ${plan.rationale}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    response: clip(
      [
        `verdict: ${record.verdict} (confidence ${record.confidence})`,
        `reason: ${record.reason}`,
        record.delta.length > 0
          ? `state delta: ${record.delta.map((d) => `${d.field} ${JSON.stringify(d.before)} → ${JSON.stringify(d.after)}`).join(", ")}`
          : "",
        "--- attack response body ---",
        record.attackBody,
      ]
        .filter(Boolean)
        .join("\n"),
    ),
    beforeState: parseIfJson(record.baselineBody),
    afterState: parseIfJson(record.attackBody),
    ...(record.delta.length > 0 ? { stateDelta: record.delta } : {}),
  };
}

/** A probe the scope guard, rate limiter, budget or safety gate refused. */
export function toBlockedTestRow(input: {
  plan: ProbePlan;
  reason: string;
  detail: string;
  actorLabel: string;
  ownerLabel: string;
}): TestRowShape {
  const { plan, reason, detail, actorLabel, ownerLabel } = input;
  const path = safePath(plan.url);
  return {
    endpointKey: plan.endpointKey,
    method: plan.method,
    path,
    category: reason === "destructive_not_approved" ? "business" : "authorization",
    probe: probeNameFor(plan.method),
    actorKey: plan.attackerKey,
    actorLabel,
    victimKey: plan.ownerKey,
    victimLabel: ownerLabel,
    ...(plan.objectRef ? { objectRef: plan.objectRef } : {}),
    expectation: "DENY",
    actual: "BLOCKED",
    outcome: "blocked",
    risk: "low",
    statusCode: 0,
    signals: [reason],
    confidence: 0,
    request: `${plan.method} ${path} (blocked before dispatch: ${detail})`,
    response: `Safety control withheld this request. reason=${reason} detail=${detail}`,
  };
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export interface FindingRowShape {
  code: string;
  title: string;
  severity: Severity;
  confidence: string;
  score: number;
  classification: string;
  cwe: string;
  owasp: string;
  endpoint: string;
  parameter?: string;
  attacker: string;
  victim?: string;
  probe: string;
  expected: string;
  actual: string;
  request: string;
  response: string;
  beforeState?: unknown;
  afterState?: unknown;
  stateDelta?: unknown;
  signals: string[];
  reproduction: string[];
  impact: string;
  remediation: string;
}

export function toFindingRow(input: {
  record: FindingRecord;
  code: string;
  actorLabel: string;
  ownerLabel: string;
}): FindingRowShape {
  const { record, code, actorLabel, ownerLabel } = input;
  const category = categoryFor(record.signals);
  const method = record.endpoint.split(" ")[0] ?? "GET";
  return {
    code,
    title: titleFor(record),
    severity: record.severity,
    confidence: record.confidence,
    score: record.score,
    classification: classificationFor(record.signals),
    cwe: cweFor(record.signals),
    owasp: owaspForCategory(category),
    endpoint: record.endpoint,
    ...(record.objectRef ? { parameter: `object:${record.objectRef}` } : {}),
    attacker: actorLabel,
    victim: ownerLabel,
    probe: probeNameFor(method),
    expected: record.expected,
    actual: record.actual,
    request: clip(
      [
        `${record.endpoint} as ${actorLabel}`,
        `baseline (as ${ownerLabel}): ${clip(record.beforeState, 4000)}`,
      ].join("\n"),
    ),
    response: clip(
      [
        `verdict: ${record.verdict} (${record.score}/100)`,
        `reason: ${record.reason}`,
        record.delta.length > 0
          ? `state delta: ${record.delta.map((d) => `${d.field} ${JSON.stringify(d.before)} → ${JSON.stringify(d.after)}`).join(", ")}`
          : "",
        "--- after ---",
        clip(record.afterState, 8000),
      ]
        .filter(Boolean)
        .join("\n"),
    ),
    beforeState: parseIfJson(record.beforeState),
    afterState: parseIfJson(record.afterState),
    ...(record.delta.length > 0 ? { stateDelta: record.delta } : {}),
    signals: record.signals,
    reproduction: reproductionFor(record, { attacker: actorLabel, owner: ownerLabel }),
    impact: impactFor(record),
    remediation: record.remediation,
  };
}

/* ------------------------------------------------------------------ */
/* coverage                                                            */
/* ------------------------------------------------------------------ */

export interface CoverageInput {
  endpoints: Array<{ inScope: boolean; authRequired: boolean }>;
  tests: Array<{ outcome: string; category: string; actorKey?: string }>;
  findings: Array<{ severity: string }>;
  objects: unknown[];
  identities: unknown[];
  requestBudget: number;
  requestsUsed: number;
  blockedOutOfScope: number;
  dryRun: boolean;
}

/**
 * Same coverage vocabulary as the modelled engine so the dashboard, exports
 * and both run modes render identically.
 */
export function realCoverage(input: CoverageInput): Coverage {
  const { endpoints, tests, findings } = input;
  const failed = tests.filter((t) => t.outcome === "fail").length;
  const bySeverity = (severity: string) => findings.filter((f) => f.severity === severity).length;
  return {
    endpointsDiscovered: endpoints.length,
    endpointsInScope: endpoints.filter((e) => e.inScope).length,
    blockedOutOfScope: input.blockedOutOfScope,
    authenticatedEndpoints: endpoints.filter((e) => e.authRequired).length,
    objectsIdentified: input.objects.length,
    rolesIdentified:
      new Set(tests.map((t) => t.actorKey).filter(Boolean)).size || input.identities.length,
    authorizationTests: tests.filter((t) => t.category !== "business").length,
    businessLogicTests: tests.filter((t) => t.category === "business").length,
    totalTests: tests.length,
    passed: tests.filter((t) => t.outcome === "pass").length,
    failed,
    inconclusive: tests.filter((t) => t.outcome === "inconclusive").length,
    blocked: tests.filter((t) => t.outcome === "blocked").length,
    findings: findings.length,
    critical: bySeverity("critical"),
    high: bySeverity("high"),
    medium: bySeverity("medium"),
    low: bySeverity("low"),
    requestsUsed: input.requestsUsed,
    requestBudget: input.requestBudget,
    safetyBlocks: tests.filter((t) => t.outcome === "blocked").length,
    dryRun: input.dryRun,
  };
}

/** `WABVE-001` style codes, ordered by the caller's severity ranking. */
export function findingCode(index: number): string {
  return `WABVE-${String(index + 1).padStart(3, "0")}`;
}
