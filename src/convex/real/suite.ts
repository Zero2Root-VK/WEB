/**
 * WABVE — authorization test suite.
 *
 * Plans cross-identity probes from a real endpoint registry, runs a baseline
 * request as the owner and an attack request as the challenger, then lets the
 * differential oracle decide whether anything was actually violated.
 *
 * The network is injected (`Transport`), so this entire pipeline is testable
 * without touching a real host — and `executor.ts` supplies the real one in
 * production. Nothing here decides a finding from a status code alone.
 */

import {
  differentialOracle,
  protectedMarkers,
  type DeltaEntry,
  type ScopeConfig,
} from "./engine";
import type { RealIdentity } from "./executor";

/* ------------------------------------------------------------------ */
/* model                                                               */
/* ------------------------------------------------------------------ */

export interface EndpointSpec {
  key: string;
  method: string;
  /** Path template, e.g. `/api/orders/{order_id}`. */
  path: string;
  parameters: string[];
  requiresAuth: boolean;
  source: string;
}

export interface ObservedObject {
  ref: string;
  type: string;
  ownerKey: string;
  tenant: string;
  source: string;
}

export interface ProbePlan {
  id: string;
  endpointKey: string;
  method: string;
  url: string;
  /** Identity whose request is expected to be permitted. */
  ownerKey: string;
  /** Identity attempting the access. */
  attackerKey: string;
  objectRef?: string;
  destructive: boolean;
  rationale: string;
}

export interface TestRecord {
  planId: string;
  endpointKey: string;
  method: string;
  path: string;
  attackerKey: string;
  ownerKey: string;
  objectRef?: string;
  expectation: "ALLOW" | "DENY";
  actual: "ALLOW" | "DENY";
  attackerStatus: number;
  ownerStatus: number;
  verdict: string;
  signals: string[];
  confidence: number;
  reason: string;
  baselineBody: string;
  attackBody: string;
  delta: DeltaEntry[];
}

export interface FindingRecord {
  code: string;
  testId: string;
  endpoint: string;
  objectRef?: string;
  attacker: string;
  owner: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: string;
  score: number;
  verdict: string;
  signals: string[];
  expected: string;
  actual: string;
  reason: string;
  beforeState: string;
  afterState: string;
  delta: DeltaEntry[];
  remediation: string;
}

export interface SuiteResult {
  tests: TestRecord[];
  findings: FindingRecord[];
  requestsUsed: number;
  blocked: number;
  errors: number;
}

/* ------------------------------------------------------------------ */
/* object indexing                                                     */
/* ------------------------------------------------------------------ */

const OBJECT_KEYS = /(?:^|_)(?:id|identifier|ref|code|number)$/i;
const OWNER_KEYS = /^(?:owner|owner_?id|owner_?name|user_?id|user_?name|created_?by|author|account_?id)$/i;
const TENANT_KEYS = /^(?:tenant_?id|tenant_?name|org_?id|organisation|organization|company_?id|workspace_?id)$/i;

/**
 * Learn which identity owns which resource by reading real responses.
 *
 * An object is attributed to whoever returned it unless the payload names an
 * owner explicitly, which is what makes a cross-identity probe meaningful
 * rather than a coin flip.
 */
export function indexObjects(
  responses: Array<{ identityKey: string; path: string; body: string }>,
): ObservedObject[] {
  const seen = new Map<string, ObservedObject>();

  for (const response of responses) {
    let payload: unknown;
    try {
      payload = JSON.parse(response.body);
    } catch {
      continue;
    }
    const type = guessType(response.path);
    walk(payload, (node) => {
      const ref = readRef(node);
      if (!ref) return;
      const key = `${type}:${ref}`;
      if (seen.has(key)) return;
      const owner = readField(node, OWNER_KEYS) ?? response.identityKey;
      const tenant = readField(node, TENANT_KEYS) ?? "unknown";
      seen.set(key, {
        ref,
        type,
        ownerKey: typeof owner === "string" ? owner : String(owner),
        tenant: typeof tenant === "string" ? tenant : String(tenant),
        source: response.path,
      });
    });
  }
  return Array.from(seen.values());
}

function walk(value: unknown, visit: (node: Record<string, unknown>) => void, depth = 0): void {
  if (depth > 8) return;
  if (Array.isArray(value)) {
    for (const item of value) walk(item, visit, depth + 1);
    return;
  }
  if (!value || typeof value !== "object") return;
  const node = value as Record<string, unknown>;
  visit(node);
  for (const item of Object.values(node)) walk(item, visit, depth + 1);
}

function readRef(node: Record<string, unknown>): string | null {
  // Prefer a plain `id`: `user_id` also matches the pattern but names a
  // foreign key, which would index the wrong object.
  const entries = Object.entries(node).sort(([a], [b]) => Number(b === "id") - Number(a === "id"));
  for (const [key, value] of entries) {
    if (!OBJECT_KEYS.test(key)) continue;
    if (typeof value === "number") return String(value);
    if (typeof value === "string" && value.length > 0 && value.length <= 64) return value;
  }
  return null;
}

function readField(node: Record<string, unknown>, pattern: RegExp): unknown {
  for (const [key, value] of Object.entries(node)) {
    if (pattern.test(key) && (typeof value === "string" || typeof value === "number")) return value;
  }
  return null;
}

/** `/api/orders/{order_id}` → `order`. */
export function guessType(path: string): string {
  const segments = path.split("/").filter(Boolean);
  // Keep segments that name something, so a concrete id or a path parameter
  // never gets mistaken for the resource.
  const named = segments.filter((s) => !s.startsWith("{") && /[a-z]/i.test(s));
  const resource =
    named.find((s) => !/^(?:api|v\d+|rest|graphql|app|auth)$/i.test(s)) ?? named[0];
  if (!resource) return "resource";
  const clean = resource.replace(/\.[a-z0-9]+$/i, "");
  return clean.endsWith("s") ? clean.slice(0, -1) : clean;
}

/* ------------------------------------------------------------------ */
/* planning                                                            */
/* ------------------------------------------------------------------ */

export function substitute(path: string, parameter: string, value: string): string {
  return path.replace(`{${parameter}}`, encodeURIComponent(value));
}

/**
 * Build the cross-identity matrix: for every object-aware endpoint, each
 * non-owner identity is tested against an object owned by someone else, with
 * the owner's own request as the baseline.
 */
export function planProbes(input: {
  endpoints: EndpointSpec[];
  objects: ObservedObject[];
  identities: RealIdentity[];
  baseUrl: string;
  /** Only plan probes where identities differ in this dimension. */
  tenantOf: (identityKey: string) => string;
  destructivePaths?: string[];
}): ProbePlan[] {
  const { endpoints, objects, identities, baseUrl } = input;
  const authenticated = identities.filter((i) => i.authType !== "none");
  const plans: ProbePlan[] = [];

  for (const endpoint of endpoints) {
    const parameter = endpoint.parameters[0];
    if (!parameter) continue;
    if (!endpoint.path.includes("{")) continue;

    // The path parameter names the object it resolves to: `{order_id}` → order.
    const parameterBase = parameter.replace(/_id$/, "");
    const candidates = objects.filter(
      (object) => object.type === parameterBase || parameterBase === "id",
    );
    if (candidates.length === 0) continue;

    for (const object of candidates) {
      const url = `${baseUrl.replace(/\/$/, "")}${substitute(endpoint.path, parameter, object.ref)}`;
      const isDestructive =
        endpoint.method.toUpperCase() === "DELETE" ||
        (input.destructivePaths ?? []).includes(endpoint.path);

      for (const attacker of authenticated) {
        if (attacker.key === object.ownerKey) continue;
        plans.push({
          id: `${endpoint.key}:${object.type}:${object.ref}:${attacker.key}`,
          endpointKey: endpoint.key,
          method: endpoint.method.toUpperCase(),
          url,
          ownerKey: object.ownerKey,
          attackerKey: attacker.key,
          objectRef: object.ref,
          destructive: isDestructive,
          rationale:
            input.tenantOf(attacker.key) !== object.tenant
              ? `${attacker.label} is outside the object's tenant`
              : `${attacker.label} does not own ${object.type} ${object.ref}`,
        });
      }
    }
  }
  return plans;
}

/* ------------------------------------------------------------------ */
/* execution                                                           */
/* ------------------------------------------------------------------ */

export type TransportPhase = "baseline" | "attack" | "verify";

export type Transport = (input: {
  plan: ProbePlan;
  identity: RealIdentity;
  phase: TransportPhase;
}) => Promise<{ status: number; body: string }>;

const READ_ONLY = new Set(["GET", "HEAD", "OPTIONS"]);

const SEVERITY_BY_SIGNAL: Record<string, FindingRecord["severity"]> = {
  ownership_reassigned: "critical",
  server_state_changed: "high",
  protected_record_returned: "high",
};

export async function executeSuite(args: {
  plans: ProbePlan[];
  identitiesByKey: Map<string, RealIdentity>;
  transport: Transport;
  volatileKeys?: string[];
  /** Stops the run as soon as it returns false (kill switch / budget). May be
   * async so the runner can re-read live run state between probes. */
  shouldContinue?: () => boolean | Promise<boolean>;
}): Promise<SuiteResult> {
  const tests: TestRecord[] = [];
  const findings: FindingRecord[] = [];
  let requestsUsed = 0;
  let blocked = 0;
  let errors = 0;
  let counter = 0;

  /**
   * A transport that refuses a request (scope guard, rate limiter, budget,
   * safety gate) reports it as a block. Blocked probes are evidence that a
   * control worked — errors are infrastructure failures. Either way the plan
   * is skipped: an incomplete exchange can never become a finding.
   */
  const recordFailure = (error: unknown): void => {
    if (error instanceof Error && error.message.startsWith("blocked:")) blocked += 1;
    else errors += 1;
  };

  for (const plan of args.plans) {
    if (args.shouldContinue && !(await args.shouldContinue())) break;

    const attacker = args.identitiesByKey.get(plan.attackerKey);
    const owner = args.identitiesByKey.get(plan.ownerKey);
    if (!attacker || !owner) {
      errors += 1;
      continue;
    }

    let ownerStatus = 0;
    let baselineBody = "";
    try {
      const baseline = await args.transport({ plan, identity: owner, phase: "baseline" });
      ownerStatus = baseline.status;
      baselineBody = baseline.body;
      requestsUsed += 1;
    } catch (error) {
      recordFailure(error);
      continue;
    }

    let attackerStatus = 0;
    let attackBody = "";
    try {
      const attack = await args.transport({ plan, identity: attacker, phase: "attack" });
      attackerStatus = attack.status;
      attackBody = attack.body;
      requestsUsed += 1;
    } catch (error) {
      recordFailure(error);
      continue;
    }

    // For a mutating probe the owner re-reads the record afterwards. That
    // before/after pair is the state delta — the evidence that a write really
    // landed, rather than merely returning 200.
    let verifyBody = "";
    if (!READ_ONLY.has(plan.method)) {
      try {
        const verify = await args.transport({ plan, identity: owner, phase: "verify" });
        verifyBody = verify.body;
        requestsUsed += 1;
      } catch {
        errors += 1;
        continue;
      }
    }
    const mutating = !READ_ONLY.has(plan.method);

    const expectedDenied = plan.ownerKey !== plan.attackerKey;
    const oracle = differentialOracle({
      expectedDenied,
      attackerStatus,
      ownerStatus,
      attackerBody: attackBody,
      ownerBody: baselineBody,
      protectedMarkers: protectedMarkers(baselineBody),
      ...(mutating && verifyBody ? { stateBefore: baselineBody, stateAfter: verifyBody } : {}),
      ...(args.volatileKeys ? { volatileKeys: args.volatileKeys } : {}),
    });

    const record: TestRecord = {
      planId: plan.id,
      endpointKey: plan.endpointKey,
      method: plan.method,
      path: new URL(plan.url).pathname,
      attackerKey: plan.attackerKey,
      ownerKey: plan.ownerKey,
      ...(plan.objectRef ? { objectRef: plan.objectRef } : {}),
      expectation: expectedDenied ? "DENY" : "ALLOW",
      actual: attackerStatus >= 200 && attackerStatus < 300 ? "ALLOW" : "DENY",
      attackerStatus,
      ownerStatus,
      verdict: oracle.verdict,
      signals: oracle.signals,
      confidence: oracle.confidence,
      reason: oracle.reason,
      baselineBody,
      attackBody,
      delta: oracle.delta,
    };
    tests.push(record);

    if (oracle.verdict === "confirmed" || oracle.verdict === "likely") {
      counter += 1;
      findings.push({
        code: `WABVE-${String(counter).padStart(3, "0")}`,
        testId: record.planId,
        endpoint: `${record.method} ${record.path}`,
        ...(record.objectRef ? { objectRef: record.objectRef } : {}),
        attacker: attacker.label,
        owner: owner.label,
        severity: severityFor(oracle.signals),
        confidence: oracle.confidence >= 90 ? "Confirmed" : oracle.confidence >= 70 ? "High" : "Medium",
        score: oracle.confidence,
        verdict: oracle.verdict,
        signals: oracle.signals,
        expected: "403 Forbidden",
        actual: `${attackerStatus} with ${oracle.delta.length} state change(s)`,
        reason: oracle.reason,
        beforeState: baselineBody,
        afterState: mutating ? verifyBody : attackBody,
        delta: oracle.delta,
        remediation: remediationFor(oracle.signals),
      });
    }
  }

  return { tests, findings, requestsUsed, blocked, errors };
}

function severityFor(signals: string[]): FindingRecord["severity"] {
  if (signals.includes("ownership_reassigned")) return "critical";
  if (signals.includes("privilege_boundary_crossed")) return "critical";
  if (signals.includes("tenant_boundary_crossed")) return "critical";
  for (const signal of signals) {
    const severity = SEVERITY_BY_SIGNAL[signal];
    if (severity) return severity;
  }
  return "medium";
}

function remediationFor(signals: string[]): string {
  if (signals.includes("ownership_reassigned")) {
    return "Bind the write to an allow-listed DTO; never accept ownership fields from the client.";
  }
  if (signals.includes("server_state_changed")) {
    return "Enforce the ownership predicate inside the write statement and reject objects the caller does not own.";
  }
  if (signals.includes("protected_record_returned")) {
    return "Scope every read by the authenticated identity and return 404 for records it does not own.";
  }
  return "Enforce authorization server-side on every access path for this resource.";
}

export function scopeIsLive(scope: ScopeConfig): boolean {
  return !scope.killSwitch && scope.requestBudget > 0;
}
