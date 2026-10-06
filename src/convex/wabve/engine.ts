/**
 * WABVE — probe engine.
 *
 * Plans the authorization / business-logic test matrix, enforces the scope
 * guard, executes each probe against the target lab, and derives findings from
 * differential evidence (reference policy vs. actual policy vs. state delta).
 * The engine is deterministic, so the same engagement always reproduces the
 * same evidence.
 */

import type { LabActor, LabDefinition, LabEndpoint, LabObject } from "./lab";
import { actualDecision, applyEffect, buildLab, referenceDecision } from "./lab";
import { pathAllowed } from "../real/engine";

export interface ScopeConfig {
  target: string;
  allowedHosts: string[];
  allowedPaths: string[];
  rateLimit: number;
  requestBudget: number;
  destructiveTesting: boolean;
  dryRun: boolean;
  profile: string;
}

export interface EndpointRow {
  key: string;
  method: string;
  path: string;
  parameters: string[];
  authRequired: boolean;
  rolesObserved: string[];
  objectType?: string;
  category: string;
  risk: string;
  discoveredVia: string;
  inScope: boolean;
  summary: string;
}

export interface DeltaEntry {
  field: string;
  before: unknown;
  after: unknown;
}

/** A resource the engine identified during the modelling stage (AC-05). */
export interface ObjectRow {
  key: string;
  type: string;
  ref: string;
  label: string;
  owner?: string;
  ownerLabel?: string;
  tenant: string;
  classification: string;
}

export interface TestRow {
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
  outcome: string;
  risk: string;
  statusCode: number;
  signals: string[];
  confidence: number;
  request: string;
  response: string;
  beforeState?: Record<string, unknown>;
  afterState?: Record<string, unknown>;
  stateDelta?: DeltaEntry[];
}

/** Declarative probe definition (metadata lives here, evidence is persisted). */
export interface Probe {
  id: string;
  endpointKey: string;
  probe: string;
  actorKey: string;
  victimKey?: string;
  object?: { type: string; ref: string };
  body?: Record<string, unknown>;
  /** Lab objects the reference policy refuses to let a client mutate. */
  protectedFields?: string[];
  title: string;
  classification: string;
  cwe: string;
  owasp: string;
  impact: string;
  remediation: string;
}

export interface Coverage {
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
  dryRun: boolean;
}

const DEFAULT_OWASP: Record<string, string> = {
  authorization: "A01:2021 - Broken Access Control",
  tenant: "A01:2021 - Broken Access Control",
  bfla: "A01:2021 - Broken Access Control",
  method: "A01:2021 - Broken Access Control",
  property: "A08:2021 - Software and Data Integrity Failures",
  workflow: "A04:2021 - Insecure Design",
  business: "A04:2021 - Insecure Design",
  session: "A07:2021 - Identification and Authentication Failures",
};

export function owaspFor(category: string): string {
  return DEFAULT_OWASP[category] ?? "A01:2021 - Broken Access Control";
}

/** Build the unified endpoint registry from the discovered target. */
export function discover(scope: ScopeConfig, lab: LabDefinition): EndpointRow[] {
  return lab.endpoints.map((ep) => {
    const parameters = [...ep.path.matchAll(/\{(\w+)\}/g)].map((m) => m[1]);
    const roles = lab.actors
      .filter((a) => {
        if (ep.requiredRole) return a.role === ep.requiredRole || a.role === "superadmin";
        return a.authenticated;
      })
      .map((a) => a.role);
    const uniqueRoles = Array.from(new Set(roles));
    if (!ep.authRequired) uniqueRoles.push("anonymous");
    return {
      key: ep.key,
      method: ep.method,
      path: ep.path,
      parameters,
      authRequired: ep.authRequired,
      rolesObserved: Array.from(new Set(uniqueRoles)),
      ...(ep.objectType ? { objectType: ep.objectType } : {}),
      category: ep.category,
      risk: ep.risk,
      discoveredVia: ep.discoveredVia,
      inScope: isInScope(scope, ep.path),
      summary: ep.summary,
    };
  });
}

/**
 * Scope predicate for demo mode.
 *
 * Delegates to the live engine's `pathAllowed` so an allowlist means exactly
 * the same thing in both modes. A bare prefix test would let `/api` silently
 * permit `/apixyz` here while the live guard refused it, and the two modes are
 * meant to render identically.
 */
export function isInScope(scope: ScopeConfig, path: string): boolean {
  return pathAllowed(path, scope.allowedPaths);
}

/**
 * Identify the resources the application operates on, together with the
 * identity that owns each one. Object identifiers are the prerequisite for
 * every cross-identity probe.
 */
export function identifyObjects(lab: LabDefinition): ObjectRow[] {
  return lab.objects.map((obj) => {
    const owner = obj.owner ? lab.actors.find((a) => a.key === obj.owner) : undefined;
    const classification = obj.state.classification;
    return {
      key: `${obj.type}:${obj.ref}`,
      type: obj.type,
      ref: obj.ref,
      label: `${obj.type} ${obj.ref}`,
      ...(obj.owner ? { owner: obj.owner } : {}),
      ...(owner ? { ownerLabel: owner.label } : {}),
      tenant: obj.tenant,
      classification: typeof classification === "string" ? classification : "standard",
    };
  });
}

function findObject(
  lab: LabDefinition,
  selector: { type: string; ref: string },
): LabObject | undefined {
  return lab.objects.find((o) => o.type === selector.type && o.ref === selector.ref);
}

function actor(lab: LabDefinition, key: string): LabActor {
  const found = lab.actors.find((a) => a.key === key);
  if (!found) throw new Error(`unknown identity: ${key}`);
  return found;
}

/**
 * Build the authorization test matrix. Each probe targets one actor, one
 * object and one endpoint so that every result is attributable.
 */
export function planProbes(scope: ScopeConfig): Probe[] {
  const deep = scope.profile === "deep";
  const quick = scope.profile === "quick";
  const probes: Probe[] = [];

  const add = (probe: Probe) => probes.push(probe);

  // ---- Baseline: establish which objects belong to which identity ---------
  add({
    id: "base.profile.own",
    endpointKey: "profile.read",
    probe: "baseline_legitimate_access",
    actorKey: "user_a",
    title: "Baseline profile read",
    classification: "Baseline",
    cwe: "CWE-284",
    owasp: owaspFor("authorization"),
    impact: "Establishes the expected shape of a legitimate response.",
    remediation: "n/a",
  });
  add({
    id: "base.profile.anon",
    endpointKey: "profile.read",
    probe: "unauthenticated_access",
    actorKey: "anon",
    title: "Anonymous profile read",
    classification: "Authentication",
    cwe: "CWE-306",
    owasp: owaspFor("session"),
    impact: "n/a",
    remediation: "n/a",
  });
  add({
    id: "base.invoice.read.own",
    endpointKey: "invoice.read",
    probe: "baseline_legitimate_access",
    actorKey: "user_b",
    object: { type: "invoice", ref: "1002" },
    title: "Baseline invoice read",
    classification: "Baseline",
    cwe: "CWE-284",
    owasp: owaspFor("authorization"),
    impact: "Establishes the expected shape of a legitimate response.",
    remediation: "n/a",
  });

  // ---- BOLA / IDOR on invoices -------------------------------------------
  add({
    id: "bola.invoice.read",
    endpointKey: "invoice.read",
    probe: "cross_identity_read",
    actorKey: "user_b",
    victimKey: "user_a",
    object: { type: "invoice", ref: "1001" },
    title: "Cross-user invoice read (BOLA)",
    classification: "BOLA / IDOR",
    cwe: "CWE-639",
    owasp: owaspFor("authorization"),
    impact:
      "Any authenticated user can read another user's invoice by changing the identifier, exposing customer and billing data.",
    remediation:
      "Resolve the invoice through a tenant- and owner-scoped query (e.g. WHERE id = ? AND owner_id = current_user) and return 404 when it is not owned.",
  });
  if (!quick) {
    add({
      id: "bola.invoice.receipt",
      endpointKey: "invoice.receipt",
      probe: "no_id_substitution_replay",
      actorKey: "user_b",
      victimKey: "user_a",
      object: { type: "invoice", ref: "1001" },
      title: "No-ID-substitution replay of an observed reference",
      classification: "BOLA / IDOR",
      cwe: "CWE-639",
      owasp: owaspFor("authorization"),
      impact:
        "Replaying the exact reference captured from User A's session, without altering the identifier, returns the protected receipt.",
      remediation:
        "Bind object access to the session identity rather than trusting the path identifier alone.",
    });
  }
  add({
    id: "bola.invoice.anon.read",
    endpointKey: "invoice.read",
    probe: "unauthenticated_access",
    actorKey: "anon",
    object: { type: "invoice", ref: "1001" },
    title: "Anonymous invoice read",
    classification: "Authentication",
    cwe: "CWE-306",
    owasp: owaspFor("session"),
    impact: "n/a",
    remediation: "n/a",
  });
  add({
    id: "bola.invoice.write",
    endpointKey: "invoice.update",
    probe: "cross_identity_write",
    actorKey: "user_a",
    victimKey: "user_b",
    object: { type: "invoice", ref: "1002" },
    title: "Cross-user invoice modification (BOLA write)",
    classification: "BOLA / IDOR",
    cwe: "CWE-639",
    owasp: owaspFor("authorization"),
    impact:
      "User A cancelled an invoice owned by User B. The server accepted the write and changed persisted state, which is stronger evidence than a 200 response alone.",
    remediation:
      "Enforce the ownership predicate inside the update statement and reject writes to objects the caller does not own.",
  });
  add({
    id: "bola.invoice.delete",
    endpointKey: "invoice.delete",
    probe: "cross_identity_destructive_write",
    actorKey: "user_a",
    victimKey: "user_c",
    object: { type: "invoice", ref: "1003" },
    title: "Cross-tenant invoice deletion (BOLA)",
    classification: "BOLA / IDOR",
    cwe: "CWE-639",
    owasp: owaspFor("authorization"),
    impact:
      "An identity in Tenant A soft-deleted a Tenant B invoice, breaching tenant isolation.",
    remediation:
      "Scope deletes by tenant and owner, and require an explicit confirmation token for destructive operations.",
  });

  // ---- File / object storage exposure ------------------------------------
  add({
    id: "bola.file.read",
    endpointKey: "file.read",
    probe: "cross_identity_read",
    actorKey: "user_b",
    victimKey: "user_a",
    object: { type: "file", ref: "7788" },
    title: "Cross-user file metadata disclosure",
    classification: "BOLA / IDOR",
    cwe: "CWE-639",
    owasp: owaspFor("authorization"),
    impact:
      "File metadata for another user's document is returned, revealing classification and naming without any ownership check.",
    remediation: "Authorize file metadata reads against the owning identity.",
  });
  add({
    id: "bola.file.download",
    endpointKey: "file.download",
    probe: "cross_identity_write",
    actorKey: "user_b",
    victimKey: "user_a",
    object: { type: "file", ref: "7788" },
    title: "Cross-user confidential file download",
    classification: "BOLA / IDOR",
    cwe: "CWE-639",
    owasp: owaspFor("authorization"),
    impact:
      "The download endpoint streams a file owned by another identity. State confirms the access was recorded against the attacker's identity.",
    remediation: "Authorize downloads and prefer short-lived, identity-bound signed URLs.",
  });

  // ---- Tenant isolation ---------------------------------------------------
  add({
    id: "tenant.report.read",
    endpointKey: "report.read",
    probe: "cross_tenant_read",
    actorKey: "user_a",
    victimKey: "user_c",
    object: { type: "report", ref: "9001" },
    title: "Cross-tenant report disclosure",
    classification: "Tenant Isolation",
    cwe: "CWE-639",
    owasp: owaspFor("tenant"),
    impact:
      "A Tenant A identity read a restricted Tenant B report. No tenant predicate is applied to the query.",
    remediation:
      "Apply a mandatory tenant predicate at the data-access layer for every tenant-scoped resource.",
  });
  add({
    id: "tenant.report.own",
    endpointKey: "report.read",
    probe: "baseline_legitimate_access",
    actorKey: "user_a",
    object: { type: "report", ref: "9002" },
    title: "Baseline tenant report read",
    classification: "Baseline",
    cwe: "CWE-284",
    owasp: owaspFor("tenant"),
    impact: "Confirms the endpoint works for the legitimate tenant.",
    remediation: "n/a",
  });

  // ---- HTTP method authorization inconsistency ---------------------------
  add({
    id: "method.order.read",
    endpointKey: "order.read",
    probe: "cross_identity_read",
    actorKey: "user_b",
    victimKey: "user_a",
    object: { type: "order", ref: "5005" },
    title: "Cross-user order read",
    classification: "Authorization",
    cwe: "CWE-639",
    owasp: owaspFor("authorization"),
    impact: "Expected to be denied; used as the control for the DELETE inconsistency.",
    remediation: "n/a",
  });
  add({
    id: "method.order.delete",
    endpointKey: "order.delete",
    probe: "method_authorization_bypass",
    actorKey: "user_b",
    victimKey: "user_a",
    object: { type: "order", ref: "5005" },
    title: "HTTP method authorization bypass (DELETE)",
    classification: "HTTP Method Bypass",
    cwe: "CWE-650",
    owasp: owaspFor("method"),
    impact:
      "Ownership is enforced on GET but not on DELETE, so a non-owner deleted another user's order. Inconsistent method-level enforcement is a common finding.",
    remediation:
      "Centralize the authorization check on the record rather than per handler, and cover every verb in the enforcement tests.",
  });

  // ---- BFLA / vertical privilege escalation ------------------------------
  add({
    id: "bfla.users.list",
    endpointKey: "admin.users.list",
    probe: "vertical_privilege_escalation",
    actorKey: "user_b",
    title: "Broken function level authorization on admin user list",
    classification: "BFLA",
    cwe: "CWE-285",
    owasp: owaspFor("bfla"),
    impact:
      "A standard user retrieved the full account listing from an administrator-only function.",
    remediation:
      "Enforce role requirements in a shared middleware layer so no handler can be reached without the required role.",
  });
  add({
    id: "bfla.users.list.manager",
    endpointKey: "admin.users.list",
    probe: "vertical_privilege_escalation",
    actorKey: "manager",
    title: "Role boundary escalation from Manager to Admin function",
    classification: "BFLA",
    cwe: "CWE-285",
    owasp: owaspFor("bfla"),
    impact: "A manager reached an administrator-only endpoint despite a lower role rank.",
    remediation: "Compare the caller's role rank against the required rank before dispatch.",
  });
  add({
    id: "bfla.users.delete",
    endpointKey: "admin.users.delete",
    probe: "vertical_privilege_escalation_destructive",
    actorKey: "user_b",
    object: { type: "account", ref: "3" },
    title: "Vertical escalation with destructive administrator action",
    classification: "BFLA",
    cwe: "CWE-285",
    owasp: owaspFor("bfla"),
    impact: "A standard user can delete administrator accounts.",
    remediation:
      "Require the administrator role and re-authentication for account-destructive operations.",
  });
  add({
    id: "bfla.settings.standard",
    endpointKey: "admin.settings.read",
    probe: "vertical_privilege_positive_control",
    actorKey: "user_b",
    title: "Admin settings access by standard user",
    classification: "BFLA",
    cwe: "CWE-285",
    owasp: owaspFor("bfla"),
    impact: "n/a",
    remediation: "n/a",
  });
  add({
    id: "bfla.settings.admin",
    endpointKey: "admin.settings.read",
    probe: "baseline_legitimate_access",
    actorKey: "admin",
    title: "Admin settings access by administrator",
    classification: "Baseline",
    cwe: "CWE-284",
    owasp: owaspFor("bfla"),
    impact: "Confirms privileged access works as intended.",
    remediation: "n/a",
  });
  add({
    id: "bfla.settings.anon",
    endpointKey: "admin.settings.read",
    probe: "unauthenticated_access",
    actorKey: "anon",
    title: "Anonymous admin settings access",
    classification: "Authentication",
    cwe: "CWE-306",
    owasp: owaspFor("session"),
    impact: "n/a",
    remediation: "n/a",
  });
  add({
    id: "bfla.audit.standard",
    endpointKey: "audit.log.read",
    probe: "vertical_privilege_positive_control",
    actorKey: "user_b",
    title: "Audit log access by standard user",
    classification: "BFLA",
    cwe: "CWE-285",
    owasp: owaspFor("bfla"),
    impact: "n/a",
    remediation: "n/a",
  });
  add({
    id: "bfla.audit.manager",
    endpointKey: "audit.log.read",
    probe: "baseline_legitimate_access",
    actorKey: "manager",
    title: "Audit log access by manager",
    classification: "Baseline",
    cwe: "CWE-284",
    owasp: owaspFor("bfla"),
    impact: "Confirms the manager role boundary is enforced correctly here.",
    remediation: "n/a",
  });

  // ---- Property-level authorization / mass assignment --------------------
  add({
    id: "property.order.owner",
    endpointKey: "order.update",
    probe: "protected_property_injection",
    actorKey: "user_a",
    object: { type: "order", ref: "5004" },
    body: { status: "SHIPPED", owner_id: "user_c" },
    protectedFields: ["owner"],
    title: "Mass assignment of a protected ownership property",
    classification: "Mass Assignment",
    cwe: "CWE-915",
    owasp: owaspFor("property"),
    impact:
      "The client-supplied owner_id was persisted, transferring ownership of the order. The state delta proves the server accepted an unauthorized property.",
    remediation:
      "Deserialize requests into a strict allow-list DTO and never bind client input to ownership or authorization fields.",
  });

  // ---- Workflow / state-transition ---------------------------------------
  add({
    id: "workflow.refund.legal",
    endpointKey: "order.refund",
    probe: "baseline_legitimate_transition",
    actorKey: "user_a",
    object: { type: "order", ref: "5001" },
    title: "Legal refund transition",
    classification: "Workflow",
    cwe: "CWE-841",
    owasp: owaspFor("workflow"),
    impact: "Confirms the PAID -> REFUNDED transition works for the owner.",
    remediation: "n/a",
  });
  add({
    id: "workflow.refund.bypass",
    endpointKey: "order.refund",
    probe: "out_of_sequence_transition",
    actorKey: "user_b",
    object: { type: "order", ref: "5002" },
    title: "Workflow bypass: refund issued before payment",
    classification: "Workflow Bypass",
    cwe: "CWE-841",
    owasp: owaspFor("workflow"),
    impact:
      "An unpaid order in the CREATED state was moved directly to REFUNDED, skipping PAY entirely. The state machine transition was not validated.",
    remediation:
      "Model the order lifecycle as an explicit state machine and reject transitions that are not defined from the current state.",
  });
  if (!quick) {
    add({
      id: "workflow.refund.double",
      endpointKey: "order.refund",
      probe: "state_replay",
      actorKey: "user_a",
      object: { type: "order", ref: "5001" },
      title: "Replay of a completed state transition (double refund)",
      classification: "Workflow Bypass",
      cwe: "CWE-841",
      owasp: owaspFor("workflow"),
      impact:
        "The refund endpoint accepted a second call on an already REFUNDED order, indicating no idempotency or state guard.",
      remediation: "Make state transitions idempotent and reject them when the target state is already reached.",
    });
  }

  // ---- Business logic / replay -------------------------------------------
  add({
    id: "business.coupon.first",
    endpointKey: "coupon.redeem",
    probe: "baseline_legitimate_access",
    actorKey: "user_a",
    object: { type: "coupon", ref: "SUMMER15" },
    body: { code: "SUMMER15" },
    title: "First coupon redemption",
    classification: "Baseline",
    cwe: "CWE-284",
    owasp: owaspFor("business"),
    impact: "Establishes the coupon as redeemable once.",
    remediation: "n/a",
  });
  add({
    id: "business.coupon.reuse",
    endpointKey: "coupon.redeem",
    probe: "replay_after_use",
    actorKey: "user_b",
    object: { type: "coupon", ref: "SUMMER15" },
    body: { code: "SUMMER15" },
    title: "Single-use coupon replay across accounts",
    classification: "Business Logic / Replay",
    cwe: "CWE-837",
    owasp: owaspFor("business"),
    impact:
      "A coupon with maxRedemptions = 1 was redeemed a second time by a different account. State shows redeemedBy overwritten.",
    remediation:
      "Enforce redemption atomically at the database level (unique constraint on coupon + account) instead of checking in application code.",
  });

  // ---- Out-of-scope target ------------------------------------------------
  add({
    id: "guard.debug.config",
    endpointKey: "debug.config",
    probe: "out_of_scope_probe",
    actorKey: "anon",
    title: "Out-of-scope debug endpoint",
    classification: "Scope Guard",
    cwe: "CWE-284",
    owasp: owaspFor("session"),
    impact: "Blocked by the scope guard before any request was issued.",
    remediation: "n/a",
  });

  // ---- Deep profile: anonymous sweep over object endpoints ---------------
  if (deep) {
    const sweep: Array<{ id: string; endpointKey: string; ref: string; type: string }> = [
      { id: "deep.anon.invoice", endpointKey: "invoice.read", ref: "1001", type: "invoice" },
      { id: "deep.anon.order", endpointKey: "order.read", ref: "5001", type: "order" },
      { id: "deep.anon.file", endpointKey: "file.read", ref: "7788", type: "file" },
      { id: "deep.anon.report", endpointKey: "report.read", ref: "9001", type: "report" },
    ];
    for (const item of sweep) {
      add({
        id: item.id,
        endpointKey: item.endpointKey,
        probe: "unauthenticated_access",
        actorKey: "anon",
        object: { type: item.type, ref: item.ref },
        title: `Anonymous access to ${item.endpointKey}`,
        classification: "Authentication",
        cwe: "CWE-306",
        owasp: owaspFor("session"),
        impact: "n/a",
        remediation: "n/a",
      });
    }
  }

  return probes;
}

function snapshot(obj: LabObject | null): Record<string, unknown> | undefined {
  if (!obj) return undefined;
  return { ...obj.state, owner: obj.owner, tenant: obj.tenant };
}

function diff(
  before: Record<string, unknown> | undefined,
  after: Record<string, unknown> | undefined,
): DeltaEntry[] {
  if (!before || !after) return [];
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const entries: DeltaEntry[] = [];
  for (const field of keys) {
    const b = before[field];
    const a = after[field];
    if (JSON.stringify(b) !== JSON.stringify(a)) {
      entries.push({ field, before: b, after: a });
    }
  }
  return entries;
}

/**
 * Execute the full matrix against a fresh target instance. Probes run in order
 * because later probes depend on the state earlier probes leave behind.
 */
export function execute(scope: ScopeConfig, probes: Probe[]): TestRow[] {
  const lab = buildLab();
  const endpointByKey = new Map(lab.endpoints.map((e) => [e.key, e]));
  const rows: TestRow[] = [];

  for (const probe of probes) {
    const ep = endpointByKey.get(probe.endpointKey);
    if (!ep) continue;
    const who = actor(lab, probe.actorKey);
    const victim = probe.victimKey ? actor(lab, probe.victimKey) : undefined;
    const obj = probe.object ? findObject(lab, probe.object) ?? null : null;

    const path = probe.object
      ? ep.path.replace(/\{\w+\}/, probe.object.ref)
      : ep.path;

    // Scope guard: block anything that is not inside the declared allowlist.
    if (!isInScope(scope, path)) {
      rows.push({
        endpointKey: ep.key,
        method: ep.method,
        path,
        category: ep.category,
        probe: probe.probe,
        actorKey: who.key,
        actorLabel: who.label,
        ...(victim ? { victimKey: victim.key, victimLabel: victim.label } : {}),
        ...(probe.object ? { objectRef: probe.object.ref } : {}),
        expectation: "DENY",
        actual: "BLOCKED",
        outcome: "blocked",
        risk: ep.risk,
        statusCode: 0,
        signals: ["scope_guard_blocked"],
        confidence: 0,
        request: `${ep.method} ${path} (blocked: outside allowed paths)`,
        response: "Scope guard blocked the request before dispatch.",
      });
      continue;
    }

    // Safety control: destructive tests need explicit approval.
    if (ep.risk === "critical" && ep.effect?.kind === "deleteObject" && !scope.destructiveTesting) {
      rows.push({
        endpointKey: ep.key,
        method: ep.method,
        path,
        category: ep.category,
        probe: probe.probe,
        actorKey: who.key,
        actorLabel: who.label,
        ...(victim ? { victimKey: victim.key, victimLabel: victim.label } : {}),
        ...(probe.object ? { objectRef: probe.object.ref } : {}),
        expectation: "DENY",
        actual: "BLOCKED",
        outcome: "blocked",
        risk: ep.risk,
        statusCode: 0,
        signals: ["destructive_testing_not_approved"],
        confidence: 0,
        request: `${ep.method} ${path} (blocked: destructive testing not approved)`,
        response: "Safety control blocked the destructive probe. Approve destructive testing to run it.",
      });
      continue;
    }

    const reference = referenceDecision(ep, who, obj);
    const actual = actualDecision(ep, who, obj);
    const before = snapshot(obj);
    const projected = scope.dryRun && obj ? { ...obj, state: { ...obj.state } } : obj;

    if (actual.allow) {
      // Dry-run computes what the request would change without applying it, so
      // no probe can mutate the target while the operator is still reviewing.
      applyEffect(ep, projected, who, probe.body);
    }
    const after = snapshot(projected);
    const delta = diff(before, after);

    const signals: string[] = [];
    let outcome: "pass" | "fail" | "inconclusive" = "pass";

    if (!reference.allow && actual.allow) {
      outcome = "fail";
      signals.push("unauthorized_access_confirmed");
      if (ep.method === "GET") signals.push("protected_record_returned");
      if (delta.length > 0) signals.push("server_state_changed");
      if (delta.some((d) => d.field === "owner")) signals.push("ownership_reassigned");
      if (ep.category === "bfla") signals.push("privilege_boundary_crossed");
      if (ep.category === "tenant") signals.push("tenant_boundary_crossed");
      if (ep.category === "workflow") signals.push("workflow_transition_violated");
      if (ep.category === "business") signals.push("replay_accepted");
      if (delta.some((d) => d.field === "deleted" && d.after === true)) {
        signals.push("destructive_effect");
      }
      if (scope.dryRun && delta.length > 0) signals.push("dry_run_projected");
      signals.push("differential_confirmed", "reproducible");
    } else if (reference.allow && actual.allow) {
      const protectedChange = (probe.protectedFields ?? []).filter((f) =>
        delta.some((d) => d.field === f),
      );
      if (protectedChange.length > 0) {
        outcome = "fail";
        signals.push(
          "unauthorized_access_confirmed",
          "protected_property_accepted",
          "ownership_reassigned",
          "server_state_changed",
          "differential_confirmed",
          "reproducible",
        );
        if (scope.dryRun) signals.push("dry_run_projected");
      }
    } else if (reference.allow && !actual.allow) {
      outcome = "inconclusive";
      signals.push("legitimate_action_denied");
    }

    const confidence = outcome === "fail" ? scoreSignals(signals) : 0;

    rows.push({
      endpointKey: ep.key,
      method: ep.method,
      path,
      category: ep.category,
      probe: probe.probe,
      actorKey: who.key,
      actorLabel: who.label,
      ...(victim ? { victimKey: victim.key, victimLabel: victim.label } : {}),
      ...(probe.object ? { objectRef: probe.object.ref } : {}),
      ...(probe.body && probe.protectedFields
        ? { parameter: probe.protectedFields[0] }
        : {}),
      expectation: reference.allow ? "ALLOW" : "DENY",
      actual: actual.allow ? "ALLOW" : "DENY",
      outcome,
      risk: ep.risk,
      statusCode: actual.allow ? 200 : 403,
      signals,
      confidence,
      request: buildRequest(ep, path, probe.body),
      response: buildResponse(ep, actual.allow, obj, {
        reference,
        actual,
        delta,
      }),
      ...(before ? { beforeState: before } : {}),
      ...(after ? { afterState: after } : {}),
      ...(delta.length > 0 ? { stateDelta: delta } : {}),
    });
  }

  return rows;
}

const SIGNAL_WEIGHTS: Record<string, number> = {
  unauthorized_access_confirmed: 30,
  protected_record_returned: 30,
  server_state_changed: 30,
  ownership_reassigned: 30,
  privilege_boundary_crossed: 30,
  tenant_boundary_crossed: 30,
  protected_property_accepted: 30,
  workflow_transition_violated: 25,
  replay_accepted: 25,
  destructive_effect: 20,
  differential_confirmed: 10,
  reproducible: 10,
};

export function scoreSignals(signals: string[]): number {
  const total = signals.reduce((sum, s) => sum + (SIGNAL_WEIGHTS[s] ?? 0), 0);
  return Math.min(100, total);
}

export function confidenceLabel(score: number): string {
  if (score >= 90) return "Confirmed";
  if (score >= 70) return "High";
  if (score >= 40) return "Medium";
  return "Inconclusive";
}

export function severityFor(
  category: string,
  risk: string,
  signals: string[],
): "critical" | "high" | "medium" | "low" {
  if (signals.includes("privilege_boundary_crossed")) return "critical";
  if (signals.includes("tenant_boundary_crossed")) return "critical";
  if (risk === "critical") return "critical";
  // Business-logic abuse is contextual: a replayed coupon is not a data breach.
  if (
    category !== "business" &&
    (signals.includes("server_state_changed") ||
      signals.includes("ownership_reassigned") ||
      signals.includes("workflow_transition_violated"))
  ) {
    return risk === "low" ? "medium" : "high";
  }
  if (risk === "high") return "high";
  if (risk === "medium") return "medium";
  return "low";
}

function buildRequest(
  ep: LabEndpoint,
  path: string,
  body: Record<string, unknown> | undefined,
): string {
  const lines = [`${ep.method} ${path}`];
  if (body) lines.push(`Content-Type: application/json`, JSON.stringify(body));
  return lines.join("\n");
}

function buildResponse(
  ep: LabEndpoint,
  allowed: boolean,
  obj: LabObject | null,
  detail: { reference: { reason: string }; actual: { reason: string }; delta: DeltaEntry[] },
): string {
  if (!allowed) {
    return `HTTP 403 Forbidden\n${JSON.stringify({ error: "forbidden", reason: detail.reference.reason })}`;
  }
  const payload = obj
    ? { id: obj.ref, ...obj.state }
    : { ok: true, endpoint: ep.key };
  const lines = [`HTTP 200 OK`, JSON.stringify(payload)];
  lines.push(`// reference policy: ${detail.reference.reason}`);
  lines.push(`// target behaviour: ${detail.actual.reason}`);
  if (detail.delta.length > 0) {
    lines.push(`// state delta: ${detail.delta.length} field(s) changed`);
  }
  return lines.join("\n");
}

/** Coverage roll-up for the engagement dashboard. */
export function buildCoverage(
  endpoints: EndpointRow[],
  tests: TestRow[],
  findings: FindingDraft[],
  scope: ScopeConfig,
  objects: ObjectRow[] = [],
): Coverage {
  const blockedOutOfScope = endpoints.filter((e) => !e.inScope).length;
  const roleCount = new Set(tests.map((t) => t.actorKey)).size;
  const failed = tests.filter((t) => t.outcome === "fail").length;
  return {
    endpointsDiscovered: endpoints.length,
    endpointsInScope: endpoints.filter((e) => e.inScope).length,
    blockedOutOfScope,
    authenticatedEndpoints: endpoints.filter((e) => e.authRequired).length,
    objectsIdentified: objects.length,
    rolesIdentified: roleCount,
    dryRun: scope.dryRun,
    authorizationTests: tests.filter((t) => t.category !== "business").length,
    businessLogicTests: tests.filter((t) => t.category === "business").length,
    totalTests: tests.length,
    passed: tests.filter((t) => t.outcome === "pass").length,
    failed,
    inconclusive: tests.filter((t) => t.outcome === "inconclusive").length,
    blocked: tests.filter((t) => t.outcome === "blocked").length,
    findings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    requestsUsed: tests.filter((t) => t.outcome !== "blocked").length,
    requestBudget: scope.requestBudget,
    safetyBlocks: tests.filter((t) => t.outcome === "blocked").length,
  };
}

export interface FindingDraft {
  code: string;
  title: string;
  severity: string;
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
  beforeState?: Record<string, unknown>;
  afterState?: Record<string, unknown>;
  stateDelta?: DeltaEntry[];
  signals: string[];
  reproduction: string[];
  impact: string;
  remediation: string;
}

export function probeKey(p: { endpointKey: string; actorKey: string; probe: string }): string {
  return `${p.endpointKey}|${p.actorKey}|${p.probe}`;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Turn failing tests into evidence-backed findings. */
export function confirm(tests: TestRow[], probeIndex: Map<string, Probe>): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  let counter = 0;

  for (const test of tests) {
    if (test.outcome !== "fail") continue;
    const probe = probeIndex.get(
      probeKey({ endpointKey: test.endpointKey, actorKey: test.actorKey, probe: test.probe }),
    );
    const severity = severityFor(test.category, test.risk, test.signals);
    const confidence = confidenceLabel(test.confidence);
    counter += 1;
    drafts.push({
      code: `WABVE-${String(counter).padStart(3, "0")}`,
      title: probe?.title ?? `Authorization violation on ${test.path}`,
      severity,
      confidence,
      score: test.confidence,
      classification: probe?.classification ?? "Broken Access Control",
      cwe: probe?.cwe ?? "CWE-639",
      owasp: probe?.owasp ?? owaspFor(test.category),
      endpoint: `${test.method} ${test.path}`,
      ...(test.parameter ? { parameter: test.parameter } : {}),
      attacker: test.actorLabel,
      ...(test.victimLabel ? { victim: test.victimLabel } : {}),
      probe: test.probe,
      expected: test.expectation === "DENY" ? "DENY (403 Forbidden)" : "ALLOW (200 OK)",
      actual: test.actual === "ALLOW" ? "ALLOW (200 OK)" : "BLOCKED",
      request: test.request,
      response: test.response,
      ...(test.beforeState ? { beforeState: test.beforeState } : {}),
      ...(test.afterState ? { afterState: test.afterState } : {}),
      ...(test.stateDelta ? { stateDelta: test.stateDelta } : {}),
      signals: test.signals,
      reproduction: [
        `Authenticate as ${test.actorLabel}.`,
        `Issue the request below against a scoped host.`,
        test.stateDelta && test.stateDelta.length > 0
          ? `Re-read the object and confirm the listed state delta persists.`
          : `Confirm the protected record is returned to a non-owning identity.`,
        `The reference policy expects ${test.expectation}.`,
      ],
      impact:
        probe?.impact ??
        "A non-owning identity reached a protected object, breaching the authorization model.",
      remediation:
        probe?.remediation ??
        "Enforce authorization on the server for every object access path.",
    });
  }

  drafts.sort((a, b) => {
    const sev = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (sev !== 0) return sev;
    return b.score - a.score;
  });

  // Re-number after sorting so report order matches severity order.
  return drafts.map((d, i) => ({ ...d, code: `WABVE-${String(i + 1).padStart(3, "0")}` }));
}
