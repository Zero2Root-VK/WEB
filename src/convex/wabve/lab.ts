/**
 * WABVE — deterministic target lab.
 *
 * WABVE never sends traffic to a third-party host from this runtime. The engine
 * executes its authorization probes against this modeled target, whose
 * endpoints carry realistic access-control defects. Every probe is evaluated
 * twice: once against a *reference policy* (what a correct implementation must
 * do) and once against the *actual policy* (what the target does). A finding is
 * only raised when the two disagree AND the disagreement is backed by a real
 * server-side state delta.
 */

export type Role = "anonymous" | "standard" | "manager" | "admin" | "superadmin";

export const ROLE_RANK: Record<Role, number> = {
  anonymous: 0,
  standard: 1,
  manager: 2,
  admin: 3,
  superadmin: 4,
};

export interface LabActor {
  key: string;
  label: string;
  role: Role;
  tenant: string;
  authenticated: boolean;
  authMethod: string;
}

export interface LabObject {
  key: string;
  type: string;
  ref: string;
  owner: string | null;
  tenant: string;
  state: Record<string, unknown>;
}

export type Category =
  | "authorization"
  | "tenant"
  | "bfla"
  | "method"
  | "property"
  | "workflow"
  | "business"
  | "session";

export type Flaw =
  | "missing_object_check"
  | "missing_role_check"
  | "missing_tenant_check"
  | "missing_method_check"
  | "mass_assignment"
  | "workflow_bypass"
  | "replay";

export type Effect =
  | { kind: "set"; field: string; value: unknown }
  | { kind: "setActor"; field: string }
  | { kind: "assignOwnerFromBody"; field: string }
  | { kind: "deleteObject" };

export interface LabEndpoint {
  key: string;
  method: string;
  path: string;
  objectType?: string;
  authRequired: boolean;
  requiredRole?: Role;
  category: Category;
  flaw?: Flaw;
  risk: "critical" | "high" | "medium" | "low";
  discoveredVia: string;
  summary: string;
  effect?: Effect;
  /** Fields the reference implementation refuses to let a client write. */
  protectedFields?: string[];
}

export interface LabDefinition {
  actors: LabActor[];
  objects: LabObject[];
  endpoints: LabEndpoint[];
}

export interface Decision {
  allow: boolean;
  reason: string;
}

let ephemeral = 0;
function makeObject(
  type: string,
  ref: string,
  owner: string | null,
  tenant: string,
  state: Record<string, unknown>,
): LabObject {
  ephemeral += 1;
  return {
    key: `${type}:${ref}:${ephemeral}`,
    type,
    ref,
    owner,
    tenant,
    state,
  };
}

/** Build a fresh instance of the target application. */
export function buildLab(): LabDefinition {
  const actors: LabActor[] = [
    {
      key: "user_a",
      label: "User A",
      role: "standard",
      tenant: "tenant-a",
      authenticated: true,
      authMethod: "bearer",
    },
    {
      key: "user_b",
      label: "User B",
      role: "standard",
      tenant: "tenant-a",
      authenticated: true,
      authMethod: "bearer",
    },
    {
      key: "user_c",
      label: "User C",
      role: "standard",
      tenant: "tenant-b",
      authenticated: true,
      authMethod: "cookie",
    },
    {
      key: "manager",
      label: "Manager",
      role: "manager",
      tenant: "tenant-a",
      authenticated: true,
      authMethod: "cookie",
    },
    {
      key: "admin",
      label: "Admin",
      role: "admin",
      tenant: "global",
      authenticated: true,
      authMethod: "cookie",
    },
    {
      key: "anon",
      label: "Unauthenticated",
      role: "anonymous",
      tenant: "none",
      authenticated: false,
      authMethod: "none",
    },
  ];

  ephemeral = 0;
  const objects: LabObject[] = [
    makeObject("invoice", "1001", "user_a", "tenant-a", {
      status: "PAID",
      amount: 125000,
      currency: "INR",
      customer: "Acme Pvt Ltd",
    }),
    makeObject("invoice", "1002", "user_b", "tenant-a", {
      status: "DRAFT",
      amount: 80000,
      currency: "INR",
      customer: "Northwind",
    }),
    makeObject("invoice", "1003", "user_c", "tenant-b", {
      status: "PAID",
      amount: 210000,
      currency: "INR",
      customer: "Globex",
    }),
    makeObject("order", "5001", "user_a", "tenant-a", {
      status: "PAID",
      paid: true,
      total: 4500,
    }),
    makeObject("order", "5002", "user_b", "tenant-a", {
      status: "CREATED",
      paid: false,
      total: 3200,
    }),
    makeObject("order", "5003", "user_c", "tenant-b", {
      status: "SHIPPED",
      paid: true,
      total: 9900,
    }),
    makeObject("order", "5004", "user_a", "tenant-a", {
      status: "PAID",
      paid: true,
      total: 7500,
    }),
    makeObject("order", "5005", "user_a", "tenant-a", {
      status: "DELIVERED",
      paid: true,
      total: 6100,
    }),
    makeObject("file", "7788", "user_a", "tenant-a", {
      classification: "internal",
      name: "quarterly-plan.pdf",
    }),
    makeObject("file", "8899", "user_c", "tenant-b", {
      classification: "confidential",
      name: "board-minutes.pdf",
    }),
    makeObject("report", "9001", "user_c", "tenant-b", {
      classification: "restricted",
      title: "Tenant B revenue report",
    }),
    makeObject("report", "9002", "user_a", "tenant-a", {
      classification: "internal",
      title: "Tenant A revenue report",
    }),
    makeObject("account", "1", null, "tenant-a", { email: "user_a@acme.test", role: "standard" }),
    makeObject("account", "2", null, "tenant-a", { email: "user_b@acme.test", role: "standard" }),
    makeObject("account", "3", null, "global", { email: "admin@acme.test", role: "admin" }),
    makeObject("coupon", "SUMMER15", null, "tenant-a", {
      redeemedBy: null,
      discount: 15,
      maxRedemptions: 1,
    }),
  ];

  const endpoints: LabEndpoint[] = [
    {
      key: "profile.read",
      method: "GET",
      path: "/api/profile",
      authRequired: true,
      category: "authorization",
      risk: "low",
      discoveredVia: "browser",
      summary: "Returns the calling identity's own profile.",
    },
    {
      key: "invoice.create",
      method: "POST",
      path: "/api/invoices",
      authRequired: true,
      category: "authorization",
      risk: "low",
      discoveredVia: "openapi",
      summary: "Creates an invoice owned by the calling identity.",
    },
    {
      key: "invoice.read",
      method: "GET",
      path: "/api/invoices/{id}",
      objectType: "invoice",
      authRequired: true,
      category: "authorization",
      flaw: "missing_object_check",
      risk: "critical",
      discoveredVia: "browser",
      summary: "Reads an invoice by identifier.",
    },
    {
      key: "invoice.update",
      method: "PUT",
      path: "/api/invoices/{id}",
      objectType: "invoice",
      authRequired: true,
      category: "authorization",
      flaw: "missing_object_check",
      risk: "critical",
      discoveredVia: "openapi",
      summary: "Updates an invoice by identifier.",
      effect: { kind: "set", field: "status", value: "CANCELLED" },
    },
    {
      key: "invoice.delete",
      method: "DELETE",
      path: "/api/invoices/{id}",
      objectType: "invoice",
      authRequired: true,
      category: "authorization",
      flaw: "missing_object_check",
      risk: "critical",
      discoveredVia: "openapi",
      summary: "Deletes an invoice by identifier.",
      effect: { kind: "deleteObject" },
    },
    {
      key: "invoice.receipt",
      method: "GET",
      path: "/api/invoices/{id}/receipt",
      objectType: "invoice",
      authRequired: true,
      category: "authorization",
      flaw: "missing_object_check",
      risk: "high",
      discoveredVia: "html",
      summary: "Returns a rendered receipt for an invoice.",
    },
    {
      key: "order.read",
      method: "GET",
      path: "/api/orders/{id}",
      objectType: "order",
      authRequired: true,
      category: "authorization",
      risk: "medium",
      discoveredVia: "browser",
      summary: "Reads an order. Correctly enforces ownership.",
    },
    {
      key: "order.update",
      method: "PUT",
      path: "/api/orders/{id}",
      objectType: "order",
      authRequired: true,
      category: "property",
      flaw: "mass_assignment",
      risk: "high",
      discoveredVia: "openapi",
      summary: "Updates an order from a client-supplied body.",
      effect: { kind: "assignOwnerFromBody", field: "owner_id" },
      protectedFields: ["owner"],
    },
    {
      key: "order.delete",
      method: "DELETE",
      path: "/api/orders/{id}",
      objectType: "order",
      authRequired: true,
      category: "method",
      flaw: "missing_method_check",
      risk: "high",
      discoveredVia: "openapi",
      summary: "Deletes an order. Ownership is only checked on GET/PUT.",
      effect: { kind: "deleteObject" },
    },
    {
      key: "order.refund",
      method: "POST",
      path: "/api/orders/{id}/refund",
      objectType: "order",
      authRequired: true,
      category: "workflow",
      flaw: "workflow_bypass",
      risk: "high",
      discoveredVia: "browser",
      summary: "Refunds an order. Should only fire from the PAID state.",
      effect: { kind: "set", field: "status", value: "REFUNDED" },
    },
    {
      key: "file.read",
      method: "GET",
      path: "/api/files/{id}",
      objectType: "file",
      authRequired: true,
      category: "authorization",
      flaw: "missing_object_check",
      risk: "critical",
      discoveredVia: "har",
      summary: "Reads file metadata by identifier.",
    },
    {
      key: "file.download",
      method: "POST",
      path: "/api/files/{id}/download",
      objectType: "file",
      authRequired: true,
      category: "authorization",
      flaw: "missing_object_check",
      risk: "high",
      discoveredVia: "browser",
      summary: "Streams file contents.",
      effect: { kind: "setActor", field: "lastAccessedBy" },
    },
    {
      key: "report.read",
      method: "GET",
      path: "/api/reports/{id}",
      objectType: "report",
      authRequired: true,
      category: "tenant",
      flaw: "missing_tenant_check",
      risk: "critical",
      discoveredVia: "openapi",
      summary: "Reads a tenant-scoped report.",
    },
    {
      key: "coupon.redeem",
      method: "POST",
      path: "/api/coupons/redeem",
      objectType: "coupon",
      authRequired: true,
      category: "business",
      flaw: "replay",
      risk: "medium",
      discoveredVia: "browser",
      summary: "Redeems a single-use coupon.",
      effect: { kind: "setActor", field: "redeemedBy" },
    },
    {
      key: "admin.users.list",
      method: "GET",
      path: "/api/admin/users",
      authRequired: true,
      requiredRole: "admin",
      category: "bfla",
      flaw: "missing_role_check",
      risk: "critical",
      discoveredVia: "forced-browsing",
      summary: "Lists every account in the tenant.",
    },
    {
      key: "admin.users.delete",
      method: "DELETE",
      path: "/api/admin/users/{id}",
      objectType: "account",
      authRequired: true,
      requiredRole: "admin",
      category: "bfla",
      flaw: "missing_role_check",
      risk: "critical",
      discoveredVia: "forced-browsing",
      summary: "Deletes an account.",
      effect: { kind: "deleteObject" },
    },
    {
      key: "admin.settings.read",
      method: "GET",
      path: "/api/admin/settings",
      authRequired: true,
      requiredRole: "admin",
      category: "bfla",
      risk: "medium",
      discoveredVia: "forced-browsing",
      summary: "Returns platform settings. Role check is enforced.",
    },
    {
      key: "audit.log.read",
      method: "GET",
      path: "/api/audit/log",
      authRequired: true,
      requiredRole: "manager",
      category: "bfla",
      risk: "medium",
      discoveredVia: "forced-browsing",
      summary: "Returns the audit log. Role check is enforced.",
    },
    {
      key: "debug.config",
      method: "GET",
      path: "/internal/debug/config",
      authRequired: false,
      category: "session",
      flaw: "missing_role_check",
      risk: "critical",
      discoveredVia: "passive-js",
      summary: "Exposes runtime configuration. Outside the declared scope.",
    },
  ];

  return { actors, objects, endpoints };
}

function isPrivileged(actor: LabActor): boolean {
  return actor.role === "admin" || actor.role === "superadmin";
}

/** What a correct implementation must decide. */
export function referenceDecision(
  ep: LabEndpoint,
  actor: LabActor,
  obj: LabObject | null,
): Decision {
  if (ep.authRequired && !actor.authenticated) {
    return { allow: false, reason: "endpoint requires authentication" };
  }
  if (ep.requiredRole && ROLE_RANK[actor.role] < ROLE_RANK[ep.requiredRole]) {
    return { allow: false, reason: `requires ${ep.requiredRole} role` };
  }
  if (obj) {
    if (!isPrivileged(actor) && obj.tenant !== actor.tenant) {
      return { allow: false, reason: "object belongs to another tenant" };
    }
    if (obj.owner && obj.owner !== actor.key && !isPrivileged(actor)) {
      return { allow: false, reason: "object is owned by another identity" };
    }
    // State-aware business rules: a transition is only legal from the right state.
    if (ep.key === "order.refund" && obj.state.status !== "PAID") {
      return {
        allow: false,
        reason: `refund is only permitted from the PAID state (current: ${String(obj.state.status)})`,
      };
    }
    if (ep.key === "coupon.redeem" && obj.state.redeemedBy !== null && obj.state.redeemedBy !== undefined) {
      return { allow: false, reason: "coupon has already been redeemed" };
    }
  }
  return { allow: true, reason: "permitted by policy" };
}

/** What the target application actually decides (defect-aware). */
export function actualDecision(
  ep: LabEndpoint,
  actor: LabActor,
  obj: LabObject | null,
): Decision {
  const base = referenceDecision(ep, actor, obj);
  if (base.allow) return base;
  switch (ep.flaw) {
    case "missing_object_check":
    case "missing_tenant_check":
      if (actor.authenticated) {
        return { allow: true, reason: "defect: ownership/tenant check not evaluated" };
      }
      return base;
    case "missing_role_check":
      if (actor.authenticated || !ep.authRequired) {
        return { allow: true, reason: "defect: role check not enforced" };
      }
      return base;
    case "missing_method_check":
      if (actor.authenticated) {
        return { allow: true, reason: "defect: method-level authorization missing" };
      }
      return base;
    case "workflow_bypass":
      if (actor.authenticated) {
        return { allow: true, reason: "defect: state transition not validated" };
      }
      return base;
    case "replay":
      if (actor.authenticated) {
        return { allow: true, reason: "defect: replay/idempotency protection missing" };
      }
      return base;
    default:
      return base;
  }
}

/** Apply the server-side side effect of an allowed request. */
export function applyEffect(
  ep: LabEndpoint,
  obj: LabObject | null,
  actor: LabActor,
  body: Record<string, unknown> | undefined,
): void {
  if (!obj || !ep.effect) return;
  const effect = ep.effect;
  switch (effect.kind) {
    case "set":
      obj.state[effect.field] = effect.value;
      break;
    case "setActor":
      obj.state[effect.field] = actor.key;
      break;
    case "assignOwnerFromBody": {
      const supplied = body?.[effect.field];
      if (typeof supplied === "string") obj.owner = supplied;
      break;
    }
    case "deleteObject":
      obj.state.deleted = true;
      obj.state.deletedBy = actor.key;
      break;
  }
}
