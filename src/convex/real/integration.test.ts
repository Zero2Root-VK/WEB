/**
 * WABVE — end-to-end integration test.
 *
 * Every other test in this folder injects a fake transport. This one closes the
 * last gap: it binds a real HTTP server to a real socket, then drives the real
 * pipeline — discovery → object model → differential probe — through the real
 * dispatcher, the real scope guard and the real rate limiter.
 *
 * No transport is faked here. Every assertion is made about bytes that actually
 * crossed a socket, which is the only way to know the product works against a
 * live target rather than a mock of one.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { createBucket, type ScopeConfig } from "./engine";
import { dispatch, fetchDocument, type RealIdentity, type RateState } from "./executor";
import {
  mergeEndpoints,
  openApiBaseUrl,
  parseHtml,
  parseOpenApi,
  type DiscoveredEndpoint,
} from "./discovery";
import {
  executeSuite,
  indexObjects,
  planProbes,
  type EndpointSpec,
  type ProbePlan,
  type Transport,
  type TransportPhase,
} from "./suite";

/* ------------------------------------------------------------------ */
/* the target: a real, two-tenant API                                  */
/* ------------------------------------------------------------------ */

type Owner = "alice" | "bob";

interface Record_ {
  id: string;
  owner: Owner;
  tenant: string;
  total: number;
  reference: string;
  title: string;
}

const TOKENS: Record<string, Owner> = { "alice-token": "alice", "bob-token": "bob" };

const ORDERS: Record<string, Record_> = {
  "1001": { id: "1001", owner: "alice", tenant: "acme", total: 420.5, reference: "ORD-1001-ACME", title: "Acme rack" },
  "2002": { id: "2002", owner: "bob", tenant: "globex", total: 88, reference: "ORD-2002-GLOBEX", title: "Globex seats" },
};

const INVOICES: Record<string, Record_> = {
  "5001": { id: "5001", owner: "alice", tenant: "acme", total: 420.5, reference: "INV-5001-ACME", title: "Acme invoice" },
  "6002": { id: "6002", owner: "bob", tenant: "globex", total: 88, reference: "INV-6002-GLOBEX", title: "Globex invoice" },
};

const PAGE = `<!doctype html><html><body>
<h1>Acme API</h1>
<a href="/api/orders">Orders</a>
<a href="/api/invoices">Invoices</a>
<script>fetch('/api/orders')</script>
</body></html>`;

const SPEC = {
  swagger: "2.0",
  host: "127.0.0.1",
  schemes: ["http"],
  basePath: "/",
  paths: {
    "/api/orders": { get: {} },
    "/api/orders/{order_id}": { get: { parameters: [{ name: "order_id", in: "path" }] } },
    "/api/invoices": { get: {} },
    "/api/invoices/{invoice_id}": { get: { parameters: [{ name: "invoice_id", in: "path" }] } },
  },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function ownerOf(req: Request): Owner | null {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.get("authorization") ?? "");
  return match ? TOKENS[match[1] ?? ""] ?? null : null;
}

/** Every path the server was actually asked for — proof of what left the box. */
const requestLog: string[] = [];
let server: Bun.Server<undefined>;
let base = "";

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    fetch(req) {
      const path = new URL(req.url).pathname;
      requestLog.push(`${req.method} ${path}`);
      if (req.method !== "GET") return json({ error: "method_not_allowed" }, 405);

      // Discovery surfaces — served over the same real socket as the API.
      if (path === "/api") return new Response(PAGE, { headers: { "content-type": "text/html" } });
      if (path === "/openapi.json") return json(SPEC);

      // Out of scope. It exists and would answer 200, so the only thing that can
      // keep this off the wire is the scope guard itself.
      if (path === "/admin/users") return json([{ id: "root", email: "root@acme.test" }]);

      const caller = ownerOf(req);
      if (!caller) return json({ error: "unauthorized" }, 401);

      if (path === "/api/orders") return json(Object.values(ORDERS).filter((o) => o.owner === caller));
      if (path === "/api/invoices") return json(Object.values(INVOICES).filter((o) => o.owner === caller));

      // VULNERABLE: any authenticated caller may read any order (broken object
      // level authorization / IDOR).
      const order = /^\/api\/orders\/([^/]+)$/.exec(path);
      if (order) {
        const record = ORDERS[order[1] ?? ""];
        if (!record) return json({ error: "not_found" }, 404);
        // Test hook for the "HTTP 200 is not a finding" rule: answer 200 with an
        // empty object to a caller who does not own the record.
        if (req.headers.get("x-blank") === "1" && record.owner !== caller) return json({});
        return json(record);
      }

      // SECURE: the ownership predicate is enforced inside the read.
      const invoice = /^\/api\/invoices\/([^/]+)$/.exec(path);
      if (invoice) {
        const record = INVOICES[invoice[1] ?? ""];
        if (!record) return json({ error: "not_found" }, 404);
        if (record.owner !== caller) return json({ error: "forbidden" }, 403);
        return json(record);
      }

      return json({ error: "not_found" }, 404);
    },
  });
  base = `http://127.0.0.1:${server.port}`;
});

afterAll(() => {
  server.stop(true);
});

/* ------------------------------------------------------------------ */
/* scope and identities                                                */
/* ------------------------------------------------------------------ */

const scope: ScopeConfig = {
  target: base,
  allowedHosts: ["127.0.0.1"],
  // `/admin` is deliberately absent: an out-of-scope path must be refused by
  // `authorize()`, not merely by the target's own routing.
  allowedPaths: ["/api", "/openapi.json"],
  rateLimit: 50,
  requestBudget: 500,
  killSwitch: false,
  destructiveTesting: false,
  dryRun: false,
};

const secrets = ["alice-token", "bob-token"];

const identities: RealIdentity[] = [
  { key: "alice", label: "Alice (acme)", role: "customer", authType: "bearer", secret: "alice-token" },
  { key: "bob", label: "Bob (globex)", role: "customer", authType: "bearer", secret: "bob-token" },
];

const identitiesByKey = new Map(identities.map((i) => [i.key, i]));

/** A real transport: every call goes through the real guard and real socket. */
function makeTransport(options: { headers?: Record<string, string>; limit?: number } = {}) {
  const rate: RateState = {
    bucket: createBucket(options.limit ?? scope.rateLimit, Date.now()),
    rateLimit: options.limit ?? scope.rateLimit,
  };
  let used = 0;
  const transport: Transport = async ({
    plan,
    identity,
  }: {
    plan: ProbePlan;
    identity: RealIdentity;
    phase: TransportPhase;
  }) => {
    used += 1;
    const outcome = await dispatch({
      scope,
      request: { method: plan.method, url: plan.url, ...(options.headers ? { headers: options.headers } : {}) },
      identity,
      requestsUsed: used,
      secrets,
      rate,
    });
    if (outcome.kind === "sent") return { status: outcome.response.status, body: outcome.response.body };
    // The suite treats a `blocked:` failure as blocked evidence, not an error.
    if (outcome.kind === "blocked") throw new Error(`blocked: ${outcome.reason}`);
    throw new Error(outcome.message);
  };
  return { transport, used: () => used };
}

/** One real request as one identity, via the real dispatcher. */
async function fetchAs(identity: RealIdentity, url: string): Promise<{ status: number; body: string }> {
  const outcome = await dispatch({
    scope,
    request: { method: "GET", url },
    identity,
    requestsUsed: 0,
    secrets,
  });
  if (outcome.kind !== "sent") throw new Error(`expected a response for ${url}, got ${outcome.kind}`);
  return { status: outcome.response.status, body: outcome.response.body };
}

/* ------------------------------------------------------------------ */
/* stages                                                              */
/* ------------------------------------------------------------------ */

async function discover(): Promise<DiscoveredEndpoint[]> {
  const retrieved: DiscoveredEndpoint[] = [];

  const spec = await fetchDocument({ scope, url: `${base}/openapi.json`, requestsUsed: 0 });
  if (spec.kind === "ok") retrieved.push(...parseOpenApi(JSON.parse(spec.text)));

  const page = await fetchDocument({ scope, url: `${base}/api`, requestsUsed: 0 });
  if (page.kind === "ok") retrieved.push(...parseHtml(page.text, base));

  return mergeEndpoints(retrieved);
}

async function learnObjects() {
  const responses: Array<{ identityKey: string; path: string; body: string }> = [];
  for (const identity of identities) {
    for (const path of ["/api/orders", "/api/invoices"]) {
      const response = await fetchAs(identity, `${base}${path}`);
      responses.push({ identityKey: identity.key, path, body: response.body });
    }
  }
  return indexObjects(responses);
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

describe("live end-to-end run against a real HTTP target", () => {
  test("discovery reads the target's OpenAPI document and HTML over the socket", async () => {
    expect(openApiBaseUrl(SPEC)).toContain("127.0.0.1");

    const endpoints = await discover();
    const keys = endpoints.map((e) => `${e.method} ${e.path}`);
    expect(keys).toContain("GET /api/orders/{order_id}");
    expect(keys).toContain("GET /api/invoices/{invoice_id}");
    // Learned from the served HTML, not the spec.
    expect(keys).toContain("GET /api/orders");
    expect(endpoints.find((e) => e.path === "/api/orders/{order_id}")?.parameters).toContain("order_id");
  });

  test("the model attributes each real record to the identity the server says owns it", async () => {
    const objects = await learnObjects();
    const byRef = new Map(objects.map((o) => [`${o.type}:${o.ref}`, o]));
    expect(byRef.get("order:2002")?.ownerKey).toBe("bob");
    expect(byRef.get("order:1001")?.ownerKey).toBe("alice");
    expect(byRef.get("invoice:6002")?.ownerKey).toBe("bob");
    expect(objects.length).toBeGreaterThanOrEqual(4);
  });

  test("the real differential suite confirms the IDOR and clears the secure endpoint", async () => {
    const endpoints = await discover();
    const specs: EndpointSpec[] = endpoints.map((e) => ({
      key: `${e.method} ${e.path}`,
      method: e.method,
      path: e.path,
      parameters: e.parameters,
      requiresAuth: true,
      source: e.source,
    }));

    const objects = await learnObjects();
    const plans = planProbes({
      endpoints: specs,
      objects,
      identities,
      baseUrl: base,
      tenantOf: (key) => (key === "alice" ? "acme" : "globex"),
    });
    // A cross-tenant pair exists for the order endpoint and for the invoice one.
    expect(plans.some((p) => p.url.includes("/api/orders/"))).toBe(true);
    expect(plans.some((p) => p.url.includes("/api/invoices/"))).toBe(true);

    const { transport, used } = makeTransport();
    const result = await executeSuite({ plans, identitiesByKey, transport });

    const orderFindings = result.findings.filter((f) => f.endpoint.includes("/api/orders/"));
    expect(orderFindings.length).toBeGreaterThanOrEqual(1);
    for (const finding of orderFindings) {
      expect(finding.verdict).toBe("confirmed");
      expect(finding.signals).toContain("protected_record_returned");
      expect(finding.score).toBeGreaterThanOrEqual(70);
      expect(finding.severity).toBe("high");
    }

    // The secure endpoint denies the outsider: no finding, an explicit verdict.
    const invoiceFindings = result.findings.filter((f) => f.endpoint.includes("/api/invoices/"));
    expect(invoiceFindings).toHaveLength(0);
    const invoiceTests = result.tests.filter((t) => t.path.includes("/api/invoices/"));
    expect(invoiceTests.length).toBeGreaterThanOrEqual(1);
    for (const test of invoiceTests) {
      expect(test.actual).toBe("DENY");
      expect(test.verdict).toBe("not_vulnerable");
    }

    // Real traffic was used, and nothing was faked to reach the verdict.
    expect(used()).toBeGreaterThan(0);
    expect(result.errors).toBe(0);

    // Credentials never reach the database or a report.
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("alice-token");
    expect(serialized).not.toContain("bob-token");
    expect(serialized).not.toContain("Bearer ");
  });

  test("a live 200 with no corroborating payload is not reported as a finding", async () => {
    const plan: ProbePlan = {
      id: "trap:order:2002:alice",
      endpointKey: "GET /api/orders/{order_id}",
      method: "GET",
      url: `${base}/api/orders/2002`,
      ownerKey: "bob",
      attackerKey: "alice",
      objectRef: "2002",
      destructive: false,
      rationale: "Alice does not own order 2002",
    };

    const { transport } = makeTransport({ headers: { "x-blank": "1" } });
    const result = await executeSuite({ plans: [plan], identitiesByKey, transport });

    expect(result.findings).toHaveLength(0);
    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]?.verdict).toBe("inconclusive");
    expect(result.tests[0]?.signals).toContain("unauthorized_access_confirmed");
  });

  test("the scope guard stops an out-of-scope request before it reaches the target", async () => {
    const outcome = await dispatch({
      scope,
      request: { method: "GET", url: `${base}/admin/users` },
      identity: identities[0]!,
      requestsUsed: 0,
      secrets,
    });

    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") {
      expect(outcome.reason).toBe("path_not_allowed");
    }
    // The route exists and would have answered: the guard, not the target, held.
    expect(requestLog.filter((entry) => entry.includes("/admin"))).toHaveLength(0);
  });

  test("the rate limiter withholds requests instead of dispatching them", async () => {
    const tight: ScopeConfig = { ...scope, rateLimit: 2 };
    const rate: RateState = { bucket: createBucket(2, Date.now()), rateLimit: 2 };

    const outcomes = [];
    for (let i = 0; i < 6; i += 1) {
      outcomes.push(
        await dispatch({
          scope: tight,
          request: { method: "GET", url: `${base}/api/orders` },
          identity: identities[0]!,
          requestsUsed: i,
          secrets,
          rate,
        }),
      );
    }

    const sent = outcomes.filter((o) => o.kind === "sent");
    const withheld = outcomes.filter((o) => o.kind === "blocked" && o.reason === "rate_limited");
    expect(sent.length).toBe(2);
    expect(withheld.length).toBe(4);
  });
});
