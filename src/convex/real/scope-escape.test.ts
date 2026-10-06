/**
 * WABVE — adversarial QA: can the scope guard be escaped?
 *
 * A pentest tool is only sellable if its own safety controls hold under a
 * hostile target. These tests do not trust `authorize()` to be correct — they
 * prove it at the socket, by standing up a target that logs every request and
 * asserting that nothing out of scope was ever delivered to it.
 *
 * A "blocked" return value alone is not evidence: the assertion that matters is
 * that the target's request log did not grow.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { authorize, createBucket, type ScopeConfig, type DenyReason } from "./engine";
import { dispatch, type RealIdentity, type RateState } from "./executor";

/* ------------------------------------------------------------------ */
/* two real servers: one in scope, one that must never be reached      */
/* ------------------------------------------------------------------ */

const insideLog: string[] = [];
const outsideLog: string[] = [];
let inside: Bun.Server<undefined>;
let outside: Bun.Server<undefined>;
let base = "";
let stealUrl = "";

beforeAll(() => {
  inside = Bun.serve({
    port: 0,
    fetch(req) {
      const path = new URL(req.url).pathname;
      insideLog.push(`${req.method} ${path}`);
      // A hostile in-scope response: bounce the scanner somewhere it was never
      // authorised to go.
      if (path === "/api/redirect") {
        return new Response(null, { status: 302, headers: { location: stealUrl } });
      }
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  outside = Bun.serve({
    port: 0,
    fetch(req) {
      outsideLog.push(`${req.method} ${new URL(req.url).pathname}`);
      return new Response(JSON.stringify({ stolen: "secret" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  base = `http://127.0.0.1:${inside.port}`;
  // Different port, same host name — so the host allowlist alone cannot stop
  // this. Only the *path* is out of scope, which is exactly the point.
  stealUrl = `http://127.0.0.1:${outside.port}/steal`;
});

afterAll(() => {
  inside.stop(true);
  outside.stop(true);
});

const scope: ScopeConfig = {
  target: base,
  allowedHosts: ["127.0.0.1"],
  allowedPaths: ["/api"],
  rateLimit: 100,
  requestBudget: 500,
  killSwitch: false,
  destructiveTesting: false,
  dryRun: false,
};

const identity: RealIdentity = { key: "alice", label: "Alice", role: "customer", authType: "bearer", secret: "tok-alice" };

async function attempt(input: {
  url: string;
  method?: string;
  scope?: ScopeConfig;
  destructive?: boolean;
  requestsUsed?: number;
}) {
  const outcome = await dispatch({
    scope: input.scope ?? scope,
    request: { method: input.method ?? "GET", url: input.url },
    identity,
    // The budget is enforced against the counter the caller supplies, exactly as
    // the runner does it — a caller that always passes 0 would never run out.
    requestsUsed: input.requestsUsed ?? 0,
    secrets: ["tok-alice"],
    ...(input.destructive !== undefined ? { destructive: input.destructive } : {}),
  });
  return outcome;
}

/* ------------------------------------------------------------------ */
/* the hostile battery                                                 */
/* ------------------------------------------------------------------ */

describe("hostile URLs never reach the target", () => {
  test("a single in-scope request does get through, so the log is not vacuously empty", async () => {
    const before = insideLog.length;
    const outcome = await attempt({ url: `${base}/api/orders` });
    expect(outcome.kind).toBe("sent");
    expect(insideLog.length).toBe(before + 1);
  });

  test("every out-of-scope attempt is refused before a socket opens", async () => {
    const before = insideLog.length;

    const cases: Array<{ label: string; url: string; method?: string; reasons: DenyReason[] }> = [
      {
        label: "path prefix lookalike /apixyz",
        url: `${base}/apixyz`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "raw traversal /api/../admin",
        url: `${base}/api/../admin`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "percent-encoded traversal /api/%2e%2e/admin",
        url: `${base}/api/%2e%2e/admin`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "mixed-encoding traversal /api/..%2fadmin",
        url: `${base}/api/..%2fadmin`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "dot-segment escape /api/./../admin",
        url: `${base}/api/./../admin`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "empty segment //api",
        url: `${base}//admin`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "case-varied path /API/orders",
        url: `${base}/API/orders`,
        reasons: ["path_not_allowed"],
      },
      {
        label: "sibling host 127.0.0.1.evil.test",
        url: `http://127.0.0.1.evil.test/api`,
        reasons: ["host_not_allowed"],
      },
      {
        // The URL parser reads an all-numeric final label as IPv4 and rejects
        // this host outright, so it is refused as unparseable rather than by the
        // allowlist. Either way it must never be dispatched.
        label: "suffix host evil-127.0.0.1",
        url: `http://evil-127.0.0.1/api`,
        reasons: ["host_not_allowed", "unparseable_url"],
      },
      {
        label: "unrelated host evil.test",
        url: `http://evil.test/api`,
        reasons: ["host_not_allowed"],
      },
      {
        label: "userinfo trick 127.0.0.1@evil.test",
        url: `http://127.0.0.1@evil.test/api`,
        reasons: ["host_not_allowed"],
      },
      { label: "file scheme", url: `file:///etc/passwd`, reasons: ["protocol"] },
      { label: "ftp scheme", url: `ftp://127.0.0.1/api`, reasons: ["protocol"] },
      { label: "javascript scheme", url: `javascript:alert(1)`, reasons: ["protocol"] },
      {
        label: "unknown method BREW",
        url: `${base}/api/orders`,
        method: "BREW",
        reasons: ["protocol"],
      },
      {
        label: "DELETE without destructive approval",
        url: `${base}/api/orders/1001`,
        method: "DELETE",
        reasons: ["destructive_not_approved"],
      },
    ];

    for (const entry of cases) {
      const outcome = await attempt(entry);
      expect(`${entry.label}: ${outcome.kind}`).toBe(`${entry.label}: blocked`);
      if (outcome.kind === "blocked") {
        expect(entry.reasons).toContain(outcome.reason);
      }
    }

    // The assertion that actually matters: not one byte reached the target.
    expect(insideLog.length).toBe(before);
  });
});

/* ------------------------------------------------------------------ */
/* budget and kill switch, at the socket                               */
/* ------------------------------------------------------------------ */

describe("budget and kill switch stop traffic at the socket", () => {
  test("a spent budget refuses further requests and sends nothing", async () => {
    const limited: ScopeConfig = { ...scope, requestBudget: 2 };
    const before = insideLog.length;

    const outcomes = [];
    for (let i = 0; i < 5; i += 1) outcomes.push(await attempt({ url: `${base}/api/orders`, scope: limited, requestsUsed: i }));

    expect(outcomes.filter((o) => o.kind === "sent").length).toBe(2);
    const refused = outcomes.filter((o) => o.kind === "blocked");
    expect(refused.length).toBe(3);
    for (const outcome of refused) {
      if (outcome.kind === "blocked") expect(outcome.reason).toBe("budget_exhausted");
    }
    expect(insideLog.length).toBe(before + 2);
  });

  test("engaging the kill switch stops an in-progress run immediately", async () => {
    const live: ScopeConfig = { ...scope };
    const before = insideLog.length;

    expect((await attempt({ url: `${base}/api/orders`, scope: live })).kind).toBe("sent");
    live.killSwitch = true;
    expect((await attempt({ url: `${base}/api/orders`, scope: live })).kind).toBe("blocked");
    expect((await attempt({ url: `${base}/api/orders`, scope: live })).kind).toBe("blocked");

    expect(insideLog.length).toBe(before + 1);
  });

  test("a rate-limited request is withheld rather than sent", async () => {
    const rate: RateState = { bucket: createBucket(1, Date.now()), rateLimit: 1 };
    const before = insideLog.length;

    const send = () =>
      dispatch({ scope, request: { method: "GET", url: `${base}/api/orders` }, identity, requestsUsed: 0, secrets: [], rate });
    const first = await send();
    const second = await send();

    expect(first.kind).toBe("sent");
    expect(second.kind).toBe("blocked");
    if (second.kind === "blocked") expect(second.reason).toBe("rate_limited");
    expect(insideLog.length).toBe(before + 1);
  });
});

/* ------------------------------------------------------------------ */
/* redirects                                                           */
/* ------------------------------------------------------------------ */

describe("redirects cannot leave the allowlist", () => {
  test("an in-scope 302 must not be followed out of scope", async () => {
    const before = outsideLog.length;
    const outcome = await attempt({ url: `${base}/api/redirect` });

    // The target is free to answer 302. What WABVE must never do is follow that
    // Location to a path the operator did not authorise: following it would
    // turn any in-scope host into a pivot onto an unauthorised one.
    expect(outsideLog.length).toBe(before);
    expect(outsideLog.filter((entry) => entry.includes("/steal"))).toHaveLength(0);
    void outcome;
  });

  test("a direct request to the redirect target is refused as well", async () => {
    const before = outsideLog.length;
    const outcome = await attempt({ url: stealUrl });
    expect(outcome.kind).toBe("blocked");
    expect(outsideLog.length).toBe(before);
  });
});

/* ------------------------------------------------------------------ */
/* manual spot-check of one hostile case, for readable failure output   */
/* ------------------------------------------------------------------ */

describe("guard decision is explainable", () => {
  test("a traversal attempt reports a human-readable reason", () => {
    const decision = authorize({ scope, url: `${base}/api/%2e%2e/admin`, method: "GET", requestsUsed: 0 });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("path_not_allowed");
      expect(decision.detail.length).toBeGreaterThan(0);
    }
  });

});
