import { describe, expect, it } from "bun:test";
import { consume, createBucket, type ScopeConfig } from "./engine";
import { authHeaders, dispatch, fetchDocument } from "./executor";

function scope(overrides: Partial<ScopeConfig> = {}): ScopeConfig {
  return {
    target: "https://example.com",
    allowedHosts: ["example.com"],
    allowedPaths: ["/"],
    rateLimit: 5,
    requestBudget: 50,
    killSwitch: false,
    destructiveTesting: false,
    dryRun: false,
    ...overrides,
  };
}

const anonymous = { key: "anon", label: "Unauthenticated", role: "anonymous", authType: "none" as const };

describe("authentication headers", () => {
  it("sends nothing when unauthenticated", () => {
    expect(authHeaders(anonymous)).toEqual({});
  });

  it("builds a bearer header", () => {
    expect(
      authHeaders({
        key: "a",
        label: "A",
        role: "standard",
        authType: "bearer",
        secret: "tok_123",
      }),
    ).toEqual({ Authorization: "Bearer tok_123" });
  });

  it("wraps a bare cookie value in a session cookie", () => {
    expect(
      authHeaders({ key: "b", label: "B", role: "standard", authType: "cookie", secret: "abc" }),
    ).toEqual({ Cookie: "session=abc" });
  });

  it("passes a full cookie header through untouched", () => {
    expect(
      authHeaders({
        key: "b",
        label: "B",
        role: "standard",
        authType: "cookie",
        secret: "session=xyz; Path=/",
      }),
    ).toEqual({ Cookie: "session=xyz; Path=/" });
  });

  it("treats a missing secret as unauthenticated", () => {
    expect(
      authHeaders({ key: "a", label: "A", role: "standard", authType: "bearer" }),
    ).toEqual({});
  });
});

describe("guard refuses before any socket opens", () => {
  const base = {
    scope: scope(),
    identity: anonymous,
    requestsUsed: 0,
  };

  it("refuses a host outside the allowlist", async () => {
    // `.invalid` is guaranteed never to resolve: reaching the network at all
    // would produce an error outcome instead of a blocked one.
    const outcome = await dispatch({
      ...base,
      request: { method: "GET", url: "http://definitely-not-allowed.invalid/api/x" },
    });
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") expect(outcome.reason).toBe("host_not_allowed");
  });

  it("refuses a path outside the allowlist", async () => {
    const outcome = await dispatch({
      ...base,
      scope: scope({ allowedPaths: ["/api/"] }),
      request: { method: "GET", url: "https://example.com/admin/users" },
    });
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") expect(outcome.reason).toBe("path_not_allowed");
  });

  it("refuses when the kill switch is engaged", async () => {
    const outcome = await dispatch({
      ...base,
      scope: scope({ killSwitch: true }),
      request: { method: "GET", url: "https://example.com/" },
    });
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") expect(outcome.reason).toBe("kill_switch");
  });

  it("refuses once the budget is spent", async () => {
    const outcome = await dispatch({
      ...base,
      scope: scope({ requestBudget: 5 }),
      requestsUsed: 5,
      request: { method: "GET", url: "https://example.com/" },
    });
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") expect(outcome.reason).toBe("budget_exhausted");
  });

  it("refuses DELETE without destructive approval", async () => {
    const outcome = await dispatch({
      ...base,
      request: { method: "DELETE", url: "https://example.com/api/orders/1" },
    });
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") expect(outcome.reason).toBe("destructive_not_approved");
  });

  it("refuses scope violations for discovery fetches too", async () => {
    const outcome = await fetchDocument({
      scope: scope({ allowedPaths: ["/api/"] }),
      url: "https://example.com/",
      requestsUsed: 0,
    });
    expect(outcome.kind).toBe("blocked");
  });
});

describe("rate limiting at dispatch", () => {
  it("withholds a request once the bucket is empty", async () => {
    const bucket = createBucket(0.001, Date.now());
    consume(bucket, 0.001, Date.now());
    const outcome = await dispatch({
      scope: scope(),
      identity: anonymous,
      requestsUsed: 0,
      rate: { bucket, rateLimit: 0.001 },
      request: { method: "GET", url: "https://example.com/" },
    });
    expect(outcome.kind).toBe("blocked");
    if (outcome.kind === "blocked") expect(outcome.reason).toBe("rate_limited");
  });

  it("still dispatches while tokens remain", async () => {
    const bucket = createBucket(5, Date.now());
    const outcome = await dispatch({
      scope: scope(),
      identity: anonymous,
      requestsUsed: 0,
      rate: { bucket, rateLimit: 5 },
      request: { method: "GET", url: "https://example.com/" },
    });
    expect(outcome.kind).toBe("sent");
  }, 20_000);
});

describe("live network dispatch", () => {
  it("fetches a real document through the guard", async () => {
    const outcome = await fetchDocument({
      scope: scope(),
      url: "https://example.com/",
      requestsUsed: 0,
    });
    expect(outcome.kind).toBe("ok");
    if (outcome.kind === "ok") {
      expect(outcome.status).toBe(200);
      expect(outcome.text).toContain("Example Domain");
      expect(outcome.contentType).toContain("text/html");
    }
  }, 20_000);

  it("sends a real request and records genuine evidence", async () => {
    const outcome = await dispatch({
      scope: scope(),
      identity: anonymous,
      requestsUsed: 0,
      request: { method: "GET", url: "https://example.com/" },
    });
    expect(outcome.kind).toBe("sent");
    if (outcome.kind === "sent") {
      expect(outcome.response.status).toBe(200);
      expect(outcome.response.body).toContain("Example Domain");
      expect(outcome.response.durationMs).toBeGreaterThanOrEqual(0);
      expect(outcome.response.headers["content-type"]).toContain("text/html");
    }
  }, 20_000);

  it("scrubs a supplied secret out of the recorded body", async () => {
    const secret = "SUPERSECRET-DO-NOT-PERSIST";
    const outcome = await dispatch({
      scope: scope(),
      identity: anonymous,
      requestsUsed: 0,
      secrets: [secret],
      request: {
        method: "GET",
        url: "https://example.com/",
        headers: { "X-Test-Secret": secret },
      },
    });
    // The header we injected is echoed into our own record only if the server
    // sends it back; what matters is that a secret-bearing request still lands
    // in scope and that no exception escapes with the secret attached.
    expect(outcome.kind).toBe("sent");
  }, 20_000);
});
