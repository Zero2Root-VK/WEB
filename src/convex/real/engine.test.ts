import { describe, expect, it } from "bun:test";
import {
  authorize,
  confidenceLabel,
  consume,
  createBucket,
  differentialOracle,
  diffSnapshots,
  hostAllowed,
  normalizePath,
  normalizeSnapshot,
  pathAllowed,
  protectedMarkers,
  scrubSecrets,
  scoreSignals,
  type ScopeConfig,
} from "./engine";

function scope(overrides: Partial<ScopeConfig> = {}): ScopeConfig {
  return {
    target: "https://staging.acme.test",
    allowedHosts: ["staging.acme.test"],
    allowedPaths: ["/api/"],
    rateLimit: 5,
    requestBudget: 100,
    killSwitch: false,
    destructiveTesting: false,
    dryRun: false,
    ...overrides,
  };
}

describe("path normalisation", () => {
  it("leaves a well-formed path alone", () => {
    expect(normalizePath("/api/orders/5001")).toBe("/api/orders/5001");
  });

  it("collapses dot segments", () => {
    expect(normalizePath("/api/../admin/x")).toBe("/admin/x");
    expect(normalizePath("/api/./orders")).toBe("/api/orders");
  });

  it("collapses encoded traversal", () => {
    expect(normalizePath("/api/%2e%2e/admin")).toBe("/admin");
    expect(normalizePath("/api/%2E%2E/%2e%2e/secrets")).toBe("/secrets");
  });

  it("pops as many levels as it consumes", () => {
    expect(normalizePath("/a/b/../../../c")).toBe("/c");
  });
});

describe("host allowlist", () => {
  it("accepts an exact host", () => {
    expect(hostAllowed("staging.acme.test", ["staging.acme.test"])).toBe(true);
  });

  it("accepts a real subdomain of a dotted pattern", () => {
    expect(hostAllowed("api.acme.test", ["acme.test"])).toBe(true);
  });

  it("rejects a host outside the allowlist", () => {
    expect(hostAllowed("evil.test", ["staging.acme.test"])).toBe(false);
  });

  it("never treats a bare pattern as a domain suffix", () => {
    // The footgun that would open the entire internet: an allowlist of `test`
    // must not authorise `staging.test`.
    expect(hostAllowed("staging.test", ["test"])).toBe(false);
    expect(hostAllowed("evil-com.test", ["test"])).toBe(false);
  });

  it("ignores a trailing dot on the request host", () => {
    expect(hostAllowed("staging.acme.test.", ["staging.acme.test"])).toBe(true);
  });
});

describe("path allowlist", () => {
  it("accepts anything when unconstrained", () => {
    expect(pathAllowed("/whatever", [])).toBe(true);
  });

  it("requires a path-segment boundary", () => {
    expect(pathAllowed("/api/orders", ["/api"])).toBe(true);
    expect(pathAllowed("/apixyz/orders", ["/api"])).toBe(false);
  });

  it("rejects a sibling prefix", () => {
    expect(pathAllowed("/apikeys", ["/api/"])).toBe(false);
  });
});

describe("authorize", () => {
  const allow = { scope: scope(), url: "https://staging.acme.test/api/orders", method: "GET", requestsUsed: 0 };

  it("permits an in-scope GET", () => {
    const decision = authorize(allow);
    expect(decision.allowed).toBe(true);
  });

  it("refuses when the kill switch is engaged", () => {
    const decision = authorize({ ...allow, scope: scope({ killSwitch: true }) });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("kill_switch");
  });

  it("refuses once the request budget is spent", () => {
    const decision = authorize({ ...allow, scope: scope({ requestBudget: 10 }), requestsUsed: 10 });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("budget_exhausted");
  });

  it("refuses a host outside the allowlist before any socket opens", () => {
    const decision = authorize({ ...allow, url: "https://evil.test/api/orders" });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("host_not_allowed");
  });

  it("refuses a path outside the allowlist", () => {
    const decision = authorize({ ...allow, url: "https://staging.acme.test/admin/users" });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("path_not_allowed");
  });

  it("refuses encoded traversal that passes the raw prefix check", () => {
    const decision = authorize({ ...allow, url: "https://staging.acme.test/api/%2e%2e/admin/users" });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("path_not_allowed");
  });

  it("refuses non-http protocols", () => {
    for (const url of ["file:///etc/passwd", "javascript:alert(1)", "ftp://staging.acme.test/api/x"]) {
      const decision = authorize({ ...allow, url });
      expect(decision.allowed).toBe(false);
    }
  });

  it("refuses an unparseable url", () => {
    const decision = authorize({ ...allow, url: "::not a url" });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("unparseable_url");
  });

  it("refuses DELETE until destructive testing is approved", () => {
    const decision = authorize({ ...allow, method: "DELETE" });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("destructive_not_approved");
  });

  it("allows DELETE once approved", () => {
    const decision = authorize({
      ...allow,
      method: "DELETE",
      scope: scope({ destructiveTesting: true }),
    });
    expect(decision.allowed).toBe(true);
  });

  it("does not require approval for ordinary writes", () => {
    expect(authorize({ ...allow, method: "POST" }).allowed).toBe(true);
    expect(authorize({ ...allow, method: "PUT" }).allowed).toBe(true);
  });

  it("honours an endpoint-level destructive flag", () => {
    const decision = authorize({ ...allow, method: "POST", destructive: true });
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("destructive_not_approved");
  });

  it("refuses an unknown HTTP method", () => {
    const decision = authorize({ ...allow, method: "PURGE" });
    expect(decision.allowed).toBe(false);
  });
});

describe("rate limiter", () => {
  it("allows the burst capacity then denies", () => {
    const bucket = createBucket(5, 1000);
    for (let i = 0; i < 5; i += 1) expect(consume(bucket, 5, 1000)).toBe(true);
    expect(consume(bucket, 5, 1000)).toBe(false);
  });

  it("refills over time at the configured rate", () => {
    const bucket = createBucket(5, 1000);
    for (let i = 0; i < 5; i += 1) consume(bucket, 5, 1000);
    expect(consume(bucket, 5, 1100)).toBe(false);
    expect(consume(bucket, 5, 1300)).toBe(true);
  });

  it("never refills beyond capacity", () => {
    const bucket = createBucket(5, 1000);
    for (let i = 0; i < 5; i += 1) consume(bucket, 5, 1000);
    expect(consume(bucket, 5, 1000)).toBe(false);
    // 60s of credit at 5/s would be 300 tokens; capacity must clamp it to 5.
    let successes = 0;
    for (let i = 0; i < 10; i += 1) {
      if (consume(bucket, 5, 60_000)) successes += 1;
    }
    expect(successes).toBe(5);
  });

  it("enforces a rate of one per second", () => {
    const bucket = createBucket(1, 0);
    expect(consume(bucket, 1, 0)).toBe(true);
    expect(consume(bucket, 1, 500)).toBe(false);
    expect(consume(bucket, 1, 1000)).toBe(true);
  });
});

describe("secret redaction", () => {
  it("removes known secrets", () => {
    expect(scrubSecrets("token=super-secret-value", ["super-secret-value"])).not.toContain(
      "super-secret-value",
    );
  });

  it("ignores pathologically short secrets", () => {
    expect(scrubSecrets("abcd value", ["ab"])).toContain("abcd value");
  });

  it("masks authorization values regardless of knowledge", () => {
    const out = scrubSecrets("Authorization: Bearer sk-live-12345");
    expect(out).not.toContain("sk-live-12345");
    expect(out).toContain("••••••");
  });

  it("masks cookie headers", () => {
    const out = scrubSecrets("set-cookie: session=abc123; HttpOnly");
    expect(out).not.toContain("abc123");
  });

  it("masks JWT-shaped values", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart";
    expect(scrubSecrets(`payload ${jwt}`)).not.toContain("eyJzdWIi");
  });
});

describe("state snapshots", () => {
  it("ignores volatile timestamps", () => {
    const before = { status: "PAID", updatedAt: "2026-01-01T00:00:00Z" };
    const after = { status: "PAID", updatedAt: "2026-01-02T00:00:00Z" };
    expect(diffSnapshots(before, after)).toEqual([]);
  });

  it("reports a real change", () => {
    const delta = diffSnapshots({ status: "PAID" }, { status: "CANCELLED" });
    expect(delta).toHaveLength(1);
    expect(delta[0]).toEqual({ field: "status", before: "PAID", after: "CANCELLED" });
  });

  it("respects operator-supplied volatile keys", () => {
    const delta = diffSnapshots({ csrf: "a" }, { csrf: "b" }, ["csrf"]);
    expect(delta).toEqual([]);
  });

  it("surfaces ownership changes", () => {
    const delta = diffSnapshots({ owner: "user_a" }, { owner: "user_b" });
    expect(delta.some((d) => d.field === "owner")).toBe(true);
  });

  it("normalises nested structures", () => {
    const value = normalizeSnapshot({ order: { status: "PAID", createdAt: "x" } });
    expect(value).toEqual({ order: { status: "PAID" } });
  });
});

describe("differential oracle", () => {
  it("confirms when a denied request returns the protected record", () => {
    const result = differentialOracle({
      expectedDenied: true,
      attackerStatus: 200,
      ownerStatus: 200,
      attackerBody: '{"id":5001,"owner":"User A","amount":4500}',
      ownerBody: '{"id":5001,"owner":"User A","amount":4500}',
      protectedMarkers: ["User A", "5001"],
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBeGreaterThanOrEqual(70);
    expect(result.signals).toContain("protected_record_returned");
  });

  it("does NOT confirm on a status code alone", () => {
    const result = differentialOracle({
      expectedDenied: true,
      attackerStatus: 200,
      ownerStatus: 200,
      attackerBody: "{}",
      ownerBody: '{"id":5001,"owner":"User A"}',
      protectedMarkers: ["User A"],
    });
    expect(result.verdict).toBe("inconclusive");
    expect(result.signals).not.toContain("differential_confirmed");
  });

  it("confirms on a persisted state change without markers", () => {
    const result = differentialOracle({
      expectedDenied: true,
      attackerStatus: 200,
      ownerStatus: 404,
      attackerBody: "{}",
      ownerBody: "{}",
      protectedMarkers: [],
      stateBefore: { status: "PAID" },
      stateAfter: { status: "CANCELLED" },
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.delta).toHaveLength(1);
  });

  it("reports not_vulnerable when the server denies", () => {
    const result = differentialOracle({
      expectedDenied: true,
      attackerStatus: 403,
      ownerStatus: 200,
      attackerBody: '{"error":"forbidden"}',
      ownerBody: '{"id":5001}',
      protectedMarkers: ["5001"],
    });
    expect(result.verdict).toBe("not_vulnerable");
    expect(result.confidence).toBe(0);
  });

  it("treats a legitimate action succeeding as not vulnerable", () => {
    const result = differentialOracle({
      expectedDenied: false,
      attackerStatus: 200,
      ownerStatus: 200,
      attackerBody: '{"ok":true}',
      ownerBody: '{"ok":true}',
      protectedMarkers: [],
    });
    expect(result.verdict).toBe("not_vulnerable");
  });

  it("flags a legitimate action that the server wrongly blocks", () => {
    const result = differentialOracle({
      expectedDenied: false,
      attackerStatus: 403,
      ownerStatus: 200,
      attackerBody: "",
      ownerBody: "",
      protectedMarkers: [],
    });
    expect(result.verdict).toBe("inconclusive");
    expect(result.signals).toContain("legitimate_action_denied");
  });
});

describe("confidence scoring", () => {
  it("sums signal weights and caps at 100", () => {
    expect(scoreSignals([])).toBe(0);
    expect(scoreSignals(["unauthorized_access_confirmed", "differential_confirmed"])).toBe(40);
    expect(
      scoreSignals([
        "unauthorized_access_confirmed",
        "protected_record_returned",
        "server_state_changed",
        "differential_confirmed",
        "reproducible",
      ]),
    ).toBe(100);
  });

  it("ignores unknown signals", () => {
    expect(scoreSignals(["not_a_real_signal"])).toBe(0);
  });

  it("maps scores to PRD confidence bands", () => {
    expect(confidenceLabel(95)).toBe("Confirmed");
    expect(confidenceLabel(70)).toBe("High");
    expect(confidenceLabel(45)).toBe("Medium");
    expect(confidenceLabel(10)).toBe("Inconclusive");
  });
});

describe("protected marker extraction", () => {
  it("collects identifying fields", () => {
    const markers = protectedMarkers({ owner: "User A", id: 5001, amount: 4500 });
    expect(markers).toContain("User A");
    expect(markers).toContain("5001");
    expect(markers).toContain("4500");
  });

  it("reads markers from a response body string", () => {
    const markers = protectedMarkers('{"email":"alice@acme.test"}');
    expect(markers).toContain("alice@acme.test");
  });

  it("skips volatile keys", () => {
    const markers = protectedMarkers({ updatedAt: "2026-01-01" });
    expect(markers).toEqual([]);
  });
});
