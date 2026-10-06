import { describe, expect, it } from "bun:test";
import {
  categoryFor,
  cweFor,
  classificationFor,
  clip,
  findingCode,
  outcomeFor,
  probeNameFor,
  realCoverage,
  riskFor,
  toBlockedTestRow,
  toFindingRow,
  toTestRow,
  owaspForCategory,
} from "./reporting";
import type { FindingRecord, ProbePlan, TestRecord } from "./suite";

const plan: ProbePlan = {
  id: "order.read:order:5001:user_b",
  endpointKey: "order.read",
  method: "GET",
  url: "https://staging.acme.test/api/orders/5001",
  ownerKey: "user_a",
  attackerKey: "user_b",
  objectRef: "5001",
  destructive: false,
  rationale: "User B does not own order 5001",
};

function testRecord(overrides: Partial<TestRecord> = {}): TestRecord {
  return {
    planId: plan.id,
    endpointKey: "order.read",
    method: "GET",
    path: "/api/orders/5001",
    attackerKey: "user_b",
    ownerKey: "user_a",
    objectRef: "5001",
    expectation: "DENY",
    actual: "ALLOW",
    attackerStatus: 200,
    ownerStatus: 200,
    verdict: "confirmed",
    signals: ["unauthorized_access_confirmed", "protected_record_returned", "differential_confirmed"],
    confidence: 90,
    reason: "attacker received 200 with protected values",
    baselineBody: JSON.stringify({ id: "5001", total: 4200, owner: "user_a" }),
    attackBody: JSON.stringify({ id: "5001", total: 4200, owner: "user_a" }),
    delta: [],
    ...overrides,
  };
}

function findingRecord(overrides: Partial<FindingRecord> = {}): FindingRecord {
  return {
    code: "WABVE-001",
    testId: plan.id,
    endpoint: "GET /api/orders/5001",
    objectRef: "5001",
    attacker: "User B",
    owner: "User A",
    severity: "critical",
    confidence: "Confirmed",
    score: 90,
    verdict: "confirmed",
    signals: ["unauthorized_access_confirmed", "protected_record_returned"],
    expected: "403 Forbidden",
    actual: "200 with 0 state change(s)",
    reason: "protected payload returned to a non-owner",
    beforeState: JSON.stringify({ id: "5001", owner: "user_a" }),
    afterState: JSON.stringify({ id: "5001", owner: "user_a" }),
    delta: [],
    remediation: "Scope the read by owner.",
    ...overrides,
  };
}

describe("verdict → outcome", () => {
  it("maps confirmed and likely to a failure", () => {
    expect(outcomeFor("confirmed")).toBe("fail");
    expect(outcomeFor("likely")).toBe("fail");
  });

  it("maps inconclusive to inconclusive and everything else to pass", () => {
    expect(outcomeFor("inconclusive")).toBe("inconclusive");
    expect(outcomeFor("not_vulnerable")).toBe("pass");
    expect(outcomeFor("anything-else")).toBe("pass");
  });
});

describe("classification", () => {
  it("classifies by corroborating signal, not by status code", () => {
    expect(categoryFor(["privilege_boundary_crossed"])).toBe("bfla");
    expect(categoryFor(["tenant_boundary_crossed"])).toBe("tenant");
    expect(categoryFor(["protected_property_accepted"])).toBe("property");
    expect(categoryFor(["protected_record_returned"])).toBe("authorization");
  });

  it("maps categories to OWASP and signals to CWE", () => {
    expect(owaspForCategory("bfla")).toContain("A01:2021");
    expect(owaspForCategory("unknown")).toContain("A01:2021");
    expect(cweFor(["protected_property_accepted"])).toBe("CWE-915");
    expect(cweFor(["privilege_boundary_crossed"])).toBe("CWE-285");
    expect(cweFor(["server_state_changed"])).toBe("CWE-862");
    expect(cweFor(["protected_record_returned"])).toBe("CWE-639");
  });

  it("names the finding class", () => {
    expect(classificationFor(["tenant_boundary_crossed"])).toBe("Tenant Isolation");
    expect(classificationFor(["privilege_boundary_crossed"])).toBe("BFLA");
    expect(classificationFor(["protected_property_accepted"])).toBe("Mass Assignment");
    expect(classificationFor(["unauthorized_access_confirmed"])).toBe("BOLA / IDOR");
  });

  it("derives risk from the evidence", () => {
    expect(riskFor(["ownership_reassigned"])).toBe("critical");
    expect(riskFor(["privilege_boundary_crossed"])).toBe("critical");
    expect(riskFor(["server_state_changed"])).toBe("high");
    expect(riskFor(["unauthorized_access_confirmed"])).toBe("medium");
  });

  it("names the probe by verb", () => {
    expect(probeNameFor("GET")).toBe("cross_identity_read");
    expect(probeNameFor("PUT")).toBe("cross_identity_write");
    expect(probeNameFor("DELETE")).toBe("cross_identity_destructive_write");
  });
});

describe("test rows", () => {
  it("builds an evidence-rich row for a confirmed read", () => {
    const row = toTestRow({
      record: testRecord(),
      plan,
      actorLabel: "User B",
      ownerLabel: "User A",
    });
    expect(row.outcome).toBe("fail");
    expect(row.category).toBe("authorization");
    expect(row.risk).toBe("high");
    expect(row.actorLabel).toBe("User B");
    expect(row.victimLabel).toBe("User A");
    expect(row.statusCode).toBe(200);
    expect(row.request).toContain("reference (as User A): HTTP 200");
    expect(row.response).toContain("verdict: confirmed");
    expect(row.request).toContain("rationale: User B does not own order 5001");
    expect(row.beforeState).toEqual({ id: "5001", total: 4200, owner: "user_a" });
  });

  it("does not report a 2xx without corroboration as a failure", () => {
    const row = toTestRow({
      record: testRecord({
        verdict: "inconclusive",
        signals: ["unauthorized_access_confirmed"],
        confidence: 30,
        reason: "status 200 without corroborating payload",
      }),
      plan,
      actorLabel: "User B",
      ownerLabel: "User A",
    });
    expect(row.outcome).toBe("inconclusive");
    expect(row.risk).toBe("low");
  });

  it("records a blocked probe as first-class evidence", () => {
    const row = toBlockedTestRow({
      plan: { ...plan, method: "DELETE" },
      reason: "destructive_not_approved",
      detail: "DELETE is not approved for this engagement",
      actorLabel: "User B",
      ownerLabel: "User A",
    });
    expect(row.outcome).toBe("blocked");
    expect(row.statusCode).toBe(0);
    expect(row.signals).toEqual(["destructive_not_approved"]);
    expect(row.response).toContain("withheld");
  });
});

describe("finding rows", () => {
  it("builds a reportable finding with classification and reproduction", () => {
    const row = toFindingRow({
      record: findingRecord(),
      code: findingCode(0),
      actorLabel: "User B",
      ownerLabel: "User A",
    });
    expect(row.code).toBe("WABVE-001");
    expect(row.title).toContain("/api/orders/5001");
    expect(row.classification).toBe("BOLA / IDOR");
    expect(row.cwe).toBe("CWE-639");
    expect(row.owasp).toContain("Broken Access Control");
    expect(row.impact).toContain("User B");
    expect(row.reproduction.length).toBeGreaterThanOrEqual(4);
    expect(row.severity).toBe("critical");
  });

  it("titles ownership takeover differently from a read", () => {
    const row = toFindingRow({
      record: findingRecord({
        endpoint: "PUT /api/orders/5001",
        signals: ["ownership_reassigned", "server_state_changed"],
        delta: [{ field: "owner", before: "user_a", after: "user_b" }],
      }),
      code: findingCode(1),
      actorLabel: "User B",
      ownerLabel: "User A",
    });
    expect(row.code).toBe("WABVE-002");
    expect(row.title).toContain("Ownership");
    expect(row.classification).toBe("BOLA / IDOR");
    expect(row.impact).toContain("transferred ownership");
    expect(row.stateDelta).toEqual([{ field: "owner", before: "user_a", after: "user_b" }]);
  });
});

describe("coverage rollup", () => {
  it("aggregates endpoints, tests and findings", () => {
    const coverage = realCoverage({
      endpoints: [
        { inScope: true, authRequired: true },
        { inScope: false, authRequired: false },
      ],
      tests: [
        { outcome: "fail", category: "authorization", actorKey: "user_b" },
        { outcome: "pass", category: "authorization", actorKey: "user_a" },
        { outcome: "blocked", category: "authorization", actorKey: "user_b" },
        { outcome: "inconclusive", category: "business", actorKey: "user_b" },
      ],
      findings: [{ severity: "critical" }, { severity: "high" }, { severity: "medium" }],
      objects: [{}, {}],
      identities: [1, 2, 3],
      requestBudget: 500,
      requestsUsed: 42,
      blockedOutOfScope: 1,
      dryRun: false,
    });
    expect(coverage.endpointsDiscovered).toBe(2);
    expect(coverage.endpointsInScope).toBe(1);
    expect(coverage.totalTests).toBe(4);
    expect(coverage.failed).toBe(1);
    expect(coverage.blocked).toBe(1);
    expect(coverage.inconclusive).toBe(1);
    expect(coverage.businessLogicTests).toBe(1);
    expect(coverage.findings).toBe(3);
    expect(coverage.critical).toBe(1);
    expect(coverage.high).toBe(1);
    expect(coverage.medium).toBe(1);
    expect(coverage.low).toBe(0);
    expect(coverage.requestsUsed).toBe(42);
    expect(coverage.requestBudget).toBe(500);
    expect(coverage.objectsIdentified).toBe(2);
    expect(coverage.rolesIdentified).toBe(2);
    expect(coverage.dryRun).toBe(false);
  });
});

describe("clipping", () => {
  it("keeps short bodies intact and truncates long ones", () => {
    expect(clip("short")).toBe("short");
    const long = "x".repeat(50_000);
    const clipped = clip(long);
    expect(clipped.length).toBeLessThan(long.length);
    expect(clipped).toContain("[truncated");
  });
});
