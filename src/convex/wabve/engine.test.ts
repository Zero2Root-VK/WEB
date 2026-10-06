/**
 * WABVE — demo-mode pipeline.
 *
 * Demo mode runs the modelled lab and had no test coverage at all, even though
 * it is a shipped product surface. These tests assert the invariants the
 * dashboard and the report exporters rely on: referential integrity between
 * probes and endpoints, the "a 200 alone is never a finding" rule, coverage
 * arithmetic, and determinism.
 *
 * They are deliberately written against invariants rather than exact fixture
 * values, so changing the lab does not require rewriting the suite — only a
 * genuine violation fails.
 */

import { describe, expect, test } from "bun:test";

import { buildLab } from "./lab";
import {
  buildCoverage,
  confirm,
  discover,
  execute,
  identifyObjects,
  isInScope,
  owaspFor,
  planProbes,
  probeKey,
  severityFor,
  type ScopeConfig,
} from "./engine";
import { pathAllowed } from "../real/engine";

const scope: ScopeConfig = {
  target: "https://lab.wabve.test",
  allowedHosts: ["lab.wabve.test"],
  allowedPaths: ["/api"],
  rateLimit: 50,
  requestBudget: 500,
  destructiveTesting: false,
  dryRun: false,
  profile: "balanced",
};

const lab = buildLab();
const endpoints = discover(scope, lab);
const objects = identifyObjects(lab);
const probes = planProbes(scope);
const tests = execute(scope, probes);
const probeIndex = new Map(probes.map((p) => [probeKey(p), p]));
const findings = confirm(tests, probeIndex);
const coverage = buildCoverage(endpoints, tests, findings, scope, objects);

describe("scope consistency between run modes", () => {
  test("demo scope uses the same boundary rule as the live guard", () => {
    // A prefix allowlist must not silently permit a lookalike path.
    expect(isInScope(scope, "/api/orders/1001")).toBe(true);
    expect(isInScope(scope, "/apixyz")).toBe(false);
    expect(isInScope({ ...scope, allowedPaths: [] }, "/anything")).toBe(true);
    // Identical to the predicate the live dispatcher uses.
    for (const path of ["/api/orders", "/apixyz", "/admin", "/api"]) {
      expect(isInScope(scope, path)).toBe(pathAllowed(path, scope.allowedPaths));
    }
  });
});

describe("discovery and modelling", () => {
  test("discovers every endpoint with a unique key", () => {
    expect(endpoints.length).toBe(lab.endpoints.length);
    expect(new Set(endpoints.map((e) => e.key)).size).toBe(endpoints.length);
    expect(endpoints.some((e) => e.inScope)).toBe(true);
  });

  test("identifies resources and resolves their owners to a label", () => {
    expect(objects.length).toBe(lab.objects.length);
    expect(new Set(objects.map((o) => o.key)).size).toBe(objects.length);
    const owned = objects.filter((o) => o.owner);
    expect(owned.length).toBeGreaterThan(0);
    for (const object of owned) expect(object.ownerLabel).toBeTruthy();
  });
});

describe("probe planning", () => {
  test("plans probes and every probe references a discovered endpoint", () => {
    expect(probes.length).toBeGreaterThan(0);
    const keys = new Set(endpoints.map((e) => e.key));
    for (const probe of probes) {
      expect(keys).toContain(probe.endpointKey);
      expect(probe.actorKey).toBeTruthy();
    }
  });

  test("probe keys are unique, so evidence can be attributed back", () => {
    const keys = probes.map(probeKey);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("execution", () => {
  test("produces exactly one attributable result per probe", () => {
    expect(tests.length).toBe(probes.length);
    for (const row of tests) {
      expect(row.outcome).toBeTruthy();
      expect(row.actorKey).toBeTruthy();
    }
  });

  test("a failure is never recorded from a status code alone", () => {
    // The PRD's core rule: a 200 without corroborating signals is not a finding.
    for (const row of tests.filter((t) => t.outcome === "fail")) {
      expect(row.signals.length).toBeGreaterThan(0);
      expect(row.confidence).toBeGreaterThan(0);
      expect(row.actual).toBe("ALLOW");
    }
  });

  test("confidence stays within bounds", () => {
    for (const row of tests) {
      expect(row.confidence).toBeGreaterThanOrEqual(0);
      expect(row.confidence).toBeLessThanOrEqual(100);
    }
  });

  test("the same engagement reproduces the same evidence", () => {
    const again = execute(scope, planProbes(scope));
    expect(JSON.stringify(again)).toBe(JSON.stringify(tests));
  });
});

describe("findings", () => {
  test("the deliberately vulnerable lab produces findings", () => {
    expect(findings.length).toBeGreaterThan(0);
  });

  test("every finding is backed by a failing test", () => {
    const failing = new Set(
      tests.filter((t) => t.outcome === "fail").map((t) => `${t.endpointKey}|${t.actorKey}|${t.probe}`),
    );
    expect(findings.length).toBeLessThanOrEqual(failing.size);
    for (const finding of findings) {
      expect(finding.signals.length).toBeGreaterThan(0);
      expect(finding.severity).toBeTruthy();
      expect(finding.cwe).toMatch(/^CWE-\d+$/);
      expect(finding.owasp).toContain("2021");
      expect(finding.reproduction.length).toBeGreaterThan(0);
      expect(finding.remediation.length).toBeGreaterThan(0);
    }
  });

  test("codes are sequential after severity ordering", () => {
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.forEach((finding, index) => {
      expect(finding.code).toBe(`WABVE-${String(index + 1).padStart(3, "0")}`);
      if (index > 0) {
        expect(rank[finding.severity] ?? 9).toBeGreaterThanOrEqual(rank[findings[index - 1]?.severity ?? ""] ?? 9);
      }
    });
  });
});

describe("coverage arithmetic", () => {
  test("outcome buckets account for every test", () => {
    expect(coverage.passed + coverage.failed + coverage.inconclusive + coverage.blocked).toBe(coverage.totalTests);
    expect(coverage.totalTests).toBe(tests.length);
  });

  test("category buckets account for every test", () => {
    expect(coverage.authorizationTests + coverage.businessLogicTests).toBe(coverage.totalTests);
  });

  test("severity buckets account for every finding", () => {
    expect(coverage.critical + coverage.high + coverage.medium + coverage.low).toBe(coverage.findings);
    expect(coverage.findings).toBe(findings.length);
  });

  test("endpoint buckets account for every endpoint", () => {
    expect(coverage.endpointsInScope + coverage.blockedOutOfScope).toBe(coverage.endpointsDiscovered);
    expect(coverage.safetyBlocks).toBe(coverage.blocked);
  });

  test("objects are counted", () => {
    expect(coverage.objectsIdentified).toBe(objects.length);
  });
});

describe("severity and mapping helpers", () => {
  test("privilege and tenant crossings are critical regardless of endpoint risk", () => {
    expect(severityFor("authorization", "medium", ["privilege_boundary_crossed"])).toBe("critical");
    expect(severityFor("authorization", "low", ["tenant_boundary_crossed"])).toBe("critical");
  });

  test("business-logic abuse is not escalated to a data-breach severity", () => {
    expect(severityFor("business", "low", ["server_state_changed"])).toBe("low");
  });

  test("state changes on authorization endpoints escalate", () => {
    expect(severityFor("authorization", "low", ["server_state_changed"])).toBe("medium");
    expect(severityFor("authorization", "high", ["server_state_changed"])).toBe("high");
  });

  test("unknown categories fall back to broken access control", () => {
    expect(owaspFor("nonsense")).toBe("A01:2021 - Broken Access Control");
  });
});
