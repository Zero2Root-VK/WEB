/**
 * WABVE — runner planning primitives.
 *
 * These functions decide what the report says about each endpoint, so they are
 * tested directly rather than only through a live run. The last test is a
 * cross-module one: it proves the runner's `objectTypeFor` names the same
 * resource that the probe planner in `suite.ts` matches on, so an endpoint can
 * never be labelled with an object type that no probe addresses.
 */

import { describe, expect, test } from "bun:test";

import { authorize } from "./engine";
import { planProbes } from "./suite";
import {
  categoryForPath,
  crawlLimit,
  objectTypeFor,
  originOf,
  scopeFrom,
  specLimit,
  type ScopeSource,
} from "./runplan";

const SOURCE: ScopeSource = {
  target: "https://staging.acme.test",
  allowedHosts: ["acme.test"],
  allowedPaths: ["/api"],
  rateLimit: 5,
  requestBudget: 1000,
  killSwitch: false,
  destructiveTesting: false,
  dryRun: false,
};

describe("scopeFrom", () => {
  test("projects an engagement onto the guard's configuration", () => {
    const scope = scopeFrom(SOURCE);
    expect(scope).toEqual({
      target: "https://staging.acme.test",
      allowedHosts: ["acme.test"],
      allowedPaths: ["/api"],
      rateLimit: 5,
      requestBudget: 1000,
      killSwitch: false,
      destructiveTesting: false,
      dryRun: false,
    });
  });

  test("the projected scope really drives the guard", () => {
    const scope = scopeFrom(SOURCE);
    expect(authorize({ scope, url: "https://acme.test/api/orders", method: "GET", requestsUsed: 0 }).allowed).toBe(true);
    expect(authorize({ scope, url: "https://acme.test/admin", method: "GET", requestsUsed: 0 }).allowed).toBe(false);
    expect(authorize({ scope, url: "https://evil.test/api/orders", method: "GET", requestsUsed: 0 }).allowed).toBe(false);
  });
});

describe("originOf", () => {
  test("keeps the origin and discards the path", () => {
    expect(originOf("https://staging.acme.test/api/v1/orders?x=1")).toBe("https://staging.acme.test");
    expect(originOf("http://127.0.0.1:8080/")).toBe("http://127.0.0.1:8080");
  });

  test("refuses anything that is not an http(s) target", () => {
    expect(originOf("ftp://acme.test")).toBeNull();
    expect(originOf("file:///etc/passwd")).toBeNull();
    expect(originOf("not a url")).toBeNull();
    expect(originOf("")).toBeNull();
  });
});

describe("profile budgets", () => {
  test("crawl limits bound the discovery crawl per profile", () => {
    expect(crawlLimit("quick")).toBe(6);
    expect(crawlLimit("balanced")).toBe(15);
    expect(crawlLimit("deep")).toBe(30);
    expect(crawlLimit("unknown")).toBe(15);
  });

  test("spec limits bound how many API documents are probed", () => {
    expect(specLimit("quick")).toBe(2);
    expect(specLimit("balanced")).toBe(5);
    expect(specLimit("deep")).toBe(5);
  });
});

describe("categoryForPath", () => {
  test("classifies administrative surfaces as broken function-level authorization", () => {
    expect(categoryForPath("/admin/users")).toBe("bfla");
    expect(categoryForPath("/backoffice")).toBe("bfla");
    expect(categoryForPath("/internal/debug")).toBe("bfla");
  });

  test("classifies authentication surfaces as session issues", () => {
    expect(categoryForPath("/api/auth/login")).toBe("session");
    expect(categoryForPath("/login")).toBe("session");
    expect(categoryForPath("/api/oauth/token")).toBe("session");
  });

  test("classifies money-moving surfaces as business logic", () => {
    expect(categoryForPath("/api/checkout")).toBe("business");
    expect(categoryForPath("/api/refund/9")).toBe("business");
    expect(categoryForPath("/api/coupon/SUMMER")).toBe("business");
  });

  test("everything else is an authorization endpoint", () => {
    expect(categoryForPath("/api/orders/1001")).toBe("authorization");
    expect(categoryForPath("/api/invoices/{invoice_id}")).toBe("authorization");
    // Only top-level administrative and exact singular terms are classified:
    // a nested `/api/internal` or a plural `/api/payments` stays generic rather
    // than being mislabelled into the wrong OWASP category.
    expect(categoryForPath("/api/internal/report")).toBe("authorization");
    expect(categoryForPath("/api/payments")).toBe("authorization");
  });
});

describe("objectTypeFor", () => {
  test("names the resource addressed by a path parameter", () => {
    expect(objectTypeFor("/api/orders/{order_id}")).toBe("order");
    expect(objectTypeFor("/api/invoices/{invoice_id}")).toBe("invoice");
    expect(objectTypeFor("/api/users/{user_id}/posts/{post_id}")).toBe("user");
  });

  test("returns null when the parameter names nothing", () => {
    expect(objectTypeFor("/api/users/{id}")).toBeNull();
    expect(objectTypeFor("/api/orders")).toBeNull();
    expect(objectTypeFor("/")).toBeNull();
  });

  test("names the same resource the probe planner matches on", () => {
    const path = "/api/orders/{order_id}";
    const objectType = objectTypeFor(path);
    expect(objectType).toBe("order");

    const plans = planProbes({
      endpoints: [
        { key: `GET ${path}`, method: "GET", path, parameters: ["order_id"], requiresAuth: true, source: "openapi" },
      ],
      objects: [{ ref: "2002", type: objectType!, ownerKey: "bob", tenant: "globex", source: "/api/orders" }],
      identities: [
        { key: "alice", label: "Alice", role: "customer", authType: "bearer" },
        { key: "bob", label: "Bob", role: "customer", authType: "bearer" },
      ],
      baseUrl: "https://staging.acme.test",
      tenantOf: () => "globex",
    });

    expect(plans).toHaveLength(1);
    expect(plans[0]?.attackerKey).toBe("alice");
    expect(plans[0]?.url).toBe("https://staging.acme.test/api/orders/2002");
  });
});
