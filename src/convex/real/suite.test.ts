import { describe, expect, it } from "bun:test";
import type { RealIdentity } from "./executor";
import {
  executeSuite,
  guessType,
  indexObjects,
  planProbes,
  type EndpointSpec,
  type ObservedObject,
} from "./suite";

const userA: RealIdentity = {
  key: "user_a",
  label: "User A",
  role: "standard",
  authType: "bearer",
  secret: "secret-a",
};
const userB: RealIdentity = {
  key: "user_b",
  label: "User B",
  role: "standard",
  authType: "bearer",
  secret: "secret-b",
};
const anonymous: RealIdentity = {
  key: "anon",
  label: "Unauthenticated",
  role: "anonymous",
  authType: "none",
};

const identities = [userA, userB, anonymous];
const byKey = new Map(identities.map((i) => [i.key, i]));

const orderRead: EndpointSpec = {
  key: "order.read",
  method: "GET",
  path: "/api/orders/{order_id}",
  parameters: ["order_id"],
  requiresAuth: true,
  source: "openapi",
};

const orderUpdate: EndpointSpec = {
  key: "order.update",
  method: "PUT",
  path: "/api/orders/{order_id}",
  parameters: ["order_id"],
  requiresAuth: true,
  source: "openapi",
};

const orderObject: ObservedObject = {
  ref: "5001",
  type: "order",
  ownerKey: "user_a",
  tenant: "tenant-a",
  source: "/api/orders",
};

const ownerTenant = (key: string) => (key === "user_a" ? "tenant-a" : "tenant-b");

describe("resource type inference", () => {
  it("reads the resource from a templated path", () => {
    expect(guessType("/api/orders/{order_id}")).toBe("order");
  });

  it("reads the resource from a concrete path", () => {
    expect(guessType("/api/orders/5001")).toBe("order");
    expect(guessType("/api/invoices/1001")).toBe("invoice");
  });

  it("skips api and version prefixes", () => {
    expect(guessType("/api/v1/users")).toBe("user");
  });
});

describe("object indexing", () => {
  it("indexes objects returned by their owner", () => {
    const objects = indexObjects([
      {
        identityKey: "user_a",
        path: "/api/orders",
        body: '{"items":[{"id":5001,"owner":"user_a","tenant_id":"tenant-a"}]}',
      },
    ]);
    expect(objects).toHaveLength(1);
    expect(objects[0]).toMatchObject({
      ref: "5001",
      type: "order",
      ownerKey: "user_a",
      tenant: "tenant-a",
    });
  });

  it("attributes an object to the identity that returned it when no owner is named", () => {
    const objects = indexObjects([
      { identityKey: "user_a", path: "/api/orders", body: '{"items":[{"id":7}]}' },
    ]);
    expect(objects[0].ownerKey).toBe("user_a");
  });

  it("prefers `id` over a foreign key when both match", () => {
    const objects = indexObjects([
      { identityKey: "user_a", path: "/api/orders", body: '{"user_id":"user_a","id":5001}' },
    ]);
    expect(objects[0].ref).toBe("5001");
  });

  it("ignores responses that are not JSON", () => {
    expect(
      indexObjects([{ identityKey: "user_a", path: "/api/orders", body: "<html>nope</html>" }]),
    ).toEqual([]);
  });

  it("de-duplicates an object seen twice", () => {
    const objects = indexObjects([
      { identityKey: "user_a", path: "/api/orders", body: '{"id":5001}' },
      { identityKey: "user_b", path: "/api/orders", body: '{"id":5001}' },
    ]);
    expect(objects).toHaveLength(1);
  });
});

describe("probe planning", () => {
  it("plans one cross-identity probe per non-owner", () => {
    const plans = planProbes({
      endpoints: [orderRead],
      objects: [orderObject],
      identities,
      baseUrl: "https://staging.acme.test",
      tenantOf: ownerTenant,
    });
    expect(plans).toHaveLength(1);
    expect(plans[0].ownerKey).toBe("user_a");
    expect(plans[0].attackerKey).toBe("user_b");
    expect(plans[0].url).toBe("https://staging.acme.test/api/orders/5001");
    expect(plans[0].destructive).toBe(false);
  });

  it("never plans the owner against their own object", () => {
    const plans = planProbes({
      endpoints: [orderRead],
      objects: [orderObject],
      identities,
      baseUrl: "https://t.test",
      tenantOf: ownerTenant,
    });
    expect(plans.every((p) => p.attackerKey !== p.ownerKey)).toBe(true);
  });

  it("excludes unauthenticated identities from authenticated endpoints", () => {
    const plans = planProbes({
      endpoints: [orderRead],
      objects: [orderObject],
      identities,
      baseUrl: "https://t.test",
      tenantOf: ownerTenant,
    });
    expect(plans.some((p) => p.attackerKey === "anon")).toBe(false);
  });

  it("marks DELETE probes destructive", () => {
    const plans = planProbes({
      endpoints: [{ ...orderRead, key: "order.delete", method: "DELETE" }],
      objects: [orderObject],
      identities,
      baseUrl: "https://t.test",
      tenantOf: ownerTenant,
    });
    expect(plans[0].destructive).toBe(true);
  });

  it("explains a cross-tenant rationale", () => {
    const plans = planProbes({
      endpoints: [orderRead],
      objects: [orderObject],
      identities: [userA, userB],
      baseUrl: "https://t.test",
      tenantOf: () => "tenant-b",
    });
    expect(plans[0].rationale).toContain("tenant");
  });

  it("skips endpoints that do not address an object", () => {
    const plans = planProbes({
      endpoints: [{ key: "health", method: "GET", path: "/api/health", parameters: [], requiresAuth: false, source: "manual" }],
      objects: [orderObject],
      identities,
      baseUrl: "https://t.test",
      tenantOf: ownerTenant,
    });
    expect(plans).toEqual([]);
  });
});

describe("suite execution — vulnerable target", () => {
  const objectJson = '{"id":5001,"owner":"User A","amount":4500}';

  it("confirms cross-user read disclosure", async () => {
    const result = await executeSuite({
      plans: planProbes({
        endpoints: [orderRead],
        objects: [orderObject],
        identities,
        baseUrl: "https://t.test",
        tenantOf: ownerTenant,
      }),
      identitiesByKey: byKey,
      transport: async () => ({ status: 200, body: objectJson }),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0].verdict).toBe("confirmed");
    expect(result.tests[0].signals).toContain("protected_record_returned");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].confidence).toBe("High");
    expect(result.requestsUsed).toBe(2);
  });

  it("confirms a write through the owner's post-attack re-read", async () => {
    const result = await executeSuite({
      plans: planProbes({
        endpoints: [orderUpdate],
        objects: [orderObject],
        identities,
        baseUrl: "https://t.test",
        tenantOf: ownerTenant,
      }),
      identitiesByKey: byKey,
      transport: async ({ phase }) => {
        if (phase === "baseline") return { status: 200, body: '{"id":5001,"status":"PAID"}' };
        if (phase === "attack") return { status: 200, body: '{"ok":true}' };
        return { status: 200, body: '{"id":5001,"status":"CANCELLED"}' };
      },
    });

    expect(result.findings).toHaveLength(1);
    expect(result.tests[0].delta).toEqual([
      { field: "status", before: "PAID", after: "CANCELLED" },
    ]);
    expect(result.findings[0].severity).toBe("high");
    // baseline + attack + owner re-read
    expect(result.requestsUsed).toBe(3);
  });
});

describe("suite execution — secure target", () => {
  it("reports nothing when the server denies the attacker", async () => {
    const result = await executeSuite({
      plans: planProbes({
        endpoints: [orderRead],
        objects: [orderObject],
        identities,
        baseUrl: "https://t.test",
        tenantOf: ownerTenant,
      }),
      identitiesByKey: byKey,
      transport: async ({ phase }) =>
        phase === "attack"
          ? { status: 403, body: '{"error":"forbidden"}' }
          : { status: 200, body: '{"id":5001,"owner":"User A"}' },
    });

    expect(result.tests[0].verdict).toBe("not_vulnerable");
    expect(result.findings).toHaveLength(0);
    expect(result.findings).toEqual([]);
  });

  it("does not raise a finding from a 200 with no protected payload", async () => {
    const result = await executeSuite({
      plans: planProbes({
        endpoints: [orderRead],
        objects: [orderObject],
        identities,
        baseUrl: "https://t.test",
        tenantOf: ownerTenant,
      }),
      identitiesByKey: byKey,
      transport: async ({ phase }) =>
        phase === "attack"
          ? { status: 200, body: "{}" }
          : { status: 200, body: '{"id":5001,"owner":"User A","amount":4500}' },
    });

    expect(result.tests[0].verdict).toBe("inconclusive");
    expect(result.findings).toHaveLength(0);
  });

  it("does not raise a finding when the write did not land", async () => {
    const unchanged = '{"id":5001,"status":"PAID"}';
    const result = await executeSuite({
      plans: planProbes({
        endpoints: [orderUpdate],
        objects: [orderObject],
        identities,
        baseUrl: "https://t.test",
        tenantOf: ownerTenant,
      }),
      identitiesByKey: byKey,
      transport: async ({ phase }) =>
        phase === "attack"
          ? { status: 403, body: '{"error":"forbidden"}' }
          : { status: 200, body: unchanged },
    });

    expect(result.findings).toHaveLength(0);
    expect(result.tests[0].delta).toEqual([]);
  });
});

describe("suite execution — control flow", () => {
  const plans = () =>
    planProbes({
      endpoints: [orderRead],
      objects: [orderObject],
      identities,
      baseUrl: "https://t.test",
      tenantOf: ownerTenant,
    });

  it("stops immediately when shouldContinue is false", async () => {
    const result = await executeSuite({
      plans: plans(),
      identitiesByKey: byKey,
      transport: async () => ({ status: 200, body: '{"id":5001}' }),
      shouldContinue: () => false,
    });
    expect(result.tests).toEqual([]);
    expect(result.requestsUsed).toBe(0);
  });

  it("records an error when an identity is missing", async () => {
    const result = await executeSuite({
      plans: plans(),
      identitiesByKey: new Map([["user_b", userB]]),
      transport: async () => ({ status: 200, body: '{"id":5001}' }),
    });
    expect(result.errors).toBe(1);
    expect(result.tests).toEqual([]);
  });

  it("counts a transport failure as an error, not a finding", async () => {
    const result = await executeSuite({
      plans: plans(),
      identitiesByKey: byKey,
      transport: async () => {
        throw new Error("connection refused");
      },
    });
    expect(result.errors).toBe(1);
    expect(result.findings).toHaveLength(0);
  });

  it("counts a refused dispatch as blocked evidence, not as an error", async () => {
    const result = await executeSuite({
      plans: plans(),
      identitiesByKey: byKey,
      transport: async () => {
        throw new Error("blocked:path_not_allowed — /api is outside the allowlist");
      },
    });
    expect(result.blocked).toBe(1);
    expect(result.errors).toBe(0);
    expect(result.tests).toEqual([]);
    expect(result.findings).toHaveLength(0);
  });

  it("awaits an asynchronous shouldContinue between probes", async () => {
    let checks = 0;
    const expected = plans().length;
    const result = await executeSuite({
      plans: plans(),
      identitiesByKey: byKey,
      transport: async () => ({ status: 403, body: '{"error":"forbidden"}' }),
      shouldContinue: async () => {
        checks += 1;
        return true;
      },
    });
    expect(checks).toBe(expected);
    expect(result.tests).toHaveLength(expected);
  });
});
