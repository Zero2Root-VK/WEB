import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { Infer, v } from "convex/values";

// default user roles. can add / remove based on the project as needed
export const ROLES = {
  ADMIN: "admin",
  USER: "user",
  MEMBER: "member",
} as const;

export const roleValidator = v.union(
  v.literal(ROLES.ADMIN),
  v.literal(ROLES.USER),
  v.literal(ROLES.MEMBER),
);
export type Role = Infer<typeof roleValidator>;

const schema = defineSchema(
  {
    // default auth tables using convex auth.
    ...authTables, // do not remove or modify

    // the users table is the default users table that is brought in by the authTables
    users: defineTable({
      name: v.optional(v.string()), // name of the user. do not remove
      image: v.optional(v.string()), // image of the user. do not remove
      email: v.optional(v.string()), // email of the user. do not remove
      emailVerificationTime: v.optional(v.number()), // email verification time. do not remove
      isAnonymous: v.optional(v.boolean()), // is the user anonymous. do not remove

      role: v.optional(roleValidator), // role of the user. do not remove
    }).index("email", ["email"]), // index for the email. do not remove or modify

    // ---------------------------------------------------------------------
    // WABVE — Web Authorization & Business Logic Verification Engine
    // ---------------------------------------------------------------------

    // An engagement is one scoped authorization assessment.
    engagements: defineTable({
      ownerId: v.id("users"),
      name: v.string(),
      target: v.string(),
      allowedHosts: v.array(v.string()),
      allowedPaths: v.array(v.string()),
      rateLimit: v.number(),
      requestBudget: v.number(),
      destructiveTesting: v.boolean(),
      dryRun: v.boolean(),
      killSwitch: v.boolean(),
      profile: v.string(),
      // "live" runs the real network engine; "demo" runs the modelled lab.
      mode: v.optional(v.string()),
      // Discovery channels the operator enabled for live runs.
      discoverySources: v.optional(v.array(v.string())),
      status: v.string(),
      stage: v.number(),
      runId: v.optional(v.string()),
      requestsUsed: v.number(),
      blockedOutOfScope: v.number(),
      coverage: v.optional(v.any()),
      createdAt: v.number(),
      finishedAt: v.optional(v.number()),
    }).index("by_owner", ["ownerId"]),

    // One authenticated (or anonymous) actor used to prove authorization rules.
    identities: defineTable({
      engagementId: v.id("engagements"),
      key: v.string(),
      label: v.string(),
      role: v.string(),
      tenant: v.string(),
      authMethod: v.string(),
      status: v.string(),
      secretHint: v.optional(v.string()),
      lastVerifiedAt: v.optional(v.number()),
    }).index("by_engagement", ["engagementId"]),

    // Unified endpoint registry built by the discovery stage.
    endpoints: defineTable({
      engagementId: v.id("engagements"),
      key: v.string(),
      method: v.string(),
      path: v.string(),
      parameters: v.array(v.string()),
      authRequired: v.boolean(),
      rolesObserved: v.array(v.string()),
      objectType: v.optional(v.string()),
      category: v.string(),
      risk: v.string(),
      discoveredVia: v.string(),
      inScope: v.boolean(),
      summary: v.string(),
    }).index("by_engagement", ["engagementId"]),

    // Encrypted identity credentials. Deliberately has NO query attached — no
    // frontend request can return these documents. Only the execution path
    // reads them, inside a Node action that decrypts in memory.
    identityCredentials: defineTable({
      engagementId: v.id("engagements"),
      identityKey: v.string(),
      authType: v.string(),
      ciphertext: v.string(),
      mask: v.string(),
      updatedAt: v.number(),
    }).index("by_engagement", ["engagementId"])
      .index("by_identity", ["engagementId", "identityKey"]),

    // Resources the application operates on, with the owning identity. Every
    // cross-identity probe is attributed to one of these object identifiers.
    objects: defineTable({
      engagementId: v.id("engagements"),
      key: v.string(),
      type: v.string(),
      ref: v.string(),
      label: v.string(),
      owner: v.optional(v.string()),
      ownerLabel: v.optional(v.string()),
      tenant: v.string(),
      classification: v.string(),
    }).index("by_engagement", ["engagementId"]),

    // One authorization / business-logic probe and its differential verdict.
    tests: defineTable({
      engagementId: v.id("engagements"),
      endpointKey: v.string(),
      method: v.string(),
      path: v.string(),
      category: v.string(),
      probe: v.string(),
      actorKey: v.string(),
      actorLabel: v.string(),
      victimKey: v.optional(v.string()),
      victimLabel: v.optional(v.string()),
      objectRef: v.optional(v.string()),
      parameter: v.optional(v.string()),
      expectation: v.string(),
      actual: v.string(),
      outcome: v.string(),
      risk: v.string(),
      statusCode: v.number(),
      signals: v.array(v.string()),
      confidence: v.number(),
      request: v.string(),
      response: v.string(),
      beforeState: v.optional(v.any()),
      afterState: v.optional(v.any()),
      stateDelta: v.optional(v.any()),
      createdAt: v.number(),
    }).index("by_engagement", ["engagementId"]),

    // A confirmed / likely authorization finding with full evidence.
    findings: defineTable({
      engagementId: v.id("engagements"),
      code: v.string(),
      title: v.string(),
      severity: v.string(),
      confidence: v.string(),
      score: v.number(),
      classification: v.string(),
      cwe: v.string(),
      owasp: v.string(),
      endpoint: v.string(),
      parameter: v.optional(v.string()),
      attacker: v.string(),
      victim: v.optional(v.string()),
      probe: v.string(),
      expected: v.string(),
      actual: v.string(),
      request: v.string(),
      response: v.string(),
      beforeState: v.optional(v.any()),
      afterState: v.optional(v.any()),
      stateDelta: v.optional(v.any()),
      signals: v.array(v.string()),
      reproduction: v.array(v.string()),
      impact: v.string(),
      remediation: v.string(),
      createdAt: v.number(),
    }).index("by_engagement", ["engagementId"]),

    // Imported discovery artefacts (OpenAPI, HAR, JS bundle, HTML, manual).
    // Parsed at import time: only the extracted endpoint registry is stored,
    // never the raw dump, so a customer's API description does not accumulate
    // in our database.
    artifacts: defineTable({
      engagementId: v.id("engagements"),
      kind: v.string(),
      name: v.string(),
      baseUrl: v.optional(v.string()),
      endpoints: v.array(
        v.object({
          method: v.string(),
          path: v.string(),
          parameters: v.array(v.string()),
          source: v.string(),
        }),
      ),
      createdAt: v.number(),
    }).index("by_engagement", ["engagementId"]),

    // Audit log + live console stream.
    events: defineTable({
      engagementId: v.id("engagements"),
      ts: v.number(),
      level: v.string(),
      phase: v.string(),
      message: v.string(),
    }).index("by_engagement", ["engagementId"]),
  },
  {
    // Enforced by the type checker on every insert/patch (the platform runs
    // `tsc -b --noEmit` after every change); runtime validation stays off per
    // the template convention so pre-existing documents remain readable.
    schemaValidation: false,
  },
);

export default schema;
