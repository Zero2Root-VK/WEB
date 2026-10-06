import { getAuthUserId } from "@convex-dev/auth/server";
import { v } from "convex/values";
import type { MutationCtx } from "./_generated/server";
import { internalMutation, mutation, query } from "./_generated/server";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import * as engine from "./wabve/engine";
import { buildLab } from "./wabve/lab";

const STAGE_DELAY_MS = 620;
const MAX_STAGE = 7;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

async function log(
  ctx: MutationCtx,
  engagementId: Id<"engagements">,
  level: string,
  phase: string,
  message: string,
) {
  await ctx.db.insert("events", {
    engagementId,
    ts: Date.now(),
    level,
    phase,
    message,
  });
}

async function clearRun(ctx: MutationCtx, engagementId: Id<"engagements">) {
  for (const row of await ctx.db
    .query("tests")
    .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
    .collect()) {
    await ctx.db.delete(row._id);
  }
  for (const row of await ctx.db
    .query("findings")
    .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
    .collect()) {
    await ctx.db.delete(row._id);
  }
  for (const row of await ctx.db
    .query("events")
    .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
    .collect()) {
    await ctx.db.delete(row._id);
  }
  for (const row of await ctx.db
    .query("endpoints")
    .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
    .collect()) {
    await ctx.db.delete(row._id);
  }
  for (const row of await ctx.db
    .query("objects")
    .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
    .collect()) {
    await ctx.db.delete(row._id);
  }
}

async function scheduleStage(
  ctx: MutationCtx,
  engagementId: Id<"engagements">,
  stage: number,
  runId: string,
) {
  // The run token lets a restarted engagement invalidate any in-flight stage
  // chain, so two overlapping runs can never write the same evidence twice.
  await ctx.scheduler.runAfter(STAGE_DELAY_MS, internal.wabve.runStage, {
    engagementId,
    stage,
    runId,
  });
}

/* ------------------------------------------------------------------ */
/* queries                                                             */
/* ------------------------------------------------------------------ */

export const listEngagements = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    return await ctx.db
      .query("engagements")
      .withIndex("by_owner", (q) => q.eq("ownerId", userId))
      .collect();
  },
});

export const listIdentities = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    return await ctx.db
      .query("identities")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const listEndpoints = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    return await ctx.db
      .query("endpoints")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const listObjects = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    return await ctx.db
      .query("objects")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const listTests = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    return await ctx.db
      .query("tests")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const listFindings = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    return findings.sort((a, b) => a.code.localeCompare(b.code));
  },
});

export const listEvents = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    const events = await ctx.db
      .query("events")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    return events.sort((a, b) => a.ts - b.ts);
  },
});

/* ------------------------------------------------------------------ */
/* mutations                                                           */
/* ------------------------------------------------------------------ */

export const createEngagement = mutation({
  args: {
    name: v.string(),
    target: v.string(),
    allowedHosts: v.array(v.string()),
    allowedPaths: v.array(v.string()),
    rateLimit: v.number(),
    requestBudget: v.number(),
    destructiveTesting: v.boolean(),
    dryRun: v.boolean(),
    profile: v.string(),
    /** "live" runs the real network engine, "demo" runs the modelled lab. */
    mode: v.optional(v.string()),
    discoverySources: v.optional(v.array(v.string())),
    identities: v.array(
      v.object({
        key: v.string(),
        label: v.string(),
        role: v.string(),
        tenant: v.string(),
        authMethod: v.string(),
        secretHint: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");
    const now = Date.now();
    const engagementId = await ctx.db.insert("engagements", {
      ownerId: userId,
      name: args.name,
      target: args.target,
      allowedHosts: args.allowedHosts,
      allowedPaths: args.allowedPaths,
      rateLimit: args.rateLimit,
      requestBudget: args.requestBudget,
      destructiveTesting: args.destructiveTesting,
      dryRun: args.dryRun,
      killSwitch: false,
      profile: args.profile,
      mode: args.mode ?? "live",
      ...(args.discoverySources ? { discoverySources: args.discoverySources } : {}),
      status: "draft",
      stage: -1,
      requestsUsed: 0,
      blockedOutOfScope: 0,
      createdAt: now,
    });
    for (const identity of args.identities) {
      await ctx.db.insert("identities", {
        engagementId,
        key: identity.key,
        label: identity.label,
        role: identity.role,
        tenant: identity.tenant,
        authMethod: identity.authMethod,
        status: identity.role === "anonymous" ? "unauthenticated" : "pending",
        ...(identity.secretHint ? { secretHint: identity.secretHint } : {}),
      });
    }
    await log(ctx, engagementId, "INFO", "engagement", `Engagement "${args.name}" created for ${args.target}`);
    await log(ctx, engagementId, "INFO", "scope", `Scope: hosts=${args.allowedHosts.join(", ") || "none"} paths=${args.allowedPaths.join(", ") || "any"}`);
    return engagementId;
  },
});

export const startEngagement = mutation({
  args: { engagementId: v.id("engagements"), destructiveTesting: v.optional(v.boolean()) },
  handler: async (ctx, { engagementId, destructiveTesting }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) throw new Error("Not found");

    await clearRun(ctx, engagementId);
    const runId = String(Date.now());
    await ctx.db.patch(engagementId, {
      status: "running",
      stage: 0,
      runId,
      killSwitch: false,
      requestsUsed: 0,
      blockedOutOfScope: 0,
      coverage: undefined,
      finishedAt: undefined,
      ...(destructiveTesting !== undefined ? { destructiveTesting } : {}),
    });
    await log(ctx, engagementId, "INFO", "engine", "Verification engine started");

    // Demo engagements run the modelled lab in-process; live engagements are
    // handed to the Node runner, which performs real, scope-guarded requests.
    if ((engagement.mode ?? "live") === "demo") {
      await log(
        ctx,
        engagementId,
        "INFO",
        "engine",
        "Demo mode: modelled target — no outbound network traffic",
      );
      await scheduleStage(ctx, engagementId, 0, runId);
      return;
    }
    await log(ctx, engagementId, "INFO", "engine", "Live mode: outbound requests stay inside the declared allowlist");
    await ctx.scheduler.runAfter(0, internal.runner.discover, { engagementId, runId });
  },
});

export const setKillSwitch = mutation({
  args: { engagementId: v.id("engagements"), value: v.boolean() },
  handler: async (ctx, { engagementId, value }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) throw new Error("Not found");
    await ctx.db.patch(engagementId, { killSwitch: value });
    await log(
      ctx,
      engagementId,
      value ? "WARN" : "INFO",
      "safety",
      value ? "KILL SWITCH ENGAGED — halting pipeline" : "Kill switch released",
    );
  },
});

export const deleteEngagement = mutation({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) throw new Error("Not found");
    await clearRun(ctx, engagementId);
    for (const identity of await ctx.db
      .query("identities")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect()) {
      await ctx.db.delete(identity._id);
    }
    for (const row of await ctx.db
      .query("identityCredentials")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect()) {
      await ctx.db.delete(row._id);
    }
    await ctx.db.delete(engagementId);
  },
});

/**
 * Persists an already-encrypted credential. This deliberately does not touch
 * key material: encryption happens in the Node action, so the ciphertext is
 * all this default-runtime mutation ever sees.
 */
export const storeIdentityCredential = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    identityKey: v.string(),
    authType: v.string(),
    ciphertext: v.string(),
    mask: v.string(),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("identityCredentials")
      .withIndex("by_identity", (q) =>
        q.eq("engagementId", args.engagementId).eq("identityKey", args.identityKey),
      )
      .collect();
    const now = Date.now();
    for (const row of existing) {
      await ctx.db.patch(row._id, {
        authType: args.authType,
        ciphertext: args.ciphertext,
        mask: args.mask,
        updatedAt: now,
      });
    }
    if (existing.length === 0) {
      await ctx.db.insert("identityCredentials", {
        engagementId: args.engagementId,
        identityKey: args.identityKey,
        authType: args.authType,
        ciphertext: args.ciphertext,
        mask: args.mask,
        updatedAt: now,
      });
    }
  },
});

/* ------------------------------------------------------------------ */
/* the pipeline — one stage per scheduled tick so the console streams  */
/* ------------------------------------------------------------------ */

export const runStage = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    stage: v.number(),
    runId: v.string(),
  },
  handler: async (ctx, { engagementId, stage, runId }) => {
    const engagement = await ctx.db.get(engagementId);
    if (!engagement) return;

    // A newer run has taken over — stop this stale chain.
    if (engagement.runId !== runId) return;

    if (engagement.killSwitch) {
      await ctx.db.patch(engagementId, { status: "halted", finishedAt: Date.now() });
      await log(ctx, engagementId, "WARN", "safety", "Pipeline halted by kill switch");
      return;
    }
    if (engagement.status !== "running") return;

    const scope: engine.ScopeConfig = {
      target: engagement.target,
      allowedHosts: engagement.allowedHosts,
      allowedPaths: engagement.allowedPaths,
      rateLimit: engagement.rateLimit,
      requestBudget: engagement.requestBudget,
      destructiveTesting: engagement.destructiveTesting,
      dryRun: engagement.dryRun,
      profile: engagement.profile,
    };

    await ctx.db.patch(engagementId, { stage });

    if (stage === 0) {
      await log(ctx, engagementId, "INFO", "scope", `Scope guard armed — allowlist ${scope.allowedPaths.join(", ") || "(any path)"}, ${scope.rateLimit} req/s, budget ${scope.requestBudget}`);
      await log(ctx, engagementId, "INFO", "scope", engagement.dryRun ? "Dry-run mode: state mutations are simulated" : "Live mode: state mutations are exercised");
      if (!scope.destructiveTesting) {
        await log(ctx, engagementId, "WARN", "safety", "Destructive testing not approved — destructive probes will be blocked");
      }
    }

    if (stage === 1) {
      const lab = buildLab();
      const endpoints = engine.discover(scope, lab);
      for (const ep of endpoints) {
        await ctx.db.insert("endpoints", { engagementId, ...ep });
      }
      const outOfScope = endpoints.filter((e) => !e.inScope);
      await log(ctx, engagementId, "INFO", "discovery", `Discovered ${endpoints.length} endpoints across ${new Set(endpoints.map((e) => e.category)).size} test classes`);
      await log(ctx, engagementId, "INFO", "discovery", `OpenAPI ${endpoints.filter((e) => e.discoveredVia === "openapi").length} · browser ${endpoints.filter((e) => e.discoveredVia === "browser").length} · forced-browsing ${endpoints.filter((e) => e.discoveredVia === "forced-browsing").length}`);
      for (const ep of outOfScope.slice(0, 3)) {
        await log(ctx, engagementId, "VERIFY", "discovery", `Endpoint ${ep.path} registered but outside the declared scope`);
      }
    }

    if (stage === 2) {
      const identities = await ctx.db
        .query("identities")
        .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
        .collect();
      for (const identity of identities) {
        await ctx.db.patch(identity._id, {
          status: identity.role === "anonymous" ? "unauthenticated" : "authenticated",
          lastVerifiedAt: Date.now(),
        });
        await log(
          ctx,
          engagementId,
          "INFO",
          "identity",
          `${identity.label} [${identity.role}/${identity.tenant}] session verified via ${identity.authMethod}`,
        );
      }
    }

    if (stage === 3) {
      const lab = buildLab();
      const objects = engine.identifyObjects(lab);
      for (const object of objects) {
        await ctx.db.insert("objects", { engagementId, ...object });
      }
      const byType = new Map<string, number>();
      for (const obj of objects) byType.set(obj.type, (byType.get(obj.type) ?? 0) + 1);
      await log(ctx, engagementId, "INFO", "model", `Application model built — ${objects.length} objects across ${byType.size} entity types`);
      await log(ctx, engagementId, "INFO", "model", `Entities: ${Array.from(byType.entries()).map(([t, n]) => `${t}×${n}`).join(", ")}`);
      for (const object of objects.slice(0, 6)) {
        await log(
          ctx,
          engagementId,
          "INFO",
          "model",
          `Object ${object.key} — owner ${object.ownerLabel ?? "unowned"}, tenant ${object.tenant}, classification ${object.classification}`,
        );
      }
      await log(ctx, engagementId, "INFO", "model", `Roles inferred: ${Array.from(new Set(lab.actors.map((a) => a.role))).join(", ")}`);
    }

    if (stage === 4) {
      const probes = engine.planProbes(scope);
      const categoryByKey = new Map(buildLab().endpoints.map((e) => [e.key, e.category]));
      const categories = new Map<string, number>();
      for (const p of probes) {
        const cat = categoryByKey.get(p.endpointKey) ?? "authorization";
        categories.set(cat, (categories.get(cat) ?? 0) + 1);
      }
      await log(ctx, engagementId, "INFO", "matrix", `Authorization test matrix generated — ${probes.length} probes`);
      for (const [cat, count] of categories) {
        await log(ctx, engagementId, "INFO", "matrix", `  ${cat}: ${count} probe(s)`);
      }
    }

    if (stage === 5) {
      const probes = engine.planProbes(scope);
      const tests = engine.execute(scope, probes);
      const now = Date.now();
      for (const test of tests) {
        await ctx.db.insert("tests", { engagementId, ...test, createdAt: now });
      }
      const failed = tests.filter((t) => t.outcome === "fail");
      const blocked = tests.filter((t) => t.outcome === "blocked");
      await log(ctx, engagementId, "INFO", "execution", `Executed ${tests.length} probes — ${tests.filter((t) => t.outcome === "pass").length} passed, ${failed.length} violated, ${blocked.length} blocked`);
      for (const t of tests.filter((x) => x.category === "authorization").slice(0, 4)) {
        await log(ctx, engagementId, "TEST", "execution", `${t.actorLabel} → ${t.method} ${t.path}`);
      }
      for (const t of failed.slice(0, 8)) {
        await log(ctx, engagementId, "VERIFY", "verification", `Differential mismatch on ${t.method} ${t.path} — target ALLOW, reference DENY`);
      }
      for (const t of blocked) {
        await log(ctx, engagementId, "WARN", "safety", `Blocked ${t.method} ${t.path} (${t.signals[0]})`);
      }
      await ctx.db.patch(engagementId, {
        requestsUsed: tests.filter((t) => t.outcome !== "blocked").length,
        blockedOutOfScope: tests.filter((t) => t.outcome === "blocked").length,
      });
    }

    if (stage === 6) {
      const stored = await ctx.db
        .query("tests")
        .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
        .collect();
      const tests = stored as unknown as engine.TestRow[];
      const probes = engine.planProbes(scope);
      const index = new Map<string, engine.Probe>();
      for (const p of probes) index.set(engine.probeKey(p), p);
      const findings = engine.confirm(tests, index);
      const now = Date.now();
      for (const finding of findings) {
        await ctx.db.insert("findings", { engagementId, ...finding, createdAt: now });
      }
      for (const finding of findings.slice(0, 10)) {
        await log(
          ctx,
          engagementId,
          "CONFIRMED",
          "findings",
          `${finding.code} ${finding.title} — ${finding.severity.toUpperCase()} (${finding.confidence}/${finding.score})`,
        );
      }
      await log(ctx, engagementId, "INFO", "findings", `${findings.length} finding(s) confirmed from differential evidence`);
    }

    if (stage >= MAX_STAGE) {
      const endpoints = await ctx.db
        .query("endpoints")
        .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
        .collect();
      const tests = await ctx.db
        .query("tests")
        .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
        .collect();
      const findings = await ctx.db
        .query("findings")
        .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
        .collect();
      const objects = await ctx.db
        .query("objects")
        .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
        .collect();
      const coverage = engine.buildCoverage(
        endpoints as engine.EndpointRow[],
        tests as engine.TestRow[],
        findings,
        scope,
        objects,
      );
      await ctx.db.patch(engagementId, {
        status: "complete",
        stage: MAX_STAGE,
        finishedAt: Date.now(),
        coverage,
      });
      await log(ctx, engagementId, "INFO", "report", `Coverage: ${coverage.totalTests} probes, ${coverage.failed} violations, ${coverage.findings} findings (${coverage.critical} critical / ${coverage.high} high / ${coverage.medium} medium)`);
      await log(ctx, engagementId, "INFO", "report", "Report artefacts ready: HTML, PDF, JSON, Markdown, SARIF, CSV");
      return;
    }

    await scheduleStage(ctx, engagementId, stage + 1, runId);
  },
});
