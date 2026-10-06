import { getAuthUserId } from "@convex-dev/auth/server";
import { v } from "convex/values";
import { internal } from "./_generated/api";
import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import {
  extractFromJs,
  mergeEndpoints,
  parseForms,
  parseHar,
  parseHtml,
  parseOpenApi,
  type DiscoveredEndpoint,
} from "./real/discovery";

/**
 * The data plane between the Node runner and the database.
 *
 * A Convex action cannot touch `ctx.db`, so every read the runner performs and
 * every row it writes goes through these internal functions. They are
 * `internal.*`, which means no browser client can call them: the credential
 * ciphertexts below are only ever readable by server code.
 */

/* ------------------------------------------------------------------ */
/* validators — mirror the schema exactly                              */
/* ------------------------------------------------------------------ */

const endpointRow = v.object({
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
});

const objectRow = v.object({
  key: v.string(),
  type: v.string(),
  ref: v.string(),
  label: v.string(),
  owner: v.optional(v.string()),
  ownerLabel: v.optional(v.string()),
  tenant: v.string(),
  classification: v.string(),
});

const testRow = v.object({
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
});

const findingRow = v.object({
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
});



/* ------------------------------------------------------------------ */
/* reads for the runner                                                */
/* ------------------------------------------------------------------ */

export const getRunContext = internalQuery({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const engagement = await ctx.db.get(engagementId);
    if (!engagement) return null;
    const identities = await ctx.db
      .query("identities")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    const credentials = await ctx.db
      .query("identityCredentials")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    const artifacts = await ctx.db
      .query("artifacts")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    return {
      engagement,
      identities: identities.map((i) => ({
        key: i.key,
        label: i.label,
        role: i.role,
        tenant: i.tenant,
        authMethod: i.authMethod,
        status: i.status,
      })),
      credentials: credentials.map((c) => ({
        identityKey: c.identityKey,
        authType: c.authType,
        ciphertext: c.ciphertext,
        mask: c.mask,
      })),
      artifactEndpoints: artifacts.flatMap((a) =>
        a.endpoints.map((e) => ({
          method: e.method,
          path: e.path,
          parameters: e.parameters,
          source: e.source,
        })),
      ),
    };
  },
});

/** Lightweight state read — the runner calls this between probes so a kill
 * switch or a budget change takes effect without waiting for the next stage. */
export const getRunState = internalQuery({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const engagement = await ctx.db.get(engagementId);
    if (!engagement) return null;
    return {
      status: engagement.status,
      runId: engagement.runId ?? "",
      killSwitch: engagement.killSwitch,
      requestsUsed: engagement.requestsUsed,
      requestBudget: engagement.requestBudget,
      blockedOutOfScope: engagement.blockedOutOfScope,
      dryRun: engagement.dryRun,
      mode: engagement.mode ?? "live",
    };
  },
});

export const getEndpoints = internalQuery({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    return await ctx.db
      .query("endpoints")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const getObjects = internalQuery({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    return await ctx.db
      .query("objects")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const getTests = internalQuery({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    return await ctx.db
      .query("tests")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

export const getFindings = internalQuery({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    return await ctx.db
      .query("findings")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
  },
});

/* ------------------------------------------------------------------ */
/* writes for the runner                                               */
/* ------------------------------------------------------------------ */

export const saveEndpoints = internalMutation({
  args: { engagementId: v.id("engagements"), endpoints: v.array(endpointRow) },
  handler: async (ctx, { engagementId, endpoints }) => {
    const existing = await ctx.db
      .query("endpoints")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    for (const row of existing) await ctx.db.delete(row._id);
    for (const endpoint of endpoints) {
      await ctx.db.insert("endpoints", { engagementId, ...endpoint });
    }
  },
});

export const saveObjects = internalMutation({
  args: { engagementId: v.id("engagements"), objects: v.array(objectRow) },
  handler: async (ctx, { engagementId, objects }) => {
    const existing = await ctx.db
      .query("objects")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    for (const row of existing) await ctx.db.delete(row._id);
    for (const object of objects) {
      await ctx.db.insert("objects", { engagementId, ...object });
    }
  },
});

export const saveTests = internalMutation({
  args: { engagementId: v.id("engagements"), tests: v.array(testRow) },
  handler: async (ctx, { engagementId, tests }) => {
    const now = Date.now();
    for (const test of tests) {
      await ctx.db.insert("tests", { engagementId, ...test, createdAt: now });
    }
  },
});

export const saveFindings = internalMutation({
  args: { engagementId: v.id("engagements"), findings: v.array(findingRow) },
  handler: async (ctx, { engagementId, findings }) => {
    const now = Date.now();
    for (const finding of findings) {
      await ctx.db.insert("findings", { engagementId, ...finding, createdAt: now });
    }
  },
});

export const logEvents = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    events: v.array(
      v.object({
        level: v.string(),
        phase: v.string(),
        message: v.string(),
        ts: v.optional(v.number()),
      }),
    ),
  },
  handler: async (ctx, { engagementId, events }) => {
    const now = Date.now();
    for (const event of events) {
      await ctx.db.insert("events", {
        engagementId,
        ts: event.ts ?? now,
        level: event.level,
        phase: event.phase,
        message: event.message,
      });
    }
  },
});

export const updateRunProgress = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    runId: v.string(),
    stage: v.optional(v.number()),
    status: v.optional(v.string()),
    requestsUsed: v.optional(v.number()),
    blockedOutOfScope: v.optional(v.number()),
    finishedAt: v.optional(v.number()),
    coverage: v.optional(v.any()),
  },
  handler: async (ctx, args) => {
    const engagement = await ctx.db.get(args.engagementId);
    if (!engagement || engagement.runId !== args.runId) return;
    await ctx.db.patch(args.engagementId, {
      ...(args.stage !== undefined ? { stage: args.stage } : {}),
      ...(args.status !== undefined ? { status: args.status } : {}),
      ...(args.requestsUsed !== undefined ? { requestsUsed: args.requestsUsed } : {}),
      ...(args.blockedOutOfScope !== undefined
        ? { blockedOutOfScope: args.blockedOutOfScope }
        : {}),
      ...(args.finishedAt !== undefined ? { finishedAt: args.finishedAt } : {}),
      ...(args.coverage !== undefined ? { coverage: args.coverage } : {}),
    });
  },
});

export const setIdentityStatuses = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    statuses: v.array(
      v.object({
        key: v.string(),
        status: v.string(),
        lastVerifiedAt: v.optional(v.number()),
      }),
    ),
  },
  handler: async (ctx, { engagementId, statuses }) => {
    const identities = await ctx.db
      .query("identities")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    const byKey = new Map(statuses.map((s) => [s.key, s]));
    for (const identity of identities) {
      const update = byKey.get(identity.key);
      if (!update) continue;
      await ctx.db.patch(identity._id, {
        status: update.status,
        lastVerifiedAt: update.lastVerifiedAt ?? Date.now(),
      });
    }
  },
});

/**
 * Final bookkeeping: findings are re-numbered in severity order so report
 * codes match the way the report is read, then the engagement is closed.
 */
export const finalizeRun = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    runId: v.string(),
    stage: v.number(),
    status: v.string(),
    finishedAt: v.number(),
    coverage: v.any(),
  },
  handler: async (ctx, args) => {
    const engagement = await ctx.db.get(args.engagementId);
    if (!engagement || engagement.runId !== args.runId) return;

    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_engagement", (q) => q.eq("engagementId", args.engagementId))
      .collect();
    findings.sort((a, b) => {
      const severity = (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
      if (severity !== 0) return severity;
      if (b.score !== a.score) return b.score - a.score;
      return a.endpoint.localeCompare(b.endpoint);
    });
    for (let i = 0; i < findings.length; i += 1) {
      const code = `WABVE-${String(i + 1).padStart(3, "0")}`;
      if (findings[i].code !== code) await ctx.db.patch(findings[i]._id, { code });
    }

    await ctx.db.patch(args.engagementId, {
      status: args.status,
      stage: args.stage,
      finishedAt: args.finishedAt,
      coverage: args.coverage,
    });
  },
});

/* ------------------------------------------------------------------ */
/* public: artifact import                                             */
/* ------------------------------------------------------------------ */

export const importArtifact = mutation({
  args: {
    engagementId: v.id("engagements"),
    kind: v.string(),
    name: v.string(),
    baseUrl: v.optional(v.string()),
    content: v.string(),
  },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");
    const engagement = await ctx.db.get(args.engagementId);
    if (!engagement || engagement.ownerId !== userId) throw new Error("Not found");
    if (args.content.length === 0) throw new Error("Nothing to import");
    if (args.content.length > 1_000_000) {
      throw new Error("Import is too large (1 MB limit). Split the capture first.");
    }

    let discovered: DiscoveredEndpoint[] = [];
    const kind = args.kind;
    if (kind === "openapi" || kind === "har") {
      let parsed: unknown;
      try {
        parsed = JSON.parse(args.content);
      } catch {
        throw new Error(
          kind === "openapi"
            ? "That is not valid JSON. Export the OpenAPI document as JSON (not YAML)."
            : "That is not valid JSON. Export the capture as a .har file.",
        );
      }
      discovered = kind === "openapi" ? parseOpenApi(parsed) : parseHar(parsed);
    } else if (kind === "js") {
      discovered = extractFromJs(args.content, args.baseUrl ?? engagement.target);
    } else if (kind === "html") {
      const base = args.baseUrl ?? engagement.target;
      discovered = [...parseHtml(args.content, base), ...parseForms(args.content, base)];
    } else if (kind === "manual") {
      discovered = args.content
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [method, ...rest] = line.split(/\s+/);
          const path = rest.join(" ");
          if (!path.startsWith("/")) {
            throw new Error(`Manual endpoint must look like "GET /path" — got: ${line}`);
          }
          return {
            method: (method ?? "GET").toUpperCase(),
            path,
            source: "manual" as const,
            parameters: [],
          };
        });
    } else {
      throw new Error(`Unsupported import kind: ${kind}`);
    }

    const merged = mergeEndpoints(discovered).slice(0, 2000);
    if (merged.length === 0) {
      throw new Error("No endpoints could be parsed from that artefact.");
    }

    await ctx.db.insert("artifacts", {
      engagementId: args.engagementId,
      kind,
      name: args.name.trim() || kind,
      ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
      endpoints: merged.map((endpoint) => ({
        method: endpoint.method,
        path: endpoint.path,
        parameters: endpoint.parameters,
        source: endpoint.source,
      })),
      createdAt: Date.now(),
    });
    return { count: merged.length };
  },
});

export const listArtifacts = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    const artifacts = await ctx.db
      .query("artifacts")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    return artifacts
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((a) => ({
        _id: a._id,
        kind: a.kind,
        name: a.name,
        endpointCount: a.endpoints.length,
        createdAt: a.createdAt,
      }));
  },
});

export const deleteArtifact = mutation({
  args: { artifactId: v.id("artifacts") },
  handler: async (ctx, { artifactId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");
    const artifact = await ctx.db.get(artifactId);
    if (!artifact) throw new Error("Not found");
    const engagement = await ctx.db.get(artifact.engagementId);
    if (!engagement || engagement.ownerId !== userId) throw new Error("Not found");
    await ctx.db.delete(artifactId);
  },
});

/* ------------------------------------------------------------------ */
/* public: credential masks (never the ciphertext)                     */
/* ------------------------------------------------------------------ */

export const listCredentialMasks = query({
  args: { engagementId: v.id("engagements") },
  handler: async (ctx, { engagementId }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const engagement = await ctx.db.get(engagementId);
    if (!engagement || engagement.ownerId !== userId) return [];
    const credentials = await ctx.db
      .query("identityCredentials")
      .withIndex("by_engagement", (q) => q.eq("engagementId", engagementId))
      .collect();
    return credentials.map((c) => ({
      identityKey: c.identityKey,
      authType: c.authType,
      mask: c.mask,
      updatedAt: c.updatedAt,
    }));
  },
});

/** Convenience for the runner: schedule the next stage of a live run. */
export const scheduleRunnerStage = internalMutation({
  args: {
    engagementId: v.id("engagements"),
    runId: v.string(),
    stage: v.union(v.literal("discover"), v.literal("model"), v.literal("probe"), v.literal("report")),
    delayMs: v.number(),
    chunk: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const engagement = await ctx.db.get(args.engagementId);
    if (!engagement || engagement.runId !== args.runId || engagement.status !== "running") return;
    if (args.stage === "probe") {
      await ctx.scheduler.runAfter(args.delayMs, internal.runner.probe, {
        engagementId: args.engagementId,
        runId: args.runId,
        chunk: args.chunk ?? 0,
      });
    } else if (args.stage === "model") {
      await ctx.scheduler.runAfter(args.delayMs, internal.runner.model, {
        engagementId: args.engagementId,
        runId: args.runId,
      });
    } else if (args.stage === "report") {
      await ctx.scheduler.runAfter(args.delayMs, internal.runner.report, {
        engagementId: args.engagementId,
        runId: args.runId,
      });
    } else {
      await ctx.scheduler.runAfter(args.delayMs, internal.runner.discover, {
        engagementId: args.engagementId,
        runId: args.runId,
      });
    }
  },
});
