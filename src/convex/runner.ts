"use node";

/**
 * WABVE — live runner.
 *
 * This is the Node-runtime action chain that performs a real assessment:
 * discover → model → probe (chunked) → report. Every outbound request goes
 * through `executor.dispatch`, which applies the scope guard, the rate bucket
 * and the budget before any socket opens. Results are written back through
 * `internal.pipeline.*`; nothing here can be called from a browser.
 */

import { v } from "convex/values";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import type { ActionCtx } from "./_generated/server";
import { internalAction } from "./_generated/server";
import {
  findingCode,
  realCoverage,
  toBlockedTestRow,
  toFindingRow,
  toTestRow,
  type TestRowShape,
} from "./real/reporting";
import { authorize, createBucket, type ScopeConfig } from "./real/engine";
import {
  extractFromJs,
  mergeEndpoints,
  parseForms,
  parseHtml,
  parseOpenApi,
  pathParameters,
  type DiscoveredEndpoint,
} from "./real/discovery";
import { dispatch, fetchDocument, type RateState, type RealIdentity } from "./real/executor";
import {
  categoryForPath,
  crawlLimit,
  objectTypeFor,
  originOf,
  scopeFrom,
  specLimit,
} from "./real/runplan";
import { decryptSecret, requireSecretKey } from "./real/secrets";
import {
  executeSuite,
  indexObjects,
  planProbes,
  type EndpointSpec,
  type ObservedObject,
  type ProbePlan,
  type Transport,
} from "./real/suite";

const DISCOVER_TIMEOUT_MS = 6_000;
const PROBE_TIMEOUT_MS = 8_000;
const CHUNK_PLANS = 4;
const MAX_DOC_BYTES = 2_000_000;
const STAGE_DELAY_MS = 350;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const PUBLIC_PATH = /^\/(?:$|login|signup|register|logout|health|healthz|status|robots\.txt|favicon\.ico)/i;

interface Evt {
  level: string;
  phase: string;
  message: string;
  ts?: number;
}

interface RunArgs {
  engagementId: Id<"engagements">;
  runId: string;
}

type Loaded = NonNullable<Awaited<ReturnType<typeof loadRun>>>;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

async function loadRun(ctx: ActionCtx, args: RunArgs, opts: { lenient?: boolean } = {}) {
  const data = await ctx.runQuery(internal.pipeline.getRunContext, {
    engagementId: args.engagementId,
  });
  if (!data) return null;
  const engagement = data.engagement;
  if ((engagement.mode ?? "live") !== "live") return null;
  if (engagement.runId !== args.runId) return null;
  if (!opts.lenient && engagement.status !== "running") return null;
  return data;
}

function rateStateFor(scope: ScopeConfig): RateState {
  return { bucket: createBucket(scope.rateLimit, Date.now()), rateLimit: scope.rateLimit };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function emit(ctx: ActionCtx, engagementId: Id<"engagements">, events: Evt[]) {
  if (events.length === 0) return;
  await ctx.runMutation(internal.pipeline.logEvents, { engagementId, events });
}

async function setStage(ctx: ActionCtx, args: RunArgs, stage: number) {
  await ctx.runMutation(internal.pipeline.updateRunProgress, {
    engagementId: args.engagementId,
    runId: args.runId,
    stage,
  });
}

/** A crash must never leave an engagement "running" forever. */
async function guard(ctx: ActionCtx, args: RunArgs, body: () => Promise<void>) {
  try {
    await body();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await emit(ctx, args.engagementId, [
      { level: "ERROR", phase: "engine", message: `Run aborted: ${message}` },
    ]).catch(() => undefined);
    await ctx
      .runMutation(internal.pipeline.updateRunProgress, {
        engagementId: args.engagementId,
        runId: args.runId,
        status: "error",
        finishedAt: Date.now(),
      })
      .catch(() => undefined);
  }
}

/**
 * Identities with a decrypted credential, in memory only. Identities that
 * cannot authenticate are skipped with an explicit reason rather than being
 * silently downgraded to anonymous — a silent downgrade would manufacture
 * false positives.
 */
async function loadIdentities(
  ctx: ActionCtx,
  data: Loaded,
): Promise<{ identities: RealIdentity[]; skipped: { key: string; label: string; reason: string }[] }> {
  const labels = new Map(data.identities.map((i) => [i.key, i.label]));
  const identities: RealIdentity[] = [];
  const skipped: { key: string; label: string; reason: string }[] = [];
  let key: CryptoKey | null = null;

  for (const identity of data.identities) {
    const label = labels.get(identity.key) ?? identity.key;
    if (identity.role === "anonymous" || identity.authMethod === "none") {
      identities.push({ key: identity.key, label, role: identity.role, authType: "none" });
      continue;
    }
    const credential = data.credentials.find((c) => c.identityKey === identity.key);
    if (!credential) {
      skipped.push({ key: identity.key, label, reason: "no credential stored" });
      continue;
    }
    if (credential.authType !== "bearer" && credential.authType !== "cookie") {
      skipped.push({
        key: identity.key,
        label,
        reason: `${credential.authType} login flow is not executable — store a bearer token or session cookie`,
      });
      continue;
    }
    if (!key) key = await requireSecretKey(process.env);
    try {
      const secret = await decryptSecret(credential.ciphertext, key);
      identities.push({
        key: identity.key,
        label,
        role: identity.role,
        authType: credential.authType,
        secret,
      });
    } catch {
      skipped.push({
        key: identity.key,
        label,
        reason: "credential could not be decrypted (was WABVE_SECRETS_KEY rotated?)",
      });
    }
  }
  return { identities, skipped };
}

function endpointRowFor(ep: DiscoveredEndpoint, scope: ScopeConfig, base: string) {
  const method = ep.method.toUpperCase();
  const parameters = Array.from(new Set([...ep.parameters, ...pathParameters(ep.path)]));
  const decision = authorize({ scope, url: `${base}${ep.path}`, method, requestsUsed: 0 });
  const category = categoryForPath(ep.path);
  const objectType = objectTypeFor(ep.path);
  return {
    key: `${method} ${ep.path}`,
    method,
    path: ep.path,
    parameters,
    authRequired: !PUBLIC_PATH.test(ep.path),
    rolesObserved: [] as string[],
    ...(objectType ? { objectType } : {}),
    category,
    risk: method === "DELETE" || category === "bfla" ? "high" : "medium",
    discoveredVia: ep.source,
    inScope: decision.allowed,
    summary: decision.allowed
      ? `Discovered via ${ep.source}`
      : `Outside scope: ${decision.detail}`,
  };
}

/* ------------------------------------------------------------------ */
/* stage 1 — discovery                                                 */
/* ------------------------------------------------------------------ */

export const discover = internalAction({
  args: { engagementId: v.id("engagements"), runId: v.string() },
  handler: async (ctx, args) =>
    guard(ctx, args, async () => {
      const data = await loadRun(ctx, args);
      if (!data) return;
      const engagement = data.engagement;
      const scope = scopeFrom(engagement);
      const events: Evt[] = [];
      const base = originOf(scope.target);
      await setStage(ctx, args, 1);

      if (!base) {
        events.push({
          level: "ERROR",
          phase: "scope",
          message: `Target "${scope.target}" is not a valid http(s) URL — cannot start discovery`,
        });
        await emit(ctx, args.engagementId, events);
        await ctx.runMutation(internal.pipeline.updateRunProgress, {
          engagementId: args.engagementId,
          runId: args.runId,
          status: "error",
          finishedAt: Date.now(),
        });
        return;
      }

      events.push({
        level: "INFO",
        phase: "scope",
        message: `Scope guard armed — hosts ${scope.allowedHosts.join(", ") || "(any)"}, paths ${scope.allowedPaths.join(", ") || "(any)"}, ${scope.rateLimit} req/s, budget ${scope.requestBudget}`,
      });
      events.push({
        level: "INFO",
        phase: "scope",
        message: scope.dryRun
          ? "Dry-run: mutating requests are withheld; only read-only probes are dispatched"
          : "Live mode: state-changing probes are dispatched and re-read as evidence",
      });
      if (!scope.destructiveTesting) {
        events.push({
          level: "WARN",
          phase: "safety",
          message: "Destructive testing not approved — DELETE probes are blocked before dispatch",
        });
      }

      const rate = rateStateFor(scope);
      let used = engagement.requestsUsed;
      let blocked = engagement.blockedOutOfScope;
      /**
       * Re-read live run state before every outbound phase: the kill switch
       * and the budget are operator controls and must take effect promptly,
       * not at the next stage boundary.
       */
      const stopRequested = async (): Promise<boolean> => {
        if (scope.killSwitch) return true;
        const live = await ctx.runQuery(internal.pipeline.getRunState, {
          engagementId: args.engagementId,
        });
        if (!live || live.runId !== args.runId || live.status !== "running") return true;
        if (live.killSwitch) return true;
        return used >= live.requestBudget;
      };

      const collected: DiscoveredEndpoint[] = data.artifactEndpoints.map((a) => ({
        method: a.method,
        path: a.path,
        parameters: a.parameters,
        source: a.source as DiscoveredEndpoint["source"],
      }));
      if (collected.length > 0) {
        events.push({
          level: "INFO",
          phase: "discovery",
          message: `${collected.length} endpoint(s) loaded from imported artefact(s)`,
        });
      }

      // Which live channels the operator enabled. An empty list (legacy
      // engagements) keeps every channel on.
      const enabled = engagement.discoverySources ?? [];
      const wants = (key: string) => enabled.length === 0 || enabled.includes(key);
      const liveCrawl = wants("browser") || wants("forced-browsing");
      const specProbing = wants("openapi");
      const passiveJs = wants("passive-js");
      events.push({
        level: "INFO",
        phase: "discovery",
        message: `Discovery channels — crawl ${liveCrawl ? "on" : "off"}, openapi ${specProbing ? "on" : "off"}, passive-js ${passiveJs ? "on" : "off"}`,
      });

      // 1. the landing page, for links and forms
      const root = liveCrawl
        ? await fetchDocument({
            scope,
            url: `${base}/`,
            requestsUsed: used,
            rate,
            timeoutMs: DISCOVER_TIMEOUT_MS,
          })
        : ({ kind: "skipped" } as const);
      if (root.kind === "ok") {
        used += 1;
        const html = root.text.slice(0, MAX_DOC_BYTES);
        const found = [...parseHtml(html, base), ...parseForms(html, base)];
        collected.push(...found);
        events.push({
          level: "INFO",
          phase: "discovery",
          message: `Fetched ${base}/ — ${found.length} candidate link(s) and form(s)`,
        });
      } else if (root.kind === "blocked") {
        blocked += 1;
        events.push({
          level: "WARN",
          phase: "discovery",
          message:
            root.reason === "path_not_allowed"
              ? `Root fetch blocked: ${root.detail}. Crawling needs the site root inside the allowed paths — add "/" (or the app base path), or import an OpenAPI/HAR artefact instead.`
              : `Root fetch blocked by the scope guard: ${root.reason} — ${root.detail}`,
        });
      } else if (root.kind === "error") {
        events.push({
          level: "WARN",
          phase: "discovery",
          message: `Root fetch failed: ${root.message}`,
        });
      }

      // 2. machine-readable API descriptions
      const jsonLinks = collected
        .filter((e) => e.path.endsWith(".json"))
        .map((e) => e.path)
        .slice(0, 3);
      // Spec locations inside the declared path allowlist come first — a
      // scope-guarded target refuses everything outside those prefixes.
      const scopedSpecs = scope.allowedPaths
        .map((raw) => raw.trim())
        .filter((raw) => raw !== "" && raw !== "/")
        .flatMap((raw) => {
          const prefix = raw.endsWith("/") ? raw : `${raw}/`;
          return [`${prefix}openapi.json`, `${prefix}swagger.json`];
        });
      const specCandidates = !specProbing
        ? []
        : Array.from(
            new Set([
              ...scopedSpecs,
              "/openapi.json",
              "/swagger.json",
              "/v3/api-docs",
              "/api-docs",
              "/swagger/v1/swagger.json",
              ...jsonLinks,
            ]),
          ).slice(0, specLimit(engagement.profile) + 5);

      let specsFound = 0;
      for (const path of specCandidates) {
        if ((await stopRequested()) || specsFound >= specLimit(engagement.profile)) break;
        const result = await fetchDocument({
          scope,
          url: `${base}${path}`,
          requestsUsed: used,
          rate,
          timeoutMs: DISCOVER_TIMEOUT_MS,
        });
        if (result.kind === "blocked") {
          blocked += 1;
          continue;
        }
        if (result.kind === "error") continue;
        used += 1;
        try {
          const parsed: unknown = JSON.parse(result.text.slice(0, MAX_DOC_BYTES));
          const endpoints = parseOpenApi(parsed);
          if (endpoints.length > 0) {
            collected.push(...endpoints);
            specsFound += 1;
            events.push({
              level: "INFO",
              phase: "discovery",
              message: `OpenAPI at ${path}: ${endpoints.length} operation(s) registered`,
            });
          }
        } catch {
          // Not JSON or not an API description — normal for most sites.
        }
      }

      // 3. one bounded crawl level over the pages we already know about
      const crawlCandidates = !liveCrawl
        ? []
        : mergeEndpoints(collected)
        .filter((e) => e.source === "html" || e.source === "js")
        .filter((e) => !e.path.endsWith(".json"))
        .slice(0, crawlLimit(engagement.profile));
      let crawled = 0;
      for (const candidate of crawlCandidates) {
        if (await stopRequested()) break;
        const result = await fetchDocument({
          scope,
          url: `${base}${candidate.path}`,
          requestsUsed: used,
          rate,
          timeoutMs: DISCOVER_TIMEOUT_MS,
        });
        if (result.kind === "blocked") {
          blocked += 1;
          continue;
        }
        if (result.kind === "error") continue;
        used += 1;
        crawled += 1;
        const text = result.text.slice(0, MAX_DOC_BYTES);
        if (passiveJs && /\.m?js(?:$|\?)/i.test(candidate.path)) {
          const fromBundle = extractFromJs(text, base);
          collected.push(...fromBundle);
          if (fromBundle.length > 0) {
            events.push({
              level: "INFO",
              phase: "discovery",
              message: `${candidate.path}: ${fromBundle.length} route literal(s) extracted from bundle`,
            });
          }
        } else if (/html/i.test(result.contentType) || text.trimStart().startsWith("<")) {
          collected.push(...parseHtml(text, base), ...parseForms(text, base));
        }
      }
      if (crawled > 0) {
        events.push({
          level: "INFO",
          phase: "discovery",
          message: `Crawled ${crawled} page(s) inside the allowlist`,
        });
      }
      if (await stopRequested()) {
        events.push({
          level: "WARN",
          phase: "safety",
          message: "Discovery stopped early — kill switch engaged or request budget exhausted",
        });
      }

      // 4. persist the registry
      const rows = mergeEndpoints(collected).map((ep) => endpointRowFor(ep, scope, base));
      const inScope = rows.filter((r) => r.inScope).length;
      await ctx.runMutation(internal.pipeline.saveEndpoints, {
        engagementId: args.engagementId,
        endpoints: rows,
      });
      const bySource = new Map<string, number>();
      for (const row of rows) bySource.set(row.discoveredVia, (bySource.get(row.discoveredVia) ?? 0) + 1);
      events.push({
        level: "INFO",
        phase: "discovery",
        message: `${rows.length} endpoint(s) registered — ${inScope} in scope, ${rows.length - inScope} outside the allowlist`,
      });
      events.push({
        level: "INFO",
        phase: "discovery",
        message: Array.from(bySource.entries())
          .map(([source, count]) => `${source} ${count}`)
          .join(" · "),
      });

      await ctx.runMutation(internal.pipeline.updateRunProgress, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: 1,
        requestsUsed: used,
        blockedOutOfScope: blocked,
      });
      await emit(ctx, args.engagementId, events);
      await ctx.runMutation(internal.pipeline.scheduleRunnerStage, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: "model",
        delayMs: STAGE_DELAY_MS,
      });
    }),
});

/* ------------------------------------------------------------------ */
/* stage 2 — identity sessions + application model                     */
/* ------------------------------------------------------------------ */

/**
 * Object ownership only counts when it can be attributed to an identity we
 * hold a credential for. An owner name we cannot map to an identity would
 * make the reference policy a guess, so those objects are dropped (and
 * counted) instead of producing a coin-flip baseline.
 */
function resolveOwners(
  objects: ObservedObject[],
  identities: Array<{ key: string; label: string }>,
): { objects: ObservedObject[]; dropped: number; remapped: number } {
  const byKey = new Map(identities.map((i) => [i.key, i]));
  const byLabel = new Map(identities.map((i) => [i.label.toLowerCase(), i.key]));
  const kept: ObservedObject[] = [];
  let dropped = 0;
  let remapped = 0;
  for (const object of objects) {
    if (byKey.has(object.ownerKey)) {
      kept.push(object);
      continue;
    }
    const mapped = byLabel.get(object.ownerKey.toLowerCase());
    if (mapped) {
      kept.push({ ...object, ownerKey: mapped });
      remapped += 1;
      continue;
    }
    dropped += 1;
  }
  return { objects: kept, dropped, remapped };
}

function collectionScore(path: string): number {
  let score = 0;
  if (/\/api\//i.test(path)) score += 3;
  if (!/\/assets\/|\.\w{2,4}$/i.test(path)) score += 1;
  score -= path.split("/").length / 10;
  return score;
}

export const model = internalAction({
  args: { engagementId: v.id("engagements"), runId: v.string() },
  handler: async (ctx, args) =>
    guard(ctx, args, async () => {
      const data = await loadRun(ctx, args);
      if (!data) return;
      const engagement = data.engagement;
      const scope = scopeFrom(engagement);
      const base = originOf(scope.target);
      const events: Evt[] = [];
      await setStage(ctx, args, 2);
      if (!base) return;

      let identities: RealIdentity[] = [];
      let skipped: { key: string; label: string; reason: string }[] = [];
      try {
        ({ identities, skipped } = await loadIdentities(ctx, data));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        events.push({
          level: "ERROR",
          phase: "identity",
          message: `Cannot start identity manager: ${message}`,
        });
        await emit(ctx, args.engagementId, events);
        await ctx.runMutation(internal.pipeline.updateRunProgress, {
          engagementId: args.engagementId,
          runId: args.runId,
          status: "error",
          finishedAt: Date.now(),
        });
        return;
      }
      for (const entry of skipped) {
        events.push({
          level: "WARN",
          phase: "identity",
          message: `${entry.label} skipped: ${entry.reason}`,
        });
      }

      const endpoints = await ctx.runQuery(internal.pipeline.getEndpoints, {
        engagementId: args.engagementId,
      });
      const collections = endpoints
        .filter(
          (e) =>
            e.inScope &&
            e.method === "GET" &&
            !e.path.includes("{") &&
            PUBLIC_PATH.test(e.path) === false,
        )
        .sort((a, b) => collectionScore(b.path) - collectionScore(a.path))
        .slice(0, engagement.profile === "quick" ? 4 : engagement.profile === "deep" ? 12 : 8);

      const rate = rateStateFor(scope);
      let used = engagement.requestsUsed;
      let blocked = engagement.blockedOutOfScope;
      const responses: Array<{ identityKey: string; path: string; body: string }> = [];
      const statuses = new Map<string, string>();

      for (const identity of identities) {
        if (identity.authType === "none") {
          statuses.set(identity.key, "unauthenticated");
          continue;
        }
        let ok = 0;
        let unauthorised = 0;
        for (const endpoint of collections) {
          const live = await ctx.runQuery(internal.pipeline.getRunState, {
            engagementId: args.engagementId,
          });
          if (
            !live ||
            live.runId !== args.runId ||
            live.status !== "running" ||
            live.killSwitch ||
            used >= live.requestBudget
          ) {
            break;
          }
          const outcome = await dispatch({
            scope,
            request: { method: "GET", url: `${base}${endpoint.path}` },
            identity,
            requestsUsed: used,
            rate,
            timeoutMs: PROBE_TIMEOUT_MS,
          });
          if (outcome.kind === "sent") {
            used += 1;
            if (outcome.response.status >= 200 && outcome.response.status < 300) {
              ok += 1;
              responses.push({
                identityKey: identity.key,
                path: endpoint.path,
                body: outcome.response.body,
              });
            } else if (outcome.response.status === 401) {
              unauthorised += 1;
            }
          } else if (outcome.kind === "blocked") {
            blocked += 1;
            if (outcome.reason === "kill_switch" || outcome.reason === "budget_exhausted") break;
          }
        }
        statuses.set(
          identity.key,
          ok > 0 ? "authenticated" : unauthorised > 0 ? "unauthenticated" : "unverified",
        );
      }

      const rawObjects = indexObjects(responses);
      const resolved = resolveOwners(rawObjects, data.identities);
      const tenantByKey = new Map(data.identities.map((i) => [i.key, i.tenant]));
      const labelByKey = new Map(data.identities.map((i) => [i.key, i.label]));
      const objectRows = resolved.objects
        .filter((object) => object.ref && object.type)
        .map((object) => ({
          key: `${object.type}:${object.ref}`,
          type: object.type,
          ref: object.ref,
          label: `${object.type} ${object.ref}`,
          owner: object.ownerKey,
          ownerLabel: labelByKey.get(object.ownerKey) ?? object.ownerKey,
          tenant:
            object.tenant !== "unknown" ? object.tenant : (tenantByKey.get(object.ownerKey) ?? "unknown"),
          classification: "standard",
        }));
      // De-duplicate by key: the same record seen through two paths must not
      // produce two competing owners.
      const uniqueObjects = Array.from(new Map(objectRows.map((o) => [o.key, o])).values());

      await ctx.runMutation(internal.pipeline.saveObjects, {
        engagementId: args.engagementId,
        objects: uniqueObjects,
      });
      await ctx.runMutation(internal.pipeline.setIdentityStatuses, {
        engagementId: args.engagementId,
        statuses: Array.from(statuses.entries()).map(([key, status]) => ({
          key,
          status,
          lastVerifiedAt: Date.now(),
        })),
      });

      const byType = new Map<string, number>();
      for (const object of uniqueObjects) byType.set(object.type, (byType.get(object.type) ?? 0) + 1);
      events.push({
        level: "INFO",
        phase: "identity",
        message: `${identities.length} identity session(s) usable, ${skipped.length} skipped`,
      });
      events.push({
        level: "INFO",
        phase: "model",
        message: `Application model built — ${uniqueObjects.length} objects across ${byType.size} entity type(s)`,
      });
      if (resolved.dropped > 0) {
        events.push({
          level: "VERIFY",
          phase: "model",
          message: `${resolved.dropped} observed record(s) had an owner outside the credential set and were excluded from cross-identity probes`,
        });
      }
      if (uniqueObjects.length === 0) {
        events.push({
          level: "WARN",
          phase: "model",
          message:
            "No objects could be attributed — no templated endpoints were discovered or no collection returned records. Import an OpenAPI/HAR artefact or widen the path allowlist.",
        });
      }

      await ctx.runMutation(internal.pipeline.updateRunProgress, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: 3,
        requestsUsed: used,
        blockedOutOfScope: blocked,
      });
      await emit(ctx, args.engagementId, events);
      await ctx.runMutation(internal.pipeline.scheduleRunnerStage, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: "probe",
        delayMs: STAGE_DELAY_MS,
        chunk: 0,
      });
    }),
});

/* ------------------------------------------------------------------ */
/* stage 3 — cross-identity probes (chunked)                           */
/* ------------------------------------------------------------------ */

export const probe = internalAction({
  args: {
    engagementId: v.id("engagements"),
    runId: v.string(),
    chunk: v.number(),
  },
  handler: async (ctx, args) =>
    guard(ctx, args, async () => {
      const data = await loadRun(ctx, args);
      if (!data) return;
      const engagement = data.engagement;
      const scope = scopeFrom(engagement);
      const base = originOf(scope.target);
      const events: Evt[] = [];
      await setStage(ctx, args, args.chunk === 0 ? 4 : 5);
      if (!base) return;

      let identities: RealIdentity[] = [];
      try {
        ({ identities } = await loadIdentities(ctx, data));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await emit(ctx, args.engagementId, [
          { level: "ERROR", phase: "identity", message: `Cannot decrypt credentials: ${message}` },
        ]);
        await ctx.runMutation(internal.pipeline.updateRunProgress, {
          engagementId: args.engagementId,
          runId: args.runId,
          status: "error",
          finishedAt: Date.now(),
        });
        return;
      }

      // A session the model stage proved dead (401 on every read) must not be
      // replayed: it wastes budget and turns every probe into noise.
      const deadSessions = new Set(
        data.identities
          .filter((i) => i.status === "unauthenticated" && i.authMethod !== "none")
          .map((i) => i.key),
      );
      if (deadSessions.size > 0) {
        identities = identities.filter((i) => !deadSessions.has(i.key));
        events.push({
          level: "WARN",
          phase: "identity",
          message: `${deadSessions.size} identity session(s) returned 401 during modelling and were excluded — re-check their credentials before the next run`,
        });
      }

      const identitiesByKey = new Map(identities.map((i) => [i.key, i]));
      const labelByKey = new Map(data.identities.map((i) => [i.key, i.label]));
      const tenantByKey = new Map(data.identities.map((i) => [i.key, i.tenant]));
      const labelFor = (key: string) =>
        identitiesByKey.get(key)?.label ?? labelByKey.get(key) ?? key;

      const endpoints = await ctx.runQuery(internal.pipeline.getEndpoints, {
        engagementId: args.engagementId,
      });
      const objectDocs = await ctx.runQuery(internal.pipeline.getObjects, {
        engagementId: args.engagementId,
      });

      const specs: EndpointSpec[] = endpoints
        .filter((e) => e.inScope && e.path.includes("{") && e.parameters.length > 0)
        .map((e) => ({
          key: e.key,
          method: e.method,
          path: e.path,
          parameters: e.parameters,
          requiresAuth: e.authRequired,
          source: e.discoveredVia,
        }));
      const objects: ObservedObject[] = objectDocs
        .filter((o) => Boolean(o.owner))
        .map((o) => ({
          ref: o.ref,
          type: o.type,
          ownerKey: o.owner as string,
          tenant: o.tenant,
          source: o.key,
        }));

      if (args.chunk === 0) {
        events.push({
          level: "INFO",
          phase: "matrix",
          message: `Authorization test matrix — ${specs.length} object-aware endpoint(s), ${objects.length} attributed object(s), ${identities.length} usable identity session(s)`,
        });
      }

      let plans = planProbes({
        endpoints: specs,
        objects,
        identities,
        baseUrl: base,
        tenantOf: (key) => tenantByKey.get(key) ?? "unknown",
      });

      const usable = new Set(identities.map((i) => i.key));
      const droppedForCredentials = plans.filter(
        (p) => !usable.has(p.ownerKey) || !usable.has(p.attackerKey),
      ).length;
      plans = plans.filter((p) => usable.has(p.ownerKey) && usable.has(p.attackerKey));
      if (droppedForCredentials > 0 && args.chunk === 0) {
        events.push({
          level: "WARN",
          phase: "matrix",
          message: `${droppedForCredentials} planned probe(s) skipped — a credential is missing for one of the two identities`,
        });
      }

      const cap =
        engagement.profile === "quick"
          ? 12
          : engagement.profile === "balanced"
            ? 30
            : Number.MAX_SAFE_INTEGER;
      if (plans.length > cap) plans = plans.slice(0, cap);

      let withheld = 0;
      if (scope.dryRun) {
        const before = plans.length;
        plans = plans.filter((p) => SAFE_METHODS.has(p.method.toUpperCase()));
        withheld = before - plans.length;
      }
      if (withheld > 0) {
        events.push({
          level: "WARN",
          phase: "safety",
          message: `Dry-run withheld ${withheld} mutating probe(s) — no write request was dispatched`,
        });
      }
      if (args.chunk === 0 && plans.length === 0) {
        events.push({
          level: "WARN",
          phase: "matrix",
          message:
            "No cross-identity probe could be planned — object-aware endpoints are required. Import an OpenAPI/HAR artefact or widen discovery.",
        });
      }

      const start = args.chunk * CHUNK_PLANS;
      const slice = plans.slice(start, start + CHUNK_PLANS);
      const rate = rateStateFor(scope);

      // The guard runs again here: a plan that is refused never reaches the
      // transport, and is recorded as blocked evidence instead.
      const runnable: ProbePlan[] = [];
      const blockedRows: TestRowShape[] = [];
      let preblocked = 0;
      for (const plan of slice) {
        const decision = authorize({
          scope,
          url: plan.url,
          method: plan.method,
          requestsUsed: engagement.requestsUsed,
          destructive: plan.destructive,
        });
        if (!decision.allowed) {
          preblocked += 1;
          blockedRows.push(
            toBlockedTestRow({
              plan,
              reason: decision.reason,
              detail: decision.detail,
              actorLabel: labelFor(plan.attackerKey),
              ownerLabel: labelFor(plan.ownerKey),
            }),
          );
          continue;
        }
        runnable.push(plan);
      }

      const state = { used: engagement.requestsUsed, blocked: 0 };
      const transport: Transport = async ({ plan, identity }) => {
        for (let attempt = 0; attempt < 5; attempt += 1) {
          const outcome = await dispatch({
            scope,
            request: { method: plan.method, url: plan.url },
            identity,
            requestsUsed: state.used,
            destructive: plan.destructive,
            rate,
            timeoutMs: PROBE_TIMEOUT_MS,
          });
          if (outcome.kind === "sent") {
            state.used += 1;
            return { status: outcome.response.status, body: outcome.response.body };
          }
          if (outcome.kind === "error") {
            // Timeout / DNS / reset — the suite counts it as a transport error
            // and never turns it into a finding.
            throw new Error(outcome.message);
          }
          if (outcome.reason === "rate_limited") {
            await sleep(Math.ceil(1000 / Math.max(1, scope.rateLimit)) + 50);
            continue;
          }
          state.blocked += 1;
          throw new Error(`blocked:${outcome.reason} — ${outcome.detail}`);
        }
        state.blocked += 1;
        throw new Error("blocked:rate_limited — no rate token became available");
      };

      const result = await executeSuite({
        plans: runnable,
        identitiesByKey,
        transport,
        shouldContinue: async () => {
          const live = await ctx.runQuery(internal.pipeline.getRunState, {
            engagementId: args.engagementId,
          });
          if (!live || live.runId !== args.runId || live.status !== "running") return false;
          if (live.killSwitch) return false;
          return state.used < live.requestBudget;
        },
      });

      const planById = new Map(slice.map((p) => [p.id, p]));
      const mappedTests = result.tests
        .map((record) => {
          const plan = planById.get(record.planId);
          if (!plan) return null;
          return toTestRow({
            record,
            plan,
            actorLabel: labelFor(record.attackerKey),
            ownerLabel: labelFor(record.ownerKey),
          });
        })
        .filter((row): row is TestRowShape => row !== null);
      const testRows: TestRowShape[] = [...blockedRows, ...mappedTests];

      const existingFindings = await ctx.runQuery(internal.pipeline.getFindings, {
        engagementId: args.engagementId,
      });
      const findingRows = result.findings.map((record, index) => {
        const plan = planById.get(record.testId);
        return toFindingRow({
          record,
          code: findingCode(existingFindings.length + index),
          actorLabel: plan ? labelFor(plan.attackerKey) : record.attacker,
          ownerLabel: plan ? labelFor(plan.ownerKey) : record.owner,
        });
      });

      if (testRows.length > 0) {
        await ctx.runMutation(internal.pipeline.saveTests, {
          engagementId: args.engagementId,
          tests: testRows,
        });
      }
      if (findingRows.length > 0) {
        await ctx.runMutation(internal.pipeline.saveFindings, {
          engagementId: args.engagementId,
          findings: findingRows,
        });
        for (const row of findingRows.slice(0, 10)) {
          events.push({
            level: "CONFIRMED",
            phase: "findings",
            message: `${row.code} ${row.title} — ${row.severity.toUpperCase()} (${row.confidence}/${row.score})`,
          });
        }
      }

      const passed = mappedTests.filter((t) => t.outcome === "pass").length;
      const failed = mappedTests.filter((t) => t.outcome === "fail").length;
      const inconclusive = mappedTests.filter((t) => t.outcome === "inconclusive").length;
      events.push({
        level: "INFO",
        phase: "execution",
        message: `Chunk ${args.chunk + 1}: ${testRows.length} result(s) — ${passed} passed, ${failed} violated, ${inconclusive} inconclusive, ${blockedRows.length} blocked, ${result.errors} transport error(s)`,
      });

      const blockedTotal = engagement.blockedOutOfScope + state.blocked + preblocked;
      await ctx.runMutation(internal.pipeline.updateRunProgress, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: 5,
        requestsUsed: state.used,
        blockedOutOfScope: blockedTotal,
      });
      await emit(ctx, args.engagementId, events);

      const live = await ctx.runQuery(internal.pipeline.getRunState, {
        engagementId: args.engagementId,
      });
      const more = start + CHUNK_PLANS < plans.length;

      if (live?.killSwitch) {
        await ctx.runMutation(internal.pipeline.scheduleRunnerStage, {
          engagementId: args.engagementId,
          runId: args.runId,
          stage: "report",
          delayMs: STAGE_DELAY_MS,
        });
        await ctx.runMutation(internal.pipeline.updateRunProgress, {
          engagementId: args.engagementId,
          runId: args.runId,
          status: "halted",
        });
        return;
      }
      if (live && state.used >= live.requestBudget) {
        await emit(ctx, args.engagementId, [
          {
            level: "WARN",
            phase: "safety",
            message: "Request budget exhausted — reporting on the evidence collected so far",
          },
        ]);
        await ctx.runMutation(internal.pipeline.scheduleRunnerStage, {
          engagementId: args.engagementId,
          runId: args.runId,
          stage: "report",
          delayMs: STAGE_DELAY_MS,
        });
        return;
      }
      if (more) {
        await ctx.runMutation(internal.pipeline.scheduleRunnerStage, {
          engagementId: args.engagementId,
          runId: args.runId,
          stage: "probe",
          delayMs: STAGE_DELAY_MS,
          chunk: args.chunk + 1,
        });
        return;
      }
      await ctx.runMutation(internal.pipeline.scheduleRunnerStage, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: "report",
        delayMs: STAGE_DELAY_MS,
      });
    }),
});

/* ------------------------------------------------------------------ */
/* stage 4 — coverage + report                                         */
/* ------------------------------------------------------------------ */

export const report = internalAction({
  args: { engagementId: v.id("engagements"), runId: v.string() },
  handler: async (ctx, args) =>
    guard(ctx, args, async () => {
      const data = await loadRun(ctx, args, { lenient: true });
      if (!data) return;
      const engagement = data.engagement;
      await setStage(ctx, args, 6);
      const endpoints = await ctx.runQuery(internal.pipeline.getEndpoints, {
        engagementId: args.engagementId,
      });
      const tests = await ctx.runQuery(internal.pipeline.getTests, {
        engagementId: args.engagementId,
      });
      const findings = await ctx.runQuery(internal.pipeline.getFindings, {
        engagementId: args.engagementId,
      });
      const objects = await ctx.runQuery(internal.pipeline.getObjects, {
        engagementId: args.engagementId,
      });

      const coverage = realCoverage({
        endpoints,
        tests,
        findings,
        objects,
        identities: data.identities,
        requestBudget: engagement.requestBudget,
        requestsUsed: engagement.requestsUsed,
        blockedOutOfScope: engagement.blockedOutOfScope,
        dryRun: engagement.dryRun,
      });

      const status =
        engagement.status === "halted" || engagement.status === "error"
          ? engagement.status
          : "complete";
      const events: Evt[] = [
        {
          level: "INFO",
          phase: "report",
          message: `Coverage: ${coverage.totalTests} probes, ${coverage.failed} violations, ${coverage.findings} findings (${coverage.critical} critical / ${coverage.high} high / ${coverage.medium} medium / ${coverage.low} low)`,
        },
        {
          level: "INFO",
          phase: "report",
          message: `${coverage.requestsUsed}/${coverage.requestBudget} requests used · ${coverage.blocked} probe(s) blocked by safety controls · ${coverage.endpointsInScope}/${coverage.endpointsDiscovered} endpoint(s) in scope`,
        },
        {
          level: "INFO",
          phase: "report",
          message: "Report artefacts ready: HTML, PDF, JSON, Markdown, SARIF, CSV",
        },
      ];
      await emit(ctx, args.engagementId, events);
      await ctx.runMutation(internal.pipeline.finalizeRun, {
        engagementId: args.engagementId,
        runId: args.runId,
        stage: 7,
        status,
        finishedAt: Date.now(),
        coverage,
      });
    }),
});
