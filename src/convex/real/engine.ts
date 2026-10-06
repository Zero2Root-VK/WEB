/**
 * WABVE — dispatch safety core and differential oracle.
 *
 * Everything in this module is pure: no I/O, no clock reads, no randomness.
 * Scope, rate, budget and secret-redaction rules are the parts of a scanner a
 * client's security team audits first, so they are written here as small
 * deterministic functions and covered by unit tests in `engine.test.ts`.
 *
 * A request is only ever dispatched when `authorize()` returns `{allowed:true}`
 * for the exact URL being sent, after normalisation, on the same tick as the
 * budget and kill-switch checks.
 */

/* ------------------------------------------------------------------ */
/* configuration                                                       */
/* ------------------------------------------------------------------ */

export interface ScopeConfig {
  /** Base URL of the engagement target, e.g. https://staging.acme.test */
  target: string;
  /** Hosts that may be contacted. Subdomains match only when the pattern has a dot. */
  allowedHosts: string[];
  /** Path prefixes that may be contacted. Empty array means "any path". */
  allowedPaths: string[];
  /** Sustained requests per second. */
  rateLimit: number;
  /** Hard ceiling on requests for the whole engagement. */
  requestBudget: number;
  killSwitch: boolean;
  destructiveTesting: boolean;
  dryRun: boolean;
}

export type DenyReason =
  | "kill_switch"
  | "budget_exhausted"
  | "rate_limited"
  | "protocol"
  | "host_not_allowed"
  | "path_not_allowed"
  | "unparseable_url"
  | "destructive_not_approved";

export type Decision =
  | { allowed: true; url: string; host: string; path: string }
  | { allowed: false; reason: DenyReason; detail: string };

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);
export const DESTRUCTIVE_METHODS = new Set(["DELETE"]);

/* ------------------------------------------------------------------ */
/* path normalisation                                                  */
/* ------------------------------------------------------------------ */

/**
 * Collapse `.` / `..` and duplicate slashes so a traversal payload cannot slip
 * past a prefix check. The result always starts with a single `/`.
 */
export function normalizePath(pathname: string): string {
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    // Malformed percent-encoding: keep the raw form, the deny-by-default
    // caller still has to pass both forms.
  }
  const out: string[] = [];
  for (const segment of decoded.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      out.pop();
      continue;
    }
    out.push(segment);
  }
  return `/${out.join("/")}`;
}

/** True when `path` is inside the allowlist prefix set. */
export function pathAllowed(path: string, allowedPaths: string[]): boolean {
  if (allowedPaths.length === 0) return true;
  return allowedPaths.some((raw) => {
    const prefix = raw.trim();
    if (prefix === "" || prefix === "/") return true;
    // Require the prefix to end on a path-segment boundary so an allowlist of
    // `/api` does not silently permit `/apixyz`.
    return path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
  });
}

/**
 * Exact host match, or a real subdomain of an allowed host. A pattern without
 * a dot (e.g. `com`) is only ever an exact match — otherwise a single overly
 * broad entry would silently open the entire internet.
 */
export function hostAllowed(hostname: string, allowedHosts: string[]): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return allowedHosts.some((raw) => {
    const pattern = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    if (pattern === "") return false;
    if (host === pattern) return true;
    return pattern.includes(".") && host.endsWith(`.${pattern}`);
  });
}

/* ------------------------------------------------------------------ */
/* authorize                                                           */
/* ------------------------------------------------------------------ */

export interface AuthorizeInput {
  scope: ScopeConfig;
  url: string;
  method: string;
  requestsUsed: number;
  /** Set by the registry for endpoints an operator flagged as irreversible. */
  destructive?: boolean;
}

/**
 * Decide whether a specific request may be dispatched. Deny by default: an
 * unparseable URL, an unsupported protocol or a host outside the allowlist all
 * refuse, and no caller can bypass the result.
 */
export function authorize(input: AuthorizeInput): Decision {
  const { scope, url, method, requestsUsed } = input;
  const upper = method.toUpperCase();

  if (scope.killSwitch) {
    return { allowed: false, reason: "kill_switch", detail: "kill switch is engaged" };
  }
  if (requestsUsed >= scope.requestBudget) {
    return {
      allowed: false,
      reason: "budget_exhausted",
      detail: `${requestsUsed} of ${scope.requestBudget} requests already used`,
    };
  }
  // Only genuinely irreversible operations need approval. Safe methods and
  // ordinary writes stay available, otherwise the engine could never run.
  const destructive = input.destructive === true || DESTRUCTIVE_METHODS.has(upper);
  if (destructive && !scope.destructiveTesting) {
    return {
      allowed: false,
      reason: "destructive_not_approved",
      detail: `${upper} is not approved for this engagement`,
    };
  }
  if (!SAFE_METHODS.has(upper) && !/^(GET|HEAD|OPTIONS|TRACE|POST|PUT|PATCH|DELETE|CONNECT)$/.test(upper)) {
    return {
      allowed: false,
      reason: "protocol",
      detail: `method ${upper} is not a known HTTP method`,
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { allowed: false, reason: "unparseable_url", detail: "url could not be parsed" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      allowed: false,
      reason: "protocol",
      detail: `protocol ${parsed.protocol} is not permitted`,
    };
  }

  if (!hostAllowed(parsed.hostname, scope.allowedHosts)) {
    return {
      allowed: false,
      reason: "host_not_allowed",
      detail: `${parsed.hostname} is outside the host allowlist`,
    };
  }

  // Check the raw and the normalised path. Both must pass, so an encoded
  // traversal cannot be dispatched even if only one form matches the prefix.
  const rawPath = parsed.pathname || "/";
  const normalized = normalizePath(rawPath);
  if (!pathAllowed(rawPath, scope.allowedPaths)) {
    return {
      allowed: false,
      reason: "path_not_allowed",
      detail: `${rawPath} is outside the path allowlist`,
    };
  }
  if (!pathAllowed(normalized, scope.allowedPaths)) {
    return {
      allowed: false,
      reason: "path_not_allowed",
      detail: `normalised ${normalized} is outside the path allowlist`,
    };
  }

  return { allowed: true, url, host: parsed.hostname, path: normalized };
}

/* ------------------------------------------------------------------ */
/* rate limiting                                                       */
/* ------------------------------------------------------------------ */

export interface Bucket {
  tokens: number;
  updatedAt: number;
}

/** Token bucket seeded at `now`. Capacity equals the sustained rate. */
export function createBucket(ratePerSecond: number, now: number): Bucket {
  return { tokens: Math.max(1, ratePerSecond), updatedAt: now };
}

/**
 * Take one token, refilling first. Returns false when under rate — the caller
 * must NOT dispatch. `now` is an argument so the behaviour is testable.
 */
export function consume(bucket: Bucket, ratePerSecond: number, now: number, cost = 1): boolean {
  const rate = Math.max(0.001, ratePerSecond);
  const capacity = Math.max(1, ratePerSecond);
  const elapsedSeconds = Math.max(0, (now - bucket.updatedAt) / 1000);
  bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSeconds * rate);
  bucket.updatedAt = now;
  if (bucket.tokens < cost) return false;
  bucket.tokens -= cost;
  return true;
}

/* ------------------------------------------------------------------ */
/* secret redaction                                                    */
/* ------------------------------------------------------------------ */

const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g;
const AUTH_HEADER_PATTERN = /((?:authorization|proxy-authorization)\s*[:=]\s*)(\S+(?:\s+\S+)*)/gi;
const COOKIE_PATTERN = /((?:^|[\r\n;])\s*(?:set-)?cookie\s*[:=]\s*)([^\r\n;]+)/gi;

/** Replace secrets and secret-shaped values before anything is persisted. */
export function scrubSecrets(text: string, secrets: string[] = []): string {
  let out = text;
  for (const secret of secrets) {
    const value = secret.trim();
    if (value.length < 4) continue;
    out = splitJoin(out, value, "••••••");
  }
  out = out.replace(AUTH_HEADER_PATTERN, (_m, prefix: string) => `${prefix}••••••`);
  out = out.replace(COOKIE_PATTERN, (_m, prefix: string) => `${prefix}••••••`);
  out = out.replace(JWT_PATTERN, "••••••");
  return out;
}

function splitJoin(haystack: string, needle: string, replacement: string): string {
  if (!haystack.includes(needle)) return haystack;
  return haystack.split(needle).join(replacement);
}

export function scrubHeaders(
  headers: Record<string, string>,
  secrets: string[] = [],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = /authorization|cookie|token|api-?key|secret/i.test(key)
      ? "••••••"
      : scrubSecrets(value, secrets);
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* state snapshots and delta                                           */
/* ------------------------------------------------------------------ */

export type Snapshot = Record<string, unknown>;

export interface DeltaEntry {
  field: string;
  before: unknown;
  after: unknown;
}

/**
 * Keys whose churn is noise, not evidence. Matched against camelCase and
 * snake_case alike (`updatedAt` and `updated_at`), because real APIs use both —
 * and a missed one is a false positive on every single record.
 */
const VOLATILE_KEY =
  /^(?:[a-z0-9]+_?)*(?:timestamp|created_?at|updated_?at|deleted_?at|modified_?at|last_?seen|nonce|request_?id|trace_?id|correlation_?id|iat|nbf|exp)$/i;

/**
 * Drop volatile fields and nested noise so two legitimate reads of an unchanged
 * record compare equal. Without this a scanner reports a finding every time a
 * clock ticks — the classic false-positive source.
 */
export function normalizeSnapshot(value: unknown, volatileKeys: string[] = []): Snapshot {
  const extra = new Set(volatileKeys.map((k) => k.toLowerCase()));
  const walk = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(walk);
    if (input && typeof input === "object") {
      const out: Snapshot = {};
      for (const [key, item] of Object.entries(input as Snapshot)) {
        if (VOLATILE_KEY.test(key)) continue;
        if (extra.has(key.toLowerCase())) continue;
        out[key] = walk(item);
      }
      return out;
    }
    return input;
  };
  const cleaned = walk(value);
  return cleaned && typeof cleaned === "object" && !Array.isArray(cleaned)
    ? (cleaned as Snapshot)
    : { value: cleaned };
}

export function diffSnapshots(before: unknown, after: unknown, volatileKeys: string[] = []): DeltaEntry[] {
  const a = normalizeSnapshot(before, volatileKeys);
  const b = normalizeSnapshot(after, volatileKeys);
  const keys = Array.from(new Set([...Object.keys(a), ...Object.keys(b)]));
  const entries: DeltaEntry[] = [];
  for (const field of keys) {
    const left = JSON.stringify(a[field]);
    const right = JSON.stringify(b[field]);
    if (left !== right) entries.push({ field, before: a[field], after: b[field] });
  }
  return entries;
}

/* ------------------------------------------------------------------ */
/* differential oracle                                                  */
/* ------------------------------------------------------------------ */

export type Verdict = "confirmed" | "likely" | "inconclusive" | "not_vulnerable";

export interface OracleInput {
  /** Whether the reference policy says the attacker's request must be denied. */
  expectedDenied: boolean;
  attackerStatus: number;
  ownerStatus: number;
  /** Response bodies already scrubbed of secrets. */
  attackerBody: string;
  ownerBody: string;
  /** Values that identify the protected record (ids, emails, amounts). */
  protectedMarkers: string[];
  /** State read before the attack, or undefined when the probe is read-only. */
  stateBefore?: unknown;
  stateAfter?: unknown;
  volatileKeys?: string[];
}

export interface OracleResult {
  verdict: Verdict;
  signals: string[];
  confidence: number;
  delta: DeltaEntry[];
  reason: string;
}

const SIGNAL_WEIGHTS: Record<string, number> = {
  unauthorized_access_confirmed: 30,
  protected_record_returned: 30,
  server_state_changed: 30,
  ownership_reassigned: 30,
  privilege_boundary_crossed: 30,
  tenant_boundary_crossed: 30,
  protected_property_accepted: 30,
  workflow_transition_violated: 25,
  replay_accepted: 25,
  destructive_effect: 20,
  differential_confirmed: 10,
  reproducible: 10,
};

export function scoreSignals(signals: string[]): number {
  const total = signals.reduce((sum, s) => sum + (SIGNAL_WEIGHTS[s] ?? 0), 0);
  return Math.min(100, total);
}

export function confidenceLabel(score: number): string {
  if (score >= 90) return "Confirmed";
  if (score >= 70) return "High";
  if (score >= 40) return "Medium";
  return "Inconclusive";
}

/**
 * Decide whether a finding exists. A 200 alone is never enough: it must be a
 * 2xx to a request the reference policy denies, and it must be corroborated by
 * the protected payload actually coming back or by server state changing.
 */
export function differentialOracle(input: OracleInput): OracleResult {
  const delta = diffSnapshots(
    toSnapshot(input.stateBefore),
    toSnapshot(input.stateAfter),
    input.volatileKeys,
  );
  const signals: string[] = [];

  const attackerOk = input.attackerStatus >= 200 && input.attackerStatus < 300;
  const markersFound = input.protectedMarkers.filter(
    (marker) => marker.length > 0 && input.attackerBody.includes(marker),
  );

  if (input.expectedDenied && attackerOk) signals.push("unauthorized_access_confirmed");
  if (input.expectedDenied && attackerOk && markersFound.length > 0) {
    signals.push("protected_record_returned");
  }
  if (delta.length > 0) signals.push("server_state_changed");
  if (delta.some((d) => d.field === "owner" || d.field === "owner_id")) {
    signals.push("ownership_reassigned");
  }

  if (!input.expectedDenied) {
    const blocked = !attackerOk;
    return {
      verdict: blocked ? "inconclusive" : "not_vulnerable",
      signals: blocked ? ["legitimate_action_denied"] : [],
      confidence: 0,
      delta,
      reason: blocked
        ? `reference policy allows the action but the server returned ${input.attackerStatus}`
        : "reference policy allows the action and the server agreed",
    };
  }

  if (attackerOk && markersFound.length > 0) {
    signals.push("differential_confirmed", "reproducible");
    const confidence = scoreSignals(signals);
    return {
      verdict: confidence >= 70 ? "confirmed" : "likely",
      signals,
      confidence,
      delta,
      reason: `attacker received ${input.attackerStatus} and the response contained ${markersFound.length} protected value(s) the reference policy forbids`,
    };
  }

  if (attackerOk && delta.length > 0) {
    signals.push("differential_confirmed", "reproducible");
    const confidence = scoreSignals(signals);
    return {
      verdict: confidence >= 70 ? "confirmed" : "likely",
      signals,
      confidence,
      delta,
      reason: `attacker received ${input.attackerStatus} and persisted state changed on ${delta.length} field(s)`,
    };
  }

  if (attackerOk) {
    // A 2xx with nothing to corroborate it is the "HTTP 200 = vulnerable" trap
    // this engine exists to avoid, so it is never reported.
    signals.push("unauthorized_access_confirmed");
    return {
      verdict: "inconclusive",
      signals,
      confidence: scoreSignals(signals),
      delta,
      reason: `status ${input.attackerStatus} without corroborating payload or state change — not reported`,
    };
  }

  return {
    verdict: "not_vulnerable",
    signals: [],
    confidence: 0,
    delta,
    reason: `server returned ${input.attackerStatus}, matching the reference decision`,
  };
}

/** Extract the identifying values worth looking for in a protected response. */
export function protectedMarkers(...sources: Array<Record<string, unknown> | string | undefined>): string[] {
  const markers = new Set<string>();
  for (const source of sources) {
    if (!source) continue;
    if (typeof source === "string") {
      const json = tryParse(source);
      if (json) collectMarkers(json, markers);
      continue;
    }
    collectMarkers(source, markers);
  }
  return Array.from(markers);
}

function collectMarkers(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 6) return;
  if (Array.isArray(value)) {
    for (const item of value) collectMarkers(item, out, depth + 1);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value as Snapshot)) {
    if (VOLATILE_KEY.test(key)) continue;
    if (typeof item === "string" && item.length >= 4 && item.length <= 200 && !looksLikeBlob(item)) {
      if (/id|email|name|owner|amount|status|total|reference|title/i.test(key)) out.add(item);
    } else if (typeof item === "number") {
      if (/id|amount|total|balance/i.test(key)) out.add(String(item));
    } else if (item && typeof item === "object") {
      collectMarkers(item, out, depth + 1);
    }
  }
}

function looksLikeBlob(value: string): boolean {
  return /^(?:data:image|https?:\/\/.*\.(?:png|jpg|jpeg|gif|svg))/i.test(value);
}

export function tryParse(json: string): Snapshot | null {
  try {
    const parsed: unknown = JSON.parse(json);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Snapshot)
      : { items: parsed as unknown };
  } catch {
    return null;
  }
}

/**
 * Response bodies arrive as JSON text. Diffing the raw strings would collapse
 * the whole evidence trail into a single opaque `value` field instead of the
 * field-level delta a report needs, so parse before comparing.
 */
function toSnapshot(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return tryParse(trimmed) ?? value;
  }
  return value;
}
