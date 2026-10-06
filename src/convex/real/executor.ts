/**
 * WABVE — real HTTP dispatcher.
 *
 * The only place in the codebase that opens a socket. Every request passes the
 * scope guard first; when the guard refuses, nothing is sent and no network
 * call is attempted. Responses are scrubbed of credentials before they leave
 * this function, so no secret reaches the database or the browser.
 */

import {
  authorize,
  consume,
  scrubHeaders,
  scrubSecrets,
  type Bucket,
  type Decision,
  type DenyReason,
  type ScopeConfig,
} from "./engine";

export type AuthType = "bearer" | "cookie" | "none";

export interface RealIdentity {
  key: string;
  label: string;
  role: string;
  authType: AuthType;
  /** Decrypted immediately before dispatch, never persisted. */
  secret?: string;
}

export interface HttpRequestSpec {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface HttpResponseRecord {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  durationMs: number;
}

export type DispatchOutcome =
  | { kind: "sent"; decision: Extract<Decision, { allowed: true }>; response: HttpResponseRecord }
  | { kind: "blocked"; reason: DenyReason; detail: string }
  | { kind: "error"; message: string };

export const DEFAULT_TIMEOUT_MS = 15_000;

/** Cap on redirect hops, so a redirect loop cannot spin forever. */
const MAX_REDIRECTS = 5;
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

type Hop =
  | { kind: "follow"; url: string; method: string; body: string | undefined }
  | { kind: "stop" };

/**
 * Resolve the next hop of a redirect chain.
 *
 * Redirects are never followed blindly. `redirect: "follow"` would hand the
 * request to whatever the target's `Location` names, with the scope guard
 * having only ever seen the first URL — so any in-scope host could pivot the
 * scanner onto a path or host the operator never authorised. Instead each hop
 * is resolved here and re-authorised by the caller.
 *
 * Stops on a non-redirect status, a missing or unparseable `Location`, or once
 * the hop cap is reached.
 */
function nextHop(
  response: Response,
  currentUrl: string,
  method: string,
  body: string | undefined,
  hops: number,
): Hop {
  if (!REDIRECT_STATUS.has(response.status) || hops >= MAX_REDIRECTS) return { kind: "stop" };
  const location = response.headers.get("location");
  if (!location) return { kind: "stop" };
  let url: string;
  try {
    url = new URL(location, currentUrl).toString();
  } catch {
    return { kind: "stop" };
  }
  // 303 — and 301/302 on a non-GET — become GET and drop the body, matching how
  // fetch itself resolves those redirects.
  const upper = method.toUpperCase();
  const downgrade =
    response.status === 303 ||
    ((response.status === 301 || response.status === 302) && upper !== "GET" && upper !== "HEAD");
  return { kind: "follow", url, method: downgrade ? "GET" : upper, body: downgrade ? undefined : body };
}

/** Shared pacing state passed by the runner so every dispatch counts. */
export interface RateState {
  bucket: Bucket;
  rateLimit: number;
}

/** Authentication headers for an identity, built fresh on every dispatch. */
export function authHeaders(identity: RealIdentity): Record<string, string> {
  if (identity.authType === "none" || !identity.secret) return {};
  if (identity.authType === "bearer") {
    return { Authorization: `Bearer ${identity.secret}` };
  }
  // Cookie values are supplied either as a full `name=value` pair or as the
  // raw value for the conventional `session` cookie.
  const secret = identity.secret.trim();
  return { Cookie: secret.includes("=") ? secret : `session=${secret}` };
}

function withTimeout(ms: number): { signal: AbortSignal; done: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return {
    signal: controller.signal,
    done: () => clearTimeout(timer),
  };
}

function readHeaders(response: Response): Record<string, string> {
  const out: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

/**
 * Send one request if — and only if — the scope guard permits it.
 * Returns a discriminated outcome rather than throwing, so callers can record
 * blocked and errored probes as first-class evidence.
 */
export async function dispatch(
  input: {
    scope: ScopeConfig;
    request: HttpRequestSpec;
    identity: RealIdentity;
    requestsUsed: number;
    destructive?: boolean;
    timeoutMs?: number;
    secrets?: string[];
    rate?: RateState;
  },
): Promise<DispatchOutcome> {
  const { scope, request, identity, requestsUsed } = input;

  const decision = authorize({
    scope,
    url: request.url,
    method: request.method,
    requestsUsed,
    ...(input.destructive !== undefined ? { destructive: input.destructive } : {}),
  });
  if (!decision.allowed) {
    return { kind: "blocked", reason: decision.reason, detail: decision.detail };
  }

  // Pace after the guard passes: a request that was never going to be allowed
  // must not consume the operator's rate budget.
  if (input.rate && !consume(input.rate.bucket, input.rate.rateLimit, Date.now())) {
    return {
      kind: "blocked",
      reason: "rate_limited",
      detail: `rate limit of ${input.rate.rateLimit}/s reached; request withheld`,
    };
  }

  const secrets = [...(input.secrets ?? []), ...(identity.secret ? [identity.secret] : [])];
  const headers: Record<string, string> = {
    Accept: "application/json, text/html;q=0.9, */*;q=0.8",
    "User-Agent": "WABVE/1.0 (authorization verification)",
    ...authHeaders(identity),
    ...(request.headers ?? {}),
  };

  const timeout = withTimeout(input.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const startedAt = Date.now();

  try {
    let currentUrl = request.url;
    let currentMethod = request.method.toUpperCase();
    let currentBody = currentMethod === "GET" || currentMethod === "HEAD" ? undefined : request.body;
    let hops = 0;

    for (;;) {
      // Every redirect hop is a separate request and must clear the same guard
      // as the first. The identity's credentials travel with the chain, but only
      // to a host the operator explicitly allowlisted — that list is the
      // authorisation decision, and a hop outside it is refused here.
      if (hops > 0) {
        const hopDecision = authorize({
          scope,
          url: currentUrl,
          method: currentMethod,
          requestsUsed: requestsUsed + hops,
          ...(input.destructive !== undefined ? { destructive: input.destructive } : {}),
        });
        if (!hopDecision.allowed) {
          return {
            kind: "blocked",
            reason: hopDecision.reason,
            detail: `redirect to ${currentUrl} refused: ${hopDecision.detail}`,
          };
        }
        if (input.rate && !consume(input.rate.bucket, input.rate.rateLimit, Date.now())) {
          return {
            kind: "blocked",
            reason: "rate_limited",
            detail: "rate limit reached while following a redirect; request withheld",
          };
        }
      }

      const response = await fetch(currentUrl, {
        method: currentMethod,
        headers,
        signal: timeout.signal,
        ...(currentBody !== undefined ? { body: currentBody } : {}),
        redirect: "manual",
      });

      const hop = nextHop(response, currentUrl, currentMethod, currentBody, hops);
      if (hop.kind === "stop") {
        const rawBody = await response.text();
        return {
          kind: "sent",
          decision,
          response: {
            status: response.status,
            statusText: response.statusText,
            headers: scrubHeaders(readHeaders(response), secrets),
            body: scrubSecrets(rawBody, secrets),
            durationMs: Date.now() - startedAt,
          },
        };
      }

      hops += 1;
      currentUrl = hop.url;
      currentMethod = hop.method;
      currentBody = hop.body;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      kind: "error",
      message: /abort/i.test(message)
        ? `timed out after ${input.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`
        : scrubSecrets(message, secrets),
    };
  } finally {
    timeout.done();
  }
}

/**
 * Fetch a document for discovery (OpenAPI, HTML, a bundle). Still guarded by
 * scope — a discovery crawl must not leave the allowlist either.
 */
export async function fetchDocument(input: {
  scope: ScopeConfig;
  url: string;
  requestsUsed: number;
  timeoutMs?: number;
  rate?: RateState;
}): Promise<
  | { kind: "ok"; status: number; contentType: string; text: string; decision: Extract<Decision, { allowed: true }> }
  | { kind: "blocked"; reason: DenyReason; detail: string }
  | { kind: "error"; message: string }
> {
  const decision = authorize({
    scope: input.scope,
    url: input.url,
    method: "GET",
    requestsUsed: input.requestsUsed,
  });
  if (!decision.allowed) {
    return { kind: "blocked", reason: decision.reason, detail: decision.detail };
  }
  if (input.rate && !consume(input.rate.bucket, input.rate.rateLimit, Date.now())) {
    return {
      kind: "blocked",
      reason: "rate_limited",
      detail: `rate limit of ${input.rate.rateLimit}/s reached; request withheld`,
    };
  }

  const timeout = withTimeout(input.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    let currentUrl = input.url;
    let hops = 0;

    for (;;) {
      // A document fetch is no different: a redirect must not carry discovery
      // outside the allowlist either.
      if (hops > 0) {
        const hopDecision = authorize({
          scope: input.scope,
          url: currentUrl,
          method: "GET",
          requestsUsed: input.requestsUsed + hops,
        });
        if (!hopDecision.allowed) {
          return {
            kind: "blocked",
            reason: hopDecision.reason,
            detail: `redirect to ${currentUrl} refused: ${hopDecision.detail}`,
          };
        }
        if (input.rate && !consume(input.rate.bucket, input.rate.rateLimit, Date.now())) {
          return {
            kind: "blocked",
            reason: "rate_limited",
            detail: "rate limit reached while following a redirect; request withheld",
          };
        }
      }

      const response = await fetch(currentUrl, {
        method: "GET",
        headers: {
          Accept: "application/json, text/html;q=0.9, */*;q=0.8",
          "User-Agent": "WABVE/1.0 (authorization verification)",
        },
        signal: timeout.signal,
        redirect: "manual",
      });

      const hop = nextHop(response, currentUrl, "GET", undefined, hops);
      if (hop.kind === "stop") {
        const text = await response.text();
        return {
          kind: "ok",
          status: response.status,
          contentType: response.headers.get("content-type") ?? "",
          text,
          decision,
        };
      }

      hops += 1;
      currentUrl = hop.url;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { kind: "error", message: /abort/i.test(message) ? "document fetch timed out" : message };
  } finally {
    timeout.done();
  }
}
