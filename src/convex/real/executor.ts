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
    const response = await fetch(request.url, {
      method: request.method.toUpperCase(),
      headers,
      signal: timeout.signal,
      ...(request.body !== undefined && request.method.toUpperCase() !== "GET"
        ? { body: request.body }
        : {}),
      redirect: "follow",
    });

    const rawBody = await response.text();
    const durationMs = Date.now() - startedAt;

    return {
      kind: "sent",
      decision,
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: scrubHeaders(readHeaders(response), secrets),
        body: scrubSecrets(rawBody, secrets),
        durationMs,
      },
    };
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
    const response = await fetch(input.url, {
      method: "GET",
      headers: {
        Accept: "application/json, text/html;q=0.9, */*;q=0.8",
        "User-Agent": "WABVE/1.0 (authorization verification)",
      },
      signal: timeout.signal,
      redirect: "follow",
    });
    const text = await response.text();
    return {
      kind: "ok",
      status: response.status,
      contentType: response.headers.get("content-type") ?? "",
      text,
      decision,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { kind: "error", message: /abort/i.test(message) ? "document fetch timed out" : message };
  } finally {
    timeout.done();
  }
}
