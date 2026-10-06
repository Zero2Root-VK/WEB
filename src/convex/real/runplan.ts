/**
 * WABVE — runner planning primitives.
 *
 * The runner is a Convex action chain and cannot be unit-tested directly, but
 * these decisions do not need Convex: they map an engagement and a discovered
 * endpoint onto a scope, a crawl budget and a report category. They are pure so
 * they can be verified here rather than trusted.
 *
 * `objectTypeFor` must agree with the probe planner in `suite.ts`, which derives
 * the same resource name from a path parameter (`{order_id}` → `order`). If the
 * two ever diverged, an endpoint would be labelled with an object type that no
 * probe ever addresses.
 */

import type { ScopeConfig } from "./engine";

/** The scope-bearing fields of an engagement document. */
export interface ScopeSource {
  target: string;
  allowedHosts: string[];
  allowedPaths: string[];
  rateLimit: number;
  requestBudget: number;
  killSwitch: boolean;
  destructiveTesting: boolean;
  dryRun: boolean;
}

/** Project an engagement document onto the guard's configuration. */
export function scopeFrom(engagement: ScopeSource): ScopeConfig {
  return {
    target: engagement.target,
    allowedHosts: engagement.allowedHosts,
    allowedPaths: engagement.allowedPaths,
    rateLimit: engagement.rateLimit,
    requestBudget: engagement.requestBudget,
    killSwitch: engagement.killSwitch,
    destructiveTesting: engagement.destructiveTesting,
    dryRun: engagement.dryRun,
  };
}

/** Origin of a target URL, or null when it is not an http(s) URL. */
export function originOf(target: string): string | null {
  try {
    const url = new URL(target);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Pages fetched during a crawl, per assessment profile. */
export function crawlLimit(profile: string): number {
  if (profile === "quick") return 6;
  if (profile === "deep") return 30;
  return 15;
}

/** Candidate API-description documents probed, per assessment profile. */
export function specLimit(profile: string): number {
  return profile === "quick" ? 2 : 5;
}

/**
 * Report category for an endpoint. Categories drive OWASP mapping and
 * remediation text, so this is a reporting decision, not a routing one.
 * Anything that is not a named functional area is an authorization endpoint.
 */
export function categoryForPath(path: string): string {
  if (/^\/(?:admin|manage|internal|debug|console|backoffice)(?:\/|$)/i.test(path)) return "bfla";
  if (/\/(?:auth|login|session|token|oauth|sso)(?:\/|$)/i.test(path)) return "session";
  if (/\/(?:coupon|refund|checkout|promotion|redeem|payment)(?:\/|$)/i.test(path)) return "business";
  return "authorization";
}

/**
 * Resource named by a path parameter: `/api/orders/{order_id}` → `order`.
 * Returns null when the path parameter is unnamed (`{id}` names nothing).
 */
export function objectTypeFor(path: string): string | null {
  const match = /\{(\w+_id)\}/.exec(path);
  if (match) return match[1].replace(/_id$/, "");
  return null;
}
