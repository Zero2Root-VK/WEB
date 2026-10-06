/**
 * WABVE — discovery.
 *
 * Turns real artefacts (an OpenAPI document, a fetched HTML page, a HAR export,
 * a JavaScript bundle) into the unified endpoint registry. Everything here
 * operates on text it is given; network I/O lives in `executor.ts` so parsers
 * stay deterministically testable.
 */

export type EndpointSource = "openapi" | "html" | "har" | "js" | "manual";

export interface DiscoveredEndpoint {
  method: string;
  path: string;
  source: EndpointSource;
  parameters: string[];
}

const HTTP_VERBS = ["get", "put", "post", "delete", "patch", "head", "options", "trace"] as const;

/* ------------------------------------------------------------------ */
/* normalisation                                                       */
/* ------------------------------------------------------------------ */

/**
 * Turn a concrete path into a template: `/orders/5001` → `/orders/{id}`,
 * UUIDs, hex ids and long numerics all collapse to the same parameter.
 * Without this every concrete id becomes its own "endpoint" and the registry
 * explodes into noise.
 */
export function normalizePathTemplate(path: string): string {
  const parts = path.split("/").filter((segment) => segment !== "");
  const templated = parts.map((segment, index) => {
    if (segment.startsWith("{") && segment.endsWith("}")) return segment;
    if (/^\d+$/.test(segment)) return `{${guessParamName(parts, index)}}`;
    if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(segment)) {
      return "{id}";
    }
    if (/^[0-9a-fA-F]{16,}$/.test(segment)) return "{id}";
    if (/^\d+[a-zA-Z0-9]{6,}$/.test(segment)) return "{id}";
    if (/^[\w.-]+\.(?:json|xml|html|js|css|png|jpg|svg|csv|pdf)$/i.test(segment)) return "{file}";
    return segment;
  });
  return `/${templated.join("/")}`;
}

/** Parameter name inferred from the preceding segment: `/users/42` → `{user_id}`. */
function guessParamName(parts: string[], index: number): string {
  const previous = index > 0 ? parts[index - 1] : "";
  if (!previous || previous.startsWith("{") || /\.[a-z0-9]+$/i.test(previous)) return "id";
  const singular = previous.endsWith("s") ? previous.slice(0, -1) : previous;
  return `${singular}_id`;
}

/** Path templates declared as `{id}` in the source, plus query parameter names. */
export function pathParameters(path: string): string[] {
  const fromTemplate = Array.from(path.matchAll(/\{(\w+)\}/g)).map((m) => m[1]);
  return Array.from(new Set(fromTemplate));
}

/* ------------------------------------------------------------------ */
/* OpenAPI / Swagger                                                   */
/* ------------------------------------------------------------------ */

interface OpenApiLike {
  paths?: Record<string, Record<string, unknown> | undefined>;
  openapi?: string;
  swagger?: string;
}

/** Parse OpenAPI 3 and Swagger 2 documents into endpoints. */
export function parseOpenApi(spec: unknown): DiscoveredEndpoint[] {
  if (!spec || typeof spec !== "object") return [];
  const doc = spec as OpenApiLike;
  if (!doc.paths || typeof doc.paths !== "object") return [];

  const endpoints: DiscoveredEndpoint[] = [];
  for (const [rawPath, pathItem] of Object.entries(doc.paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;
    const path = normalizePathTemplate(rawPath);
    const shared = readParameters(pathItem as Record<string, unknown>);

    for (const verb of HTTP_VERBS) {
      const operation = (pathItem as Record<string, unknown>)[verb];
      if (!operation || typeof operation !== "object") continue;
      const own = readParameters(operation as Record<string, unknown>);
      endpoints.push({
        method: verb.toUpperCase(),
        path,
        source: "openapi",
        parameters: Array.from(new Set([...pathParameters(path), ...shared, ...own])),
      });
    }
  }
  return endpoints;
}

function readParameters(node: Record<string, unknown>): string[] {
  const params = node.parameters;
  if (!Array.isArray(params)) return [];
  const names: string[] = [];
  for (const entry of params) {
    if (entry && typeof entry === "object") {
      const name = (entry as { name?: unknown }).name;
      if (typeof name === "string") names.push(name);
    }
  }
  return names;
}

/** Base URL declared by a Swagger 2 document, when present. */
export function openApiBaseUrl(spec: unknown): string | null {
  if (!spec || typeof spec !== "object") return null;
  const doc = spec as Record<string, unknown>;
  if (typeof doc.servers === "object" && doc.servers !== null) {
    const servers = doc.servers as Array<{ url?: unknown }>;
    const first = servers.find((s) => typeof s?.url === "string");
    if (first && typeof first.url === "string") return first.url;
  }
  const host = doc.host;
  const schemes = doc.schemes;
  const basePath = doc.basePath;
  if (typeof host === "string" && host.length > 0) {
    const scheme = Array.isArray(schemes) && typeof schemes[0] === "string" ? schemes[0] : "https";
    const base = typeof basePath === "string" ? basePath : "";
    return `${scheme}://${host}${base}`;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* HTML                                                                */
/* ------------------------------------------------------------------ */

const ATTRIBUTE_PATTERN = /\b(?:href|src|action|formaction|data-url|data-href|data-api)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
const FETCH_PATTERN = /(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest\.prototype\.open|\.open)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
const URL_LITERAL_PATTERN = /(?<![\w$])["']?(?:url|path|endpoint|apiUrl|baseURL|apiBase|resource)["']?\s*[:=]\s*["']([^"']+)["']/gi;

/**
 * Extract candidate endpoints from a real HTML page: navigation links, form
 * actions, script sources and API paths referenced from inline JavaScript.
 * Regex-driven by design — this runs server-side where there is no DOM.
 */
export function parseHtml(html: string, baseUrl?: string): DiscoveredEndpoint[] {
  const found = new Set<string>();
  const patterns = [ATTRIBUTE_PATTERN, FETCH_PATTERN, URL_LITERAL_PATTERN];

  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(html)) !== null) {
      const raw = match[1] ?? match[2] ?? match[3] ?? "";
      if (raw) found.add(raw);
    }
  }

  const endpoints: DiscoveredEndpoint[] = [];
  for (const candidate of found) {
    const resolved = resolveUrl(candidate, baseUrl);
    if (!resolved) continue;
    let url: URL;
    try {
      url = new URL(resolved);
    } catch {
      continue;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") continue;
    if (isStaticAsset(url.pathname) && !/\/api\b/i.test(url.pathname)) continue;

    endpoints.push({
      method: "GET",
      path: normalizePathTemplate(url.pathname || "/"),
      source: "html",
      parameters: pathParameters(url.pathname || "/"),
    });
  }
  return endpoints;
}

/** Bundled assets are noise in an endpoint registry. */
function isStaticAsset(pathname: string): boolean {
  return /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp)(?:\?|$)/i.test(pathname);
}

/** Form methods are recoverable from the tag itself; callers merge them in. */
export function parseForms(html: string, baseUrl?: string): DiscoveredEndpoint[] {
  const formPattern = /<form\b[^>]*>/gi;
  const endpoints: DiscoveredEndpoint[] = [];
  let match: RegExpExecArray | null;
  while ((match = formPattern.exec(html)) !== null) {
    const tag = match[0];
    const action = /\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    const method = /\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    const raw = action?.[1] ?? action?.[2] ?? action?.[3] ?? "";
    const resolved = resolveUrl(raw || "/", baseUrl);
    if (!resolved) continue;
    try {
      const url = new URL(resolved);
      const verb = (method?.[1] ?? method?.[2] ?? method?.[3] ?? "GET").toUpperCase();
      endpoints.push({
        method: ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(verb) ? verb : "POST",
        path: normalizePathTemplate(url.pathname || "/"),
        source: "html",
        parameters: readInputNames(html, tag),
      });
    } catch {
      continue;
    }
  }
  return endpoints;
}

/** Read field names from inside the form the tag belongs to. */
function readInputNames(html: string, formTag: string): string[] {
  const start = html.indexOf(formTag);
  if (start < 0) return [];
  const end = html.indexOf("</form>", start);
  const scope = html.slice(start, end < 0 ? start + 4000 : end);
  const names = Array.from(scope.matchAll(/\bname\s*=\s*["']([^"']+)["']/gi)).map((m) => m[1]);
  return Array.from(new Set(names)).slice(0, 20);
}

/* ------------------------------------------------------------------ */
/* HAR                                                                 */
/* ------------------------------------------------------------------ */

interface HarRequestLike {
  method?: unknown;
  url?: unknown;
  headers?: Array<{ name?: unknown }>;
  queryString?: Array<{ name?: unknown }>;
}

interface HarEntry extends HarRequestLike {
  request?: HarRequestLike;
}

/** Extract endpoints from a browser/proxy HAR export. */
export function parseHar(har: unknown): DiscoveredEndpoint[] {
  const entries = (har as { log?: { entries?: HarEntry[] } } | null)?.log?.entries;
  if (!Array.isArray(entries)) return [];

  const endpoints: DiscoveredEndpoint[] = [];
  for (const entry of entries) {
    // HAR nests everything under `request`; a flat entry is also tolerated.
    const request: HarRequestLike = entry?.request ?? entry;
    if (!request || typeof request.url !== "string" || typeof request.method !== "string") continue;
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      continue;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") continue;

    const query = Array.isArray(request.queryString)
      ? request.queryString.map((q) => String(q?.name ?? "")).filter(Boolean)
      : [];
    const headers = Array.isArray(request.headers)
      ? request.headers.map((h) => String(h?.name ?? "")).filter(Boolean)
      : [];

    endpoints.push({
      method: request.method.toUpperCase(),
      path: normalizePathTemplate(url.pathname || "/"),
      source: "har",
      parameters: Array.from(new Set([...pathParameters(url.pathname), ...query, ...headers])),
    });
  }
  return endpoints;
}

/* ------------------------------------------------------------------ */
/* JavaScript bundles                                                  */
/* ------------------------------------------------------------------ */

const JS_PATH_LITERAL = /["'`]((?:https?:\/\/[^"'`\s]+)?\/(?:api|v\d+|app|auth|admin|graphql|ws|rest|internal|users?|orders?|invoices?|files?|accounts?|payments?|sessions?|settings|reports?)[^"'`\s]*)["'`]/gi;

/** Pull route literals out of a minified bundle. */
export function extractFromJs(source: string, baseUrl?: string): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  const seen = new Set<string>();
  JS_PATH_LITERAL.lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = JS_PATH_LITERAL.exec(source)) !== null) {
    const raw = match[1];
    if (!raw || seen.has(raw)) continue;
    seen.add(raw);
    const resolved = resolveUrl(raw, baseUrl);
    if (!resolved) continue;
    try {
      const url = new URL(resolved);
      if (url.protocol !== "http:" && url.protocol !== "https:") continue;
      endpoints.push({
        method: "GET",
        path: normalizePathTemplate(url.pathname || "/"),
        source: "js",
        parameters: pathParameters(url.pathname || "/"),
      });
    } catch {
      continue;
    }
  }
  return endpoints;
}

/* ------------------------------------------------------------------ */
/* registry helpers                                                    */
/* ------------------------------------------------------------------ */

export function resolveUrl(candidate: string, baseUrl?: string): string | null {
  const trimmed = candidate.trim();
  if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("mailto:") || trimmed.startsWith("tel:")) {
    return null;
  }
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (trimmed.startsWith("/")) {
    if (!baseUrl) return null;
    try {
      return new URL(trimmed, baseUrl).toString();
    } catch {
      return null;
    }
  }
  return null;
}

/** Merge duplicate method/path pairs, keeping the richest parameter set. */
export function mergeEndpoints(list: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const merged = new Map<string, DiscoveredEndpoint>();
  for (const endpoint of list) {
    const key = `${endpoint.method.toUpperCase()} ${endpoint.path}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, endpoint);
      continue;
    }
    existing.parameters = Array.from(new Set([...existing.parameters, ...endpoint.parameters]));
    if (existing.source !== endpoint.source && endpoint.source === "openapi") {
      existing.source = "openapi";
    }
  }
  return Array.from(merged.values()).sort((a, b) =>
    a.path === b.path ? a.method.localeCompare(b.method) : a.path.localeCompare(b.path),
  );
}

/** Endpoints that must be attempted as more than their declared verb. */
export const METHOD_VARIANTS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
