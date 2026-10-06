import { describe, expect, it } from "bun:test";
import {
  extractFromJs,
  mergeEndpoints,
  normalizePathTemplate,
  openApiBaseUrl,
  parseForms,
  parseHar,
  parseHtml,
  parseOpenApi,
} from "./discovery";

describe("path templating", () => {
  it("keeps static paths untouched", () => {
    expect(normalizePathTemplate("/api/orders")).toBe("/api/orders");
  });

  it("replaces numeric ids with a parameter named after the resource", () => {
    expect(normalizePathTemplate("/users/42")).toBe("/users/{user_id}");
    expect(normalizePathTemplate("/api/invoices/1001")).toBe("/api/invoices/{invoice_id}");
  });

  it("keeps the parameter for a trailing sub-resource", () => {
    expect(normalizePathTemplate("/orders/5001/refund")).toBe("/orders/{order_id}/refund");
  });

  it("collapses uuid and long-hex ids to id", () => {
    expect(normalizePathTemplate("/files/8f14e45f-ea2d-4b6e-9c1d-2a3b4c5d6e7f")).toBe(
      "/files/{id}",
    );
    expect(normalizePathTemplate("/sessions/abcdef0123456789abcdef")).toBe("/sessions/{id}");
  });

  it("preserves an already-templated path", () => {
    expect(normalizePathTemplate("/pets/{petId}")).toBe("/pets/{petId}");
  });

  it("treats an extension-bearing segment as a file", () => {
    expect(normalizePathTemplate("/files/quarterly-report.pdf")).toBe("/files/{file}");
  });
});

describe("OpenAPI discovery", () => {
  const oas3 = {
    openapi: "3.0.0",
    paths: {
      "/pets": {
        get: { parameters: [{ name: "limit", in: "query" }] },
        post: {},
      },
      "/pets/{petId}": {
        get: {},
        delete: {},
      },
    },
  };

  it("reads every verb of every path", () => {
    const endpoints = parseOpenApi(oas3);
    const keys = endpoints.map((e) => `${e.method} ${e.path}`);
    expect(keys).toContain("GET /pets");
    expect(keys).toContain("POST /pets");
    expect(keys).toContain("GET /pets/{petId}");
    expect(keys).toContain("DELETE /pets/{petId}");
  });

  it("collects operation parameters", () => {
    const endpoints = parseOpenApi(oas3);
    const list = endpoints.find((e) => e.method === "GET" && e.path === "/pets");
    expect(list?.parameters).toContain("limit");
  });

  it("collects path-level parameters", () => {
    const endpoints = parseOpenApi({
      paths: { "/pets": { parameters: [{ name: "tenant" }], get: {} } },
    });
    expect(endpoints[0].parameters).toContain("tenant");
  });

  it("tags the source so the report can attribute it", () => {
    expect(parseOpenApi(oas3)[0].source).toBe("openapi");
  });

  it("returns nothing for input it cannot use", () => {
    expect(parseOpenApi(null)).toEqual([]);
    expect(parseOpenApi({})).toEqual([]);
    expect(parseOpenApi("not a spec")).toEqual([]);
  });

  it("derives a Swagger 2 base url", () => {
    expect(
      openApiBaseUrl({
        swagger: "2.0",
        host: "api.acme.test",
        basePath: "/v2",
        schemes: ["https"],
        paths: {},
      }),
    ).toBe("https://api.acme.test/v2");
  });

  it("reads OpenAPI 3 servers", () => {
    expect(openApiBaseUrl({ openapi: "3.0.0", servers: [{ url: "https://api.acme.test" }] })).toBe(
      "https://api.acme.test",
    );
  });
});

describe("HTML discovery", () => {
  const page = `<!doctype html>
    <html><head><link rel="stylesheet" href="/static/app.css" /></head>
    <body>
      <a href="/api/orders">Orders</a>
      <a href='https://staging.acme.test/api/invoices/1001'>Invoice</a>
      <script src="/static/bundle.js"></script>
      <script>
        fetch("/api/users/123");
        const conf = { endpoint: "/api/reports" };
      </script>
    </body></html>`;

  it("extracts links, inline fetch calls and config literals", () => {
    const paths = parseHtml(page, "https://staging.acme.test").map((e) => e.path);
    expect(paths).toContain("/api/orders");
    expect(paths).toContain("/api/invoices/{invoice_id}");
    expect(paths).toContain("/api/users/{user_id}");
    expect(paths).toContain("/api/reports");
  });

  it("ignores bundled assets", () => {
    const paths = parseHtml(page, "https://staging.acme.test").map((e) => e.path);
    expect(paths).not.toContain("/static/app.css");
    expect(paths).not.toContain("/static/bundle.js");
  });

  it("ignores in-page and mailto links", () => {
    const paths = parseHtml('<a href="#top">t</a><a href="mailto:x@y.test">m</a>').map((e) => e.path);
    expect(paths).toEqual([]);
  });

  it("recovers form methods and field names", () => {
    const forms = parseForms(
      '<form action="/login" method="POST"><input name="email" /><input name="password" /></form>',
      "https://staging.acme.test",
    );
    expect(forms).toHaveLength(1);
    expect(forms[0].method).toBe("POST");
    expect(forms[0].path).toBe("/login");
    expect(forms[0].parameters).toEqual(expect.arrayContaining(["email", "password"]));
  });
});

describe("HAR discovery", () => {
  it("reads method, path and query parameters", () => {
    const endpoints = parseHar({
      log: {
        entries: [
          {
            request: {
              method: "post",
              url: "https://api.acme.test/v1/orders?expand=items",
              queryString: [{ name: "expand" }],
            },
          },
          { request: { method: "GET", url: "::invalid::" } },
        ],
      },
    });
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].method).toBe("POST");
    expect(endpoints[0].path).toBe("/v1/orders");
    expect(endpoints[0].parameters).toContain("expand");
  });

  it("returns nothing for a malformed HAR", () => {
    expect(parseHar(null)).toEqual([]);
    expect(parseHar({ log: { entries: "nope" } })).toEqual([]);
  });
});

describe("JavaScript bundle discovery", () => {
  it("pulls route literals out of a bundle", () => {
    const source = `const a="/api/invoices";axios.post("/api/payments");fetch("/graphql")`;
    const paths = extractFromJs(source, "https://staging.acme.test").map((e) => e.path);
    expect(paths).toContain("/api/invoices");
    expect(paths).toContain("/api/payments");
    expect(paths).toContain("/graphql");
  });

  it("ignores unrelated string literals", () => {
    const paths = extractFromJs('const color="#ff0000"; const name="Vinod";').map((e) => e.path);
    expect(paths).toEqual([]);
  });
});

describe("registry merging", () => {
  it("deduplicates on method and path", () => {
    const merged = mergeEndpoints([
      { method: "GET", path: "/api/orders", source: "html", parameters: [] },
      { method: "GET", path: "/api/orders", source: "openapi", parameters: ["expand"] },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0].parameters).toContain("expand");
    expect(merged[0].source).toBe("openapi");
  });

  it("keeps distinct methods separate", () => {
    const merged = mergeEndpoints([
      { method: "GET", path: "/api/orders", source: "html", parameters: [] },
      { method: "POST", path: "/api/orders", source: "html", parameters: [] },
    ]);
    expect(merged).toHaveLength(2);
  });

  it("sorts deterministically so runs are reproducible", () => {
    const merged = mergeEndpoints([
      { method: "POST", path: "/b", source: "html", parameters: [] },
      { method: "GET", path: "/a", source: "html", parameters: [] },
    ]);
    expect(merged.map((e) => `${e.method} ${e.path}`)).toEqual(["GET /a", "POST /b"]);
  });
});
