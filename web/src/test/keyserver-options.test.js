/**
 * Keyserver dropdown option list (This site + preferred + allowlist).
 */
import { describe, expect, it } from "vitest";
import { buildKeyserverOptions } from "../lib/keyserver-select.js";
import { hkpLookupUrl, pageKeyserverOrigin } from "../lib/upstream-hkp.js";

describe("buildKeyserverOptions", () => {
  it("labels This site with page origin and keeps empty value", () => {
    const opts = buildKeyserverOptions({
      pageOrigin: "https://keys.example.com:8443",
      allowlist: ["keys.openpgp.org"],
    });
    expect(opts[0]).toEqual({
      value: "",
      label: "This site (https://keys.example.com:8443)",
    });
    expect(opts.some((o) => o.value === "keys.openpgp.org")).toBe(true);
  });

  it("inserts preferred upstream without duplicating allowlist", () => {
    const opts = buildKeyserverOptions({
      pageOrigin: "http://localhost:5173",
      preferred: "keys.mailvelope.com",
      allowlist: ["keys.openpgp.org", "keys.mailvelope.com"],
    });
    const values = opts.map((o) => o.value);
    expect(values.filter((v) => v === "keys.mailvelope.com")).toHaveLength(1);
    expect(opts.find((o) => o.value === "keys.mailvelope.com")?.label).toMatch(
      /Preferred upstream/
    );
  });

  it("includes current host when missing from allowlist", () => {
    const opts = buildKeyserverOptions({
      pageOrigin: null,
      allowlist: [],
      current: "keys.openpgp.org",
    });
    expect(opts[0].label).toBe("This site");
    expect(opts.some((o) => o.value === "keys.openpgp.org")).toBe(true);
  });
});

describe("HKP URL wire parity", () => {
  it("This site and upstream share path + query (host/origin differ)", () => {
    const search = "alice@example.com";
    const local = new URL(hkpLookupUrl("https://keys.example.com:8443", search));
    const up = new URL(hkpLookupUrl("keys.openpgp.org", search));
    expect(local.pathname).toBe("/pks/lookup");
    expect(up.pathname).toBe(local.pathname);
    expect(local.searchParams.get("op")).toBe("get");
    expect(up.searchParams.get("op")).toBe(local.searchParams.get("op"));
    expect(local.searchParams.get("options")).toBe("mr");
    expect(up.searchParams.get("options")).toBe("mr");
    expect(local.searchParams.get("search")).toBe(search);
    expect(up.searchParams.get("search")).toBe(search);
    expect(local.origin).toBe("https://keys.example.com:8443");
    expect(up.origin).toBe("https://keys.openpgp.org");
  });

  it("builds op=index with options=mr", () => {
    const url = hkpLookupUrl("https://example.test", "0xABCDEF", { op: "index" });
    const u = new URL(url);
    expect(u.searchParams.get("op")).toBe("index");
    expect(u.searchParams.get("options")).toBe("mr");
    expect(u.searchParams.get("search")).toBe("0xABCDEF");
  });

  it("pageKeyserverOrigin reads location.origin", () => {
    expect(pageKeyserverOrigin({ origin: "https://a.example:9" })).toBe(
      "https://a.example:9"
    );
    expect(pageKeyserverOrigin({ origin: "null" })).toBeNull();
  });
});
