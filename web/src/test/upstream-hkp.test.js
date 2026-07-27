/**
 * Upstream config + HKP client unit tests (mocked fetch).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  _resetUpstreamConfigCache,
  isKeyserverAllowed,
  normalizeKeyserverHost,
} from "../lib/upstream-config.js";
import { hkpLookupUrl, upstreamLookupGet } from "../lib/upstream-hkp.js";

beforeEach(() => {
  _resetUpstreamConfigCache();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      const u = String(url);
      if (u.includes("/api/v1/config")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            upstream: {
              enabled: true,
              allowlist: ["keys.openpgp.org", "keys.mailvelope.com"],
              default: "keys.openpgp.org",
            },
          }),
        };
      }
      throw new Error(`unexpected ${u}`);
    })
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  _resetUpstreamConfigCache();
});

describe("normalizeKeyserverHost", () => {
  it("accepts host and hkps URLs", () => {
    expect(normalizeKeyserverHost("keys.openpgp.org")).toBe("keys.openpgp.org");
    expect(normalizeKeyserverHost("hkps://keys.openpgp.org/pks")).toBe(
      "keys.openpgp.org"
    );
    expect(normalizeKeyserverHost("KEYS.Mailvelope.COM:443")).toBe(
      "keys.mailvelope.com"
    );
  });

  it("rejects IP literals, userinfo, and junk", () => {
    expect(normalizeKeyserverHost("127.0.0.1")).toBeNull();
    expect(normalizeKeyserverHost("http://user@evil.com")).toBeNull();
    expect(normalizeKeyserverHost("localhost")).toBeNull();
    expect(normalizeKeyserverHost("")).toBeNull();
  });
});

describe("allowlist + lookup", () => {
  it("isKeyserverAllowed respects list", () => {
    const allow = ["keys.openpgp.org"];
    expect(isKeyserverAllowed("keys.openpgp.org", allow)).toBe(true);
    expect(isKeyserverAllowed("evil.example", allow)).toBe(false);
  });

  it("builds HKP URL", () => {
    expect(hkpLookupUrl("keys.openpgp.org", "a@b.c")).toContain(
      "https://keys.openpgp.org/pks/lookup?"
    );
    expect(hkpLookupUrl("keys.openpgp.org", "a@b.c")).toContain("op=get");
  });

  it("upstreamLookupGet returns armor and rejects off-allowlist", async () => {
    const armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nx\n-----END PGP PUBLIC KEY BLOCK-----";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const u = String(url);
        if (u.includes("/api/v1/config")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              upstream: {
                enabled: true,
                allowlist: ["keys.openpgp.org"],
                default: "keys.openpgp.org",
              },
            }),
          };
        }
        if (u.includes("keys.openpgp.org")) {
          return {
            ok: true,
            status: 200,
            url: u,
            arrayBuffer: async () => new TextEncoder().encode(armor).buffer,
          };
        }
        throw new Error(u);
      })
    );
    const got = await upstreamLookupGet("keys.openpgp.org", "test@example.com");
    expect(got).toContain("BEGIN PGP");
    await expect(upstreamLookupGet("evil.example", "x")).rejects.toThrow(
      /allowlist/i
    );
  });
});
