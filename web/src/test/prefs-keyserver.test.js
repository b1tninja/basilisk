/**
 * Preferred upstream keyserver preference (localStorage).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  getPreferredKeyserver,
  setPreferredKeyserver,
} from "../lib/prefs.js";
import {
  _resetUpstreamConfigCache,
  resolveUpstreamHost,
} from "../lib/upstream-config.js";

function installMemoryLocalStorage() {
  /** @type {Map<string, string>} */
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => {
      store.set(String(k), String(v));
    },
    removeItem: (k) => {
      store.delete(k);
    },
    clear: () => {
      store.clear();
    },
    key: (i) => [...store.keys()][i] ?? null,
    get length() {
      return store.size;
    },
  };
}

installMemoryLocalStorage();

beforeEach(() => {
  localStorage.clear();
  _resetUpstreamConfigCache();
  vi.unstubAllGlobals();
});

describe("preferred keyserver prefs", () => {
  it("get/set/clear preferred keyserver", () => {
    expect(getPreferredKeyserver()).toBe("");
    setPreferredKeyserver("keys.mailvelope.com");
    expect(getPreferredKeyserver()).toBe("keys.mailvelope.com");
    setPreferredKeyserver("");
    expect(getPreferredKeyserver()).toBe("");
  });

  it("resolveUpstreamHost prefers localStorage over server default", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        if (String(url).includes("/api/v1/config")) {
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
        throw new Error(String(url));
      })
    );
    setPreferredKeyserver("keys.mailvelope.com");
    expect(await resolveUpstreamHost()).toBe("keys.mailvelope.com");
    expect(await resolveUpstreamHost("keys.openpgp.org")).toBe(
      "keys.openpgp.org"
    );
    setPreferredKeyserver("evil.example");
    // Not on allowlist → fall back to server default
    expect(await resolveUpstreamHost()).toBe("keys.openpgp.org");
  });
});
