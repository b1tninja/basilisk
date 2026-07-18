import { beforeEach, describe, expect, it } from "vitest";
import {
  expiryCellText,
  keyHitHtml,
  keyMetaChipsHtml,
  keyPillExtrasHtml,
  primaryUidLabel,
  shortKeyId,
  userLabelOf,
} from "../lib/key-hit.js";
import { setTrust } from "../lib/trust.js";

/** Minimal localStorage for Node vitest. */
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

/** Minimal document for escapeHtml (utils.js uses createElement). */
if (typeof document === "undefined") {
  globalThis.document = {
    createElement: () => {
      let text = "";
      return {
        set textContent(v) {
          text = v == null ? "" : String(v);
        },
        get textContent() {
          return text;
        },
        get innerHTML() {
          return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
        },
      };
    },
  };
}

beforeEach(() => {
  localStorage.clear();
});

const FPR = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("primaryUidLabel / userLabelOf / shortKeyId", () => {
  it("formats name + email UID", () => {
    expect(
      primaryUidLabel({
        fingerprint: FPR,
        approved_uids: [{ name: "Ada", email: "ada@example.com", raw: "Ada <ada@example.com>" }],
      })
    ).toBe("Ada <ada@example.com>");
  });

  it("reads user label and short key id", () => {
    expect(userLabelOf({ label: " Laptop " })).toBe("Laptop");
    expect(
      shortKeyId({ fingerprint: FPR, key_id: "1122334455667788" })
    ).toBe("55667788");
    expect(shortKeyId({ fingerprint: FPR })).toBe("AAAAAAAA");
  });
});

describe("keyMetaChipsHtml", () => {
  it("includes label, trust, revoked, expiry, and key id", () => {
    setTrust(FPR, "trusted");
    const html = keyMetaChipsHtml({
      fingerprint: FPR,
      label: "Work YubiKey",
      revoked: true,
      key_expiration: "2020-01-01T00:00:00Z",
      key_id: "DEADBEEFCAFEBABE",
      approval_state: "approved",
    });
    expect(html).toContain("Work YubiKey");
    expect(html).toContain("trusted");
    expect(html).toContain("revoked");
    expect(html).toContain("Expired");
    expect(html).toContain("CAFEBABE");
  });

  it("shows no expiry chip when unset", () => {
    const html = keyMetaChipsHtml({
      fingerprint: FPR,
      approval_state: "approved",
    });
    expect(html).toContain("no expiry");
  });
});

describe("keyHitHtml / keyPillExtrasHtml / expiryCellText", () => {
  it("renders a selectable hit with chips and Added state", () => {
    const html = keyHitHtml(
      {
        fingerprint: FPR,
        label: "Backup",
        approved_uids: [{ email: "a@b.c", name: "A" }],
        approval_state: "approved",
      },
      { already: true, dataAttrs: { "data-add-fpr": FPR } }
    );
    expect(html).toContain("data-add-fpr=");
    expect(html).toContain("disabled");
    expect(html).toContain("Added");
    expect(html).toContain("Backup");
    expect(html).toContain("A &lt;a@b.c&gt;");
  });

  it("pill extras include label and warn expiry", () => {
    const soon = new Date(Date.now() + 5 * 86400000).toISOString();
    const html = keyPillExtrasHtml({
      fingerprint: FPR,
      userLabel: "Travel",
      keyExpiration: soon,
    });
    expect(html).toContain("Travel");
    expect(html).toContain("Expires");
  });

  it("expiryCellText for missing and expired", () => {
    expect(expiryCellText({})).toBe("—");
    expect(expiryCellText({ key_expiration: "2010-01-01T00:00:00Z" })).toMatch(
      /Expired/i
    );
  });
});
