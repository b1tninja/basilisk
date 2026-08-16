import { beforeEach, describe, expect, it } from "vitest";
import {
  expiryCellText,
  keyHitHtml,
  keyMetaChipsHtml,
  keyPillExtrasHtml,
  primaryUidLabel,
  userLabelOf,
} from "../lib/key-hit.js";
import { renderKeysTable } from "../lib/keys.js";
import { setTrust } from "../lib/trust.js";
import { formatFingerprint } from "../lib/utils.js";

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
/**
 * Distinguishable characters, so an assertion about a *part* of a key can fail.
 *
 * `FPR` is forty identical `A`s, which was fine for everything above and useless
 * for the rule below: "the last eight characters are absent" is unprovable on a
 * value whose every eight characters are the same eight. The one that caught
 * this was a real key's shape.
 */
const VARIED = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
/** The 32-bit short key id — the form none of these surfaces may print. */
const SHORT = VARIED.slice(-8);

describe("primaryUidLabel / userLabelOf", () => {
  it("formats name + email UID", () => {
    expect(
      primaryUidLabel({
        fingerprint: FPR,
        approved_uids: [{ name: "Ada", email: "ada@example.com", raw: "Ada <ada@example.com>" }],
      })
    ).toBe("Ada <ada@example.com>");
  });

  it("reads a user label", () => {
    expect(userLabelOf({ label: " Laptop " })).toBe("Laptop");
  });
});

/**
 * No surface here publishes part of a key, and every one of them publishes all
 * of it.
 *
 * A `shortKeyId` printed `…6AD01388` into all three — the results list, the
 * recipient pills and the key table — under the caption "Key ID". Thirty-two
 * bits, on the page whose own copy reads "Short (8-character) key IDs are
 * collision-prone. Confirm the full fingerprint out of band before trusting a
 * key", one row away from the sentence.
 *
 * Both halves are asserted because either alone is satisfiable by an accident:
 * deleting the chip and the fingerprint together would pass an absence test,
 * and lengthening the chip to sixteen would pass a presence test. Neither is
 * the rule. The rule is that the whole value is what identifies a key here and
 * no part of it is offered as a substitute.
 */
describe("the chips tell keys apart without publishing part of one", () => {
  const item = {
    fingerprint: VARIED,
    key_id: "2C5EBBB46AD01388",
    userLabel: "Work YubiKey",
    approved_uids: [{ email: "ada@lovelace.dev", name: "Ada" }],
    approval_state: "approved",
  };

  it("keeps the short key id out of the search-result chips", () => {
    expect(keyMetaChipsHtml(item)).not.toContain(SHORT);
  });

  it("keeps it out of a selected recipient's pill", () => {
    expect(keyPillExtrasHtml(item)).not.toContain(SHORT);
  });

  it("keeps it out of the key table, which prints the whole value above it", () => {
    const table = renderKeysTable([item]);
    expect(table).toContain(formatFingerprint(VARIED));
    // Tags stripped, because the whole ungrouped fingerprint is legitimately in
    // this row twice — the `/key?fpr=` href and the delete button's data
    // attribute — and both of those end in the same eight characters without
    // showing anybody anything. What must not come back is a `…6AD01388` a
    // reader can see and read out. `formatFingerprint` groups in fours, so the
    // printed value cannot satisfy this by accident.
    expect(table.replace(/<[^>]*>/g, " ")).not.toContain(SHORT);
  });

  it("prints the whole fingerprint on the hit itself", () => {
    // The reason the chip was removable rather than shortenable: the value it
    // was a part of is already on the same row.
    expect(keyHitHtml(item)).toContain(formatFingerprint(VARIED));
  });
});

describe("keyMetaChipsHtml", () => {
  it("includes label, trust, revoked and expiry", () => {
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
    // `key_id` is still on the record and still correct — 64 bits, for the
    // vault and HKP lookups that index by it. It is not a chip.
    expect(html).not.toContain("CAFEBABE");
  });

  it("shows no expiry chip when unset", () => {
    const html = keyMetaChipsHtml({
      fingerprint: FPR,
      approval_state: "approved",
    });
    expect(html).toContain("no expiry");
  });

  it("shows upstream origin chip and trusted row class", () => {
    setTrust(FPR, "trusted");
    const chips = keyMetaChipsHtml({
      fingerprint: FPR,
      approval_state: "",
      origin: "upstream",
      source_keyserver: "keys.openpgp.org",
    });
    expect(chips).toContain("keys.openpgp.org");
    expect(chips).toContain("key-chip-origin");
    const hit = keyHitHtml({
      fingerprint: FPR,
      approved_uids: [{ email: "a@b.c", name: "A" }],
      origin: "upstream",
      source_keyserver: "keys.openpgp.org",
    });
    expect(hit).toContain("key-hit-trusted");
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
