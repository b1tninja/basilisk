import { describe, expect, it } from "vitest";
import {
  compareFingerprints,
  findFingerprints,
  findShortKeyIds,
  normalizeFingerprintInput,
  normalizeSearchQuery,
} from "../lib/pgp/verify-fpr.js";
import { formatFingerprint } from "../lib/utils.js";

describe("verify-fpr", () => {
  it("normalizes openpgp4fpr URIs and spaced hex", () => {
    expect(
      normalizeFingerprintInput("openpgp4fpr:abb3a7283d5ee084295cf439fdba0d5445aa8148")
    ).toBe("ABB3A7283D5EE084295CF439FDBA0D5445AA8148");
    expect(
      normalizeFingerprintInput("ABB3 A728 3D5E E084 295C F439 FDBA 0D54 45AA 8148")
    ).toBe("ABB3A7283D5EE084295CF439FDBA0D5445AA8148");
  });

  it("PASS when fingerprints match", () => {
    const fpr = "ABB3A7283D5EE084295CF439FDBA0D5445AA8148";
    const r = compareFingerprints(fpr, `openpgp4fpr:${fpr.toLowerCase()}`);
    expect(r.ok).toBe(true);
  });

  it("FAIL on mismatch", () => {
    const r = compareFingerprints(
      "ABB3A7283D5EE084295CF439FDBA0D5445AA8148",
      "0000000000000000000000000000000000000000"
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/do not match/i);
  });

  it("normalizeSearchQuery strips spaces from fingerprints", () => {
    expect(
      normalizeSearchQuery("ABB3 A728 3D5E E084 295C F439 FDBA 0D54 45AA 8148")
    ).toBe("ABB3A7283D5EE084295CF439FDBA0D5445AA8148");
    expect(normalizeSearchQuery("alice@example.com")).toBe("alice@example.com");
    expect(normalizeSearchQuery("Alice Example")).toBe("Alice Example");
  });

  it("normalizeSearchQuery keeps common-length hex fingerprints contiguous", () => {
    expect(normalizeSearchQuery("0xdeadbeef")).toBe("DEADBEEF"); // 8 short key ID
    expect(normalizeSearchQuery("0xdeadbeefcafebabe")).toBe("DEADBEEFCAFEBABE"); // 16
    expect(
      normalizeSearchQuery("AABB CCDD EEFF 0011 2233 4455 6677 8899")
    ).toBe("AABBCCDDEEFF00112233445566778899"); // 32 partial
    // Non-standard / short all-hex stay as text (name search)
    expect(normalizeSearchQuery("FDBA 0D54 45AA")).toBe("FDBA 0D54 45AA");
    expect(normalizeSearchQuery("Ada")).toBe("Ada");
    expect(normalizeSearchQuery("Cafe")).toBe("Cafe");
  });
});

/* ───────────────── extraction, beside the normaliser ───────────────── */

const V4 = "ABB3A7283D5EE084295CF439FDBA0D5445AA8148";
const V4B = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const V6 = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388D772078C5C7C2A0EDCA09ED3";

describe("findFingerprints recovers everything formatFingerprint prints", () => {
  it("round-trips one printed fingerprint, v4 and v6", () => {
    // The reported bug, as a property. `formatFingerprint` groups hex into
    // four-character blocks, so My Keys, the Keyring and every roster row print
    // `AABB CCDD …` — and the extractor wanted one contiguous run of 40 to 64,
    // which a grouped fingerprint is not. Ten runs of four matched nothing and
    // the paste silently yielded zero.
    for (const fpr of [V4, V4B, V6]) {
      expect(findFingerprints(formatFingerprint(fpr)), fpr).toEqual([fpr]);
    }
  });

  it("round-trips a printed list, in each form this product emits", () => {
    // `#j=a,b` writes commas and the paste box gets one per line, which is
    // exactly why neither is a separator *inside* a fingerprint: folding either
    // into that class would glue two grouped fingerprints into one 80-character
    // run and lose both.
    for (const [a, b] of [[V4, V4B], [V4, V6], [V6, V4B]]) {
      for (const sep of [",", "\n", ", ", ",\n", "\r\n"]) {
        const text = `${formatFingerprint(a)}${sep}${formatFingerprint(b)}`;
        expect(findFingerprints(text).sort(), JSON.stringify(text)).toEqual([a, b].sort());
      }
    }
  });

  it("takes the separators a person actually types", () => {
    expect(findFingerprints(V4.replace(/(.{4})(?=.)/g, "$1:"))).toEqual([V4]);
    expect(findFingerprints(V4.replace(/(.{4})(?=.)/g, "$1-"))).toEqual([V4]);
    expect(findFingerprints(`0x${V4}`)).toEqual([V4]);
    expect(findFingerprints(`openpgp4fpr:${V4.toLowerCase()}`)).toEqual([V4]);
  });

  it("keeps two contiguous fingerprints apart, and invents nothing when it cannot", () => {
    // The quieter half of the same defect: `{40,64}` on an unseparated pair
    // matched the first 64 characters and fabricated an id belonging to
    // nobody. Taking 40 or 64 out of an 80-character blob is a guess about
    // where the boundary was, and a room derived from a guess is worse than a
    // paste that says it found nothing.
    expect(findFingerprints(`${V4}${V4B}`)).toEqual([]);
    // Separated by anything at all, both survive.
    expect(findFingerprints(`${V4} ${V4B}`).sort()).toEqual([V4, V4B].sort());
    expect(findFingerprints(`${V4},${V4B}`).sort()).toEqual([V4, V4B].sort());
    // And the same refusal one level up: two *grouped* fingerprints with only a
    // space between them are blocks of four all the way across, so where one
    // ends is a guess. `formatFingerprint` never prints a pair that way — the
    // product's lists are comma- or newline-separated, and both are recovered
    // above — so the honest answer here is none rather than a boundary picked
    // by the parser.
    expect(findFingerprints(`${formatFingerprint(V4)} ${formatFingerprint(V4B)}`)).toEqual([]);
  });

  it("finds a grouped fingerprint beside a contiguous one", () => {
    // The two printed forms in one paste — which is what happens when somebody
    // copies one out of the Keyring and one out of a URL.
    expect(
      findFingerprints(`${V4} ${formatFingerprint(V4B)}`).sort()
    ).toEqual([V4, V4B].sort());
  });

  it("pulls a fingerprint out of the prose around it", () => {
    expect(findFingerprints(`Ada is here: ${formatFingerprint(V4)} — add her.`)).toEqual([V4]);
    expect(findFingerprints("nothing here")).toEqual([]);
    expect(findFingerprints("")).toEqual([]);
  });

  it("says each fingerprint once, however many times it was pasted", () => {
    expect(findFingerprints(`${V4}\n${formatFingerprint(V4)}`)).toEqual([V4]);
  });
});

describe("findShortKeyIds names the ids a room cannot be derived from", () => {
  it("finds the lengths SEARCH_HEX_LENGTHS calls collision-prone", () => {
    expect(findShortKeyIds("0xDEADBEEF")).toEqual(["DEADBEEF"]);
    expect(findShortKeyIds(V4.slice(-16))).toEqual([V4.slice(-16)]);
    expect(findShortKeyIds(V4.slice(0, 32))).toEqual([V4.slice(0, 32)]);
  });

  it("is silent about a whole fingerprint, which is not a short id", () => {
    expect(findShortKeyIds(formatFingerprint(V4))).toEqual([]);
    expect(findShortKeyIds(V6)).toEqual([]);
    expect(findShortKeyIds("nothing here")).toEqual([]);
  });
});
