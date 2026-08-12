/**
 * WebAuthn attestation parse + soft MDS JWT helpers.
 */
import { beforeAll, describe, expect, it } from "vitest";

/**
 * A localStorage for Node, the way `device-label.test.js` and `key-hit.test.js`
 * already do it.
 *
 * `mds.js` caches the blob in localStorage, and these tests clear that cache so
 * the mocked fetch is the thing under test. Without a stub they ran one path
 * locally and a different one in CI: Node 22 has no `localStorage`, Node 25
 * does, so the cache branch was exercised on a developer's machine and skipped
 * on the runner. The stub makes it the same code either way, which is the point
 * of the clearing.
 *
 * The old guard was `localStorage?.removeItem?.(…)`, which reads as safe and is
 * not: optional chaining protects a binding whose *value* may be nullish, never
 * one that was never declared. On Node 22 that line threw ReferenceError, and
 * the surrounding `try` had a `finally` and no `catch`, so it propagated.
 */
beforeAll(() => {
  // Installed unconditionally. Node 25 *has* a `localStorage` global under its
  // experimental web storage, but without a backing store file its methods are
  // not callable — so deferring to the ambient one trades a ReferenceError on
  // Node 22 for a TypeError on Node 25. The tests own this object.
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
  };
});
import {
  ZERO_AAGUID,
  decodeCbor,
  parseAttestationObject,
} from "../lib/webauthn/attestation.js";
import {
  decodeJwtPayload,
  lookupAaguidInMds,
  mdsStatusBadgeHtml,
  normalizeAaguid,
} from "../lib/webauthn/mds.js";

/** Encode a tiny CBOR map { fmt: "none", authData: <bytes> }. */
function encodeAttestation(authData) {
  // Manual CBOR: map(2), text("fmt"), text("none"), text("authData"), bytes(authData)
  const encText = (s) => {
    const b = new TextEncoder().encode(s);
    return new Uint8Array([0x60 | b.length, ...b]);
  };
  const encBytes = (b) => {
    if (b.length < 24) return new Uint8Array([0x40 | b.length, ...b]);
    return new Uint8Array([0x58, b.length, ...b]);
  };
  const fmt = encText("fmt");
  const none = encText("none");
  const adk = encText("authData");
  const ad = encBytes(authData);
  const out = new Uint8Array(1 + fmt.length + none.length + adk.length + ad.length);
  out[0] = 0xa2; // map of 2
  let o = 1;
  out.set(fmt, o);
  o += fmt.length;
  out.set(none, o);
  o += none.length;
  out.set(adk, o);
  o += adk.length;
  out.set(ad, o);
  return out;
}

function authDataWithAaguid(aaguidHex32) {
  const ad = new Uint8Array(55);
  ad[32] = 0x40; // AT flag
  const hex = aaguidHex32.replace(/-/g, "");
  for (let i = 0; i < 16; i++) {
    ad[37 + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return ad;
}

describe("webauthn attestation", () => {
  it("decodes CBOR maps and byte strings", () => {
    const ad = new Uint8Array([1, 2, 3]);
    const obj = encodeAttestation(ad);
    const { value } = decodeCbor(obj);
    expect(value.get("fmt")).toBe("none");
    expect([...value.get("authData")]).toEqual([1, 2, 3]);
  });

  it("extracts AAGUID from attestationObject", () => {
    const aaguid = "2fc0579f-8113-47ea-b116-bb5a8db9202a";
    const obj = encodeAttestation(authDataWithAaguid(aaguid));
    const parsed = parseAttestationObject(obj);
    expect(parsed?.aaguid).toBe(aaguid);
    expect(parsed?.fmt).toBe("none");
  });

  it("returns zero AAGUID when AT flag missing", () => {
    const ad = new Uint8Array(37);
    ad[32] = 0x01; // UP only
    const parsed = parseAttestationObject(encodeAttestation(ad));
    expect(parsed?.aaguid).toBe(ZERO_AAGUID);
  });
});

describe("mds helpers", () => {
  it("normalizes AAGUID forms", () => {
    expect(normalizeAaguid("2FC0579F811347EAB116BB5A8DB9202A")).toBe(
      "2fc0579f-8113-47ea-b116-bb5a8db9202a"
    );
  });

  it("decodes JWT payload", () => {
    const header = btoa(JSON.stringify({ alg: "none" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const body = btoa(
      JSON.stringify({
        entries: [
          {
            aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a",
            metadataStatement: { description: "YubiKey Test" },
            statusReports: [{ status: "FIDO_CERTIFIED", effectiveDate: "2020-01-01" }],
          },
        ],
      })
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const payload = decodeJwtPayload(`${header}.${body}.sig`);
    expect(payload.entries).toHaveLength(1);
  });

  it("lookup marks listed AAGUID verified (mocked fetch)", async () => {
    const header = btoa("{}").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const body = btoa(
      JSON.stringify({
        entries: [
          {
            aaguid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            metadataStatement: { description: "Acme Key" },
            statusReports: [{ status: "FIDO_CERTIFIED_L1", effectiveDate: "2024-01-01" }],
          },
        ],
      })
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const jwt = `${header}.${body}.x`;

    const prev = globalThis.fetch;
    globalThis.fetch = async () =>
      /** @type {Response} */ ({
        ok: true,
        status: 200,
        text: async () => jwt,
      });
    try {
      localStorage.removeItem("basilisk.mdsBlob.v1");
      const r = await lookupAaguidInMds("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
      // lookupAaguidInMds returns one of "verified" | "unverified" |
      // "unavailable" — never a boolean-ish string.
      expect(r.status).toBe("verified");
      expect(r.description).toBe("Acme Key");
    } finally {
      globalThis.fetch = prev;
    }
  });

  it("lookup marks adverse status unverified", async () => {
    const header = btoa("{}").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const body = btoa(
      JSON.stringify({
        entries: [
          {
            aaguid: "11111111-2222-3333-4444-555555555555",
            metadataStatement: { description: "Broken Key" },
            statusReports: [
              { status: "FIDO_CERTIFIED", effectiveDate: "2020-01-01" },
              { status: "REVOKED", effectiveDate: "2024-06-01" },
            ],
          },
        ],
      })
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const jwt = `${header}.${body}.x`;
    const prev = globalThis.fetch;
    globalThis.fetch = async () =>
      /** @type {Response} */ ({
        ok: true,
        status: 200,
        text: async () => jwt,
      });
    try {
      localStorage.removeItem("basilisk.mdsBlob.v1");
      const r = await lookupAaguidInMds("11111111-2222-3333-4444-555555555555");
      expect(r.status).toBe("unverified");
      expect(r.detail).toMatch(/REVOKED/);
    } finally {
      globalThis.fetch = prev;
    }
  });

  it("badge HTML covers statuses", () => {
    expect(mdsStatusBadgeHtml("verified")).toMatch(/MDS verified/);
    expect(mdsStatusBadgeHtml("unverified")).toMatch(/MDS unverified/);
    expect(mdsStatusBadgeHtml("unavailable")).toMatch(/MDS unavailable/);
  });
});
