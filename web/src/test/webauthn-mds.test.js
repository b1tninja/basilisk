/**
 * WebAuthn attestation parse + soft MDS JWT helpers.
 */
import { describe, expect, it } from "vitest";
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
      localStorage?.removeItem?.("basilisk.mdsBlob.v1");
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
      localStorage?.removeItem?.("basilisk.mdsBlob.v1");
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
