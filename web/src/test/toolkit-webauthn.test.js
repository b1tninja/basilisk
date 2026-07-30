/**
 * WebAuthn toolbox registry shelves + attest/mds ops (no live authenticator).
 */
import { describe, expect, it } from "vitest";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import {
  SHELF_META,
  TOOLBOX_META,
  getShelfMeta,
  getStep,
  listSteps,
  recipeNeedsMainThread,
} from "../lib/toolkit/registry.js";
import { formatType, inferSourceType } from "../lib/toolkit/types.js";
import { execWaAttest, execWaCaps, execWaMds } from "../lib/toolkit/webauthn-ops.js";
import { ZERO_AAGUID } from "../lib/webauthn/attestation.js";

/** Encode a tiny CBOR map { fmt: "none", authData: <bytes> }. */
function encodeAttestation(authData) {
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
  out[0] = 0xa2;
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

describe("webauthn toolbox shelves", () => {
  it("registers webauthn toolbox and shelf meta", () => {
    expect(TOOLBOX_META.webauthn?.badge).toBe("WebAuthn");
    expect(SHELF_META.essentials.defaultCollapsed).toBe(false);
    expect(SHELF_META.attestation.defaultCollapsed).toBe(true);
    expect(getShelfMeta("attestation").label).toMatch(/Attestation/);
  });

  it("places webauthn.* ops on essentials vs attestation shelves", () => {
    const byName = Object.fromEntries(listSteps().map((s) => [s.name, s]));
    expect(byName["webauthn.caps"].toolbox).toBe("webauthn");
    expect(byName["webauthn.caps"].shelf).toBe("essentials");
    expect(byName["webauthn.create"].shelf).toBe("essentials");
    expect(byName["webauthn.prf"].shelf).toBe("essentials");
    expect(byName["webauthn.attest"].shelf).toBe("attestation");
    expect(byName["webauthn.mds"].shelf).toBe("attestation");
  });

  it("recipeNeedsMainThread detects webauthn steps", () => {
    const { ast: plain } = compileRecipe("random 16 | encode hex");
    expect(recipeNeedsMainThread(plain)).toBe(false);
    const { ast: wa } = compileRecipe("webauthn.caps");
    expect(recipeNeedsMainThread(wa)).toBe(true);
    expect(getStep("webauthn.prf")?.toolbox).toBe("webauthn");
  });

  it("inferSourceType types webauthn sources for piping", () => {
    expect(formatType(inferSourceType("webauthn.caps"))).toBe("text/opaque");
    expect(formatType(inferSourceType("webauthn.get"))).toBe("text/opaque");
    expect(formatType(inferSourceType("webauthn.create"))).toBe("bytes/opaque");
    expect(formatType(inferSourceType("webauthn.prf"))).toBe("bytes/opaque");
    expect(compileRecipe("webauthn.create | encode hex").validation.ok).toBe(true);
    expect(compileRecipe("webauthn.get | out @a").validation.ok).toBe(true);
  });
});

describe("webauthn ops (offline)", () => {
  it("webauthn.caps returns JSON without throwing when WebAuthn is absent", async () => {
    const out = await execWaCaps();
    expect(out.type).toBe("text");
    const caps = JSON.parse(out.data);
    expect(typeof caps.publicKeyCredential).toBe("boolean");
  });

  it("webauthn.attest parses attestationObject bytes", async () => {
    const withAaguid = new Uint8Array(55);
    withAaguid[32] = 0x41; // flags: AT
    for (let i = 0; i < 16; i++) withAaguid[37 + i] = i;
    const att = encodeAttestation(withAaguid);
    const out = await execWaAttest({ type: "bytes", data: att });
    const body = JSON.parse(out.data);
    expect(body.fmt).toBe("none");
    expect(body.aaguid).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("webauthn.attest accepts base64 text from Inputs", async () => {
    const withAaguid = new Uint8Array(55);
    withAaguid[32] = 0x41;
    for (let i = 0; i < 16; i++) withAaguid[37 + i] = i;
    const att = encodeAttestation(withAaguid);
    let b64 = "";
    for (let i = 0; i < att.length; i++) b64 += String.fromCharCode(att[i]);
    b64 = btoa(b64);
    const out = await execWaAttest({ type: "text", data: b64 });
    expect(JSON.parse(out.data).fmt).toBe("none");
  });

  it("webauthn.attest empty input hints at Templates → WebAuthn", async () => {
    await expect(execWaAttest(null)).rejects.toThrow(/Templates → WebAuthn/);
  });

  it("input | webauthn.attest | webauthn.mds typechecks (Attestation → MDS template)", () => {
    const { validation } = compileRecipe(
      `input | webauthn.attest | out @att

in @att | webauthn.mds | out @mds`
    );
    expect(validation.ok, validation.errors?.[0]?.message).toBe(true);
  });

  it("webauthn.mds returns unverified for zero AAGUID without network", async () => {
    const out = await execWaMds(null, { aaguid: ZERO_AAGUID });
    const body = JSON.parse(out.data);
    expect(body.status).toBe("unverified");
    expect(body.aaguid).toBe(ZERO_AAGUID);
  });
});
