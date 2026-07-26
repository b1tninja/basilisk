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

  it("places wa-* ops on essentials vs attestation shelves", () => {
    const byName = Object.fromEntries(listSteps().map((s) => [s.name, s]));
    expect(byName["wa-caps"].toolbox).toBe("webauthn");
    expect(byName["wa-caps"].shelf).toBe("essentials");
    expect(byName["wa-create"].shelf).toBe("essentials");
    expect(byName["wa-prf"].shelf).toBe("essentials");
    expect(byName["wa-attest"].shelf).toBe("attestation");
    expect(byName["wa-mds"].shelf).toBe("attestation");
  });

  it("recipeNeedsMainThread detects webauthn steps", () => {
    const { ast: plain } = compileRecipe("random 16 | hex");
    expect(recipeNeedsMainThread(plain)).toBe(false);
    const { ast: wa } = compileRecipe("wa-caps");
    expect(recipeNeedsMainThread(wa)).toBe(true);
    expect(getStep("wa-prf")?.toolbox).toBe("webauthn");
  });
});

describe("webauthn ops (offline)", () => {
  it("wa-caps returns JSON without throwing when WebAuthn is absent", async () => {
    const out = await execWaCaps();
    expect(out.type).toBe("text");
    const caps = JSON.parse(out.data);
    expect(typeof caps.publicKeyCredential).toBe("boolean");
  });

  it("wa-attest parses attestationObject bytes", async () => {
    const withAaguid = new Uint8Array(55);
    withAaguid[32] = 0x41; // flags: AT
    for (let i = 0; i < 16; i++) withAaguid[37 + i] = i;
    const att = encodeAttestation(withAaguid);
    const out = await execWaAttest({ type: "bytes", data: att });
    const body = JSON.parse(out.data);
    expect(body.fmt).toBe("none");
    expect(body.aaguid).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("wa-mds returns unverified for zero AAGUID without network", async () => {
    const out = await execWaMds(null, { aaguid: ZERO_AAGUID });
    const body = JSON.parse(out.data);
    expect(body.status).toBe("unverified");
    expect(body.aaguid).toBe(ZERO_AAGUID);
  });
});
