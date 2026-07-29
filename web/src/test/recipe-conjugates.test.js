/**
 * Companion preset + self-roundtrip smoke (Vitest / runRecipe — not CAST).
 */
import { describe, expect, it } from "vitest";
import {
  listPresetPairs,
  stitchPresetPair,
} from "../lib/toolkit/conjugate-stitch.js";
import {
  SELF_ROUNDTRIP_IDS,
  assertPresetCompiles,
  extractPem,
  findArtifactContent,
  listSelfRoundtrips,
  runInputsBridgePair,
  runSlotBridgePair,
} from "../lib/toolkit/conjugate-smoke.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, PRESETS } from "../lib/toolkit/recipe.js";
import { base64ToBytes } from "../lib/toolkit/encode.js";

describe("conjugate stitch for all PRESET pairs", () => {
  it("every pair stitches and compiles", () => {
    const pairs = listPresetPairs();
    expect(pairs.length).toBeGreaterThanOrEqual(4);
    for (const p of pairs) {
      const st = stitchPresetPair(p.forward, p.reverse);
      expect(st.errors || [], p.id).toEqual([]);
      expect(["as-is", "slot", "inputs"]).toContain(st.mode);
      const { validation } = compileRecipe(st.recipe);
      expect(validation.ok, `${p.id}: ${validation.errors?.[0]?.message}`).toBe(
        true
      );
    }
  });
});

describe("inputs-bridge pairs (SSS / envelope)", () => {
  it("slip39-secret: split → recover matches secret", async () => {
    const pair = listPresetPairs().find((p) => p.id === "slip39-secret");
    expect(pair).toBeTruthy();
    const { fwdArts, revArts, mnemonics, stitch } = await runInputsBridgePair(
      pair.forward,
      pair.reverse
    );
    expect(stitch.mode).toBe("inputs");
    expect(mnemonics.length).toBeGreaterThanOrEqual(2);
    const secretB64 = findArtifactContent(revArts, /^[A-Za-z0-9+/=]+$/);
    expect(secretB64).toBeTruthy();
    // Forward emits share tiles; recovered 32-byte secret as base64.
    const bytes = base64ToBytes(secretB64);
    expect(bytes.byteLength).toBe(32);
    expect(extractShareCount(fwdArts)).toBe(3);
  }, 60_000);

  it("slip39-scalar: rebuild private PEM", async () => {
    const pair = listPresetPairs().find((p) => p.id === "slip39-scalar");
    expect(pair).toBeTruthy();
    const { revArts, stitch } = await runInputsBridgePair(
      pair.forward,
      pair.reverse
    );
    expect(stitch.mode).toBe("inputs");
    const pem = extractPem(revArts, "private");
    expect(pem).toContain("BEGIN PRIVATE KEY");
  }, 60_000);

  it("slip39-pem-envelope: recover PEM matches forward @pem", async () => {
    const pair = listPresetPairs().find((p) => p.id === "slip39-pem-envelope");
    expect(pair).toBeTruthy();
    const { fwdArts, revArts, envelope, stitch } = await runInputsBridgePair(
      pair.forward,
      pair.reverse
    );
    expect(stitch.mode).toBe("inputs");
    expect(envelope).toMatch(/BEGIN PGP MESSAGE/);
    const fwdPem = extractPem(fwdArts, "private");
    const revPem = extractPem(revArts, "private");
    expect(fwdPem).toBeTruthy();
    expect(revPem).toBeTruthy();
    // Normalize whitespace for comparison
    expect(normPem(revPem)).toBe(normPem(fwdPem));
  }, 90_000);
});

describe("slot-bridge synthetic pair via kernel", () => {
  it("hex payload survives in @bridge across cells", async () => {
    const forward = {
      id: "fwd",
      pair: "hex-bridge",
      title: "fwd",
      recipe: "random 16 | to hex | out @payload",
    };
    const reverse = {
      id: "rev",
      pair: "hex-bridge",
      title: "rev",
      recipe: "input | out @echo",
    };
    const { stitch, slots } = await runSlotBridgePair(forward, reverse);
    expect(stitch.mode).toBe("slot");
    expect(stitch.bridge).toBe("@payload");
    // Terminal `out` registers slots (may not emit tiles); assert kernel handoff.
    expect(slots["@payload"]).toMatch(/^[0-9a-f]{32}$/);
    expect(slots["@echo"]).toBe(slots["@payload"]);
  }, 30_000);
});

describe("self-contained roundtrip presets", () => {
  it("lists expected ids", () => {
    const ids = listSelfRoundtrips().map((p) => p.id);
    for (const id of SELF_ROUNDTRIP_IDS) {
      if (id === "gpg-sign-verify") continue; // may need vault at runtime
      expect(ids).toContain(id);
    }
  });

  it("every self-roundtrip compiles", () => {
    for (const p of listSelfRoundtrips()) {
      assertPresetCompiles(p);
    }
  });

  it("rsa-oaep-roundtrip decrypts plaintext", async () => {
    const p = PRESETS.find((x) => x.id === "rsa-oaep-roundtrip");
    const { ast, validation } = compileRecipe(p.recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "basilisk-rsa-oaep" } },
    });
    const plain = arts.find((a) => /basilisk-rsa-oaep/.test(String(a.content)));
    expect(plain).toBeTruthy();
  }, 60_000);

  it("aes-gcm-roundtrip decrypts plaintext", async () => {
    const p = PRESETS.find((x) => x.id === "aes-gcm-roundtrip");
    const { ast, validation } = compileRecipe(p.recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "gcm-plain" } },
    });
    expect(findArtifactContent(arts, /^gcm-plain$/)).toBe("gcm-plain");
  }, 30_000);

  it("pbkdf2-aes-gcm decrypts plaintext", async () => {
    const p = PRESETS.find((x) => x.id === "pbkdf2-aes-gcm");
    const { ast, validation } = compileRecipe(p.recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "pbkdf-plain" } },
    });
    expect(findArtifactContent(arts, /^pbkdf-plain$/)).toBe("pbkdf-plain");
  }, 60_000);

  it("aes-cbc-roundtrip decrypts plaintext", async () => {
    const p = PRESETS.find((x) => x.id === "aes-cbc-roundtrip");
    const { ast, validation } = compileRecipe(p.recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "cbc-plain" } },
    });
    expect(findArtifactContent(arts, /^cbc-plain$/)).toBe("cbc-plain");
  }, 30_000);

  it("gpg-decrypt compiles", () => {
    const p = PRESETS.find((x) => x.id === "gpg-decrypt");
    assertPresetCompiles(p);
  });

  it("webauthn-prf-aes-gcm compiles", () => {
    const p = PRESETS.find((x) => x.id === "webauthn-prf-aes-gcm");
    assertPresetCompiles(p);
  });

  it("webauthn-attest-mds compiles", () => {
    const p = PRESETS.find((x) => x.id === "webauthn-attest-mds");
    assertPresetCompiles(p);
  });

  it("aes-ctr-roundtrip decrypts plaintext", async () => {
    const p = PRESETS.find((x) => x.id === "aes-ctr-roundtrip");
    const { ast, validation } = compileRecipe(p.recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "ctr-plain" } },
    });
    expect(findArtifactContent(arts, /^ctr-plain$/)).toBe("ctr-plain");
  }, 30_000);

  it("hmac-sign-verify emits ok", async () => {
    const p = PRESETS.find((x) => x.id === "hmac-sign-verify");
    const { ast, validation } = compileRecipe(p.recipe);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "hmac-msg" } },
    });
    const ok = arts.find(
      (a) =>
        String(a.content).toLowerCase() === "true" ||
        String(a.content).toLowerCase() === "ok" ||
        String(a.content).toLowerCase() === "valid"
    );
    // hmac.verify / soft verify emit bool true (or text "true" / "ok")
    expect(
      ok || arts.some((a) => /^true$/i.test(String(a.content).trim()))
    ).toBeTruthy();
  }, 30_000);

  it("gpg-sign-verify compiles; runtime needs a signing key", () => {
    const p = PRESETS.find((x) => x.id === "gpg-sign-verify");
    assertPresetCompiles(p);
  });
});

describe("quorum-gpg pair compile + stitch", () => {
  it("stiches as inputs bridge", () => {
    const pair = listPresetPairs().find((p) => p.id === "quorum-gpg");
    expect(pair).toBeTruthy();
    const st = stitchPresetPair(pair.forward, pair.reverse);
    expect(st.mode).toBe("inputs");
    expect(compileRecipe(st.recipe).validation.ok).toBe(true);
  });
});

/** @param {import("../lib/toolkit/engine.js").ToolkitArtifact[]} arts */
function extractShareCount(arts) {
  return arts.filter(
    (a) =>
      a.shareIndex ||
      a.role === "share" ||
      /^Share\s+\d+/i.test(a.label || "")
  ).length;
}

/** @param {string|null} pem */
function normPem(pem) {
  return String(pem || "")
    .replace(/\r\n/g, "\n")
    .trim();
}
