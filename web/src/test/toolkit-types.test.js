/**
 * Refined pipeline types + overload matching.
 */
import { describe, expect, it } from "vitest";
import { getStep, stepsAccepting } from "../lib/toolkit/registry.js";
import {
  artifactIsTextualForEncrypt,
  formatType,
  matchOverload,
  resolveStepType,
  typeOf,
  typeSatisfies,
  walkPipelineTypes,
} from "../lib/toolkit/types.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("refined types", () => {
  it("formats refinements", () => {
    expect(formatType(typeOf("bytes", { kind: "scalar", alg: "ec/p256", length: 32 }))).toBe(
      "bytes/scalar/ec/p256/32B"
    );
  });

  it("typeSatisfies requires present refinements", () => {
    expect(
      typeSatisfies(typeOf("bytes", { kind: "master", length: 32 }), {
        base: "bytes",
        kind: "master",
      })
    ).toBe(true);
    expect(
      typeSatisfies(typeOf("bytes", { kind: "pem" }), { base: "bytes", kind: "master" })
    ).toBe(false);
    expect(
      typeSatisfies(typeOf("bytes"), { base: "bytes", kind: "master" })
    ).toBe(false);
  });

  it("sss overloads match master/scalar only", () => {
    const spec = getStep("sss.split");
    expect(
      matchOverload(spec.overloads, typeOf("bytes", { kind: "master", length: 32 }), {})
    ).toBeTruthy();
    expect(
      matchOverload(spec.overloads, typeOf("bytes", { kind: "scalar", length: 32 }), {})
    ).toBeTruthy();
    expect(matchOverload(spec.overloads, typeOf("text", { kind: "pem" }), {})).toBeNull();
    expect(matchOverload(spec.overloads, typeOf("bytes", { kind: "der" }), {})).toBeNull();
  });

  it("resolveStepType: export scalar carries alg/length", () => {
    const spec = getStep("export");
    const r = resolveStepType(
      spec,
      typeOf("keypair", { alg: "ec/p256", which: "private" }),
      { format: "scalar" }
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.output.kind).toBe("scalar");
      expect(r.output.length).toBe(32);
      expect(r.output.alg).toBe("ec/p256");
    }
  });

  it("select .public/.private projects keypair → key tip", () => {
    const sel = getStep("select");
    const pub = resolveStepType(
      sel,
      typeOf("keypair", { alg: "ec/p256" }),
      { selector: ".public" }
    );
    expect(pub.ok).toBe(true);
    if (pub.ok) {
      expect(pub.output.base).toBe("key");
      expect(pub.output.which).toBe("public");
      expect(pub.output.alg).toBe("ec/p256");
    }
    const priv = resolveStepType(
      sel,
      typeOf("keypair", { alg: "ed25519" }),
      { selector: ".priv" }
    );
    expect(priv.ok).toBe(true);
    if (priv.ok) {
      expect(priv.output.base).toBe("key");
      expect(priv.output.which).toBe("private");
    }
  });

  it("export respects projected key tip which", () => {
    const spec = getStep("export");
    const publicKey = typeOf("key", { alg: "ec/p256", which: "public" });
    expect(resolveStepType(spec, publicKey, { format: "spki" }).ok).toBe(true);
    expect(resolveStepType(spec, publicKey, { format: "pkcs8" }).ok).toBe(false);
    expect(resolveStepType(spec, publicKey, { format: "scalar" }).ok).toBe(false);

    const privateKey = typeOf("key", { alg: "ec/p256", which: "private" });
    expect(resolveStepType(spec, privateKey, { format: "pkcs8" }).ok).toBe(true);
    expect(resolveStepType(spec, privateKey, { format: "spki" }).ok).toBe(false);
  });

  it("import spki yields public key tip", () => {
    const r = resolveStepType(
      getStep("import"),
      typeOf("bytes", { kind: "der", which: "public" }),
      { format: "spki", alg: "ec/p256" }
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.output.base).toBe("key");
      expect(r.output.which).toBe("public");
    }
  });

  it("import rejects mismatched DER half", () => {
    expect(
      resolveStepType(
        getStep("import"),
        typeOf("bytes", { kind: "der", which: "public" }),
        { format: "pkcs8", alg: "ec/p256" }
      ).ok
    ).toBe(false);
    expect(
      resolveStepType(
        getStep("import"),
        typeOf("bytes", { kind: "der", which: "private" }),
        { format: "spki", alg: "ec/p256" }
      ).ok
    ).toBe(false);
  });

  it("pem.encode/decode preserve which on the tip", () => {
    const derPub = typeOf("bytes", {
      kind: "der",
      which: "public",
      alg: "ec/p256",
    });
    const enc = resolveStepType(getStep("pem"), derPub, {});
    expect(enc.ok).toBe(true);
    if (enc.ok) {
      expect(enc.output.kind).toBe("pem");
      expect(enc.output.which).toBe("public");
    }
    const dec = resolveStepType(getStep("pem"), enc.ok ? enc.output : derPub, {
      decode: true,
    });
    expect(dec.ok).toBe(true);
    if (dec.ok) {
      expect(dec.output.kind).toBe("der");
      expect(dec.output.which).toBe("public");
    }
  });

  it("walkPipelineTypes: tee .public branch is key then DER", () => {
    const compiled = compileRecipe(
      "genkey ec/p256 | tee\n  - .public | export spki\n| export pkcs8"
    );
    expect(compiled.validation.ok).toBe(true);
    const { edges } = walkPipelineTypes(compiled.ast.steps, { getStep });
    const tee = edges.find((e) => e.name === "tee");
    expect(tee?.branches?.[0]?.member).toBe("public");
    const br0 = tee?.branches?.[0]?.edges || [];
    expect(formatType(br0[0]?.input)).toBe("key/ec/p256/public");
    expect(formatType(br0[0]?.output)).toMatch(/bytes\/der/);
  });

  it("stepsAccepting hides sss after pem", () => {
    const afterPem = typeOf("text", { kind: "pem" });
    const names = stepsAccepting(afterPem).map((s) => s.name);
    expect(names).not.toContain("sss");
    expect(names).toContain("gpg.symencrypt");
  });

  it("stepsAccepting offers sss.split after scalar export", () => {
    const afterScalar = typeOf("bytes", {
      kind: "scalar",
      alg: "ec/p256",
      length: 32,
    });
    const names = stepsAccepting(afterScalar).map((s) => s.name);
    expect(names).toContain("sss.split");
    expect(names).not.toContain("gpg.symencrypt");
  });

  it("Encrypt disposition follows recipe sinks (not hex/base64 sniffing)", () => {
    // `out` → file even when content is printable hex/base64
    expect(
      artifactIsTextualForEncrypt({
        encoding: "hex",
        content: "deadbeef",
        disposition: "file",
      })
    ).toBe(false);
    expect(
      artifactIsTextualForEncrypt({
        encoding: "base64",
        content: "AAAA",
        mime: "application/octet-stream",
        disposition: "file",
      })
    ).toBe(false);
    // `text` / `print` → message
    expect(
      artifactIsTextualForEncrypt({
        disposition: "message",
        role: "text",
        content: "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----",
      })
    ).toBe(true);
    expect(
      artifactIsTextualForEncrypt({
        role: "text",
        content: "hello",
      })
    ).toBe(true);
    expect(
      artifactIsTextualForEncrypt({
        role: "share",
        shareIndex: 1,
        encoding: "text",
        content: "academic …",
      })
    ).toBe(false);
  });

  it("walkPipelineTypes: shares | blip39 -d | sss.combine → shares then master", () => {
    const { edges, final } = walkPipelineTypes(
      [
        { name: "shares", params: {} },
        { name: "blip39", params: { decode: true } },
        { name: "sss.combine", params: {} },
      ],
      { getStep }
    );
    expect(edges).toHaveLength(3);
    expect(formatType(edges[0].output)).toBe("shares/mnemonic");
    expect(formatType(edges[1].output)).toBe("shares/raw");
    expect(formatType(edges[2].output)).toBe("bytes/master");
    expect(formatType(final)).toBe("bytes/master");
  });

  it("warns on trailing unhandled typed value", () => {
    const dangling = compileRecipe("genkey ec/p256 | export scalar");
    expect(dangling.validation.ok).toBe(true);
    expect(
      dangling.validation.warnings.some((w) => /Trailing bytes\/scalar/i.test(w))
    ).toBe(true);

    const handled = compileRecipe("genkey ec/p256 | export scalar | inspect");
    expect(handled.validation.ok).toBe(true);
    expect(
      handled.validation.warnings.some((w) => /Trailing /i.test(w))
    ).toBe(false);
  });

  it("webcrypto ops accept bytes/text; ecdh/wrap from none", () => {
    expect(
      resolveStepType(getStep("digest"), typeOf("bytes"), { alg: "sha-256" }).ok
    ).toBe(true);
    expect(
      resolveStepType(getStep("digest"), typeOf("text"), { alg: "sha-256" }).ok
    ).toBe(true);
    expect(
      resolveStepType(getStep("sign"), typeOf("bytes"), {}).ok
    ).toBe(true);
    expect(
      resolveStepType(getStep("aes-gcm"), typeOf("bytes"), {}).ok
    ).toBe(true);
    expect(
      resolveStepType(getStep("hkdf"), typeOf("bytes"), { length: 16 }).ok
    ).toBe(true);
    expect(resolveStepType(getStep("ecdh"), typeOf("none"), {}).ok).toBe(true);
    expect(resolveStepType(getStep("wrap"), typeOf("none"), {}).ok).toBe(true);
    expect(
      resolveStepType(getStep("unwrap"), typeOf("bytes"), {}).ok
    ).toBe(true);
  });
});
