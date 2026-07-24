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
    const spec = getStep("sss");
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

  it("stepsAccepting hides sss after pem", () => {
    const afterPem = typeOf("text", { kind: "pem" });
    const names = stepsAccepting(afterPem).map((s) => s.name);
    expect(names).not.toContain("sss");
    expect(names).toContain("symencrypt");
  });

  it("stepsAccepting offers sss after scalar export", () => {
    const afterScalar = typeOf("bytes", {
      kind: "scalar",
      alg: "ec/p256",
      length: 32,
    });
    const names = stepsAccepting(afterScalar).map((s) => s.name);
    expect(names).toContain("sss");
    expect(names).not.toContain("symencrypt");
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

  it("walkPipelineTypes: shares | blip39 -d | recover → shares then master", () => {
    const { edges, final } = walkPipelineTypes(
      [
        { name: "shares", params: {} },
        { name: "blip39", params: { decode: true } },
        { name: "recover", params: {} },
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
});
