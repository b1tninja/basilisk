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

  it("select :public/:private projects keypair → key tip", () => {
    const sel = getStep("select");
    const pub = resolveStepType(
      sel,
      typeOf("keypair", { alg: "ec/p256" }),
      { selector: ":public" }
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
      { selector: ":private" }
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

  it("pem / der preserve which on the tip", () => {
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
    const dec = resolveStepType(getStep("der"), enc.ok ? enc.output : derPub, {});
    expect(dec.ok).toBe(true);
    if (dec.ok) {
      expect(dec.output.kind).toBe("der");
      expect(dec.output.which).toBe("public");
    }
  });

  it("walkPipelineTypes: a public branch is keypair, then key, then DER", () => {
    const compiled = compileRecipe(
      "genkey ec/p256 | tee\n  - public | export spki\n| export pkcs8"
    );
    expect(compiled.validation.ok).toBe(true);
    const { edges } = walkPipelineTypes(compiled.ast.steps, { getStep });
    const tee = edges.find((e) => e.name === "tee");
    // The projection is a step in the branch rather than a prefix on it, so
    // the branch starts on a clone of the stem and its first edge is the
    // `public` that narrows it. The chain of types is the same one; it is now
    // spelled out edge by edge instead of half of it living in `member`.
    expect(tee?.branches?.[0]?.member).toBe("");
    const br0 = tee?.branches?.[0]?.edges || [];
    expect(br0[0]?.name).toBe("select");
    expect(formatType(br0[0]?.input)).toMatch(/^keypair\/ec\/p256/);
    expect(formatType(br0[0]?.output)).toBe("key/ec/p256/public");
    expect(formatType(br0[1]?.input)).toBe("key/ec/p256/public");
    expect(formatType(br0[1]?.output)).toMatch(/bytes\/der/);
  });

  it("walkPipelineTypes: a keypair half refuses a value with no halves", () => {
    // The rule that came with `public` when it stopped being `:public`: the
    // spelling changed and the refusal did not. Asserted through the *type
    // walk* rather than through `compileRecipe`, because there are two copies
    // of this predicate and only one of them is on the compile path.
    // `walkPipelineTypes` is the other, and it is what the builder's caret and
    // the tee's ghost chips read — so a value with no halves has to be refused
    // here too, or the drawer would offer `public` after `random 32`.
    //
    // Removing the guard in `resolveStepType` used to change nothing any test
    // could see, because `projectTypeForMember` refused the same recipe one
    // layer up. This is that gap.
    const { edges } = walkPipelineTypes(
      [
        { name: "random", params: { length: 32 } },
        { name: "select", params: { selector: ":public" } },
      ],
      { getStep }
    );
    expect(edges[1]?.error).toMatch(/requires keypair/);
    expect(edges[1]?.error).toContain("bytes");
    // And the same walk says yes on the value that does have halves.
    const ok = walkPipelineTypes(
      [
        { name: "genkey", params: { alg: "ec/p256" } },
        { name: "select", params: { selector: ":private" } },
      ],
      { getStep }
    );
    expect(ok.edges[1]?.error).toBeFalsy();
    expect(formatType(ok.edges[1]?.output)).toBe("key/ec/p256/private");
  });

  it("walkPipelineTypes: in $slot resolves prior out tip", () => {
    const compiled = compileRecipe(
      "genkey ec/p256 | out $kp\n\n$kp | :public | export spki"
    );
    expect(compiled.validation.ok).toBe(true);
    const slots = new Map();
    const c0 = walkPipelineTypes(compiled.ast.chains[0].steps, { getStep }, slots);
    expect(formatType(c0.final)).toMatch(/keypair/);
    expect(slots.get("kp")?.base).toBe("keypair");
    const c1 = walkPipelineTypes(compiled.ast.chains[1].steps, { getStep }, slots);
    const inEdge = c1.edges.find((e) => e.name === "in");
    expect(inEdge?.output?.base).toBe("keypair");
  });

  it("stepsAccepting hides sss after pem", () => {
    const afterPem = typeOf("text", { kind: "pem" });
    const names = stepsAccepting(afterPem).map((s) => s.name);
    expect(names).not.toContain("sss");
    expect(names).toContain("gpg.symencrypt");
  });

  it("stepsAccepting does not tip-fit digest/AEAD on PEM text", () => {
    const afterPem = typeOf("text", {
      kind: "pem",
      which: "private",
      alg: "ec/p256",
    });
    const names = stepsAccepting(afterPem).map((s) => s.name);
    expect(names).not.toContain("digest");
    expect(names).not.toContain("aes-gcm");
    expect(names).not.toContain("sign");
    expect(names).not.toContain("ecdh");
    expect(names).toContain("der");
    expect(names).toContain("out");
  });

  it("tip chain: PEM → der → as key / import", () => {
    const pemPriv = typeOf("text", {
      kind: "pem",
      which: "private",
      alg: "ec/p256",
    });
    expect(stepsAccepting(pemPriv).map((s) => s.name)).toContain("der");
    expect(stepsAccepting(pemPriv).map((s) => s.name)).toContain("as");
    const afterDer = resolveStepType(getStep("der"), pemPriv, {});
    expect(afterDer.ok).toBe(true);
    if (!afterDer.ok) return;
    expect(afterDer.output.kind).toBe("der");
    expect(afterDer.output.which).toBe("private");
    const derNames = stepsAccepting(afterDer.output).map((s) => s.name);
    expect(derNames).toContain("import");
    expect(derNames).toContain("as");
    expect(derNames).toContain("pem");

    const asKey = resolveStepType(getStep("as"), afterDer.output, {
      type: "key",
      alg: "ec/p256",
    });
    expect(asKey.ok).toBe(true);
    if (asKey.ok) {
      expect(asKey.output.base).toBe("key");
      expect(asKey.output.which).toBe("private");
    }
    const asPair = resolveStepType(getStep("as"), afterDer.output, {
      type: "keypair",
      alg: "ec/p256",
    });
    expect(asPair.ok).toBe(true);
    if (asPair.ok) {
      expect(asPair.output.base).toBe("keypair");
    }

    const pemPub = typeOf("text", {
      kind: "pem",
      which: "public",
      alg: "ec/p256",
    });
    const derPub = resolveStepType(getStep("der"), pemPub, {});
    expect(derPub.ok).toBe(true);
    if (!derPub.ok) return;
    expect(stepsAccepting(derPub.output).map((s) => s.name)).toContain("import");
    expect(
      resolveStepType(getStep("as"), derPub.output, { type: "keypair" }).ok
    ).toBe(false);
    const imported = resolveStepType(getStep("import"), derPub.output, {
      format: "spki",
      alg: "ec/p256",
    });
    expect(imported.ok).toBe(true);
    if (imported.ok) {
      expect(imported.output.base).toBe("key");
      expect(imported.output.which).toBe("public");
    }
  });

  it("as public / as private retag which on der/pem", () => {
    const der = typeOf("bytes", { kind: "der", alg: "ec/p256" });
    const pub = resolveStepType(getStep("as"), der, { type: "public" });
    expect(pub.ok).toBe(true);
    if (pub.ok) {
      expect(pub.output.which).toBe("public");
      expect(pub.output.kind).toBe("der");
    }
    expect(
      resolveStepType(getStep("as"), pub.ok ? pub.output : der, {
        type: "private",
      }).ok
    ).toBe(false);
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
      dangling.validation.warnings.some((w) =>
        /Trailing bytes\/scalar/i.test(w.message)
      )
    ).toBe(true);

    const handled = compileRecipe("genkey ec/p256 | export scalar | inspect");
    expect(handled.validation.ok).toBe(true);
    expect(
      handled.validation.warnings.some((w) => /Trailing /i.test(w.message))
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

describe("network / WebRTC types (design v2 §25a)", () => {
  it("formats list-shaped network types with an element count, not bytes", () => {
    expect(formatType(typeOf("candidate", { length: 3 }))).toBe("candidate/×3");
    expect(formatType(typeOf("endpoint", { kind: "ice-servers" }))).toBe(
      "endpoint/ice-servers"
    );
    expect(formatType(typeOf("sdp", { which: "answer" }))).toBe("sdp/answer");
    expect(formatType(typeOf("host", { family: "v6" }))).toBe("host/v6");
  });

  it("type-checks the offer → answer SDP exchange", () => {
    const ok = compileRecipe("peer.offer | peer.answer | out $a");
    expect(ok.validation.ok, JSON.stringify(ok.validation.errors)).toBe(true);

    const bad = compileRecipe("rtc.gather | peer.answer | out $a");
    expect(bad.validation.ok).toBe(false);
    expect(bad.validation.errors[0].message).toMatch(/expects sdp, got candidate/);
  });

  it("refuses to let a live session handle be consumed by a crypto op", () => {
    const { validation } = compileRecipe('quorum.offer to="AAAA" | digest | out $d');
    expect(validation.ok).toBe(false);
    expect(validation.errors[0].message).toMatch(/live handle/);
  });

  it("refuses to let an observe-only diagnostic be consumed", () => {
    const { validation } = compileRecipe("rtc.state | base64 | out $b");
    expect(validation.ok).toBe(false);
    expect(validation.errors[0].message).toMatch(/observe-only/);
  });

  it("still lets every network type reach out / inspect", () => {
    for (const src of [
      "rtc.gather | out $c",
      "rtc.state | inspect",
      "rtc.ice | out $ice",
      "quorum.offer to=\"AAAA\" | out $s",
      "rtc.quality | out $q",
    ]) {
      const { validation } = compileRecipe(src);
      expect(validation.ok, `${src}: ${JSON.stringify(validation.errors)}`).toBe(true);
    }
  });

  it("accepts an rtc.ice endpoint slot for ice=, and rejects a wrong-typed slot", () => {
    const ok = compileRecipe(
      "rtc.ice | out $ice\n\nrtc.gather ice=$ice | out $c"
    );
    expect(ok.validation.ok, JSON.stringify(ok.validation.errors)).toBe(true);

    const bad = compileRecipe(
      "genkey ec/p256 | out $kp\n\nrtc.gather ice=$kp | out $c"
    );
    expect(bad.validation.ok).toBe(false);
    expect(bad.validation.errors.some((e) => /not an ICE config/.test(e.message))).toBe(true);
  });
});
