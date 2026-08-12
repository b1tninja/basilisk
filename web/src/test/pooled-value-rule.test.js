/**
 * A value the whole room can recompute must not become key material.
 *
 * `entropy.pool` draws randomness every participant helped choose and can
 * derive again — which is what makes a distributed run agree, and exactly what
 * must never reach a key: a private key everyone can recompute is not one.
 *
 * The guard written for this, `mirroredRunRefusals`, reads each op's declared
 * `entropy` and refuses ops that **draw** keying randomness. `hkdf` and
 * `pbkdf2` draw none — they *derive* — so they declare `none`, correctly, and
 * the guard has nothing to say about them. This compiled, planned and **ran**:
 *
 *     entropy.pool | out $salt
 *     in $salt | hkdf as=aes/256 | out $roomkey
 *
 * producing an artifact labelled `roomkey · secret JWK` that every participant
 * shared. The rule below is where that is caught, and the two tests it turns on
 * are the exploit refused and the legitimate salt still running. A fix that
 * only proved the first would be a regression wearing a security badge.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { STEPS } from "../lib/toolkit/registry.js";
import { inferSourceType } from "../lib/toolkit/types.js";

const compile = (src) => compileRecipe(src).validation;
const errors = (src) => compile(src).errors.map((e) => e.message).join("\n");

describe("the exploit, refused", () => {
  it("refuses a pooled value piped into a key derivation", () => {
    const v = compile("entropy.pool | out $salt\n\nin $salt | hkdf as=aes/256 | out $roomkey");
    expect(v.ok).toBe(false);
    expect(errors("entropy.pool | out $salt\n\nin $salt | hkdf as=aes/256 | out $roomkey")).toMatch(
      /`hkdf` would turn a pooled value into key material/
    );
  });

  it("refuses it through PBKDF2 as well, which stretches the pipe value", () => {
    // Same shape, different derivation: the thing being stretched is the pipe
    // value, and a public one is not a secret to stretch.
    expect(errors("entropy.pool | out $p\n\nin $p | pbkdf2 as=aes/256 | out $k")).toMatch(
      /would turn a pooled value into key material/
    );
  });

  it("survives the hop the exploit uses", () => {
    // `out $x` then `in $x` is the only way the pooled value reaches the
    // derivation, so the refinement has to ride through the slot boundary. If
    // it were lost there the whole rule would be decoration.
    expect(inferSourceType("entropy.pool")).toMatchObject({ base: "bytes", pooled: true });
    // Proven end to end rather than by inspecting the type map: the refusal
    // above *only* fires if the flag came back out of `in $salt`.
    expect(errors("entropy.pool | out $a\n\nin $a | out $b\n\nin $b | hkdf as=aes/256 | out $k")).toMatch(
      /would turn a pooled value into key material/
    );
  });

  it("refuses a pooled value bound to a param that makes a key", () => {
    // The param half. `unwrap key=` is the wrapping key, not a public input,
    // so it does not declare `acceptsPooled` and a pooled value cannot go there.
    const src =
      "entropy.pool | out $p\n\ngenkey alg=aes/256 | wrap key=$p | out $w";
    // (Compiles or not on other grounds; what matters is the pooled sentence.)
    expect(errors("entropy.pool | out $p\n\nbytes 00 | unwrap key=$p alg=aes/256 | out $k")).toMatch(
      /binds a pooled value where the step makes key material/
    );
    expect(src).toBeTruthy();
  });
});

describe("the legitimate use, still running", () => {
  it("allows a pooled salt into PBKDF2 over a typed passphrase", () => {
    // The feature's headline case. A PBKDF2 salt need not be secret (RFC 8018
    // §4.1) and a salt the room agreed on is the reason `entropy.pool` exists.
    // Refusing this would forbid what the op is for.
    const v = compile("entropy.pool | out $salt\n\ninput | utf8 | pbkdf2 salt=$salt | out $k");
    expect(v.errors).toEqual([]);
    expect(v.ok).toBe(true);
  });

  it("allows a pooled salt and info into HKDF", () => {
    // RFC 5869 §3.1 — the salt is non-secret by construction, and `info` is
    // public context. The *pipe* value there is still the secret.
    const v = compile(
      "entropy.pool | out $s\n\nrandom 32 | hkdf as=aes/256 salt=$s info=$s | out $k"
    );
    expect(v.errors).toEqual([]);
  });

  it("allows a pooled value anywhere it is not becoming a key", () => {
    // A public number in a public place, which is what it is for.
    expect(compile("entropy.pool | out $p\n\nin $p | encode hex | out $h").ok).toBe(true);
    expect(compile("entropy.pool | out $iv\n\ninput | utf8 | aes-gcm key=$k aad=$iv | out $c").errors.map((e) => e.message).join("")).not.toMatch(
      /pooled/
    );
  });
});

describe("acceptance is declared, not listed", () => {
  it("is carried by the params that are public by definition, and no others", () => {
    const accepting = [];
    for (const s of STEPS) {
      for (const p of s.params || []) if (p.acceptsPooled) accepting.push(`${s.name}.${p.name}`);
    }
    // Pinned deliberately. Every entry is an input that travels in the clear
    // beside what it protects; anything else appearing here should have to be
    // argued, not merged. Growing this list is how default-deny becomes
    // default-allow one param at a time.
    expect([...accepting].sort()).toEqual([
      "aes-gcm.aad",
      "hkdf.info",
      "hkdf.salt",
      "pbkdf2.salt",
    ]);
  });

  it("never lets a key, passphrase or master param accept one", () => {
    // The rule the population above has to keep obeying. Read from the
    // registry rather than from the list, so a future declaration on a secret
    // input fails here rather than in a room.
    const wrong = [];
    for (const s of STEPS) {
      for (const p of s.params || []) {
        if (!p.acceptsPooled) continue;
        if (/^(key|passphrase|master|secret|identity|private)$/i.test(p.name)) {
          wrong.push(`${s.name}.${p.name}`);
        }
      }
    }
    expect(wrong, "a pooled value cannot be the secret").toEqual([]);
  });

  it("refuses by default, so a new op needs no remembering", () => {
    // The property the declaration buys. `unwrap.key` declares nothing and is
    // refused; it never had to be added anywhere.
    const unwrapKey = STEPS.find((s) => s.name === "unwrap")?.params?.find((p) => p.name === "key");
    expect(unwrapKey?.acceptsPooled).toBeUndefined();
    expect(errors("entropy.pool | out $p\n\nbytes 00 | unwrap key=$p alg=aes/256 | out $k")).toMatch(
      /binds a pooled value/
    );
  });
});
