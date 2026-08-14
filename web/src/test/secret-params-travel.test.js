/**
 * A secret is *named* in a recipe and never carried by one.
 *
 * `sss.split threshold=2 shares=3 passphrase=hunter2` compiled, ran, and
 * serialized verbatim — into the `#r=` fragment, into the workspace saved in
 * `localStorage`, and into the `recipeSource` a run manifest digests. The mask
 * whose whole job is to make a stolen share useless travelled beside the recipe
 * that made the shares, to the people the shares go to.
 *
 * The fix was not to hide it. `secret: true` alone drops a literal at
 * serialization, which leaves the recipe describing a split it no longer
 * performs: whoever adopts the notebook masks with nothing, and `handoffContext`
 * digests two texts that mean different things into manifests claiming to be the
 * same run. So the parameter takes a `$ref` and nothing else — the refusal
 * happens at the parser, while the author is still there, and the ref survives
 * every serialization intact.
 *
 * Three things have to hold together, and the middle one is the reason the first
 * is safe:
 *
 * 1. a literal is refused, everywhere the class appears — derived from the
 *    registry rather than listed, so the next `secret` param is covered by
 *    declaring itself;
 * 2. the `$ref` spelling round-trips, so the recipe still reproduces;
 * 3. the three boundaries refuse text that binds a secret to a literal anyway —
 *    because none of them compile, and a notebook that cannot run can still be
 *    copied as a link.
 */
import { describe, expect, it } from "vitest";
import { decryptKey, readPrivateKey } from "openpgp";
import { STEPS, getStep } from "../lib/toolkit/registry.js";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { hashForRecipe, decodeSharePayload } from "../lib/toolkit/fragment.js";
import { saveWorkspace, listWorkspaces } from "../lib/toolkit/workspace-store.js";
import { recipeLooksSecret } from "../lib/toolkit/recipe-secrets.js";
import { buildRunManifest } from "../lib/toolkit/manifest.js";
import { stepUnboundSlots } from "../lib/toolkit/input-needs.js";

/** Every `[step, param]` the registry declares a secret. */
const SECRETS = STEPS.flatMap((s) =>
  (s.params || []).filter((p) => p.secret).map((p) => [s.name, p])
);

/**
 * Params whose *name* says they carry key material, or the passphrase standing
 * between key material and whoever holds the artifact.
 *
 * A name sweep and not a list, for `param-slot-declared.js`'s reason: reading
 * 276 declarations would miss one, and the defect this file exists for was a
 * param nobody had declared anything about at all. `salt` is deliberately not
 * here — RFC 5869 §3.1 and RFC 8018 §4.1 make it non-secret by construction, and
 * the registry says so at both declarations.
 */
const SECRET_BEARING = STEPS.flatMap((s) =>
  (s.params || [])
    .filter((p) => /^(?:passphrase|password|credential|key|secret|master)$/i.test(p.name))
    .map((p) => [s.name, p])
);

const errorsFor = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message);

const LITERAL = "hunter2";

describe("a parameter that carries a secret takes a ref and nothing else", () => {
  it("finds the class by name, so a new one cannot be missed", () => {
    // The sweep must actually sweep. A regex that matched nothing would make
    // every assertion below vacuously true.
    expect(SECRET_BEARING.length).toBeGreaterThan(20);
    expect(SECRET_BEARING.map(([s, p]) => `${s} ${p.name}=`)).toContain(
      "sss.split passphrase="
    );
  });

  it("refuses a literal on every one of them", () => {
    const literalOk = SECRET_BEARING.filter(([, p]) => p.slot !== "required").map(
      ([step, p]) => `${step} ${p.name}=`
    );
    expect(
      literalOk,
      `${literalOk.join(", ")} may hold a literal secret. Recipe text is copied ` +
        `into share links, workspace saves and the run manifest both ends ` +
        `digest, so a value written there is disclosed in all three. Declare ` +
        `slot: "required" (and secret: true) so the recipe names the value ` +
        `instead of carrying it.`
    ).toEqual([]);
  });

  it("never returns to redact-on-serialize", () => {
    // `secret: true` with `slot: true` is the state this fix rejected: the
    // literal parses, runs, and vanishes from the text, so the recipe describes
    // something it no longer does. `age.encrypt` sat there and is why the drop
    // in `serializeStep` exists at all.
    const redacting = SECRETS.filter(([, p]) => p.slot !== "required").map(
      ([step, p]) => `${step} ${p.name}=`
    );
    expect(
      redacting,
      `${redacting.join(", ")} declare secret: true without slot: "required", ` +
        `so a literal there is dropped on serialize rather than refused at ` +
        `parse — and a dropped passphrase is a recipe that quietly stopped ` +
        `meaning what it says.`
    ).toEqual([]);
  });

  it("says so in the refusal, without repeating the value it is refusing", () => {
    for (const [step, p] of SECRETS) {
      const said = errorsFor(`${step} ${p.name}=${LITERAL}`).join("\n");
      expect(said, `${step} ${p.name}=`).toMatch(/\$slot/);
      // The generic answer was "Slot labels require $ (use $hunter2, not
      // hunter2)": it quotes the secret into a message that gets rendered and
      // pasted around, and the remedy it names would put the passphrase in the
      // text as a slot *label*.
      expect(said, `${step} ${p.name}= echoes the literal`).not.toContain(LITERAL);
    }
  });

  it("does not invent a binding nobody owes", () => {
    // The cost of making a param ref-only: `stepUnboundSlots` treats a
    // `slot: "required"` param left blank as an error deferred, and every one
    // of these is optional. `random 32 | sss.split | blip39` — the most common
    // recipe in the corpus — would otherwise carry a warning that it is missing
    // a passphrase it never wanted. `emptyMeans` is what says the blank is a
    // choice, and it is the same field that renders under the field itself.
    // Only the passphrases. `quorum.offer key=` is `secret` and ref-only too,
    // and reporting *it* is right: an exchange cannot open without your private
    // key, so a blank there is an error deferred and the tray should say so.
    const noisy = [];
    for (const step of new Set(SECRETS.filter(([, p]) => p.name === "passphrase").map(([s]) => s))) {
      const spec = getStep(step);
      const params = {};
      for (const p of spec.params || []) if (p.default !== undefined) params[p.name] = p.default;
      const unbound = stepUnboundSlots({ name: step, params }, spec).filter(
        (u) => u.param === "passphrase"
      );
      if (unbound.length) noisy.push(`${step}: ${unbound.map((u) => u.param).join(", ")}`);
    }
    expect(
      noisy,
      `${noisy.join("; ")} — a bare instance of the op is reported as missing a ` +
        `binding. An optional ref-only param says what blank does (emptyMeans) ` +
        `or it is a warning on every recipe that never wanted one.`
    ).toEqual([]);
  });

  it("still compiles the spelling that keeps the recipe reproducible", () => {
    // The other half, and the reason refusing is not the same as hiding: a
    // notebook that names its secret runs for whoever holds the slot.
    const { validation, ast } = compileRecipe(
      `input | out $pw\n\nrandom 32 | sss.split threshold=2 shares=3 passphrase=$pw | out $s`
    );
    expect(validation.errors).toEqual([]);
    expect(serializeRecipe(ast)).toContain("passphrase=$pw");
  });
});

describe("the three places the passphrase used to travel", () => {
  const LEAKY = `random 32 | sss.split threshold=2 shares=3 passphrase=${LITERAL} | out $s`;
  const NAMED = `input | out $pw\n\nrandom 32 | sss.split threshold=2 shares=3 passphrase=$pw | out $s`;

  it("a share link", () => {
    const leaky = hashForRecipe(LEAKY);
    expect(leaky.ok).toBe(false);
    expect(leaky.hash).toBe("#");
    expect(leaky.reason).toMatch(/secret material/i);

    const named = hashForRecipe(NAMED);
    expect(named.ok).toBe(true);
    const carried = String(decodeSharePayload(named.hash.replace(/^#r=/, "")));
    expect(carried).toContain("passphrase=$pw");
    expect(carried).not.toContain(LITERAL);
  });

  it("a workspace save", () => {
    const mem = new Map();
    const storage = {
      getItem: (k) => (mem.has(k) ? mem.get(k) : null),
      setItem: (k, v) => mem.set(k, v),
    };
    const leaky = saveWorkspace({ title: "ceremony", recipe: LEAKY }, storage);
    expect(leaky.ok).toBe(false);
    expect([...mem.values()].join("")).not.toContain(LITERAL);

    expect(saveWorkspace({ title: "ceremony", recipe: NAMED }, storage).ok).toBe(true);
    const stored = listWorkspaces(storage)[0].recipe;
    expect(stored).toContain("passphrase=$pw");
    expect(stored).not.toContain(LITERAL);
  });

  it("the run manifest both ends digest", async () => {
    // A manifest is derived from the notebook's own text, so the guard here is
    // that the text cannot exist: a run that would produce one has to compile,
    // and the literal does not.
    expect(errorsFor(LEAKY).join("\n")).toMatch(/sss\.split passphrase=/);

    const manifest = await buildRunManifest({ title: "t", recipeSource: NAMED });
    expect(manifest.recipeSource).toContain("passphrase=$pw");
    expect(manifest.recipeSource).not.toContain(LITERAL);
  });

  it("is one predicate, so all three answer the same", () => {
    // The point of `recipe-secrets.js`: adding a form of secret protects every
    // boundary at once. These three callers share it, and the wire is checked
    // in `notebook-travels.test.js`.
    expect(recipeLooksSecret(LEAKY)).toBe(true);
    expect(recipeLooksSecret(NAMED)).toBe(false);
  });

  it("does not refuse a notebook that merely talks about passphrases", () => {
    // The cost of a false refusal is what took the fingerprint entry back out
    // of this predicate. `bindsSecretToLiteral` asks the parser rather than
    // grepping, so text that is not an argument is not an argument.
    expect(recipeLooksSecret(`"key=2&passphrase=x" | utf8 | base64 | out $q`)).toBe(false);
    expect(recipeLooksSecret(`# remember: passphrase goes in Inputs\nrandom 32 | out $r`)).toBe(
      false
    );
  });
});

describe("the ref is resolved, not used as the value", () => {
  it("masks with what the slot holds", async () => {
    // `age.encrypt` shipped this defect: `secret: true` bound a slot in the UI
    // and serialize dropped literals, while the op read `params.passphrase`
    // straight — so the file was encrypted under the four characters `$pw`. On
    // a split the same mistake is silent until somebody tries to recover, which
    // is why this asserts the recovered bytes rather than that a run happened.
    const HEX = "00112233445566778899aabbccddeeff".repeat(2);
    const split = compileRecipe(
      `input | out $pw\n\nbytes ${HEX} | sss.split threshold=2 shares=3 passphrase=$pw | blip39 | out $set`
    );
    expect(split.validation.errors).toEqual([]);
    const arts = await runRecipe(split.ast, {
      inputs: { text: { value: "correct horse" } },
    });
    const mnemonics = arts.filter((a) => a.shareIndex).map((a) => a.content);
    expect(mnemonics.length).toBe(3);

    // Recovered through the *named* mask, not the tray's: `sss.combine` resolves
    // its own ref, and a recipe that named `$pw` while combining under the four
    // characters `$pw` would give back thirty-two bytes of nothing in
    // particular — a wrong answer that still looks like an answer.
    const recover = compileRecipe(
      `input | out $pw\n\nshares | blip39 -d | sss.combine passphrase=$pw | encode hex | out $back`
    );
    expect(recover.validation.errors).toEqual([]);
    const back = await runRecipe(recover.ast, {
      inputs: {
        text: { value: "correct horse" },
        shares: { mnemonics: mnemonics.slice(0, 2) },
      },
    });
    const labelled = (arts, name) =>
      String(arts.find((a) => String(a.label || "").includes(name))?.content ?? "");
    expect(labelled(back, "back")).toBe(HEX);

    // And the tray still answers when the recipe names nothing — the fallback
    // `emptyMeans` promises, and the one `ssh.decode` keeps for its reason.
    const fromTray = compileRecipe(
      "shares | blip39 -d | sss.combine | encode hex | out $back"
    );
    expect(
      String(
        (
          await runRecipe(fromTray.ast, {
            inputs: {
              shares: { mnemonics: mnemonics.slice(0, 2), passphrase: "correct horse" },
            },
          })
        )[0].content
      )
    ).toBe(HEX);

    // And the mask is a mask: the same shares under the wrong one do not give
    // the secret back.
    const wrong = await runRecipe(fromTray.ast, {
      inputs: { shares: { mnemonics: mnemonics.slice(0, 2), passphrase: "$pw" } },
    });
    expect(String(wrong[0].content)).not.toBe(HEX);
  }, 30_000);

  it("protects a generated key with what the slot holds", async () => {
    // `gpg.genkey passphrase=` read its param straight too. Nothing else in the
    // suite binds it, so without this the engine could go back to writing the
    // characters `$pw` into an S2K and no test would notice — and the armor
    // would still look protected.
    const { ast, validation } = compileRecipe(
      `input | out $pw\n\ngpg.genkey email=a@b.example passphrase=$pw | out $k`
    );
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, { inputs: { text: { value: "correct horse" } } });
    const armored = arts
      .map((a) => String(a.content ?? ""))
      .find((c) => c.includes("BEGIN PGP PRIVATE KEY BLOCK"));
    const key = await readPrivateKey({ armoredKey: armored });
    expect(key.isDecrypted()).toBe(false);
    await expect(
      decryptKey({ privateKey: key, passphrase: "$pw" })
    ).rejects.toThrow();
    expect((await decryptKey({ privateKey: key, passphrase: "correct horse" })).isDecrypted()).toBe(
      true
    );
  }, 60_000);

  it("names the slot when nothing registered it, before the run", () => {
    expect(
      errorsFor("random 32 | sss.split threshold=2 shares=3 passphrase=$nope | out $s").join(
        "\n"
      )
    ).toMatch(/passphrase=\$nope: unknown slot/);
  });
});

describe("the UI half stays attached to the language half", () => {
  it("locks every passphrase field to the tray", () => {
    // `ParamField` renders a bind-only control for `secret: true` and free text
    // for everything else. A passphrase that refuses literals in the grammar
    // while offering a text box would be a field whose every keystroke is an
    // error, which is how `sss.split` invited the literal in the first place.
    //
    // Only the passphrase family. A `key=` param is ref-only too, but it binds a
    // live key and its field is a key picker — a different control, and one
    // where nothing can be typed by hand anyway.
    const unlocked = SECRET_BEARING.filter(
      ([, p]) => /^passphrase$/i.test(p.name) && !p.secret
    ).map(([step, p]) => `${step} ${p.name}=`);
    expect(
      unlocked,
      `${unlocked.join(", ")} refuse a literal but still render a text box.`
    ).toEqual([]);
    expect(getStep("sss.split").params.find((p) => p.name === "passphrase").secret).toBe(
      true
    );
  });
});
