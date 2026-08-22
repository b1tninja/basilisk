/**
 * Module aliases — a second spelling for a *namespace* (docs/RECIPE.md,
 * "Vocabulary aliases" / "Module aliases").
 *
 * `MODULE_ALIASES` declares `openpgp` → `gpg`, so `openpgp.encrypt` and
 * `gpg.encrypt` are one step reached two ways. The whole safety of that rests
 * on *where* the two spellings converge: the recipe text is hashed into the run
 * manifest both ends compare, so an alias that survived into the AST would let
 * two peers who mean one thing hold two agreements about one run. These specs
 * pin the convergence at parse, and pin what it must therefore be true of
 * everything downstream — serialize, the notebook source, the manifest.
 */
import { describe, expect, it } from "vitest";
import {
  MODULE_ALIASES,
  canonicalName,
  getStep,
  listSteps,
  moduleAliasHint,
  moduleAliasSpellings,
} from "../lib/toolkit/registry.js";
import {
  canonicalizeRecipe,
  parseRecipe,
  registryIssues,
  serializeRecipe,
} from "../lib/toolkit/recipe.js";
import { handoffContext } from "../lib/toolkit/handoff-shell.js";
import { opsRegistryVersion } from "../lib/toolkit/receipt.js";

/** Every `gpg.*` verb, read off the registry rather than listed here. */
const GPG_STEPS = listSteps()
  .map((s) => s.name)
  .filter((n) => n.toLowerCase().startsWith("gpg."));

describe("module alias declaration", () => {
  it("declares openpgp → gpg, and gpg is the canonical direction", () => {
    // The direction is the decision, so it is asserted rather than implied.
    // Canonicalizing the other way would rewrite every preset, ceremony, doc
    // fence and `#r=` link in the corpus and change their digests.
    expect(MODULE_ALIASES.openpgp).toBe("gpg");
    expect(MODULE_ALIASES.gpg).toBeUndefined();
  });

  it("covers every gpg.* step, with none left behind", () => {
    expect(GPG_STEPS.length).toBeGreaterThan(0);
    const spelled = moduleAliasSpellings();
    expect(spelled.map((s) => s.canonical).sort()).toEqual([...GPG_STEPS].sort());
    // Nothing shadowed: a spelling silently claimed by a real step would be an
    // alias the docs promise and the parser resolves elsewhere.
    expect(spelled.filter((s) => s.shadowed)).toEqual([]);
  });

  it("the shipped registry has no shadowed spelling", () => {
    expect(registryIssues()).toEqual([]);
  });

  it("registryIssues reports a spelling another step already claims", () => {
    // The collision cannot happen in the shipped registry, which is exactly why
    // it is asked of a hand-built one: a check nobody can show would fire is
    // the defect this repo keeps finding under other names. Here `openpgp.foo`
    // is a real step, so the module expansion yields to it — an alias is a
    // second way to *reach* an op, never a way to take one over — and yielding
    // in silence would leave docs/RECIPE.md promising a spelling that resolves
    // somewhere else.
    const base = { kind: "transform", toolbox: "openpgp", doc: "d", input: "bytes", output: "bytes", entropy: "none" };
    const collides = [
      { ...base, name: "gpg.foo" },
      { ...base, name: "openpgp.foo" },
    ];
    const issues = registryIssues(collides);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toContain('module alias "openpgp.foo"');
    expect(issues[0]).toContain("gpg.foo");

    // The control. Same two specs, one renamed so nothing collides — if the
    // check fired on any two-step list the assertion above would be empty.
    expect(
      registryIssues([{ ...base, name: "gpg.foo" }, { ...base, name: "openpgp.bar" }])
    ).toEqual([]);
  });

  it("resolves through canonicalName and getStep, case-insensitively", () => {
    for (const name of GPG_STEPS) {
      const alias = name.replace(/^gpg\./i, "openpgp.");
      expect(canonicalName(alias)).toBe(name);
      expect(canonicalName(alias.toUpperCase())).toBe(name);
      expect(getStep(alias)).toBe(getStep(name));
    }
  });

  it("maps prefixes only — the unnamespaced ops keep their bare names", () => {
    // `seal` is in the OpenPGP *toolbox* and carries no namespace. Giving the
    // unnamespaced verbs one is a decision nobody has made, and a module alias
    // must not be what makes it.
    expect(getStep("seal")).toBeTruthy();
    expect(canonicalName("openpgp.seal")).toBeNull();
    expect(canonicalName("openpgp.sign")).toBe("gpg.sign");
  });

  it("stays out of the ops registry fingerprint", () => {
    // `opsRegistryVersion` sits inside every run manifest and two peers on
    // different fingerprints refuse each other's offers, so an alias — a way of
    // spelling an op, not a new op — must not move it. (It does not: the
    // fingerprint was `ops-132-f8182428` before this alias existed and after.)
    //
    // Pinned by the *reason* rather than by that literal, because the literal
    // is supposed to change whenever an op is added and a test that has to be
    // edited on every registry change is one people learn to edit without
    // reading. The reason is that `opsRegistryVersion` folds `listSteps()`,
    // which is canonical entries only — so the pin that matters is that no
    // alias spelling ever reaches that list.
    expect(listSteps().filter((s) => /^openpgp\./i.test(s.name))).toEqual([]);
    const spelled = new Set(moduleAliasSpellings().map((s) => s.alias));
    expect(spelled.size).toBeGreaterThan(0);
    for (const s of listSteps()) expect(spelled.has(s.name.toLowerCase())).toBe(false);
    expect(opsRegistryVersion()).toMatch(new RegExp(`^ops-${listSteps().length}-[0-9a-f]{8}$`));
  });
});

describe("module alias round trip", () => {
  const PAIRS = [
    ["openpgp.encrypt to=alice@example.com", "gpg.encrypt to=alice@example.com"],
    ["input | openpgp.sign", "input | gpg.sign"],
    ["openpgp.symencrypt mode=passphrase", "gpg.symencrypt mode=passphrase"],
    ["openpgp.decrypt | out $plain", "gpg.decrypt | out $plain"],
    ["OpenPGP.Encrypt to=a@b.c", "gpg.encrypt to=a@b.c"],
  ];

  it.each(PAIRS)("%s parses and serializes to the canonical form", (alias, canon) => {
    const aliased = parseRecipe(alias);
    expect(aliased.errors).toEqual([]);
    const serialized = serializeRecipe(aliased.ast);
    expect(serialized).toBe(serializeRecipe(parseRecipe(canon).ast));
    // The alias is gone from the AST's *names*, not merely from the serialized
    // text — anything that reads step names (the planner, the engine, every
    // refusal string) sees one spelling. `ast.source` deliberately keeps the
    // text as typed, so the walk asks the names rather than the JSON; nothing
    // digests `ast.source` (`canonicalizeRecipe` overwrites it, and
    // `handoffContext` is handed `serializeRecipe(chains)`).
    const names = [];
    const walk = (steps) => {
      for (const s of steps || []) {
        names.push(s.name);
        for (const b of s.body || []) walk(b.steps || b);
      }
    };
    for (const chain of aliased.ast.chains) walk(chain.steps);
    expect(names.length).toBeGreaterThan(0);
    expect(names.filter((n) => /^openpgp\./i.test(n))).toEqual([]);
  });

  it.each(PAIRS)("%s: serializeRecipe stays a fixed point", (alias, canon) => {
    // Both directions, as required: the canonical text is unchanged by another
    // pass, and the aliased text lands on it in one.
    const canonical = serializeRecipe(parseRecipe(canon).ast);
    expect(serializeRecipe(parseRecipe(canonical).ast)).toBe(canonical);
    expect(serializeRecipe(parseRecipe(alias).ast)).toBe(canonical);
    expect(canonicalizeRecipe(alias).text).toBe(canonical);
    expect(canonicalizeRecipe(canonical).changed).toBe(false);
  });

  it("is a function of the text and nothing else", () => {
    // Determinism: same input, same canonical form, however many times and in
    // whatever order. A canonicalization that consulted runtime state — a
    // session, a preference, a clock — would let two peers on one text derive
    // two manifests.
    const runs = [];
    for (let i = 0; i < 5; i++) {
      runs.push(serializeRecipe(parseRecipe("input | openpgp.sign key=$k").ast));
    }
    expect(new Set(runs).size).toBe(1);
    expect(runs[0]).toBe("input | gpg.sign key=$k");
  });

  it("keeps reading after the corpus has moved on", () => {
    // The alias reads *forever*: a `#r=` link somebody is holding must keep
    // opening into the notebook it meant, which is why the retired `publish=`
    // header still parses. Removing an entry from `MODULE_ALIASES` breaks a
    // link that is already in the world; this is the pin that says so.
    expect(parseRecipe("openpgp.encrypt to=a@b.c").errors).toEqual([]);
  });
});

describe("the alias resolves before anything digests it", () => {
  const me = "A".repeat(40);
  const roster = { alice: me, bob: "B".repeat(40) };

  /** The notebook source a run digests is `serializeRecipe(chains)`. */
  async function manifestFor(typed) {
    const { ast } = parseRecipe(typed);
    const source = serializeRecipe(ast);
    const { manifest } = await handoffContext({ source, me, roster, title: "t" });
    return manifest;
  }

  it("gives two spellings of one run one manifest", async () => {
    const aliased = await manifestFor("input | openpgp.sign key=$k | out $sig");
    const canonical = await manifestFor("input | gpg.sign key=$k | out $sig");
    expect(aliased.recipeSource).toBe("input | gpg.sign key=$k | out $sig");
    expect(aliased.recipeSource).toBe(canonical.recipeSource);
    expect(aliased.recipeDigest).toBe(canonical.recipeDigest);
    expect(aliased.cells).toEqual(canonical.cells);
    expect(aliased).toEqual(canonical);
  });

  it("is the control: two runs that really differ still differ", async () => {
    // Without this the assertion above is satisfied by a manifest that ignores
    // the recipe entirely.
    const a = await manifestFor("input | openpgp.sign key=$k | out $sig");
    const b = await manifestFor("input | openpgp.verify key=$k | out $sig");
    expect(a.recipeDigest).not.toBe(b.recipeDigest);
  });
});

describe("refusal names the half that was understood", () => {
  it("names the module and what it actually holds", () => {
    const { errors } = parseRecipe("openpgp.seal");
    expect(errors).toHaveLength(1);
    const msg = errors[0].message;
    // The state that is true: the namespace resolved, the verb did not.
    expect(msg).toContain('Unknown step "openpgp.seal"');
    expect(msg).toContain("`openpgp.` is a second spelling of `gpg.`");
    expect(msg).toContain("which has no `seal`");
    for (const name of GPG_STEPS) expect(msg).toContain(name);
    // Not the generic message it used to be.
    expect(msg).not.toContain("See the Reference panel");
  });

  it("leaves an unknown namespace to the generic message", () => {
    // `pgp` is not a declared module alias, so there is nothing true to say
    // about its prefix and the hint must stay quiet rather than invent one.
    expect(moduleAliasHint("pgp.encrypt")).toBeNull();
    expect(moduleAliasHint("encrypt")).toBeNull();
    expect(parseRecipe("pgp.encrypt").errors[0].message).toContain(
      "See the Reference panel"
    );
  });

  it("does not steal the legacy-token hint", () => {
    // A legacy token has a rewrite to name, which is the more actionable fact.
    expect(parseRecipe("aesgcm").errors[0].message).toContain("aes-gcm");
  });
});
