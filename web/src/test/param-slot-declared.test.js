/**
 * A parameter says what value it needs *and* how the value may be supplied.
 *
 * `ParamSpec.type` used to answer both with one word, badly. `type: "slot"`
 * said *how* and never said *what*; `type: "string"` said *what* and implied a
 * literal — while the runtime took a slot anyway, because "is this a slot?"
 * was answered by looking at the first character of the value. Six params were
 * known to be on the wrong side of that line (`passphrase=`, `aad=`, `salt=`,
 * `info=`, `signature=`, `gpg.encrypt to=`); a sweep found eleven, and one of
 * the eleven — `age.encrypt passphrase=` — was declared `secret: true`, bound
 * to a slot by the UI, and encrypted the file under the string `$pw`.
 *
 * So the gate is not "did the six get fixed". It is: *derive* the set of
 * params the compiler reads as slots, and require the registry to match it
 * exactly, in both directions. Reading 268 declarations would miss cases; the
 * sweep below cannot, because it asks the compiler rather than the reader.
 *
 * The probe is the "unknown slot" error. Only code paths that treat a value as
 * a reference emit it — a param that reads `$probe` as a literal string says
 * nothing at all. Registering `$probe` first and varying the type it holds
 * gives the second axis, `slotOf`.
 *
 * `emptyMeans` and `entropy` before it: the field defaults to the value that
 * fails closed, so omission is caught rather than assumed. That is why the
 * migration *was* the audit.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { STEPS, getStep } from "../lib/toolkit/registry.js";
import { compileRecipe, parseRecipe, registryIssues } from "../lib/toolkit/recipe.js";
import { walkPipelineTypes } from "../lib/toolkit/types.js";

/** Every `[step, param]` pair in the registry. */
const PARAMS = STEPS.flatMap((s) => (s.params || []).map((p) => [s.name, p]));

const PROBE = "$slotprobe";

const errorsFor = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message);

/** Does the compiler read this param's value as a slot reference? */
function readsAsSlot(stepName, paramName) {
  return errorsFor(`${stepName} ${paramName}=${PROBE}`).some(
    (m) => m.includes("slotprobe") && /unknown slot|no slot registered/i.test(m)
  );
}

/**
 * Chains that register `$slotprobe` holding each pipeline type a `slotOf`
 * names. Verified below to hold what they claim — a producer that quietly
 * changed shape would turn this whole file into a tautology.
 */
const PRODUCERS = {
  bytes: "random 32",
  text: "passphrase",
  keypair: "genkey ec/p256",
  key: "random 32 | hkdf as=aes/256",
  "openpgp-key": "agent.pub",
  recipients: "hkp.search alice@example.org",
  endpoint: "rtc.ice",
};

/** The refined base a producer chain leaves in `$slotprobe`. */
function producedBase(chain) {
  const { ast } = parseRecipe(`${chain} | out ${PROBE}`);
  const slots = new Map();
  walkPipelineTypes(ast?.steps || [], { getStep }, slots);
  return slots.get("slotprobe")?.base ?? null;
}

/** The producer bases the compiler will accept for `step param=$slotprobe`. */
function acceptedBases(stepName, paramName) {
  const ok = [];
  for (const [base, chain] of Object.entries(PRODUCERS)) {
    const bad = errorsFor(`${chain} | out ${PROBE}\n\n${stepName} ${paramName}=${PROBE}`)
      .filter((m) => m.includes("slotprobe"));
    if (!bad.length) ok.push(base);
  }
  return ok.sort();
}

describe("the producers this file measures with", () => {
  it("register the type each one claims", () => {
    for (const [base, chain] of Object.entries(PRODUCERS)) {
      expect(producedBase(chain), `${chain} | out ${PROBE}`).toBe(base);
    }
  });
});

describe("every param the compiler reads as a slot says so", () => {
  it("declares slot wherever a $ref is resolved rather than taken literally", () => {
    // The forward direction, and the one that found the defect: a param can
    // accept a reference without any declaration saying it does, because the
    // leading sigil was the whole rule.
    const undeclared = PARAMS.filter(
      ([step, p]) => !p.slot && readsAsSlot(step, p.name)
    ).map(([step, p]) => `${step} ${p.name}=`);
    expect(
      undeclared,
      `${undeclared.join(", ")} resolve a $ref at compile time but do not ` +
        `declare it. Add slot: true (literal or $ref) or slot: "required" ` +
        `($ref only), and slotOf for the type the ref must resolve to.`
    ).toEqual([]);
  });

  it("is read as a slot wherever it declares one", () => {
    // The reverse drift. A declaration the compiler ignores is worse than no
    // declaration: it reads as a check that is being made.
    const inert = PARAMS.filter(
      ([step, p]) => p.slot && !readsAsSlot(step, p.name)
    ).map(([step, p]) => `${step} ${p.name}=`);
    expect(
      inert,
      `${inert.join(", ")} declare slot, but binding a $ref there raises no ` +
        `unknown-slot error — nothing resolves it. Either wire the param ` +
        `through validateStepSlotParams or drop the declaration.`
    ).toEqual([]);
  });

  it("refuses a $ref on a param that takes a literal", () => {
    // The compile-time half of the fix. `hkdf length=$n` used to reach the
    // runtime holding the two characters `$n`.
    const literalParam = PARAMS.find(([, p]) => !p.slot && p.type === "int");
    const [step, p] = literalParam;
    expect(errorsFor(`${step} ${p.name}=${PROBE}`)).toContain(
      `${step} ${p.name}=${PROBE}: ${p.name}= takes a literal, not a slot`
    );
  });

  it("still lets `out $label` write a slot", () => {
    // `out` is the one place a `$` is a binding occurrence rather than a
    // reference, so the rule above must not fire on it.
    expect(compileRecipe("random 32 | out $kp").validation.ok).toBe(true);
  });
});

describe("slotOf names the types the compiler actually accepts", () => {
  it("accepts exactly the declared set, no more and no less", () => {
    const drift = [];
    for (const [step, p] of PARAMS) {
      if (!p.slot || !p.slotOf) continue;
      const want = (Array.isArray(p.slotOf) ? p.slotOf : [p.slotOf])
        .filter((t) => t in PRODUCERS)
        .sort();
      const got = acceptedBases(step, p.name);
      if (want.join(",") !== got.join(",")) {
        drift.push(`${step} ${p.name}= declares ${want.join("|")}, accepts ${got.join("|") || "nothing"}`);
      }
    }
    expect(
      drift,
      `${drift.join("; ")}. slotOf is the compile-time contract for what a ` +
        `ref may resolve to; if the compiler and the declaration disagree, ` +
        `the declaration is decoration.`
    ).toEqual([]);
  });

  it("is omitted only where no type can honestly be named", () => {
    // `in $x` takes whatever was registered. Everywhere else, leaving slotOf
    // off would silently drop the type check on that input.
    const untyped = PARAMS.filter(([, p]) => p.slot && !p.slotOf).map(
      ([step, p]) => `${step} ${p.name}=`
    );
    expect(untyped).toEqual(["in ref="]);
  });
});

describe("the two axes stay apart", () => {
  it("never spells a supply mechanism as a value kind again", () => {
    // `type: "slot"` said how a value arrives and left what it is unsaid.
    for (const [step, p] of PARAMS) {
      expect(p.type, `${step} ${p.name}=`).not.toBe("slot");
    }
    const source = readFileSync(
      fileURLToPath(new URL("../lib/toolkit/registry.js", import.meta.url)),
      "utf8"
    ).replace(/\r\n/g, "\n");
    expect(source).not.toMatch(/type: "slot"/);
    // registryIssues owns the allowed set; `slot` must not creep back into it.
    expect(registryIssues()).toEqual([]);
    expect(
      compileRecipe("random 32 | out $kp").validation.ok,
      "sanity: the corpus compiles"
    ).toBe(true);
  });

  it("gives every param a value kind", () => {
    const KINDS = new Set(["enum", "int", "string", "bytes", "bool", "flag"]);
    for (const [step, p] of PARAMS) {
      expect(KINDS.has(p.type), `${step} ${p.name}= type=${p.type}`).toBe(true);
    }
  });

  it("declares slot on every param the UI locks to one", () => {
    // `secret: true` means the field renders a slot picker and serialize drops
    // any literal. `age.encrypt passphrase=` carried that flag while nothing
    // resolved the ref — the value reached typage as `$pw`.
    for (const [step, p] of PARAMS) {
      if (!p.secret) continue;
      expect(p.slot, `${step} ${p.name}= is secret: true`).toBeTruthy();
    }
  });
});
