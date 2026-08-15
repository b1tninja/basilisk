/**
 * A recipe's runtime input requirements are *derived* from the declarations.
 *
 * They used to be detected. `stepNeedsKeyPanel(step)` was a `switch` over ten
 * op names deciding whether the key panel appeared, `stepNeedsGpgPrivatePanel`
 * a second over four, and the slot-binding errors were computed somewhere else
 * entirely by comparing `out` registrations against references. Two answers to
 * "what does this recipe need from the user", sharing no source.
 *
 * The failure mode was silent by construction. Adding a key param to an op did
 * not add it to the `switch`, and nothing failed when you forgot: the panel
 * simply never appeared and the user saw a recipe that could not be run with no
 * indication what was missing. `stream.seal` and `stream.open` had sat that way
 * — `key` declared `slot: "required"`, the engine falling back to
 * `resolveBoundKey`, and the `switch` never told.
 *
 * So the gate is not "are the twelve ops listed". It is, in both directions:
 *
 * - every param that requires a value contributes an input need (§forward);
 * - every input need is accounted for by a declaration (§reverse);
 * - the ops whose *engine* falls back to a panel are exactly the ops whose
 *   *registry* says so (§the sweep that would have caught it) — derived by
 *   reading the runtime, which is the producer the compiler was guessing about;
 * - and nothing in the derivation knows an op's name (§no list).
 *
 * The last is the one that matters. `param-slot-declared.test.js` earned this
 * shape: reading 268 declarations would miss cases, and a sweep that asks the
 * compiler cannot.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { STEPS, getStep } from "../lib/toolkit/registry.js";
import {
  INPUT_PANELS,
  panelForSlotOf,
  specInputNeeds,
  stepInputDeclarations,
  stepInputNeeds,
  stepUnboundSlots,
} from "../lib/toolkit/input-needs.js";
import { PRESETS, compileRecipe, parseRecipe, recipeChains } from "../lib/toolkit/recipe.js";

const read = (rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8").replace(
    /\r\n/g,
    "\n"
  );

/** Source with comments removed — prose about an op is not knowledge of it. */
const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

/** Every `[step, param]` pair the registry declares a runtime fallback for. */
const UNRESOLVED = STEPS.flatMap((s) =>
  (s.params || []).filter((p) => p.unresolvedInput).map((p) => [s, p])
);

const needsFor = (src) => compileRecipe(src).validation.inputNeeds || [];

/** Arm a param's `requiredWith` gate, if it has one. */
function armed(spec, p) {
  return p.requiredWith ? `${p.requiredWith}=true` : "";
}

describe("every param that requires a value contributes an input need", () => {
  it("asks for a panel wherever a declaration says the run will", () => {
    // Bare, so nothing is bound: the requirement is at its loudest. Type
    // errors from the missing pipeline input do not suppress the need — a
    // recipe that is half-written still has to say what it will want.
    const silent = [];
    for (const [spec, p] of UNRESOLVED) {
      const want = panelForSlotOf(p.slotOf);
      if (!needsFor(`${spec.name} ${armed(spec, p)}`.trim()).includes(want)) {
        silent.push(`${spec.name} ${p.name}= (wanted ${want})`);
      }
    }
    expect(
      silent,
      `${silent.join(", ")} declare unresolvedInput but produce no input need. ` +
        `An unbound param the run will ask for *is* an input need; if the ` +
        `compiler does not report it the panel never opens and the recipe ` +
        `cannot be run, with nothing on screen saying why.`
    ).toEqual([]);
  });

  it("stops asking once a slot supplies the value", () => {
    // The half `unresolvedInputs` at step level could never express, which is
    // why `stepNeedsKeyPanel` had to exist alongside it.
    const stuck = [];
    for (const [spec, p] of UNRESOLVED) {
      const panel = panelForSlotOf(p.slotOf);
      const needs = stepInputNeeds({
        name: spec.name,
        params: Object.fromEntries(
          (spec.params || [])
            .filter((q) => q.unresolvedInput)
            .map((q) => [q.name, "$bound"])
            .concat(p.requiredWith ? [[p.requiredWith, true]] : [])
        ),
      });
      if (needs.includes(panel)) stuck.push(`${spec.name} ${p.name}=`);
    }
    expect(
      stuck,
      `${stuck.join(", ")} still ask for their panel with every ` +
        `unresolvedInput param bound to a slot. Binding is the whole point of ` +
        `\`slot\`; a panel that stays open after it reads as a check nobody made.`
    ).toEqual([]);
  });
});

describe("no input need appears that a declaration does not account for", () => {
  /**
   * Re-derive one step's panels from raw registry fields only.
   *
   * `whenInput:` is the one guard this cannot evaluate: it asks what type is
   * arriving through the pipe, and the whole point of re-deriving from raw
   * fields is to do it without the type walker under test. A step that opens a
   * chain has nothing piped in, and `whenInput` is required to include "none"
   * (`recipe.js` refuses one that does not), so at position 0 the guard always
   * holds. Anywhere else the incoming type is unknown here, and claiming the
   * panel is required would be a guess — `gpg.decrypt count=all | shares` is
   * the shipped case, where a bundle arrives and the tray stays shut.
   *
   * @param {*} step
   * @param {boolean} isFirst  step opens its chain, so nothing is piped in
   */
  function fromDeclarations(step, isFirst) {
    const spec = getStep(step.name);
    if (!spec) return [];
    const out = [];
    for (const d of stepInputDeclarations(spec.unresolvedInputs)) {
      if (d.whenInput && !isFirst) continue;
      const holds = Object.entries(d.when || {}).every(([k, v]) =>
        Array.isArray(v)
          ? v.includes(String(step.params?.[k] ?? ""))
          : String(step.params?.[k] ?? "") === v
      );
      if (holds) out.push(d.panel);
    }
    for (const p of spec.params || []) {
      if (!p.unresolvedInput) continue;
      if (p.requiredWith && !step.params?.[p.requiredWith]) continue;
      const panel = panelForSlotOf(p.slotOf);
      const bound = String(step.params?.[p.name] ?? "").trim() !== "";
      if (!bound) out.push(panel);
      else if (panel === "gpg") out.push("gpgPass");
    }
    return out;
  }

  /**
   * @param {*} steps
   * @param {Set<string>} into
   * @param {boolean} [nested]  inside a `foreach` / `tee` body, where even the
   *   first step is fed the stem — so no step in one opens a chain
   */
  function walk(steps, into, nested = false) {
    (steps || []).forEach((s, i) => {
      for (const n of fromDeclarations(s, !nested && i === 0)) into.add(n);
      walk(s.body, into, true);
      for (const br of s.branches || []) walk(br.body, into, true);
    });
  }

  // Presets are the recipes people actually load; the per-op sweep is what
  // catches an op nobody wrote a preset for — which is the population the
  // hand-written switch kept losing track of.
  const CORPUS = [
    ...PRESETS.map((p) => [`preset ${p.id}`, p.recipe]),
    ...STEPS.map((s) => [`op ${s.name}`, s.name]),
    ...STEPS.flatMap((s) =>
      (s.params || [])
        .filter((p) => p.enum)
        .flatMap((p) =>
          p.enum.map((v) => [`op ${s.name} ${p.name}=${v}`, `${s.name} ${p.name}=${v}`])
        )
    ),
  ];

  it("reports exactly the union the declarations imply", () => {
    const drift = [];
    for (const [id, src] of CORPUS) {
      const { ast } = parseRecipe(src);
      const want = new Set();
      for (const chain of recipeChains(ast)) walk(chain.steps, want);
      const got = new Set(needsFor(src));
      const missing = [...want].filter((n) => !got.has(n));
      const extra = [...got].filter((n) => !want.has(n));
      if (missing.length || extra.length) {
        drift.push(
          `${id}: ${missing.length ? `missing ${missing.join("/")}` : ""}${
            extra.length ? ` unaccounted ${extra.join("/")}` : ""
          }`
        );
      }
    }
    expect(
      drift.slice(0, 20),
      `${drift.join("; ")}. Every entry in inputNeeds must trace to an ` +
        `\`unresolvedInputs\` on the step or an \`unresolvedInput\` param; an ` +
        `entry with no declaration behind it is the parallel vocabulary coming back.`
    ).toEqual([]);
  });

  it("names only panels the UI has a tray for", () => {
    for (const [, src] of CORPUS) {
      for (const n of needsFor(src)) expect(INPUT_PANELS).toContain(n);
    }
  });
});

describe("the ops the runtime asks a panel for are the ops the registry says", () => {
  /**
   * Op names whose engine case falls back to `resolveBoundKey` — i.e. runs
   * without a bound slot by reading the key panel. Derived from the runtime
   * rather than read off a list, because the list is what kept being wrong.
   */
  function opsWithPanelFallback() {
    const lines = read("../lib/toolkit/engine.js").split("\n");
    const found = new Set();
    let labels = [];
    let collecting = false;
    for (const line of lines) {
      const m = line.match(/^\s*case "([^"]+)":/);
      if (m) {
        if (!collecting) labels = [];
        labels.push(m[1]);
        collecting = true;
        continue;
      }
      if (/resolveBoundKey\(/.test(line)) for (const l of labels) found.add(l);
      if (line.trim()) collecting = false;
    }
    return found;
  }

  it("declares unresolvedInput on every op whose engine falls back to a panel", () => {
    // This is the sweep that would have caught `stream.seal` / `stream.open`
    // the day they were written: the engine has always read the key panel for
    // them, and only the hand-written switch disagreed.
    const undeclared = [...opsWithPanelFallback()].filter(
      (name) => !specInputNeeds(getStep(name)).includes("key")
    );
    expect(
      undeclared,
      `${undeclared.join(", ")} fall back to the key panel in engine.js but ` +
        `declare no unresolvedInput param, so no panel opens and the run ` +
        `fails with nothing said. Add \`unresolvedInput: true\` to the key param.`
    ).toEqual([]);
  });

  it("claims no key panel for an op that would never read one", () => {
    const fallback = opsWithPanelFallback();
    const inert = STEPS.filter(
      (s) => specInputNeeds(s).includes("key") && !fallback.has(s.name)
    ).map((s) => s.name);
    expect(
      inert,
      `${inert.join(", ")} advertise the key panel, but their engine case ` +
        `never calls resolveBoundKey — opening the tray would not help. Drop ` +
        `unresolvedInput; the param wants a \`$slot\`, not a panel.`
    ).toEqual([]);
  });
});

describe("the derivation knows no op names", () => {
  it("has no hand-maintained detection to fall out of date", () => {
    // The `switch (step.name)` family, by name and by shape.
    const recipe = read("../lib/toolkit/recipe.js");
    expect(recipe).not.toMatch(/function stepNeeds\w*Panel/);
    // The other half of the old shape: recipe.js reading `unresolvedInputs`
    // and subtracting the values it had decided to handle by hand.
    expect(code(recipe)).not.toMatch(/unresolvedInputs\s*!==/);

    const derivation = code(read("../lib/toolkit/input-needs.js"));
    expect(derivation, "a switch is how the last one started").not.toMatch(
      /\bswitch\s*\(/
    );
    expect(derivation).not.toMatch(/\.name\s*===/);
    // Panels and ops share three spellings (`text`, `shares`, `keypair`);
    // those literals are the panel vocabulary, which is closed and small.
    const panels = new Set(INPUT_PANELS);
    const named = STEPS.map((s) => s.name)
      .filter((n) => !panels.has(n))
      .filter((n) => new RegExp(`["'\`]${n.replace(/\./g, "\\.")}["'\`]`).test(derivation));
    expect(
      named,
      `input-needs.js names ${named.join(", ")} in code. The moment it knows ` +
        `one op it is a list again, and the next op to grow a key param will ` +
        `be the one nobody remembers to add.`
    ).toEqual([]);
  });

  it("gives a panel to an op the registry has never heard of", () => {
    // The property the whole change buys: adding a key param makes the panel
    // appear without touching any list. Nothing below is registered anywhere.
    const invented = {
      name: "nobody.knows.this.op",
      kind: "transform",
      toolbox: "webcrypto",
      doc: "",
      input: "bytes",
      output: "bytes",
      params: [
        {
          name: "key",
          type: "bytes",
          slot: "required",
          unresolvedInput: true,
          slotOf: ["key", "keypair", "bytes", "text"],
          default: "",
        },
      ],
    };
    expect(getStep(invented.name)).toBeFalsy();
    expect(stepInputNeeds({ name: invented.name, params: {} }, invented)).toEqual([
      "key",
    ]);
    expect(
      stepInputNeeds({ name: invented.name, params: { key: "$k" } }, invented)
    ).toEqual([]);
    // …and an OpenPGP-capable slot set renders the other tray, from the type
    // alone. The panel is a view of `slotOf`, not a word chosen per op.
    const pgp = {
      ...invented,
      params: [
        { ...invented.params[0], slotOf: [...invented.params[0].slotOf, "openpgp-key"] },
      ],
    };
    expect(stepInputNeeds({ name: pgp.name, params: {} }, pgp)).toEqual(["gpg"]);
    expect(stepInputNeeds({ name: pgp.name, params: { key: "$k" } }, pgp)).toEqual([
      "gpgPass",
    ]);
  });
});

/* ─────────────── the other half: what nothing will ask for ─────────────── */

/**
 * `stepInputRequirements` finds the params a run will *stop and ask* about.
 * These are the ones it will not: `slot: "required"` and no `unresolvedInput`
 * means there is no tray behind the param, so an empty one is not a question
 * deferred to run time, it is an error deferred to run time.
 *
 * `input | utf8 | ssh.sign` compiles with no error and no warning, and dies
 * on "SSH: key= (private key slot) is required" — which is the fourth entry in
 * `ReadinessBar`'s own priority list, "blocked required param", written into
 * its doc comment at §20e and never given a producer.
 */
describe("a param nothing will ask for is named before the run", () => {
  /** An op no registry has heard of, so nothing here can be a list lookup. */
  const invented = (param) => ({
    name: "nobody.knows.this.op",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "",
    input: "bytes",
    output: "bytes",
    params: [{ name: "key", type: "bytes", slot: "required", slotOf: ["key"], ...param }],
  });

  const flags = (spec, params = {}) =>
    stepUnboundSlots({ name: spec.name, params }, spec).map((u) => u.param);

  it("flags a slot-only param with no panel, no default and no declared blank", () => {
    expect(getStep("nobody.knows.this.op")).toBeFalsy();
    expect(flags(invented({}))).toEqual(["key"]);
    expect(flags(invented({ default: "" }))).toEqual(["key"]);
  });

  it("is quiet once the recipe binds it", () => {
    expect(flags(invented({}), { key: "$k" })).toEqual([]);
  });

  it("is quiet when a declaration says an empty one is a choice", () => {
    // The three ways to say so, each meaning something different: the value
    // arrives anyway, blank has a named effect, or the need is not armed.
    expect(flags(invented({ default: "builtin" }))).toEqual([]);
    expect(flags(invented({ emptyMeans: "the key already in the pipeline" }))).toEqual([]);
    const gated = invented({ requiredWith: "sign" });
    gated.params.push({ name: "sign", type: "bool", default: false });
    expect(flags(gated)).toEqual([]);
    expect(flags(gated, { sign: true })).toEqual(["key"]);
  });

  it("is quiet when the run has a panel to ask through", () => {
    // The two halves must not both fire: a param with a tray behind it is
    // `stepInputRequirements`' business, and reporting it here as well would
    // put two sentences on screen for one missing value.
    const withPanel = invented({ unresolvedInput: true });
    expect(stepInputNeeds({ name: withPanel.name, params: {} }, withPanel)).toEqual(["key"]);
    expect(flags(withPanel)).toEqual([]);
  });

  it("exempts nothing in the registry by accident", () => {
    // The reverse direction, and the one that keeps the derivation honest: for
    // every slot-only param it stays quiet about, some declaration has to say
    // why. Silence with nothing behind it is how the old switch went stale.
    const unexplained = [];
    for (const s of STEPS) {
      const params = {};
      for (const p of s.params || []) if (p.default !== undefined) params[p.name] = p.default;
      const flagged = new Set(stepUnboundSlots({ name: s.name, params }, s).map((u) => u.param));
      for (const p of s.params || []) {
        if (p.slot !== "required" || flagged.has(p.name)) continue;
        const declared =
          p.unresolvedInput ||
          p.emptyMeans ||
          p.requiredWith ||
          (p.default !== undefined && String(p.default).trim() !== "");
        if (!declared) unexplained.push(`${s.name}.${p.name}`);
      }
    }
    expect(
      unexplained,
      `${unexplained.join(", ")} take only a $slot, will not be asked for, and ` +
        `are passed over anyway with no declaration saying an empty one is ` +
        `allowed. Either the run needs them — in which case they should be ` +
        `flagged — or write \`emptyMeans\`, which the field, its hint and the ` +
        `tool card all render.`
    ).toEqual([]);
  });

  it("stays off the four params whose blank state was undeclared", () => {
    // These four read as missing bindings until each was given the declaration
    // its behaviour already had. Pinned because losing one turns a true warning
    // into a false one on an ordinary recipe, which is how a warning becomes
    // noise: `ssh.decode` opens an unprotected block or uses the Inputs
    // passphrase; `vss.verify` reads commitments off the share set;
    // `rtc.ice credential=` means nothing without a `turn=`; and `age.decrypt`
    // takes an identity *or* a passphrase.
    const bare = (name) => {
      const spec = getStep(name);
      const params = {};
      for (const p of spec.params || []) if (p.default !== undefined) params[p.name] = p.default;
      return stepUnboundSlots({ name, params }, spec).map((u) => u.param);
    };
    expect(bare("ssh.decode")).not.toContain("passphrase");
    expect(bare("vss.verify")).not.toContain("commitments");
    expect(bare("rtc.ice")).not.toContain("credential");
    expect(bare("age.decrypt")).not.toContain("key");
    // …and the gate really is the `turn=` that arms it, not a blanket exemption.
    expect(
      stepUnboundSlots({ name: "rtc.ice", params: { turn: "turn:relay.example:3478" } })
        .map((u) => u.param)
    ).toEqual(["credential"]);
  });

  it("names a case the compiler passes clean today", () => {
    // The whole justification, stated as a fact about the compiler rather than
    // an opinion: this recipe has no error and no warning about `key=`, and
    // will not run.
    const { validation } = compileRecipe("input | utf8 | ssh.sign");
    expect(validation.ok).toBe(true);
    expect(validation.errors).toEqual([]);
    expect(validation.warnings.map((w) => w.message).join(" ")).not.toMatch(/key=/);
    expect(stepUnboundSlots({ name: "ssh.sign", params: {} }).map((u) => u.param)).toEqual([
      "key",
    ]);
  });
});

describe("the readiness line is where it lands", () => {
  const SHELL = read("../toolkit/ToolkitShell.tsx");

  it("feeds ReadinessBar rather than inventing a second panel", () => {
    expect(SHELL).toMatch(/import \{ stepUnboundSlots \}/);
    expect(SHELL).toMatch(/unbound = focused \? unboundSlotBlockers\(chain, i\) : \[\]/);
    expect(SHELL).toMatch(/focused && \(needs\.length \|\| unbound\.length\)/);
  });

  it("walks nests, so a step inside a tee is not quietly exempt", () => {
    // `collectProfileOverrides` set the shape; a walk that stopped at the top
    // level would be wrong exactly where a recipe is hardest to read.
    expect(SHELL).toMatch(/\(step\.body \|\| \[\]\)\.forEach[\s\S]{0,200}branches/);
  });

  it("opens the field it is talking about", () => {
    // A tray cannot supply this — the fix is a line of recipe — so the action
    // has to reach the param editor. `setFocusParamHint` now carries the op
    // with the param because `key` is a param on a dozen ops.
    expect(SHELL).toMatch(/setChipEdit\(path\);\s*\n\s*setFocusParamHint\(\{ step, param \}\);/);
    expect(SHELL).toMatch(/focusParamHint\?\.step === selectedStep\.name/);
    expect(SHELL).toMatch(/action: `Bind \$\{param\}=`/);
  });
});
