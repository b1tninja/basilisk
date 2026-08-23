/**
 * Every way into the engine is FIPS-gated, or is on this list with a reason.
 *
 * `assertRecipeAllowedUnderFips` fires for a caller that puts `fipsMode` into
 * the bindings it hands `runRecipe`. For a long time exactly one caller did,
 * and it was `executeToolkitRun` — reached by a crypto-worker message nothing
 * in the app ever posted — so the switch flagged a recipe and then ran it
 * anyway. That caller has since been deleted along with the arm, and the
 * notebook is wired, so the one gated way in is a way in something uses.
 *
 * The failure that produced was not "the gate is wrong"; it was that nobody
 * could see which callers reached the gate and which did not. This sweeps the
 * source for the callers and makes the answer a list. A new way into the engine
 * either routes the flag or has to be argued onto `UNGATED` — which is the
 * difference between an exemption and an oversight.
 *
 * Source-scanning on purpose. The question is "does this call site route the
 * flag", which is a fact about the code rather than about a run, and a
 * behavioural test would only prove the paths it happened to drive.
 */
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../", import.meta.url));

/**
 * Ways into the engine that deliberately route no `fipsMode`.
 *
 * May only shrink. Each entry is a claim that the switch *should not* reach
 * that path, and the claim has to survive being read.
 */
const UNGATED = {
  // The suite self-check. FIPS refuses runs that reach an unverified suite;
  // this exists to find out whether a suite works, so gating it would answer
  // the question by declining to ask it. Nothing a person typed reaches it.
  "lib/toolkit/conjugate-smoke.js":
    "the suite self-check, which must be able to test an unverified suite",
};

/**
 * The file with its comments removed.
 *
 * Every check below asks whether the *code* does something, and the first draft
 * of this file could not tell code from prose: the exemption assertion failed
 * against the paragraph in `conjugate-smoke.js` explaining why it is exempt,
 * because that paragraph says the word `fipsMode`. A sweep a comment can
 * satisfy is a sweep documentation can silence.
 *
 * One honest gap: only the exemption check below is currently *proved* to need
 * this. Swapping `codeOf` for the raw text in the `routed` check survives as a
 * mutation, because the sole file whose comments say `fipsMode` is the one that
 * check skips. It stays because it is correct, not because a test forces it —
 * and the first non-exempt caller to explain FIPS in a comment is what would
 * make it matter.
 */
function codeOf(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
}

/** Every source file under `src/`, excluding the tests that measure it. */
function sourceFiles(dir = "", out = []) {
  for (const entry of readdirSync(SRC + dir, { withFileTypes: true })) {
    const rel = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (rel === "test" || entry.name === "node_modules") continue;
      sourceFiles(rel, out);
    } else if (/\.(js|ts|tsx)$/.test(entry.name)) {
      out.push(rel);
    }
  }
  return out;
}

/** Files whose code calls `runRecipe(` or `.runAll(`, excluding the engine. */
function engineCallers() {
  return sourceFiles()
    .filter((rel) => rel !== "lib/toolkit/engine.js")
    .filter((rel) => /\brunRecipe\s*\(|\.runAll\s*\(/.test(codeOf(readFileSync(SRC + rel, "utf8"))))
    .sort();
}

describe("the FIPS gate reaches every way into the engine", () => {
  it("finds the callers it is measuring", () => {
    // An empty sweep passes every assertion below it.
    //
    // The sweep finds exactly two now — `kernel.js` and `conjugate-smoke.js` —
    // so this bound has no slack left. It was three until `toolkit-run.js` was
    // deleted with the crypto-worker arm nothing posted. A third disappearing
    // is the scan breaking, which is what this is for.
    const callers = engineCallers();
    expect(callers.length, "no engine callers found at all — the scan is broken").toBeGreaterThan(1);
    expect(callers, "the notebook's own path is gone from the sweep").toContain(
      "lib/toolkit/kernel.js"
    );
  });

  it("routes the flag from every caller that is not written down as exempt", () => {
    const bad = [];
    for (const rel of engineCallers()) {
      if (rel in UNGATED) continue;
      const code = codeOf(readFileSync(SRC + rel, "utf8"));
      // Either is enough, and the second is why: `kernel.js` forwards the
      // `bindings` it was handed rather than naming the flag, so a caller that
      // passes its bindings through carries whatever the layer above put in
      // them. That indirection is the whole reason the gate was reachable
      // without `kernel.js` ever mentioning FIPS.
      const routed = /fipsMode/.test(code) || /bindings/.test(code);
      if (!routed) bad.push(rel);
    }
    expect(
      bad,
      `these reach the engine with no route for the flag and are not exempt: ${bad.join(", ")}`
    ).toEqual([]);
  });

  it("keeps the exemption list honest — nothing on it has quietly become gated", () => {
    // An exemption that is no longer needed is a comment asserting something
    // untrue about the code beside it.
    for (const rel of Object.keys(UNGATED)) {
      expect(
        engineCallers(),
        `${rel} no longer reaches the engine, so its exemption is stale`
      ).toContain(rel);
      expect(
        /fipsMode/.test(codeOf(readFileSync(SRC + rel, "utf8"))),
        `${rel} routes fipsMode now, so take it off the list`
      ).toBe(false);
    }
  });
});
