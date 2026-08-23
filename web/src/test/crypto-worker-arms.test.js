/**
 * Every arm the crypto worker answers has something that posts to it.
 *
 * `crypto-worker.js` shipped four arms — `decrypt`, `encrypt`, `toolkit-run`,
 * `generate` — and for a long time only `generate` had a poster. The other
 * three were finished, correct, tested code that no run could reach, and the
 * cost was not the dead bytes. It was that two other places cited them as
 * protections in force: `docs/CRYPTOGRAPHY.md` described the FIPS gate on the
 * `toolkit-run` arm as enforcement, and `lib/pgp/intended-recipient.js` named
 * the `decrypt` arm as where its §13.12 check belonged. Both sentences were
 * true of the file and false of the app, which is the worst combination —
 * a reader who checks the code finds it does exactly what the doc says.
 *
 * The three arms are gone. This sweep is what makes their absence a rule
 * instead of a moment: an arm and a poster are one list, so growing the worker
 * a fifth arm without wiring anything to it fails here, and so does deleting
 * the poster of an arm that stays.
 *
 * Source-scanning on purpose, in the manner of `fips-engine-entrypoints.test.js`
 * and `glyph-shadowing.test.js`. "Does anything post this message" is a fact
 * about the code, and a behavioural test could only prove the arms it thought
 * to drive — which is precisely the blind spot that let three of them rot.
 */
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../", import.meta.url));
const WORKER = "lib/crypto-worker.js";

/**
 * Arms that deliberately have no poster.
 *
 * Empty, and that is the point. May only be added to with an argument that
 * survives being read — an arm nothing posts to is the defect this file exists
 * to catch, so an entry here is a claim that some *other* thing posts it: a
 * browser, an extension, a page embedding the app. "We will wire it later" is
 * not such a claim.
 */
const UNPOSTED = {};

/**
 * The file with its comments removed.
 *
 * Load-bearing, and measured to be: comment out the `postMessage` in
 * `generate-key.js` and the sweep with `codeOf` fails as it should, while the
 * same sweep reading raw text passes — it counts the commented-out call as a
 * live poster. That is not a hypothetical mutation. Commenting out the caller
 * is one of the ordinary ways an arm becomes orphaned, and it is the way this
 * sweep would be least able to see.
 *
 * It is *not* what keeps the worker's own header from being read as four arms
 * and a poster; the header narrates the deleted arms in prose, and prose
 * matches neither `msg.type === "…"` nor a `postMessage` payload. The arm scan
 * would survive losing this. The poster scan would not.
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

/** The message types `crypto-worker.js` branches on. */
function arms() {
  const code = codeOf(readFileSync(SRC + WORKER, "utf8"));
  return [...code.matchAll(/msg\.type\s*===\s*"([^"]+)"/g)]
    .map((m) => m[1])
    .sort();
}

/** Files whose code builds a `Worker` from `crypto-worker.js`. */
function workerHolders() {
  return sourceFiles()
    .filter((rel) => rel !== WORKER)
    .filter((rel) =>
      /new\s+Worker\s*\([^)]*crypto-worker\.js/.test(
        codeOf(readFileSync(SRC + rel, "utf8"))
      )
    )
    .sort();
}

/** The message types those files actually post, with the file that posts each. */
function posted() {
  /** @type {Map<string, string[]>} */
  const byType = new Map();
  for (const rel of workerHolders()) {
    const code = codeOf(readFileSync(SRC + rel, "utf8"));
    for (const call of code.matchAll(/postMessage\s*\(\s*\{([\s\S]*?)\}\s*\)/g)) {
      for (const t of call[1].matchAll(/\btype\s*:\s*"([^"]+)"/g)) {
        byType.set(t[1], [...(byType.get(t[1]) || []), rel]);
      }
    }
  }
  return byType;
}

describe("the crypto worker's arms and its posters are one list", () => {
  it("finds what it is measuring", () => {
    // An empty scan on either side passes every assertion below it, and the
    // regexes are the fragile part of this file — a rename of `msg` or a
    // reformat of the `postMessage` call silently empties one.
    expect(arms(), "no arms found — the arm scan is broken").not.toEqual([]);
    expect(
      workerHolders(),
      "nothing in src constructs the crypto worker — the holder scan is broken"
    ).toContain("lib/generate-key.js");
    expect(
      [...posted().keys()],
      "no posted message types found — the poster scan is broken"
    ).not.toEqual([]);
  });

  it("answers no message type that nothing posts", () => {
    const posts = posted();
    const orphans = arms().filter((a) => !posts.has(a) && !(a in UNPOSTED));
    expect(
      orphans,
      `crypto-worker.js handles these and nothing posts them: ${orphans.join(", ")}. ` +
        "Wire a caller, delete the arm, or argue it onto UNPOSTED — but do not " +
        "leave it, because other files will start citing it as a live defence."
    ).toEqual([]);
  });

  it("is not posted a message type it does not answer", () => {
    const handled = new Set([...arms(), ...Object.keys(UNPOSTED)]);
    const unanswered = [...posted().entries()]
      .filter(([type]) => !handled.has(type))
      .map(([type, files]) => `${type} (from ${files.join(", ")})`);
    expect(
      unanswered,
      `these are posted to the worker and fall through to "Unknown worker ` +
        `message type": ${unanswered.join(", ")}`
    ).toEqual([]);
  });

  it("keeps UNPOSTED honest — nothing on it has quietly gained a poster", () => {
    // An exemption that is no longer needed is a comment asserting something
    // untrue about the code beside it.
    const posts = posted();
    const armSet = new Set(arms());
    for (const type of Object.keys(UNPOSTED)) {
      expect(armSet, `UNPOSTED names "${type}", which is not an arm`).toContain(type);
      expect(
        posts.has(type),
        `"${type}" has a poster now, so take it off UNPOSTED`
      ).toBe(false);
    }
  });

  it("still generates keys in a worker, which is the one arm worth the boundary", () => {
    // Not redundant with the pairing above: the pairing is satisfied by zero
    // arms and zero posters. `generate` earns the worker specifically —
    // `generate-key.js` calls `terminate()` the moment the armored key comes
    // back, so the heap that held the fresh private key dies with it and the
    // main thread never sees the key object. If this arm is ever removed, that
    // property leaves with it and the deletion should be argued, not silent.
    expect(arms()).toContain("generate");
    const genCode = codeOf(readFileSync(SRC + "lib/generate-key.js", "utf8"));
    expect(genCode, "the worker is no longer terminated after keygen").toMatch(
      /\.terminate\s*\(\s*\)/
    );
  });
});
