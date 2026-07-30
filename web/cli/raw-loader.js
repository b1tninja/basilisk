/**
 * Node ESM loader hooks for Vite's `?raw` asset imports.
 *
 * Two library modules read a wordlist as text through Vite's `?raw` suffix:
 * `lib/slip39/wordlist.js` (SLIP-0039, needed by `blip39` — a core headless op)
 * and `lib/passphrase-gen.js` (EFF large wordlist). Plain Node refuses both
 * with `Unknown file extension ".txt"`.
 *
 * The fix belongs here, not in those modules. Both files ship *verbatim* so
 * they can be checked against their publishers' SHA-256 — converting them to
 * `.js` string modules to appease Node would destroy that property, and
 * forking a Node-only copy of the wordlist would be worse still. So the CLI
 * teaches Node the one thing it is missing: how to read a text file as a
 * module. Vitest already does this via Vite's own transform, which is why the
 * in-process tests never register these hooks.
 *
 * Registered by `cli/basilisk.js` before the engine is imported.
 * @module cli/raw-loader
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const RAW = "?raw";

/**
 * @param {string} specifier
 * @param {{ parentURL?: string }} context
 * @param {Function} nextResolve
 */
export async function resolve(specifier, context, nextResolve) {
  if (specifier.endsWith(RAW)) {
    const bare = specifier.slice(0, -RAW.length);
    const url = new URL(bare, context.parentURL).href;
    return { url: `${url}${RAW}`, format: "module", shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

/**
 * @param {string} url
 * @param {object} context
 * @param {Function} nextLoad
 */
export async function load(url, context, nextLoad) {
  if (url.endsWith(RAW)) {
    const path = fileURLToPath(url.slice(0, -RAW.length));
    const text = await readFile(path, "utf8");
    return {
      format: "module",
      shortCircuit: true,
      source: `export default ${JSON.stringify(text)};`,
    };
  }
  return nextLoad(url, context);
}
