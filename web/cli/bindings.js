/**
 * Runtime input bindings for the headless CLI.
 *
 * The notebook feeds `input` / `shares` / `gpg.decrypt` from paste panels via
 * `RuntimeBindings` (see `useNotebook`'s buildBindings). Headless, the same
 * shape is assembled from flags, files and stdin — the engine never learns the
 * difference, which is the point: one code path, two front ends.
 *
 * On passphrases: there is no `--passphrase` flag, deliberately. A bare flag
 * lands in `~/.bash_history`, in `ps` output for every user on the box, and in
 * CI job logs. `--passphrase-env VAR` reads it from the environment instead,
 * where it is at least scoped to the process. Piping is also fine
 * (`--passphrase-env` on a var you `read -s` into).
 * @module cli/bindings
 */

import { readFileSync } from "node:fs";

/**
 * @typedef {object} BindingSpec
 * @property {string} [input]        literal text for the `input` op
 * @property {string} [inputFile]    file whose contents feed `input`
 * @property {string} [shares]       file, one BLIP39 mnemonic per line
 * @property {string} [ciphertext]   file holding OpenPGP armor (or an envelope)
 * @property {string} [passphraseEnv] env var name holding the passphrase
 * @property {boolean} [stdinInput]  use piped stdin as `input` text
 */

/** @param {string} path */
function readText(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`cannot read ${path}: ${/** @type {*} */ (err)?.message || err}`);
  }
}

/**
 * Split a shares file into mnemonics: one per line, blanks and `#` comments
 * dropped. Blank-line-separated blocks are joined, so a file that wraps long
 * mnemonics across lines still works.
 * @param {string} text
 * @returns {string[]}
 */
export function parseSharesFile(text) {
  return String(text)
    .split(/\n\s*\n/)
    .map((block) =>
      block
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"))
        .join(" ")
        .replace(/\s+/g, " ")
        .trim()
    )
    .filter(Boolean);
}

/**
 * Assemble `RuntimeBindings` from CLI options.
 * @param {BindingSpec} spec
 * @param {{ env?: Record<string, string|undefined>, stdin?: string }} [ctx]
 * @returns {import("../src/lib/toolkit/engine.js").RuntimeBindings}
 */
export function buildBindings(spec = {}, ctx = {}) {
  const env = ctx.env || process.env;
  /** @type {*} */
  const inputs = {};

  let text = spec.input;
  if (text == null && spec.inputFile) text = readText(spec.inputFile);
  if (text == null && spec.stdinInput && ctx.stdin != null) text = ctx.stdin;
  if (text != null) inputs.text = { value: String(text) };

  if (spec.shares) {
    const mnemonics = parseSharesFile(readText(spec.shares));
    if (!mnemonics.length) {
      throw new Error(`--shares ${spec.shares}: no mnemonics found`);
    }
    inputs.shares = { mnemonics };
  }

  if (spec.ciphertext) {
    const armored = readText(spec.ciphertext).trim();
    if (!armored) throw new Error(`--ciphertext ${spec.ciphertext}: file is empty`);
    // `gpg.decrypt` reads armoredMessages; envelope-consuming ops read
    // `envelope.armored`. One file can legitimately be either, so bind both
    // rather than making the caller guess which op will want it.
    inputs.gpg = { ...(inputs.gpg || {}), armoredMessages: [armored] };
    inputs.envelope = { armored };
  }

  if (spec.passphraseEnv) {
    const value = env[spec.passphraseEnv];
    if (value == null || value === "") {
      throw new Error(
        `--passphrase-env ${spec.passphraseEnv}: environment variable is unset or empty`
      );
    }
    inputs.gpg = { ...(inputs.gpg || {}), passphrase: value };
    inputs.shares = { mnemonics: [], ...(inputs.shares || {}), passphrase: value };
  }

  return { inputs };
}
