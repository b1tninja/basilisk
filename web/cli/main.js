/**
 * `basilisk` — run Basilisk toolkit recipes headlessly. Command implementations.
 *
 * The registry / recipe / engine layer is pure JS and Node ships WebCrypto, so
 * this is packaging, not a second engine: every command below drives the exact
 * modules the toolkit page drives (`compileRecipe`, `createKernel`,
 * `listSteps`). Nothing is forked, and ops that genuinely need a browser say so
 * by name instead of crashing (see `cli/capability.js`).
 *
 *   basilisk check recipe.txt
 *   basilisk run recipe.txt --out-dir ./artifacts
 *   basilisk list-ops --json
 *
 * `cli/basilisk.js` is the executable wrapper; this module is what the tests
 * import, so `main()` is pure with respect to stdout/stderr/env — it writes
 * through the `CliIO` it is handed and returns an exit code rather than
 * calling `process.exit`.
 * @module cli/main
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { compileRecipe, recipeChains } from "../src/lib/toolkit/recipe.js";
import { listSteps } from "../src/lib/toolkit/registry.js";
import { buildBindings } from "./bindings.js";
import {
  BrowserOnlyError,
  browserOnlySteps,
  classifyBrowserFailure,
} from "./capability.js";

export const EXIT = {
  ok: 0,
  usage: 1,
  invalidRecipe: 2,
  runtime: 3,
  browserOnly: 4,
};

const USAGE = `basilisk — run Basilisk toolkit recipes headlessly

Usage:
  basilisk run <recipe>       Compile, validate and execute a recipe
  basilisk check <recipe>     Compile and validate only (non-zero if invalid)
  basilisk list-ops           Dump the op registry

Run options:
  --out-dir <dir>             Write each artifact to a file in <dir>
  --json                      Emit artifacts as JSON instead of text blocks
  --input <text>              Text for the \`input\` op
  --input-file <file>         Same, read from a file
  --stdin                     Same, read from piped stdin
  --shares <file>             BLIP39 mnemonics, one per line, for \`shares\`
  --ciphertext <file>         OpenPGP armor for \`gpg.decrypt\` / envelope ops
  --private-key <file>        Armored OpenPGP private key (the key panel's job;
                              there is no vault headless — \`agent.*\` is
                              browser-only)
  --passphrase-env <VAR>      Read the passphrase from an environment variable
                              (there is no --passphrase: it would land in shell
                              history, in \`ps\`, and in CI logs)

check options:
  --json                      Emit errors and warnings as JSON

list-ops options:
  --json                      Emit the registry as JSON
  --toolbox <name>            Only ops in that toolbox

Exit codes: 0 ok · 1 usage · 2 invalid recipe · 3 runtime error · 4 browser-only op
`;

const FLAGS_WITH_VALUE = new Set([
  "--out-dir",
  "--input",
  "--input-file",
  "--shares",
  "--ciphertext",
  "--private-key",
  "--passphrase-env",
  "--toolbox",
]);

const BOOL_FLAGS = new Set(["--json", "--stdin", "--help", "-h", "--quiet"]);

/**
 * @param {string[]} argv
 * @returns {{ command: string, positional: string[], options: Record<string, string|boolean> }}
 */
export function parseArgs(argv) {
  /** @type {Record<string, string|boolean>} */
  const options = {};
  /** @type {string[]} */
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("-")) {
      positional.push(arg);
      continue;
    }
    // `--flag=value` and `--flag value` both work.
    const eq = arg.indexOf("=");
    const name = eq >= 0 ? arg.slice(0, eq) : arg;
    if (FLAGS_WITH_VALUE.has(name)) {
      const value = eq >= 0 ? arg.slice(eq + 1) : argv[++i];
      if (value == null) throw new Error(`${name} requires a value`);
      options[name] = value;
      continue;
    }
    if (BOOL_FLAGS.has(name)) {
      options[name] = true;
      continue;
    }
    throw new Error(`unknown option ${name}`);
  }
  return { command: positional.shift() || "", positional, options };
}

/**
 * Flatten a chain's steps (bodies and tee branches included) so an error can
 * be located by op name.
 * @param {*[]} steps
 * @returns {{ name: string, index: number }[]}
 */
function flattenSteps(steps) {
  /** @type {{ name: string, index: number }[]} */
  const out = [];
  let n = 0;
  const walk = (/** @type {*[]} */ list) => {
    for (const step of list || []) {
      if (!step?.name) continue;
      out.push({ name: String(step.name), index: n++ });
      if (Array.isArray(step.body)) walk(step.body);
      for (const br of step.branches || []) walk(br?.body || []);
    }
  };
  walk(steps);
  return out;
}

/**
 * Render validation errors the way the toolkit's per-cell banner does: the
 * offending op named, then the validator's own message, unchanged.
 * @param {*} ast
 * @param {*[]} errors
 * @returns {string[]}
 */
function formatErrors(ast, errors) {
  const flat = ast ? flattenSteps(ast.chains?.[0]?.steps || ast.steps || []) : [];
  return errors.map((e) => {
    const step = e.stepIndex != null && e.stepIndex >= 0 ? flat[e.stepIndex] : null;
    return step ? `${step.name}: ${e.message}` : String(e.message);
  });
}

/**
 * @param {string} path
 */
function readRecipe(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`cannot read recipe ${path}: ${/** @type {*} */ (err)?.message || err}`);
  }
}

/**
 * @typedef {object} CliIO
 * @property {(s: string) => void} out
 * @property {(s: string) => void} err
 * @property {Record<string, string|undefined>} [env]
 * @property {string} [stdin]
 */

/**
 * @param {string[]} positional
 * @param {Record<string, string|boolean>} options
 * @param {CliIO} io
 */
function cmdCheck(positional, options, io) {
  const path = positional[0];
  if (!path) {
    io.err("check: a recipe file is required");
    return EXIT.usage;
  }
  const { ast, validation } = compileRecipe(readRecipe(path));
  const errors = formatErrors(ast, validation.errors || []);
  const warnings = validation.warnings || [];

  if (options["--json"]) {
    io.out(
      JSON.stringify(
        {
          ok: !!validation.ok,
          errors,
          warnings,
          cells: ast ? recipeChains(ast).length : 0,
          inputNeeds: validation.inputNeeds || [],
        },
        null,
        2
      )
    );
  } else if (!validation.ok) {
    io.err(`${basename(path)}: ${errors.length} error${errors.length === 1 ? "" : "s"}`);
    for (const e of errors) io.err(`  ${e}`);
  } else {
    const cells = ast ? recipeChains(ast).length : 0;
    io.out(`ok — ${cells} cell${cells === 1 ? "" : "s"}`);
    for (const w of warnings) io.out(`  warning: ${w}`);
    const needs = validation.inputNeeds || [];
    if (needs.length) io.out(`  runtime inputs needed: ${needs.join(", ")}`);
  }
  return validation.ok ? EXIT.ok : EXIT.invalidRecipe;
}

/**
 * @param {import("../src/lib/toolkit/engine.js").ToolkitArtifact} art
 * @param {number} n
 */
function artifactHeader(art, n) {
  const tags = [];
  if (art.sensitive) tags.push("sensitive");
  if (art.role) tags.push(`role=${art.role}`);
  const suffix = tags.length ? `  [${tags.join(" ")}]` : "";
  return `── ${n}. ${art.label || art.filename || "artifact"}${
    art.filename ? `  (${art.filename})` : ""
  }${suffix}`;
}

/**
 * @param {import("../src/lib/toolkit/engine.js").ToolkitArtifact[]} artifacts
 * @param {string} dir
 * @returns {string[]} written paths
 */
function writeArtifacts(artifacts, dir) {
  mkdirSync(dir, { recursive: true });
  /** @type {string[]} */
  const written = [];
  const used = new Map();
  for (const art of artifacts) {
    const base = art.filename || `${art.label || "artifact"}.txt`;
    const seen = used.get(base) || 0;
    used.set(base, seen + 1);
    const name = seen ? base.replace(/(\.[^.]*)?$/, (ext) => `-${seen + 1}${ext || ""}`) : base;
    const path = join(dir, name);
    writeFileSync(path, art.content ?? "", "utf8");
    written.push(path);
  }
  return written;
}

/**
 * @param {string[]} positional
 * @param {Record<string, string|boolean>} options
 * @param {CliIO} io
 */
async function cmdRun(positional, options, io) {
  const path = positional[0];
  if (!path) {
    io.err("run: a recipe file is required");
    return EXIT.usage;
  }
  const { ast, validation } = compileRecipe(readRecipe(path));
  if (!validation.ok || !ast) {
    const errors = formatErrors(ast, validation.errors || []);
    io.err(`${basename(path)}: ${errors.length} error${errors.length === 1 ? "" : "s"}`);
    for (const e of errors) io.err(`  ${e}`);
    return EXIT.invalidRecipe;
  }

  const chains = recipeChains(ast);

  // Pre-flight: refuse before doing crypto work rather than half-running a
  // notebook and dying in cell 4.
  for (let i = 0; i < chains.length; i++) {
    const hits = browserOnlySteps(chains[i].steps || [], i);
    if (hits.length) {
      io.err(new BrowserOnlyError(hits[0]).message);
      return EXIT.browserOnly;
    }
  }

  const bindings = buildBindings(
    {
      input: typeof options["--input"] === "string" ? options["--input"] : undefined,
      inputFile:
        typeof options["--input-file"] === "string" ? options["--input-file"] : undefined,
      shares: typeof options["--shares"] === "string" ? options["--shares"] : undefined,
      ciphertext:
        typeof options["--ciphertext"] === "string" ? options["--ciphertext"] : undefined,
      privateKey:
        typeof options["--private-key"] === "string" ? options["--private-key"] : undefined,
      passphraseEnv:
        typeof options["--passphrase-env"] === "string"
          ? options["--passphrase-env"]
          : undefined,
      stdinInput: options["--stdin"] === true,
    },
    { env: io.env, stdin: io.stdin }
  );

  // Lazy: `check` and `list-ops` never touch the engine, so they never pay for
  // loading OpenPGP.js. Same pattern the engine itself uses for browser ops.
  const { createKernel } = await import("../src/lib/toolkit/kernel.js");
  const kernel = createKernel();
  /** @type {import("../src/lib/toolkit/engine.js").ToolkitArtifact[]} */
  const all = [];
  try {
    for (let i = 0; i < chains.length; i++) {
      if (!chains[i]?.steps?.length) continue;
      try {
        // One kernel across every cell: `out @slot` in cell 1 is live in cell 3,
        // exactly as in the notebook.
        const artifacts = await kernel.runCell(i, chains[i], bindings);
        all.push(...artifacts);
      } catch (err) {
        const cap = classifyBrowserFailure(err);
        if (cap) {
          const name = String(/** @type {*} */ (err)?.basiliskStep || "");
          const flat = flattenSteps(chains[i].steps || []);
          const hit = flat.find((s) => s.name === name);
          throw new BrowserOnlyError(
            {
              step: name || "(unknown step)",
              capability: cap,
              cellIndex: i,
              stepIndex: hit ? hit.index : -1,
            },
            err
          );
        }
        const name = String(/** @type {*} */ (err)?.basiliskStep || "");
        const where = name ? `cell ${i + 1}, ${name}` : `cell ${i + 1}`;
        throw new Error(`${where}: ${/** @type {*} */ (err)?.message || err}`);
      }
    }

    if (options["--json"]) {
      io.out(
        JSON.stringify(
          all.map((a) => ({
            label: a.label,
            filename: a.filename,
            role: a.role,
            sensitive: !!a.sensitive,
            mime: a.mime,
            stepName: a.stepName,
            content: a.content,
          })),
          null,
          2
        )
      );
    } else {
      for (let n = 0; n < all.length; n++) {
        io.out(artifactHeader(all[n], n + 1));
        if (!options["--quiet"]) io.out(String(all[n].content ?? ""));
      }
      if (!all.length) io.out("(no artifacts)");
    }

    const outDir = options["--out-dir"];
    if (typeof outDir === "string") {
      const written = writeArtifacts(all, outDir);
      io.err(`wrote ${written.length} artifact${written.length === 1 ? "" : "s"} to ${outDir}`);
    }
    return EXIT.ok;
  } finally {
    // Slots and tiles hold key material; do not leave them for the GC.
    kernel.destroy();
  }
}

/**
 * First sentence of a registry doc, for the column view. Registry docs are
 * written for the Reference panel and run to several sentences with examples;
 * `--json` carries them whole.
 * @param {string|undefined} doc
 */
function summary(doc) {
  const line = String(doc || "").split("\n")[0].trim();
  const stop = /^(.*?[.!?])(\s|$)/.exec(line);
  return stop ? stop[1] : line;
}

/**
 * @param {Record<string, string|boolean>} options
 * @param {CliIO} io
 */
function cmdListOps(options, io) {
  // Generated from the registry, never hand-written: an op that stops existing
  // stops being listed, and one that appears needs no edit here.
  let steps = listSteps();
  const toolbox = options["--toolbox"];
  if (typeof toolbox === "string") {
    steps = steps.filter((s) => String(s.toolbox) === toolbox);
    if (!steps.length) {
      io.err(`no ops in toolbox "${toolbox}"`);
      return EXIT.usage;
    }
  }
  if (options["--json"]) {
    io.out(
      JSON.stringify(
        steps.map((s) => ({
          name: s.name,
          toolbox: s.toolbox,
          doc: s.doc,
          input: s.input,
          output: s.output,
        })),
        null,
        2
      )
    );
    return EXIT.ok;
  }
  const width = steps.reduce((m, s) => Math.max(m, String(s.name).length), 0);
  const box = steps.reduce((m, s) => Math.max(m, String(s.toolbox).length), 0);
  for (const s of steps) {
    io.out(`${String(s.name).padEnd(width)}  ${String(s.toolbox).padEnd(box)}  ${summary(s.doc)}`);
  }
  return EXIT.ok;
}

/**
 * @param {string[]} argv
 * @param {CliIO} io
 * @returns {Promise<number>} exit code
 */
export async function main(argv, io) {
  /** @type {ReturnType<typeof parseArgs>} */
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    io.err(String(/** @type {*} */ (err)?.message || err));
    io.err(USAGE);
    return EXIT.usage;
  }
  const { command, positional, options } = parsed;

  if (!command || options["--help"] || options["-h"]) {
    io.out(USAGE);
    return command ? EXIT.ok : EXIT.usage;
  }

  try {
    switch (command) {
      case "check":
        return cmdCheck(positional, options, io);
      case "run":
        return await cmdRun(positional, options, io);
      case "list-ops":
        return cmdListOps(options, io);
      default:
        io.err(`unknown command "${command}"`);
        io.err(USAGE);
        return EXIT.usage;
    }
  } catch (err) {
    if (err instanceof BrowserOnlyError) {
      io.err(err.message);
      return EXIT.browserOnly;
    }
    io.err(String(/** @type {*} */ (err)?.message || err));
    return EXIT.runtime;
  }
}

export { USAGE };
