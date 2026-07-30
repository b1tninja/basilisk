/**
 * Vitest: docs/CLI.md is executable, not decorative.
 *
 * Every `basilisk …` invocation on that page is parsed with the CLI's own
 * argument parser, so a flag that gets renamed or dropped fails here rather
 * than in someone's terminal. The examples that carry a claimed output — the
 * SHA-256 of "hello world", the browser-only message, the recipes — are then
 * actually run and compared.
 *
 * This is the doc-drift gate: a doc that lies is a failing test.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { EXIT, main, parseArgs } from "../../cli/main.js";

const here = dirname(fileURLToPath(import.meta.url));
const DOC = resolve(here, "../../../docs/CLI.md");
const docText = readFileSync(DOC, "utf8");

const workdirs = [];
function workdir() {
  const dir = mkdtempSync(join(tmpdir(), "basilisk-cli-docs-"));
  workdirs.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of workdirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

function file(dir, name, content) {
  const path = join(dir, name);
  writeFileSync(path, content, "utf8");
  return path;
}

async function cli(argv, ctx = {}) {
  const out = [];
  const err = [];
  const code = await main(argv, {
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    env: ctx.env || {},
    stdin: ctx.stdin,
  });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

/**
 * Every command line in a fenced block that invokes the CLI, un-wrapped from
 * trailing-backslash continuations and stripped of `VAR=… ` prefixes and shell
 * pipelines.
 * @returns {string[][]} argv arrays (without the `node .../basilisk.js` head)
 */
function documentedInvocations() {
  /** @type {string[][]} */
  const found = [];
  // Track fences line by line. A regex that only matches shell fences pairs the
  // *closing* ``` of a `text` block with the next opener and swallows prose.
  const shellBlocks = [];
  let fence = null;
  /** @type {string[]} */
  let buffer = [];
  for (const line of docText.split("\n")) {
    const open = /^```(\w*)\s*$/.exec(line);
    if (open) {
      if (fence == null) {
        fence = open[1] || "";
        buffer = [];
      } else {
        if (fence === "" || fence === "bash" || fence === "sh" || fence === "console") {
          shellBlocks.push(buffer.join("\n"));
        }
        fence = null;
      }
      continue;
    }
    if (fence != null) buffer.push(line);
  }

  for (const block of shellBlocks) {
    // Join `\`-continued lines into one.
    const body = block.replace(/\\\n\s*/g, " ");
    for (const rawLine of body.split("\n")) {
      let line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      line = line.replace(/^\$\s+/, "");
      // Take the segment that actually runs the CLI (drops `echo … |` heads).
      const seg = line
        .split("|")
        .map((s) => s.trim())
        .find((s) => s.includes("basilisk.js") || /^basilisk\s/.test(s));
      if (!seg) continue;
      // Drop leading `VAR=value` environment prefixes.
      const words = seg.split(/\s+/).filter(Boolean);
      while (words.length && /^[A-Z_][A-Z0-9_]*=/.test(words[0])) words.shift();
      const head = words.findIndex(
        (w) => w.endsWith("basilisk.js") || w === "basilisk"
      );
      if (head < 0) continue;
      found.push(words.slice(head + 1));
    }
  }
  return found;
}

describe("docs/CLI.md", () => {
  it("documents at least the three shipped commands", () => {
    const invocations = documentedInvocations();
    expect(invocations.length).toBeGreaterThan(5);
    const commands = new Set(invocations.map((a) => a[0]));
    expect(commands).toContain("run");
    expect(commands).toContain("check");
    expect(commands).toContain("list-ops");
  });

  it("every documented invocation parses — no stale or invented flags", () => {
    for (const argv of documentedInvocations()) {
      // Placeholder values like `…` are fine; only the *shape* is checked here.
      expect(() => parseArgs(argv), argv.join(" ")).not.toThrow();
      const { command } = parseArgs(argv);
      expect(["run", "check", "list-ops"], argv.join(" ")).toContain(command);
    }
  });

  it("documents every option the parser accepts", () => {
    // The reverse direction: a flag that exists but is undocumented.
    const documented = docText;
    for (const flag of [
      "--out-dir",
      "--json",
      "--quiet",
      "--input",
      "--input-file",
      "--stdin",
      "--shares",
      "--ciphertext",
      "--private-key",
      "--passphrase-env",
      "--toolbox",
    ]) {
      expect(documented, `${flag} undocumented`).toContain(flag);
    }
  });

  it("runs the split → recover example and gets the shape the page claims", async () => {
    // The recipe as written on the page, lifted from the fenced `text` block.
    const match = /```text\n(random 32 \| sss\.split[\s\S]*?)```/.exec(docText);
    expect(match, "split/recover recipe block missing from CLI.md").toBeTruthy();
    const dir = workdir();
    const recipe = file(dir, "split-recover.txt", match[1]);
    const outDir = join(dir, "artifacts");

    const { code, out } = await cli(["run", recipe, "--out-dir", outDir, "--json"]);
    expect(code).toBe(EXIT.ok);
    const artifacts = JSON.parse(out);
    // The page shows share-1.txt … and secret.txt with a 32-byte base64 secret.
    expect(artifacts.filter((a) => a.role === "share")).toHaveLength(3);
    expect(artifacts.some((a) => a.filename === "share-1.txt")).toBe(true);
    const secret = artifacts.find((a) => a.filename === "secret.txt");
    expect(secret).toBeTruthy();
    expect(Buffer.from(String(secret.content).trim(), "base64").length).toBe(32);
  });

  it("reproduces the hash the page prints for the --input / --stdin example", async () => {
    const claimed = /`(b94d27b9[0-9a-f]+)`/.exec(docText);
    expect(claimed, "documented digest missing from CLI.md").toBeTruthy();
    const recipeText = /`(input \| utf8 \| digest \| encode hex \| out @hash)`/.exec(
      docText
    );
    expect(recipeText, "documented hash recipe missing from CLI.md").toBeTruthy();

    const dir = workdir();
    const recipe = file(dir, "hash.txt", `${recipeText[1]}\n`);
    const flag = await cli(["run", recipe, "--input", "hello world"]);
    expect(flag.code).toBe(EXIT.ok);
    expect(flag.out).toContain(claimed[1]);

    const piped = await cli(["run", recipe, "--stdin"], { stdin: "hello world" });
    expect(piped.out).toContain(claimed[1]);
  });

  it("reproduces the browser-only message the page quotes", async () => {
    const dir = workdir();
    const recipe = file(
      dir,
      "rtc.txt",
      "random 8 | encode hex | out @nonce\n\nrtc.certificate | out @cert\n"
    );
    const { code, err } = await cli(["run", recipe]);
    expect(code).toBe(EXIT.browserOnly);
    // The page quotes this line; keep them the same sentence.
    expect(err).toContain('browser-only op: "rtc.certificate" (cell 2, step 1)');
    expect(err).toContain("needs WebRTC");
    expect(docText).toContain('browser-only op: "rtc.certificate" (cell 2, step 1)');
  });

  it("the documented gpg.decrypt recipe is the one the flags actually drive", async () => {
    expect(docText).toContain("gpg.decrypt | out @plain");
    const dir = workdir();
    const recipe = file(dir, "decrypt.txt", "gpg.decrypt | out @plain\n");
    // Valid recipe, missing inputs — proves the recipe on the page compiles.
    const { code } = await cli(["check", recipe]);
    expect(code).toBe(EXIT.ok);
  });

  it("states the exit codes the CLI actually returns", async () => {
    expect(docText).toMatch(/`0` ok · `1` usage · `2` invalid recipe · `3` runtime error/);
    expect(EXIT).toEqual({
      ok: 0,
      usage: 1,
      invalidRecipe: 2,
      runtime: 3,
      browserOnly: 4,
    });
  });
});
