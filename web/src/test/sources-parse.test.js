/**
 * Every file `tsc` is told to check must parse.
 *
 * This exists because of one nested comment terminator. `lib/memory-safety.js`
 * is prose with a `.js` extension, and two of its examples wrote the cleanup
 * note as a block comment inside the surrounding block comment. The first inner
 * closed the outer one, and the remaining seventy lines of English parsed as
 * code. `tsc --noEmit` then reported 646 errors, all of them in that file.
 *
 * The cost was not the 646. A parse failure ends the compilation there, so no
 * other file in the repo was checked at all — for as long as it lasted, three
 * real errors shipped past a typecheck that looked like it was running: a
 * symbol used but never imported, a duplicate import, and a four-argument call
 * to a three-argument function. A red typecheck that is red for one reason is
 * indistinguishable, at a glance, from one that is red for every reason.
 *
 * So the assertion here is not "the code is correct" — `tsc --noEmit` says that,
 * and CI runs it. It is narrower and it is the one that was missing: *nothing
 * is hiding the rest of the repo from the compiler.* When this fails, treat the
 * named file as the only thing you know, and re-run `tsc` once it parses.
 *
 * Parsing is done with esbuild (through vite, which already depends on it)
 * rather than by spawning `node --check` per file: same verdict on the failure
 * that prompted this — both reject the historical file — but 0.2 s instead of
 * 0.8 s of process spawns. esbuild's parser is not tsc's, so this is a smoke
 * alarm for the cascade, not a second opinion on the types.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { transformWithEsbuild } from "vite";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");

/** The three extensions tsconfig.json's `include` names under `src`. */
const CHECKED = /\.(js|ts|tsx)$/;

const LOADERS = { ".js": "js", ".ts": "ts", ".tsx": "tsx" };

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "node_modules") continue;
      walk(path, out);
    } else if (CHECKED.test(name)) {
      out.push(path);
    }
  }
  return out;
}

function rel(path) {
  return relative(WEB_ROOT, path).replace(/\\/g, "/");
}

describe("sources tsc is told to check", () => {
  it("all parse, so no single file can hide the rest from the compiler", async () => {
    const files = walk(SRC_ROOT);
    // The include list is not empty by accident — a walk that finds nothing
    // would make this test pass while checking nothing, which is the exact
    // failure shape it exists to catch.
    expect(files.length).toBeGreaterThan(100);

    const failures = (
      await Promise.all(
        files.map(async (path) => {
          const loader = LOADERS[path.slice(path.lastIndexOf("."))];
          try {
            await transformWithEsbuild(readFileSync(path, "utf8"), path, { loader });
            return null;
          } catch (err) {
            const first = String(err?.message ?? err).split("\n").find((l) => l.includes("ERROR"));
            return `${rel(path)}: ${(first ?? String(err?.message ?? err)).trim()}`;
          }
        })
      )
    ).filter(Boolean);

    expect(
      failures,
      `Does not parse. Until this is fixed, tsc's report on every other file is` +
        ` meaningless — it stopped here:\n${failures.join("\n")}`
    ).toEqual([]);
  });
});
