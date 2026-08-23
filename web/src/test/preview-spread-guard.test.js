/**
 * A preview's shared const is checked, because a spread is not.
 *
 * `tsconfig.previews.json` brought `.design-sync/previews/` under `tsc` and
 * closed sixty type errors. It did not close one hole, and the hole is the
 * reason six of those sixty were *drift* rather than sloppy fixtures:
 * **TypeScript exempts spread properties from excess-property checking.**
 *
 * A preview that writes
 *
 * ```tsx
 * const base = { … };
 * export const Story = () => <SessionStart {...base} />;
 * ```
 *
 * can put anything at all in `base`. The component's props type is never
 * consulted for properties it does not declare, so a const carrying a prop that
 * was renamed years ago typechecks forever. That is exactly how
 * `SessionStart`'s `suggestions` survived being renamed to `trusted` — it was
 * found by reading the prop list against the fixture, not by the compiler.
 *
 * `satisfies Partial<XProps>` restores the check at the one place it was lost:
 * it performs excess-property checking against the target while leaving the
 * literal types inferred, so `defaultOpen: true` stays `true` rather than
 * widening to `boolean`.
 *
 * ## Why this file exists as well as the annotation
 *
 * The annotation is the check; this is what stops it being removed. Deleting a
 * `satisfies` clause is a one-word edit that makes a preview compile *more*
 * easily, and nothing else would notice. This asserts that every preview
 * spreading a shared const still declares what that const is supposed to be —
 * the same "may only shrink" shape as `glyph-shadowing` and
 * `fips-engine-entrypoints`.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PREVIEWS = fileURLToPath(new URL("../../../.design-sync/previews/", import.meta.url));

/** The file with its comments removed, so prose cannot satisfy a scan. */
function codeOf(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
}

/** Every preview, as `{ name, code }`. */
function previews() {
  return readdirSync(PREVIEWS)
    .filter((f) => f.endsWith(".tsx"))
    .map((name) => ({ name, code: codeOf(readFileSync(PREVIEWS + name, "utf8")) }));
}

/**
 * Names spread into a JSX tag from a module-level const in the same file.
 *
 * `{...props}` inside a component that takes `props` is a parameter, not a
 * shared fixture, and there is nothing for it to drift from — so only spreads
 * whose name is declared as a top-level `const` are collected.
 */
function spreadConsts({ code }) {
  const spread = [...code.matchAll(/\{\s*\.\.\.\s*([A-Za-z_$][\w$]*)\s*\}/g)].map((m) => m[1]);
  return [...new Set(spread)].filter((name) =>
    new RegExp(`^const\\s+${name}\\s*=`, "m").test(code)
  );
}

describe("a preview says what its shared fixture is", () => {
  it("finds the previews it is measuring", () => {
    // An empty sweep passes every assertion below it.
    const all = previews();
    expect(all.length, "no preview files found — the path is wrong").toBeGreaterThan(40);
    expect(
      all.filter((p) => spreadConsts(p).length).length,
      "no preview spreads a shared const any more, so this file has nothing to guard"
    ).toBeGreaterThan(3);
  });

  it("annotates every shared const that is spread into a component", () => {
    const bare = [];
    for (const preview of previews()) {
      for (const name of spreadConsts(preview)) {
        const declared = new RegExp(
          `const\\s+${name}\\s*=[\\s\\S]*?satisfies\\s+(Partial<)?\\w+`,
          "m"
        ).test(preview.code);
        if (!declared) bare.push(`${preview.name}:${name}`);
      }
    }
    expect(
      bare,
      "these consts are spread into a component with no `satisfies`, so TypeScript " +
        `will not check what they contain: ${bare.join(", ")}`
    ).toEqual([]);
  });

  it("names a type the design-system surface actually exports", () => {
    // `satisfies Partial<Anything>` would pass the check above while asserting
    // nothing, and a preview can only import from `basilisk-portal` — so the
    // type has to be on the barrel, which is the constraint that made this
    // possible at all.
    const barrel = readFileSync(
      fileURLToPath(new URL("../ds-entry.ts", import.meta.url)),
      "utf8"
    );
    const missing = [];
    for (const preview of previews()) {
      for (const [, type] of preview.code.matchAll(/satisfies\s+(?:Partial<)?(\w+)>?/g)) {
        if (!new RegExp(`\\b${type}\\b`).test(barrel)) missing.push(`${preview.name}:${type}`);
      }
    }
    expect(
      missing,
      `a preview asserts against a type the barrel does not export: ${missing.join(", ")}`
    ).toEqual([]);
  });
});
