/**
 * The design surface has to bundle for a browser, and it has to match the map.
 *
 * `ds-entry.ts` is the list of components that go to the design tool, declared
 * rather than discovered (see its own note). Two things can quietly break it,
 * and neither shows up anywhere else in this suite: the file is imported by
 * nothing in the app, so `tsc` type-checks it and no test ever *builds* it.
 *
 * The first is a node builtin reaching the graph. `IntegrityPanel` sat outside
 * the surface for exactly that: it imports `deployment-check.js`, which imports
 * `module-integrity.js`, which carried an `await import("node:crypto")` fallback
 * written before Node exposed WebCrypto globally. The branch was unreachable —
 * it sat behind `if (!globalThis.crypto?.subtle)` — but a bundler resolves a
 * dynamic import whether or not it runs, and the whole export surface failed on
 * "Could not resolve node:crypto". Nothing said so; the widget was simply left
 * out, and by the time anyone looked the exclusion had outlived its reason.
 *
 * The second is drift between the export list and `componentSrcMap` in
 * `.design-sync/config.json`. A name in one and not the other is a component
 * the tool either cannot render or cannot trace back to a file, and both fail
 * on the far side of a sync where nobody in this repo sees it.
 *
 * esbuild is vite's own bundler and already installed. This is a resolve check,
 * not a build product — nothing is written.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const ENTRY = fileURLToPath(new URL("../ds-entry.ts", import.meta.url));
const CONFIG = fileURLToPath(new URL("../../../.design-sync/config.json", import.meta.url));

const config = JSON.parse(readFileSync(CONFIG, "utf8"));
const entrySource = readFileSync(ENTRY, "utf8");

describe("the design-sync export surface", () => {
  it("bundles for a browser, with no node builtin in the graph", async () => {
    const { build } = await import("esbuild");
    // React is the host's, as it is in the design tool; everything else has to
    // resolve from this repo. `platform: "browser"` is what makes a `node:*`
    // specifier an error rather than something quietly stubbed.
    const result = await build({
      entryPoints: [ENTRY],
      absWorkingDir: WEB_ROOT,
      bundle: true,
      write: false,
      format: "esm",
      platform: "browser",
      jsx: "automatic",
      external: ["react", "react-dom", "react/jsx-runtime"],
      loader: { ".css": "empty" },
      logLevel: "silent",
    }).catch((err) => err);

    const errors = (result.errors || []).map(
      (e) => `${e.text}${e.location ? ` (${e.location.file}:${e.location.line})` : ""}`
    );
    expect(
      errors,
      `ds-entry.ts does not bundle for a browser. A node builtin in this graph ` +
        `does not fail the app — vite never bundles this file — it fails the ` +
        `sync, silently, for every component in the surface.\n${errors.join("\n")}`
    ).toEqual([]);
    expect(result.warnings ?? []).toEqual([]);
  });

  it("exports every component the map names", () => {
    // A map entry with no export is a card the tool cannot render.
    const missing = Object.keys(config.componentSrcMap).filter(
      (name) => !new RegExp(`\\b${name}\\b`).test(entrySource)
    );
    expect(
      missing,
      `${missing.join(", ")} are in componentSrcMap but not exported from ` +
        `ds-entry.ts. The map is what points a card back at its source file; ` +
        `an entry with nothing behind it points at nothing.`
    ).toEqual([]);
  });

  it("names a source file for every widget it exports", () => {
    // The reverse: an exported widget with no map entry renders, and then
    // cannot be traced to the file it came from. Primitives and the plain
    // helper re-exports are not widgets and are not mapped, so this asks only
    // about `toolkit/widgets`, which is where the cards come from.
    const exported = [...entrySource.matchAll(/from "\.\/toolkit\/widgets\/([\w-]+)"/g)].map(
      (m) => m[1]
    );
    const mapped = new Set(
      Object.values(config.componentSrcMap).map((p) => String(p).split("/").pop()?.replace(/\.tsx$/, ""))
    );
    const unmapped = [...new Set(exported)].filter((file) => !mapped.has(file));
    expect(
      unmapped,
      `${unmapped.join(", ")} are exported from ds-entry.ts with no ` +
        `componentSrcMap entry, so the design tool has no path back to the source.`
    ).toEqual([]);
  });

  it("keeps IntegrityPanel in, now that nothing stops it", () => {
    // Pinned because the exclusion was the kind that outlives its reason: the
    // widget was dropped from the list, the `node:crypto` line that caused it
    // was three modules away, and neither end said anything about the other.
    expect(entrySource).toMatch(/export \{ IntegrityPanel/);
    expect(config.componentSrcMap.IntegrityPanel).toBe(
      "src/toolkit/widgets/IntegrityPanel.tsx"
    );
  });
});

/**
 * A preview drifting from the component it documents.
 *
 * Everything above asks whether the *set* of components is consistent — the
 * barrel, the map, the bundle. None of it looks at a preview's contents, and
 * that is where the third failure lives: `60a68f6` gave `encryptCapable` a
 * third state, `null` — "nobody could ask" — and `RecipientsCard` drew it as
 * "encryption unverified", while the preview kept a two-state fixture. The
 * gallery went on documenting a component that had stopped existing, and every
 * check here passed, because the name was still in both lists.
 *
 * ## What this check is, and what it deliberately is not
 *
 * It is a **domain** check, not a copy check. `recipientRows` normalises the
 * field to exactly `true | false | null`, and `RecipientsCard` branches three
 * ways on it, so "the previews must exhibit all three" is a statement about a
 * closed set rather than about any sentence. The card's branches are read out
 * of the card rather than listed here, so collapsing it back to two states
 * fails loudly instead of quietly making this vacuous.
 *
 * It is **not** general, and the general version is not cheap for the reason
 * that is worth writing down: rendering is not the obstacle — this suite
 * already calls `renderToStaticMarkup` (`compose-before-session.test.js`), so
 * a product component *can* be drawn in a node test. The obstacle is getting a
 * preview's props back out of it. Each preview is a hand-authored `.tsx` module
 * that imports from `basilisk-portal`, a specifier nothing in this repo
 * resolves, and its fixtures are ordinary module-scope bindings in whatever
 * shape that component wants. Extracting them means either evaluating the
 * module with a shimmed import — which is a second bundler in the test suite —
 * or parsing TSX for literals, which is a heuristic that would go wrong quietly
 * and get relaxed the first time it did. So this is one component's closed
 * field, honestly narrow, rather than a mechanism claiming to cover fifty.
 */
describe("a preview keeps up with the component it documents", () => {
  const CARD = fileURLToPath(
    new URL("../toolkit/widgets/RecipientsCard.tsx", import.meta.url)
  );
  const PREVIEW = fileURLToPath(
    new URL("../../../.design-sync/previews/RecipientsCard.tsx", import.meta.url)
  );

  it("shows every encryptCapable state RecipientsCard draws", () => {
    const card = readFileSync(CARD, "utf8");
    // The card's own comparisons. `true` never appears as a comparison — it is
    // the else branch that draws nothing — so the two explicit ones plus the
    // fall-through are the three states.
    const branches = new Set(
      [...card.matchAll(/encryptCapable === (false|null)/g)].map((m) => m[1])
    );
    expect(
      [...branches].sort(),
      `RecipientsCard no longer branches on both \`false\` and \`null\`. If the ` +
        `state space changed, this check has to change with it — do not delete ` +
        `it, or the preview goes back to documenting a component that is gone.`
    ).toEqual(["false", "null"]);

    const shown = new Set(
      [...readFileSync(PREVIEW, "utf8").matchAll(/encryptCapable:\s*(true|false|null)/g)].map(
        (m) => m[1]
      )
    );
    expect(
      [...shown].sort(),
      `The RecipientsCard preview never produces ${["true", "false", "null"]
        .filter((s) => !shown.has(s))
        .join(", ")}. A gallery card that cannot reach a state the product ` +
        `draws is documentation of a component that does not ship.`
    ).toEqual(["false", "null", "true"]);
  });
});

describe("module integrity computes its root one way", () => {
  it("refuses a runtime with no WebCrypto instead of reaching for node:crypto", async () => {
    // Two implementations of one security check drift, and the one that drifts
    // is the one nobody reads — `deployment-check.js` says so about itself.
    // The fallback is gone; what replaced it has to actually refuse.
    const source = readFileSync(
      fileURLToPath(new URL("../lib/module-integrity.js", import.meta.url)),
      "utf8"
    );
    // The *import*, not the word: the comment that replaced it names
    // `node:crypto` on purpose, so that the next person to reach for it finds
    // out why it went rather than rediscovering the bundle failure.
    expect(source).not.toMatch(/import\s*\(\s*["']node:/);
    expect(source).not.toMatch(/from\s+["']node:/);
    expect(source).toMatch(/has no WebCrypto/);

    // And the refusal is live, not merely written: with `subtle` taken away
    // the hash fails loudly rather than quietly producing a second answer.
    // `hashIntegrityLeaf` is the smallest exported thing that reaches it.
    const { hashIntegrityLeaf } = await import("../lib/module-integrity.js");
    const real = globalThis.crypto;
    try {
      Object.defineProperty(globalThis, "crypto", { value: {}, configurable: true });
      await expect(
        hashIntegrityLeaf({ url: "/assets/a.js", alg: "sha256", b64: "AAAA" })
      ).rejects.toThrow(/WebCrypto/);
    } finally {
      Object.defineProperty(globalThis, "crypto", { value: real, configurable: true });
    }
  });
});
