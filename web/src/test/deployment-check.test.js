/**
 * Verify-this-deployment — the verdicts.
 *
 * The states worth pinning are the ones that mean *no answer*. A check that
 * reports "verified" when it could not reach the pin document, or when the
 * page carried no integrity hashes at all, is worse than no check: it converts
 * an absence of evidence into a green tick. Each of those paths is asserted to
 * be non-`ok` here, by tone, so a later refactor cannot make one of them look
 * successful without failing this file.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  LIMIT_NOTE,
  SINGLE_SOURCE_NOTE,
  checkDeployment,
  shortRoot,
} from "../lib/toolkit/deployment-check.js";

/** A minimal stand-in for the bits of `Document` the check actually reads. */
function fakeDoc({ sri = [], pins = "", page = "" } = {}) {
  const nodes = sri.map((l) => ({
    getAttribute: (k) =>
      k === "integrity" ? l.integrity : k === "src" ? l.src : null,
  }));
  return {
    querySelectorAll: (sel) => (sel === "[integrity]" ? nodes : []),
    querySelector: (sel) => {
      if (sel === 'meta[name="basilisk-integrity-pins"]') {
        return pins ? { getAttribute: () => pins } : null;
      }
      if (sel === 'meta[name="basilisk-integrity-page"]') {
        return page ? { getAttribute: () => page } : null;
      }
      return null;
    },
  };
}

const ONE_LEAF = [{ integrity: "sha384-AAAA", src: "/assets/app.js" }];

describe("checkDeployment", () => {
  it("refuses to compute a verdict from a page with no SRI at all", async () => {
    const v = await checkDeployment({ document: fakeDoc(), pinUrls: [] });
    expect(v.status).toBe("no-sri");
    expect(v.tone).toBe("warn");
    expect(v.headline).toMatch(/^Cannot verify/);
    // Names the realistic explanation without treating it as harmless.
    expect(v.detail).toMatch(/dev server/);
    // And shows no root. The fallback path hashes this module's own bytes and
    // yields a well-formed 64-hex value over one file — a number that looks
    // exactly like the one a reader is meant to compare against another
    // machine, and is not it.
    expect(v.root).toBe("");
    expect(v.leafCount).toBe(0);
  });

  it("computes a root but calls it unverified when nothing pins it", async () => {
    const v = await checkDeployment({
      document: fakeDoc({ sri: ONE_LEAF }),
      pinUrls: [],
    });
    expect(v.status).toBe("unpinned");
    expect(v.tone).not.toBe("ok");
    expect(v.root).toMatch(/^[0-9a-f]{64}$/);
    expect(v.leafCount).toBe(1);
    expect(v.detail).toMatch(/attests to nothing but itself/);
  });

  it("treats an unreachable pin as unverified, not as fine", async () => {
    const v = await checkDeployment({
      document: fakeDoc({ sri: ONE_LEAF }),
      // No fetch implementation in this environment — the failure path is the
      // point, and it is the one a blocked network produces in a real browser.
      pinUrls: ["/integrity/module-roots.json"],
    });
    expect(v.status).toBe("unreachable");
    expect(v.tone).toBe("error");
    expect(v.detail).toMatch(/looks exactly like a suppressed one/);
  });

  it("derives the page key from an explicit meta when the build sets one", async () => {
    const v = await checkDeployment({
      document: fakeDoc({ sri: ONE_LEAF, page: "toolkit.html" }),
      pinUrls: [],
    });
    expect(v.pageKey).toBe("toolkit.html");
  });

  it("keeps the limitation blunt", () => {
    // The panel renders this under every verdict including the successful one.
    expect(LIMIT_NOTE).toMatch(/runs inside the page it is checking/);
    expect(LIMIT_NOTE).toMatch(/cannot catch/);
    expect(LIMIT_NOTE).toMatch(/CLI/);
  });

  it("shows an em dash rather than an empty root", () => {
    expect(shortRoot("")).toBe("—");
    expect(shortRoot("abcdef0123456789ff")).toBe("abcdef0123456789…");
  });
});

/**
 * The verdict the panel can draw and no deployment can produce.
 *
 * `disagree` compares two independently fetched pin documents, which is the
 * only one of these outcomes that survives a host serving one thing and
 * claiming another. Reaching it needs `VITE_INTEGRITY_PIN_MIRRORS` set at build
 * time, and nothing in this repository sets it — so on every deployed page the
 * comparison is inert while the panel goes on rendering a card for it. These
 * pin the two halves of the honest version: the sentence exists, and the panel
 * shows it exactly when there are fewer than two sources.
 */
describe("the mirror comparison, when there is nothing to compare", () => {
  const ROOT = new URL("../", import.meta.url);
  const PANEL = readFileSync(new URL("toolkit/widgets/IntegrityPanel.tsx", ROOT), "utf8");

  it("says the check did not run, rather than implying it did", () => {
    expect(SINGLE_SOURCE_NOTE).toMatch(/did not run/i);
    // Names what a second source would be for, so a reader knows what is
    // missing rather than only that something is.
    expect(SINGLE_SOURCE_NOTE).toMatch(/second origin/i);
    // And a remedy the reader can actually perform. "Configure a mirror" would
    // not be one: they do not run the deploy.
    expect(SINGLE_SOURCE_NOTE).toMatch(/another network or another machine/i);
  });

  it("is rendered by the panel below two sources and not at two", () => {
    expect(PANEL).toMatch(/SINGLE_SOURCE_NOTE/);
    expect(PANEL).toMatch(/state\.pinUrls\.length < 2/);
    // Not while the check is still running: at that point `pinUrls` is the
    // empty array in `PENDING`, and the note would be describing a state
    // nothing has established yet.
    expect(PANEL).toMatch(/state\.status !== "checking" &&\s*state\.pinUrls\.length < 2/);
  });

  it("is not an inline style, and not a bare string in the component", () => {
    // The note lives beside the verdicts for the reason LIMIT_NOTE does: so it
    // cannot be dropped from the UI while the confident wording stays.
    expect(PANEL).toMatch(/className="integrity-single-source"/);
    const css = readFileSync(new URL("css/toolkit.css", ROOT), "utf8");
    expect(css).toMatch(/\.integrity-single-source \{/);
  });

  it("still holds for the build that would make it reachable", () => {
    // The one place the variable is read. If a future change moves that read,
    // the note above is describing a mechanism that no longer exists and this
    // fails rather than going quietly stale.
    const plugin = readFileSync(
      new URL("../scripts/externalize-importmaps.js", ROOT),
      "utf8"
    );
    expect(plugin).toMatch(/VITE_INTEGRITY_PIN_MIRRORS/);
  });
});
