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
import { describe, expect, it } from "vitest";
import { LIMIT_NOTE, checkDeployment, shortRoot } from "../lib/toolkit/deployment-check.js";

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
