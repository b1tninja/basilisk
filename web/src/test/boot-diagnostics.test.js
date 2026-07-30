/**
 * Boot diagnostics — telling a *load failure* from an ordinary exception.
 *
 * This is the part worth pinning. Reporting "something failed" without naming
 * it is barely better than silence, and misclassifying a thrown error as a
 * missing subresource would send someone hunting for a network problem that
 * does not exist — the exact wild goose chase the module exists to prevent.
 */
import { describe, expect, it } from "vitest";
import { classifyResourceError } from "../lib/boot-diagnostics.js";

/** Minimal stand-in for a failed element load event. */
function resourceEvent(tag, attrs = {}) {
  return {
    target: {
      tagName: tag.toUpperCase(),
      getAttribute: (k) => attrs[k] ?? null,
    },
  };
}

describe("classifyResourceError", () => {
  it("names a failed script by its src", () => {
    const hit = classifyResourceError(resourceEvent("script", { src: "/assets/toolkit.js" }));
    expect(hit).toEqual({ url: "/assets/toolkit.js", detail: "script failed to load" });
  });

  it("calls out integrity when the script was pinned", () => {
    // This app ships SRI on its importmaps, and a hash mismatch looks exactly
    // like a network failure unless the message says otherwise.
    const hit = classifyResourceError(
      resourceEvent("script", { src: "/assets/x.js", integrity: "sha384-abc" })
    );
    expect(hit.detail).toMatch(/integrity/);
  });

  it("handles stylesheets, which use href rather than src", () => {
    const hit = classifyResourceError(resourceEvent("link", { href: "/assets/site.css" }));
    expect(hit.url).toBe("/assets/site.css");
    expect(hit.detail).toMatch(/stylesheet/);
  });

  it("ignores thrown exceptions — those are not load failures", () => {
    // A real error event carries `error` and targets window. Treating it as a
    // missing subresource would be actively misleading.
    expect(
      classifyResourceError({
        target: { tagName: "SCRIPT", getAttribute: () => "/a.js" },
        error: new Error("boom"),
      })
    ).toBeNull();
  });

  it("ignores events with no element or no URL", () => {
    expect(classifyResourceError({})).toBeNull();
    expect(classifyResourceError({ target: {} })).toBeNull();
    expect(classifyResourceError(resourceEvent("script", {}))).toBeNull();
  });

  it("describes an unexpected tag rather than guessing", () => {
    const hit = classifyResourceError(resourceEvent("img", { src: "/logo.png" }));
    expect(hit.detail).toContain("img");
  });
});
