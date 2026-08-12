/**
 * Boot diagnostics — telling a *load failure* from an ordinary exception.
 *
 * This is the part worth pinning. Reporting "something failed" without naming
 * it is barely better than silence, and misclassifying a thrown error as a
 * missing subresource would send someone hunting for a network problem that
 * does not exist — the exact wild goose chase the module exists to prevent.
 */
import { describe, expect, it } from "vitest";
import {
  classifyResourceError,
  connectionConsequence,
  isConnection,
  violationTarget,
} from "../lib/boot-diagnostics.js";

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

/**
 * A refused connection, reported as one.
 *
 * The production report this pins: a blocked signalling socket announced as
 * "1 subresource failed to load — this page is running incomplete", above a
 * line naming `/assets/session-*.js`. Nothing failed to load, it was not a
 * subresource, and the chunk named was the caller rather than the origin that
 * could not be reached — so the one fact needed to diagnose it was the one
 * fact missing.
 */
describe("a blocked connection is not a missing subresource", () => {
  const violation = (over) => ({
    effectiveDirective: "connect-src",
    blockedURI: "wss://basilisk-dev-wps.webpubsub.azure.com",
    sourceFile: "https://keys.b1tninja.com/assets/session-CTwn9POk.js",
    lineNumber: 1,
    ...over,
  });

  it("separates connect-src from the directives that govern subresources", () => {
    expect(isConnection("connect-src")).toBe(true);
    expect(isConnection("script-src")).toBe(false);
    expect(isConnection("style-src-elem")).toBe(false);
  });

  it("names the origin it could not reach, not the caller that tried", () => {
    // The reported line pointed at the chunk. The chunk was fine.
    expect(violationTarget(violation())).toBe("wss://basilisk-dev-wps.webpubsub.azure.com");
  });

  it("still locates a blocked subresource by its source file", () => {
    // The other direction must not regress: for a script or style the file and
    // line are what a reader needs, and `blockedURI` is often "inline".
    const target = violationTarget(
      violation({ effectiveDirective: "style-src", blockedURI: "inline" })
    );
    expect(target).toBe("https://keys.b1tninja.com/assets/session-CTwn9POk.js:1");
  });

  it("says what a refused websocket costs, because it has exactly one cost", () => {
    // The only socket this app opens is the signalling relay, so the
    // consequence is knowable and worth stating rather than leaving to be
    // inferred from a hostname.
    expect(connectionConsequence("wss://x.webpubsub.azure.com")).toMatch(
      /shared sessions are unavailable/
    );
    expect(connectionConsequence("https://keys.openpgp.org")).toBe("this page cannot reach it");
  });
});
