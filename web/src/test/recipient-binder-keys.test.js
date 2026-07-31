/**
 * The recipient binder's keyboard and CSP-shaped behaviour.
 *
 * Both of these were reported from the *deployed* site, and neither is
 * reproducible on the dev server — the dev CSP is relaxed, and the missing
 * key handler is the kind of gap that only shows up when someone types a
 * fingerprint and presses Enter.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = readFileSync(
  fileURLToPath(new URL("../lib/recipient-picker.js", import.meta.url)),
  "utf8"
);
const CSS = readFileSync(
  fileURLToPath(new URL("../css/toolkit.css", import.meta.url)),
  "utf8"
);

describe("Enter runs the lookup", () => {
  it("binds a keydown handler to the search field", () => {
    // The field is an <input type="search"> outside any <form>, so nothing
    // submits it implicitly. Without this the only way to search is to notice
    // the button, and the binder reads as broken.
    expect(SRC).toMatch(/\.binder-search[\s\S]{0,400}addEventListener\("keydown"/);
  });

  it("delegates to the button rather than duplicating the lookup", () => {
    // One definition of what a lookup does. A second copy would drift — and
    // the button's handler is where the keyserver, trust and hex-fingerprint
    // branches live.
    const handler = SRC.match(/addEventListener\("keydown"[\s\S]{0,700}?\}\);/);
    expect(handler, "no keydown handler found").toBeTruthy();
    expect(handler[0]).toMatch(/\.binder-go\[data-slot/);
    expect(handler[0]).toMatch(/click\(\)/);
  });

  it("ignores Enter mid-composition, so IME input is not submitted early", () => {
    const handler = SRC.match(/addEventListener\("keydown"[\s\S]{0,700}?\}\);/);
    expect(handler[0]).toMatch(/isComposing/);
  });
});

describe("scroll areas need no runtime style injection", () => {
  const SCROLL = readFileSync(
    fileURLToPath(new URL("../components/ui/scroll-area.tsx", import.meta.url)),
    "utf8"
  );

  it("does not depend on Radix's ScrollArea", () => {
    // Its only real contribution was hiding the native scrollbar so it could
    // draw its own, and it did that by injecting a <style> element — which
    // `style-src 'self'` refuses, so on the built site the rules never applied
    // and every mount reported a violation to deliver CSS we can just write.
    //
    // Matched on the *import*, not any mention: the comment above the
    // component names the package precisely to explain why it is gone.
    expect(SCROLL).not.toMatch(/^\s*import[^\n]*@radix-ui\/react-scroll-area/m);
  });

  it("scrolls and styles its scrollbar from the stylesheet", () => {
    expect(SCROLL).toContain("scroll-area");
    expect(CSS).toMatch(/\.scroll-area\s*\{[^}]*overflow-y:\s*auto/);
    expect(CSS).toMatch(/\.scroll-area::-webkit-scrollbar-thumb\s*\{/);
  });

  it("keeps the policy free of an exemption for a library's inline style", () => {
    // A `style-src` hash would have silenced the report while leaving the
    // injection in place. Declaring the rules is the fix; blessing them is not.
    const html = readFileSync(
      fileURLToPath(new URL("../../toolkit.html", import.meta.url)),
      "utf8"
    );
    expect(html).toMatch(/style-src 'self';/);
    expect(html).not.toMatch(/style-src[^;]*sha256-/);
  });
});
