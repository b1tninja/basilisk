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

describe("Radix ScrollArea styling survives the production CSP", () => {
  it("ships the viewport rules Radix can only deliver inline", () => {
    // `style-src 'self'` blocks Radix's injected <style>, so on the built site
    // native scrollbars reappear inside every ScrollArea unless we serve the
    // same rules ourselves.
    expect(CSS).toMatch(/\[data-radix-scroll-area-viewport\]\s*\{[^}]*scrollbar-width:\s*none/);
    expect(CSS).toMatch(
      /\[data-radix-scroll-area-viewport\]::-webkit-scrollbar\s*\{[^}]*display:\s*none/
    );
  });

  it("says why the rules are duplicated, so nobody deletes them as dead CSS", () => {
    const idx = CSS.indexOf("[data-radix-scroll-area-viewport]");
    const preamble = CSS.slice(Math.max(0, idx - 1200), idx);
    expect(preamble).toMatch(/style-src|inline/i);
  });
});
