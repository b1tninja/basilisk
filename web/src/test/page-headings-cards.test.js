/**
 * The titled cards that string-building modules emit, and whether a reader
 * moving by heading can reach them.
 *
 * Three modules build HTML as template strings and inject it with
 * `innerHTML`, so nothing React renders can see them and no `.tsx` file
 * mentions their titles. Each one printed its card's name as
 * `<p class="card-title">` -- typographically a heading, structurally not one
 * -- which is why `/`'s "Command-line usage", `/key`'s "Install with GnuPG /
 * HKP" and every card on `/published` were absent from the outline.
 *
 * These tests run in `node` (there is no jsdom in this project), so they
 * assert on the strings the modules return plus the `<h1>` each page's own
 * source states. What they cannot see is the *composed* document: that the
 * fragments land in the order asserted here is verified by e2e, not here.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  renderKeyClientSnippets,
  renderSearchHelpSnippets,
  renderSnippetCard,
  renderSubmitSnippets,
} from "../lib/snippets.js";
import { renderUploadCard } from "../lib/keys.js";
import {
  renderNothingPublishedSection,
  renderSignedInHtml,
  renderSignedOutHtml,
} from "../lib/published-mount.js";

/** Minimal document for escapeHtml (utils.js uses createElement). */
if (typeof document === "undefined") {
  globalThis.document = {
    createElement: () => {
      let text = "";
      return {
        set textContent(v) {
          text = v == null ? "" : String(v);
        },
        get textContent() {
          return text;
        },
        get innerHTML() {
          return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
        },
      };
    },
  };
}

const hadWindow = "window" in globalThis;

beforeAll(() => {
  if (!hadWindow) {
    globalThis.window = { location: { origin: "https://keys.example" } };
  }
});

afterAll(() => {
  if (!hadWindow) delete globalThis.window;
});

const SRC = resolve(import.meta.dirname, "..");

/**
 * Source with comments removed.
 *
 * Both `pages/key.tsx` and `lib/key-mount.js` explain *in prose* that the
 * `<h1>` used to live in the other file. Counting raw `<h1` would read those
 * sentences as markup and score the page as having two.
 */
function code(file) {
  return readFileSync(resolve(SRC, file), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^[ \t]*\/\/.*$/gm, "");
}

/** Every heading in an HTML string, in document order. */
function headings(html) {
  return [...html.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/g)].map((m) => ({
    level: Number(m[1]),
    text: m[2].replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim(),
  }));
}

/**
 * Levels only, starting from the page's `h1`, so a fragment is checked at the
 * depth it is actually mounted at.
 */
function levelsFrom(html, pageStartsAt = 1) {
  return [pageStartsAt, ...headings(html).map((h) => h.level)];
}

function assertNoSkippedLevels(levels) {
  for (let i = 1; i < levels.length; i++) {
    // A heading may close any number of levels but may only open one.
    expect(
      levels[i] - levels[i - 1],
      `heading level went ${levels[i - 1]} -> ${levels[i]} (sequence ${levels.join(",")})`
    ).toBeLessThanOrEqual(1);
  }
}

const PAGES = {
  "/": "pages/index.tsx",
  "/key": "pages/key.tsx",
  "/published": "pages/published.tsx",
};

describe("exactly one h1 per affected page", () => {
  for (const [route, file] of Object.entries(PAGES)) {
    it(`${route} states its h1 once, in ${file}`, () => {
      const opens = code(file).match(/<h1[\s>]/g) || [];
      expect(opens.length).toBe(1);
    });
  }

  it("the string-building modules never emit an h1 of their own", () => {
    const sources = [
      "lib/snippets.js",
      "lib/keys.js",
      "lib/published-mount.js",
      "lib/key-mount.js",
    ];
    for (const file of sources) {
      expect(code(file), `${file} emits an <h1>`).not.toMatch(/<h1[\s>]/);
    }
  });
});

describe("renderSnippetCard", () => {
  it("titles the card with a heading, not a paragraph", () => {
    const html = renderSnippetCard({ title: "Some title", items: [] });
    expect(html).toContain('<h2 class="card-title">Some title</h2>');
    expect(html).not.toContain('<p class="card-title">');
  });

  it("keeps the title escaped now that it is inside a heading", () => {
    const html = renderSnippetCard({
      title: '<script>alert(1)</script> & "quoted"',
      items: [],
    });
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(headings(html)).toHaveLength(1);
  });

  it("emits no inline style attribute", () => {
    const html = renderSnippetCard({
      title: "Some title",
      hint: "a hint",
      items: [{ id: "x", cmd: "gpg --version", note: "n" }],
    });
    expect(html).not.toMatch(/\sstyle=/);
  });
});

describe("/ — search landing page", () => {
  it("the command-line card is an h2 under the page h1", () => {
    const html = renderSearchHelpSnippets();
    expect(headings(html)).toEqual([{ level: 2, text: "Command-line usage" }]);
    assertNoSkippedLevels(levelsFrom(html));
  });
});

describe("/key — key detail page", () => {
  it("the install card is an h2, matching the other cards on the page", () => {
    const html = renderKeyClientSnippets({
      fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
      keyId: "ABCDEF1234567890",
      approved: true,
    });
    expect(headings(html)).toEqual([
      { level: 2, text: "Install with GnuPG / HKP" },
    ]);
    assertNoSkippedLevels(levelsFrom(html));
  });

  it("sits at the same level as the sibling cards key-mount.js builds", () => {
    const src = code("lib/key-mount.js");
    // Every card on /key names itself with an h2; the snippet card now does
    // too, so the sequence around it is flat rather than broken.
    expect(src).toMatch(/<h2 class="card-title">Key information<\/h2>/);
    expect(src).not.toMatch(/<p class="card-title">/);
  });
});

describe("/published — signed out", () => {
  const html = () =>
    renderSignedOutHtml({
      hint: "Sign in with your Google account.",
      buttons: '<a class="btn" href="/login/google">Google</a>',
    });

  it("has headings at all", () => {
    expect(headings(html()).length).toBeGreaterThan(0);
  });

  it("names each of its sections with an h2, in order", () => {
    expect(headings(html())).toEqual([
      { level: 2, text: "Submit a public key" },
      { level: 2, text: "Submit with GnuPG" },
      { level: 2, text: "Sign in to see what is published under your address" },
      { level: 2, text: "Looking for the keys that can sign?" },
    ]);
  });

  it("skips no level below the page h1", () => {
    assertNoSkippedLevels(levelsFrom(html()));
  });

  it("adds no h1 of its own and no inline style", () => {
    expect(headings(html()).some((h) => h.level === 1)).toBe(false);
    expect(html()).not.toMatch(/\sstyle=/);
  });

  it("leaves the sign-in hint as prose, not as a second heading", () => {
    const out = html();
    expect(out).toContain(
      '<p class="muted mb-xl">Sign in with your Google account.</p>'
    );
  });
});

describe("/published — signed in with no keys", () => {
  const html = () =>
    renderSignedInHtml({
      email: "someone@example.com",
      keysSectionHtml: renderNothingPublishedSection(),
    });

  it("has headings at all", () => {
    expect(headings(html()).length).toBeGreaterThan(0);
  });

  it("keeps the published section's heading when the list under it is empty", () => {
    expect(headings(html())).toEqual([
      { level: 2, text: "Submit a public key" },
      { level: 2, text: "Submit with GnuPG" },
      { level: 2, text: "Published under your address" },
      { level: 2, text: "Looking for the keys that can sign?" },
    ]);
  });

  it("skips no level below the page h1", () => {
    assertNoSkippedLevels(levelsFrom(html()));
  });

  it("leaves the empty-state sentence as prose under that heading", () => {
    const out = renderNothingPublishedSection();
    expect(out).toMatch(
      /<p class="muted">Nothing is published under your address yet\./
    );
    expect(headings(out)).toEqual([
      { level: 2, text: "Published under your address" },
    ]);
  });

  it("still escapes the signed-in address", () => {
    const out = renderSignedInHtml({
      email: '<script>alert(1)</script>',
      keysSectionHtml: "",
    });
    expect(out).not.toContain("<script>");
    expect(out).toContain("&lt;script&gt;");
  });
});

describe("/published — signed in with keys", () => {
  it("still opens the list with an h2 and keeps the labels section an h2", () => {
    const src = code("lib/published-mount.js");
    expect(src).toMatch(/<h2>Published under your address<\/h2>/);
    expect(src).toMatch(/<h2>Key labels<\/h2>/);
    expect(src).not.toMatch(/<p class="card-title">/);
  });
});

describe("the upload card, wherever it is mounted", () => {
  for (const signedIn of [true, false]) {
    it(`names both of its sections with an h2 (signedIn=${signedIn})`, () => {
      const out = renderUploadCard({ signedIn });
      expect(headings(out)).toEqual([
        { level: 2, text: "Submit a public key" },
        { level: 2, text: "Submit with GnuPG" },
      ]);
      expect(out).not.toContain('<p class="card-title">');
    });
  }

  it("renderSubmitSnippets is the source of the second one", () => {
    expect(headings(renderSubmitSnippets())).toEqual([
      { level: 2, text: "Submit with GnuPG" },
    ]);
  });
});
