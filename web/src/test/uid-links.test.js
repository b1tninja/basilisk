/**
 * UID rendering: verified email links + cautioned unverified name links.
 */

import { beforeAll, describe, expect, it } from "vitest";

beforeAll(() => {
  globalThis.document = {
    createElement() {
      return {
        _text: "",
        set textContent(v) {
          this._text = v == null ? "" : String(v);
        },
        get textContent() {
          return this._text;
        },
        get innerHTML() {
          return this._text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
        },
      };
    },
  };
});

describe("uidWithSearchLinks", () => {
  it("links email normally and name as unverified", async () => {
    const { uidWithSearchLinks } = await import("../lib/utils.js");
    const html = uidWithSearchLinks({
      raw: "Justin Capella <justincapella@gmail.com>",
      name: "Justin Capella",
      email: "justincapella@gmail.com",
      comment: null,
    });
    expect(html).toMatch(/<a class="text-link unverified"[^>]*>Justin Capella<\/a>/);
    expect(html).toMatch(/title="Name is NOT verified/);
    expect(html).toMatch(/<a class="text-link"[^>]*>justincapella@gmail\.com<\/a>/);
    expect(html).not.toMatch(/unverified"[^>]*>justincapella@gmail\.com/);
  });

  it("keeps comments plain while name stays unverified", async () => {
    const { uidWithSearchLinks } = await import("../lib/utils.js");
    const html = uidWithSearchLinks({
      raw: "Justin Capella (work) <justincapella@gmail.com>",
      name: "Justin Capella",
      email: "justincapella@gmail.com",
      comment: "work",
    });
    expect(html).toContain("(work)");
    expect(html).toMatch(/unverified/);
    expect(html).toMatch(/justincapella@gmail\.com<\/a>/);
  });

  it("escapes opaque string UIDs with no links", async () => {
    const { uidWithSearchLinks } = await import("../lib/utils.js");
    const html = uidWithSearchLinks("Justin Capella <justincapella@gmail.com>");
    expect(html).toBe("Justin Capella &lt;justincapella@gmail.com&gt;");
    expect(html).not.toContain("<a ");
  });
});
