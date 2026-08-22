/**
 * What a blocked row and a toolbox header say on the shipped bundle.
 *
 * Two reports, measured where they are read rather than where they are
 * declared. `ops-type-glyphs.test.js` is the source-and-registry half; this is
 * the half that opens `dist/`, so `npm run build` must have run — a spec here
 * scored against a stale bundle is a false pass, which is how 138020a's first
 * two runs went.
 *
 * ## 1. The type vocabulary had no consumer in the shelf
 *
 * `KIND_GLYPHS` measures ink at 12px to keep a public key apart from a private
 * one, and neither `OpsShelf.tsx` nor `OpsTile.tsx` referenced it. Measured on
 * the committed bundle at 1440×900 with an empty notebook: **52 captions
 * across the shelf printed a type as bare words with no mark beside it** —
 * `needs bytes` 13 times, `needs text` 15, `needs shares` 8, `needs
 * recipients` 2, `needs sdp` 2, `needs item` 2, `needs openpgp-key` once —
 * while every one of those types has a pictogram the artifact tiles draw.
 *
 * A further **nine** read `needs any`, which names a constraint none of those
 * steps has: `any` is the absence of one. They read `needs a value` now, which
 * is the true state — the caret is holding nothing for them to take.
 *
 * ## 2. The header said the module and never the suite
 *
 * `CastDot` renders one light per toolbox and nothing at all where
 * `toolboxToSuite` answers null, so on the committed page the SSH header was a
 * dot and the word "SSH" — with no way to learn that what qualifies those ops
 * is the **webcrypto** suite — and the `age`, `jose`, `otp`, `io`, `encoding`
 * and `flow` headers were indistinguishable from a toolbox whose status had
 * not arrived yet. Eleven of fourteen toolboxes make no CAST claim and the
 * page said so nowhere.
 *
 * ## What is asserted, and what is deliberately not
 *
 * The glyph claim is made against `GLYPH_PATHS` by comparing painted `d`
 * attributes with declared geometry, the way `ops-pair-row.e2e.js` does it —
 * markup would be asserting React's serialiser. `needs text` is the control
 * in the same sweep: a change that dropped the map and drew one house glyph
 * everywhere would satisfy "has a mark" and fail there.
 *
 * The chip is **not** checked against live suite status, because it does not
 * carry any: which suite qualifies an op is a registry fact, and whether that
 * suite is green this session is the dot's job and `ToolkitShell`'s state.
 *
 * The fit sweep covers the *solo* rows, which `ops-pair-row.e2e.js` skips by
 * construction — it selects rows with exactly two buttons. Eleven solo rows
 * were clipping their op name at the panel's 160px minimum before this, with
 * no caret active, and all five Key-formats rows were rendering their name
 * into a column of zero width.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GLYPH_PATHS } from "../../lib/toolkit/glyphs.js";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the shelf is measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[ops-type-and-suite.e2e] skipping — chromium not installed (${availability.reason})`);
}

/** The `d` of every path in a glyph body, in order. What was painted, not how. */
function pathData(svgInner) {
  return [...String(svgInner || "").matchAll(/\sd="([^"]*)"/g)].map((m) => m[1]);
}

/** Every refusal caption on the page, with whatever art it draws. */
function captions() {
  const out = [];
  for (const el of document.querySelectorAll(".ops-panel [data-disabled-reason]")) {
    const svg = el.querySelector("svg");
    out.push({
      /** What it announces — the caption is `aria-describedby`'s target. */
      text: (el.textContent || "").trim(),
      hasGlyph: !!svg,
      svg: svg?.innerHTML || "",
      /** A glyph inside a caption is decoration and must stay out of the name. */
      hidden: svg ? svg.getAttribute("aria-hidden") === "true" : true,
      /** The control that points at it, so a caption cannot be orphaned art. */
      described: !!document.querySelector(`[aria-describedby~="${CSS.escape(el.id)}"]`),
    });
  }
  return out;
}

/**
 * Conjugate rows whose two handles are refused for the *same* reason.
 *
 * A row is a conjugate one by shape — one `<code>` and exactly two buttons —
 * the way `ops-pair-row.e2e.js` finds them, and the reason is read off the
 * handles' own names rather than off the captions, so a row that printed no
 * caption at all still shows up here as a row printing zero.
 */
function sharedReasonRows() {
  const rows = [];
  for (const code of document.querySelectorAll(".ops-category code")) {
    const row = code.parentElement;
    const buttons = [...row.querySelectorAll("button")];
    if (buttons.length !== 2) continue;
    const reasons = buttons.map(
      (b) => (b.getAttribute("aria-label") || "").split(", unavailable: ")[1]
    );
    if (!reasons[0] || reasons[0] !== reasons[1]) continue;
    rows.push({
      at: (code.textContent || "∅").trim(),
      reason: reasons[0],
      printed: [...row.querySelectorAll("[data-disabled-reason]")].map((c) =>
        c.textContent.trim()
      ),
    });
  }
  return rows;
}

/** Every toolbox header, its chip, and the name the header announces. */
function headers() {
  const nameOf = (el) => {
    const parts = [];
    for (const n of el.childNodes) {
      if (n.nodeType === 3) parts.push(n.textContent.trim());
      else if (n.nodeType === 1) {
        if (n.getAttribute("aria-hidden") === "true") continue;
        parts.push((n.getAttribute("aria-label") || n.textContent || "").trim());
      }
    }
    return parts.filter(Boolean).join(" ");
  };
  return [...document.querySelectorAll(".ops-category")].map((cat) => {
    const button = cat.querySelector("button");
    const chip = cat.querySelector("[data-suite-chip]");
    return {
      toolbox: cat.getAttribute("data-toolbox"),
      chip: chip ? (chip.textContent || "").trim() : null,
      suiteAttr: chip ? chip.getAttribute("data-suite-chip") : null,
      name: button ? nameOf(button) : "",
    };
  });
}

/**
 * Anything on the shelf that is cut off or hanging outside its row.
 *
 * Covers the solo rows and the Key-formats rows as well as the conjugate ones,
 * because those are the rows the type mark was added to and the rows the
 * existing overflow spec cannot see. `scrollWidth > clientWidth` is the test
 * for a clipped string; the box comparison is the test for one that escaped.
 */
function shelfOverflow() {
  const bad = [];
  const panel =
    document.querySelector(".ops-panel aside, aside.ops-panel") ||
    document.querySelector(".ops-panel");
  const pb = panel.getBoundingClientRect();
  const codes = document.querySelectorAll(
    ".ops-category code, [data-shelf] code, [data-format-kit] code"
  );
  for (const code of codes) {
    const row = code.parentElement;
    const rb = row.getBoundingClientRect();
    const at = `${(code.textContent || "∅").trim()}|${[...row.querySelectorAll("button")]
      .map((b) => b.textContent.trim())
      .join("|")}`;
    if (code.scrollWidth > code.clientWidth + 1) bad.push(`${at}: the op name is clipped`);
    for (const b of row.querySelectorAll("button")) {
      const bb = b.getBoundingClientRect();
      if (b.scrollWidth > b.clientWidth + 1)
        bad.push(`${at}: control ${JSON.stringify(b.textContent.trim())} is clipped`);
      if (bb.left < rb.left - 0.5 || bb.right > rb.right + 0.5)
        bad.push(`${at}: control ${JSON.stringify(b.textContent.trim())} is outside the row`);
      if (bb.right > pb.right + 0.5) bad.push(`${at}: control escaped the panel`);
    }
    for (const c of row.querySelectorAll("[data-disabled-reason]")) {
      if (c.scrollWidth > c.clientWidth + 1)
        bad.push(`${at}: caption ${JSON.stringify(c.textContent.trim())} is clipped`);
      if (c.getBoundingClientRect().right > rb.right + 0.5)
        bad.push(`${at}: caption is outside the row`);
    }
  }
  for (const chip of document.querySelectorAll("[data-suite-chip]")) {
    const host = chip.closest("button") || chip.parentElement;
    const hb = host.getBoundingClientRect();
    const cb = chip.getBoundingClientRect();
    const at = chip.textContent.trim();
    if (chip.scrollWidth > chip.clientWidth + 1) bad.push(`chip ${at} is clipped`);
    if (cb.right > hb.right + 0.5 || cb.right > pb.right + 0.5)
      bad.push(`chip ${at} escaped its header`);
  }
  const wide = [...document.querySelectorAll(".ops-category")]
    .filter((c) => c.scrollWidth > c.clientWidth)
    .map((c) => `${c.getAttribute("data-toolbox")} scrolls sideways`);
  return { bad: [...bad, ...wide], rows: codes.length };
}

describe.skipIf(!availability.ok)("the shelf draws the type it names", () => {
  /** @type {Awaited<ReturnType<typeof serveDist>>} */
  let server;
  /** @type {import("playwright").Browser} */
  let browser;
  /** @type {import("playwright").Page} */
  let page;
  /** @type {ReturnType<typeof captions>} */
  let caps;
  /** @type {ReturnType<typeof sharedReasonRows>} */
  let shared;

  beforeAll(async () => {
    const { chromium } = await import("playwright");
    server = await serveDist(DIST_ROOT);
    browser = await chromium.launch();
    page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
    await page.waitForFunction(() => document.readyState === "complete");
    await page.waitForSelector(".ops-category code");
    await page.waitForTimeout(500);
    caps = await page.evaluate(captions);
    shared = await page.evaluate(sharedReasonRows);
  });

  afterAll(async () => {
    await page?.close();
    await browser?.close();
    await server?.close();
  });

  it("finds the captions it is measuring", () => {
    // A selector that has rotted returns an empty sweep, and an empty sweep
    // passes every assertion below it. 61 captions on the default page.
    expect(caps.length, "no refusal captions on the shelf at all").toBeGreaterThan(30);
    expect(
      caps.filter((c) => c.text.startsWith("needs ")).length,
      "nothing on the page says what it needs"
    ).toBeGreaterThan(20);
  });

  it("puts a mark beside every caption that names a type", () => {
    // The captions that name a real type are exactly the ones that must draw
    // one. `needs a value` and `needs input` name the caret's state instead
    // and are excluded by name below, not by being allowed to fail here.
    const named = caps.filter(
      (c) => c.text.startsWith("needs ") && !/^needs (a value|input)$/.test(c.text)
    );
    expect(named.length, "no type-naming captions found").toBeGreaterThan(20);
    const bare = [...new Set(named.filter((c) => !c.hasGlyph).map((c) => c.text))];
    expect(bare, `captions naming a type with nothing drawn: ${bare.join(", ")}`).toEqual([]);
  });

  it("draws the OpenPGP key's own asset, and the control's is still its own", () => {
    // Geometry, not markup: React serialises `<path … />` as `<path …></path>`
    // and a string compare would be asserting the serialiser.
    const pgp = caps.find((c) => c.text === "needs openpgp-key");
    expect(pgp, "no row on the default page asks for an openpgp-key").toBeTruthy();
    expect(pathData(pgp.svg)).toEqual(pathData(GLYPH_PATHS["key-openpgp"]));
    // …and it is not the key an SSH row draws. `key-secret` is what
    // `ssh-private` resolves to, and reusing it is the defect the split above
    // this exists to prevent.
    expect(pathData(pgp.svg)).not.toEqual(pathData(GLYPH_PATHS["key-secret"]));
    expect(pathData(pgp.svg)).not.toEqual(pathData(GLYPH_PATHS["key-public"]));
  });

  it("draws different types differently, bar one pair it names", () => {
    // The cheap way to pass the sweep above is one glyph everywhere, so the
    // painted geometry is grouped and the groups are asserted — not a count,
    // which a single collapse would still satisfy.
    const byText = new Map();
    for (const c of caps) {
      if (!c.hasGlyph) continue;
      byText.set(c.text, c.svg.replace(/\s+/g, " ").trim());
    }
    expect(byText.size, "fewer than five distinct types on the page").toBeGreaterThan(4);
    const byShape = new Map();
    for (const [text, shape] of byText) {
      byShape.set(shape, [...(byShape.get(shape) || []), text].sort());
    }
    const collisions = [...byShape.values()].filter((g) => g.length > 1).map((g) => g.join(" = "));
    // **None**, and the exemption that used to be here is what closed it.
    // This asserted the exact pair `shares = recipients`, both of which
    // resolved to lucide's `Users` in `KIND_GLYPHS` while `GLYPH_PATHS` held a
    // drawing for each. The comment justifying that consulted `kindGlyph`'s
    // own note about the tray tab keeping its chrome icon — which turned out
    // to be about `share`, a different name that never collided with either.
    //
    // Five names were shadowed that way, not two. They are out of
    // `KIND_GLYPHS` now and draw their own art, and the invariant that keeps
    // them there is pinned at the unit layer by `glyph-shadowing.test.js`: no
    // name may appear in both maps.
    //
    // Spending the exemption rather than deleting the assertion, because the
    // sweep above is still satisfied by one glyph everywhere. An empty list is
    // the strongest form this test has ever had, and any new collision fails
    // it — which is what the exact-pair form was for.
    expect(
      collisions,
      `types sharing a mark: ${collisions.join("; ")}`
    ).toEqual([]);
  });

  it("never asks for `any`, which is not a type", () => {
    const wrong = caps.filter((c) => /\bany\b/.test(c.text)).map((c) => c.text);
    expect(wrong, `captions naming \`any\` as a type: ${wrong.join(", ")}`).toEqual([]);
    // …and the rows that used to say it still say something. Deleting the
    // caption would satisfy the line above and leave nine rows dead and
    // silent, which is the state the caption exists to prevent.
    const value = caps.filter((c) => c.text === "needs a value");
    expect(value.length, "the `any` rows lost their caption instead of fixing it").toBeGreaterThan(4);
  });

  it("states one reason once when both directions want the same type", () => {
    // Found by mutation, and it is a gap this change widened rather than
    // opened: `sharedNeed` is what stops a row printing "needs bytes" twice
    // and doubling its height, `ops-shelf-states.test.js` holds it as a
    // *source regex*, and nothing anywhere looked at the page. Carrying
    // `{ text, type }` instead of a string makes it easier to break —
    // comparing the two objects by identity always splits and reads as a
    // perfectly ordinary equality — so the claim gets a measurement.
    expect(shared.length, "no conjugate row on the page refuses both directions alike").toBeGreaterThan(2);
    const doubled = shared
      .filter((r) => r.printed.length !== 1)
      .map((r) => `${r.at}: ${r.printed.length} captions — ${r.printed.join(" / ")}`);
    expect(doubled, `rows repeating one reason:\n  ${doubled.join("\n  ")}`).toEqual([]);
    // …and the one it prints is the reason, not an empty box that satisfies
    // the count.
    for (const r of shared) expect(r.printed[0]).toBe(r.reason);
  });

  it("keeps the art out of the announcement", () => {
    // A caption is `aria-describedby`'s target, so anything inside it is read
    // out. The mark is decoration; the sentence is the content.
    const exposed = caps.filter((c) => !c.hidden).map((c) => c.text);
    expect(exposed, `glyphs exposed to the accessibility tree: ${exposed.join(", ")}`).toEqual([]);
    const orphaned = caps
      .filter((c) => c.text.startsWith("needs ") && !c.described)
      .map((c) => c.text);
    expect(
      orphaned,
      `captions no control describes itself with: ${orphaned.join(", ")}`
    ).toEqual([]);
  });
});

describe.skipIf(!availability.ok)("the header names the suite, not the module", () => {
  /** @type {Awaited<ReturnType<typeof serveDist>>} */
  let server;
  /** @type {import("playwright").Browser} */
  let browser;
  /** @type {import("playwright").Page} */
  let page;
  /** @type {ReturnType<typeof headers>} */
  let heads;
  /** width → what the fit sweep found there. */
  const fit = {};

  beforeAll(async () => {
    const { chromium } = await import("playwright");
    server = await serveDist(DIST_ROOT);
    browser = await chromium.launch();
    page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
    await page.waitForSelector(".ops-category code");
    await page.waitForTimeout(500);
    heads = await page.evaluate(headers);

    // `OPS_PANE_LIMITS` is { min: 160, max: 520, def: 220 }. Both ends are
    // measured, and the Key-formats kit with them: it is reached from the
    // footer bar, so a sweep of the browse tree alone never sees it.
    for (const width of [220, 160]) {
      const p2 = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      await p2.addInitScript((w) => {
        localStorage.setItem("basilisk.toolkit.layout", JSON.stringify({ opsW: w }));
      }, width);
      await p2.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
      await p2.waitForSelector(".ops-category code");
      // Every toolbox open, so the sweep sees the OpenPGP rows and not just
      // whatever the caret happens to leave expanded.
      await p2.getByRole("button", { name: /Show all/ }).first().click();
      await p2.waitForTimeout(400);
      fit[`${width}:browse`] = await p2.evaluate(shelfOverflow);
      await p2.getByRole("button", { name: "Formats", exact: true }).click();
      await p2.waitForTimeout(300);
      await p2.getByRole("button", { name: "Export", exact: true }).click();
      await p2.waitForTimeout(300);
      fit[`${width}:formats`] = await p2.evaluate(shelfOverflow);
      await p2.close();
    }
  });

  afterAll(async () => {
    await page?.close();
    await browser?.close();
    await server?.close();
  });

  it("finds the headers it is measuring", () => {
    expect(heads.length, "no toolbox headers on the shelf").toBeGreaterThan(10);
    expect(heads.map((h) => h.toolbox)).toEqual(expect.arrayContaining(["ssh", "age", "openpgp"]));
  });

  it("gives every toolbox a chip, including the ones with nothing to claim", () => {
    const missing = heads.filter((h) => !h.chip).map((h) => h.toolbox);
    expect(missing, `toolboxes with no CAST chip: ${missing.join(", ")}`).toEqual([]);
  });

  it("says `webcrypto` on the SSH header, because that is what qualifies it", () => {
    // The whole point of naming the suite rather than the module. `SSH` alone
    // invites a reader to assume an SSH self-test exists; there is none.
    const ssh = heads.find((h) => h.toolbox === "ssh");
    expect(ssh.chip).toBe("CAST webcrypto");
    expect(ssh.suiteAttr).toBe("webcrypto");
    // …and the two toolboxes whose name *is* their suite still print it, so
    // SSH does not read as a special case.
    expect(heads.find((h) => h.toolbox === "openpgp").chip).toBe("CAST openpgp");
    expect(heads.find((h) => h.toolbox === "webcrypto").chip).toBe("CAST webcrypto");
    expect(heads.find((h) => h.toolbox === "sss").chip).toBe("CAST sss");
  });

  it("reads a null suite as nothing verifying it, not as a pass and not as blank", () => {
    // The claim this whole chip is worth making. `age` is unmistakably crypto
    // and no CAST suite covers it; a chip that omitted the null case would be
    // worse than no chip, because absence would read as "fine".
    for (const tb of ["age", "jose", "otp", "io", "encoding", "flow"]) {
      const h = heads.find((x) => x.toolbox === tb);
      expect(h, `${tb} is not on the page`).toBeTruthy();
      expect(h.chip, `${tb} header`).toBe("no CAST suite");
      expect(h.suiteAttr).toBe("none");
    }
  });

  it("announces the chip as part of the header, not only in pixels", () => {
    // A `role="img"` label would replace the words a sighted reader has; a
    // `title` would be a description a reader may never hear. It is content.
    const ssh = heads.find((h) => h.toolbox === "ssh");
    expect(ssh.name, `SSH announces ${JSON.stringify(ssh.name)}`).toContain("CAST webcrypto");
    const age = heads.find((h) => h.toolbox === "age");
    expect(age.name, `age announces ${JSON.stringify(age.name)}`).toContain("no CAST suite");
  });

  it("fits the panel at its default width and at its minimum", () => {
    for (const key of ["220:browse", "160:browse", "220:formats", "160:formats"]) {
      const m = fit[key];
      // An empty sweep passes; so does one taken before the shelf rendered.
      expect(m, `the ${key} sweep never ran`).toBeTruthy();
      expect(m.rows, `nothing on the shelf at ${key}`).toBeGreaterThan(2);
      expect(m.bad, `at ${key} the shelf does not fit:\n  ${m.bad.join("\n  ")}`).toEqual([]);
    }
    // The browse sweep is the one that has to be large, or "nothing clips"
    // is a claim about three rows.
    expect(fit["160:browse"].rows).toBeGreaterThan(60);
  });
});
