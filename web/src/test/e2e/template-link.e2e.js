/**
 * `#t=` in the address bar, followed the way a person follows a link.
 *
 * ## The state that was true
 *
 * `#t=<anything this build does not have>` loaded nothing and said nothing.
 * `fragment.js` parses it to `{ kind: "preset", id }`, `useNotebook`'s
 * `loadFromHash` did `PRESETS.find(…); if (!p) return;` — and then, 250ms
 * later, the address bar rewrote itself. `hashForToolkitState` reads `#t=` as
 * one of the forms this product writes, so a notebook with nothing in it took
 * the `keepOrClear` branch and cleared it. The link a person had just followed
 * disappeared out of the bar in front of them, the notebook stayed empty, and
 * no sentence appeared anywhere on the page.
 *
 * That is worse than an ordinary silent failure, because it destroys the
 * evidence: a reader who wanted to ask somebody "this link does nothing" no
 * longer has the link.
 *
 * ## Why it is reachable, given that no id has been retired
 *
 * Nothing this product generates makes such a URL — every `#t=` it writes comes
 * from `hashForPreset` over a real member of `PRESETS`. What made the silence
 * reachable is `6575aba`, which added two gallery entries that are deliberately
 * **not** in `PRESETS`: the room templates, which carry no recipe because a
 * room notebook is one cell per holder addressed by whole fingerprint and
 * nothing static can know the audience. Their ids are exactly `#t=`'s shape.
 * So `#t=room-deal` is a thing a person can type, bookmark off a screenshot, or
 * infer from a menu that shows the entry — and it behaved precisely like a
 * typo.
 *
 * ## What it does now, and the line between the two answers
 *
 * An id that matches nothing is **said**, and nothing is guessed: no redirect
 * to something plausible, because that would be this product deciding what
 * somebody meant with their notebook as the stake.
 *
 * An id that names a room entry **opens the picker the entry declares**, which
 * is the one thing such a link can have meant — `ROOM_TEMPLATES` carries
 * `opens`, `PresetMenu`'s card presses the same field, and this is the same
 * door from the address bar. The notebook is not touched either way.
 *
 * ## Why a browser
 *
 * Every piece of this is a seam between layers that are each already right.
 * `parseToolkitHash` parses correctly and has unit tests; `PRESETS` and
 * `ROOM_TEMPLATES` are both swept by `preset-company.test.js`; the session
 * sheet opens when it is told to. What was wrong is what the *shell* does with
 * a parse result, and both halves of that live in `useCallback`s and
 * `useEffect`s inside two hooks — unreachable from `environment: "node"`, and
 * the failure mode is a page that looks exactly like a page that has just
 * finished loading normally. The only witness is somebody watching the screen.
 *
 * One browser and no session: nothing here crosses a machine boundary, and the
 * two-peer journeys should not pay for a link.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers } from "../helpers/browser-peers.js";
import { PRESETS, ROOM_TEMPLATES } from "../../lib/toolkit/recipe.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the template-link suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[template-link.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * The status line under the run bar, plus the error line that replaces it.
 *
 * One string because the shell draws one paragraph — `runError || runStatus` —
 * so a reader sees whichever is true and so does this. It is also the only
 * place a sentence about a link could appear: `loadFromHash` runs before there
 * is a notebook, a cell or a tray to hang anything else off.
 */
async function runLine(page) {
  const p = page.locator("[data-run-state]").locator("xpath=following-sibling::p[1]");
  // **The paragraph is only in the DOM when there is something to say** — the
  // shell draws it on `runStatus || runError` and nothing otherwise. So "" is a
  // real answer here and is the one the control asserts: a link that worked says
  // nothing at all. Reading `innerText` unconditionally would instead spend
  // Playwright's full locator budget on the silent case and report a timeout,
  // which is the least informative way to describe a page that is behaving.
  return (await p.count()) ? (await p.innerText()).trim() : "";
}

/** What the address bar actually holds — not a DOM node, so this evaluates. */
const hashOf = (page) => page.evaluate(() => window.location.hash);

/**
 * Open a hash **cold**, as a bookmark or a pasted link opens one.
 *
 * `page.goto` to a URL that differs only in its fragment is a same-document
 * navigation: `hashchange` fires and nothing remounts. That is a real way to
 * arrive and the last test in this file drives it deliberately — but it is not
 * the way a stale link is usually followed, and the two are genuinely different
 * code paths *for the defect this file is about*. The address-bar rewrite is
 * debounced off `nb.source`, so it fires 250ms after a mount and not again
 * until the notebook changes: on a same-document hop it never runs at all, and
 * the `#t=` survives by accident. Only a cold load reproduces the vanishing.
 */
async function openCold(page, url) {
  await page.goto(url, { waitUntil: "load" });
  await page.reload({ waitUntil: "load" });
  // Wait for the shell itself, not just the document. `load` fires before React
  // has mounted anything, and every assertion below reads a node the shell
  // draws — so without this the first read of each test spends Playwright's own
  // thirty-second locator budget waiting for a node that arrives in one, which
  // outlives the poll wrapped around it and reports as a timeout rather than as
  // a difference. A notebook always has one cell, so this is true on every page
  // this file opens, including the ones that load nothing.
  await page.locator("article").first().waitFor({ state: "visible", timeout: 30000 });
}

describe.runIf(availability.ok)("a template link that names nothing this build has", () => {
  /** @type {Awaited<ReturnType<typeof openPeers>>} */
  let mesh;
  /** @type {import("playwright").Page} */
  let page;

  beforeAll(async () => {
    mesh = await openPeers({ count: 1, path: "/toolkit" });
    page = mesh.peers[0].page;
  }, 120000);

  afterAll(async () => {
    await mesh?.close();
  });

  /**
   * The control, and it runs first so that everything below is a difference
   * from a link that works rather than a claim about a page nobody has seen
   * load. A real preset id must still load its recipe and say nothing wrong.
   */
  it("still loads a real one, silently, which is the control", async () => {
    const real = PRESETS[0];
    // The op the recipe opens with, as the cell draws it. Read off the rendered
    // pipeline rather than the Source panel, because that is what a person sees
    // arrive — and the assertion only needs a token an empty notebook cannot
    // produce, which the first op's name is.
    const firstOp = real.recipe.trim().split(/[\s|\n]/)[0];
    await openCold(page, `${mesh.origin}/toolkit#t=${real.id}`);
    await expect
      .poll(async () => await page.locator("article").first().innerText(), { timeout: 20000 })
      .toContain(firstOp);
    // Nothing was said, because nothing needed saying. This is the assertion
    // that the two below are about a *new* sentence rather than about a shell
    // that narrates every link it opens.
    expect(await runLine(page)).toBe("");
    // **And the bar keeps a link**, which is the half that makes this a control
    // for the two tests below rather than a smoke test. The same rewrite that
    // clears an unknown `#t=` runs here — `keepOrClear` only reaches its clear
    // branch when there is no notebook to describe, and there is one now, so
    // what lands is this notebook's own form.
    await expect.poll(async () => await hashOf(page), { timeout: 20000 }).toMatch(/^#(t|r)=/);
  });

  it("says so, and leaves the notebook alone", async () => {
    // Cold, because a stale bookmark is opened cold — and because only a cold
    // load reaches the rewrite the next test is about. The last test in this
    // file drives the same-document arrival.
    await openCold(page, `${mesh.origin}/toolkit#t=not-a-real-template`);

    await expect
      .poll(async () => await runLine(page), { timeout: 20000 })
      .toMatch(/No template called "not-a-real-template" is in this build/);
    // The reader is told where the real list is, and told their work is safe —
    // the two questions a person has when a link they followed did nothing.
    const said = await runLine(page);
    expect(said).toMatch(/notebook is untouched/);
    expect(said).toMatch(/Templates lists everything there is/);
    // And it is drawn as a refusal rather than as progress.
    const line = page.locator("[data-run-state]").locator("xpath=following-sibling::p[1]");
    expect(await line.getAttribute("class")).toContain("--error");

    // Nothing was loaded. One empty cell is what an untouched notebook is.
    expect(await page.locator("article").count()).toBe(1);
  });

  it("keeps saying so once the bar has rewritten itself", async () => {
    // The rewrite is the part that made this state unreportable: `#t=` is a
    // form this product writes, so an empty notebook clears it 250ms later and
    // the reader loses the link as well as the answer. The sentence has to
    // outlive it, and this is the assertion that it does.
    await expect.poll(async () => await hashOf(page), { timeout: 20000 }).toBe("");
    expect(await runLine(page)).toMatch(/No template called/);
  });
});

describe.runIf(availability.ok)("a template link naming a room entry", () => {
  /** @type {Awaited<ReturnType<typeof openPeers>>} */
  let mesh;
  /** @type {import("playwright").Page} */
  let page;

  beforeAll(async () => {
    mesh = await openPeers({ count: 1, path: "/toolkit" });
    page = mesh.peers[0].page;
  }, 120000);

  afterAll(async () => {
    await mesh?.close();
  });

  /**
   * Every room entry, by its own declaration.
   *
   * Driven off `ROOM_TEMPLATES` rather than a list of two ids written here, so
   * a third entry added tomorrow is covered on the day it is added — which is
   * the shape of the defect this file exists for. A room template that shipped
   * with no way in from a link would be exactly `6575aba`'s two, again.
   */
  for (const entry of ROOM_TEMPLATES) {
    it(`opens the ${entry.opens} picker for #t=${entry.id}`, async () => {
      await openCold(page, `${mesh.origin}/toolkit#t=${entry.id}`);

      // The sheet, focused on the picker the entry names. `data-session-focus`
      // is what `SessionSheet` puts the focus on, so this reads the shell's own
      // answer to "which half of this sheet did the link ask for".
      const sheet = page.locator("[data-session-focus]");
      await sheet.waitFor({ state: "visible", timeout: 20000 });
      expect(await sheet.getAttribute("data-session-focus")).toBe(entry.opens);

      // And the notebook was not replaced by opening it — the promise the
      // menu's own card makes ("nothing you have open is replaced"), kept for
      // the link too.
      expect(await page.locator("article").count()).toBe(1);

      // Said, as well as shown. A sheet that appears on its own is not an
      // explanation of why the template had no text to load.
      const said = await runLine(page);
      expect(said).toContain(entry.title);
      expect(said).toMatch(/a link cannot carry its text/);
      expect(said).toMatch(/Nothing in your notebook has been replaced/);
    });
  }

  it("answers a link that arrives while the toolkit is already open", async () => {
    // A same-document navigation: the URL changes and no document loads, so a
    // mount-only effect never runs again. It is the likeliest way any of these
    // links is opened — the two of you are talking and they already have this
    // page up — and it is the exact shape of the defect `4027326` closed for
    // `#j=`. Start somewhere else so the hash genuinely changes.
    await page.goto(`${mesh.origin}/toolkit`, { waitUntil: "load" });
    await page.evaluate(() => {
      document.querySelector("[data-session-focus]")?.remove();
    });
    await page.evaluate(() => {
      window.location.hash = "#t=room-recover";
    });
    const sheet = page.locator("[data-session-focus]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    expect(await sheet.getAttribute("data-session-focus")).toBe("recovery");

    // And the unknown-id half answers a hash change too, on the same page.
    await page.evaluate(() => {
      window.location.hash = "#t=still-not-a-template";
    });
    await expect
      .poll(async () => await runLine(page), { timeout: 20000 })
      .toMatch(/No template called "still-not-a-template"/);
  });
});
