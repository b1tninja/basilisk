/**
 * The search page, as shipped, against a real directory.
 *
 * `src/pages/index.tsx` is the first page anyone sees and the browser suite has
 * never opened it. What it does is not decoration: it decides — in the page,
 * before any request — whether a query is even askable, and it decides which of
 * two cautions a result is shown under. Both of those are the kind of thing
 * that breaks without failing. A caution that stops rendering leaves a person
 * trusting an eight-character key ID; a validator that stops refusing sends
 * malformed queries to a keyserver that will answer *something*.
 *
 * So the assertions are about that, not about the hero copy. Nothing here
 * re-tests `/api/v1/search` — `tests/unit` owns the server's own answers, and
 * `hkp-directory.e2e.js` owns the ops the toolkit calls it with. This is the
 * page: what it sends, what it refuses to send, and what it says over the
 * answer that comes back.
 *
 * Like every spec here it serves `dist/` and drives Chromium, so the module
 * under test is the built bundle under the shipped `<meta>` CSP, not a copy
 * vite compiled for the test. `run npm run build` first or there is nothing to
 * serve.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers } from "../helpers/browser-peers.js";
import { buildKeyCorpus } from "../helpers/key-corpus.js";
import {
  basiliskAvailability,
  seedDirectory,
  startBasilisk,
} from "../helpers/basilisk-server.js";

const chromium = await chromiumAvailability();
const python = await basiliskAvailability();

// Present-but-broken is a failure and absent is a skip — `ssh-format.test.js`'s
// rule, which the rest of this directory already follows.
if (!python.ok && python.kind === "broken") {
  it("runs the keyserver the search page talks to", () => {
    expect.unreachable(`python is installed but would not run the server: ${python.reason}`);
  });
} else if (!python.ok) {
  console.warn(`[portal-search.e2e] skipping — no python can import basilisk.serve (${python.reason})`);
}
if (!chromium.ok && chromium.kind === "broken") {
  it("launches the browser the search page runs in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${chromium.reason}`);
  });
} else if (!chromium.ok) {
  console.warn(`[portal-search.e2e] skipping — chromium not installed (${chromium.reason})`);
}

const corpus = python.ok ? await buildKeyCorpus() : null;

describe.skipIf(!python.ok || !chromium.ok)("the search page, against a real directory", () => {
  /** @type {Awaited<ReturnType<typeof startBasilisk>>} */
  let basilisk;
  /** @type {Awaited<ReturnType<typeof openPeers>>} */
  let fixture;
  /** @type {import("playwright").Page} */
  let page;
  /** @type {any} */
  let alice;
  /** @type {any} */
  let heidi;

  beforeAll(async () => {
    basilisk = await startBasilisk({ python: python.python });
    // A named subset rather than the whole corpus, and rather than
    // `rejectRevoked: false`. `grace` is revoked and `/pks/add` refuses her by
    // policy — a policy this file is not testing and should not be switching
    // off to get a fixture up. Three approved keys and one pending is every
    // state the page draws differently: a result, and a directory that holds a
    // key it will not publish.
    const seeded = await seedDirectory(
      basilisk,
      ["alice", "bob", "carol", "heidi"].map((id) => /** @type {any} */ (corpus).byId(id))
    );
    if (seeded.refused.length) {
      throw new Error(`the directory refused a corpus key: ${JSON.stringify(seeded.refused)}`);
    }
    alice = /** @type {any} */ (corpus).byId("alice");
    heidi = /** @type {any} */ (corpus).byId("heidi");
    fixture = await openPeers({ path: "/", count: 1, routes: basilisk.routes });
    page = fixture.peers[0].page;
  });

  afterAll(async () => {
    await fixture?.close();
    await basilisk?.close();
  });

  /** Load the page with `?q=`, which is the deep link every result links out of. */
  async function search(q) {
    await page.goto(`${fixture.origin}/?q=${encodeURIComponent(q)}`, { waitUntil: "load" });
    // Settled means the *button* is back — "Searching…" is written into the
    // same `p.muted` the answer lands in, so waiting for that paragraph to
    // have text catches the page mid-request and reads an empty result list as
    // a real one. The button is rendered straight off `searching`, which is
    // the state actually being waited for.
    await page.waitForFunction(
      () => {
        const btn = document.querySelector(".search-submit-btn");
        if (!btn || btn.textContent?.trim() !== "Search") return false;
        return (
          !!document.querySelector(".result-card") ||
          (document.querySelector("p.muted")?.textContent || "").trim().length > 0
        );
      },
      undefined,
      { timeout: 15000 }
    );
  }

  const cards = () =>
    page.$$eval(".result-card", (els) =>
      els.map((el) => ({
        label: el.querySelector(".result-email")?.textContent?.trim() || "",
        pill: el.querySelector(".result-pill")?.textContent?.trim() || "",
        fpr: el.querySelector(".result-fpr")?.textContent?.trim() || "",
        href: el.querySelector(".result-view-btn")?.getAttribute("href") || "",
      }))
    );

  const cautions = () =>
    page.$$eval(".name-search-caution", (els) => els.map((el) => el.textContent?.trim() || ""));

  const message = () =>
    page.$eval("p.muted", (el) => el.textContent?.trim() || "").catch(() => "");

  it("answers a deep link on load, and links the result to its key page", async () => {
    // `?q=` is not a convenience: it is what a result's View button and every
    // link anyone pastes resolve to, so a page that only searched on submit
    // would break every one of them and still look fine by hand.
    await search("alice@corp.test");
    const found = await cards();
    expect(found).toHaveLength(1);
    expect(found[0].label).toBe("alice@corp.test");
    expect(found[0].pill).toBe("approved");
    // Grouped for reading, not the raw 40 characters the API returns.
    expect(found[0].fpr.replace(/\s+/g, "")).toBe(alice.fingerprint);
    expect(found[0].fpr).not.toBe(alice.fingerprint);
    expect(found[0].href).toBe(`/key?fpr=${alice.fingerprint}`);
  });

  it("says a pending key is pending instead of saying there is none", async () => {
    // The directory holds heidi and has approved nothing about her. "No
    // matching keys" would be a lie a person would act on by uploading again.
    await search(heidi.email);
    expect(await cards()).toEqual([]);
    expect(await message()).toMatch(/pending approval/i);
  });

  it("puts the collision caution on a short key ID, with the result", async () => {
    // The security copy this page exists to carry. Eight hex characters are
    // eight hex characters; the server says so in `warning` and the page has
    // to render it *next to the key it is warning about*, not instead of it.
    await search(alice.fingerprint.slice(-8));
    const found = await cards();
    expect(found).toHaveLength(1);
    expect(found[0].fpr.replace(/\s+/g, "")).toBe(alice.fingerprint);
    expect((await cautions()).join(" ")).toMatch(/Short key ID/);
  });

  it("puts the unverified-names caution on a name search", async () => {
    // Names in a user id are whatever the key's owner typed. Every corpus key
    // is an "Example", so this is the many-hits case as well.
    await search("Example");
    expect((await cards()).length).toBeGreaterThan(1);
    expect((await cautions()).join(" ")).toMatch(/Names are unverified/);
  });

  it("refuses a malformed fingerprint in the page, without asking the server", async () => {
    // The half no server test can cover. `validateQuery` runs before `fetch`,
    // so a bad `0x…` never becomes a request — and the request log is the only
    // honest way to assert "never became a request".
    await page.goto(`${fixture.origin}/`, { waitUntil: "load" });
    basilisk.resetCounts();
    await page.fill("#q", "0xZZZZ");
    await page.click(".search-submit-btn");
    await page.waitForFunction(
      () => (document.querySelector("p.muted")?.textContent || "").includes("hex characters"),
      undefined,
      { timeout: 5000 }
    );
    expect(await cards()).toEqual([]);
    expect(basilisk.counts().search ?? 0).toBe(0);
  });

  /**
   * The fingerprint is a control, and this is the only place it is one in a
   * real browser under the real policy.
   *
   * The node suite renders it with `react-dom/server`, which can see what the
   * markup says and nothing about what a press does. Three things can only fail
   * here: the menu is a Radix portal, which writes inline styles that
   * `style-src 'self'` refuses outright unless `lib/scroll-lock` is aliased in;
   * the clipboard is a browser API; and the whole point of the exercise is that
   * what leaves on the clipboard is *not* what the reader is looking at.
   */
  it("copies the whole fingerprint from a control, under the shipped policy", async () => {
    await search("alice@corp.test");

    // The clipboard is stubbed rather than granted, because the assertion is
    // about the argument, not about Chromium's clipboard: `writeText` is what
    // the component calls, and what it is called with is the claim.
    await page.evaluate(() => {
      /** @type {string[]} */
      const wrote = [];
      Object.defineProperty(window, "__copied", { value: wrote, configurable: true });
      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: async (t) => void wrote.push(String(t)) },
        configurable: true,
      });
    });

    await page.click(".result-fpr .fingerprint-value");
    await page.waitForFunction(
      () => (document.querySelector(".fingerprint-said")?.textContent || "").length > 0,
      undefined,
      { timeout: 5000 }
    );

    const copied = await page.evaluate(() => window.__copied);
    expect(copied).toHaveLength(1);
    expect(copied[0].replace(/\s+/g, "")).toBe(alice.fingerprint);
    // Grouped, which is the one spelling `findFingerprints` is built to recover
    // — so this pastes back into the session invite box and names the same key.
    expect(copied[0]).not.toBe(alice.fingerprint);

    // And it said what it copied, on screen, counting the characters rather
    // than implying it got all of them.
    expect(await page.textContent(".fingerprint-said")).toMatch(
      /Copied the whole fingerprint — all 40 characters/
    );
  });

  it("opens the fingerprint's actions without the policy refusing the menu", async () => {
    await search("alice@corp.test");
    await page.click(".result-fpr .fingerprint-actions");
    await page.waitForSelector(".fingerprint-menu", { timeout: 5000 });

    const menu = await page.$eval(".fingerprint-menu", (el) => ({
      text: el.textContent || "",
      href: el.querySelector("a")?.getAttribute("href") || "",
      // The trust mark has never been set in this browser, so exactly one row
      // refuses — and it names the state the reader is in rather than going
      // grey. `aria-disabled`, so it is still in the arrow-key walk.
      refusing: [...el.querySelectorAll('[aria-disabled="true"]')].map(
        (r) => r.textContent || ""
      ),
    }));
    expect(menu.text).toContain("Copy the whole fingerprint");
    expect(menu.href).toBe(`/key?fpr=${alice.fingerprint}`);
    expect(menu.refusing.join(" ")).toMatch(/no trust mark on this key/);
    // A room is not on offer here: the search page has no session, so the row
    // is absent rather than refused.
    expect(menu.text).not.toContain("Add to the room");

    // The portal is where a CSP failure would land, and it would land silently.
    expect(await fixture.peers[0].cspViolations()).toEqual([]);
    await page.keyboard.press("Escape");
  });

  it("did all of that inside its own Content-Security-Policy", async () => {
    // The page writes the cautions and the help snippets with innerHTML, which
    // is exactly the shape `script-src 'self'` exists to keep honest.
    await search("Example");
    expect(await fixture.peers[0].cspViolations()).toEqual([]);

    const noise = fixture.peers[0].pageErrors();
    // An uncaught exception is a defect however the page looks afterwards.
    expect(noise.filter((e) => e.startsWith("pageerror:"))).toEqual([]);
    // The console is not empty, and the reason is named rather than filtered:
    // `ProfileMenu` asks `/api/v1/me` on every load and nobody is signed in
    // here, so each navigation logs one 401. Asserting the shape means a
    // seventh kind of error cannot hide behind the six expected ones.
    expect(noise.filter((e) => !/401 \(Unauthorized\)/.test(e))).toEqual([]);
  });

  it("left the server with nothing to complain about", () => {
    expect(basilisk.log()).not.toMatch(/Traceback \(most recent call last\)/);
  });
});
