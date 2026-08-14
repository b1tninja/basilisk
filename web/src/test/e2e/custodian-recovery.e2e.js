/**
 * A custodian, a mnemonic on paper, and a browser that has never seen the deal.
 *
 * ## The situation this drives
 *
 * `three-party-ceremony.e2e.js` and `dealer-absent-recovery.e2e.js` both recover
 * on machines that took part: the notebook is in memory, the shares are in
 * slots, and the recipe that recombines them was written by somebody else's
 * press. That is the easy half. The other half is the one the cards and the
 * playbook are printed for — a person opening the toolkit cold, months later,
 * holding words on paper and nothing else. No vault, no notebook, no session, no
 * slots, and no copy of the ceremony that dealt them.
 *
 * Two browser contexts, and only two things cross between them: **the mnemonics
 * and the expected digest, read off one screen and typed into the other.** That
 * is not a shortcut around the no-shared-variables rule the session suites keep;
 * it is the scenario. A share reaches a custodian because a person carried it,
 * and this file carries it the same way — through the rendered text of a tile,
 * into a textarea, one paste at a time.
 *
 * ## Why the shares are minted here rather than borrowed
 *
 * The split cell below is `roomCeremony`'s own first cell, character for
 * character in what it does: `random 32 | tee - digest … | sss.split
 * threshold=2 shares=3 | blip39 | out $set`. So the mnemonics a custodian is
 * handed here are the same objects a room ceremony deals — same `sss.split`,
 * same BLIP39 encoding, same set id, same absence of commitments. Borrowing them
 * out of the three-party suite would couple two files and prove less: what
 * matters is that these are shares of a 2-of-3, not which ceremony made them.
 *
 * ## The four refusals, and why they are the point
 *
 * A plain Shamir recombination of an insufficient or corrupted set does not
 * error — it returns *a different secret*. `room-ceremony.js` says so where it
 * writes the digest branch, and `ceremony.js` says it again where `vss.verify`
 * goes in front of `vss.combine`. So silence is the dangerous outcome here and
 * the assertions that matter most are the ones about what the refusals say:
 *
 * 1. one share of a 2-of-3 — does it name *how many it has and how many it
 *    needs*, or only that it could not?
 * 2. a share with one word changed — is the checksum caught, and does the
 *    message say which of the pasted rows is the bad one?
 * 3. a share from a different split — is the set id caught, and does the message
 *    say which share is the odd one out?
 * 4. two good shares — does the secret come back, and does it match a digest
 *    computed on a machine this one has never spoken to?
 *
 * Each is driven through the shipped Inputs tray, by filling the same textareas
 * a person fills, and read out of the cell's own error box.
 *
 * ## What it found
 *
 * Numbered in the steps that hold them, and pinned on assertions so a fix has to
 * come back here:
 *
 * - **2a** — a custodian holding a mnemonic and an empty notebook has nowhere to
 *   put it. The shares tray appears only once a recipe that reads `shares` has
 *   been typed, and nothing on an empty notebook names that recipe.
 * - **2b** — the cold "Check a share…" panel *can* say which share this is, how
 *   many recombine and which set it belongs to — the exact facts
 *   `three-party-ceremony.e2e.js` finding 5c says a holder cannot learn — and it
 *   then sends the reader after a commitments document that a `sss.split`
 *   ceremony never produces and never can.
 * - **3a** — the too-few-shares refusal names the true count, and then attaches a
 *   remedy about OpenPGP ciphertext and a GPG panel to a reader who has neither.
 * - **4a** — a corrupted share is caught by the checksum and the message does not
 *   say which of the pasted rows failed.
 * - **4b** — a share from another split is caught by the set id and the message
 *   does not say which share is the stranger, or what either set is called.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers } from "../helpers/browser-peers.js";
import { readNotebookSource } from "../helpers/toolkit-ui.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the custodian suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[custodian-recovery.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * The ceremony's own dealing cell, and the ceremony's own gather.
 *
 * Written out rather than imported from `room-ceremony.js` because the point of
 * the second one is that a custodian has to *retype* it: importing the string
 * this file is complaining nobody can find would be asserting against the very
 * copy a person does not have. The split is spelled here for the same reason the
 * generator spells it — one place, so the two numbers cannot drift.
 */
const SPLIT = [
  "random 32 | tee",
  "  - digest | encode hex | out $expected",
  "| sss.split threshold=2 shares=3 | blip39 | out $set",
].join("\n");

/**
 * What a custodian must arrive at with no notebook in front of them.
 *
 * `shares` collects from the Inputs tray when the recipe names nothing else,
 * which is the only road in for somebody holding paper. The `tee` is the awkward
 * part and it is not decoration: without a digest branch there is nothing to
 * compare against the ceremony's `$expected`, and comparing is the only way to
 * know a recombination produced the right bytes rather than merely some bytes.
 */
const RECOVER = [
  "shares | blip39 -d | sss.combine | tee",
  "  - digest | encode hex | out $recovered",
  "| encode hex | out $secret",
].join("\n");

/** One notebook cell, by index — the shell renders exactly one `<article>` each. */
const cell = (page, i) => page.locator("article").nth(i);

/** The session tray, as a scope. */
const tray = (page) => page.locator('[aria-label="Session tray"]').locator("xpath=..");

/** Open one of the tray's tabs and wait for it to be the selected one. */
async function trayTab(page, name) {
  const tab = tray(page).getByRole("tab", { name, exact: true });
  await tab.click();
  await expect
    .poll(async () => await tab.getAttribute("aria-selected"), { timeout: 10000 })
    .toBe("true");
}

/** Whether the run bar is between runs — the only "did it finish" the UI has. */
async function runSettled(page) {
  await expect
    .poll(async () => await page.locator("[data-run-state]").getAttribute("data-run-state"), {
      timeout: 120000,
      intervals: [250],
    })
    .toMatch(/^(idle|blocked)$/);
}

/** What the cell's own status dot says. */
const cellStatus = (page, i) =>
  cell(page, i).locator("[data-cell-status]").getAttribute("data-cell-status");

/** Whatever a cell is currently complaining about, compile-time or run-time. */
async function cellErrors(page, i) {
  const box = cell(page, i).locator("[data-cell-type-errors]");
  return (await box.count()) ? (await box.innerText()).replace(/\s+/g, " ").trim() : "";
}

/**
 * Type a pipeline into a cell, the way the Source view takes one.
 *
 * **Applies on blur**, so the `blur()` is the act and not a tidy-up — the same
 * correction `notebook-cells.e2e.js` and `placed-journey.e2e.js` both carry, for
 * the same reason: without it the text never reaches `chains` and every
 * assertion afterwards is about a notebook the shell does not have.
 */
async function writeCell(page, i, text) {
  const art = cell(page, i);
  await art.locator("button").filter({ hasText: /^Source$/ }).click();
  const box = art.locator("textarea");
  await box.waitFor({ state: "visible", timeout: 10000 });
  await box.fill(text);
  await box.blur();
}

/**
 * Uncover one output tile and read what it says.
 *
 * The reveal is part of what is tested: a value delivered into a tile nobody can
 * open is a value nobody can use. The list re-hides after fifteen seconds, so the
 * read follows the press immediately.
 */
async function reveal(page, i, label) {
  const tile = cell(page, i).locator("[data-artifact-kind]").filter({ hasText: label }).first();
  await tile.waitFor({ state: "visible", timeout: 20000 });
  const button = tile.getByRole("button", { name: "Reveal" });
  if (await button.count()) await button.click();
  const body = tile.locator(".artifact-body");
  await body.waitFor({ state: "visible", timeout: 10000 });
  return (await body.innerText()).trim();
}

/**
 * Put these mnemonics in the Inputs tray's share rows, and nothing else.
 *
 * Rows are added and cleared through the panel's own controls, because the tray
 * is half of what is under test: a custodian who cannot find the second box
 * cannot recover anything, and a helper that wrote state past the UI would pass
 * over that.
 */
async function pasteShares(page, mnemonics) {
  await trayTab(page, "Inputs");
  const panel = tray(page);
  const add = panel.getByRole("button", { name: "+ Add share" });
  for (;;) {
    const rows = panel.locator("textarea");
    const have = await rows.count();
    if (have >= mnemonics.length) break;
    await add.click();
    await expect.poll(async () => await rows.count(), { timeout: 5000 }).toBe(have + 1);
  }
  const rows = panel.locator("textarea");
  const have = await rows.count();
  for (let i = 0; i < have; i += 1) {
    await rows.nth(i).fill(mnemonics[i] ?? "");
  }
}

describe.runIf(availability.ok)("recovering on a machine that never saw the deal", () => {
  /** @type {Awaited<ReturnType<typeof openPeers>>} */ let fx;
  /** The machine the ceremony ran on. Never spoken to after step 1. */
  /** @type {import("playwright").Page} */ let ceremony;
  /** The custodian's machine: fresh context, empty vault, empty notebook. */
  /** @type {import("playwright").Page} */ let custodian;
  /** The three mnemonics, as a person reads them off the cards. */
  /** @type {string[]} */ let cards = [];
  /** A share of an unrelated 2-of-3, for the wrong-set case. */
  let strangerCard = "";
  /** SHA-256 of the master, off the ceremony's screen. Never the master. */
  let expectedDigest = "";

  beforeAll(async () => {
    // Two contexts, no hub and no room: nothing here crosses a machine boundary
    // over a wire, so making the pair pay for a signalling fixture would be
    // buying a transport this scenario deliberately does not have.
    fx = await openPeers({ count: 2, path: "/toolkit" });
    ceremony = fx.peers[0].page;
    custodian = fx.peers[1].page;
  }, 180_000);

  afterAll(async () => {
    await fx?.close();
  });

  /* ── 1. the cards, printed ───────────────────────────────────────────────── */

  it("deals three mnemonics and a digest of a secret that reaches no slot", async () => {
    await writeCell(ceremony, 0, SPLIT);
    await ceremony.getByRole("button", { name: "Run all" }).click();
    await runSettled(ceremony);
    expect(await cellStatus(ceremony, 0), await cellErrors(ceremony, 0)).toBe("ok");

    expectedDigest = await reveal(ceremony, 0, "expected");
    expect(expectedDigest, "the split wrote no digest of the master").toMatch(/^[0-9a-f]{64}$/);

    // Three tiles, one per share, labelled by the engine as `set · share N`.
    // Read in order and off the screen, which is the whole of what a person can
    // carry away from this machine.
    for (let n = 1; n <= 3; n += 1) {
      const words = await reveal(ceremony, 0, `set · share ${n}`);
      expect(words.split(/\s+/).length, `share ${n} arrived as: ${words}`).toBeGreaterThan(8);
      cards.push(words);
    }
    expect(new Set(cards).size, "two of the three cards are the same words").toBe(3);

    // A second, unrelated 2-of-3, for step 5. Minted from a second press on this
    // same machine so it is a real share of a real split rather than a mutated
    // string — the set id it carries has to have been assigned by `blip39`, not
    // by this file.
    await ceremony.getByRole("button", { name: "Cell", exact: true }).click();
    await writeCell(
      ceremony,
      1,
      "random 32 | sss.split threshold=2 shares=3 | blip39 | out $other"
    );
    await cell(ceremony, 1).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(ceremony);
    expect(await cellStatus(ceremony, 1), await cellErrors(ceremony, 1)).toBe("ok");
    strangerCard = await reveal(ceremony, 1, "other · share 2");
    expect(strangerCard).not.toBe(cards[1]);
  }, 180_000);

  /* ── 2. the custodian opens the toolkit cold ─────────────────────────────── */

  it("gives a custodian holding a mnemonic nowhere to put it", async () => {
    // Nothing has ever run here. This is the state the cards are printed for.
    expect(await readNotebookSource(custodian)).toBe("");
    expect(await custodian.locator("article").count()).toBe(1);

    // **FINDING (2a) — the shares tray does not exist until a recipe asks for
    // it, and the sentence in its place names a panel rather than a pipeline.**
    // `notebookNeeds` is derived from the recipe, so an empty notebook needs
    // nothing and the share rows are not drawn. What is drawn is honest and is
    // as far as it goes helpful — it says a step that reads *shares* would open
    // one — but the gap it leaves is the whole of what this reader is missing:
    // which step, in what order, with what after it. The room ceremony teaches
    // `shares with=$share-1`, which names a slot this browser has never had;
    // `shareCheckRecipe()` teaches `vss.verify`, which belongs to the other
    // ceremony and cannot recombine anything. So the affordance is downstream of
    // the knowledge it exists to supply, and the two documents that would close
    // the gap — the notebook and the printed playbook — are the two things a
    // custodian arriving cold does not have.
    await trayTab(custodian, "Inputs");
    const inputs = (await tray(custodian).innerText()).replace(/\s+/g, " ");
    expect(
      inputs,
      `the Inputs tray on an empty notebook: ${inputs.slice(0, 300)}`
    ).not.toContain("BLIP39 share mnemonics");
    expect(await tray(custodian).locator("textarea").count()).toBe(0);
    // The sentence that is there instead, pinned in full: it names the *kind* of
    // input and stops. A fix that turns "shares" into something a person can
    // press has to come back and change this line.
    expect(inputs, `the Inputs tray on an empty notebook: ${inputs}`).toContain(
      "No cell needs runtime input yet"
    );
    expect(inputs).toContain("add a step that reads text, ciphertext, shares");
    expect(inputs, "the empty tray started naming the op that reads them").not.toContain(
      "sss.combine"
    );
  });

  /* ── 3. what the cold check surface can and cannot tell them ─────────────── */

  it("names the share and then asks for a document this split never had", async () => {
    // "Check a share…" is reachable with no notebook state, from the ⋯ menu
    // beside Templates. It is the one surface in the product written for exactly
    // this reader, and step 2's finding is that nothing points a custodian at it.
    // The ⋯ trigger carries a lucide glyph and no text, so it has no accessible
    // name to ask for. Selected by the class the two toolbar menus share, minus
    // the one Templates adds — which is itself worth noticing: the only route to
    // the custodian's own surface is a button a screen reader announces as
    // nothing.
    await custodian.locator("button.toolbar-menu-trigger:not(.toolkit-presets-summary)").click();
    await custodian.getByRole("menuitem", { name: "Check a share…" }).click();
    const panel = custodian.locator(".share-check");
    await panel.waitFor({ state: "visible", timeout: 20000 });
    expect(await panel.getAttribute("data-status")).toBe("empty");

    // **Everything is read first and asserted after the sheet is shut.** This
    // panel is a modal over the notebook, so a failed assertion inside it leaves
    // the sheet open and every later step in this file dies clicking through it
    // — five cascading Playwright timeouts hiding one real failure. Reading, then
    // closing, then asserting costs nothing and keeps the first red line the
    // informative one.
    /** @type {Record<string, string>} */
    const read = {};
    try {
      await panel.locator("textarea").first().fill(cards[1]);
      await expect
        .poll(async () => await panel.getAttribute("data-status"), { timeout: 10000 })
        .toBe("share-only");
      read.facts = (await panel.locator(".share-check-facts").innerText()).replace(/\s+/g, " ");
      read.detail = (await panel.locator(".share-check-detail").innerText()).replace(/\s+/g, " ");
      read.labels = (await panel.innerText()).replace(/\s+/g, " ");
      // Opened rather than read through the closed `<details>`, because
      // `innerText` skips hidden content and an assertion against a collapsed
      // panel would pass for the wrong reason forever — the exact trap
      // `helpers/toolkit-ui.js` carries a correction for.
      await panel.locator("summary", { hasText: "Do this by hand instead" }).click();
      read.byHand = (await panel.locator(".share-check-recipe pre").innerText()).replace(
        /\s+/g,
        " "
      );
    } finally {
      await custodian.keyboard.press("Escape");
      await panel.waitFor({ state: "hidden", timeout: 10000 });
    }

    // **What it can say, and it is exactly what `three-party-ceremony.e2e.js`
    // finding 5c says a holder cannot learn.** Share 2 of 3, any 2 recombine,
    // and a set id — off one mnemonic, offline, with no other share and no
    // notebook. The facts were in the BLIP39 header the whole time; what was
    // missing on the holder's screen was anything that read them.
    const { facts } = read;
    expect(facts, `the panel's facts: ${facts}`).toMatch(/share 2 of 3/);
    expect(facts, `the panel's facts: ${facts}`).toMatch(/any 2 recombine/);
    expect(facts, `the panel's facts: ${facts}`).toMatch(/set [0-9A-F]{4}/);

    // **FINDING (2b) — and then it sends them after a document that cannot
    // exist.** The verdict is honest about what it has *not* checked, which is
    // right and is the whole reason `share-only` is its own status. The remedy is
    // not: the only route out of it is "paste the published commitments", and a
    // share dealt by the room ceremony came from `sss.split`, which produces no
    // commitments and never will. The panel's own `mismatch` copy knows this —
    // it lists "the card came from `sss.split`, which produces shares that carry
    // no commitments and can never match any" as one of three explanations for a
    // failed check — but a custodian holding an SSS card can only reach that
    // sentence by pasting somebody else's commitments and being told their card
    // might be broken.
    //
    // The field label below states it as settled fact: the ceremony "was supposed
    // to hand these out openly". For every share this room ceremony deals, it was
    // not, and there is nothing the reader can do about it from here.
    expect(read.detail, `the share-only verdict: ${read.detail}`).toContain(
      "published commitments"
    );
    expect(read.labels, "the commitments field stopped promising the ceremony published them")
      .toContain("was supposed to hand these out openly");
    // And the one recipe it prints verifies rather than recovers, so even the
    // custodian who opens the fold and copies what they are shown is one op short
    // of getting their secret back.
    expect(read.byHand, `the recipe the panel prints: ${read.byHand}`).toContain("vss.verify");
    expect(read.byHand, "the check panel grew a recovery recipe").not.toContain("sss.combine");
  }, 120_000);

  /* ── 4. one share of a 2-of-3 ────────────────────────────────────────────── */

  it("refuses one share of two and says how many of each", async () => {
    // The recipe a custodian has to arrive at unaided. Once it is typed the tray
    // appears — which is the shape of finding 2a: the affordance is downstream of
    // the knowledge it exists to supply.
    await writeCell(custodian, 0, RECOVER);
    await trayTab(custodian, "Inputs");
    await expect
      .poll(async () => (await tray(custodian).innerText()).includes("BLIP39 share mnemonics"), {
        timeout: 10000,
      })
      .toBe(true);

    await pasteShares(custodian, [cards[1]]);
    await custodian.getByRole("button", { name: "Run all" }).click();
    await runSettled(custodian);

    expect(await cellStatus(custodian, 0), "one share of a 2-of-3 recombined into something").toBe(
      "error"
    );
    const said = await cellErrors(custodian, 0);

    // **The assertion that matters most in this file.** Shamir does not error on
    // an insufficient set — it interpolates whatever it was given and returns a
    // different secret — so the dangerous outcome here is `ok`, and the refusal
    // has to name both numbers. It does: the threshold is read out of the share's
    // own BLIP39 header, so "2" is this split's real threshold and not a default.
    expect(said, `the refusal: ${said}`).toContain("Need at least 2 shares, got 1");
    // And it is attributed to the step that made the decision, which is what tells
    // a reader whether to look at their paste or at their pipeline.
    expect(said, `the refusal: ${said}`).toContain("sss.combine");

    // **FINDING (3a) — and then it answers a question this reader did not ask.**
    // `engine.js` appends a sentence to every `Need at least …` about shares
    // "decrypted outside the browser (Kleopatra/gpg/YubiKey)" and about keeping
    // "remaining OpenPGP ciphertext in the GPG panel". This custodian has no
    // ciphertext, no GPG panel open, and no share that has been anywhere near a
    // smartcard: they typed words off a card. Half the remedy is performable —
    // paste more mnemonics in the share rows — and it is buried inside a
    // conditional about a workflow they are not in, which is exactly the shape
    // `47e7ffa` rules out. The sentence a person needs here is "add the second
    // card", and it is not in the box.
    expect(said, `the refusal: ${said}`).toContain("Kleopatra");
    expect(said, `the refusal: ${said}`).toContain("OpenPGP ciphertext");
    // Nothing was written: a partial recovery must not leave a slot behind that a
    // later cell could read as the secret.
    await trayTab(custodian, "Slots");
    const slots = (await tray(custodian).innerText()).replace(/\s+/g, " ");
    expect(slots, `the custodian's slots: ${slots}`).not.toContain("$secret");
    expect(slots, `the custodian's slots: ${slots}`).not.toContain("$recovered");
  }, 180_000);

  /* ── 5. a word changed, and a share from somewhere else ──────────────────── */

  it("catches a corrupted word by checksum, without saying which row it was", async () => {
    // One word swapped for another word from the same wordlist, so the mnemonic
    // is still made of legal words and only the RS1024 checksum can tell. A
    // nonsense word would be caught by the wordlist lookup instead and would be
    // testing the easier of the two.
    const words = cards[2].split(/\s+/);
    const swapFrom = words[3];
    const swapTo = cards[1].split(/\s+/).find((w) => w !== swapFrom) || cards[1].split(/\s+/)[0];
    const corrupted = [...words.slice(0, 3), swapTo, ...words.slice(4)].join(" ");
    expect(corrupted).not.toBe(cards[2]);
    expect(corrupted.split(/\s+/).length).toBe(words.length);

    await pasteShares(custodian, [cards[1], corrupted]);
    await custodian.getByRole("button", { name: "Run all" }).click();
    await runSettled(custodian);

    expect(await cellStatus(custodian, 0), "a corrupted share recombined into something").toBe(
      "error"
    );
    const said = await cellErrors(custodian, 0);

    // Caught, and caught by the right thing: BLIP39 carries a checksum precisely
    // so a transcription slip is refused here rather than becoming a silently
    // different secret three steps later.
    expect(said, `the refusal: ${said}`).toContain("Invalid share checksum");
    expect(said, `the refusal: ${said}`).toContain("blip39");

    // **FINDING (4a) — it does not say which row.** `decodeShareSet` maps
    // `decodeMnemonic` over the set and rethrows the first failure, and the
    // failure carries no index, so a custodian who has typed two cards in is told
    // one of them is wrong and left to work out which. The panel that *can* tell
    // them — "Check a share…", which reads one mnemonic at a time — is behind a
    // menu nobody has pointed them at, and the error does not point at it either.
    //
    // Pinned in both directions: the message must not name a row, and must not
    // name the good card, because either would mean this has been fixed.
    expect(said, `the refusal: ${said}`).not.toMatch(/share (1|2) of the .* is/i);
    expect(said, `the refusal: ${said}`).not.toMatch(/\brow\b/i);
    expect(said, `the refusal: ${said}`).not.toMatch(/second|first/i);
  }, 180_000);

  it("catches a share from another split by set id, without naming either set", async () => {
    await pasteShares(custodian, [cards[1], strangerCard]);
    await custodian.getByRole("button", { name: "Run all" }).click();
    await runSettled(custodian);

    expect(
      await cellStatus(custodian, 0),
      "a share from a different split recombined into something"
    ).toBe("error");
    const said = await cellErrors(custodian, 0);

    // This is the case that would otherwise be silent and wrong. Both mnemonics
    // are internally valid — each passes its own checksum — so nothing before
    // `decodeShareSet` can object, and `combineSecret` would happily interpolate
    // two points from two different polynomials and hand back 32 bytes that are
    // not anybody's secret. The set id in the header is the only thing standing
    // between a custodian and that, and it holds.
    expect(said, `the refusal: ${said}`).toContain("Share set ID mismatch");

    // **FINDING (4b) — and it says nothing else.** Four words, no set ids, no
    // indication which of the two pasted shares is the stranger, and no mention
    // of the fact a person can act on: every one of these mnemonics knows its own
    // set id, "Check a share…" prints it as `set XXXX`, and comparing two of those
    // is the whole diagnosis. The refusal has all of it in hand at the moment it
    // throws — `decodeShareSet` is holding both decoded headers — and passes none
    // of it on.
    expect(said, `the refusal: ${said}`).not.toMatch(/set [0-9A-F]{4}/);
    expect(said, `the refusal: ${said}`).not.toMatch(/\bcheck a share\b/i);
  }, 180_000);

  /* ── 6. two good cards ───────────────────────────────────────────────────── */

  it("rebuilds the secret from two cards and matches a digest it never received", async () => {
    await pasteShares(custodian, [cards[1], cards[2]]);
    await custodian.getByRole("button", { name: "Run all" }).click();
    await runSettled(custodian);

    expect(await cellStatus(custodian, 0), await cellErrors(custodian, 0)).toBe("ok");
    expect(await cellErrors(custodian, 0)).toBe("");

    // **The comparison the whole file is for.** A SHA-256 computed inside a
    // browser context that this one shares no storage, no realm and no session
    // with, of thirty-two bytes that were never written to a slot on either
    // machine — equal to a SHA-256 computed here out of two mnemonics that
    // crossed as words on a screen. Shares 2 and 3, so the dealer's own share 1
    // is not involved in it at all.
    const recovered = await reveal(custodian, 0, "recovered");
    expect(recovered, "the custodian recombined into something else").toBe(expectedDigest);

    const secret = await reveal(custodian, 0, "secret");
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(secret).not.toBe(recovered);

    // And the machine that dealt the cards never learned that this happened —
    // there is no session, no room and no wire between the two contexts. Stated
    // as an assertion rather than left implicit because "the custodian recovered
    // it" and "the custodian recovered it *alone*" are two claims.
    expect(await readNotebookSource(ceremony)).toContain("sss.split");
    expect(await readNotebookSource(custodian)).not.toContain("sss.split");
  }, 180_000);

  /* ── what the journey cost ───────────────────────────────────────────────── */

  it("drove both browsers without tripping the production CSP", async () => {
    for (const peer of fx.peers) expect(await peer.cspViolations()).toEqual([]);
  });
});
