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
 * The split cell below mints with the same codec the room ceremony deals with:
 * `sss.split threshold=2 shares=3 | blip39`. So the mnemonics a custodian is
 * handed here are the same objects a room ceremony's `scatter` delivers — same
 * split, same BLIP39 encoding, same set id, same absence of commitments — minus
 * the live room this fixture deliberately does not have. Borrowing them out of
 * the three-party suite would couple two files and prove less: what matters is
 * that these are shares of a 2-of-3, not which ceremony made them.
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
 * - **2a** — *fixed, and turned over in step 2.* A custodian holding a
 *   mnemonic and an empty notebook had nowhere to put it: the shares tray
 *   appears only once a recipe that reads `shares` exists, and nothing on an
 *   empty notebook named that recipe. The recovery section on the session
 *   sheet now offers "Recover from cards instead" — one press writes the
 *   one-cell paste recovery (`room-recovery.js`'s `custodianRecovery`), and
 *   the share rows open because the notebook now asks for them. Step 2 first
 *   pins the honest *before* (an empty notebook still needs nothing), then
 *   drives the road; nothing in this file types a pipeline any more.
 * - **2b** — the cold "Check a share…" panel *can* say which share this is, how
 *   many recombine and which set it belongs to — the exact facts
 *   `three-party-ceremony.e2e.js` finding 5c says a holder cannot learn — and it
 *   then sends the reader after a commitments document that a `sss.split`
 *   ceremony never produces and never can.
 * - **3a** — *fixed.* The too-few-shares refusal named the true count and then
 *   attached a remedy about OpenPGP ciphertext and a GPG panel to a reader who
 *   had neither. The appendix is now conditional on armor actually sitting in
 *   the GPG panel, and a custodian who typed words off a card is told to paste
 *   the missing card. Step 4 asserts both directions.
 * - **4a** — *fixed.* A corrupted share is caught by the checksum, and the
 *   message now names the row it was pasted into and says the others decoded.
 * - **4b** — *fixed.* A share from another split is caught by the set id, and
 *   the message now names every row with the set it came from — in the same
 *   four hex digits the check panel prints, which is what step 5 compares.
 *
 * What remains pinned unfixed is 2b: the one surface that reads a lone share
 * still asks for commitments an `sss.split` ceremony cannot produce.
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
 * A minting cell for the cards this file carries — the solo shape, typed on
 * the ceremony machine only. It used to mirror `roomCeremony`'s first cell
 * character for character; the room's deal cell is a `scatter` now, which
 * needs a live room this fixture deliberately does not have, so this is the
 * *solo* minting the "Split a secret" road produces: same `sss.split`, same
 * BLIP39 encoding, same set id, same absence of commitments. What matters is
 * that the mnemonics are shares of a real 2-of-3, not which ceremony made
 * them — the custodian's machine never sees this cell at all.
 */
const SPLIT = [
  "random 32 | tee",
  "  - digest | encode hex | out $expected",
  "| sss.split threshold=2 shares=3 | blip39 | out $set",
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
  /**
   * The set id the cold check panel printed for `cards[1]`, as `XXXX`.
   *
   * Carried from step 3 to step 5 so the two surfaces are compared against each
   * other rather than each against a regex: the panel says `set 465E` about one
   * card, and the refusal has to name that same string for the row that card
   * was pasted into. Two spellings of fifteen bits would make a custodian's
   * whole diagnosis — hold this card up against that message — silently
   * meaningless, and only a cross-surface assertion can catch it.
   */
  let panelSetId = "";
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

  it("hands a custodian holding a mnemonic somewhere to put it, in one press", async () => {
    // Nothing has ever run here. This is the state the cards are printed for.
    expect(await readNotebookSource(custodian)).toBe("");
    expect(await custodian.locator("article").count()).toBe(1);

    // The honest *before*, kept: the shares tray is derived from the recipe,
    // so an empty notebook needs nothing and the share rows are not drawn.
    // This is still right — an affordance for every input kind on an empty
    // notebook would be a form with no question — and it is exactly why the
    // road below has to exist somewhere a cold reader can find it.
    await trayTab(custodian, "Inputs");
    const inputs = (await tray(custodian).innerText()).replace(/\s+/g, " ");
    expect(
      inputs,
      `the Inputs tray on an empty notebook: ${inputs.slice(0, 300)}`
    ).not.toContain("BLIP39 share mnemonics");
    expect(await tray(custodian).locator("textarea").count()).toBe(0);
    expect(inputs, `the Inputs tray on an empty notebook: ${inputs}`).toContain(
      "No cell needs runtime input yet"
    );

    // **FINDING (2a), turned over — the road exists and this drives it.** The
    // session sheet's recovery section offers the paste path to exactly this
    // reader: no vault, no session, no notebook, no picker to fill in. One
    // press writes `room-recovery.js`'s one-cell paste recovery, and the share
    // rows open because the notebook now reads `shares`. The affordance is no
    // longer downstream of the knowledge it exists to supply — nothing in this
    // file types a pipeline into the custodian's browser any more.
    await trayTab(custodian, "Connections");
    await tray(custodian).getByRole("button", { name: "Start session" }).click();
    const sheet = custodian.locator("[data-session-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const recovery = custodian.locator("[data-room-recovery]");
    await recovery.waitFor({ state: "visible", timeout: 20000 });
    // The contributor picker refuses honestly — there is no deal here and no
    // key to recover as — while the cards road stays open beside it, because
    // the reader it serves is precisely the one the picker cannot describe.
    expect(await recovery.locator("[data-room-recovery-issues]").count()).toBeGreaterThan(0);
    await recovery.getByRole("button", { name: "Recover from cards instead" }).click();
    await expect
      .poll(async () => await recovery.locator("[data-room-recovery-note='1']").innerText(), {
        timeout: 20000,
      })
      .toContain("Inputs tray");
    await custodian.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    // The notebook is the paste recovery now — recombine, digest, and the two
    // outs — and the tray it needs opened itself.
    const source = await readNotebookSource(custodian);
    expect(source, `the written recovery: ${source}`).toContain("sss.combine");
    expect(source).toContain("blip39");
    expect(source).toContain("out $recovered");
    expect(source).toContain("out $secret");
    expect(source, "the paste recovery grew a header").not.toContain("@");
    await trayTab(custodian, "Inputs");
    await expect
      .poll(async () => (await tray(custodian).innerText()).includes("BLIP39 share mnemonics"), {
        timeout: 10000,
      })
      .toBe(true);
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
    panelSetId = /set ([0-9A-F]{4})/.exec(facts)?.[1] || "";

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

  it("refuses one share of two, says how many of each, and asks for a card", async () => {
    // The notebook is the one the recovery section wrote in step 2 — nothing
    // typed, and the tray is already open. What is under test from here down
    // is the refusals, which are the point: Shamir does not error on a bad
    // set, it returns a different secret.
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

    // **FINDING (3a), fixed — and pinned in both directions.**
    //
    // `engine.js` used to append the same sentence to *every* `Need at least …`
    // — about shares "decrypted outside the browser (Kleopatra/gpg/YubiKey)"
    // and about keeping "remaining OpenPGP ciphertext in the GPG panel". This
    // custodian has no ciphertext, no GPG panel open and no share that has been
    // near a smartcard: they typed words off a card. So half that remedy named
    // an act nobody could perform, and the half they could was buried inside a
    // conditional about a workflow they were not in — the shape `47e7ffa` rules
    // out. `missingSharesRemedy` now branches on states the run can see are
    // true, and the state here is "share rows are filled in, the GPG panel is
    // empty".
    expect(said, `the refusal: ${said}`).toContain(
      "Paste one more card's mnemonic into the share rows"
    );
    // And why any card will do, which is the fact that turns "get another one"
    // into something a person can act on without ringing the dealer to ask
    // which.
    expect(said, `the refusal: ${said}`).toContain(
      "Any 2 shares of this split rebuild it"
    );
    // The direction that regresses silently: a reader with nothing in the GPG
    // panel must not be sent to it. If this line ever goes red the appendix has
    // become unconditional again.
    expect(
      said,
      `a reader with no ciphertext was sent to the GPG panel — ${said}`
    ).not.toMatch(/Kleopatra|GPG panel|OpenPGP/i);
    // Nothing was written: a partial recovery must not leave a slot behind that a
    // later cell could read as the secret.
    await trayTab(custodian, "Slots");
    const slots = (await tray(custodian).innerText()).replace(/\s+/g, " ");
    expect(slots, `the custodian's slots: ${slots}`).not.toContain("$secret");
    expect(slots, `the custodian's slots: ${slots}`).not.toContain("$recovered");
  }, 180_000);

  /* ── 5. a word changed, and a share from somewhere else ──────────────────── */

  it("catches a corrupted word by checksum and names the row it went into", async () => {
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

    // **FINDING (4a), fixed — it says which row.** `decodeShareSet` used to map
    // `decodeMnemonic` over the set and rethrow the first failure, which
    // carries no index, so a custodian who had typed two cards in was told one
    // of them was wrong and left to work out which. It now decodes every row
    // before it throws — the only way the row number is knowable, since the
    // rows after the first failure would otherwise never be read — and names
    // the ones that failed.
    //
    // The corrupted card went into row 2, and it is asserted as row 2 rather
    // than as "a row": the whole value of the fix is that the number is the
    // right one.
    expect(said, `the refusal: ${said}`).toMatch(
      /Row 2 of the 2 pasted shares is not readable/
    );
    // And that the other one is fine, which is what stops a custodian re-typing
    // both cards.
    expect(said, `the refusal: ${said}`).toContain("The other row decoded cleanly");

    // **What a refusal about a share must never contain: the share.** Four
    // consecutive words is well past coincidence for English prose and is a
    // sequence that only the mnemonic has. An error box is copied into chats
    // and screenshots, so a message that quoted the card to show where it went
    // wrong would be the leak.
    const firstWords = (m) => m.split(/\s+/).slice(0, 4).join(" ");
    expect(said, "the refusal quoted the good card").not.toContain(firstWords(cards[1]));
    expect(said, "the refusal quoted the corrupted card").not.toContain(
      firstWords(corrupted)
    );
  }, 180_000);

  it("catches a share from another split and names both sets, by row", async () => {
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

    // **FINDING (4b), fixed — and this is the highest-value line in the file.**
    //
    // It used to be four words and nothing else: no set ids, no indication
    // which of the two pasted shares was the stranger. `decodeShareSet` is
    // holding both decoded headers at the moment it throws, and passed none of
    // it on. It now names every row with the set it came from.
    expect(said, `the refusal: ${said}`).toMatch(/row 1 is from set [0-9A-F]{4}/);
    expect(said, `the refusal: ${said}`).toMatch(/row 2 is from set [0-9A-F]{4}/);
    // Two different sets, which is the thing being reported. A message that
    // printed one id twice would satisfy both lines above and say nothing.
    const named = [...said.matchAll(/from set ([0-9A-F]{4})/g)].map((m) => m[1]);
    expect(new Set(named).size, `the sets named: ${JSON.stringify(named)}`).toBe(2);

    // **And it is the same four hex digits the check panel printed.** Step 3
    // read `set XXXX` off "Check a share…" for this exact card; row 1 is where
    // that card was pasted. This is the assertion that keeps the codec's
    // `formatSetId` the only speller of a set id — a refusal naming the raw
    // fifteen bits would still pass every line above and leave a custodian
    // comparing `set 465E` against `set 17998`.
    expect(panelSetId, "step 3 never read a set id off the panel").toMatch(/^[0-9A-F]{4}$/);
    expect(said, `the refusal: ${said}`).toContain(`row 1 is from set ${panelSetId}`);

    // Why it is caught here rather than downstream, said to the person: two
    // internally valid mnemonics from two ceremonies do not fail to combine,
    // they combine into a different secret. Observed directly — dropping the
    // guard and interpolating share 2 of one set with share 3 of another
    // returns thirty-two bytes and no error at all.
    expect(said, `the refusal: ${said}`).toContain("returns a different secret");

    // Never the words themselves, on the refusal that is most tempting to
    // illustrate: the set ids and the row numbers are the whole diagnosis.
    const firstWords = (m) => m.split(/\s+/).slice(0, 4).join(" ");
    expect(said, "the refusal quoted the good card").not.toContain(firstWords(cards[1]));
    expect(said, "the refusal quoted the stranger").not.toContain(firstWords(strangerCard));
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
