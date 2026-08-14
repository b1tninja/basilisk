/**
 * The dealer is gone. Two holders rebuild the secret between themselves.
 *
 * ## Why this is a different scenario and not a later step of the other one
 *
 * `three-party-ceremony.e2e.js` proves a 2-of-3 recombines. It proves it on
 * machines that have just performed the deal, with the dealer sitting there,
 * and — the part that matters — it cannot say *whose two shares* were used. Its
 * own finding 6a is exactly that: `count=` is `threshold - 1`, two machines were
 * told to hand a share back, and the gather takes whichever arrived first with
 * nothing anywhere reporting which. A 2-of-3 that only ever recombines while all
 * three parties are present has not demonstrated the property it is sold for.
 *
 * This file removes the dealer. Not "the dealer stops pressing buttons" —
 * `fx.peers[0].context.close()`, the browser context destroyed, the vault with
 * it, the data channels to both holders torn down and observed as torn down on
 * the two screens that are left. Everything after that happens between two
 * browsers over the joiner↔joiner link that `three-party-ceremony.e2e.js`
 * established exists, and the share that completes the recovery is put on the
 * wire *after* the dealer's page no longer exists.
 *
 * ## What had to be changed before the case could be driven at all
 *
 * **The ceremony as generated cannot demonstrate this, and the reason is a
 * control that does not exist.** `roomCeremony` marks its cells `phase: "deal"`
 * and `phase: "recover"`, and the picker prints the two phases as separate
 * things a room does at separate times — "Dealing — run once, together" and
 * "Recovering — run when the secret is wanted back". The notebook has no way to
 * run one phase. The only run control on a cell is `runFrom(i)`, which walks to
 * the end of the document; there is no run-this-cell-only anywhere in the shell.
 *
 * On a holder that costs a press (`three-party-ceremony.e2e.js` finding 5a). On
 * the dealer it costs the property this file is about: the dealer's *recovery*
 * cell — `$set | at 1 | quorum.send to=…`, the one that hands its share back —
 * sits below the split, so the single press that deals the secret also returns
 * the dealer's share to the recoverer. By the time anybody could decide the
 * dealer should leave, the dealer's share is already in the recoverer's inbox,
 * and `quorum.recv count=1` will take it in preference to anything a holder
 * sends later, because it arrived first. A recovery run after that is a recovery
 * that used the dealer's share, and it looks identical to one that did not.
 *
 * So step 1 below **deletes the dealer's own recovery cell before the notebook
 * is shared**, using the Delete cell button a person has. That is not a
 * workaround for a test harness; it is the only sequence of presses that
 * produces a 2-of-3 whose dealer has really given up its share, and nothing on
 * the ceremony panel says so. Finding 1a holds the whole argument, on an
 * assertion that pins the generated shape, so a fix has to come back here.
 *
 * ## What is asserted, and what is inferred
 *
 * The digest comparison is the same one the sibling suite ships on: a SHA-256
 * computed on the dealer's machine, read off its screen before it was closed,
 * against a SHA-256 computed on a machine that never held the secret. What this
 * file adds is that the two shares behind the second number can only be the two
 * holders': the dealer has no cell that returns share 1 — it was deleted, on all
 * three copies, before the notebook crossed — so the only share that can reach
 * the recoverer other than its own is the bystander's, and it is sent over a
 * link the dealer was never part of, after the dealer's browser is gone.
 *
 * Nothing crosses between the contexts in a variable, which is
 * `room-ceremony.e2e.js`'s rule and the only thing that makes the comparison
 * mean anything.
 *
 * ## What it found
 *
 * The recovery itself works, once it can be reached. Everything else here is a
 * place where a person driving this would not know what to do next, written on
 * assertions that pin the *current* behaviour so a fix has to come back and
 * change a line rather than quietly improving past a green test. They are
 * numbered in the steps that hold them:
 *
 * - **1a** — the two phases are one run, and on the dealer that costs the
 *   property rather than a press: the cell that returns the dealer's share is
 *   below the split and fires with it.
 * - **1b** — the gather the ceremony writes gives the other custodian 120
 *   seconds, and says so only after they have run out.
 * - **7a** — nothing on the recovering machine says whose shares rebuilt the
 *   secret. The sender writes an Activity entry; the receiver writes none.
 * - **8a** — the destroyed browser's row reads "verified" beside "failed",
 *   because the field that retracts a verdict is cleared by a channel close and
 *   a destroyed browser never sends one.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the dealer-absent suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[dealer-absent-recovery.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/** What `roomCeremony` writes for three people: split, 2 sends, 2 receives, 2 returns, 1 gather. */
const DEALT_CELLS = 8;

/** What is left once the dealer's own return cell is deleted. */
const CELLS = DEALT_CELLS - 1;

/** The index of the dealer's return cell in the generated notebook. */
const DEALER_RETURN = 5;

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
      timeout: 180000,
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
  return (await box.count()) ? (await box.innerText()).trim() : "";
}

/**
 * Every cell's state and complaint on one machine, as one object.
 *
 * The same move `three-party-ceremony.e2e.js` makes and for the same reason: a
 * ceremony that stops halfway is diagnosed by what the *other* cells did, and a
 * failure reported one cell at a time reports only the first.
 */
async function board(page, count = CELLS) {
  /** @type {Record<number, string>} */
  const out = {};
  for (let i = 0; i < count; i += 1) {
    const err = await cellErrors(page, i);
    out[i] = `${await cellStatus(page, i)}${err ? ` — ${err}` : ""}`;
  }
  return out;
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

/** The ceremony's slots, as the Slots tab prints them, on one machine. */
async function ceremonySlots(page) {
  await trayTab(page, "Slots");
  const rows = tray(page).locator("li code");
  const out = [];
  for (const text of await rows.allInnerTexts()) {
    const m = /^@(expected|set|share-\d+|recovered|secret)$/.exec(text.trim());
    if (m) out.push(m[1]);
  }
  return out.sort();
}

/**
 * Every Connections row on one machine: who, what state the link is in, and
 * whether the row still calls them verified.
 *
 * The whole `<li>`, not the verdict badge — the badge is what
 * `three-party-ceremony.e2e.js` counts, and a count is exactly what cannot
 * describe a departure. `data-peer-state` on the dot and the verdict on the
 * badge are two separate facts about one peer and after somebody leaves they
 * stop agreeing, which is the thing worth reading.
 */
async function rosterRows(page) {
  await trayTab(page, "Connections");
  const rows = await tray(page).locator("li").filter({ has: page.locator("[data-verified]") }).all();
  /** @type {string[]} */
  const out = [];
  for (const row of rows) {
    const state = await row.locator("[data-peer-state]").getAttribute("data-peer-state");
    const verified = await row.locator("[data-verified]").getAttribute("data-verified");
    // Whitespace squeezed *out*, not collapsed to single spaces: `Fingerprint`
    // draws a key in four-character groups, so the row text of a whole
    // fingerprint does not contain the fingerprint. Matching a peer by eye and
    // matching one in a test have to be the same act, and the grouping is
    // presentation — so it is removed here rather than a truncated prefix being
    // compared, which is the one thing this product never does with a key.
    const text = (await row.innerText()).replace(/\s+/g, "");
    out.push(`${text} [state=${state} verified=${verified}]`);
  }
  return out;
}

/** Seed one browser's vault with the identity that browser is, and reload onto the shell. */
async function becomeMember(page, member, uid) {
  const stored = await page.evaluate(
    seedVaultKeyExpr({
      fingerprint: member.fpr,
      armoredPrivate: member.armoredPrivate,
      armoredPublic: member.armoredPublic,
      uid,
    })
  );
  expect(stored).toContain(member.fpr);
  await page.reload({ waitUntil: "load" });
  await page.waitForSelector(".toolkit-shell", { timeout: 30000 });
}

describe.runIf(availability.ok)("a 2-of-3 rebuilt after the dealer is gone", () => {
  /** @type {any} */ let room;
  /** @type {any} */ let fx;
  /** @type {(() => Promise<void>)|null} */ let closeMesh = null;
  /** The machine that draws the secret, deals it, and is then destroyed. */
  /** @type {import("playwright").Page} */ let dealer;
  /** The holder the generator picked to recombine — `holders[0]`. */
  /** @type {import("playwright").Page} */ let recoverer;
  /** The holder who returns their share to the one who recombines. */
  /** @type {import("playwright").Page} */ let bystander;
  /** @type {string} */ let origin = "";
  /** Whole fingerprints, in the order the generator will read them. */
  let L = { dealer: "", recoverer: "", bystander: "" };
  /** The URL the dealer's own address bar held after Start. Nothing else crosses. */
  let inviteUrl = "";
  /** The seven-cell ceremony, as the dealer's own Source view prints it. */
  let ceremonySource = "";
  /** The digest of the master, off the dealer's screen, before it was closed. */
  let expectedDigest = "";
  /**
   * What the dealer's page had to say for itself, collected before it is closed.
   *
   * A destroyed context cannot be asked, and the CSP question is about the whole
   * run rather than about whichever pages happen to survive it — so the answer is
   * taken while there is somebody to ask and asserted at the end with the others.
   */
  let dealerCsp = /** @type {{ directive: string, blocked: string }[]} */ ([]);
  /**
   * What each surviving screen drew, in order, while the dealer went away.
   *
   * Collected in step 5 and asserted in step 8 rather than at the moment it is
   * read, because the interesting question is what a person is left looking at
   * once everything has settled, and the samples in between are what make a
   * failure of that assertion diagnosable.
   * @type {Record<string, string[]>}
   */
  const departure = {};

  beforeAll(async () => {
    room = await createQuorumRoom({ count: 3 });
    const mesh = await openMesh(room, { count: 3 });
    if (!mesh.ok) {
      throw new Error(`local Web PubSub hub did not start (${mesh.kind}): ${mesh.reason}`);
    }
    closeMesh = mesh.close;
    fx = mesh.fx;
    origin = fx.origin;
    expect(room.audience).toHaveLength(3);
    expect(fx.peers).toHaveLength(3);

    // Who is who is decided by `roomCeremony` and not by this file, exactly as
    // in the sibling suite: the dealer is whoever is chosen in the key picker,
    // and the recoverer is the first member of the room who is not them.
    const [me, first, second] = room.audience;
    L = { dealer: me, recoverer: first, bystander: second };

    dealer = fx.peers[0].page;
    recoverer = fx.peers[1].page;
    bystander = fx.peers[2].page;
  }, 240_000);

  afterAll(async () => {
    if (closeMesh) await closeMesh();
    else if (fx) await fx.close();
  });

  /* ── 1. a 2-of-3 whose dealer keeps nothing to give back ─────────────────── */

  it("writes the ceremony, then deletes the cell that would return the dealer's share", async () => {
    await dealer.goto(`${origin}/toolkit`, { waitUntil: "load" });
    // The one evaluate, and the reason the sibling suites give for it: there is
    // no import UI for a key this fixture already holds, and the key has to be
    // one the room's keyserver can hand out.
    await becomeMember(dealer, room.members[0], "Dealer <dealer@ceremony.test>");

    const sheet = dealer.locator("[data-session-sheet]");
    await dealer.evaluate((h) => {
      window.location.hash = h;
    }, `#j=${room.audience.join(",")}`);
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    await dealer.getByRole("button", { name: "I am starting it" }).click();
    await dealer.locator("[data-session-key] select").selectOption(L.dealer);

    const ceremony = dealer.locator("[data-room-ceremony]");
    await ceremony.waitFor({ state: "visible", timeout: 20000 });

    // **FINDING (1a) — the ceremony names two phases and writes them as one
    // run, so the dealer gives its share back while it is dealing.**
    //
    // The panel a person presses says the two phases are separate occasions:
    // one is run once, together, and the other is run "when the secret is
    // wanted back". `roomCeremony` agrees — it stamps every cell `phase`, and
    // the cell deleted below is stamped `recover`. Nothing in the notebook can
    // honour that. The only per-cell run control is `runFrom(i)`, which runs
    // every cell from `i` to the end of the document, so the press that draws
    // the secret and deals it also runs the dealer's return cell.
    //
    // The consequence is not cosmetic. `quorum.recv count=1` in the gather takes
    // the first message in the inbox, so a recovery attempted at any later date
    // — with the dealer present, absent, or dead — silently prefers the share
    // the dealer sent during the deal. **Recovery without the dealer is not
    // reachable by pressing the buttons in the order the ceremony describes.**
    //
    // Pinned on the panel's own phase lists — `data-room-ceremony-phase`, the
    // attribute the widget puts on each `<ol>` — rather than on the sentence
    // above them, because the numbers in those lists are the claim: cell 5 is
    // printed under *Recovering*, and cell 5 is a cell the dealer cannot avoid
    // running when it presses Run on cell 0.
    await ceremony.getByRole("button", { name: /Show the \d+ cells this writes/ }).click();
    // Per `<li>`, not by splitting the list's text on newlines: a `why` long
    // enough to wrap would otherwise read as an extra row with no number in it.
    const phaseCells = async (phase) =>
      (
        await ceremony
          .locator(`[data-room-ceremony-phase="${phase}"]`)
          .locator("li")
          .allInnerTexts()
      ).map((line) => Number(/\[(\d+)\]/.exec(line)?.[1]));
    const dealing = await phaseCells("deal");
    const recovering = await phaseCells("recover");
    expect(dealing, `Dealing lists ${JSON.stringify(dealing)}`).toEqual([0, 1, 2, 3, 4]);
    expect(
      recovering,
      `Recovering lists ${JSON.stringify(recovering)} — finding 1a is pinned to cell ${DEALER_RETURN} being in it`
    ).toEqual([5, 6, 7]);
    // The two lists are contiguous and adjacent, which is the whole mechanism:
    // `runFrom(0)` reaches the first Recovering cell without passing any control
    // that could stop it, so a dealer following the panel's own instruction to
    // "run once, together" runs a recovery cell too.
    expect(Math.min(...recovering), "the phases stopped being contiguous").toBe(
      Math.max(...dealing) + 1
    );

    await ceremony.getByRole("button", { name: /^Write the 2-of-3 ceremony$/ }).click();
    await expect
      .poll(async () => await ceremony.locator("[data-room-ceremony-note='1']").innerText(), {
        timeout: 20000,
      })
      .toContain("2-of-3");

    await dealer.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    const dealt = await readNotebookSource(dealer);
    const dealtCells = dealt.split(/\n\s*\n+/).map((c) => c.trim());
    expect(dealtCells, dealt).toHaveLength(DEALT_CELLS);
    expect(
      dealtCells[DEALER_RETURN].split("\n")[0],
      "the dealer's return cell moved — finding 1a is pinned to its position"
    ).toBe(`@${L.dealer}`);
    // Matched on the shape rather than the spelling: `at 1` is drawn back as
    // `[1]`, `publish` became a step an hour ago and `sss.split` is being
    // reconsidered next door. What must not change is that this cell reads the
    // dealer's whole set, selects one share out of it, and addresses the
    // recoverer.
    expect(dealtCells[DEALER_RETURN], `the dealer's sixth cell: ${dealtCells[DEALER_RETURN]}`)
      .toMatch(/\$set/);
    expect(dealtCells[DEALER_RETURN]).toContain(L.recoverer);

    // **The press a dealer who means to give up their share has to find.** It is
    // the ordinary Delete cell control, it is not named anywhere on the ceremony
    // panel, and nothing on screen connects "this machine should not keep a
    // share" to it. Done here, before the notebook is shared, so all three
    // machines hold the same seven cells — a cell only crosses to somebody
    // holding the same text.
    await cell(dealer, DEALER_RETURN).getByRole("button", { name: "Delete cell" }).click();
    await expect
      .poll(async () => await dealer.locator("article").count(), { timeout: 10000 })
      .toBe(CELLS);

    ceremonySource = await readNotebookSource(dealer);
    const cells = ceremonySource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(cells, ceremonySource).toHaveLength(CELLS);

    // **Where each cell landed now.** The headers are the one piece of recipe
    // text this file reads exactly, because they are the whole answer to "who
    // does what" and they are written by `setCellPeer` rather than by any
    // spelling of a verb.
    const on = cells.map((c) => c.split("\n")[0]);
    expect(on, JSON.stringify(on, null, 1)).toEqual([
      `@${L.dealer}`, // draw and split
      `@${L.dealer}`, // hand share 2 to the recoverer
      `@${L.dealer}`, // hand share 3 to the bystander
      `@${L.recoverer}`, // receive
      `@${L.bystander}`, // receive
      `@${L.bystander}`, // return their share, when a recovery is called for
      `@${L.recoverer}`, // gather and recombine
    ]);
    // The dealer has three cells and every one of them is a deal cell. This is
    // the property the rest of the file rests on: after this notebook is shared
    // there is no press anywhere that sends the dealer's share to anybody.
    expect(
      on.filter((h) => h === `@${L.dealer}`),
      "the dealer kept a cell that can put a share on the wire"
    ).toHaveLength(3);
    // And no cell anywhere selects share 1 out of the set. Written as an
    // alternation because the editor re-serializes `at 1` as `[1]` and this
    // assertion is about the *selection*, not the spelling of it.
    expect(
      ceremonySource,
      "a cell still selects the dealer's own share out of the set"
    ).not.toMatch(/\$set\s*\|\s*(\[1\]|at\s+1)\b/);

    // **FINDING (1b) — the recovery gather gives the other custodian two
    // minutes.** The generated cell is `quorum.recv count=1 | …` with no `wait=`
    // on it, and `quorum.recv`'s registry default is 120000 ms. So the cell the
    // picker describes as "run when the secret is wanted back" fails two minutes
    // after it is pressed unless the second holder happens to be sitting at their
    // machine, and the refusal it fails with is about the room ("Nobody having
    // sent yet is an ordinary state of a healthy room… give it a longer wait=
    // than 120s") — a remedy that requires editing a generated recipe, in a
    // notebook whose other copies would then no longer match this one.
    //
    // Observed rather than argued: driving the recoverer's gather before the
    // other holder had pressed anything produced exactly that sentence, twice.
    // It is pinned here on the recipe instead of on a two-minute wait, because a
    // test that spends 120 s proving a default is 120 s buys nothing the text
    // does not already say.
    expect(
      cells[CELLS - 1],
      `the gather cell: ${cells[CELLS - 1]}`
    ).toMatch(/quorum\.recv\b/);
    expect(
      cells[CELLS - 1],
      "the gather grew a wait= — finding 1b is fixed and this line should say so"
    ).not.toMatch(/\bwait\s*=/);

    // It still compiles, for the person: read off the control rather than out of
    // the compiler, because "the recipe parses" and "Run all can be pressed" are
    // two facts and only the second is what a reader has.
    expect(
      await dealer.getByRole("button", { name: "Run all" }).getAttribute("aria-disabled")
    ).toBe(null);
    for (let i = 0; i < CELLS; i += 1) expect(await cellErrors(dealer, i)).toBe("");
    for (let i = 0; i < CELLS; i += 1) expect(await cellStatus(dealer, i)).toBe("idle");
    expect(await ceremonySlots(dealer)).toEqual([]);
  });

  /* ── 2. three people in a room, one of whom will not be staying ──────────── */

  it("meshes all three before anybody leaves", async () => {
    await trayTab(dealer, "Connections");
    await tray(dealer).getByRole("button", { name: "Start session" }).click();
    const sheet = dealer.locator("[data-session-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const start = dealer.getByRole("button", { name: "Start shared session" });
    await expect.poll(async () => await start.isEnabled(), { timeout: 15000 }).toBe(true);
    await start.click();
    await expect
      .poll(
        async () => await dealer.locator("[data-run-state]").getAttribute("data-run-state"),
        { timeout: 60000, intervals: [250] }
      )
      .toBe("waiting-peer");

    await expect
      .poll(async () => await dealer.evaluate(() => window.location.hash), { timeout: 20000 })
      .toMatch(/^#j=/);
    inviteUrl = dealer.url();

    const joiners = [
      { page: recoverer, member: room.members[1], uid: "Recoverer <recoverer@ceremony.test>" },
      { page: bystander, member: room.members[2], uid: "Bystander <bystander@ceremony.test>" },
    ];
    for (const who of joiners) {
      await who.page.goto(inviteUrl, { waitUntil: "load" });
      await becomeMember(who.page, who.member, who.uid);

      const startPanel = who.page.locator("[data-session-start]");
      await startPanel.waitFor({ state: "visible", timeout: 20000 });
      expect(await startPanel.getAttribute("data-session-start")).toBe("join");

      await who.page.locator("[data-session-key] select").selectOption(who.member.fpr);
      const join = who.page.getByRole("button", { name: "Join shared session" });
      await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
      await join.click();
      await who.page.locator("[data-session-sheet]").waitFor({ state: "hidden", timeout: 20000 });
    }

    // Two verified peers each, on all three machines — including the
    // holder↔holder link neither holder was introduced over, which is the link
    // the whole recovery below will run on once the dealer is gone.
    for (const [name, page] of Object.entries({ dealer, recoverer, bystander })) {
      try {
        await expect
          .poll(
            async () => {
              await trayTab(page, "Connections");
              return await tray(page).locator('[data-verified="1"]').count();
            },
            { timeout: 90000, intervals: [500] }
          )
          .toBe(2);
      } catch {
        expect.unreachable(
          `${name} never key-confirmed both of the others — ${JSON.stringify(
            {
              wire: room
                .signalled()
                .map((f) => `${f.seq} ${f.signer.slice(0, 4)} ${f.type} → ${f.to?.slice(0, 4) || "*"}`),
              dealer: await rosterRows(dealer),
              recoverer: await rosterRows(recoverer),
              bystander: await rosterRows(bystander),
            },
            null,
            1
          )}`
        );
      }
    }
    for (const page of [dealer, recoverer, bystander]) await runSettled(page);
  }, 400_000);

  /* ── 3. one notebook, three copies ───────────────────────────────────────── */

  it("carries the seven-cell ceremony to both holders", async () => {
    for (const page of [recoverer, bystander]) {
      expect(await readNotebookSource(page)).toBe("");
    }
    await trayTab(dealer, "Connections");
    await tray(dealer).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await dealer.locator("[data-notebook-share-note]").innerText(), {
        timeout: 30000,
      })
      .toMatch(/signed and shared with 2 peers/);

    for (const page of [recoverer, bystander]) {
      await expect
        .poll(async () => await readNotebookSource(page), { timeout: 60000 })
        .toBe(ceremonySource);
      expect(await page.locator("article").count()).toBe(CELLS);
      for (let i = 0; i < CELLS; i += 1) expect(await cellStatus(page, i)).toBe("idle");
    }
  });

  /* ── 4. the deal, and nothing else ───────────────────────────────────────── */

  it("deals both shares without returning the dealer's own", async () => {
    await cell(dealer, 0).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(dealer);

    const dealt = await board(dealer);
    const why = JSON.stringify(dealt, null, 1);
    expect(dealt[0], why).toBe("ok"); // draw and split
    expect(dealt[1], why).toBe("ok"); // share 2 → recoverer
    expect(dealt[2], why).toBe("ok"); // share 3 → bystander
    expect(dealt[3], `the dealer performed the recoverer's cell — ${why}`).toBe("declined");
    expect(dealt[4], `the dealer performed the bystander's cell — ${why}`).toBe("declined");
    expect(dealt[5], why).toBe("declined");
    expect(dealt[6], why).toBe("declined");

    // The dealer's press did exactly three things, and none of them was a
    // recovery. With the generated notebook this same press would also have run
    // cell 5 and put share 1 in the recoverer's inbox — finding 1a, in the one
    // place where its absence is visible as a state rather than as an argument.
    expect(
      Object.values(dealt).filter((s) => s.startsWith("ok")),
      why
    ).toHaveLength(3);

    // **The dealer still holds every share**, which is
    // `three-party-ceremony.e2e.js`'s finding 4a and is not fixed by anything
    // here: `$set` is the whole set, in a revealable slot, on the machine that is
    // about to be destroyed. Repeated rather than cross-referenced because it is
    // the thing that makes the destruction below meaningful — closing this
    // context is the only act in this file that actually removes the dealer's
    // copy of share 1 from the world, and no control on screen does it.
    const held = await ceremonySlots(dealer);
    expect(held, "the dealer's slots changed shape").toEqual(["expected", "set"]);
    expect(held, "the master reached a slot").not.toContain("secret");

    expectedDigest = await reveal(dealer, 0, "expected");
    expect(expectedDigest, "the split wrote no digest of the master").toMatch(/^[0-9a-f]{64}$/);
  });

  /* ── 5. the dealer is destroyed ──────────────────────────────────────────── */

  it("closes the dealer's browser before either holder has run anything", async () => {
    dealerCsp = await fx.peers[0].cspViolations();

    // Not a cancel, not a Clear session, not a page the test stopped touching:
    // the context is destroyed, so the vault, the unlocked key, `$set` with every
    // share in it, and both data channels go with it. There is no press that
    // could be un-pressed after this.
    //
    // **Before either holder runs**, which is the ordering the whole file turns
    // on. Every cell from here to the end of the notebook is pressed on a
    // machine whose dealer no longer exists, so nothing after this line can be
    // leaning on the dealer's presence without the run failing.
    await fx.peers[0].context.close();

    // What the two remaining screens say about it, sampled over the ICE consent
    // window rather than read once. Both facts are kept: `data-peer-state`, which
    // is the link, and the verdict badge, which is the key confirmation. They are
    // deliberately separate in `ConnectionsPanel` — "a peer can be fully
    // connected and completely unverified" — so a departure is only legible if
    // at least one of them moves.
    for (const [name, page] of Object.entries({ recoverer, bystander })) {
      /** Every distinct roster this screen drew, with the second it changed on. */
      /** @type {string[]} */
      const timeline = [];
      const started = Date.now();
      /** @type {string[]} */
      let rows = [];
      /** @type {string} */
      let last = "";
      for (;;) {
        rows = await rosterRows(page);
        const now = JSON.stringify(rows);
        if (now !== last) {
          timeline.push(`+${Math.round((Date.now() - started) / 1000)}s ${now}`);
          last = now;
        }
        // Settled once the departed peer stops reading as a live, verified link.
        const stillLive = rows.some(
          (r) => r.includes(L.dealer) && r.includes("state=connected") && r.includes("verified=1")
        );
        if (!stillLive || Date.now() - started > 45000) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      departure[name] = timeline;

      // Both rows are still drawn. A peer that left is not deleted from the
      // roster, which is right: the room's audience did not change, only its
      // reachability, and a row that vanished would make "who was in this room"
      // unanswerable at exactly the moment somebody wants to know.
      expect(rows, `${name}'s roster: ${JSON.stringify(rows)}`).toHaveLength(2);
      // The whole fingerprint of the peer that left, never a prefix of one.
      expect(rows.join(" "), `${name}'s roster: ${JSON.stringify(rows)}`).toContain(L.dealer);

      // The link is reported dead, which is the half of this that works. It is
      // not instant and it is not a channel close: `channel.onclose` never fires
      // for a browser that was destroyed rather than shut down, so what moves
      // this row is `onConnectionState("failed")` after ICE consent expires —
      // measured at up to sixteen seconds here, which is why this is a poll and
      // not a read.
      const gone = rows.find((r) => r.includes(L.dealer));
      expect(gone, `${name}'s roster: ${JSON.stringify(rows)} over ${JSON.stringify(timeline)}`)
        .toContain("state=failed");
    }
  }, 200_000);

  /* ── 6. the bystander returns their share to a machine nobody else can reach ─ */

  it("returns the bystander's share over the link the dealer was never part of", async () => {
    // The share the dealer dealt is already in this browser's inbox — it arrived
    // over a channel that no longer exists, from a machine that no longer exists.
    // The same press takes delivery of it and hands it straight back, because
    // `runFrom` walks to the end; finding 1a is the same mechanism seen from the
    // holder's side, where it costs a press rather than the property.
    await cell(bystander, 4).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(bystander);

    const seen = await board(bystander);
    const whyB = JSON.stringify(seen, null, 1);
    expect(seen[4], `the bystander never took delivery — ${whyB}`).toBe("ok");
    expect(seen[5], `the bystander could not return its share — ${whyB}`).toBe("ok");
    // The send is the assertion: `sendChatTo` throws rather than reaching
    // nobody, so an `ok` here is the session saying it wrote to a verified,
    // open channel — and the only such channel this browser has left is the one
    // to the other holder.
    const held = await ceremonySlots(bystander);
    expect(held, `the bystander's slots: ${JSON.stringify(held)}`).toEqual(["share-2"]);
    expect(held, "the bystander somehow holds the dealer's set").not.toContain("set");
  }, 200_000);

  /* ── 7. two holders, one secret, no dealer ───────────────────────────────── */

  it("recombines the dealer's secret out of two holders' shares, with the dealer destroyed", async () => {
    // One press on the recoverer, and both of its cells find what they need
    // already waiting: `quorum.recv from=<dealer>` takes the share dealt before
    // the dealer left, and the gather's unfiltered `quorum.recv count=1` takes
    // the one the other holder sent after. Two messages, one inbox, told apart
    // by the `from=` on the earlier cell — which is what makes the order of
    // these two presses survivable.
    await cell(recoverer, 3).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(recoverer, 3), { timeout: 180000, intervals: [250] })
      .toBe("ok");
    await expect
      .poll(async () => await cellStatus(recoverer, 6), { timeout: 180000, intervals: [250] })
      .toBe("ok");
    await runSettled(recoverer);

    const held = await ceremonySlots(recoverer);
    const whyR = `the recoverer's slots: ${JSON.stringify(held)}`;
    expect(held, whyR).toContain("share-1");
    expect(held, whyR).toContain("secret");
    expect(held, whyR).toContain("recovered");
    expect(held, whyR).not.toContain("set");
    expect(held, whyR).not.toContain("expected");

    // **This is the assertion the file exists for.** A SHA-256 computed on a
    // machine that no longer exists, read off its screen while it did, equal to a
    // SHA-256 computed here out of two mnemonics neither of which the dealer
    // returned: this machine's own, delivered during the deal, and one sent by a
    // third browser after the dealer was destroyed. There is no cell anywhere in
    // this notebook that could have supplied the dealer's share.
    const recovered = await reveal(recoverer, 6, "recovered");
    expect(recovered, "the two holders recombined into something else").toBe(expectedDigest);

    // And the secret itself is here, revealable, on the machine that is meant to
    // end up with it. Without this the digest match would only prove the shares
    // agree about a value nobody can spend.
    const secret = await reveal(recoverer, 6, "secret");
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(secret).not.toBe(recovered);

    // **FINDING (7a) — nothing on either screen says whose shares rebuilt it.**
    // The recoverer's gather is `quorum.recv count=1`, which takes a message and
    // reports a value; the sender's fingerprint rides on `meta.from` and reaches
    // no tile, no slot row and no receipt. This file can name the two holders
    // only because it removed every other possibility from the notebook first. A
    // person who ran the ceremony as generated cannot, and the question "did this
    // recovery need the dealer?" is exactly the question a 2-of-3 is bought to be
    // able to answer.
    //
    // Pinned in the two places a person would look. The gather cell itself,
    // which is the thing they are reading when the secret comes back; and the
    // Activity tray, which is where a disposition goes — `noteSend` writes an
    // outward entry on the *sender* naming who it wrote to, and the receiving
    // end writes nothing at all, so the one machine that ends up with the secret
    // is the one machine with no record of where it came from.
    const gather = await cell(recoverer, 6).innerText();
    expect(gather, "the gather cell names its sender after all").not.toContain(L.bystander);
    await trayTab(recoverer, "Activity");
    const activity = (await tray(recoverer).innerText()).replace(/\s+/g, " ");
    expect(
      activity,
      `the recoverer's Activity tray: ${activity.slice(0, 400)}`
    ).not.toContain(L.bystander);
  }, 300_000);

  /* ── 8. what is left on the two screens ──────────────────────────────────── */

  it("leaves two machines holding one ceremony, one link and no dealer", async () => {
    for (const page of [recoverer, bystander]) {
      expect(await readNotebookSource(page)).toBe(ceremonySource);
      expect(await page.locator("article").count()).toBe(CELLS);
      const settled = await board(page);
      expect(
        Object.values(settled).map((s) => s.split(" — ")[0]),
        JSON.stringify(settled, null, 1)
      ).not.toContain("error");
      // **FINDING (8a) — the row for the destroyed browser still says
      // "verified".**
      //
      // `ConnectionsPanel` argues for keeping connectivity and authentication
      // apart, and the argument is right: "a peer can be fully connected and
      // completely unverified, and conflating the two is how you end up trusting
      // the wrong end of a working pipe." What is left over is the other
      // direction. `data-verified` is `pgpVerified && kcVerified`, and the one
      // place that clears `kcVerified` is `channel.onclose` — which does not run
      // when a browser is destroyed rather than closed down. So the field that
      // was written to retract the verdict when a link dies is not the field
      // that fires, and the row a person is left reading is the whole
      // fingerprint, then the word **verified**, then the word **failed**.
      //
      // Nothing acts on the stale bit: `_sendChatFiltered` gates on the channel's
      // own `readyState`, and `sendAudience` and `recvTimeoutMessage` both
      // require `state === "connected"` as well. So this is a reading, not a
      // routing defect — which is why it is pinned rather than fixed, and why
      // the fix is a product decision about what a verdict badge is claiming.
      const rows = await rosterRows(page);
      const gone = rows.find((r) => r.includes(L.dealer));
      expect(gone, `roster: ${JSON.stringify(rows)}`).toContain("state=failed");
      expect(gone, `roster: ${JSON.stringify(rows)}`).toContain("verified=1");
      // And the word itself, which is what is actually on the screen — the
      // attribute could be renamed without the sentence a person reads changing.
      expect(gone, `roster: ${JSON.stringify(rows)}`).toMatch(/verifiedfailed/);
      // The timeline that got there, kept on the assertion so a change in how
      // long a departure takes to show is diagnosable rather than merely red.
      expect(
        departure[page === recoverer ? "recoverer" : "bystander"],
        "no roster sample was taken while the dealer went away"
      ).not.toHaveLength(0);
    }
  });

  /* ── what the journey cost ───────────────────────────────────────────────── */

  it("drove three browsers and one departure without tripping the production CSP", async () => {
    expect(dealerCsp, "the dealer tripped the CSP before it was closed").toEqual([]);
    for (const peer of fx.peers.slice(1)) expect(await peer.cspViolations()).toEqual([]);
    expect(fx.tunnelFaults()).toEqual([]);
    expect(room.faults()).toEqual([]);
  });
});
