/**
 * The ceremony the room generates, driven from the picker to the recovered
 * secret, across two browsers.
 *
 * ## Why this is not a section of `placed-journey.e2e.js`
 *
 * That file is the road, and this ceremony has to be written *before* the road
 * starts. `SessionSheet` shows `SessionStart` only while `live` is null —
 * "closing the session is what returns this to the naming half" — so the
 * control that generates a ceremony is on screen exactly until Start is pressed,
 * and `placed-journey` presses Start in its third step. Writing the ceremony
 * there would also replace the notebook that file spends steps 1 through 7
 * proving, and the instruction was not to weaken a single assertion in it. So
 * this is a second road with the same fixture, the same helpers and the same
 * rule: **no variable carries anything between the two browsers.** Everything
 * either side knows about the other arrived over the wire or out of the address
 * bar.
 *
 * ## What is new here, and what is borrowed
 *
 * Borrowed: the room, the mesh, the two vaults, the invite, Share, and the fact
 * that `quorum.send` / `quorum.recv` deliver — all of that is `cf56628` and
 * `dc5d7cb` and is proven in the sibling file.
 *
 * New, and the whole reason this exists:
 *
 * 1. **The notebook is not typed.** Every other suite in this repo composes by
 *    typing pipelines into cell editors. Here the only presses that produce a
 *    notebook are: choose a key, name the room, and one button. Nothing in this
 *    file types a pipeline, a header, a threshold or a fingerprint into an
 *    editor — which is the product owner's complaint stated as a test, and it is
 *    why step 1 asserts the *absence* of any typing as well as the presence of
 *    the cells.
 * 2. **The quorum comes from the room.** A two-person room is a 2-of-2, and the
 *    panel says so before the press. A count that disagreed with the number of
 *    people is unreachable rather than refused.
 * 3. **The deal is the whole notebook, and the recovery is a second one,
 *    written at recovery time.** The generated ceremony used to carry both —
 *    return cells, an armed gather, phase labels one press could not honour —
 *    and LANGUAGE.md's "two agreements, two notebooks" retired that shape.
 *    Step 6 drives the recovery picker on the *holder's* machine, with the
 *    dealer as its one named contributor: a 2-of-2 needs both shares, so this
 *    file is where the dealer-present recovery — the dealer as an ordinary
 *    checkbox, their own `$share` sent by an ordinary cell — runs across real
 *    browsers. Step 6 is still the assertion the whole thing ships or does
 *    not ship on: a digest computed on the dealer's machine, of thirty-two
 *    bytes that were never written to any slot, equal to a digest computed on
 *    the holder's machine of what the holder put back together out of two
 *    mnemonics that crossed a room.
 *
 * ## What the run does at the end, and what that used to cost
 *
 * `startSession` **appended** two cells — `agent.unlock` and `quorum.offer` —
 * so after Start the notebook was the ceremony followed by the session. A run
 * always walks to the end of the notebook, so a run started at the ceremony's
 * first cell reached a `quorum.offer` for an exchange that was already live and
 * `execQuorumOpen` threw. This file pinned that as a wart: step 7 asserted a
 * cell in `error` at the bottom of a ceremony that had otherwise succeeded, and
 * `placed-journey` sidestepped the same thing by starting its run *after* the
 * session cells.
 *
 * It is not a wart any more, because the cells are gone (`START_OPENS` carries
 * the argument). Step 7 asserts the property that replaced it, which is the one
 * a person actually wanted: **the notebook the ceremony wrote runs from the top
 * and every cell in it is the ceremony's.** The refusal itself has not been
 * weakened and has not moved — `execQuorumOpen` still declines a second
 * exchange, `quorum-lifecycle.test.js` holds that assertion, and step 7 checks
 * here that exactly one exchange is live and still verified on both ends. A
 * change that let a second one open behind the reader's back would still show.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";
import { roomRoster } from "../../lib/notebook/roster.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the room-ceremony suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[room-ceremony.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/** One notebook cell, by index — the shell renders exactly one `<article>` each. */
const cell = (page, i) => page.locator("article").nth(i);

/** The session tray, as a scope. */
const tray = (page) => page.locator('[aria-label="Session tray"]').locator("xpath=..");

/** Open one of the tray's tabs and wait for it to be the selected one. */
async function trayTab(page, name) {
  const tab = tray(page).getByRole("tab", { name, exact: true });
  await tab.click();
  await expect.poll(async () => await tab.getAttribute("aria-selected"), {
    timeout: 10000,
  }).toBe("true");
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
  return (await box.count()) ? (await box.innerText()).trim() : "";
}

/**
 * Uncover one output tile and read what it says.
 *
 * The reveal is part of what is tested: `out` is what marks a tile revealable,
 * and a road that delivered a value into a tile nobody could open would be a
 * road that delivered nothing a person can use. The list re-hides after fifteen
 * seconds, so the read follows the press immediately.
 */
async function reveal(page, i, label) {
  const tile = cell(page, i).locator("[data-artifact-kind]").filter({ hasText: label }).first();
  await tile.waitFor({ state: "visible", timeout: 20000 });
  const button = tile.getByRole("button", { name: "Reveal" });
  if (await button.count()) {
    await button.click();
  }
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
    const m = /^@(expected|share(?:-\d+)?|recovered|secret|set)$/.exec(text.trim());
    if (m) out.push(m[1]);
  }
  return out.sort();
}

describe.runIf(availability.ok)("a ceremony generated from the room, end to end", () => {
  /** @type {any} */ let room;
  /** @type {any} */ let fx;
  /** @type {(() => Promise<void>)|null} */ let closeMesh = null;
  /** @type {import("playwright").Page} */ let dealer;
  /** @type {import("playwright").Page} */ let holder;
  /** @type {string} */ let origin = "";
  /** @type {{ dealer: string, holder: string }} */
  let L = { dealer: "", holder: "" };
  /** The URL the dealer's own address bar held after Start. Nothing else crosses. */
  let inviteUrl = "";
  /** The ceremony as the dealer's own Source view prints it. */
  let ceremonySource = "";
  /** The whole notebook at the moment Share is pressed — ceremony plus session. */
  let sharedSource = "";
  /** The recovery the holder writes for itself in step 6. */
  let recoverySource = "";
  /** The digest of the master, off the dealer's screen. Never the master. */
  let expectedDigest = "";

  beforeAll(async () => {
    room = await createQuorumRoom();
    const mesh = await openMesh(room);
    if (!mesh.ok) {
      throw new Error(`local Web PubSub hub did not start (${mesh.kind}): ${mesh.reason}`);
    }
    closeMesh = mesh.close;
    fx = mesh.fx;
    origin = fx.origin;
    dealer = fx.peers[0].page;
    holder = fx.peers[1].page;

    L = {
      dealer: roomRoster(room.audience, [], room.members[0].fpr).me,
      holder: roomRoster(room.audience, [], room.members[1].fpr).me,
    };
    expect(L.dealer).toBe(room.members[0].fpr);
    expect(L.holder).toBe(room.members[1].fpr);
    // Two people, so the ceremony this room generates is a 2-of-2. That is the
    // room the fixture opens, and the numbers below are derived from it rather
    // than chosen: this file never types a threshold anywhere.
    expect(room.audience).toHaveLength(2);
  }, 180_000);

  afterAll(async () => {
    if (closeMesh) await closeMesh();
    else if (fx) await fx.close();
  });

  /* ── 1. the picker writes the notebook, and nobody types a pipeline ──────── */

  it("generates a whole ceremony from the audience, before any session exists", async () => {
    await dealer.goto(`${origin}/toolkit`, { waitUntil: "load" });
    // The one evaluate, and the reason `placed-journey` gives for it: there is
    // no import UI for a key this fixture already holds, and the key has to be
    // one the room's keyserver can hand out.
    const stored = await dealer.evaluate(
      seedVaultKeyExpr({
        fingerprint: room.members[0].fpr,
        armoredPrivate: room.members[0].armoredPrivate,
        armoredPublic: room.members[0].armoredPublic,
        uid: "Dealer <dealer@ceremony.test>",
      })
    );
    expect(stored).toContain(room.members[0].fpr);
    await dealer.reload({ waitUntil: "load" });
    await dealer.waitForSelector(".toolkit-shell", { timeout: 30000 });

    // The room is named the way anybody names one — a fingerprint handed over
    // out of band, in the form this product puts one in.
    const sheet = dealer.locator("[data-session-sheet]");
    await dealer.evaluate((h) => {
      window.location.hash = h;
    }, `#j=${room.audience.join(",")}`);
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    await dealer.getByRole("button", { name: "I am starting it" }).click();
    await dealer.locator("[data-session-key] select").selectOption(room.members[0].fpr);

    // **The panel names the quorum before the press.** The numbers are the
    // room's, and nothing on this screen offered to let them disagree with it:
    // there is no shares field and no threshold field, which is the whole point
    // — a count that did not match the number of people is unreachable rather
    // than refused.
    const ceremony = dealer.locator("[data-room-ceremony]");
    await ceremony.waitFor({ state: "visible", timeout: 20000 });
    const summary = await ceremony.locator("[data-room-ceremony-summary]").innerText();
    expect(summary).toContain("One share each for 2 people");
    expect(summary).toContain("any 2 of them rebuild the secret");
    // The two facts a reader would otherwise have to be told by somebody: that
    // this machine sees every share, and that 2-of-2 has no redundancy.
    expect(summary).toContain("dealer-based split");
    expect(summary).toContain("not distributed key generation");
    expect(summary).toContain("no redundancy at all");
    // And the master's whereabouts, stated where the decision is made rather
    // than discovered by reading the recipe.
    expect(summary).toContain("never written to a slot");
    expect(
      await ceremony.locator("[data-room-ceremony-issues]").count(),
      "the ceremony refused a room it can serve"
    ).toBe(0);

    // The cells, before they replace anything. A generated notebook that could
    // not be read first would be the one thing in this app you had to take on
    // trust.
    await ceremony.getByRole("button", { name: /Show the \d+ cells this writes/ }).click();
    const preview = await ceremony.locator("[data-room-ceremony-recipe]").innerText();
    // The quorum as the verb's object (migration step 2) — the generator writes
    // the canonical fraction, so the preview and the notebook cannot differ by
    // a respelling.
    expect(preview).toContain("sss.split 2/2");
    // **Every destination is a derivation now.** The deal is one `scatter`
    // cell: `to=room` is the audience in canonical order and `to=each` is the
    // pair's member, so no constant `quorum.send <fpr>` appears — the pairing
    // is derived on every machine and chosen by nobody.
    expect(preview).toContain("scatter to=room");
    expect(preview).toContain("- send to=each | out $share");
    expect(preview).not.toContain(`quorum.send ${L.holder}`);
    expect(preview).toContain(`quorum.recv from=${L.dealer}`);
    // Whole keys in the preview too — the one place a reader checks who is
    // being handed a share before anyone is handed one.
    expect(preview).not.toContain("…");
    for (const fpr of room.audience) expect(preview).toContain(fpr);

    await ceremony.getByRole("button", { name: /^Write the 2-of-2 ceremony$/ }).click();
    await expect
      .poll(async () => await ceremony.locator("[data-room-ceremony-note='1']").innerText(), {
        timeout: 20000,
      })
      .toContain("2-of-2 split");

    await dealer.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    ceremonySource = await readNotebookSource(dealer);
    // Two cells: the deal, and the holder's receive. Written out rather than
    // counted from a formula, so a change in shape has to be re-derived here.
    // The five-cell shape this used to assert — split, send, receive, the
    // dealer's return, the recombination — was the deal and the recovery in
    // one document, which is the one-press hazard the two-notebooks change
    // retired; the recovery is generated in step 6, when it is wanted.
    const cells = ceremonySource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(cells, ceremonySource).toHaveLength(2);
    // **The headers are in the notebook and this file never typed one, and
    // never chose one from a menu either.** `placed-journey` proves the menu
    // works; this proves the generator does not need it.
    expect(cells[0].split("\n")[0]).toBe(`@${L.dealer}`);
    expect(cells[1].split("\n")[0]).toBe(`@${L.holder}`);
    // The quorum is in the text, where two peers will digest it — `ade4043`,
    // spelled as the verb's object since migration step 2.
    expect(ceremonySource).toContain("sss.split 2/2");
    // Never `publish`: a share leaves this machine because a verb said so.
    expect(ceremonySource).not.toContain("publish");
    // The master is in no slot, **and neither is the set**: `random 32` flows
    // into `sss.split` and the shares flow through the scatter body without
    // stopping — split, sent, gone. The deal cell's only outs are the digest
    // and this machine's own share, which is what retired the revealable
    // `$set` (the three-party suite's finding 4a) by construction.
    expect(cells[0]).toContain("out $expected");
    expect(cells[0]).toContain("out $share");
    expect(ceremonySource).not.toContain("$set");
    expect(ceremonySource).not.toContain("out $master");
    // And no recovery anywhere in it — no gather, no armed wait, nothing below
    // the deal for a run to walk into.
    expect(ceremonySource).not.toContain("sss.combine");
    expect(ceremonySource).not.toContain("wait=");

    // It compiles, for the person: read off the control rather than out of the
    // compiler, because "the recipe parses" and "Run all can be pressed" are two
    // facts and only the second is what a reader has.
    expect(
      await dealer.getByRole("button", { name: "Run all" }).getAttribute("aria-disabled")
    ).toBe(null);
    for (let i = 0; i < 2; i++) expect(await cellErrors(dealer, i)).toBe("");
    // Nothing has run: the press wrote a notebook, it did not perform one.
    for (let i = 0; i < 2; i++) expect(await cellStatus(dealer, i)).toBe("idle");
    expect(await ceremonySlots(dealer)).toEqual([]);
  });

  /* ── 2. start it, and the joiner arrives through the address bar ─────────── */

  it("opens the room the ceremony was written for", async () => {
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
    expect(new URL(inviteUrl).hash).not.toContain("r=");

    await holder.goto(inviteUrl, { waitUntil: "load" });
    const stored = await holder.evaluate(
      seedVaultKeyExpr({
        fingerprint: room.members[1].fpr,
        armoredPrivate: room.members[1].armoredPrivate,
        armoredPublic: room.members[1].armoredPublic,
        uid: "Holder <holder@ceremony.test>",
      })
    );
    expect(stored).toContain(room.members[1].fpr);
    await holder.reload({ waitUntil: "load" });
    await holder.waitForSelector(".toolkit-shell", { timeout: 30000 });

    const holderSheet = holder.locator("[data-session-sheet]");
    const holderStart = holder.locator("[data-session-start]");
    await holderStart.waitFor({ state: "visible", timeout: 20000 });
    expect(await holderStart.getAttribute("data-session-start")).toBe("join");
    // **Before a key is chosen there is no ceremony to offer, and it says which
    // of the two lists is missing.** The audience arrived whole in the link, so
    // "add somebody" would be a remedy for a state this reader is not in; the
    // refusal names the chooser instead, which is the one control on this panel
    // they have not touched.
    const invitedCeremony = holder.locator("[data-room-ceremony]");
    await invitedCeremony.waitFor({ state: "visible", timeout: 20000 });
    expect(await invitedCeremony.locator("[data-room-ceremony-issues]").innerText()).toContain(
      "Choose the key you are joining as"
    );
    expect(await invitedCeremony.locator("[data-room-ceremony-summary]").count()).toBe(0);

    await holder.locator("[data-session-key] select").selectOption(room.members[1].fpr);
    // **And once it is chosen the invitee is offered the same ceremony**, which
    // is the room deriving it rather than the creator deciding it: both pickers
    // read one audience and reach one quorum. The holder must not press it —
    // that would be a second dealer-based split, of a different secret, by the
    // machine that is meant to be receiving one — and nothing on this page does.
    await expect
      .poll(
        async () => await invitedCeremony.locator("[data-room-ceremony-summary]").innerText(),
        { timeout: 20000 }
      )
      .toContain("One share each for 2 people");
    const join = holder.getByRole("button", { name: "Join shared session" });
    await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
    await join.click();
    await holderSheet.waitFor({ state: "hidden", timeout: 20000 });

    for (const page of [dealer, holder]) {
      await trayTab(page, "Connections");
      await expect
        .poll(async () => await tray(page).locator('[data-verified="1"]').count(), {
          timeout: 120000,
          intervals: [500],
        })
        .toBe(1);
    }
    await runSettled(dealer);
    await runSettled(holder);
  });

  /* ── 3. the ceremony travels ─────────────────────────────────────────────── */

  it("carries the generated notebook to the holder, who wrote none of it", async () => {
    const before = await readNotebookSource(holder);
    // **Nothing at all**, which is the assertion pressing Join used to make
    // impossible: it appended `agent.unlock` and `quorum.join`, so a joiner was
    // never empty and this line read `expect(before).toContain("quorum.join")`.
    // The holder has not generated their own copy of anything — the ceremony
    // they end up running has to have arrived over the wire.
    expect(before).toBe("");

    sharedSource = await readNotebookSource(dealer);
    // The dealer's notebook is the ceremony and only the ceremony. Byte for
    // byte with what step 1 read off the same screen, so Start added nothing to
    // it between then and now.
    expect(sharedSource).toBe(ceremonySource);
    expect(sharedSource).not.toContain("quorum.offer");

    await trayTab(dealer, "Connections");
    await tray(dealer).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await dealer.locator("[data-notebook-share-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/written to 1 open channel · unconfirmed/);

    // **No press.** `decideProposal` adopts without asking when there is no
    // local work to lose, and an empty notebook is exactly that state — so the
    // holder's first notebook arrives rather than being offered. While Start
    // appended cells this could not happen to anybody, and the question came up
    // for a notebook the reader had never written a line of.
    await expect
      .poll(async () => await readNotebookSource(holder), { timeout: 30000 })
      .toBe(sharedSource);
    expect(
      await holder.getByRole("button", { name: "Adopt their notebook" }).count(),
      "the holder was asked about a notebook they had no work to lose to"
    ).toBe(0);
    // Byte for byte, which is what makes the run that follows a reproducible
    // build rather than two machines agreeing to agree. The generator produced
    // canonical text, so nothing was re-spelled on the way.
    expect(await readNotebookSource(holder)).toBe(sharedSource);
    // Arrived and untouched by any run.
    for (let i = 0; i < 2; i++) expect(await cellStatus(holder, i)).toBe("idle");
    expect(await ceremonySlots(holder)).toEqual([]);
  });

  /* ── 4. the deal ─────────────────────────────────────────────────────────── */

  it("splits, deals the holder's share, and keeps exactly its own", async () => {
    await cell(dealer, 0).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(dealer);

    // The dealer's one cell ran and the holder's did not. `declined` rather
    // than `ok` is `cf56628`'s finding standing on a generated notebook: a
    // cell the gate refused must not be drawn as a cell that ran.
    const dealerCells = {};
    for (let i = 0; i < 2; i++) {
      dealerCells[i] = `${await cellStatus(dealer, i)}${
        (await cellErrors(dealer, i)) ? ` — ${await cellErrors(dealer, i)}` : ""
      }`;
    }
    const why = JSON.stringify(dealerCells, null, 1);
    expect(dealerCells[0], why).toBe("ok");
    expect(
      dealerCells[1],
      `the dealer performed the holder's receiving cell — ${why}`
    ).toBe("declined");

    // What the dealer is holding: a digest, and **one share — its own**. Not
    // the secret, and not the set: `random 32` flows into `sss.split` and is
    // never `out`-ed, and the shares flow through the scatter body without
    // stopping, so the only copies anywhere are one per member, each on its
    // member. The three-party suite holds the full argument as finding 4a
    // turned over; this is the same state on the smallest room.
    const held = await ceremonySlots(dealer);
    expect(held).toEqual(["expected", "share"]);
    expect(held, "the master reached a slot").not.toContain("secret");
    expect(held, "the whole set reached a slot").not.toContain("set");
    expect(held).not.toContain("recovered");

    expectedDigest = await reveal(dealer, 0, "expected");
    expect(expectedDigest, "the split wrote no digest of the master").toMatch(
      /^[0-9a-f]{64}$/
    );
  });

  /* ── 5. the holder receives, on a machine that split nothing ─────────────── */

  it("delivers one share to the holder", async () => {
    await cell(holder, 1).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(holder, 1), { timeout: 60000, intervals: [250] })
      .toBe("ok");

    const held = await ceremonySlots(holder);
    // `share-2`, not `share-1`. Slots are numbered by the pairing that fills
    // them — share i to member i in canonical audience order — so the holder,
    // second in the sorted room, was dealt share 2. The dealer's own share is
    // the unnumbered `$share` on their machine, and `$share-1` correctly
    // exists nowhere. `three-party-ceremony.e2e.js` finding 5b is the same
    // rule seen where it mattered most.
    expect(held, "the share did not arrive").toContain("share-2");
    // And nothing the dealer holds. This browser has never run `random`, holds
    // no set, and could not have produced a share of this split by itself.
    expect(held).not.toContain("set");
    expect(held).not.toContain("expected");
  });

  /* ── 6. and the secret comes back, on the machine that never held it ─────── */

  it("writes the recovery at recovery time and recombines away from the dealer", async () => {
    await runSettled(holder);

    // **The recovery picker, on the holder — the machine that never held the
    // secret.** A 2-of-2 needs both shares, so the one contributor to name is
    // the dealer: not a special case, a checkbox, whose generated cell reads
    // the unnumbered `$share` their own deal bound. This is the
    // dealer-present recovery, driven the same way the dealer-absent suite
    // drives the other one.
    await trayTab(holder, "Connections");
    await tray(holder).getByRole("button", { name: "Session", exact: true }).click();
    const sheet = holder.locator("[data-session-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const recovery = holder.locator("[data-room-recovery]");
    await recovery.waitFor({ state: "visible", timeout: 20000 });

    // Everything but "who" is read off the share this machine holds.
    const facts = await recovery.locator("[data-room-recovery-facts]").innerText();
    expect(facts, `the recovery facts: ${facts}`).toContain("share 2 of 2");
    expect(facts).toContain("any 2 recombine");

    await recovery
      .locator(`input[aria-label="Add ${L.dealer} as a contributor"]`)
      .check();
    await expect
      .poll(async () => await recovery.locator("[data-room-recovery-issues]").count(), {
        timeout: 10000,
      })
      .toBe(0);
    await recovery.getByRole("button", { name: /^Write the 2-of-2 recovery$/ }).click();
    await expect
      .poll(async () => await recovery.locator("[data-room-recovery-note='1']").innerText(), {
        timeout: 20000,
      })
      .toContain("2-of-2 recovery");
    await holder.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    recoverySource = await readNotebookSource(holder);
    const rcells = recoverySource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(rcells, recoverySource).toHaveLength(2);
    expect(rcells[0].split("\n")[0]).toBe(`@${L.dealer}`);
    expect(rcells[0]).toContain("$share |");
    expect(rcells[1].split("\n")[0]).toBe(`@${L.holder}`);
    expect(rcells[1]).toContain(`quorum.recv from=${L.dealer}`);
    expect(rcells[1]).toContain("shares with=$share-2");

    // The agreement crosses like any notebook — and the dealer, who has run
    // work to lose, is asked before their deal is replaced by it.
    await trayTab(holder, "Connections");
    await tray(holder).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await holder.locator("[data-notebook-share-note]").innerText(), {
        timeout: 30000,
      })
      .toMatch(/written to 1 open channel · unconfirmed/);
    // The proposal is offered where sharing lives — the Connections tray — so
    // the dealer's is opened to read it, exactly as a person would.
    await trayTab(dealer, "Connections");
    const adopt = dealer.getByRole("button", { name: "Adopt their notebook" });
    await adopt.waitFor({ state: "visible", timeout: 60000 });
    await adopt.click();
    await expect
      .poll(async () => await readNotebookSource(dealer), { timeout: 30000 })
      .toBe(recoverySource);
    // Adopting replaced the notebook, not the machine's values: the dealer's
    // own share is still in `$share`, which is what the send cell reads.
    expect(await ceremonySlots(dealer)).toEqual(["expected", "share"]);

    // The dealer agrees by pressing: their send cell, then the holder's gather.
    await cell(dealer, 0).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(dealer, 0), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await runSettled(dealer);

    await cell(holder, 1).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(holder, 1), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await runSettled(holder);

    const held = await ceremonySlots(holder);
    expect(held).toContain("secret");
    expect(held).toContain("recovered");

    // **This is the assertion the ceremony ships or does not ship on.** A
    // SHA-256 computed on the dealer's machine, of thirty-two bytes that were
    // drawn there and written to no slot, equal to a SHA-256 computed here of
    // what this machine put back together out of two mnemonics that crossed the
    // room. Compared through the screen on both ends, so neither number is one
    // this file worked out.
    const recovered = await reveal(holder, 1, "recovered");
    expect(recovered, "the holder recombined into something else").toBe(expectedDigest);

    // And the secret itself is here, revealable, on the machine that is meant
    // to end up with it. Without this the digest match would only prove the
    // shares agree about a value nobody can spend.
    const secret = await reveal(holder, 1, "secret");
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(secret).not.toBe(recovered);
    // Never on the dealer. Recovery happens away from the machine that made the
    // secret, which is the property that makes the split worth anything: the
    // secret survives the dealer.
    expect(await ceremonySlots(dealer)).not.toContain("secret");
  }, 300_000);

  /* ── 7. the notebook is the ceremony, and the run reaches its end ────────── */

  it("holds the recovery both machines agreed to, and one live exchange", async () => {
    // Both machines end on the recovery notebook — the dealer because they
    // adopted it, by a press, with their deal replaced only after they were
    // asked. Two agreements existed; the second is the one both parties to it
    // are holding, and every cell of it settled without an error.
    for (const page of [dealer, holder]) {
      const source = await readNotebookSource(page);
      expect(source).toBe(recoverySource);
      expect(await page.locator("article").count()).toBe(2);
      const settled = {};
      for (let i = 0; i < 2; i++) settled[i] = await cellStatus(page, i);
      expect(Object.values(settled), JSON.stringify(settled)).not.toContain("error");
    }

    // The refusal itself is not weakened and has not moved: `execQuorumOpen`
    // still declines a second exchange, and `quorum-lifecycle.test.js` is where
    // that sentence is pinned. What is checked here is the consequence a
    // browser can see — exactly one exchange, still verified, on both ends. A
    // change that opened a second one behind the reader's back would show.
    for (const page of [dealer, holder]) {
      await trayTab(page, "Connections");
      expect(await tray(page).locator('[data-verified="1"]').count()).toBe(1);
    }
  });

  /* ── what the journey cost ───────────────────────────────────────────────── */

  it("drove a generated notebook without tripping the production CSP", async () => {
    expect(await fx.peers[0].cspViolations()).toEqual([]);
    expect(await fx.peers[1].cspViolations()).toEqual([]);
    expect(fx.tunnelFaults()).toEqual([]);
    expect(room.faults()).toEqual([]);
  });
});
