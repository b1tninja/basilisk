/**
 * The notebook reaches a peer who was not in the room when Share was pressed.
 *
 * ## The reported failure, and why every suite was green through it
 *
 * `placed-journey.e2e.js` walks the whole road a person walks and never sees
 * this, because it walks it in the one order that works: the joiner is meshed
 * and verified *before* step 4 presses Share. The owner's order is the other
 * one, and it is the order a person actually reaches by accident — you open a
 * session, the button is right there, you press it, and the person you sent the
 * link to opens it a minute later. At the press there is nobody verified, so
 * `_publishDocument` writes to nobody and says so honestly; at the join there
 * was nothing that re-sent. The notebook was never given to the joiner, and
 * neither end was told that is the state they were in.
 *
 * Running did not repair it either, which is what the owner expected to work: a
 * run offers *cells*, and every one of them is checked against a manifest
 * derived from the receiving notebook — which is empty, so each is refused as a
 * notebook this peer has not seen. The refusal is correct and names the true
 * state; there was simply no way out of it.
 *
 * This is `d1e8b0f`'s defect in a second place. The invite had exactly this
 * shape — published once, into a room the recipient had not reached — and grew
 * `knock`/`_invited` to answer it. The notebook proposal never did.
 *
 * ## What is asserted, and at which hop
 *
 * The **receiving browser's own Source view**. Not that a frame was sent, not a
 * count, not a note on the dealer's panel: those were all true on the day the
 * bug was reported. The only thing that was false is the text in the joiner's
 * notebook, so that is what is polled.
 *
 * ## Why three browsers
 *
 * Two would prove the delivery and could not prove the thing that makes the
 * delivery safe. The hard case is a *second* newcomer arriving after the dealer
 * has typed past what they signed, and in a room of two there is nobody left to
 * be that person — the one joiner has already been given the notebook, and a
 * reloaded browser is not a newcomer to the dealer's session (a peer whose page
 * went away never fires `onclose`, so the record of having written to them
 * stands, which is a limit this product states elsewhere rather than a gap
 * here). Three members is also simply what the situation is: a room that is
 * already working on something, and somebody else turning up.
 *
 * So the file walks one room through both orderings:
 *
 *  - **Share, then B joins.** The retained proposal is delivered when B
 *    verifies. That is the reproduction, and it is the assertion that was
 *    failing before this work: `expected '' to be 'bytes deadbeef …'`.
 *  - **Share, edit, then C joins.** The retention is retired the moment the
 *    dealer's text moves, so C receives nothing — delivering the older text
 *    would land silently in C's empty notebook and leave two people believing
 *    they had agreed on a notebook only one of them held. Nothing arrives, and
 *    the *dealer* is told, by name, with a remedy that is one press away.
 *
 * The second is the more important of the two. It is easy to make a late joiner
 * receive something; the question is whether what they receive is a notebook a
 * person pressed Share on and is still holding.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the late-share suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[notebook-late-share.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * One cell, and nothing placed on anybody.
 *
 * Placement is `placed-journey.e2e.js`'s subject and would only add ways for
 * this file to fail for reasons that are not about *when* the notebook travels.
 * What matters is that the text is distinctive enough that finding it in
 * somebody else's editor cannot be an accident.
 */
const CELL_0 = "bytes deadbeef | encode hex | out $seed";
/** What the dealer types *after* pressing Share. */
const CELL_0_EDITED = "bytes c0ffee | encode hex | out $seed";

/** The session tray, as a scope — `placed-journey.e2e.js`'s locator and reason. */
const tray = (page) => page.locator('[aria-label="Session tray"]').locator("xpath=..");

/** Open one of the tray's tabs and wait for it to be the selected one. */
async function trayTab(page, name) {
  const tab = tray(page).getByRole("tab", { name, exact: true });
  await tab.click();
  await expect
    .poll(async () => await tab.getAttribute("aria-selected"), { timeout: 10000 })
    .toBe("true");
}

/**
 * Type a pipeline into a cell, the way the Source view takes one.
 *
 * **Applies on blur**, so the `blur()` is the act and not a tidy-up — without
 * it the text sits in `rawDrafts` and never reaches the notebook this file is
 * about, nor the effect that retires the retention.
 */
async function writeCell(page, i, text) {
  const art = page.locator("article").nth(i);
  await art.locator("button").filter({ hasText: /^Source$/ }).click();
  const box = art.locator("textarea");
  await box.waitFor({ state: "visible", timeout: 10000 });
  await box.fill(text);
  await box.blur();
}

/** Put a key this fixture already holds into a page's vault, and reload onto it. */
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

/** Whatever the share panel last said about a press, or "" when it has said nothing. */
async function shareNote(page) {
  const p = page.locator("[data-notebook-share-note]");
  return (await p.count()) ? (await p.innerText()).trim() : "";
}

/**
 * What the panel says about peers this browser has not given its notebook to.
 *
 * A separate node from the note on purpose: the note is the outcome of the last
 * press and this is a standing fact about the room. Collapsing them would mean
 * either erasing the answer to something the reader just did, or letting a
 * stale press stand in for the state of the room.
 */
async function unsharedLine(page) {
  const p = page.locator("[data-notebook-unshared]");
  return (await p.count()) ? (await p.innerText()).trim() : "";
}

/**
 * What the panel says about peers who have said they are holding a notebook.
 *
 * The other end of `unsharedLine`, and the reason this file grew a fifth
 * locator: the dealer's warning had no counterpart, so the person who was
 * actually stuck — a newcomer with an empty notebook in a room that has one —
 * learned nothing until a cell they were handed was refused.
 */
async function heldLine(page) {
  const p = page.locator("[data-notebook-held]");
  return (await p.count()) ? (await p.innerText()).trim() : "";
}

/** How many peers this browser has key-confirmed, off its own Connections roster. */
async function verifiedCount(page) {
  await trayTab(page, "Connections");
  return await tray(page).locator('[data-verified="1"]').count();
}

describe.runIf(availability.ok)("a notebook shared before the room had filled up", () => {
  /** @type {any} */ let room;
  /** @type {any} */ let fx;
  /** @type {(() => Promise<void>)|null} */ let closeMesh = null;
  /** @type {import("playwright").Page} */ let dealer;
  /** @type {import("playwright").Page} */ let early;
  /** @type {import("playwright").Page} */ let late;
  /** @type {string} */ let origin = "";
  /** The dealer's own address bar after Start. Nothing else crosses between pages. */
  let inviteUrl = "";
  /** Each member's fingerprint, as the room's canonical audience orders them. */
  let L = { dealer: "", early: "", late: "" };

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
    L = {
      dealer: room.members[0].fpr,
      early: room.members[1].fpr,
      late: room.members[2].fpr,
    };
    dealer = fx.peers[0].page;
    early = fx.peers[1].page;
    late = fx.peers[2].page;
  }, 240_000);

  afterAll(async () => {
    if (closeMesh) await closeMesh();
    else if (fx) await fx.close();
  });

  /* ── 1. a notebook, and a room with one person in it ─────────────────────── */

  it("opens a session with a notebook in it and nobody to send it to", async () => {
    await dealer.goto(`${origin}/toolkit`, { waitUntil: "load" });
    await becomeMember(dealer, room.members[0], "Dealer <dealer@late.test>");

    await writeCell(dealer, 0, CELL_0);
    expect(await readNotebookSource(dealer)).toBe(CELL_0);

    const sheet = dealer.locator("[data-session-sheet]");
    await dealer.evaluate((h) => {
      window.location.hash = h;
    }, `#j=${room.audience.join(",")}`);
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    await dealer.getByRole("button", { name: "I am starting it" }).click();
    await dealer.locator("[data-session-key] select").selectOption(L.dealer);
    const start = dealer.getByRole("button", { name: "Start shared session" });
    await expect.poll(async () => await start.isEnabled(), { timeout: 15000 }).toBe(true);
    await start.click();

    // The room is open and empty. `waiting-peer` is the run bar's own word for
    // it, and it is the state in which Share is sitting there looking pressable
    // — which is the whole reason this ordering happens to people.
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
    // The invite carries the audience and no recipe, which is why the notebook
    // has to travel over the session at all. `fragment.js` argues that at
    // length; here it is the premise the rest of the file rests on.
    expect(new URL(inviteUrl).hash).not.toContain("r=");
  });

  /* ── 2. Share, pressed into an empty room ────────────────────────────────── */

  it("refuses the press honestly, naming the room and not the notebook", async () => {
    await trayTab(dealer, "Connections");
    await tray(dealer).getByRole("button", { name: "Share this notebook" }).click();
    // The refusal was already right on the day this was reported: it names the
    // state that is true (nobody is verified), does not blame the notebook, and
    // offers a remedy that can be performed. None of that changes. What changes
    // is that the press was not wasted.
    await expect
      .poll(async () => await shareNote(dealer), { timeout: 20000 })
      .toMatch(/Nobody in this room has a confirmed channel yet/);
    expect(await readNotebookSource(dealer)).toBe(CELL_0);
    // Nobody is verified, so there is nobody to report as empty either. The
    // line must not fire on a room that has not filled up — that would be a
    // warning about every session in its first seconds.
    expect(await unsharedLine(dealer)).toBe("");
  });

  /* ── 3. the first peer arrives, through the link, after the press ────────── */

  it("hands the late joiner the notebook the press was made on", async () => {
    await early.goto(inviteUrl, { waitUntil: "load" });
    await becomeMember(early, room.members[1], "Early <early@late.test>");
    await early.goto(inviteUrl, { waitUntil: "load" });
    await early.waitForSelector(".toolkit-shell", { timeout: 30000 });

    const sheet = early.locator("[data-session-sheet]");
    const start = early.locator("[data-session-start]");
    await start.waitFor({ state: "visible", timeout: 20000 });
    expect(await start.getAttribute("data-session-start")).toBe("join");

    // Empty before Join, and it is the emptiness the rest of this file is
    // about. Read with the sheet dismissed, because the sheet is a modal and a
    // person cannot see their own notebook while it is up.
    await early.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });
    expect(await readNotebookSource(early)).toBe("");

    await trayTab(early, "Connections");
    await tray(early).getByRole("button", { name: "Start session" }).click();
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    await early.locator("[data-session-key] select").selectOption(L.early);
    const join = early.getByRole("button", { name: "Join shared session" });
    await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
    await join.click();
    await sheet.waitFor({ state: "hidden", timeout: 20000 });

    await expect.poll(async () => await verifiedCount(dealer), { timeout: 120000, intervals: [500] }).toBe(1);
    await expect.poll(async () => await verifiedCount(early), { timeout: 120000, intervals: [500] }).toBe(1);

    // **The assertion, at the hop that matters.** Every weaker one was true
    // while this was broken: a frame had been sent (to nobody), the dealer's
    // panel had a note on it, both rosters said verified. The one false thing
    // was this string, and before this work it read `''`.
    await expect
      .poll(async () => await readNotebookSource(early), { timeout: 60000, intervals: [250] })
      .toBe(CELL_0);

    // Adopted without a press, which is `decideProposal`'s existing rule rather
    // than anything this change relaxed: a notebook with no work in it has no
    // work to lose. Nobody is asked because there was nothing to ask about.
    expect(
      await early.locator("[data-notebook-proposed]").count(),
      "the joiner was asked to adopt into a notebook they had never typed in"
    ).toBe(0);

    // Nobody is holding nothing, so neither panel says anybody is. On the
    // dealer that is because the delivery happened; on the receiver it is
    // because the one peer they can see is the peer this text came *from*, and
    // telling somebody that the person who just sent them a notebook does not
    // have it is how readers learn to stop reading warnings.
    expect(await unsharedLine(dealer)).toBe("");
    expect(await unsharedLine(early)).toBe("");
  });

  /* ── 4. the dealer types, and a second newcomer arrives ──────────────────── */

  it("delivers nothing stale, and tells the dealer who is holding nothing", async () => {
    // The moment the retention stops being honest. What was signed is a
    // revision behind what is on screen, and the session is told to stop
    // holding it — by the editor, because the session holds a signed document
    // and cannot see the text.
    await writeCell(dealer, 0, CELL_0_EDITED);
    expect(await readNotebookSource(dealer)).toBe(CELL_0_EDITED);

    await late.goto(inviteUrl, { waitUntil: "load" });
    await becomeMember(late, room.members[2], "Late <late@late.test>");
    await late.goto(inviteUrl, { waitUntil: "load" });
    await late.waitForSelector(".toolkit-shell", { timeout: 30000 });

    const sheet = late.locator("[data-session-sheet]");
    const start = late.locator("[data-session-start]");
    await start.waitFor({ state: "visible", timeout: 20000 });
    await late.locator("[data-session-key] select").selectOption(L.late);
    const join = late.getByRole("button", { name: "Join shared session" });
    await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
    await join.click();
    await sheet.waitFor({ state: "hidden", timeout: 20000 });

    await expect.poll(async () => await verifiedCount(dealer), { timeout: 120000, intervals: [500] }).toBe(2);

    // **The stale text did not arrive**, and this is asserted first so that a
    // build which delivers it fails saying *that* rather than saying a warning
    // is missing. Key confirmation has just completed on both ends, which is
    // the instant `_deliverSharedNotebook` fires; a retention that outlived the
    // dealer's edit lands here within milliseconds. The wait is for the absence
    // — there is no event for "nothing was sent" to poll on.
    //
    // Delivering it would have left the newcomer adopting — silently, since
    // their notebook is empty and `decideProposal` correctly asks nobody — a
    // notebook the dealer is no longer holding. Two people would believe they
    // had agreed, and every cell handed across would be refused by a digest
    // gate neither of them could see the reason for.
    await late.waitForTimeout(3000);
    expect(await readNotebookSource(late)).toBe("");
    expect(await readNotebookSource(late)).not.toContain("deadbeef");

    // **The dealer is told, by name.** This is the state nothing surfaced: a
    // person in the room holding no notebook, with the dealer having no way to
    // know and the newcomer having nothing to ask about. The remedy named is
    // one press, and the button is on the same panel.
    await expect
      .poll(async () => await unsharedLine(dealer), { timeout: 60000, intervals: [500] })
      .toMatch(/has not been given this notebook/);
    // Whole keys. A line telling somebody which peer to act about is the last
    // place to print part of who they are.
    expect((await unsharedLine(dealer)).replace(/\s/g, "")).toContain(L.late);
    expect(await unsharedLine(dealer)).not.toContain("…");
    // And it names the newcomer only. The early joiner *was* given this
    // browser's notebook, and naming them as well would make the sentence
    // useless the moment a room has more than two people in it.
    expect((await unsharedLine(dealer)).replace(/\s/g, "")).not.toContain(L.early);

    // Nor did the *early* joiner re-broadcast the copy they adopted. They never
    // pressed Share, and a peer who receives a notebook does not thereby become
    // a sender of it — what leaves a machine leaves because somebody there
    // pressed something.
    expect(await unsharedLine(late)).toBe("");
  });

  /* ── 4b. and the newcomer is told, from the other side ───────────────────── */

  it("tells the newcomer a notebook exists here, and nothing about it", async () => {
    // **The gap `4027326` stated and left open.** Everything above this line was
    // already true on the day it shipped: the stale text stayed put, the dealer
    // was warned. The person the situation was actually happening to was told
    // nothing, and would next learn of it when a cell they were offered came
    // back refused as a notebook they had not seen.
    await trayTab(late, "Connections");
    await expect
      .poll(async () => await heldLine(late), { timeout: 60000, intervals: [500] })
      .toMatch(/has a notebook and has not sent it here/);

    // Whole key, for the reason the dealer's line uses one: this is the line
    // that says who to go and ask.
    expect((await heldLine(late)).replace(/\s/g, "")).toContain(L.dealer);
    expect(await heldLine(late)).not.toContain("…");

    // **The disclosure is the bare fact and the browser is where that is
    // provable.** No title, no digest, no cell count reached this page — the
    // frame carries a kind and a clock — so there is nothing on this screen for
    // a reader to mistake for the notebook, and nothing for a listener with a
    // guess at the text to check the guess against.
    const said = await heldLine(late);
    expect(said).not.toContain("deadbeef");
    expect(said).not.toContain("c0ffee");
    expect(said).toContain("Nothing here says what is in it");
    // And the newcomer's own notebook is still empty: being told one exists is
    // not being given one.
    expect(await readNotebookSource(late)).toBe("");

    // **The remedy named is the one that can be performed, and it is not here.**
    // Only the sender can send a notebook, so the sentence says to ask them
    // rather than offering a control whose whole effect would be to make the
    // reader think they had done something.
    expect(said).toMatch(/Ask them to share it/);

    // **The two ends do not contradict each other.** The dealer says this peer
    // has not been given the notebook; the peer says the dealer has one they
    // have not sent. Both halves are drawn from one predicate, so a room cannot
    // end up with one end warning and the other reassured.
    expect((await unsharedLine(dealer)).replace(/\s/g, "")).toContain(L.late);
    expect(await heldLine(dealer)).toBe("");

    // The early joiner is told nothing, on both counts. They *were* given this
    // notebook, so the dealer never announces to them; and they never pressed
    // Share themselves, so they announce to nobody. A warning that fired on the
    // half of the room that is working correctly is how readers learn to stop
    // reading warnings.
    expect(await heldLine(early)).toBe("");
    expect(await heldLine(late)).not.toContain(L.early);
  });

  /* ── 5. the remedy the line names is the one that works ──────────────────── */

  it("sends the notebook now on screen when the dealer presses Share again", async () => {
    await trayTab(dealer, "Connections");
    await tray(dealer).getByRole("button", { name: "Share this notebook" }).click();

    // Both peers end up holding what the dealer is holding — the newcomer for
    // the first time, and the early joiner brought forward from the revision
    // they adopted. A second press is a second act of consent over different
    // text, and it reaches everybody who is verified.
    for (const page of [early, late]) {
      await expect
        .poll(async () => await readNotebookSource(page), { timeout: 60000, intervals: [250] })
        .toBe(CELL_0_EDITED);
    }
    // The line retires itself once it has stopped being true.
    await expect.poll(async () => await unsharedLine(dealer), { timeout: 20000 }).toBe("");
    // And so does the newcomer's, because what made it true has stopped being
    // true: the notebook arrived. Cleared by the arrival rather than by a
    // retraction frame — a peer that had to remember to un-say it could forget.
    await expect.poll(async () => await heldLine(late), { timeout: 60000 }).toBe("");
  });

  /* ── 6. the note stops being a count of writes ───────────────────────────── */

  it("says which peers acknowledged, on the press that reached them", async () => {
    // **What `7ac9f50` could not write, and said so.** The note read `written
    // to 2 open channels · unconfirmed` permanently, because a notebook left
    // through `_publishDocument` as a sealed document frame and nothing
    // acknowledged it — so "reached 1 of 2" would have been an invented
    // acknowledgment. `notebook-ack` is that acknowledgment, and this is the
    // sentence it buys.
    //
    // Polled on the *dealer's* panel after the step-5 press, and read at the
    // hop that matters: the receiving browsers above are already provably
    // holding the text, so a note that still said `unconfirmed` here would be a
    // sender who never learned it.
    await trayTab(dealer, "Connections");
    await expect
      .poll(async () => await shareNote(dealer), { timeout: 60000, intervals: [500] })
      .toMatch(/reached [0-9A-F]{40}'s session \d\d:\d\d:\d\d/);

    const note = await shareNote(dealer);
    // Both peers, by whole fingerprint. A note that named one and dropped the
    // other would let a single arrival stand in for the room.
    for (const fpr of [L.early, L.late]) {
      expect(note.replace(/\s/g, ""), `the note says nothing about ${fpr}`).toContain(fpr);
    }
    expect(note).not.toContain("…");
    // The wire fact survives intact beside the arrival. A channel stays open
    // here when the browser at the far end is gone, so the count is still a
    // count of writes and the note still says why that is not delivery.
    expect(note).toMatch(/written to 2 open channels/);
    expect(note).toMatch(/A write is not an arrival/);
    // And the sentence that is no longer true is gone from the product.
    expect(note).not.toContain("Nothing acknowledges a notebook");
  });
});
