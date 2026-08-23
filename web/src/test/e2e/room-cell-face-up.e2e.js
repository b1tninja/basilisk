/**
 * A peer's cell finishes and the slot it names is *here* — the face-up row, in
 * a browser.
 *
 * ## The gap this closes
 *
 * `RoomCells.tsx` draws three states and `cell-state.js` holds the model for
 * them: **not dealt** (no row), **face down** (the slot is named and it is
 * somebody else's), and **face up** (the slot is named and this machine holds
 * it). Two of the three were pinned end to end and the third was not.
 *
 * The reason is structural rather than an oversight. The face-up branch needs
 * a peer to announce a slot label *this* machine also holds, and the room
 * ceremony cannot produce one: `room-ceremony.js` numbers the share slots per
 * member — `$share` on the dealer, `$share-2` / `$share-3` on the holders —
 * precisely so that two cells of one document never write one label, which is
 * a rule the compiler enforces anyway (`Duplicate out slot $share`). So every
 * row `three-party-ceremony.e2e.js` can observe is legitimately face down, and
 * its step 4 asserts exactly that. The up branch was pinned only in node, by
 * `cell-state.test.js`, against a `hasSlot` predicate the test wrote itself.
 *
 * ## What actually makes a row face up, worked out rather than assumed
 *
 * Three things have to be true at once, and each of them is somewhere
 * different:
 *
 * 1. **The peer must have pressed Share.** `announceCellState` gates on
 *    `_sharedEver`, which only `shareNotebook` sets — so a machine that
 *    *received* a notebook and never offered one announces nothing at all.
 *    That is why the holders in the ceremony suites are silent and only the
 *    dealer's rows ever appear.
 * 2. **The peer's cell must write a slot label.** `announceCell` sends
 *    `run.record.cells[i].writes`, and only for `done`.
 * 3. **This machine must hold that same label**, asked of the *live slot
 *    registry* at the moment of drawing — never of the announcement.
 *
 * (1) and (3) together are what the ceremony cannot reach: its announcer is
 * the dealer, and the dealer's labels are the two nobody else has. What can
 * reach it is the plainest notebook in the product — **a cell with no `@peer`
 * header**. `planRun` reads an unplaced cell as everybody's (`runsOn.length
 * === 0 ? true`), so both machines run it, both write the same label, and one
 * of them has pressed Share. Nothing here is exotic: a notebook with no
 * placement in it is what a person writes before they have thought about
 * placement at all.
 *
 * ## The three beats, and why the order is the assertion
 *
 * One cell, run three times across two browsers, because the interesting facts
 * are all about *when* possession is asked rather than about the row's markup:
 *
 * - **The creator runs it while the joiner holds nothing.** Face down. This is
 *   the state the ceremony suites already cover, and it is here as the control
 *   for the flip below — without it, a row that was face up from the first
 *   paint would pass every assertion in the next beat.
 * - **The joiner runs the same cell.** No frame crosses. The row turns face up
 *   anyway, because `peerCellRows` re-derives faces from `slotMetas` and
 *   possession is this machine's registry answering. A row that only turned
 *   over when a peer said something would still be face down here — and that
 *   is the failure mode the whole "asked of the registry, never of the
 *   announcement" argument exists to prevent.
 * - **The creator runs it again, with the slot already held here.** Now the
 *   announcement *arrives* into a machine that holds the label, so
 *   `describeCellState`'s up branch reaches the live region and says `$tally is
 *   here.` That sentence had never been produced in a browser.
 *
 * ## And the consent gate, from the other side
 *
 * The joiner runs the same cell twice and the creator's table stays empty for
 * the whole file. That is not an absence of coverage, it is the coverage: the
 * joiner never pressed Share, so `_sharedEver` is false on that end and there
 * is no announcement to make. Asserted, because a gate that stopped firing
 * would otherwise show up as extra rows nobody looked at.
 *
 * ## What this file deliberately does not settle
 *
 * `cell-state.js` describes face up as "this machine holds the slot, **because
 * a value actually arrived**", and the code it describes checks only the first
 * half: `hasSlot(label)`, asked of the local registry. Those two are the same
 * claim on the road the ceremony walks — a holder's `$share-2` can only have
 * come from the dealer — and they come apart on the road this file walks, where
 * both machines wrote the label themselves. `CELL` is deterministic so that
 * this file never has to have an opinion about the gap: `deadbeef` is the same
 * value on both ends, so "$tally here" is true under either reading of the
 * word. The gap itself is reported rather than pinned here, because narrowing
 * it is a product decision and this is a test.
 *
 * Nothing crosses between the two contexts in a variable — `placed-journey`'s
 * rule. The joiner learns the notebook from the wire and the room from the
 * address bar.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the face-up suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[room-cell-face-up.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * The notebook, whole: one cell, no header, one slot.
 *
 * **Deterministic on purpose.** `bytes deadbeef` is the same thirty-two bits on
 * both machines, so when the row goes face up the label *and* the value agree
 * — there is no reading of this test in which "here" is a coincidence of
 * naming. A `random` source would have made the face-up row true and the story
 * behind it murkier.
 *
 * **Unplaced on purpose**, which is the mechanism the whole file rests on: a
 * cell with no `@peer` header is `mine` on every machine in the room, so both
 * ends write `$tally` and the compiler never sees the duplicate `out` that a
 * two-cell spelling of the same idea would be refused for.
 */
const CELL = "bytes deadbeef | encode hex | out $tally";

/** What both machines compute, and therefore what neither of them is told. */
const TALLY = "deadbeef";

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

/**
 * Type a pipeline into a cell, the way the Source view takes one.
 *
 * `placed-journey.e2e.js`'s helper, and its correction with it: the text
 * applies **on blur**, so the `blur()` is the act rather than a tidy-up —
 * without it the draft never reaches `chains` and every assertion below would
 * be about a notebook the shell does not have.
 */
async function writeCell(page, i, text) {
  const art = cell(page, i);
  await art.locator("button").filter({ hasText: /^Source$/ }).click();
  const box = art.locator("textarea");
  await box.waitFor({ state: "visible", timeout: 10000 });
  await box.fill(text);
  await box.blur();
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

/**
 * Which slots one machine holds, as the Slots tab prints them.
 *
 * Filtered to the one this notebook writes, so a session slot appearing beside
 * it later cannot turn an equality into a maintenance burden.
 */
async function tallySlots(page) {
  await trayTab(page, "Slots");
  const out = [];
  for (const text of await tray(page).locator("li code").allInnerTexts()) {
    if (/^@tally$/.test(text.trim())) out.push(text.trim().slice(1));
  }
  return out;
}

/**
 * Every face this machine draws for one peer's cell, as `{ slot: "up"|"down" }`.
 *
 * Read off the row rather than out of the panel text, because the copy and the
 * state are two facts: `data-room-cell-face` is what the component decided and
 * the sentence beside it is what a person is told, and a change that moved one
 * without the other is exactly the sort of drift worth failing on. Both are
 * asserted at each beat.
 */
async function facesOf(page, peerFpr, index) {
  const row = page.locator(
    `[data-room-cell][data-room-cell-peer="${peerFpr}"][data-room-cell-index="${index}"]`
  );
  const out = {};
  for (const face of await row.locator("[data-room-cell-slot]").all()) {
    out[await face.getAttribute("data-room-cell-slot")] =
      await face.getAttribute("data-room-cell-face");
  }
  return out;
}

/** The row itself, for the assertions that are about what it says. */
const rowOf = (page, peerFpr, index) =>
  page.locator(
    `[data-room-cell][data-room-cell-peer="${peerFpr}"][data-room-cell-index="${index}"]`
  );

/**
 * Start watching one machine's live region, keeping every distinct line.
 *
 * `three-party-ceremony.e2e.js`'s observer, narrowed to the region: the table
 * is polled directly here because this file's question is about *states* rather
 * than about transitions, while the region has no history at all — it holds one
 * line, replaced in place, so a read after the fact sees only the last thing
 * said and the sentence this file is hunting for would be gone.
 */
async function watchSaid(page) {
  await page.evaluate(() => {
    /** @type {string[]} */
    const said = [];
    const region = document.querySelector("[data-run-announcer]");
    const read = () => {
      const t = (region?.textContent || "").replace(/\s+/g, " ").trim();
      if (t && said[said.length - 1] !== t) said.push(t);
    };
    read();
    const obs = new MutationObserver(read);
    obs.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      characterData: true,
    });
    Object.assign(window, { __said: said, __saidStop: () => obs.disconnect() });
  });
}

/** What the live region has said so far, without stopping the observer. */
const saidSoFar = (page) => page.evaluate(() => [...window.__said]);

/**
 * Only the lines that are *about a peer's cell*.
 *
 * One region carries everything the shell says out loud — the run's own
 * verdict ("Done"), its progress, delivery acknowledgments — and this file's
 * claims are all about one kind of sentence among them. Filtered on the two
 * things `describeCellState` always writes, the whole fingerprint and the cell,
 * rather than on a negative list: a new announcement added beside these must
 * not be able to turn "the region did not move" into a failure, and must not be
 * able to stand in for one of these either.
 */
const saidAboutCells = async (page, peerFpr) =>
  (await saidSoFar(page)).filter((s) => s.includes(peerFpr) && /\bcell \d+\b/.test(s));

/** Stop watching. */
const stopSaid = (page) => page.evaluate(() => window.__saidStop());

describe.runIf(availability.ok)("a peer's cell writes a slot this machine holds", () => {
  /** @type {any} */ let room;
  /** @type {any} */ let fx;
  /** @type {(() => Promise<void>)|null} */ let closeMesh = null;
  /** The machine that composes, shares, and therefore announces. */
  /** @type {import("playwright").Page} */ let creator;
  /** The machine that receives the notebook and never shares one. */
  /** @type {import("playwright").Page} */ let joiner;
  /** @type {string} */ let origin = "";
  /** Whole fingerprints. */
  let L = { creator: "", joiner: "" };
  /** The URL the creator's own address bar held after Start. Nothing else crosses. */
  let inviteUrl = "";
  /** The notebook, as the creator's own Source view prints it. */
  let source = "";

  beforeAll(async () => {
    room = await createQuorumRoom();
    const mesh = await openMesh(room);
    if (!mesh.ok) {
      throw new Error(`local Web PubSub hub did not start (${mesh.kind}): ${mesh.reason}`);
    }
    closeMesh = mesh.close;
    fx = mesh.fx;
    origin = fx.origin;
    expect(fx.peers).toHaveLength(2);
    L = { creator: room.members[0].fpr, joiner: room.members[1].fpr };
    expect(L.creator).not.toBe(L.joiner);
    creator = fx.peers[0].page;
    joiner = fx.peers[1].page;
  }, 180_000);

  afterAll(async () => {
    if (closeMesh) await closeMesh();
    else if (fx) await fx.close();
  });

  /* ── 1. a notebook with nobody's name on it ──────────────────────────────── */

  it("composes one cell and places it on nobody", async () => {
    await creator.goto(`${origin}/toolkit`, { waitUntil: "load" });
    // The one evaluate, and the reason the sibling suites give for it: there is
    // no import UI for a key this fixture already holds, and the key has to be
    // one the room's keyserver can hand out.
    await becomeMember(creator, room.members[0], "Creator <creator@faceup.test>");

    const sheet = creator.locator("[data-session-sheet]");
    await creator.evaluate((h) => {
      window.location.hash = h;
    }, `#j=${room.audience.join(",")}`);
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    await creator.getByRole("button", { name: "I am starting it" }).click();
    await creator.locator("[data-session-key] select").selectOption(L.creator);
    await creator.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    await writeCell(creator, 0, CELL);
    source = await readNotebookSource(creator);

    // **No header, and that is the mechanism rather than an omission.** An
    // unplaced cell is `mine` on every machine in the room, which is the only
    // way two peers in one document come to write one slot label — the
    // compiler refuses a second `out $tally` anywhere in the text, so the
    // obvious spelling (a cell each, both writing `$tally`) does not compile.
    expect(source, `the notebook: ${source}`).not.toMatch(/^@/m);
    expect(source).toContain("out $tally");
    expect(source.split(/\n\s*\n+/).filter((c) => c.trim())).toHaveLength(1);
    // It compiles for the person, read off the control rather than out of the
    // compiler.
    expect(
      await creator.getByRole("button", { name: "Run all" }).getAttribute("aria-disabled")
    ).toBe(null);
    expect(await cellStatus(creator, 0)).toBe("idle");
    expect(await tallySlots(creator)).toEqual([]);
  });

  /* ── 2. two browsers, one room ───────────────────────────────────────────── */

  it("meshes the room and carries the notebook to a joiner who had none", async () => {
    await trayTab(creator, "Connections");
    await tray(creator).getByRole("button", { name: "Start session" }).click();
    const sheet = creator.locator("[data-session-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const start = creator.getByRole("button", { name: "Start shared session" });
    await expect.poll(async () => await start.isEnabled(), { timeout: 15000 }).toBe(true);
    await start.click();
    await expect
      .poll(
        async () => await creator.locator("[data-run-state]").getAttribute("data-run-state"),
        { timeout: 60000, intervals: [250] }
      )
      .toBe("waiting-peer");

    await expect
      .poll(async () => await creator.evaluate(() => window.location.hash), { timeout: 20000 })
      .toMatch(/^#j=/);
    inviteUrl = creator.url();

    await joiner.goto(inviteUrl, { waitUntil: "load" });
    await becomeMember(joiner, room.members[1], "Joiner <joiner@faceup.test>");
    const joinPanel = joiner.locator("[data-session-start]");
    await joinPanel.waitFor({ state: "visible", timeout: 20000 });
    expect(await joinPanel.getAttribute("data-session-start")).toBe("join");
    await joiner.locator("[data-session-key] select").selectOption(L.joiner);
    const join = joiner.getByRole("button", { name: "Join shared session" });
    await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
    await join.click();
    await joiner.locator("[data-session-sheet]").waitFor({ state: "hidden", timeout: 20000 });

    for (const page of [creator, joiner]) {
      await trayTab(page, "Connections");
      await expect
        .poll(async () => await tray(page).locator('[data-verified="1"]').count(), {
          timeout: 120000,
          intervals: [500],
        })
        .toBe(1);
    }
    await runSettled(creator);
    await runSettled(joiner);

    // **The Share press is what unlocks every row in this file.**
    // `announceCellState` refuses before `_sharedEver`, and only `shareNotebook`
    // sets it — so this is not merely how the joiner gets the text, it is the
    // consent the announcements below ride on.
    await trayTab(creator, "Connections");
    await tray(creator).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await creator.locator("[data-notebook-share-note]").innerText(), {
        timeout: 30000,
      })
      .toMatch(/written to 1 open channel · reached [0-9A-F]{40}'s session \d\d:\d\d:\d\d/);

    // No press on the far end: an empty notebook is nothing to lose, so
    // `decideProposal` adopts without asking.
    await expect
      .poll(async () => await readNotebookSource(joiner), { timeout: 60000 })
      .toBe(source);
    expect(await cellStatus(joiner, 0)).toBe("idle");
    expect(await tallySlots(joiner)).toEqual([]);

    // Nothing has been said about any cell, on either machine, and the panel
    // says which of the two things that means.
    for (const page of [creator, joiner]) {
      await trayTab(page, "Connections");
      const table = page.locator("[data-room-cells]");
      await table.waitFor({ state: "visible", timeout: 20000 });
      expect(await table.locator("[data-room-cell]").count()).toBe(0);
      expect(await table.innerText()).toContain("Nobody has said they are running anything");
    }
  }, 300_000);

  /* ── 3. face down: the ceremony's state, as the control for the flip ─────── */

  it("draws the creator's slot face down on a machine that does not hold it", async () => {
    await trayTab(joiner, "Connections");
    // Only the joiner's region is watched: it is the only end that ever
    // receives one of these, because the creator is the only end that shares.
    await watchSaid(joiner);

    await cell(creator, 0).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(creator, 0), { timeout: 60000, intervals: [250] })
      .toBe("ok");
    await runSettled(creator);
    expect(await tallySlots(creator)).toEqual(["tally"]);

    const row = rowOf(joiner, L.creator, 0);
    await expect
      .poll(async () => await row.getAttribute("data-room-cell-state"), {
        timeout: 60000,
        intervals: [250],
      })
      .toBe("done");

    // The joiner has run nothing, so the label exists somewhere else. This is
    // the same state `three-party-ceremony.e2e.js` step 4 pins for the dealer's
    // two slots, and it is here as the *control*: a row that were face up from
    // its first paint would make the next step's assertion vacuous.
    expect(await tallySlots(joiner)).toEqual([]);
    // Back to Connections, because reading the Slots tab moved the tray: the
    // two panels are tabs of one tray and only the selected one is in the DOM,
    // so a face read straight after a slot read is a face read off a panel that
    // is not there. It answers `{}` rather than failing, which is the shape of
    // a test that passes for the wrong reason the day the row goes missing.
    await trayTab(joiner, "Connections");
    expect(await facesOf(joiner, L.creator, 0), "a slot the joiner has never held reads as held")
      .toEqual({ tally: "down" });
    const down = (await row.innerText()).replace(/\s+/g, " ");
    expect(down).toContain("on their machine — it did not come here");
    expect(down, `the face-down row: ${down}`).not.toMatch(/\$tally here\b/);
    // And no value crossed for it. The label is the whole of what a
    // `cell-state` frame may carry, and the assertion is on the panel rather
    // than on the frame so a future field that leaked one fails here too.
    expect(
      await joiner.locator("[data-room-cells]").innerText(),
      "the table printed the value behind the label"
    ).not.toContain(TALLY);

    // The live region got the outcome, worded as somebody else's, with no
    // remedy — there is none, and nothing on this wire asks a peer for a value.
    const said = await saidAboutCells(joiner, L.creator);
    const trail = JSON.stringify(said);
    expect(said.join(" · "), `the joiner's live region — ${trail}`).toContain(
      "finished cell 0"
    );
    expect(said.join(" · "), trail).toContain("did not come here");
    expect(said.join(" · "), trail).not.toMatch(/\$tally is here/);
    expect(said.join(" · "), trail).not.toMatch(/ask them|request it/i);
    // Once, and the count is the assertion: the row moved twice — `running`
    // then `done` — and only the outcome is announceable. `7ac9f50`'s rule,
    // which `cell-state.js` applies by returning "" for a peer's ticker.
    expect(said, `a peer's ticker reached the live region — ${trail}`).toHaveLength(1);
  }, 180_000);

  /* ── 4. face up, and nothing crossed to make it so ───────────────────────── */

  it("turns the row face up when the value lands here, with no announcement", async () => {
    // What the joiner's own screen said before it ran anything, kept so the
    // claim below is a comparison rather than an assumption.
    const before = await saidAboutCells(joiner, L.creator);

    // **The press, on the joiner's own copy of the same unplaced cell.** No
    // frame crosses because of this: the joiner never pressed Share, so
    // `announceCellState` returns 0 on that end, and the creator's table is
    // asserted empty at the end of this step to say so.
    await cell(joiner, 0).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(joiner, 0), { timeout: 60000, intervals: [250] })
      .toBe("ok");
    await runSettled(joiner);
    expect(await tallySlots(joiner)).toEqual(["tally"]);

    await trayTab(joiner, "Connections");
    const row = rowOf(joiner, L.creator, 0);

    // **The row turned over on this machine's own registry answering.** The
    // peer said `$tally` once, in the previous step, while it was not here; the
    // announcement has not been repeated and could not be. What changed is
    // `slotMetas`, which `peerCellRows` re-derives faces from — so a build in
    // which possession were read off the announcement instead would still be
    // drawing "on their machine" right now.
    await expect
      .poll(async () => (await facesOf(joiner, L.creator, 0)).tally, {
        timeout: 30000,
        intervals: [250],
      })
      .toBe("up");
    const up = (await row.innerText()).replace(/\s+/g, " ");
    expect(up, `the face-up row: ${up}`).toContain("$tally here");
    expect(up, `the face-up row: ${up}`).not.toContain("did not come here");
    // Still the same row, still `done`, still the peer's — turning a card over
    // is not a new hand.
    expect(await row.getAttribute("data-room-cell-state")).toBe("done");
    expect(await joiner.locator("[data-room-cell]").count()).toBe(1);
    // And the label is still all that is on the panel. A face-up row names a
    // slot this machine holds; it does not *print* it, which is the Slots
    // tray's job and the reveal press's.
    expect(
      await joiner.locator("[data-room-cells]").innerText(),
      "the face-up row printed the value"
    ).not.toContain(TALLY);

    // **Silent, and the count is the assertion.** The live region announces on
    // *arrival*, and nothing arrived — so a flip that had gone through the
    // announcer would leave a line here. Compared against the transcript from
    // before the press rather than matched negatively, because a version that
    // said something differently worded would survive a `not.toContain`.
    const after = await saidAboutCells(joiner, L.creator);
    expect(
      after,
      `the joiner's live region moved on its own run — ${JSON.stringify({ before, after })}`
    ).toEqual(before);

    // **The other half of the consent gate.** The joiner has now run a cell
    // twice over and the creator has been told nothing about either: nobody on
    // that end pressed Share, so there is no announcement to make. A gate that
    // stopped firing would show up here as a row.
    await trayTab(creator, "Connections");
    expect(
      await creator.locator("[data-room-cell]").count(),
      "a machine that never shared a notebook announced its cells"
    ).toBe(0);
    expect(await creator.locator("[data-room-cells]").innerText()).toContain(
      "Nobody has said they are running anything"
    );
  }, 180_000);

  /* ── 5. the sentence that had never been said in a browser ───────────────── */

  it("tells the reader the slot is here when the announcement lands on a holder", async () => {
    const before = await saidAboutCells(joiner, L.creator);

    // The same cell, the same peer, the same label — and this time the frame
    // arrives at a machine that already holds it. `describeCellState` asks the
    // live registry at the moment of arrival, so this is the branch that says
    // `is here` rather than the one that names somebody else's machine.
    await cell(creator, 0).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(creator, 0), { timeout: 60000, intervals: [250] })
      .toBe("ok");
    await runSettled(creator);

    await trayTab(joiner, "Connections");
    await expect
      .poll(
        async () => (await saidAboutCells(joiner, L.creator)).slice(before.length).join(" · "),
        { timeout: 60000, intervals: [250] }
      )
      .toMatch(/\$tally is here/);

    const fresh = (await saidAboutCells(joiner, L.creator)).slice(before.length);
    const trail = JSON.stringify(fresh);
    // The whole sentence, in the order the module composes it: who, which cell,
    // and then what of it is here.
    expect(fresh.join(" · "), trail).toMatch(
      new RegExp(`${L.creator}[^·]*finished cell 0\\.[^·]*\\$tally is here\\.`)
    );
    // And it does *not* also call the same label somebody else's. One label,
    // one side of the sentence — a version that appended both would be telling
    // a reader two contradictory things about one slot.
    expect(fresh.join(" · "), trail).not.toContain("did not come here");
    // Announced and not printed: the run's own verdict is still on the line
    // under the run bar, which is `notebook-ack`'s finding held here too.
    const line = joiner.locator("[data-run-state]").locator("xpath=following-sibling::p[1]");
    expect((await line.innerText()).trim(), "an arriving fact overwrote the run's verdict")
      .toMatch(/^Done\b/);

    // The row is still face up, and still one row.
    expect(await facesOf(joiner, L.creator, 0)).toEqual({ tally: "up" });
    expect(await joiner.locator("[data-room-cell]").count()).toBe(1);

    await stopSaid(joiner);
  }, 180_000);

  /* ── what the journey cost ───────────────────────────────────────────────── */

  it("drove both browsers without tripping the production CSP", async () => {
    for (const peer of fx.peers) expect(await peer.cspViolations()).toEqual([]);
    expect(fx.tunnelFaults()).toEqual([]);
    expect(room.faults()).toEqual([]);
  });
});
