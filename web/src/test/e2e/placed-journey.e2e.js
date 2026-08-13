/**
 * The whole journey, from an empty joiner, driven by presses.
 *
 * Five commits landed a placed run in one night, each one closing a defect that
 * had survived a green suite, and the reason it survived was the same every
 * time: each layer was tested against the layer above it and nothing walked the
 * road a person walks. `placed-run-arc.e2e.js` is the sharpest case. It proves
 * the whole handoff arc across two real browsers — and hands both of them the
 * same `S.src` variable, so it never once asks how a joiner *obtains* the text.
 * `a47f630` (nothing could send the notebook) was invisible to it by
 * construction, and so was `a4f9399` (the placement gate closed over a stale
 * roster and was not firing at all), because that suite never presses Run.
 *
 * This file is the road. One notebook, two browser contexts, **no variable
 * carrying anything between them**: everything either side knows about the other
 * arrived over the wire or out of the address bar. Every act is the press a
 * person makes — the assignment menu, Start, the invite link, Share, Run, accept,
 * run, send back, accept — and every assertion is on what the person sees or
 * what the shell is holding.
 *
 * ## Why the presses, and not `page.evaluate`
 *
 * `session-source.e2e.js` argues this for one press and the argument scales:
 * the defects live *between* the widget and the notebook. `a4f9399` is the
 * proof. `runFrom` closed over `handoffWho` without listing it, so the gate held
 * whichever roster was current the last time `chains` changed — which, for the
 * compose-then-Start flow `96dde48` opened up, is the roster from before anybody
 * was in the room. Every layer underneath was correct. `planRun` plans, the gate
 * gates, `offerCell` offers; a suite driving any of them passes. The only thing
 * that fails is pressing Start after composing and then pressing Run, and the
 * failure is silent: other people's cells run on this machine and nothing says
 * so. So step 5 below asserts the *absence* of a slot, which is the only shape
 * that defect has.
 *
 * Where this file evaluates in the page it does so for one of two reasons and
 * says which: seeding the vault (there is no import UI for a key this fixture
 * already holds), and reading `location.hash` (the address bar is not a DOM
 * node). Nothing else.
 *
 * ## What is real, and what stands in
 *
 * Real: both browsers, both `RTCPeerConnection`s, the shipped `dist/` bundle
 * under the production CSP, `NotebookSession` and the whole handoff stack as the
 * chunks ship them, OpenPGP throughout, the room's keyserver, and — the part
 * that matters here — the shell. Every button pressed below is the one in the
 * product.
 *
 * Standing in: the signalling relay is `webpubsub_local.py` behind
 * `browser-mesh.js`, and `/api/v1/notebook/negotiate` is answered by the same
 * helper rather than by Flask, whose route is gated by proof-of-work and two
 * rate limits that have nothing to do with this journey. The two identities are
 * minted by `createQuorumRoom` in node and *put into the two vaults*, because a
 * session bootstraps by fetching its audience from a keyserver and a key minted
 * inside a browser is a key no directory has. Neither browser is told the
 * other's key by this file after that point: the creator learns the audience
 * from a hash it is handed the way a fingerprint is handed over out of band, and
 * the joiner learns everything from the link.
 *
 * ## What the ICE list is, and why it is not `[]`
 *
 * `quorum-key-confirmation.e2e.js` passes `iceServers: []` because it constructs
 * the session itself. This one cannot: the session is opened by a `quorum.offer`
 * cell, and `engine.js` passes `null` when no `ice=` param is written, which the
 * session reads as "use the shipped defaults". So this run gathers against the
 * shipped STUN servers exactly as a deployment does. The connection that
 * completes is still made of host candidates on the loopback interface — that is
 * what two contexts of one browser have — and a machine with no route to those
 * servers loses nothing but the time they take to fail.
 *
 * ## What walking it turned up, and where each of them is pinned
 *
 * Four things, none of which any node suite can see, because every one of them
 * is the shell handing the layer below it something the layer below cannot use,
 * or drawing something that is not true.
 *
 * 1. **The returning half of the arc had never worked from the UI.**
 *    `useNotebook.acceptHandoff` passed `doc.from` — a bare fingerprint — as
 *    `by`, where `acceptCellResult` checks it against `plan.cells[n].runsOn`,
 *    which holds labels. Every result a peer ever sent back was refused
 *    `not-theirs`. Fixed in `5022bbf`; step 7 is the guard.
 * 2. **A cell the gate declined is drawn as a cell that ran** — `ok`, with a
 *    timing, on the machine that just refused to perform it. Fixed: `runCell`
 *    stamps `declined`, with no timing and no run-log entry. Step 5.
 * 3. **Adopting a peer's notebook leaves the old notebook's runs attached** to
 *    the new cells: `loadRecipeText` replaced `chains` and told the kernel
 *    nothing. Fixed: it clears the per-cell buckets of the notebook it is
 *    closing. Step 6.
 * 4. **The notebook that travels carries the sender's session cells**, so the
 *    receiver's Run stopped at `agent.unlock <the sender's fingerprint>` with
 *    "Key not found in vault". Fixed in `sessionRecipe`, which places both
 *    cells on the peer opening the session — `agent.unlock` reaches the vault
 *    of whoever runs it and `plan.js` has always asked whose vault that is.
 *    Nothing about the transport changed: both ends still hold
 *    character-identical text, and the gate that declines a peer's cells
 *    declines these. Steps 4 and 6.
 *
 * A fifth, which the accept in step 6 now shows: `acceptHandoff` registered into
 * the kernel and bumped `sessionTick`, while `slotMetas` is memoised on
 * `kernelEpoch`, so the tray said "No slots yet" about a value the shell had
 * just reported registering.
 *
 * Two more are recorded in prose only, because pinning them would mean asserting
 * something a fix should be free to change: `decideProposal`'s
 * adopt-into-an-empty-notebook branch is unreachable through the UI (Join writes
 * two cells before any proposal can arrive), and `acceptCellResult`'s `offered`
 * bound is fabricated from the document being judged, so its "an answer to a
 * question nobody asked" refusal cannot fire in the shell.
 *
 * ## The order of the tests is the order of the journey
 *
 * Not a `beforeAll` that does everything and a set of assertions about it, which
 * is the shape of the sibling suites and is right for them: they prove
 * properties of one exchange. This proves a *sequence*, and the deliverable when
 * a sequence breaks is which step broke. So each step is its own `it`, they run
 * in order, and they share state — a failure in step 5 leaves steps 1–4 green
 * and names the press that could not be made.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";
import { roomRoster } from "../../lib/notebook/roster.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the placed-journey suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[placed-journey.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/* ────────────────────────────── the notebook ───────────────────────────────
 *
 * Three cells and two machines, and the third is what makes this an arc rather
 * than a delivery: the creator's last cell reads what the joiner's cell writes,
 * so the creator's run does not merely skip a cell and walk on — it stops.
 * Lifted from `placed-run-arc.e2e.js`, which lifted it from
 * `handoff-result.test.js`, so a difference between this file and those is a
 * difference in *how the notebook got there* rather than in the notebook.
 *
 * The pipelines are typed into the cell editors. The `@peer` headers are not:
 * they are chosen from the "Who runs this cell" menu, which is the whole point
 * of step 1 and the flow `96dde48` opened up.
 */

/** What the creator's first cell writes, before anything crosses. */
const CELL_0 = "bytes deadbeef | encode hex | out $seed";
/** The joiner's cell — the only one placed away from the machine composing. */
const CELL_1 = "in $seed | decode hex | encode base64 | out $b64";
/** The creator's again, and it reads what cell 1 wrote somewhere else. */
const CELL_2 = "in $b64 | out $done";

/** What `deadbeef` comes back as, once it has been round-tripped. */
const EXPECTED_B64 = "3q2+7w==";

/* ───────────────────────────── driving the shell ──────────────────────────── */

/** One notebook cell, by index — the shell renders exactly one `<article>` each. */
const cell = (page, i) => page.locator("article").nth(i);

/**
 * A fingerprint as this product prints one: `formatFingerprint`'s grouping.
 *
 * Reproduced here rather than imported, deliberately. Every other value in this
 * file crosses through the product; this one is what a *person reads on screen*,
 * and importing the formatter would make the assertion "the row agrees with the
 * formatter" instead of "the row shows the whole key in the shape this product
 * always shows one in".
 */
const printFpr = (fpr) => String(fpr).match(/.{1,4}/g).join(" ");

/** Escape a printed fingerprint for a `RegExp` — the spaces are fine, `+` is not. */
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The session tray, as a scope.
 *
 * Every panel this journey reads — the slot list, the connections roster, the
 * handoff queue — is inside it, and several of the strings it prints (`@b64`,
 * `peer2`) also appear in the notebook beside it. Asserting against the page
 * would be asserting that the *text of the recipe* says something, which is
 * true before any of this ran.
 */
const tray = (page) => page.locator('[aria-label="Session tray"]').locator("xpath=..");

/** Open one of the tray's tabs and wait for it to be the selected one. */
async function trayTab(page, name) {
  const tab = tray(page).getByRole("tab", { name, exact: true });
  await tab.click();
  await expect.poll(async () => await tab.getAttribute("aria-selected"), {
    timeout: 10000,
  }).toBe("true");
}

/**
 * Type a pipeline into a cell, the way the Source view takes one.
 *
 * **Applies on blur**, so the `blur()` is the act and not a tidy-up: without it
 * the text sits in `rawDrafts`, never reaches `chains`, and every assertion
 * below would be about a notebook the shell does not have. Blurred directly
 * rather than by pressing Tab, because Tab lands on whatever control happens to
 * be next and this file should not have an opinion about which one that is.
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
 * Give a cell to a peer through the menu the product calls "Who runs this cell".
 *
 * The label is *chosen*, never typed: that distinction is the whole of `96dde48`
 * — the menu read the live roster, which is empty until Start is pressed, so
 * before a session the only labels on offer were ones already in the text. A
 * test that typed `@peer2` into the editor would compose a notebook the way
 * nobody can and would pass on the day the menu went empty again.
 *
 * `publish` is a second pass over the same menu because it is a second item on
 * it, and it only appears once a peer is chosen — a cell placed on nobody has no
 * boundary for its output to cross.
 */
async function assignCell(page, i, label, { publish = false } = {}) {
  const art = cell(page, i);
  await art.locator("[data-cell-assign]").click();
  // The row prints the key the way `formatFingerprint` does — grouped in fours
  // — because a `DropdownMenuItem` cannot hold the `Fingerprint` placard and the
  // degradation is never a truncation. So the menu is found by the *printed*
  // spelling rather than by the raw hex, which is also the assertion that the
  // row is showing all of it: a truncated row would not match.
  const printed = printFpr(label);
  const item = page.getByRole("menuitem", { name: new RegExp(escapeRe(`@${printed}`)) });
  await item.waitFor({ state: "visible", timeout: 10000 });
  await item.click();
  if (!publish) return;
  await art.locator("[data-cell-assign]").click();
  const pub = page.getByRole("menuitem", { name: "Publish its output" });
  await pub.waitFor({ state: "visible", timeout: 10000 });
  await pub.click();
}

/**
 * Which of the notebook's three answers this browser is holding, as the Slots
 * tab prints them.
 *
 * Filtered to `seed`/`b64`/`done` rather than reported whole, and the filter is
 * the point rather than tidiness: pressing Start or Join runs `agent.unlock` and
 * `quorum.offer`, which register `$me` and `$session` on both machines. Those
 * are the session's own slots and say nothing about who ran which cell. Every
 * assertion below is about *where a value was computed*, so the list has to be
 * the values the notebook computes and nothing else — otherwise "the creator
 * holds two slots" would be true before the journey started.
 */
async function answerSlots(page) {
  await trayTab(page, "Slots");
  const rows = tray(page).locator("li code");
  const out = [];
  for (const text of await rows.allInnerTexts()) {
    const m = /^@(seed|b64|done)$/.exec(text.trim());
    if (m) out.push(m[1]);
  }
  return out.sort();
}

/**
 * What the cell's own status dot says — `idle` draws "never run" beside it.
 *
 * **It was not a usable answer to "did this cell run here", and this file used
 * to pin the two places where it lied.** A cell the placement gate declined came
 * back from `runCell` normally with no artifacts and was stamped `ok` with a
 * fresh timing, and a cell that arrived by adopting a peer's notebook inherited
 * whatever the cell at its index did before. Both were asserted as they were, so
 * that fixing either failed loudly instead of passing quietly, and both are
 * fixed: the gate's cells report `declined`, and adopting clears what the
 * previous notebook's cells left at each index.
 *
 * So the three answers this file now reads off it are distinct facts and each is
 * asserted as one — `ok` ran here, `declined` was left to its owner, `idle` has
 * not been reached. What is still true is that it is the *cheapest* answer and
 * not the deepest: everything about where a value was computed goes through
 * `answerSlots` or the cell's own outputs, because a status is one word about a
 * cell and those are the value itself.
 */
const cellStatus = (page, i) =>
  cell(page, i).locator("[data-cell-status]").getAttribute("data-cell-status");

/** Whether the run bar is between runs — the only "did it finish" the UI has. */
async function runSettled(page) {
  await expect
    .poll(async () => await page.locator("[data-run-state]").getAttribute("data-run-state"), {
      timeout: 120000,
      intervals: [250],
    })
    .toMatch(/^(idle|blocked)$/);
}

/**
 * The status line under the run bar, plus the error line that replaces it.
 *
 * One string because the shell draws one paragraph: `runError || runStatus`. A
 * reader sees whichever is true, and so does this.
 */
async function runLine(page) {
  const p = page.locator("[data-run-state]").locator("xpath=following-sibling::p[1]");
  return (await p.count()) ? (await p.innerText()).trim() : "";
}

/* ─────────────────────────────── the journey ──────────────────────────────── */

describe.runIf(availability.ok)("one notebook, two browsers, from an empty joiner", () => {
  /** @type {any} */ let room;
  /** @type {any} */ let fx;
  /** @type {(() => Promise<void>)|null} */ let closeMesh = null;
  /** @type {import("playwright").Page} */ let creator;
  /** @type {import("playwright").Page} */ let joiner;
  /** @type {string} */ let origin = "";
  /**
   * What each end's `@peer` header says, as the *product* derives it.
   *
   * Asked of `roomRoster` rather than written down, and that is still the rule
   * even though the answer is now each browser's own fingerprint: what a room
   * calls a member is the room's answer, and a name this file invented would be
   * one the room might not agree with. That disagreement is what `96dde48` was
   * about, and it is the class of defect this whole change removes rather than
   * repairs.
   * @type {{ creator: string, joiner: string }}
   */
  let L = { creator: "", joiner: "" };
  /** The URL the creator's own address bar held after Start. Nothing else crosses. */
  let inviteUrl = "";
  /** What the creator composed, read from the creator's own Source view. */
  let creatorSource = "";
  /**
   * The creator's notebook at the moment Share is pressed, which is not what
   * they composed: pressing Start *appends the two cells that open a session* —
   * `agent.unlock` and `quorum.offer` — because a session that happened without
   * a recipe saying so would be the one thing in this app that did. So the text
   * that travels is read again, from the creator's own Source view, right before
   * it is sent.
   */
  let sharedSource = "";

  beforeAll(async () => {
    room = await createQuorumRoom();
    const mesh = await openMesh(room);
    if (!mesh.ok) {
      // A hub that will not start is a real failure, not a reason to skip — the
      // rule `basilisk-server.js` states and `quorum-key-confirmation.e2e.js`
      // follows. Only an absent interpreter stands anything down, and that is
      // reported as the reason.
      throw new Error(`local Web PubSub hub did not start (${mesh.kind}): ${mesh.reason}`);
    }
    closeMesh = mesh.close;
    fx = mesh.fx;
    origin = fx.origin;
    creator = fx.peers[0].page;
    joiner = fx.peers[1].page;

    const roster = roomRoster(room.audience, [], room.members[0].fpr);
    L = {
      creator: roster.me,
      joiner: roomRoster(room.audience, [], room.members[1].fpr).me,
    };
    // The whole key, upper case — what `@peer` headers carry and what
    // `peersSha` binds. This used to be `/^peer\d+$/`: a position in the sorted
    // audience, which said nothing about who would run a cell and moved
    // whenever the room changed size.
    expect(L.creator, "the room could not name its own creator").toBe(room.members[0].fpr);
    expect(L.joiner).toBe(room.members[1].fpr);
    expect(L.creator).not.toBe(L.joiner);
    // And it is the room's answer, not this file's: a key the audience does not
    // contain gets "" rather than a place in a room it is not in.
    expect(roomRoster(room.audience, [], "F".repeat(40)).me).toBe("");
  }, 180_000);

  afterAll(async () => {
    if (closeMesh) await closeMesh();
    else if (fx) await fx.close();
  });

  /* ── 1. compose, and place a cell on somebody who is not here ───────────── */

  it("composes a placed notebook before any session exists", async () => {
    await creator.goto(`${origin}/toolkit`, { waitUntil: "load" });
    // The one evaluate this step makes, and the reason: there is no UI for
    // importing a key this fixture already holds, and the key has to be one the
    // room's keyserver can also hand out or `start()` refuses to mesh with a
    // stranger. Generating one in the browser is what `session-source.e2e.js`
    // does and is exactly what cannot work here.
    const stored = await creator.evaluate(
      seedVaultKeyExpr({
        fingerprint: room.members[0].fpr,
        armoredPrivate: room.members[0].armoredPrivate,
        armoredPublic: room.members[0].armoredPublic,
        uid: "Creator <creator@journey.test>",
      })
    );
    expect(stored).toContain(room.members[0].fpr);
    await creator.reload({ waitUntil: "load" });
    await creator.waitForSelector(".toolkit-shell", { timeout: 30000 });

    // The room is *named*, and nobody has connected. A creator learns who to
    // invite the way anybody does — a fingerprint handed over out of band — and
    // the invite hash is the form this product puts one in. Assigning against
    // this audience is the state the menu used to be empty in.
    const sheet = creator.locator("[data-session-sheet]");
    await creator.evaluate((h) => {
      window.location.hash = h;
    }, `#j=${room.audience.join(",")}`);
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    await creator.getByRole("button", { name: "I am starting it" }).click();
    await creator.locator("[data-session-key] select").selectOption(room.members[0].fpr);
    expect(
      await creator.locator(`[data-session-member="${L.joiner}"]`).count(),
      "the sheet did not name the invited key"
    ).toBe(1);
    // **The row is a placard, and the placard is the whole key.** This is what
    // replaced `@peer2`: the value the row shows and the value a cell header
    // writes are one string, so there is nothing binding them that could come
    // apart. `variant="compact"` used to stand the label in for the key here,
    // and it must not stand the key in for itself — it prints a name carrying
    // no bits of the key, and passing the key as that name would print all of
    // it while claiming to print something that is not it.
    const row = creator.locator(`[data-session-member="${L.joiner}"]`);
    expect(await row.locator('[data-fingerprint="full"]').count()).toBe(1);
    expect(await row.locator('[data-fingerprint="compact"]').count()).toBe(0);
    expect((await row.innerText()).replace(/\s/g, "")).toContain(L.joiner);
    // …and the human half beside it, which is the thing forty hex characters
    // cannot supply. This browser has never met the joiner's key, so the row
    // says so rather than filling the gap with characters off the key.
    expect(await row.innerText()).toContain("no name for this key in this browser");
    // The creator's own row does have a name — the uid seeded into this vault
    // — which is the pair that makes the sentence above an assertion rather
    // than a coincidence.
    const mine = creator.locator(`[data-session-member="${L.creator}"]`);
    expect(await mine.innerText()).toContain("Creator <creator@journey.test>");
    // Nothing anywhere in the room list is a truncation.
    expect(await creator.locator("[data-session-audience]").innerText()).not.toContain("…");
    await creator.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    await writeCell(creator, 0, CELL_0);
    await creator.getByRole("button", { name: "Cell", exact: true }).click();
    await writeCell(creator, 1, CELL_1);
    await creator.getByRole("button", { name: "Cell", exact: true }).click();
    await writeCell(creator, 2, CELL_2);

    await assignCell(creator, 0, L.creator, { publish: true });
    await assignCell(creator, 1, L.joiner, { publish: true });
    await assignCell(creator, 2, L.creator);

    creatorSource = await readNotebookSource(creator);
    // The headers are in the notebook and this file never typed one. Both are
    // asserted: that the placement is there, and that the cell it is on is the
    // cell whose text says `$b64` — a menu that wrote the right label onto the
    // wrong cell is a notebook that compiles and runs on the wrong machine.
    expect(creatorSource).toMatch(new RegExp(`^@${L.joiner} publish$`, "m"));
    expect(creatorSource).toMatch(new RegExp(`^@${L.creator} publish$`, "m"));
    // Structural rather than string-equal to what was typed: `serializeRecipe`
    // writes a leading `in $x` as bare `$x`, so the notebook's own spelling of
    // this pipeline is not the one the editor was handed. Comparing against the
    // typed text would be asserting that the serializer is a no-op, which it is
    // not and is not supposed to be.
    const cells = creatorSource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(cells).toHaveLength(3);
    const placed = cells.find((c) => c.includes("decode hex"));
    expect(placed, "the joiner's pipeline is in no cell of its own").toBeTruthy();
    expect(placed.split("\n")[0]).toBe(`@${L.joiner} publish`);
    expect(placed).toContain("encode base64 | out $b64");
    // The other two are the creator's, and the last one reads what the placed
    // cell writes — which is what makes this an arc rather than a delivery.
    expect(cells[0].split("\n")[0]).toBe(`@${L.creator} publish`);
    expect(cells[2].split("\n")[0]).toBe(`@${L.creator}`);
    expect(cells[2]).toContain("$b64");
    // And not one positional label anywhere in it. This is the assertion that
    // says which product this notebook came out of: `@peer1`/`@peer2` still
    // parse and still compile — a notebook written before this change has to —
    // so their absence here is a fact about what the menu writes rather than
    // about what the grammar allows.
    expect(creatorSource).not.toMatch(/^@peer\d/m);
  });

  /* ── 1b. what the notebook's own link now gives away, said on the sheet ─── */

  it("says what a placed notebook's link discloses, and only once it is placed", async () => {
    // The honest half of the trade. A `@peer` header is a whole fingerprint, so
    // a placed notebook's `#r=` link carries the audience to whoever opens it —
    // and `hashForRecipe` used to refuse to build one at all, which is what let
    // this row promise "No trust needed" about every link it produced.
    //
    // Read off the shipped sheet rather than from `recipeLinkDiscloses`,
    // because the defect this guards against is the one `42875a2` landed for:
    // a sentence that is true of the function and not of the screen.
    await creator.getByRole("button", { name: "Share", exact: true }).click();
    const sheet = creator.locator("[data-share-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const recipeTier = sheet.locator('[data-tier="Send the recipe"]');
    const trust = recipeTier.locator("[data-tier-trust]");
    expect(await trust.getAttribute("data-trust-tone")).toBe("warn");
    const said = await trust.innerText();
    expect(said).toContain("2 keys");
    expect(said).toContain("who is in the room");
    // The half of the old promise that survived, in the same sentence, so the
    // reader is not left to work out which half did.
    expect(said).toContain("reaches no server");
    expect(said).not.toContain("No trust needed");
    // The link is built rather than refused, which is the change that made the
    // sentence necessary.
    expect(await recipeTier.getAttribute("data-blocked")).toBe("no");
    await creator.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });
  });

  /* ── 2. start it ────────────────────────────────────────────────────────── */

  it("starts the session, and waits for a peer who has not arrived", async () => {
    // Through the tray, which is the door somebody who has just finished
    // composing actually reaches for.
    await trayTab(creator, "Connections");
    await tray(creator).getByRole("button", { name: "Start session" }).click();
    const sheet = creator.locator("[data-session-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const start = creator.getByRole("button", { name: "Start shared session" });
    await expect.poll(async () => await start.isEnabled(), { timeout: 15000 }).toBe(true);
    await start.click();

    // `quorum.offer` blocks until somebody joins, so the run bar sitting in
    // `waiting-peer` *is* the session being open with nobody in it. This is the
    // state `fb178e4` reported as a dead end and made survivable; the joiner has
    // not been opened yet, so the creator is genuinely first.
    await expect
      .poll(
        async () => await creator.locator("[data-run-state]").getAttribute("data-run-state"),
        { timeout: 60000, intervals: [250] }
      )
      .toBe("waiting-peer");
  });

  /* ── 3. the address bar is the invite, and it is what the joiner opens ──── */

  it("puts the invite in the address bar, and the joiner arrives through it", async () => {
    // `location.hash` is not a DOM node, so this is an evaluate and there is no
    // way for it not to be. It is also the whole assertion: `540e0ad` shipped
    // `writeToolkitHash` with no caller anywhere in the product, so a session
    // you had already started still had `/toolkit` in the bar — the one thing
    // everybody reflexively copies out of a browser.
    await expect
      .poll(async () => await creator.evaluate(() => window.location.hash), { timeout: 20000 })
      .toMatch(/^#j=/);
    inviteUrl = creator.url();
    // Before Start the bar held the *notebook*, and it is the same writer that
    // put it there — so the flip is a decision this feature makes rather than a
    // hash somebody left lying around. The audience is the room's, whole and
    // untruncated, and the invite carries no recipe.
    const hash = new URL(inviteUrl).hash;
    expect(hash).not.toContain("r=");
    for (const fpr of room.audience) expect(hash.toUpperCase()).toContain(fpr);

    await joiner.goto(`${origin}/toolkit`, { waitUntil: "load" });
    const stored = await joiner.evaluate(
      seedVaultKeyExpr({
        fingerprint: room.members[1].fpr,
        armoredPrivate: room.members[1].armoredPrivate,
        armoredPublic: room.members[1].armoredPublic,
        uid: "Joiner <joiner@journey.test>",
      })
    );
    expect(stored).toContain(room.members[1].fpr);

    // A cold arrival on the creator's own URL — not one this file built. The
    // reload is what makes it cold: changing only the hash is a same-document
    // navigation, which is a real way to open an invite and is covered on its
    // own in `session-source.e2e.js`.
    await joiner.goto(inviteUrl, { waitUntil: "load" });
    await joiner.reload({ waitUntil: "load" });
    await joiner.waitForSelector(".toolkit-shell", { timeout: 30000 });

    const sheet = joiner.locator("[data-session-sheet]");
    const start = joiner.locator("[data-session-start]");
    await start.waitFor({ state: "visible", timeout: 20000 });
    expect(await start.getAttribute("data-session-start")).toBe("join");
    expect(await joiner.locator("[data-session-audience] li").count()).toBe(
      room.audience.length
    );

    // Empty, and this is the last moment it is: pressing Join writes the two
    // session cells into it. See step 4.
    //
    // The sheet is dismissed to read this, and put back the way it was reached:
    // it is a modal, so its overlay swallows every click on the notebook behind
    // it, and there is no way to look at the Source view while it is up. That is
    // the product's arrangement, not a limitation of the harness — the reader
    // *cannot* see their own notebook while the invite is in front of them, and
    // this file has to arrive at the same view they would.
    await joiner.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });
    expect(await readNotebookSource(joiner)).toBe("");

    await trayTab(joiner, "Connections");
    await tray(joiner).getByRole("button", { name: "Start session" }).click();
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    // Still the joiner's end. The role came from the link and survived the sheet
    // being closed and reopened, which is what makes the reopen a detour rather
    // than a second arrival.
    expect(await start.getAttribute("data-session-start")).toBe("join");
    await joiner.locator("[data-session-key] select").selectOption(room.members[1].fpr);
    const join = joiner.getByRole("button", { name: "Join shared session" });
    await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
    await join.click();

    // Both ends verified, read off the connections roster rather than out of a
    // session object: `data-verified` is the shell's own answer, and it demands
    // both proofs — the signed envelope and the transcript-bound confirmation.
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
  });

  /* ── 4. the notebook itself travels ─────────────────────────────────────── */

  it("carries the notebook to the joiner, who had none", async () => {
    // What the joiner is holding before anything is shared: the two cells
    // pressing Join wrote, and not one line of the creator's work.
    const before = await readNotebookSource(joiner);
    expect(before).toContain("quorum.join");
    expect(before).not.toContain("decode hex");
    // Their own two cells are placed on *them*, which is the Join end of the
    // same fix the creator's end gets below — the label is this browser's, so
    // whoever ends up holding this text can read whose vault it asks for.
    for (const c of before.split(/\n\s*\n+/)) {
      expect(c.trim().split("\n")[0]).toBe(`@${L.joiner}`);
    }
    // And not one of the creator's, which is what this line has always been
    // about. It used to say `@${L.joiner}` — the header the creator wrote on the
    // cell they placed here — and that string is now also the joiner's own two
    // cells, so it is asked as the two things it meant: no cell of the creator's
    // is here, and nothing here publishes.
    expect(before).not.toContain(`@${L.creator}`);
    expect(before).not.toMatch(new RegExp(`^@${L.joiner} publish$`, "m"));
    await trayTab(joiner, "Connections");
    expect(
      await joiner.locator("[data-notebook-proposed]").count(),
      "something was proposed before anybody shared anything"
    ).toBe(0);

    // What the creator is actually about to send, read from their own Source
    // view rather than remembered from step 1: Start appended two cells, and a
    // test comparing the two ends against a string it wrote down before that
    // would be comparing them against a notebook neither of them holds.
    sharedSource = await readNotebookSource(creator);
    expect(sharedSource).toContain(creatorSource);
    expect(sharedSource).toContain("quorum.offer");
    // And those two cells are placed on the creator, by the creator's own
    // label, which is what makes them survivable at the other end. This is the
    // whole of the fix for the blocker: they still travel — a session that
    // happened without a recipe saying so would be the one thing in this app
    // that did — and the machine that adopts them can now read who they belong
    // to instead of being asked to unlock a key it has never held.
    const shared = sharedSource.split(/\n\s*\n+/).map((c) => c.trim());
    const unlock = shared.find((c) => c.includes("agent.unlock"));
    const opens = shared.find((c) => c.includes("quorum.offer"));
    expect(unlock, "Start wrote no agent.unlock cell").toBeTruthy();
    expect(unlock.split("\n")[0]).toBe(`@${L.creator}`);
    expect(opens.split("\n")[0]).toBe(`@${L.creator}`);
    // Never `publish`. `$me` is an unlocked private key and the header is the
    // thing that would let it out of this machine.
    expect(unlock).not.toContain("publish");

    await trayTab(creator, "Connections");
    await tray(creator).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await creator.locator("[data-notebook-share-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/signed and shared with 1 peer/);

    // It arrives, and it waits. **A press, and the joiner's notebook was never
    // empty when it landed** — see this file's report: `decideProposal`'s
    // adopt-into-an-empty-notebook branch is unreachable from the UI, because
    // Join writes two cells before any proposal can cross. So the assertion is
    // the state that is actually true, not the one the module documents.
    const proposed = joiner.locator("[data-notebook-proposed]");
    await proposed.waitFor({ state: "visible", timeout: 30000 });
    expect(await readNotebookSource(joiner)).toBe(before);

    await joiner.getByRole("button", { name: "Adopt their notebook" }).click();
    // Byte for byte the creator's text, in the joiner's own Source view. This is
    // the assertion `placed-run-arc.e2e.js` cannot make: it hands both peers one
    // `S.src` variable, so the question of how a joiner *obtains* the notebook
    // never comes up and `a47f630` was invisible to it.
    await expect
      .poll(async () => await readNotebookSource(joiner), { timeout: 20000 })
      .toBe(sharedSource);
    // Including the header this file never typed on either machine.
    expect(await readNotebookSource(joiner)).toMatch(
      new RegExp(`^@${L.joiner} publish$`, "m")
    );
  });

  /* ── 5. Run declines the joiner's cell, and hands it over by itself ─────── */

  it("runs the creator's own cell, declines the joiner's, and offers it unasked", async () => {
    await creator.getByRole("button", { name: "Run all" }).click();
    await runSettled(creator);

    const held = await answerSlots(creator);
    // One line saying where the run got to, and it has to be an equality rather
    // than two `contain`s: the two ways this goes wrong are opposite. `b64` or
    // `done` here means the gate did not fire and this machine performed a cell
    // the notebook gave to somebody else; nothing here means its own cell never
    // ran and the rest of the journey would be about a notebook that does not
    // work at all.
    expect(held, "the creator's run did not stop where the notebook places it").toEqual([
      "seed",
    ]);
    // **The assertion with teeth.** `a4f9399`: `runFrom` closed over
    // `handoffWho` without listing it, so composing and *then* pressing Start
    // left the gate holding an empty roster — `me` was "", no plan was built, no
    // placement reached `runCell`, and the joiner's cell ran here. It produced
    // the right answer on the wrong machine and nothing said so. The only shape
    // that defect has is a slot that exists, so this is an absence.
    expect(held, "the creator ran a cell the notebook gave to somebody else").not.toContain(
      "b64"
    );
    expect(held, "the creator's own cell did not run either").toContain("seed");
    // Stopped rather than finished short: the creator's last cell reads what the
    // declined cell writes, and `placementGate` says so in its own words.
    expect(await runLine(creator)).toContain("$b64");

    // **And the cell the gate declined says so.** It used to be drawn as a cell
    // that ran: `runCell` set `ok` and stamped a fresh timing on *every* return
    // from `runRecipe`, and a gated cell returns normally with no artifacts, so
    // the dot beside the joiner's cell read "ran 0s ago" on the machine that had
    // just refused to perform it. The gate's entire purpose is that this cell
    // did not run here, and the one line a reader checks to find that out said
    // the opposite.
    //
    // The creator's own cell is asserted beside it, and that pairing is the
    // point: `declined` reached by declining everything would be no better than
    // `ok` reached by stamping everything. One run, one notebook, two answers.
    expect(await cellStatus(creator, 0)).toBe("ok");
    expect(
      await cellStatus(creator, 1),
      "the cell the gate declined is drawn as a cell that ran"
    ).toBe("declined");

    // And the run handed the declined cell over without being asked. `a4f9399`
    // again, the other half: `offerCell` had exactly one caller in the product —
    // a per-row button — while the queue's own copy promised the cells "are
    // offered to whoever owns them".
    await trayTab(creator, "Connections");
    const away = tray(creator).locator("[data-handoff-outgoing] li");
    await expect.poll(async () => await away.count(), { timeout: 20000 }).toBe(1);
    expect(await away.first().innerText()).toContain(`@${L.joiner}`);
    // Whole, in the queue too. This row is the densest place a peer is drawn
    // in the product and is exactly the column that has argued itself into a
    // truncation before.
    expect(await away.first().innerText()).not.toContain("…");
    await expect
      .poll(
        async () => await away.first().locator("[data-offer-state]").getAttribute("data-offer-state"),
        { timeout: 20000 }
      )
      .toBe("sent");
  });

  /* ── 6. three presses on the joiner, and not one of them automatic ──────── */

  it("waits for the joiner to accept, run and send back — each of them a press", async () => {
    await trayTab(joiner, "Connections");
    const pending = tray(joiner).locator("[data-handoff-pending] li");
    await expect.poll(async () => await pending.count(), { timeout: 30000 }).toBe(1);
    expect(await pending.first().getAttribute("data-handoff-kind")).toBe("offer");

    // Arrived and nothing more. If accepting were automatic there would be a
    // binding here already, and if *running* were automatic there would be an
    // answer. The control is the half that makes the rest mean anything.
    expect(await answerSlots(joiner)).toEqual([]);
    expect(await cell(joiner, 1).innerText()).not.toContain(EXPECTED_B64);
    // **A second finding, fixed.** This cell has never run on this machine, and
    // it used to say "ran 0s ago · 293ms" with the *previous* notebook's
    // `$session` artifact under it. Adopting goes through `loadRecipeText`,
    // which replaced `chains` and told the kernel nothing — no
    // `markAllWithOutputsStale`, no `clearCellOutputs`, no `remapCells` — so
    // every per-cell status, timing and output stayed attached to its index
    // while the cell underneath it became somebody else's. Index 1 was
    // `quorum.join` a second ago and is the placed cell now, and it wore the old
    // one's run.
    //
    // `idle` — "never run" — is the true answer, and it has to hold for the
    // whole notebook rather than for this cell: the joiner's two Join cells were
    // at 0 and 1, so a clear that stopped at the incoming length would leave the
    // tail wearing them.
    for (const i of [0, 1, 2, 3, 4]) {
      expect(
        await cellStatus(joiner, i),
        `cell ${i} of an adopted notebook wears the previous notebook's run`
      ).toBe("idle");
    }
    await trayTab(joiner, "Connections");
    expect(
      await tray(joiner).locator("[data-handoff-owed] li").count(),
      "the joiner already owes an answer for a cell nobody accepted"
    ).toBe(0);

    // Press one: accept. This is where a handoff stops being a document.
    await joiner.getByRole("button", { name: "Review and accept" }).click();
    await expect
      .poll(async () => await joiner.locator("[data-handoff-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/Accepted — 1 value registered/);
    // Accepted, and still not run: the value that arrived is the one the cell
    // *reads*, not the answer.
    //
    // The Slots tab **is** consulted here, and it used not to be: `acceptHandoff`
    // registered into the kernel and bumped `sessionTick`, while `slotMetas` is
    // memoised on `kernelEpoch`, so the tray went on saying "No slots yet" about
    // a value the shell had just told the reader it registered — until some
    // later run bumped the epoch for reasons of its own. One press, one value,
    // and the tray says so on the same press.
    expect(
      await answerSlots(joiner),
      "the tray does not show the value the accept just reported registering"
    ).toEqual(["seed"]);
    expect(await cell(joiner, 1).innerText()).not.toContain(EXPECTED_B64);

    // Press two: run it. The cell's own Run, which is how a person runs the cell
    // they just took rather than the notebook they did not write.
    await cell(joiner, 1).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(joiner);
    // Both of them now: `b64` because this machine just made it, and `seed`
    // because the accept put it there two presses ago.
    expect(await answerSlots(joiner)).toEqual(["b64", "seed"]);
    expect(await cell(joiner, 1).innerText()).toContain(EXPECTED_B64);

    // **And the run this press started survived the notebook it was given.**
    // Third finding, and the largest of the three, fixed at the point the cells
    // are written. Pressing Run on a cell runs every cell from there on, and the
    // notebook that travelled is the creator's *whole* notebook — including the
    // two cells Start appended, which are `agent.unlock <the creator's
    // fingerprint>` and a `quorum.offer` over the room. Neither is runnable
    // here: the key is not in this vault, and this browser is already in the
    // session that cell would open. The run used to stop at cell 3 with "Key not
    // found in vault", every time, on a notebook a peer told them to adopt.
    //
    // They are the creator's cells and now say so, so the same gate that
    // declined cell 2 declines them, and the run walks to the end of the
    // notebook. Asserted as an absence *and* as the state that replaced it: a
    // run that stopped one cell earlier for some new reason would also not
    // mention the vault.
    expect(await runLine(joiner)).not.toContain("Key not found in vault");
    expect(await runLine(joiner)).toMatch(/^Done\b/);
    expect(await cellStatus(joiner, 2)).toBe("declined");
    expect(await cellStatus(joiner, 3)).toBe("declined");
    expect(await cellStatus(joiner, 4)).toBe("declined");
    // The cell they were handed is the one that ran, and it is the only one.
    expect(await cellStatus(joiner, 1)).toBe("ok");

    // Recorded in prose rather than pinned, for this file's usual reason: the
    // run above handed *three* cells back — cell 2, which carries the `$b64`
    // the creator's own cell is waiting for and is the point of the exchange,
    // and cells 3 and 4, the creator's session cells, which the creator ran
    // half an hour of wall-clock ago to open the room this offer travelled
    // over. Those two are noise: `handOffPlaced` offers every cell the gate
    // declined, and "declined" is not the same question as "this machine needs
    // its answer". Asserting a count here would pin the noise.
    //
    // Still not sent. `a4f9399` argues this one at length and refuses to
    // automate it: `runFrom` runs every cell from an index onward and nothing
    // records *why* a cell ran, so a send hung off "this cell was accepted once"
    // would fire on every later Run, forever. The proof is the creator's queue,
    // which must hold nothing from this peer.
    await trayTab(creator, "Connections");
    expect(
      await tray(creator).locator('[data-handoff-kind="result"]').count(),
      "a result was sent back without anybody pressing send"
    ).toBe(0);

    // Press three: send it back.
    await trayTab(joiner, "Connections");
    const owed = tray(joiner).locator("[data-handoff-owed] li");
    await expect.poll(async () => await owed.count(), { timeout: 20000 }).toBe(1);
    await joiner.getByRole("button", { name: `Send cell 1 back` }).click();
    await expect
      .poll(async () => await joiner.locator("[data-handoff-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/signed and sent back/);
  });

  /* ── 7. the creator's slot is bound with what the joiner produced ───────── */

  it("binds the creator's slot with the joiner's answer, and only on a press", async () => {
    await trayTab(creator, "Connections");
    const result = tray(creator).locator('[data-handoff-kind="result"]');
    await result.waitFor({ state: "visible", timeout: 30000 });

    // A result that resumed a run on a peer's say-so would continue this machine
    // on values nobody looked at. It has arrived; it has registered nothing.
    expect(await answerSlots(creator)).toEqual(["seed"]);

    await trayTab(creator, "Connections");
    await result.getByRole("button", { name: "Review and accept" }).click();
    await expect
      .poll(async () => await creator.locator("[data-handoff-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/Accepted — 1 value registered/);
    // The answer arrived; the cell did not. Read off the cell's own outputs
    // rather than its status dot, for the reason step 5 pins: a declined cell
    // reports itself as run, so the dot cannot answer this question here.
    expect(await cell(creator, 1).innerText()).not.toContain(EXPECTED_B64);

    // And it is the joiner's answer rather than a local recomputation: this
    // machine declined cell 1 in step 5 and had no `b64` a moment ago. Running
    // now completes the cell that stopped, and the value it reads is the one
    // that crossed.
    await creator.getByRole("button", { name: "Run all" }).click();
    await runSettled(creator);
    expect(await answerSlots(creator)).toEqual(["b64", "done", "seed"]);
    // The gate held on the retry too — the joiner's cell still produced nothing
    // here, and `done` came out of the value that crossed.
    expect(
      await cell(creator, 1).innerText(),
      "the gate stopped gating once the slot was bound"
    ).not.toContain(EXPECTED_B64);
    expect(await cell(creator, 2).innerText()).toContain(EXPECTED_B64);
    // The same bytes are on the joiner's screen, where they were made.
    expect(await cell(joiner, 1).innerText()).toContain(EXPECTED_B64);
  });

  /* ── what the journey cost, and what it did not ─────────────────────────── */

  it("drove the whole journey without tripping the production CSP", async () => {
    expect(await fx.peers[0].cspViolations()).toEqual([]);
    expect(await fx.peers[1].cspViolations()).toEqual([]);
    // Nothing was dropped on the way: every envelope the tunnel forwarded, the
    // room could open. A harness losing signalling reads as a dead transport
    // rather than as a harness.
    expect(fx.tunnelFaults()).toEqual([]);
    expect(room.faults()).toEqual([]);
    // The invite is the creator's, and only the creator's — one broadcast into
    // an empty room and one answering the joiner's knock, which is the pair
    // `fb178e4` produced and the reason this ordering works at all.
    const invites = room.signalled().filter((s) => s.type === "invite");
    expect(invites.map((s) => s.signer)).toEqual([room.members[0].fpr, room.members[0].fpr]);
    const knocks = room.signalled().filter((s) => s.type === "knock");
    expect(knocks).toHaveLength(1);
    expect(knocks[0].signer).toBe(room.members[1].fpr);
  });
});
