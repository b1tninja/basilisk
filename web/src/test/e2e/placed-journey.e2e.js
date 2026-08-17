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
 * the session itself. This one cannot: the session is opened by pressing Start,
 * and `openQuorumSession` passes `null` for the ICE config exactly as `engine.js`
 * does for a `quorum.offer` cell with no `ice=` param — which the session reads
 * as "use the shipped defaults". So this run gathers against the
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
 * 4. **The notebook that travels carried the sender's session cells**, so the
 *    receiver's Run stopped at `agent.unlock <the sender's fingerprint>` with
 *    "Key not found in vault". It was fixed twice. First by placing both cells
 *    on the peer opening the session — `agent.unlock` reaches the vault of
 *    whoever runs it and `plan.js` has always asked whose vault that is — which
 *    made the cells survivable at the other end. Then by not writing them:
 *    Start opens the room and appends nothing (`START_OPENS`), so there is no
 *    longer a cell in anybody's notebook that only one machine can perform.
 *    Steps 4 and 6 assert the absence, which is a narrower thing to keep true
 *    than a header on a travelling cell.
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
/**
 * The joiner's cell — the only one placed away from the machine composing.
 *
 * It carries the notebook's one `#` comment, and that is the point of it being
 * here rather than in a unit test. A comment now survives `serializeRecipe`,
 * so it is inside `manifest.recipeSource` and inside the placed cell's own
 * `recipeDigest` — which means two peers whose notebooks differ by a comment
 * derive different manifests and refuse each other. That is the intended
 * behaviour (the text is the agreement, and a comment is part of what a person
 * read before agreeing), and the risk it carries is the opposite case: a
 * comment that survived on one machine and not the other would refuse an
 * honest run. This road is where that would show, because the joiner's copy
 * arrives over the wire and is never handed to them by this file.
 */
const CELL_1 =
  "# base64 of the seed, computed on the joiner's machine\nin $seed | decode hex | encode base64 | out $b64";
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
 * Filtered to `seed`/`b64`/`done` rather than reported whole. It used to be
 * load-bearing: pressing Start or Join ran `agent.unlock` and `quorum.offer`,
 * which registered `$me` and `$session` on both machines, so "the creator holds
 * two slots" was true before the journey started. Start registers nothing now,
 * and the filter stays because the ceremony half of this file adds `$set` and
 * `$share` — every assertion below is about *where a value was computed*, so
 * the list has to be the three values the notebook computes and nothing else.
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
   * The creator's notebook at the moment Share is pressed.
   *
   * It used to differ from what they composed — Start *appended the two cells
   * that open a session* — and this variable existed because a test comparing
   * the two ends against a string written down before the press would have been
   * comparing them against a notebook neither of them held. Start appends
   * nothing now, so the two are equal and step 4 asserts that equality rather
   * than assuming it. Still read from the creator's own Source view right before
   * it is sent, because "what travels is what is on screen" is the claim.
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
    expect(creatorSource).toMatch(new RegExp(`^@${L.joiner}$`, "m"));
    expect(creatorSource).toMatch(new RegExp(`^@${L.creator}$`, "m"));
    // …and that the menu wrote the disclosure too, on the `out` it belongs
    // behind. `publish` is a step now, so "who runs this" and "what leaves" are
    // two lines apart rather than two words, and the second one is the half a
    // menu that only wrote headers would have silently dropped.
    expect(creatorSource).toContain("out $seed | publish");
    expect(creatorSource).toContain("out $b64 | publish");
    // Structural rather than string-equal to what was typed: `serializeRecipe`
    // writes a leading `in $x` as bare `$x`, so the notebook's own spelling of
    // this pipeline is not the one the editor was handed. Comparing against the
    // typed text would be asserting that the serializer is a no-op, which it is
    // not and is not supposed to be.
    const cells = creatorSource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(cells).toHaveLength(3);
    const placed = cells.find((c) => c.includes("decode hex"));
    expect(placed, "the joiner's pipeline is in no cell of its own").toBeTruthy();
    // The comment is above the header, which is where `serializeChain` puts a
    // cell's comments — so the header is the cell's second line here and the
    // first line everywhere else in this notebook. Asserted as written rather
    // than by searching for a line starting `@`, because "the comment came
    // back, and it came back above the header" is the property.
    expect(placed.split("\n").slice(0, 2)).toEqual([
      "# base64 of the seed, computed on the joiner's machine",
      `@${L.joiner}`,
    ]);
    expect(placed).toContain("encode base64 | out $b64");
    // The other two are the creator's, and the last one reads what the placed
    // cell writes — which is what makes this an arc rather than a delivery.
    expect(cells[0].split("\n")[0]).toBe(`@${L.creator}`);
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

    // Opening the room blocks until somebody joins — `startSession` holds `busy`
    // for the whole of it — so the run bar sitting in
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

    // Empty, and it stays empty: pressing Join opens the room and writes
    // nothing. This line used to be captioned "the last moment it is" — Join
    // appended two cells — and step 4 now asserts the same emptiness *after*
    // the press, which is the assertion that had no way to exist before.
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
    // What the joiner is holding after pressing Join and before anything is
    // shared: **nothing at all**. This block used to assert the two cells Join
    // wrote and that both were headed on this browser — the fix that made them
    // survivable in somebody else's notebook. They are not written now, so the
    // question of whose vault a travelling cell asks for does not arise from
    // this press, and the emptiness is the stronger statement of the same
    // thing.
    const before = await readNotebookSource(joiner);
    expect(before, "pressing Join put cells in the joiner's notebook").toBe("");
    // Belt and braces on the two the press used to write, named, so a
    // reintroduction cannot pass as "the notebook grew for some other reason".
    expect(before).not.toContain("quorum.join");
    expect(before).not.toContain("agent.unlock");
    expect(before).not.toContain("decode hex");
    expect(before).not.toContain(`@${L.creator}`);
    await trayTab(joiner, "Connections");
    expect(
      await joiner.locator("[data-notebook-proposed]").count(),
      "something was proposed before anybody shared anything"
    ).toBe(0);

    // What the creator is actually about to send, read from their own Source
    // view rather than remembered from step 1. This used to be a `toContain`
    // because Start appended two cells to what they composed; it is an equality
    // now, which is the assertion that Start added nothing between step 1 and
    // this line.
    sharedSource = await readNotebookSource(creator);
    expect(sharedSource, "Start changed the creator's notebook").toBe(creatorSource);
    // The three cells they typed, and nothing the session put there. What used
    // to be asserted here — that Start's two cells were headed on the creator,
    // so the machine adopting them could read whose vault they asked for — is
    // no longer a property of anything, because there is nothing to head.
    const shared = sharedSource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(shared).toHaveLength(3);
    expect(sharedSource).not.toContain("quorum.offer");
    expect(sharedSource).not.toContain("agent.unlock");
    // And the room is not written down in it. `$me` was an unlocked private key
    // and `to=` was the whole audience; neither is in the text a `#r=` link
    // would carry, and the only fingerprints left are the `@peer` headers a
    // reader chose, which is what the Share sheet counts.
    for (const member of room.audience) {
      const headers = sharedSource
        .split("\n")
        .filter((line) => line.startsWith(`@${member}`));
      expect(sharedSource.toUpperCase().split(member).length - 1).toBe(headers.length);
    }

    await trayTab(creator, "Connections");
    await tray(creator).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await creator.locator("[data-notebook-share-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/written to 1 open channel · unconfirmed/);

    // **It arrives and it lands, with no press.** This block used to wait for a
    // proposal card and click "Adopt their notebook", and the comment beside it
    // recorded that `decideProposal`'s adopt-into-an-empty-notebook branch was
    // unreachable from the UI because Join wrote two cells before any proposal
    // could cross. That branch is the joiner's ordinary case again: the notebook
    // here is empty, there is no work to lose, and asking would be asking about
    // a notebook the reader has not written a line of.
    //
    // Byte for byte the creator's text, in the joiner's own Source view. This is
    // the assertion `placed-run-arc.e2e.js` cannot make: it hands both peers one
    // `S.src` variable, so the question of how a joiner *obtains* the notebook
    // never comes up and `a47f630` was invisible to it.
    await expect
      .poll(async () => await readNotebookSource(joiner), { timeout: 30000 })
      .toBe(sharedSource);
    expect(
      await joiner.getByRole("button", { name: "Adopt their notebook" }).count(),
      "the joiner was asked about a notebook they had no work to lose to"
    ).toBe(0);
    // Including the header this file never typed on either machine, and the
    // `publish` it never typed either.
    expect(await readNotebookSource(joiner)).toMatch(new RegExp(`^@${L.joiner}$`, "m"));
    expect(await readNotebookSource(joiner)).toContain("out $b64 | publish");
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
    // `quorum.join` a second ago, when Join still wrote cells, and is the placed
    // cell now — and it wore the old one's run.
    //
    // `idle` — "never run" — is the true answer, and it has to hold for the
    // whole notebook rather than for this cell. When Join wrote two cells they
    // sat at 0 and 1, so a clear that stopped at the incoming length left the
    // tail wearing them; the joiner arrives with nothing now, so what this
    // guards against is the *previous* notebook in this context — the one
    // `loadRecipeText` is closing — rather than a shorter one.
    for (const i of [0, 1, 2]) {
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
    // **And the row is gone, which nothing across this seam had ever checked.**
    // `takeHandoff` may succeed exactly once and is the only way a document
    // leaves the queue; `quorum-ops` says so, `useNotebook`'s `handoffTick` says
    // so, and `ToolkitShell`'s memo says so — four comments arguing one
    // invariant across three files, asserted at neither end of it. A row left
    // behind would carry a live "Review and accept" for a document that is no
    // longer there, and the second press would answer "That handoff is no longer
    // pending" for a value the reader can see registered in the tray beside it.
    //
    // **Turned over, and it is worth more than it was.** *When* the take happens
    // has moved: `acceptHandoff` used to call it on its first line, before any
    // verdict, so this assertion held for a refusal too — the document was spent
    // whatever the answer, which is the defect step 7b reproduces. The take now
    // sits on the branch that registers. So this line has stopped being "the
    // press removes the row" and become the narrower, truer claim that it was
    // always meant to be: **an accepted document is spent.** Step 7b asserts the
    // complement on the same queue two steps later — a refused one is not — and
    // between them the exactly-once property is pinned at both ends rather than
    // at whichever end a press happened to reach.
    expect(
      await pending.count(),
      "the accepted offer is still in the queue with the press still on it"
    ).toBe(0);
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
    // Third finding, and the largest of the three. Pressing Run on a cell runs
    // every cell from there on, and the notebook that travelled used to be the
    // creator's whole notebook *plus* the two cells Start appended —
    // `agent.unlock <the creator's fingerprint>` and a `quorum.offer` over the
    // room. Neither was runnable here: the key is not in this vault, and this
    // browser is already in the session that cell would open. The run stopped at
    // cell 3 with "Key not found in vault", every time, on a notebook a peer had
    // told them to adopt.
    //
    // It was fixed by heading those cells on the creator, so the gate declined
    // them; it is fixed now by their not existing. The absence is still
    // asserted, because "the run walked to the end and never asked this vault
    // for somebody else's key" is the property, however few cells are in the
    // way of it.
    expect(await runLine(joiner)).not.toContain("Key not found in vault");
    expect(await runLine(joiner)).toMatch(/^Done\b/);
    // One declined cell, and it is the creator's last: everything else in this
    // notebook is either this machine's or already run.
    expect(await cellStatus(joiner, 2)).toBe("declined");
    // The cell they were handed is the one that ran, and it is the only one.
    expect(await cellStatus(joiner, 1)).toBe("ok");

    // What this run owes the room, and it is one cell. The history is worth
    // keeping: the run used to hand back *three* — cell 2, which carries the
    // `$b64` the creator's own cell waits on and is the point of the exchange,
    // and cells 3 and 4, the creator's session cells, which the creator ran
    // half an hour ago to open the room the offer travels over. Offering those
    // back is what forced the rule this counts: a declined cell is handed over
    // when this machine is on one end of it — it reads a value made here, or
    // writes one read here.
    //
    // Two of the three were the session's, and they are gone, so the *shape*
    // that made the rule is no longer reachable from this press. The rule is
    // not softened for that: `aside` still has to be demonstrated across two
    // browsers, and step 9 is where it is — the dealer's run declines the
    // holder's `quorum.recv`, a cell nothing here is waiting on, and that row
    // is asserted `aside` by name.
    await trayTab(joiner, "Connections");
    const outgoing = tray(joiner).locator("[data-handoff-outgoing] li");
    await expect.poll(async () => await outgoing.count(), { timeout: 20000 }).toBe(1);
    const states = await outgoing.locator("[data-offer-state]").evaluateAll((els) =>
      els.map((el) => el.getAttribute("data-offer-state"))
    );
    expect(states.filter((s) => s === "sent")).toHaveLength(1);
    expect(states.filter((s) => s === "aside")).toHaveLength(0);
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
    // The returning half of the same rule, on the other machine. A result is the
    // more dangerous of the two arrivals — accepting one puts a peer's values
    // into this registry — so a row that survived its own accept would be an
    // invitation to register them twice.
    expect(
      await result.count(),
      "the accepted result is still in the queue with the press still on it"
    ).toBe(0);
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

  /* ── 7b. a refusal that keeps the document, and a remedy that works ─────── */

  /**
   * The state this arrives in is reached by pressing Run twice, and nothing else.
   *
   * Step 7 ends with the creator pressing Run all. The gate declines cell 1
   * again — it is still the joiner's — and `handOffPlaced` hands every declined
   * cell this machine is an end of straight back over the wire as the run ends.
   * So a second offer for cell 1 lands on the joiner carrying `$seed`, which the
   * joiner accepted in step 6 and still holds. `reviewOffer` is given `hasSlot`
   * and refuses it `slot-present`. No contrivance: two Runs on one machine and
   * the second offer is on the other person's screen.
   *
   * **What this used to do, and why it was the worst place for it.**
   * `acceptHandoff` called `takeHandoff(id)` on its first line and computed the
   * verdict afterwards, so by the time anything had decided, the only copy of
   * the document was already out of the queue — `takeHandoff` succeeds exactly
   * once and is the only way a document leaves it. A refusal therefore consumed
   * what it refused. On this path the thing consumed is another person's work:
   * an offer carries the values a cell reads, and a *result* carries what their
   * machine computed. Recovering it means asking them to run the cell again.
   *
   * The sentence made it worse. `slot-present` reads "`$seed` already holds a
   * value on this machine … Clear the slot if the offered value is the one you
   * want" — and the Slots tray has a Clear button, so a reader would do exactly
   * that and find nothing left to accept. A remedy naming a press that cannot
   * complete is `47e7ffa`'s defect class, aimed at a peer's cell.
   *
   * A second finding, and it is why the note is asserted here rather than only
   * the count: **that sentence never reached a screen**. `summarizeHandoff`
   * returns `handoff refused at cell 1 (needs)` for any refusal — a locator, no
   * remedy — and the shell put that in the handoff note. The message field
   * where handoff.js does its careful wording was dropped by the projection, so
   * the promise this step is named for was one only a reader of the source
   * could see. Both halves are asserted, because fixing the ordering alone
   * would leave a person correctly told nothing.
   */
  it("refuses the second offer without spending it, and says what to do", async () => {
    await trayTab(joiner, "Connections");
    const pending = tray(joiner).locator("[data-handoff-pending] li");
    // The creator's second run handed it over by itself; nobody pressed for it.
    await expect.poll(async () => await pending.count(), { timeout: 20000 }).toBe(1);
    expect(await pending.first().getAttribute("data-handoff-kind")).toBe("offer");
    expect(await pending.first().innerText()).toContain("cell 1");
    // The collision, stated: this machine already holds what the offer carries.
    expect(await answerSlots(joiner)).toEqual(["b64", "seed"]);

    await trayTab(joiner, "Connections");
    await joiner.getByRole("button", { name: "Review and accept" }).click();
    const note = joiner.locator("[data-handoff-note]");
    // Polled on `handoff.js`'s own words rather than on anything this fix
    // added, so the wait is not satisfied by the sentence it is here to check.
    await expect
      .poll(async () => await note.innerText(), { timeout: 20000 })
      .toMatch(/Clear the slot/);

    // The remedy, on screen. Not "handoff refused at cell 1 (needs)".
    const said = await note.innerText();
    expect(said, "the refusal names a slot the reader can act on").toContain("$seed");
    // And the sentence that makes the remedy performable: it is still here.
    expect(said, "the note does not say the document survived the refusal").toMatch(
      /still in the queue|Nothing was taken/i
    );

    // **On the row as well as in the note**, which is a separate mechanism and
    // would otherwise be one nothing checks. The note is one paragraph for the
    // whole panel and the next press anywhere overwrites it; the row is where a
    // reader looks to find out why *this* document is still sitting there. A
    // refusal that reached only the note would leave the row looking like one
    // nobody has touched — the ambiguity keeping a refused document creates.
    const rowRefusal = pending.first().locator("[data-handoff-refusal]");
    await expect.poll(async () => await rowRefusal.count(), { timeout: 20000 }).toBe(1);
    expect(await rowRefusal.innerText()).toContain("$seed");

    // **The row survived its own refusal**, which is the whole of the fix. The
    // reader can clear the slot and press again, and the peer's document is
    // where they left it.
    expect(
      await pending.count(),
      "the refusal spent the document it refused — the peer's work is gone"
    ).toBe(1);

    // Perform the remedy the sentence named, through the product's own button,
    // and press accept again. This is the assertion that the sentence is true:
    // a promise a suite does not carry out is a promise nobody checked.
    await trayTab(joiner, "Slots");
    await tray(joiner)
      .locator("li")
      .filter({ hasText: "@seed" })
      .getByRole("button", { name: "Clear" })
      .click();
    expect(await answerSlots(joiner)).toEqual(["b64"]);
    await trayTab(joiner, "Connections");
    await joiner.getByRole("button", { name: "Review and accept" }).click();
    await expect
      .poll(async () => await note.innerText(), { timeout: 20000 })
      .toMatch(/Accepted — 1 value registered/);
    expect(await answerSlots(joiner)).toEqual(["b64", "seed"]);
    // Accepted, so *now* it is spent — step 6's invariant, on a document that
    // had already been refused once.
    expect(
      await pending.count(),
      "the accepted offer is still in the queue with the press still on it"
    ).toBe(0);
  });

  /* ── 7c. and a refusal a person can put down ────────────────────────────── */

  /**
   * The other half of keeping a refused document: something has to end it.
   *
   * A document that stays pending after a refusal is honest — it *is* still
   * pending, and 7b is the case where that is the whole point. But a refusal
   * whose cause never changes would leave a row with a live "Review and accept"
   * on it for the rest of the session, and the queue would stop being a list of
   * things waiting on a person. So the row also carries Dismiss.
   *
   * It is a press and never anything else, and it sends nothing: `offerAwaiting`
   * already says there is no decline message on the wire, and a peer who
   * declines and a peer who never looked are the same state from the other end.
   * Dismiss drops it here and tells nobody, which is what this asserts — the
   * creator's outgoing row must be exactly as it was.
   *
   * The exactly-once property is untouched by it. `takeHandoff` is still the
   * only way a document leaves the queue and still succeeds once; what changed
   * is that two presses reach it — accept and dismiss — and `quorum-ops` already
   * said taking and accepting were separate acts for this reason.
   */
  it("lets a person put a pending document down, and tells nobody", async () => {
    // One more offer, by the press the panel offers for it.
    await trayTab(creator, "Connections");
    const outgoing = tray(creator).locator("[data-handoff-outgoing] li");
    await expect.poll(async () => await outgoing.count(), { timeout: 20000 }).toBe(1);
    await outgoing.getByRole("button", { name: /^Hand cell 1 to/ }).click();

    await trayTab(joiner, "Connections");
    const pending = tray(joiner).locator("[data-handoff-pending] li");
    await expect.poll(async () => await pending.count(), { timeout: 20000 }).toBe(1);

    // Refuse it, the same way and for the same reason: 7b put `$seed` back, so
    // this offer collides exactly as that one did. Now the row is annotated and
    // still pending — the state a dismissal is for.
    await joiner.getByRole("button", { name: "Review and accept" }).click();
    await expect
      .poll(async () => await pending.first().locator("[data-handoff-refusal]").count(), {
        timeout: 20000,
      })
      .toBe(1);

    // **A second document, while the first one's refusal is on screen.** This is
    // what makes the annotation's keying checkable at all: the map is non-empty,
    // a new row arrives, and the reason must stay on the document it was about.
    // An annotation drawn per *panel* rather than per document would label this
    // one too, and tell the reader a fresh offer had already been refused.
    await trayTab(creator, "Connections");
    await outgoing.getByRole("button", { name: /^Hand cell 1 to/ }).click();
    await trayTab(joiner, "Connections");
    await expect.poll(async () => await pending.count(), { timeout: 20000 }).toBe(2);
    expect(
      await pending.locator("[data-handoff-refusal]").count(),
      "a document nobody has pressed is drawn as one that was already refused"
    ).toBe(1);

    // Put both down. Two presses, because two documents — there is no "dismiss
    // all", and inventing one would be a single press discarding several
    // people's work.
    await pending.first().getByRole("button", { name: "Dismiss without accepting" }).click();
    await expect
      .poll(async () => await joiner.locator("[data-handoff-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/Dismissed/);
    await expect.poll(async () => await pending.count(), { timeout: 20000 }).toBe(1);
    // And the refusal went with the document it belonged to.
    expect(await pending.locator("[data-handoff-refusal]").count()).toBe(0);
    await pending.first().getByRole("button", { name: "Dismiss without accepting" }).click();
    await expect.poll(async () => await pending.count(), { timeout: 20000 }).toBe(0);
    // Nothing was registered by putting it down — the two slots are the ones
    // this machine had before the row arrived.
    expect(await answerSlots(joiner)).toEqual(["b64", "seed"]);

    // And the other end was not told. There is no decline on this wire, by
    // design, so the creator's row still reads as an offer that went out.
    await trayTab(creator, "Connections");
    expect(
      await outgoing.locator("[data-offer-state]").getAttribute("data-offer-state")
    ).toBe("sent");
  });

  /* ═══════════════════════════ the ceremony ═════════════════════════════════
   *
   * Everything above is the *handoff* arc: a cell runs where the notebook
   * places it and its answer comes back as a signed document somebody accepts.
   * `quorum.send` / `quorum.recv` are a second road, and until this section
   * existed nothing had ever driven it. They do not go through handoffs at all
   * — `execQuorumSend` writes straight to `NotebookSession.sendChatTo`, which
   * encrypts under the per-peer session key and puts bytes on that peer's data
   * channel; `execQuorumRecv` reads `ex.inbox`, which `onChat` fills. No
   * manifest is compared, no signature is checked at this layer beyond the one
   * the session already made, and no press accepts anything.
   *
   * `docs/LANGUAGE.md` designs a whole vocabulary — `scatter`, `gather`, the
   * quorum-as-a-fraction — on top of that road, and closes by saying so: "the
   * design gates on it". It is also, verified, named by zero presets, so the
   * only way a person has ever reached these two verbs is by typing them.
   *
   * Five questions, in the order they decide whether the ceremony can ship, and
   * each of the five steps below answers one of them.
   *
   * 1. **Does the share arrive at all?** Step 8/9. The dealer splits a secret
   *    this browser has never seen before, sends exactly one share, and the
   *    holder's cell writes a value into `$share`. Both ends' tiles are
   *    *revealed by a press* and compared, and the holder's value is asserted
   *    against all three of the dealer's shares — equal to share 2, unequal to
   *    1 and 3 — so "it arrived" cannot be satisfied by the holder producing
   *    something plausible.
   * 2. **Does ordering matter?** Both orders are driven, and they are genuinely
   *    different code paths. Step 9 sends while the holder's cell has not run:
   *    `onChat` finds no waiter and pushes to `ex.inbox`, and the holder's
   *    later `takeQueued()` picks it up. Step 10 runs the holder's cell first
   *    and sends into a waiting `recvWaiters` entry. Both are safe, and step 9
   *    is the one that would have looked like the invite defect `fb178e4` fixed
   *    — arriving before anybody is listening — if the inbox were not there.
   * 3. **What does the placement gate do to the holder's cell?** Step 9 reads
   *    it off both screens. The decline itself is step 5's finding repeated on
   *    a new cell; the interesting part is what the decline *produces*, because
   *    since `a4f9399` a run also hands its declined cells over by itself. A
   *    `quorum.recv` cell is the case that makes that question sharp: its value
   *    has already arrived by a road the handoff arc knows nothing about. Step
   *    9 says what the two queues do about it and where their words stop being
   *    true of this ceremony.
   * 4. **What is a holder told when nothing is sent?** Step 11, with `wait=`
   *    turned down so the suite does not sit for two minutes. The message has
   *    to describe the room the holder is actually in — which, on the
   *    recommended ordering, is a healthy one where the dealer is still
   *    reading. The tray is asserted verified in the same breath.
   * 5. **Can the ceremony be reversed?** Steps 12 and 13, and they are the ones
   *    that decide whether any of this can ship. The dealer recovers the master
   *    from their own set, the holder recovers it from the two shares that
   *    crossed the room, and the two strings are compared through the screen.
   *
   * ## Why this rides on the session steps 1–7 already opened
   *
   * Because that is the only way a person reaches these verbs: `quorum.send`
   * refuses without a live exchange, and the exchange is the room Start and
   * Join opened in steps 2 and 3. Standing a
   * second room up here would be testing a session this file already proved and
   * would not be testing the thing that is new. The notebook simply grows: the
   * ceremony cells are appended to the notebook both browsers are holding, and
   * they travel the same way the first three did.
   *
   * It grows in **three** proposals rather than one, and that is forced rather
   * than stylistic. Pressing Run on a cell runs every cell from there down, so
   * a notebook that already contained the holder's second `quorum.recv` would
   * have the holder blocking on it the moment they ran the first — and a
   * notebook containing the dealer's second `quorum.send` would have the dealer
   * firing it before the holder was listening, which is the ordering step 10
   * exists to drive. Each phase therefore ends with the holder's receiving cell
   * as the last cell in the notebook. The re-share is free: `decideProposal`
   * adopts without a press when the text came from the same peer it came from
   * last time and nothing was typed here since, so the second and third
   * proposals land silently — which is itself asserted, because a proposal that
   * needed a press would mean the joiner had edited something.
   */

  /**
   * The ceremony, spelled as a person types it.
   *
   * Functions rather than constants because two of the three lines carry a
   * *whole fingerprint* the room chooses, and there is no fingerprint until
   * `beforeAll` has asked `roomRoster` for one. That is the same rule the
   * `@peer` headers follow and for the same reason — a name this file invented
   * would be one the room might not agree with.
   *
   * `to=` and `from=` are typed into the editor here, and that is not the
   * `@peer` header's rule being broken: a header is *chosen* from a menu
   * because the menu is the defect surface (`96dde48`), while `to=` is a step
   * parameter with no menu behind it in this product. Typing it is what a
   * person does. It is asserted against `L` rather than written down, so the
   * two fingerprints in the cell are still the room's answer and not this
   * file's.
   */
  const SPLIT = "random 32 | sss.split threshold=2 shares=3 | blip39 | out $set";
  const sendCell = (to, n) => `$set | at ${n} | quorum.send to=${to}`;
  const recvCell = (from, slot) => `quorum.recv from=${from} | out $${slot}`;

  /** Append one cell and give it to `label`. The two presses that add a cell. */
  async function appendCell(page, i, text, label) {
    await page.getByRole("button", { name: "Cell", exact: true }).click();
    await writeCell(page, i, text);
    await assignCell(page, i, label);
  }

  /**
   * The ceremony's own slots, as the Slots tab prints them.
   *
   * A second filter beside `answerSlots` rather than a widened one, for that
   * function's stated reason: every assertion here is about *where a value was
   * computed*, and `seed`/`b64`/`done` are still on both machines from steps
   * 5–7. Mixing them in would make "the holder holds one thing" a sentence
   * about the earlier arc.
   */
  async function ceremonySlots(page) {
    await trayTab(page, "Slots");
    const rows = tray(page).locator("li code");
    const out = [];
    for (const text of await rows.allInnerTexts()) {
      const m = /^@(set|share|late|never|secret|master)$/.exec(text.trim());
      if (m) out.push(m[1]);
    }
    return out.sort();
  }

  /**
   * Uncover one output tile and read what it says, which is two presses' worth
   * of a person's attention: a share is `sensitive`, so its tile says
   * "sensitive — value not shown" until Reveal is pressed.
   *
   * This is the only way to compare a value across the two browsers without
   * reaching into either of them, and the reveal is itself part of what is
   * being tested — `out` is what marks a tile `revealable`, so a road that
   * delivered a share into a tile nobody could open would be a road that
   * delivered nothing a person can use. The list re-hides after fifteen
   * seconds, so the read follows the press immediately.
   */
  async function reveal(page, i, label) {
    const tile = cell(page, i).locator("[data-artifact-kind]").filter({ hasText: label }).first();
    await tile.waitFor({ state: "visible", timeout: 20000 });
    const button = tile.getByRole("button", { name: "Reveal" });
    expect(
      await button.count(),
      `the tile for ${label} offers no way to see the value it holds`
    ).toBe(1);
    await button.click();
    const body = tile.locator(".artifact-body");
    await body.waitFor({ state: "visible", timeout: 10000 });
    return (await body.innerText()).trim();
  }

  /** Whatever a cell is currently complaining about, compile-time or run-time. */
  async function cellErrors(page, i) {
    const box = cell(page, i).locator("[data-cell-type-errors]");
    return (await box.count()) ? (await box.innerText()).trim() : "";
  }

  /**
   * Put the creator's notebook in front of the joiner and wait for it to be the
   * joiner's, however that happens.
   *
   * Polled on the *text*, not on a button, because after the first adoption
   * there is no button: `decideProposal` returns `adopt` without asking when
   * the proposal came from the same peer as the last one and nothing has been
   * typed here since. Asserting a press would be asserting the joiner had
   * edited their notebook, which is the opposite of what is true.
   */
  async function shareNotebook() {
    const want = await readNotebookSource(creator);
    await trayTab(creator, "Connections");
    await tray(creator).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await creator.locator("[data-notebook-share-note]").innerText(), {
        timeout: 20000,
      })
      .toMatch(/written to 1 open channel · unconfirmed/);
    await expect
      .poll(async () => await readNotebookSource(joiner), { timeout: 30000, intervals: [250] })
      .toBe(want);
    expect(
      await joiner.locator("[data-notebook-proposed]").count(),
      "the joiner was asked to adopt a revision of a notebook they had not edited"
    ).toBe(0);
    return want;
  }

  /** What the holder revealed out of the ceremony, phase by phase. */
  let held = { early: "", late: "" };
  /** The dealer's three shares, as the dealer's own screen prints them. */
  let dealt = [];
  /**
   * The secret behind those shares, recovered on the dealer's own machine.
   *
   * Read off the dealer's screen rather than computed here, for the reason
   * every other comparison in this file is: a value this test worked out would
   * be a claim about the library, and what is being asked is whether two
   * browsers agree.
   */
  let dealtSecret = "";

  /* ── 8. the ceremony is written into the notebook both ends hold ─────────── */

  it("writes a split-and-send ceremony into the notebook, and it travels", async () => {
    await appendCell(creator, 3, SPLIT, L.creator);
    await appendCell(creator, 4, sendCell(L.joiner, 2), L.creator);
    await appendCell(creator, 5, recvCell(L.creator, "share"), L.joiner);

    const src = await readNotebookSource(creator);
    // **The quorum is in the text.** `docs/LANGUAGE.md` opens on this exact
    // recipe as the case where it was not: `sss.split threshold=2 shares=3`
    // round-tripped to `sss.split`, so the whole security property was absent
    // from what the two ends digest. `ade4043` fixed it, and migration step 2
    // then made the quorum the verb's object — the named pair this test types
    // canonicalizes to the fraction, and the fraction is what stands in the
    // notebook that actually travels. The property pinned is unchanged: both
    // numbers are in the text.
    expect(src).toContain("sss.split 2/3");
    // Both addressed ends are whole keys, and they are the room's keys — the
    // send names the holder, the receive names the dealer. A prefix would still
    // work at run time (`sendChatTo` matches on one, `takeQueued` on the
    // other), which is exactly why it is worth pinning that neither the editor
    // nor the serializer shortened one.
    expect(src).toContain(`quorum.send ${L.joiner}`);
    expect(src).toContain(`quorum.recv from=${L.creator}`);
    expect(src).not.toContain("…");
    const cells = src.split(/\n\s*\n+/).map((c) => c.trim());
    expect(cells).toHaveLength(6);
    expect(cells[3].split("\n")[0]).toBe(`@${L.creator}`);
    expect(cells[4].split("\n")[0]).toBe(`@${L.creator}`);
    expect(cells[5].split("\n")[0]).toBe(`@${L.joiner}`);
    // Never `publish`. The whole point of `quorum.send` is that a value leaves
    // this machine because a *verb* said so — principle 2 of the language
    // design — and a header that also disclosed it would be the second road
    // out of the same cell.
    expect(cells[4]).not.toContain("publish");

    // It compiles, and it compiles *for the person* — read off the control
    // rather than out of the compiler, because "the recipe parses" and "Run all
    // can be pressed" are two facts and only the second is what a reader has.
    // `runRefusal` turns the first compiler error into this button's reason,
    // and step 12 is where that is read the other way round.
    expect(
      await creator.getByRole("button", { name: "Run all" }).getAttribute("aria-disabled")
    ).toBe(null);
    for (const i of [3, 4, 5]) expect(await cellErrors(creator, i)).toBe("");

    const shared = await shareNotebook();
    expect(shared).toBe(src);
    // Arrived and untouched by any run. `loadRecipeText` clears the per-cell
    // buckets of the notebook it closes, so the three new cells cannot be
    // wearing what stood at those indexes before — there was nothing at those
    // indexes before, and this is the assertion that says the clear reaches the
    // tail as well as the head.
    for (const i of [3, 4, 5]) expect(await cellStatus(joiner, i)).toBe("idle");
    expect(await ceremonySlots(joiner)).toEqual([]);
  });

  /* ── 9. the dealer sends before the holder is listening ──────────────────── */

  it("delivers a share to a holder whose receiving cell has not run yet", async () => {
    // The dealer's run: split, send, and stop at somebody else's cell. Started
    // at cell 3 rather than with Run all, because Run all would re-run cells
    // 0–2 and `out $seed` would refuse as a duplicate slot — which is the
    // notebook working correctly and would say nothing about this ceremony.
    await cell(creator, 3).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(creator);
    expect(await runLine(creator)).toMatch(/^Done\b/);
    expect(await cellStatus(creator, 3)).toBe("ok");
    expect(await cellStatus(creator, 4)).toBe("ok");
    // Step 5's finding, on this ceremony: the gate's cell says it did not run.
    expect(await cellStatus(creator, 5)).toBe("declined");
    expect(await ceremonySlots(creator)).toEqual(["set"]);

    // **What the dealer can see of what they just sent: nothing.** The send
    // cell has no `out`, so its tip is materialized by the engine rather than
    // asked for, and `revealable` is the engine's word for "somebody wrote
    // `out`". That is the designed behaviour (§34b) and it is worth pinning
    // here rather than only in a unit test, because it is the reason the
    // comparison below has to go through `$set`: on this screen the share that
    // left the machine is a tile that says it is not being shown.
    const sent = await cell(creator, 4).innerText();
    expect(sent).toContain("sensitive — value not shown");
    expect(
      await cell(creator, 4).getByRole("button", { name: "Reveal" }).count(),
      "the cell that sent a secret offers to show it"
    ).toBe(0);

    // The three shares the dealer holds, each uncovered by its own press. They
    // are read *before* the holder's cell runs, so nothing on the holder's
    // machine can have informed them.
    dealt = [
      await reveal(creator, 3, "share 1"),
      await reveal(creator, 3, "share 2"),
      await reveal(creator, 3, "share 3"),
    ];
    for (const m of dealt) expect(m.split(/\s+/).length).toBeGreaterThan(8);
    expect(new Set(dealt).size, "the split produced the same share twice").toBe(3);

    // **And what the dealer can see of it now: a record, which is not a copy.**
    //
    // The two paragraphs above are the designed behaviour and they stay. What
    // they left was a person who had just performed the one act in this product
    // that cannot be undone, with nothing on screen afterwards saying what left
    // the machine, to whom, or when — the run status line, which the next press
    // overwrites, and nothing else. Giving the step an `out` would have answered
    // that by putting the *holder's* share in the dealer's own Slots tray, which
    // is worse and is what `b1ce6d9` removed from this very ceremony.
    //
    // So the send writes to the Activity log, which `activity-log.js` was built
    // for and whose rules are exactly the four this needs — digests never
    // values, session-scoped never persisted, copyable as text for a ceremony's
    // minutes, and every action that moves something logged, because "a log that
    // records only the dramatic actions answers the wrong question at 2am". It
    // held Copy and Download and did not hold this.
    //
    // Asserted on the dealer's screen rather than on the entry, because the
    // recurring defect here is a finished mechanism with no consumer:
    // `recordActivity` had one caller, the artifact tile's action runner, and no
    // run has ever been able to reach it.
    await trayTab(creator, "Activity");
    const logged = tray(creator).locator("[data-activity-log] li");
    await expect.poll(async () => await logged.count(), { timeout: 20000 }).toBe(1);
    const row = logged.first();
    expect(await row.getAttribute("data-action-tier")).toBe("outward");
    const rowText = await row.innerText();
    expect(rowText).toContain("Sent over the session");
    // Which share went where — the question the ceremony is made of.
    expect(rowText).toContain("share 2");
    // Whole, in this column too. This is the record of where a secret went and
    // it is the last place in the product to print part of a key.
    expect(rowText.replace(/\s/g, "")).toContain(L.joiner);
    // A digest and not the value. `dealt[1]` is the share that left; it was read
    // off this same screen a moment ago, so this compares the record against
    // what the dealer knows rather than against something recomputed here.
    expect(rowText).toMatch(/sha256 [0-9a-f]{16}…/);
    // The row's one ellipsis is the digest's own, and it is allowed: sixteen hex
    // characters of a hash is a prefix of a *hash*, which carries no bits of
    // anybody's key and is the same sixteen a run receipt prints. Removed before
    // the sweep rather than exempted after it, so a truncation appearing
    // anywhere else in this row — the fingerprint above all — still fails.
    expect(rowText.replace(/sha256 [0-9a-f]{16}…/, "")).not.toContain("…");
    expect(
      rowText,
      "the sender kept a copy of the share instead of a record of it"
    ).not.toContain(dealt[1].split(/\s+/)[0]);

    // **What the run did with the cell it declined**, which is the third
    // question this section was written to answer and the one whose answer
    // moved while it was being asked.
    //
    // Step 5 pins the other half: a run hands its declined cells over by
    // itself, because `a4f9399` found `offerCell` with one caller in the whole
    // product while the queue's copy promised the cells "are offered to whoever
    // owns them". Cell 1 of this notebook is that case — the creator's own last
    // cell reads what it writes, so the run *is* waiting on it.
    //
    // Cell 7 is not that case and this run does not hand it over. It reads no
    // slot made here and nothing here reads `$share`, so the queue leaves it
    // alone and says which of the three states that is. That is the right
    // answer, and it is the right answer for a reason that does not survive
    // contact with this ceremony: the sentence says "it would carry nothing",
    // and what makes that true is that a handoff carries *slots*. The dealer
    // has already sent this cell its value down a road the queue cannot see, so
    // "nothing here is waiting on it" is true of the plan and false of the
    // room. Nobody is misled here — this cell genuinely needs no offer — but
    // the reasoning is about the wrong road, and a ceremony where a
    // `quorum.recv` cell *also* read a slot would get a handoff offering the
    // slot and saying nothing about the share.
    //
    // **Asserted by the state's own name now.** It used to be "not `sent`",
    // deliberately narrower, because the behaviour was being changed in another
    // chair while this was written. It has landed, and this row has become the
    // only two-browser demonstration of `aside` in the repo: step 6 used to
    // carry two of them, and both were the creator's session cells, which are
    // no longer written. A rule with no journey behind it is the shape of
    // defect this file exists to catch, so the narrower spelling is spent here
    // rather than kept.
    await trayTab(creator, "Connections");
    const away5 = tray(creator)
      .locator("[data-handoff-outgoing] li")
      .filter({ hasText: "Cell 5 is" });
    await expect.poll(async () => await away5.count(), { timeout: 20000 }).toBe(1);
    // Whole, in this column too — step 5's rule, and this row now carries the
    // key twice (in the sentence and on the button).
    expect((await away5.innerText()).replace(/\s/g, "")).toContain(L.joiner);
    expect(await away5.innerText()).not.toContain("…");
    expect(
      await away5.locator("[data-offer-state]").getAttribute("data-offer-state"),
      "the run handed over a cell nothing on this machine is waiting on"
    ).toBe("aside");
    // And nothing arrived at the holder for it. The only offer in their queue
    // is cell 1's, from step 6, which they have already accepted — the queue
    // does not clear a row once it is taken.
    await trayTab(joiner, "Connections");
    const offered5 = tray(joiner)
      .locator('[data-handoff-pending] li[data-handoff-kind="offer"]')
      .filter({ hasText: "cell 5" });
    expect(
      await offered5.count(),
      "the holder was offered a cell whose value had already reached them by another road"
    ).toBe(0);

    // Press Run on the holder's own cell — *without* accepting that offer,
    // which is the honest order: the offer is not what makes this cell
    // runnable, the header is. The gate admits it because the notebook places
    // it here.
    //
    // The clock is the assertion. `quorum.recv` defaults to a 120s wait, and
    // the message that was sent a moment ago arrived when nothing was listening
    // — `onChat` found `recvWaiters` empty and pushed it to `ex.inbox`. If it
    // had been dropped there instead of queued, this press would sit for two
    // minutes and then fail, and the failure would read as a transport fault.
    // So the cell has to *finish* in a window that could not contain a wait.
    //
    // Polled with its own thirty-second bound rather than by timing
    // `runSettled`, and that is the difference between a diagnosis and a
    // stopwatch. A break in the send path makes this cell sit for the full
    // 120s, which outlives the suite's own per-test budget — so a `took <
    // 30000` measured afterwards never gets taken, and what a reader is handed
    // is "Test timed out in 120000ms" with no mention of a share. This fails
    // first, inside the window, in a sentence about the queue.
    await cell(joiner, 5).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(joiner, 5), {
        timeout: 30000,
        intervals: [250],
        message:
          "the holder's recv is still waiting for a share the dealer already sent — " +
          "a message that arrives before the receiving cell runs is being dropped " +
          "rather than queued on `ex.inbox`",
      })
      .toBe("ok");
    await runSettled(joiner);
    expect(await runLine(joiner)).toMatch(/^Done\b/);
    expect(await ceremonySlots(joiner)).toEqual(["share"]);

    // **And it is the dealer's share 2, on the holder's screen.** Equality
    // against one of them and inequality against the other two, because either
    // half alone is satisfiable by accident: a holder that received nothing and
    // drew a blank tile would fail the first, and a road that delivered *the
    // set* rather than the share the recipe addressed would pass it.
    held.early = await reveal(joiner, 5, "share");
    expect(held.early, "the holder's slot does not hold the share that was sent").toBe(dealt[1]);
    expect(held.early).not.toBe(dealt[0]);
    expect(held.early).not.toBe(dealt[2]);
    // Thirty-two bytes of `crypto.getRandomValues`, drawn on the other machine
    // three presses ago. There is no cell in this notebook that could produce
    // this string here, and this browser had no slot at all a moment ago.
    expect(dealt[1]).not.toBe("");
  });

  /* ── 10. and the other order: the holder is listening first ──────────────── */

  it("delivers a share to a holder whose receiving cell is already waiting", async () => {
    await appendCell(creator, 6, recvCell(L.creator, "late"), L.joiner);
    await appendCell(creator, 7, sendCell(L.joiner, 3), L.creator);
    await shareNotebook();
    expect(await cellStatus(joiner, 6)).toBe("idle");

    // Not awaited. This press starts a run that walks cell 6 — the holder's
    // second `quorum.recv` — and there is nothing in the inbox for it, so it
    // parks in `recvWaiters` and the run stays in flight. Everything below
    // happens while this promise is outstanding, which is the whole of what
    // this step is for.
    const running = cell(joiner, 6).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await joiner.locator("[data-run-state]").getAttribute("data-run-state"), {
        timeout: 20000,
        intervals: [100],
      })
      .toBe("running");
    // Still running a moment later, and still holding nothing. This is the
    // difference between "waiting" and "finished quickly": step 9's run
    // returned at once because the value was already there, and this one
    // cannot return until the dealer acts.
    await joiner.waitForTimeout(2000);
    expect(
      await joiner.locator("[data-run-state]").getAttribute("data-run-state"),
      "the holder's recv finished before anything was sent to it"
    ).toBe("running");

    // The dealer sends, now, into a channel somebody is listening on.
    await cell(creator, 7).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(creator);
    expect(await cellStatus(creator, 7)).toBe("ok");

    await running;
    // Bounded well inside the 120s the holder's cell would otherwise wait, for
    // step 9's reason: a delivery that never lands has to be reported as a
    // delivery that never landed, and not as a suite that ran out of patience.
    await expect
      .poll(async () => await cellStatus(joiner, 6), {
        timeout: 30000,
        intervals: [250],
        message:
          "the holder's recv was parked on `recvWaiters` when the dealer sent, and " +
          "is still parked — the send reached no waiter",
      })
      .toBe("ok");
    await runSettled(joiner);
    expect(await runLine(joiner)).toMatch(/^Done\b/);
    // The dealer's cell 7 is declined here and was not run by this press, which
    // is what makes the value below one that crossed rather than one this
    // machine made.
    expect(await cellStatus(joiner, 7)).toBe("declined");
    expect((await ceremonySlots(joiner)).includes("late")).toBe(true);

    held.late = await reveal(joiner, 6, "late");
    expect(held.late, "the waiting holder did not receive the share that was sent").toBe(
      dealt[2]
    );
    // Two shares of one split, on the machine that never split anything, and
    // the second is not the first: a road that had simply replayed its inbox
    // would hand over share 2 again.
    expect(held.late).not.toBe(held.early);
  });

  /* ── 11. what a holder is told when nothing is sent ──────────────────────── */

  it("reports a receive that timed out in words about the room it is in", async () => {
    // `wait=3000` rather than the 120s default, and the shortening is the only
    // thing this step does differently from a real one: the message is built
    // from `wait` (`no message within ${Math.round(wait / 1000)}s`), so what a
    // reader sees at three seconds is what they see at a hundred and twenty
    // with one number changed. Nothing else about the path differs.
    await appendCell(
      creator,
      8,
      `quorum.recv from=${L.creator} wait=3000 | out $never`,
      L.joiner
    );
    await shareNotebook();

    await cell(joiner, 8).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(joiner);

    // **The room is healthy while this is being said**, and that pairing was
    // the whole finding: the peer is connected and both proofs still hold at
    // the moment the holder is told a message did not arrive. The sentence used
    // to be `quorum.recv: no message within 120s` and nothing else — a
    // stopwatch, which a reader spends on the transport, which here is the one
    // part that is working. It now says what this end can prove.
    await trayTab(joiner, "Connections");
    expect(await tray(joiner).locator('[data-verified="1"]').count()).toBe(1);

    const said = await runLine(joiner);
    expect(said).toContain("no message within 3s");
    // The peer `from=` named, whole — the same rule as every other fingerprint
    // in this file. A prefix would still have matched at run time, which is
    // exactly why it is worth pinning that the refusal prints the key.
    expect(said).toContain(L.creator);
    expect(said).not.toContain("…");
    // The link, in the words the tray two lines above draws its own verdict
    // from, so the message and the panel a reader checks it against cannot
    // disagree.
    expect(said).toContain("1 peer is connected and key-confirmed");
    // What this room has actually carried. Two shares crossed it in steps 9 and
    // 10 and both were read, so the inbox is empty and the count is not — which
    // is the distinction the old message could not make and the one that
    // separates a quiet room from a dead one.
    expect(said).toContain("2 messages so far");
    // And that waiting is normal, which it is: this is reachable on the
    // recommended ordering, where the holder listens before the dealer sends.
    expect(said).toContain("ordinary state of a healthy room");
    expect(said).toContain("quorum.send");
    // Both remedies performable by the person reading this screen — `47e7ffa`'s
    // rule. Neither of them asks them to do something on the dealer's machine.
    expect(said).toContain("Press Run on this cell again");
    expect(said).toContain("longer wait=");
    expect(await cellStatus(joiner, 8)).toBe("error");
    // The same sentence is in the cell, which is where a reader looks after the
    // run bar tells them a cell stopped.
    expect(await cellErrors(joiner, 8)).toContain("no message within 3s");
    expect(await cellErrors(joiner, 8)).toContain("2 messages so far");
    expect(await ceremonySlots(joiner)).not.toContain("never");
  });

  /* ── 12. the dealer recombines their own set, so there is something to
        compare the holder's answer against ───────────────────────────────── */

  it("puts the dealer's own secret on the dealer's screen", async () => {
    // The other end of the assertion step 13 makes. The dealer holds the whole
    // set and can recover the master from it; the holder holds two of the three
    // shares and nothing else. If those two numbers match, the ceremony
    // round-tripped — and they are recovered from *different pairs* of the same
    // polynomial (`sss.combine` takes the first `threshold` shares, so this is
    // 1 and 2, and the holder has 2 and 3), which a road that had simply copied
    // a value across could not produce.
    //
    // It has to be a cell rather than something read out of the split, because
    // `random 32 | sss.split` never writes the master anywhere: the secret is
    // not `out`, which is the design and is why this file could not compare
    // anything before.
    await appendCell(
      creator,
      9,
      "$set | blip39 -d | sss.combine | encode hex | out $master",
      L.creator
    );
    await shareNotebook();

    await cell(creator, 9).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(creator);
    expect(await cellStatus(creator, 9)).toBe("ok");
    dealtSecret = await reveal(creator, 9, "master");
    expect(dealtSecret, "the dealer's own recombination produced nothing").toMatch(
      /^[0-9a-f]{64}$/
    );
    // And it is not on the holder's machine. `idle` rather than `declined`,
    // which is the stronger of the two and worth saying why: `declined` is what
    // a run stamps on a cell it walked past and would not perform, and no run
    // on this browser has walked this cell at all — the holder's last press was
    // cell 8, three cells and one proposal ago. There is no state here that
    // could have come from it.
    expect(await cellStatus(joiner, 9)).toBe("idle");
    expect(await ceremonySlots(joiner)).not.toContain("master");
  });

  /* ── 13. and then the holder spends what they were sent ──────────────────── */

  it("turns two received shares back into the secret the dealer split", async () => {
    // This is the step the ceremony ships or does not ship on. Everything above
    // proves a share can be *delivered*; a share exists to be *recombined*, and
    // the recombining ops in this product take a `shares` collection.
    //
    // The cells are written on the joiner's own notebook and not shared, which
    // is right: this is the holder, alone, using the thing they were handed.
    // Nothing about it needs the dealer's agreement.
    await joiner.getByRole("button", { name: "Cell", exact: true }).click();
    await writeCell(joiner, 10, "$share | blip39.decode | sss.combine | out $secret");
    await assignCell(joiner, 10, L.joiner);

    // **The obvious spelling still does not compile**, and that is right rather
    // than a leftover: `quorum.recv count=1` emits `text` — deliberately, so the
    // two-party read stays unremarkable — and a mnemonic is not a share set
    // until something collects it into one. What changed is that the refusal
    // now names the step that does it, on the value it refused. It used to end
    // at `got text/opaque`, which is a true sentence with no way out of it.
    const typed = await cellErrors(joiner, 10);
    expect(typed).toContain("expects shares");
    expect(typed).toContain("text/opaque");
    expect(typed).toContain('add "shares" first');
    const runAll = joiner.getByRole("button", { name: "Run all" });
    await expect
      .poll(async () => await runAll.getAttribute("aria-disabled"), { timeout: 20000 })
      .toBe("true");
    expect(
      await joiner.locator("[data-run-state] [data-disabled-reason]").innerText()
    ).toContain("does not compile");

    // **The spelling the refusal named**, typed as a reader would type it after
    // reading it. `shares` collects: the mnemonic on the pipe, the one `with=`
    // names, and — only when the recipe named neither — the paste panel. Both
    // of these values crossed the room in steps 9 and 10.
    await writeCell(
      joiner,
      10,
      "$share | shares with=$late | blip39 -d | sss.combine | encode hex | out $secret"
    );
    await expect
      .poll(async () => await cellErrors(joiner, 10), { timeout: 20000 })
      .toBe("");
    await expect
      .poll(async () => await runAll.getAttribute("aria-disabled"), { timeout: 20000 })
      .toBe(null);

    // **And the cell offers to run**, which is the half of the old finding that
    // was not about types at all. `shares` declared `unresolvedInputs: "shares"`
    // unconditionally, so this cell's own Run was disabled pointing at the
    // Inputs tray — on a machine holding two shares of this very split, in slots
    // this very notebook wrote. The tray is now a need only when the recipe
    // named nothing, so a recipe that names its shares is runnable.
    const run10 = cell(joiner, 10).getByRole("button", { name: "Run", exact: true });
    expect(
      await run10.getAttribute("aria-disabled"),
      "the holder is still being sent to a paste panel for shares they are holding"
    ).toBe(null);

    await run10.click();
    await runSettled(joiner);
    expect(await runLine(joiner)).toMatch(/^Done\b/);
    expect(await cellStatus(joiner, 10)).toBe("ok");
    expect(await ceremonySlots(joiner)).toContain("secret");

    // **And it is the dealer's secret**, uncovered by a press on this screen and
    // compared with the one uncovered by a press on the other. Thirty-two bytes
    // drawn on a machine this browser has never run a `random` on, split there,
    // carried here as two mnemonics by two separate sends, and put back
    // together here out of the slots they landed in.
    const recovered = await reveal(joiner, 10, "secret");
    expect(recovered, "the holder recombined their shares into the wrong secret").toBe(
      dealtSecret
    );
    // Neither half alone is enough: a cell that produced nothing would fail the
    // equality, and a value that had simply been copied across the wire would
    // pass it without proving anything about recombination. The shares are what
    // crossed, and they are still what crossed.
    expect(recovered).not.toBe(held.early);
    expect(recovered).not.toBe(held.late);
    expect(await ceremonySlots(joiner)).toEqual(
      expect.arrayContaining(["share", "late", "secret"])
    );
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
