/**
 * Three browsers, one dealer, two holders, and a 2-of-3 that a *pair* rebuilds.
 *
 * ## Why a third browser is a different test and not a bigger one
 *
 * `room-ceremony.e2e.js` walks the same ceremony across two contexts and every
 * assertion in it is still true here. What it cannot reach is the set of facts
 * that only exist once there are three people, and each of them was decided by
 * argument rather than by a run:
 *
 * 1. **Two joiners have to mesh with each other.** The creator publishes an
 *    invite and answers knocks, so creator↔joiner is exercised by any pair. The
 *    link this file needs that no pair has is joiner↔joiner: `_beginMeshing`
 *    offers to every peer with a higher fingerprint, so whichever of the two
 *    holders sorts lower offers to the other, and *neither of them published the
 *    invite*. Cell 6 of the generated ceremony is one holder sending its share
 *    to the other, and it can only run over that link. With two people that cell
 *    does not exist.
 *
 * 2. **A newcomer's introduction goes over the relay rather than the channel.**
 *    `_publishInvite` says why in prose — a peer that needs an invite has no
 *    data channel, and `_sealAndSend`'s channel-first routing would hand the
 *    envelope to some *other* meshed peer to forward and count that as sent.
 *    With two people there is no other meshed peer, so the argument had nothing
 *    to be wrong about. Here the second holder knocks into a room where the
 *    dealer and the first holder are already meshed, which is the case the
 *    routing decision was actually made for.
 *
 * 3. **One inbox, two senders.** Addressing on the wire is FIFO plus a `from=`
 *    prefix. The recovering holder's own two cells read from one inbox that
 *    will hold a message from the dealer *and* a message from the other holder,
 *    and the earlier cell's `from=` is the only thing keeping them apart. Two
 *    people means one message per inbox and the question cannot arise.
 *
 * ## What this file asserts on, and what it deliberately does not
 *
 * The recipe language is moving underneath this suite — `publish` is becoming a
 * step, `sss.split` may gain a `split 2/3` spelling — so every assertion that
 * could be written against behaviour is. Cell *statuses*, *slot names*, the
 * recovered digest and the peer counts are all facts a person reads off the
 * screen and none of them changes when a verb is respelled. Where the recipe
 * text is the thing under test — the headers, and the numbers in the split —
 * it is matched loosely enough to survive a respelling and precisely enough to
 * fail if the quorum changes.
 *
 * Nothing crosses between the three contexts in a variable. Everything one
 * browser knows about another arrived over the wire or out of the address bar,
 * which is `room-ceremony.e2e.js`'s rule and the only thing that makes the
 * final digest comparison mean anything.
 *
 * ## What it found, and what had to change before it could pass
 *
 * **The third party could not join at all**, and neither half of the reason was
 * a transport failure. Both were a routing decision that two browsers could not
 * put a question to, and both are fixed in `lib/notebook/session.js`, where the
 * argument is written out at the line that changed:
 *
 * - `_sealAndSend` read "I handed the frame to some other meshed peer" as
 *   delivery and skipped the relay on it. For a newcomer that forwarder never
 *   has a link to forward *over*, so `_onChannelEnvelope` dropped the frame and
 *   nobody was any the wiser. `_publishInvite` had already written the reason
 *   down in prose and protected itself by going through `_broadcast`; `hello`,
 *   `offer`, `answer` and `ice` — the four envelopes that build the link — were
 *   not protected, so the invite arrived and everything after it vanished. An
 *   indirect hop is now a supplement rather than a substitute.
 *
 * - `_onKnock` reset a stale transport only on a session holding invite
 *   material, i.e. only the creator. The comment above that reset described a
 *   joiner's case precisely — "(when this end is the offerer) an offer and its
 *   candidates" — and the guard above it made that case unreachable. With two
 *   people the creator is the only member who can receive a knock, so the gap
 *   cost nothing; with three, the first joiner holds a half-negotiated link it
 *   aimed at an empty room and never offers again.
 *
 * Neither is visible in a room of two, in any test, at any timeout. That is the
 * shape this repo keeps paying for and the reason a third browser was worth the
 * seconds it costs.
 *
 * **The rest of the findings are not failures.** They are the places where a
 * person driving this would not know what to do next, and they are written on
 * assertions that pin the *current* behaviour — so a fix has to come back here
 * and change a line rather than quietly improving past a green test. They are
 * numbered in the steps that hold them: 4a (the dealer keeps every share, in a
 * slot, with nothing saying to delete it), 5a (the two phases the picker names
 * are one press), and 6a (a majority recovered and the spare share's press did
 * nothing that anything reports).
 *
 * Two of them are now fixed and their assertions were turned over rather than
 * deleted. **5b** — the slot name was one below the share it held, so the
 * machine dealt share 3 kept it in `$share-2`; the generator names slots for
 * shares now and step 5 asserts `$share-3`. **5c** — the widget that says which
 * share this is could not fire on a share that crossed a room, because
 * `execQuorumSend` sends `data` and nothing else; the tile now reads the
 * BLIP39 header out of the mnemonic it is already holding, so the holder is
 * told what the dealer was told, and step 5 asserts the labels on the masked
 * tile.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the three-party suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[three-party-ceremony.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/** How many cells a room of three generates: split, 2 sends, 2 receives, 2 returns, 1 gather. */
const CELLS = 8;

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
 * A ceremony that stops halfway is diagnosed by what the *other* cells did, and
 * eight separate `expect`s report only the first — `room-ceremony.e2e.js` made
 * the same move for the same reason and with three browsers it matters more.
 */
async function board(page) {
  /** @type {Record<number, string>} */
  const out = {};
  for (let i = 0; i < CELLS; i += 1) {
    const err = await cellErrors(page, i);
    out[i] = `${await cellStatus(page, i)}${err ? ` — ${err}` : ""}`;
  }
  return out;
}

/**
 * Uncover one output tile and read what it says.
 *
 * The reveal is part of what is tested: a value delivered into a tile nobody
 * can open is a value nobody can use. The list re-hides after fifteen seconds,
 * so the read follows the press immediately.
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
 * Everything the three screens say about who they are talking to.
 *
 * Attached to the mesh assertions because a failure there is otherwise
 * undiagnosable: "expected 2 to be 1" says a peer is missing and nothing about
 * which one, what state its row is in, or whether the page threw on the way.
 * Read off the Connections tray, which is the panel a person would be looking
 * at, plus the uncaught errors the fixture already collects.
 */
async function meshReport(wire, names) {
  /** @type {Record<string, unknown>} */
  const out = {
    // Every signalling envelope the relay opened, in arrival order: who signed
    // it, what it was, and who it was addressed to. Without this, "a peer is
    // missing" is a symptom with three equally plausible causes — the knock was
    // never sent, the invite was never published, or the invite was published
    // and refused — and the roster cannot tell them apart.
    wire: wire.map((f) => `${f.seq} ${f.signer.slice(0, 4)} ${f.type} → ${f.to?.slice(0, 4) || "*"}`),
  };
  for (const [name, { page, peer }] of Object.entries(names)) {
    await trayTab(page, "Connections");
    const rows = await tray(page).locator("[data-verified]").all();
    /** @type {string[]} */
    const roster = [];
    for (const row of rows) {
      roster.push(
        `${(await row.innerText()).replace(/\s+/g, " ").trim()} [verified=${await row.getAttribute(
          "data-verified"
        )}]`
      );
    }
    out[name] = {
      roster,
      errors: [...new Set(peer.pageErrors())].slice(0, 6),
    };
  }
  return JSON.stringify(out, null, 1);
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

describe.runIf(availability.ok)("a 2-of-3 ceremony across three browsers", () => {
  /** @type {any} */ let room;
  /** @type {any} */ let fx;
  /** @type {(() => Promise<void>)|null} */ let closeMesh = null;
  /** The machine that draws the secret and deals it. */
  /** @type {import("playwright").Page} */ let dealer;
  /** The holder the generator picked to recombine — `holders[0]`. */
  /** @type {import("playwright").Page} */ let recoverer;
  /** The holder who only ever holds a share and hands it back. */
  /** @type {import("playwright").Page} */ let bystander;
  /** @type {string} */ let origin = "";
  /** Whole fingerprints, in the order the generator will read them. */
  let L = { dealer: "", recoverer: "", bystander: "" };
  /** The URL the dealer's own address bar held after Start. Nothing else crosses. */
  let inviteUrl = "";
  /** The ceremony as the dealer's own Source view prints it. */
  let ceremonySource = "";
  /** The digest of the master, off the dealer's screen. Never the master. */
  let expectedDigest = "";

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

    // Who is who is decided by `roomCeremony`, not by this file: the dealer is
    // whoever is chosen in the key picker, and the recoverer is the *first*
    // member of the room who is not them. `room.audience` is sorted, so with the
    // first member dealing, the second recombines. Derived here rather than
    // asserted later so a change to that rule fails on the line that states it.
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

  /* ── 1. three people in the list, and a 2-of-3 falls out of it ───────────── */

  it("writes a 2-of-3 from a room of three, with nobody typing a pipeline", async () => {
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

    // **The quorum is the room's arithmetic, printed before the press.** Three
    // people, so three shares and a majority of two — and there is still no
    // shares field and no threshold field anywhere on this panel, so a count
    // that disagreed with the number of people remains unreachable rather than
    // refused.
    const ceremony = dealer.locator("[data-room-ceremony]");
    await ceremony.waitFor({ state: "visible", timeout: 20000 });
    const summary = await ceremony.locator("[data-room-ceremony-summary]").innerText();
    expect(summary).toContain("One share each for 3 people");
    expect(summary).toContain("any 2 of them rebuild the secret");
    expect(summary).toContain("2 is a majority of 3");
    // The sentence a room of two gets and a room of three must not: three
    // people *do* have redundancy, and printing the two-person warning here
    // would be a claim about a state this reader is not in.
    expect(
      summary,
      "the room-of-two warning was printed to a room of three"
    ).not.toContain("no redundancy at all");
    expect(
      await ceremony.locator("[data-room-ceremony-issues]").count(),
      "the ceremony refused a room it can serve"
    ).toBe(0);

    // The cells before they replace anything, with whole fingerprints in them —
    // the one place a reader checks who is being handed a share before anyone
    // is handed one.
    await ceremony.getByRole("button", { name: /Show the \d+ cells this writes/ }).click();
    const preview = await ceremony.locator("[data-room-ceremony-recipe]").innerText();
    expect(preview).not.toContain("…");
    for (const fpr of room.audience) expect(preview).toContain(fpr);
    // The quorum, in whatever spelling the language currently gives it. Written
    // as an alternation on purpose: `sss.split` is being reconsidered next door
    // and this assertion is about the *numbers*, which do not change when the
    // verb does.
    expect(preview, "the split does not name a 2-of-3").toMatch(
      /threshold=2\s+shares=3|split\s+2\/3/
    );

    await ceremony.getByRole("button", { name: /^Write the 2-of-3 ceremony$/ }).click();
    await expect
      .poll(async () => await ceremony.locator("[data-room-ceremony-note='1']").innerText(), {
        timeout: 20000,
      })
      .toContain("2-of-3");

    await dealer.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    ceremonySource = await readNotebookSource(dealer);
    const cells = ceremonySource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(cells, ceremonySource).toHaveLength(CELLS);

    // **Where each cell landed.** The headers are the one piece of recipe text
    // this file reads exactly, because they are the whole answer to "who does
    // what" and they are written by `setCellPeer` — the same mutator the "Who
    // runs this cell" menu presses — rather than by any spelling of a verb.
    const on = cells.map((c) => c.split("\n")[0]);
    expect(on, JSON.stringify(on, null, 1)).toEqual([
      `@${L.dealer}`, // draw and split
      `@${L.dealer}`, // hand share 2 to the recoverer
      `@${L.dealer}`, // hand share 3 to the bystander
      `@${L.recoverer}`, // receive
      `@${L.bystander}`, // receive
      `@${L.dealer}`, // return share 1
      `@${L.bystander}`, // return their share
      `@${L.recoverer}`, // gather and recombine
    ]);
    // Three of the eight are on machines other than this one, which is the fact
    // that makes this a ceremony rather than a script.
    expect(on.filter((h) => h !== `@${L.dealer}`)).toHaveLength(4);

    // It compiles, for the person: read off the control rather than out of the
    // compiler, because "the recipe parses" and "Run all can be pressed" are two
    // facts and only the second is what a reader has.
    expect(
      await dealer.getByRole("button", { name: "Run all" }).getAttribute("aria-disabled")
    ).toBe(null);
    for (let i = 0; i < CELLS; i += 1) expect(await cellErrors(dealer, i)).toBe("");
    for (let i = 0; i < CELLS; i += 1) expect(await cellStatus(dealer, i)).toBe("idle");
    expect(await ceremonySlots(dealer)).toEqual([]);
  });

  /* ── 2. a room of three, joined one at a time ───────────────────────────── */

  it("meshes all three, including the two who never published an invite", async () => {
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

    // **One at a time, and the second one late on purpose.** The recoverer joins
    // and meshes with the dealer first; only then does the bystander knock. That
    // is the arrangement `_publishInvite`'s note is about — a newcomer arriving
    // into a room where two peers already have a channel, so the invite it needs
    // must go over the relay and cannot be handed to the meshed peer to forward.
    // Joining them together would let both knocks land before anyone was meshed
    // and the case would never be reached.
    const joiners = [
      { page: recoverer, member: room.members[1], uid: "Recoverer <recoverer@ceremony.test>" },
      { page: bystander, member: room.members[2], uid: "Bystander <bystander@ceremony.test>" },
    ];
    for (const [i, who] of joiners.entries()) {
      await who.page.goto(inviteUrl, { waitUntil: "load" });
      await becomeMember(who.page, who.member, who.uid);

      const start = who.page.locator("[data-session-start]");
      await start.waitFor({ state: "visible", timeout: 20000 });
      expect(await start.getAttribute("data-session-start")).toBe("join");

      // Before a key is chosen there is no ceremony to offer, and the refusal
      // names the chooser — the audience arrived whole in the link, so "add
      // somebody" would be a remedy for a state this reader is not in.
      const offered = who.page.locator("[data-room-ceremony]");
      await offered.waitFor({ state: "visible", timeout: 20000 });
      expect(
        await offered.locator("[data-room-ceremony-issues]").innerText()
      ).toContain("Choose the key you are joining as");

      await who.page.locator("[data-session-key] select").selectOption(who.member.fpr);
      // Both joiners are offered the same 2-of-3 the dealer wrote, which is the
      // room deriving the quorum rather than the creator deciding it: three
      // pickers read one audience and reach one arithmetic. Neither joiner may
      // press it — that would be a second dealer-based split of a different
      // secret by a machine that is meant to be receiving one.
      await expect
        .poll(async () => await offered.locator("[data-room-ceremony-summary]").innerText(), {
          timeout: 20000,
        })
        .toContain("One share each for 3 people");

      const join = who.page.getByRole("button", { name: "Join shared session" });
      await expect.poll(async () => await join.isEnabled(), { timeout: 15000 }).toBe(true);
      await join.click();
      await who.page
        .locator("[data-session-sheet]")
        .waitFor({ state: "hidden", timeout: 20000 });

      // The dealer sees one more verified peer before the next person is even
      // opened, which is what makes the bystander a *late* arrival rather than a
      // second simultaneous one.
      await trayTab(dealer, "Connections");
      try {
        await expect
          .poll(async () => await tray(dealer).locator('[data-verified="1"]').count(), {
            timeout: 90000,
            intervals: [500],
          })
          .toBe(i + 1);
      } catch {
        // The poll's own message says "expected 1 to be 2" and nothing more,
        // which is why it is swallowed here and replaced: what a reader needs
        // is the wire log and the three rosters, and neither is in it.
        expect.unreachable(
          `the dealer key-confirmed ${i} peers after ${i + 1} joined — ${await meshReport(room.signalled(), {
            dealer: { page: dealer, peer: fx.peers[0] },
            recoverer: { page: recoverer, peer: fx.peers[1] },
            bystander: { page: bystander, peer: fx.peers[2] },
          })}`
        );
      }
    }

    // **Two verified peers each, on all three machines.** On the dealer that is
    // the invite working twice. On the two holders it is the link neither of
    // them was introduced over: the recoverer and the bystander verified each
    // other having each only ever verified an invite signed by the dealer, and
    // `_beginMeshing`'s fingerprint comparison decided between them which one
    // offered. This is the assertion that a two-browser suite cannot make and
    // the reason this file exists.
    for (const [name, page] of Object.entries({ dealer, recoverer, bystander })) {
      await trayTab(page, "Connections");
      try {
        await expect
          .poll(async () => await tray(page).locator('[data-verified="1"]').count(), {
            timeout: 90000,
            intervals: [500],
          })
          .toBe(2);
      } catch {
        expect.unreachable(
          `${name} never key-confirmed both of the others — ${await meshReport(room.signalled(), {
            dealer: { page: dealer, peer: fx.peers[0] },
            recoverer: { page: recoverer, peer: fx.peers[1] },
            bystander: { page: bystander, peer: fx.peers[2] },
          })}`
        );
      }
    }
    for (const page of [dealer, recoverer, bystander]) await runSettled(page);
  }, 400_000);

  /* ── 3. one notebook, three copies, none of them typed twice ─────────────── */

  it("carries the generated notebook to both holders at once", async () => {
    for (const page of [recoverer, bystander]) {
      expect(await readNotebookSource(page)).toBe("");
    }
    const shared = await readNotebookSource(dealer);
    expect(shared).toBe(ceremonySource);

    await trayTab(dealer, "Connections");
    await tray(dealer).getByRole("button", { name: "Share this notebook" }).click();
    // **Two peers, in one press and one sentence.** The count is the roster's,
    // so a share that reached one of the two holders and reported success would
    // fail here rather than at the run.
    await expect
      .poll(async () => await dealer.locator("[data-notebook-share-note]").innerText(), {
        timeout: 30000,
      })
      .toMatch(/signed and shared with 2 peers/);

    for (const page of [recoverer, bystander]) {
      // No press: `decideProposal` adopts without asking when there is no local
      // work to lose, and an empty notebook is exactly that state.
      await expect
        .poll(async () => await readNotebookSource(page), { timeout: 60000 })
        .toBe(ceremonySource);
      expect(
        await page.getByRole("button", { name: "Adopt their notebook" }).count(),
        "a holder was asked about a notebook they had no work to lose to"
      ).toBe(0);
      for (let i = 0; i < CELLS; i += 1) expect(await cellStatus(page, i)).toBe("idle");
      expect(await ceremonySlots(page)).toEqual([]);
    }
  });

  /* ── 4. the deal, and what the dealer is left holding ────────────────────── */

  it("splits once and sends twice, with the four foreign cells declined", async () => {
    await cell(dealer, 0).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(dealer);

    const dealt = await board(dealer);
    const why = JSON.stringify(dealt, null, 1);
    expect(dealt[0], why).toBe("ok"); // draw and split
    expect(dealt[1], why).toBe("ok"); // share 2 → recoverer
    expect(dealt[2], why).toBe("ok"); // share 3 → bystander
    expect(dealt[3], `the dealer performed the recoverer's cell — ${why}`).toBe("declined");
    expect(dealt[4], `the dealer performed the bystander's cell — ${why}`).toBe("declined");
    expect(dealt[5], why).toBe("ok"); // share 1 → recoverer, in the same run
    expect(dealt[6], why).toBe("declined");
    expect(dealt[7], why).toBe("declined");

    // **FINDING (4a) — what "the dealer keeps one share" actually looks like.**
    // The dealer's Slots tab holds `$expected` and `$set`, and `$set` is *every
    // share*: the generator deliberately writes no `$mine` — an `out $mine`
    // would bind today (the registry's `meta.shareIndex` divert is gone), but
    // it would only add a second copy of share 1 beside the full set. The
    // consequence a person meets is unchanged: the machine that was told to
    // keep one share is visibly holding all three, in a slot it can reveal,
    // with nothing on screen saying that two of them have been dealt away and
    // this copy should go. A 2-of-3 whose dealer keeps the whole set is a
    // 1-of-1 until somebody deletes it, and no control here says so.
    //
    // Pinned rather than fixed, because fixing it is a product decision about
    // what the ceremony should write, not a test's to make. A fix has to come
    // back and change this line.
    const held = await ceremonySlots(dealer);
    expect(held, "the dealer's slots changed shape").toEqual(["expected", "set"]);
    expect(held, "the master reached a slot").not.toContain("secret");

    expectedDigest = await reveal(dealer, 0, "expected");
    expect(expectedDigest, "the split wrote no digest of the master").toMatch(
      /^[0-9a-f]{64}$/
    );

    // **The deal is confirmed by the holders' sessions, not by their cells.**
    // Neither holder has pressed Run — their receive cells are still idle on
    // the two other screens — and the dealer's Activity entries already read
    // `reached <fpr>'s session`, because the ack fires when the receiving
    // exchange takes the payload into its inbox, not when a cell reads it.
    // That boundary is the claim: a send that still said `sent · unconfirmed`
    // here would be waiting on the wrong fact, and one that needed the far
    // cell to run would be overstating what anybody knows.
    expect(await cellStatus(recoverer, 3)).toBe("idle");
    expect(await cellStatus(bystander, 4)).toBe("idle");
    await trayTab(dealer, "Activity");
    const receipts = tray(dealer).locator("[data-activity-log] .activity-receipt");
    await expect
      .poll(
        async () =>
          (await receipts.allInnerTexts()).filter((t) => t.includes("reached")).length,
        { timeout: 30000 }
      )
      .toBe(3);
    // Whole fingerprints — read with the whitespace squeezed out because the
    // 40-hex key wraps in the tray — and no send left half-claimed: three
    // sends, three confirmations, none still owed.
    const flat = (await receipts.allInnerTexts()).map((t) => t.replace(/\s+/g, ""));
    expect(
      flat.filter((t) => t.includes(`reached${L.recoverer}'ssession`)),
      `receipts: ${JSON.stringify(flat)}`
    ).toHaveLength(2); // shares 2 and 1 both went to the recoverer
    expect(
      flat.filter((t) => t.includes(`reached${L.bystander}'ssession`)),
      `receipts: ${JSON.stringify(flat)}`
    ).toHaveLength(1); // share 3
    expect(flat.join(" "), "a confirmed deal still reads unconfirmed").not.toContain(
      "unconfirmed"
    );
  });

  /* ── 5. the bystander: receives a share, and hands it back ───────────────── */

  it("delivers a share to the holder who will never recombine, and gets it back out", async () => {
    // Run from *their* receiving cell, which runs it and everything below it —
    // so the same press that takes delivery of share 3 also hands it back. That
    // is not a choice this file made: `runFrom` walks to the end of the
    // notebook, and cell 6 is below cell 4.
    //
    // **FINDING (5a) — the two phases are one press.** The picker labels them
    // "Dealing — run once, together" and "Recovering — run when the secret is
    // wanted back", and the notebook offers no way to honour that. A holder who
    // presses Run on the cell that receives their share also runs the cell that
    // gives it away, immediately, with no prompt. The phases are real in the
    // preview and absent from the thing the preview describes.
    await cell(bystander, 4).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(bystander, 4), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await runSettled(bystander);

    const seen = await board(bystander);
    const why = JSON.stringify(seen, null, 1);
    expect(seen[4], why).toBe("ok"); // received
    expect(seen[6], `the bystander could not hand its share back — ${why}`).toBe("ok");

    // **FINDING (5b), fixed — the slot is named for the share it holds.** This
    // machine was dealt share **3**, and until the generator was changed the
    // slot it landed in was `$share-2`: receive cells were numbered by holder
    // rather than by share index — `$share-${i + 1}` for the holder at position
    // `i`, fed by `at ${i + 2}` — so every holder's slot name was one below the
    // share in it, and a person comparing a slot against a printed card that
    // says "share 3 of 3" could not tell whether they had been dealt the wrong
    // one. There is still no `$share-1` anywhere, and that is now the honest
    // reading rather than the off-by-one: share 1 is the dealer's and never
    // leaves `$set`.
    const held = await ceremonySlots(bystander);
    expect(held, `the bystander's slots: ${JSON.stringify(held)}`).toEqual(["share-3"]);
    // And nothing the dealer holds: this browser has never run `random`, has no
    // `$set`, and could not have produced a share of this split by itself.
    expect(held).not.toContain("set");
    expect(held).not.toContain("expected");

    // **FINDING (5c), fixed — and read before the reveal, which is the point.**
    //
    // `ShareIdentity` exists for exactly this reader. Its own note says so: "the
    // one question a custodian holding three tiles actually has — *which* share
    // is this, and how many of them recover the secret — could only be answered
    // by revealing a secret in order to read a number that is not one."
    //
    // It could not fire here. `execQuorumSend` takes the value's `data` and
    // nothing else, and `execQuorumRecv` rebuilds it as
    // `{ type: "text", meta: { sensitive, from, ts } }` — no index, no
    // threshold, no tags — so `shareIdentity` returned null and the widget drew
    // nothing. The dealer, who already knew everything, got three labels; the
    // holder, who knew nothing, got a slot name and a wall of words. Nothing
    // was added to the wire to fix it: `encodeMnemonic` writes the index, the
    // threshold and the set id into the header before a word of data, so the
    // facts were in the value the holder was already holding and nothing read
    // them out.
    //
    // Asserted **while the tile is still masked**, because `ShareIdentity` is a
    // `publicView` — it is what a share tile may say with its body covered, and
    // a revealed tile renders its own words instead. Reading it after the
    // reveal below would report zero for a widget that is working.
    const identity = {
      dealer: await cell(dealer, 0).locator("[data-share-identity]").count(),
      holder: await cell(bystander, 4).locator("[data-share-identity]").count(),
    };
    expect(
      identity.holder,
      `share-identity labels drawn — ${JSON.stringify(identity)}`
    ).toBeGreaterThan(0);
    const labels = (
      await cell(bystander, 4).locator("[data-share-identity]").first().innerText()
    ).replace(/\s+/g, " ");
    // The three facts, and the number that makes this finding rather than a
    // styling note: **3**, off a machine that was told nothing but the words.
    expect(labels, `the holder's share labels: ${labels}`).toContain("Share 3");
    expect(labels, `the holder's share labels: ${labels}`).toContain(
      "2 shares recover the secret"
    );
    expect(labels, `the holder's share labels: ${labels}`).toMatch(/set [0-9A-F]{4}/);
    // The mask is still on while all of that is on screen — which is §34b's
    // rule and the whole reason these facts may be drawn at all: they describe
    // the split, not the secret.
    expect(
      await cell(bystander, 4)
        .locator("[data-artifact-kind]")
        .filter({ hasText: "share-3" })
        .first()
        .getByRole("button", { name: "Reveal" })
        .count(),
      "the share tile was already open when its public labels were read"
    ).toBe(1);

    // What a holder is actually looking at once they do open it. Behaviour, not
    // text: a mnemonic in a tile they can open, with no other tile beside it.
    const mnemonic = await reveal(bystander, 4, "share-3");
    expect(mnemonic.split(/\s+/).length, `share arrived as: ${mnemonic}`).toBeGreaterThan(3);
  });

  /* ── 6. the recoverer: two shares from two machines, one secret ──────────── */

  it("recombines the dealer's secret out of shares that crossed the room", async () => {
    // By now this browser's inbox holds three messages from two senders — share
    // 2 and share 1 from the dealer, and share 3 from the bystander — and the
    // only thing keeping the first cell off the wrong one is the `from=` prefix
    // and FIFO. Running from cell 3 walks both of this machine's cells in one
    // press, which is the ordering a person gets.
    await cell(recoverer, 3).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(recoverer, 3), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await expect
      .poll(async () => await cellStatus(recoverer, 7), { timeout: 180000, intervals: [250] })
      .toBe("ok");
    await runSettled(recoverer);

    const held = await ceremonySlots(recoverer);
    // `share-2`, because this holder was dealt share 2 — finding 5b's rename,
    // seen from the other machine.
    expect(held, `the recoverer's slots: ${JSON.stringify(held)}`).toContain("share-2");
    expect(held).toContain("secret");
    expect(held).toContain("recovered");
    // Nothing the dealer holds, on the machine that recombined.
    expect(held).not.toContain("set");
    expect(held).not.toContain("expected");

    // **This is the assertion the ceremony ships or does not ship on.** A
    // SHA-256 computed on the dealer's machine, of thirty-two bytes that were
    // drawn there and written to no slot, equal to a SHA-256 computed here of
    // what this machine put back together out of two mnemonics — one of which
    // came from a third browser the dealer never asked. Compared through the
    // screen on both ends, so neither number is one this file worked out.
    const recovered = await reveal(recoverer, 7, "recovered");
    expect(recovered, "the recoverer recombined into something else").toBe(expectedDigest);

    // And the secret itself is here, revealable, on the machine that is meant to
    // end up with it. Without this the digest match would only prove the shares
    // agree about a value nobody can spend.
    const secret = await reveal(recoverer, 7, "secret");
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(secret).not.toBe(recovered);

    // **FINDING (6a) — a majority recovered and the third share was spare.**
    // `count=` is `threshold - 1`, which is one for a room of three, and *two*
    // machines were told to hand their share back. So the gather takes whichever
    // arrived first and the other message is left in the inbox, unread, with
    // nothing anywhere reporting that a share was offered and not needed. The
    // recovery is correct either way — any two of three rebuild it — but a
    // person watching the bystander's cell go green has been shown a press that
    // did nothing, and cannot tell which of the two it was.
    //
    // The secret never reaches the dealer's slots: recovery happens away from
    // the machine that made it, which is the property that makes the split worth
    // anything.
    expect(await ceremonySlots(dealer)).not.toContain("secret");
    expect(await ceremonySlots(bystander)).not.toContain("secret");
  });

  /* ── 7. what is left on the three screens ────────────────────────────────── */

  it("holds only the ceremony on every machine, and one live exchange each", async () => {
    for (const page of [dealer, recoverer, bystander]) {
      const source = await readNotebookSource(page);
      expect(source).toBe(ceremonySource);
      expect(await page.locator("article").count()).toBe(CELLS);
      const settled = await board(page);
      expect(
        Object.values(settled).map((s) => s.split(" — ")[0]),
        JSON.stringify(settled, null, 1)
      ).not.toContain("error");
      // The refusal itself has not moved — `execQuorumOpen` still declines a
      // second exchange and `quorum-lifecycle.test.js` holds that sentence.
      // What is checked here is the consequence a browser can see: two peers,
      // still verified, on all three machines after everything ran.
      await trayTab(page, "Connections");
      expect(await tray(page).locator('[data-verified="1"]').count()).toBe(2);
    }
  });

  /* ── what the journey cost ───────────────────────────────────────────────── */

  it("drove three browsers without tripping the production CSP", async () => {
    for (const peer of fx.peers) expect(await peer.cspViolations()).toEqual([]);
    expect(fx.tunnelFaults()).toEqual([]);
    expect(room.faults()).toEqual([]);
  });
});
