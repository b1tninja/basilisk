/**
 * Three browsers, one dealer, two holders, and a 2-of-3 that a *pair* rebuilds.
 *
 * ## Why a third browser is a different test and not a bigger one
 *
 * `room-ceremony.e2e.js` walks a ceremony across two contexts and every
 * assertion in it is still true here. What it cannot reach is the set of facts
 * that only exist once there are three people, and each of them was decided by
 * argument rather than by a run:
 *
 * 1. **Two joiners have to mesh with each other.** The creator publishes an
 *    invite and answers knocks, so creator↔joiner is exercised by any pair. The
 *    link this file needs that no pair has is joiner↔joiner: `_beginMeshing`
 *    offers to every peer with a higher fingerprint, so whichever of the two
 *    holders sorts lower offers to the other, and *neither of them published the
 *    invite*. The recovery below runs one send over that link, and it can only
 *    run over that link. With two people it does not exist.
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
 *    prefix. The recovering holder's inbox holds a message from the dealer (the
 *    deal) *and* one from the other holder (the recovery), and `from=` is the
 *    only thing keeping the two cells apart. Two people means one message per
 *    inbox and the question cannot arise.
 *
 * ## The two-notebooks shape this file now drives
 *
 * The generated ceremony used to be one notebook holding the deal *and* the
 * recovery — eight cells, phase labels, a return cell per member and an armed
 * gather. Three findings pinned here (4a: the dealer keeps every share in a
 * revealable `$set`; 5a: the two phases are one press; 6a: a spare share's
 * press did nothing that anything reports) all traced to that one decision,
 * and LANGUAGE.md's "a ceremony and its reversal are two agreements, so they
 * are two notebooks" settled it. The deal is now one `scatter` cell plus one
 * receive per holder; the recovery is generated **at recovery time** by
 * `room-recovery.js`, from the picker this file drives in step 6. Each of the
 * three findings is turned over below, at the step that used to pin it, with
 * the state that replaced it asserted instead.
 *
 * Nothing crosses between the three contexts in a variable. Everything one
 * browser knows about another arrived over the wire or out of the address bar,
 * which is `room-ceremony.e2e.js`'s rule and the only thing that makes the
 * final digest comparison mean anything.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability } from "../helpers/browser-peers.js";
import { openMesh } from "../helpers/browser-mesh.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
import { readNotebookSource, seedVaultKeyExpr } from "../helpers/toolkit-ui.js";
import { RECOVERY_WAIT_MS } from "../../lib/toolkit/room-recovery.js";

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

/** How many cells a room of three deals: the scatter cell, and 2 receives. */
const CELLS = 3;

/** How many the generated recovery holds: one contributor's send, one gather. */
const RECOVERY_CELLS = 2;

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
 * separate `expect`s report only the first — `room-ceremony.e2e.js` made the
 * same move for the same reason and with three browsers it matters more.
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
    const m = /^@(expected|share(?:-\d+)?|recovered|secret|set)$/.exec(text.trim());
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
  /** The holder who will recombine — decided in step 6, by this file's press. */
  /** @type {import("playwright").Page} */ let recoverer;
  /** The holder who only ever holds a share and hands it back. */
  /** @type {import("playwright").Page} */ let bystander;
  /** @type {string} */ let origin = "";
  /** Whole fingerprints, in canonical audience order. */
  let L = { dealer: "", recoverer: "", bystander: "" };
  /** The URL the dealer's own address bar held after Start. Nothing else crosses. */
  let inviteUrl = "";
  /** The deal, as the dealer's own Source view prints it. */
  let ceremonySource = "";
  /** The recovery, as the recoverer's Source view prints it after step 6 writes it. */
  let recoverySource = "";
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

    // Who is who is decided by the canonical audience, not by this file:
    // `scatter` deals share i to member i in sorted order, so with the first
    // member dealing, the second holds share 2 and the third share 3. The
    // second member recombines because step 6 *chooses* them — who recovers is
    // no longer the generator's nomination, it is whoever actually does it.
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
    // The property the scatter form bought, said on the panel: the dealer ends
    // holding exactly one share, and there is no set anywhere to delete.
    expect(summary).toContain("exactly one share");
    // And the two-notebooks sentence: this notebook is the deal, recovery is a
    // separate agreement written when the day comes.
    expect(summary).toContain("separate agreement");
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
    expect(preview, "the split does not name a 2-of-3").toContain("sss.split 2/3");
    // The canonical scatter deal: every destination is in the text, and every
    // destination is a derivation — `room` is the audience in canonical order,
    // `each` is this pair's member, and neither can name a person.
    expect(preview).toContain("scatter to=room");
    expect(preview).toContain("- send to=each | out $share");

    // **FINDING (5a), turned over — there are no phases to mislabel.** The
    // panel used to print "Dealing — run once, together" and "Recovering — run
    // when the secret is wanted back" over one contiguous run, which no
    // control could honour. The deal notebook is one occasion now; the phase
    // lists are gone, and the recovery has its own section and its own
    // notebook (step 6 drives both).
    expect(
      await ceremony.locator("[data-room-ceremony-phase]").count(),
      "phase labels are back on a notebook with one occasion"
    ).toBe(0);
    expect(await sheet.innerText()).not.toContain("run when the secret is wanted back");

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
      `@${L.dealer}`, // draw, split, deal — one cell, one occasion
      `@${L.recoverer}`, // receive share 2
      `@${L.bystander}`, // receive share 3
    ]);

    // **FINDING (1a)'s three-party face, turned over.** No cell below the
    // split returns anybody's share: the deal notebook has nothing for
    // `runFrom` to walk into, so the press that deals cannot also recover.
    expect(ceremonySource, "a cell selects a share back out of a set").not.toMatch(
      /\bat \d+\b|\[\d+\]/
    );
    expect(ceremonySource, "a gather is armed in the deal notebook").not.toContain(
      "sss.combine"
    );

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
      .toMatch(/written to 2 open channels · unconfirmed/);

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

  it("deals both shares in one press and keeps exactly one — its own", async () => {
    await cell(dealer, 0).getByRole("button", { name: "Run", exact: true }).click();
    await runSettled(dealer);

    const dealt = await board(dealer);
    const why = JSON.stringify(dealt, null, 1);
    expect(dealt[0], why).toBe("ok"); // draw, split, deal
    expect(dealt[1], `the dealer performed the recoverer's cell — ${why}`).toBe("declined");
    expect(dealt[2], `the dealer performed the bystander's cell — ${why}`).toBe("declined");

    // **FINDING (4a), turned over — the revealable `$set` is unconstructable.**
    // The dealer's Slots tab used to hold `$set`, *every share*, on the one
    // machine that needed no reminder of any of them — a 2-of-3 that was a
    // 1-of-1 until somebody remembered to delete a slot no screen mentioned.
    // Under `scatter` the shares flow from the split straight onto the wire:
    // a delivered pair's pipe ends at `send`, the one pair whose member is
    // this machine is the only value that reaches the body's `out`, and the
    // dealer is left holding the digest and their own share. There is no slot
    // to warn about, because no step in the text retains the set.
    const held = await ceremonySlots(dealer);
    expect(held, "the dealer's slots changed shape").toEqual(["expected", "share"]);
    expect(held, "the whole set reached a slot").not.toContain("set");
    expect(held, "the master reached a slot").not.toContain("secret");

    // The dealer's own share is a share like any holder's: the masked tile
    // reads its BLIP39 header and says which share this machine kept — share
    // 1, the dealer's canonical position — the same labels finding 5c bought
    // the holders.
    const identity = (
      await cell(dealer, 0).locator("[data-share-identity]").first().innerText()
    ).replace(/\s+/g, " ");
    expect(identity, `the dealer's share labels: ${identity}`).toContain("Share 1");

    expectedDigest = await reveal(dealer, 0, "expected");
    expect(expectedDigest, "the split wrote no digest of the master").toMatch(
      /^[0-9a-f]{64}$/
    );

    // **The deal is confirmed by the holders' sessions, not by their cells.**
    // Neither holder has pressed Run — their receive cells are still idle on
    // the two other screens — and the dealer's Activity entries already read
    // `reached <fpr>'s session`, because the ack fires when the receiving
    // exchange takes the payload into its inbox, not when a cell reads it.
    // Two sends now, not three: the deal deals, and nothing returns.
    expect(await cellStatus(recoverer, 1)).toBe("idle");
    expect(await cellStatus(bystander, 2)).toBe("idle");
    await trayTab(dealer, "Activity");
    const receipts = tray(dealer).locator("[data-activity-log] .activity-receipt");
    await expect
      .poll(
        async () =>
          (await receipts.allInnerTexts()).filter((t) => t.includes("reached")).length,
        { timeout: 30000 }
      )
      .toBe(2);
    // Whole fingerprints — read with the whitespace squeezed out because the
    // 40-hex key wraps in the tray — and no send left half-claimed: two
    // sends, two confirmations, none still owed.
    const flat = (await receipts.allInnerTexts()).map((t) => t.replace(/\s+/g, ""));
    expect(
      flat.filter((t) => t.includes(`reached${L.recoverer}'ssession`)),
      `receipts: ${JSON.stringify(flat)}`
    ).toHaveLength(1); // share 2
    expect(
      flat.filter((t) => t.includes(`reached${L.bystander}'ssession`)),
      `receipts: ${JSON.stringify(flat)}`
    ).toHaveLength(1); // share 3
    expect(flat.join(" "), "a confirmed deal still reads unconfirmed").not.toContain(
      "unconfirmed"
    );

    // **And the dealer is told, without having to be looking at this tray.**
    //
    // The receipt above is the record and it is only ever *read*. The
    // confirmation arrives seconds after the press, on a row inside a tab, so
    // a dealer who cannot see the tray had no route to the one fact that says
    // a key share got where it was sent. It goes to the polite live region.
    //
    // What it must not do is take the run's own line with it, and that is the
    // second half of this assertion rather than a separate one because the two
    // are one decision. An ack comes back milliseconds after the send: routing
    // this through `narrate` — which every other event on the hook uses —
    // replaced "Done" on screen before a person could read it, in four places
    // in `placed-journey.e2e.js`. So the confirmation is announced and not
    // printed: the visible home of this fact is the row above.
    const said = (await dealer.locator("[data-run-announcer]").innerText()).replace(/\s+/g, "");
    expect(said, `the live region: ${said}`).toContain("reached");
    expect(
      said,
      `the live region: ${said}`
    ).toContain(`${L.recoverer}'ssession`);
    const line = dealer.locator("[data-run-state]").locator("xpath=following-sibling::p[1]");
    expect(
      (await line.innerText()).trim(),
      "the delivery confirmation overwrote the run's own verdict"
    ).toMatch(/^Done\b/);
  });

  /* ── 5. the bystander: takes delivery, and nothing else happens ──────────── */

  it("delivers a share to a holder, and the press does only what it says", async () => {
    // **FINDING (5a), turned over — one press is one act now.** This press
    // used to take delivery of share 3 *and* hand it straight back, because
    // `runFrom` walks to the end and the holder's return cell sat below their
    // receive. There is no cell below the receive any more: the recovery is a
    // separate notebook that does not exist yet, so the press that takes
    // delivery is a press that takes delivery.
    await cell(bystander, 2).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(bystander, 2), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await runSettled(bystander);

    const seen = await board(bystander);
    const why = JSON.stringify(seen, null, 1);
    expect(seen[2], why).toBe("ok"); // received — and that is the whole of it
    expect(seen[0], `the press ran a cell above it — ${why}`).toBe("idle");
    expect(seen[1], `the press ran another holder's cell — ${why}`).toBe("idle");

    // The slot is named for the share it holds (finding 5b's fix, carried into
    // the scatter numbering): this machine is third in canonical audience
    // order, so it was dealt share 3 and keeps it in `$share-3`.
    const held = await ceremonySlots(bystander);
    expect(held, `the bystander's slots: ${JSON.stringify(held)}`).toEqual(["share-3"]);
    // And nothing the dealer holds: this browser has never run `random`, has no
    // `$share` of its own, and could not have produced a share of this split by
    // itself.
    expect(held).not.toContain("share");
    expect(held).not.toContain("expected");

    // **FINDING (5c), held — the masked tile says which share this is.** The
    // facts ride in the BLIP39 header the holder is already holding, and the
    // labels are what a share tile may say with its body covered — asserted
    // while the mask is still on, because a revealed tile draws its own words.
    const labels = (
      await cell(bystander, 2).locator("[data-share-identity]").first().innerText()
    ).replace(/\s+/g, " ");
    expect(labels, `the holder's share labels: ${labels}`).toContain("Share 3");
    expect(labels, `the holder's share labels: ${labels}`).toContain(
      "2 shares recover the secret"
    );
    expect(labels, `the holder's share labels: ${labels}`).toMatch(/set [0-9A-F]{4}/);
    expect(
      await cell(bystander, 2)
        .locator("[data-artifact-kind]")
        .filter({ hasText: "share-3" })
        .first()
        .getByRole("button", { name: "Reveal" })
        .count(),
      "the share tile was already open when its public labels were read"
    ).toBe(1);

    // What a holder is actually looking at once they do open it. Behaviour, not
    // text: a mnemonic in a tile they can open, with no other tile beside it.
    const mnemonic = await reveal(bystander, 2, "share-3");
    expect(mnemonic.split(/\s+/).length, `share arrived as: ${mnemonic}`).toBeGreaterThan(3);
  });

  /* ── 6. recovery is written at recovery time, by the quorum doing it ─────── */

  it("writes the recovery from the picker, and recombines the dealer's secret", async () => {
    // The recoverer takes delivery of their own share first — the picker reads
    // the threshold and set id off that share's header, so the share has to be
    // in its slot before there are facts to print.
    await cell(recoverer, 1).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(recoverer, 1), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await runSettled(recoverer);
    expect(await ceremonySlots(recoverer)).toEqual(["share-2"]);

    // **The picker, on the live session.** The session sheet shows the live
    // half now, and the recovery section sits under it — same sheet, one door.
    await trayTab(recoverer, "Connections");
    await tray(recoverer).getByRole("button", { name: "Session", exact: true }).click();
    const sheet = recoverer.locator("[data-session-sheet]");
    await sheet.waitFor({ state: "visible", timeout: 20000 });
    const recovery = recoverer.locator("[data-room-recovery]");
    await recovery.waitFor({ state: "visible", timeout: 20000 });

    // Everything but "who" was read off the share this machine holds: the
    // facts line prints the header's own numbers, before any choice is made.
    const facts = await recovery.locator("[data-room-recovery-facts]").innerText();
    expect(facts, `the recovery facts: ${facts}`).toContain("share 2 of 3");
    expect(facts).toContain("any 2 recombine");
    expect(facts).toMatch(/set [0-9A-F]{4}/);

    // **Who is contributing is the one question.** Both other members are
    // offered — the dealer is a checkbox like anyone else, not a special case
    // — and this recovery lists the bystander alone, which is the agreement
    // "the dealer's share is not part of this".
    const choices = recovery.locator("[data-room-recovery-contributors] input[type=checkbox]");
    expect(await choices.count()).toBe(2);
    await recovery
      .locator(`input[aria-label="Add ${L.bystander} as a contributor"]`)
      .check();
    await expect
      .poll(async () => await recovery.locator("[data-room-recovery-issues]").count(), {
        timeout: 10000,
      })
      .toBe(0);

    // The cells before they replace anything — the deal picker's rule, held
    // for the second notebook too.
    await recovery.getByRole("button", { name: /Show the \d+ cells this writes/ }).click();
    const preview = await recovery.locator("[data-room-recovery-recipe]").innerText();
    expect(preview).toContain(L.bystander);
    expect(preview).toContain(`wait=${RECOVERY_WAIT_MS}`);
    expect(preview, "the recovery names the dealer — the agreement lists only its contributors")
      .not.toContain(L.dealer);

    await recovery.getByRole("button", { name: /^Write the 2-of-3 recovery$/ }).click();
    await expect
      .poll(async () => await recovery.locator("[data-room-recovery-note='1']").innerText(), {
        timeout: 20000,
      })
      .toContain("2-of-3 recovery");
    await recoverer.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    recoverySource = await readNotebookSource(recoverer);
    const rcells = recoverySource.split(/\n\s*\n+/).map((c) => c.trim());
    expect(rcells, recoverySource).toHaveLength(RECOVERY_CELLS);
    expect(rcells[0].split("\n")[0]).toBe(`@${L.bystander}`);
    expect(rcells[1].split("\n")[0]).toBe(`@${L.recoverer}`);
    // The gather reads the named contributor and folds in this machine's own
    // share — and the wait is the length of the act, in the text.
    expect(rcells[1]).toContain(`quorum.recv from=${L.bystander}`);
    expect(rcells[1]).toContain("shares with=$share-2");

    // The agreement crosses like any notebook: signed, and *asked about*,
    // because both other machines have work they would lose.
    await trayTab(recoverer, "Connections");
    await tray(recoverer).getByRole("button", { name: "Share this notebook" }).click();
    await expect
      .poll(async () => await recoverer.locator("[data-notebook-share-note]").innerText(), {
        timeout: 30000,
      })
      .toMatch(/written to 2 open channels · unconfirmed/);

    // The proposal is offered where sharing lives — the Connections tray — so
    // each machine's is opened to read it, exactly as a person would.
    await trayTab(bystander, "Connections");
    const adopt = bystander.getByRole("button", { name: "Adopt their notebook" });
    await adopt.waitFor({ state: "visible", timeout: 60000 });
    await adopt.click();
    await expect
      .poll(async () => await readNotebookSource(bystander), { timeout: 30000 })
      .toBe(recoverySource);
    // Adopting the recovery replaced the notebook, not the machine's values:
    // the share the deal bound is still in its slot, which is the whole reason
    // the send cell below can run.
    expect(await ceremonySlots(bystander)).toEqual(["share-3"]);

    // The dealer is asked too, and not answering is an answer: their notebook
    // stays the deal. Two agreements, two notebooks, visibly.
    await trayTab(dealer, "Connections");
    await dealer
      .getByRole("button", { name: "Adopt their notebook" })
      .waitFor({ state: "visible", timeout: 60000 });
    expect(await readNotebookSource(dealer)).toBe(ceremonySource);

    // **Running the send cell is what agreeing looks like as a press.**
    await cell(bystander, 0).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(bystander, 0), { timeout: 120000, intervals: [250] })
      .toBe("ok");
    await runSettled(bystander);

    // And the gather, over the holder↔holder link the dealer was never part of.
    await cell(recoverer, 1).getByRole("button", { name: "Run", exact: true }).click();
    await expect
      .poll(async () => await cellStatus(recoverer, 1), { timeout: 180000, intervals: [250] })
      .toBe("ok");
    await runSettled(recoverer);

    const held = await ceremonySlots(recoverer);
    expect(held, `the recoverer's slots: ${JSON.stringify(held)}`).toContain("share-2");
    expect(held).toContain("secret");
    expect(held).toContain("recovered");

    // **This is the assertion the ceremony ships or does not ship on.** A
    // SHA-256 computed on the dealer's machine, of thirty-two bytes that were
    // drawn there and written to no slot, equal to a SHA-256 computed here of
    // what this machine put back together out of two mnemonics — one of which
    // came from a third browser the dealer never asked. Compared through the
    // screen on both ends, so neither number is one this file worked out.
    const recovered = await reveal(recoverer, 1, "recovered");
    expect(recovered, "the recoverer recombined into something else").toBe(expectedDigest);

    // And the secret itself is here, revealable, on the machine that is meant to
    // end up with it. Without this the digest match would only prove the shares
    // agree about a value nobody can spend.
    const secret = await reveal(recoverer, 1, "secret");
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(secret).not.toBe(recovered);

    // **FINDING (6a), turned over — no press is spare.** The old gather took
    // `threshold - 1` of whatever arrived first, so with two members told to
    // return a share, one press did nothing that anything reported. This
    // agreement lists exactly one contributor and the gather consumed exactly
    // that share — and the cell a person is reading when the secret comes back
    // names whose it was, by whole fingerprint (the run's provenance record).
    const gather = (await cell(recoverer, 1).innerText()).replace(/\s+/g, "");
    expect(
      gather,
      "the gather cell does not name the holder whose share it received"
    ).toContain(L.bystander);

    // The secret never reaches the dealer: recovery happened on machines the
    // dealer's press never touched, which is the property that makes the split
    // worth anything.
    expect(await ceremonySlots(dealer)).not.toContain("secret");
    expect(await ceremonySlots(bystander)).not.toContain("secret");
  }, 400_000);

  /* ── 7. what is left on the three screens ────────────────────────────────── */

  it("leaves two notebooks — the deal on the dealer, the recovery on its quorum", async () => {
    // Two agreements, two notebooks, and each machine holds the one it is
    // party to: the dealer never adopted the recovery, and the recovering
    // quorum's machines hold the agreement they wrote and ran. The refusal
    // over exchanges has not moved — `execQuorumOpen` still declines a second
    // one and `quorum-lifecycle.test.js` holds that sentence; what is checked
    // here is what a browser can see: two verified peers on every machine
    // after everything ran.
    expect(await readNotebookSource(dealer)).toBe(ceremonySource);
    expect(await dealer.locator("article").count()).toBe(CELLS);
    for (const page of [recoverer, bystander]) {
      expect(await readNotebookSource(page)).toBe(recoverySource);
      expect(await page.locator("article").count()).toBe(RECOVERY_CELLS);
    }
    for (const page of [dealer, recoverer, bystander]) {
      const count = page === dealer ? CELLS : RECOVERY_CELLS;
      const settled = await board(page, count);
      expect(
        Object.values(settled).map((s) => s.split(" — ")[0]),
        JSON.stringify(settled, null, 1)
      ).not.toContain("error");
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
