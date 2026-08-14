/**
 * A session leaves the notebook exactly as it found it.
 *
 * ## The claim this file used to make, and why it is the opposite one now
 *
 * It opened: *"`startSession` does not call the transport — it appends the two
 * cells a person could have typed and runs them, which is the design's whole
 * claim about reproducibility."* The cells were `agent.unlock <me> | out $me`
 * and `quorum.offer to="fpr,fpr,…" key=$me | out $session`, and this file
 * existed because the *text* of them was a product of pressing Start: it was
 * what Source view showed, what Copy link carried, what Workspace saved, and
 * what the compiler had to accept. It could not — `serializeStep` did not quote
 * a comma — and no test had ever read what the shell was holding after a press.
 *
 * That defect is fixed and its assertion has moved: `quorum.offer` is still a
 * verb anybody may type, so the comma round trip is now driven from typed text
 * in `session-flow.test.js`, where the shell is not in the way of the property.
 *
 * What replaced the claim is the argument that the two cells had outlived it.
 * A run walks to the end of a notebook, so a Run all reached `quorum.offer` for
 * a room that was already open, and `execQuorumOpen` refused it — correctly.
 * The notebook a session left behind was the only notebook in this product that
 * could not be run, which is the exact opposite of the reproducibility the
 * cells were cited for. Three separate mechanisms had been taught to step
 * around them (the `@me` header, the rule that stops them being offered back,
 * an e2e pinning the run walking into them), and a record every reader has to
 * be taught to skip is a record with no reader. Start opens the room now and
 * writes nothing.
 *
 * ## So what is left worth a browser
 *
 * The property that survives is stronger than the one it replaces, and it is
 * still a property of *the shell*, unreachable below the UI: **pressing Start
 * changes no notebook text, and puts nobody's fingerprint into it.** The room
 * is committed to the run record instead — `session-flow.test.js` proves the
 * manifest digests are the same with and without those cells — and a manifest
 * carries the audience as a digest, where recipe text carried it as a
 * comma-joined list that travels in a `#r=` link.
 *
 * Two contexts still, because the user may be either end and the two used to
 * write different cells. Now neither writes any, and *that* is what both are
 * checked for. They deliberately do not mesh: the notebook is decided at the
 * instant of the press, and a real handshake would be slower and would fail for
 * reasons that are not this one.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers } from "../helpers/browser-peers.js";
// The reader moved out when `placed-journey.e2e.js` needed the same one. It
// carries a correction a second copy would not — see its own note.
import { readNotebookSource } from "../helpers/toolkit-ui.js";
import { compileRecipe } from "../../lib/toolkit/recipe.js";
import { hashForNotebook } from "../../lib/toolkit/fragment.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the session-source suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[session-source.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/**
 * In-page: mint an OpenPGP key and store it in the shipped vault.
 *
 * Both modules are resolved out of the chunks the page already loaded, the
 * `LOAD_OPS` pattern from `stun-discovery.e2e.js` — importing a second copy of
 * the graph would put a different vault behind the same IndexedDB name. A
 * string rather than a function because Vitest rewrites `import()` in anything
 * it transforms.
 *
 * `protection: "device"` because the key exists to be *choosable*: the picker
 * needs a row and Start needs a key that owes nothing further. A
 * passphrase-protected key is a different (now-refused) state with its own
 * coverage, and using one here would test that refusal instead of this text.
 */
const MINT_VAULT_KEY = `(async () => {
  const paths = [...new Set(
    performance.getEntriesByType("resource")
      .map((x) => new URL(x.name).pathname)
      .filter((n) => /^\\/assets\\/.*\\.js$/.test(n))
  )];
  let pgp = null;
  let vault = null;
  for (const p of paths) {
    let mod;
    try { mod = await import(p); } catch (_) { continue; }
    const ns = [mod, ...Object.values(mod)].filter((m) => m && typeof m === "object");
    for (const m of ns) {
      if (!pgp && typeof m.generateKey === "function" && typeof m.readKey === "function") pgp = m;
      if (!vault && typeof m.saveKey === "function" && typeof m.listKeys === "function") vault = m;
    }
  }
  if (!pgp) throw new Error("the toolkit page loaded no chunk exporting generateKey");
  if (!vault) throw new Error("the toolkit page loaded no chunk exporting saveKey/listKeys");
  const gen = await pgp.generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name: "Session Source", email: "session-source@example.org" }],
    format: "armored",
  });
  const fpr = (await pgp.readKey({ armoredKey: gen.publicKey })).getFingerprint().toUpperCase();
  await vault.saveKey({
    fingerprint: fpr,
    armoredPrivate: gen.privateKey,
    publicArmored: gen.publicKey,
    uid: "Session Source <session-source@example.org>",
    email: "session-source@example.org",
    protection: "device",
  });
  return fpr;
})()`;

/**
 * Press Start the way a person does, and hand back what the notebook then says.
 *
 * `before` is read first and returned beside `after`, because the assertion is
 * now an equality between the two rather than a shape the press produced. It is
 * read before the room is named rather than immediately before the press, and
 * the sheet's own overlay is why — see the note at the read.
 *
 * @param {import("../helpers/browser-peers.js").Peer} peer
 * @param {string} origin
 * @param {"offer"|"join"} role
 * @param {string} otherFpr the peer this browser is not
 * @param {string} [recipe] work to have on the page before the press
 */
async function startFromTheSheet(peer, origin, role, otherFpr, recipe = "") {
  const { page } = peer;
  await page.goto(`${origin}/toolkit`, { waitUntil: "load" });
  const mine = await page.evaluate(MINT_VAULT_KEY);

  // The audience arrives the way an invited person's does — through the link —
  // so nothing in the notebook can have come from a fingerprint this test
  // typed into a box.
  //
  // `goto` to the same path with only the hash changed is a *same-document*
  // navigation, so React never remounts. That is a real way to open an invite
  // and it is covered on its own below; here the intent is a cold arrival, so
  // the document is loaded for real. A recipe, when one is asked for, rides in
  // on the same load — `#r=` and `#j=` are two hashes for two things, so the
  // notebook is loaded first and the room named after it.
  const carried = recipe ? hashForNotebook(recipe) : { ok: true, hash: "" };
  expect(carried.ok, carried.reason).toBe(true);
  await page.goto(`${origin}/toolkit${carried.hash}`, { waitUntil: "load" });
  await page.reload({ waitUntil: "load" });
  await page.waitForSelector(".toolkit-shell", { timeout: 20000 });

  // **Read before the room is named, and that ordering is forced.** The sheet
  // is a modal: its overlay swallows every click on the notebook behind it, so
  // there is no way to open Source view while the invite is up. That is the
  // product's arrangement — `placed-journey` records the same constraint — and
  // it is harmless here, because the only thing between this read and the press
  // is naming a room, which is exactly what is being asserted not to write
  // anything.
  const before = await readNotebookSource(page);

  await page.evaluate((h) => {
    window.location.hash = h;
  }, `#j=${mine},${otherFpr}`);

  const sheet = page.locator("[data-session-sheet]");
  await sheet.waitFor({ state: "visible", timeout: 20000 });

  // What the panel promises, read before the press rather than inferred from
  // it. The cells preview was here; this is what stands in its place, and a
  // sentence claiming the notebook is untouched beside a press that touches it
  // would be worse than no sentence.
  await page.getByRole("button", { name: "Show what this does to your notebook" }).click();
  const opens = await page.locator("[data-session-opens]").innerText();
  expect(opens).toContain("writes no cells");

  await page.getByRole("button", { name: role === "offer" ? "I am starting it" : "I was invited" }).click();

  // The picker only offers keys that can sign, so this select having our
  // fingerprint at all is part of what is under test.
  await page.locator("[data-session-key] select").selectOption(mine);

  const start = page.getByRole("button", {
    name: role === "offer" ? "Start shared session" : "Join shared session",
  });
  await start.waitFor({ state: "visible", timeout: 10000 });
  await expect
    .poll(async () => await start.isEnabled(), { timeout: 10000 })
    .toBe(true);
  await start.click();

  // The sheet closing is the press having been taken. Reading the notebook
  // before that would be reading it before anything could have happened to it,
  // which is how an "unchanged" assertion passes for the wrong reason.
  await sheet.waitFor({ state: "hidden", timeout: 20000 });

  // **There is no relay in this fixture and that is deliberate**, so the room
  // never comes up: `openPeers` starts two browser contexts and no signalling
  // hub, and opening one fails within a second or two. `placed-journey` and
  // `room-ceremony` are where a room really opens, and both assert the run bar
  // sits in `waiting-peer` while it does. What is asked here is what the press
  // did to the notebook, which is decided at the instant of the press and not
  // by whether anybody answers — so this waits for the attempt to be over
  // rather than for it to succeed, and reads the notebook after it.
  await expect
    .poll(
      async () => await page.locator("[data-run-state]").getAttribute("data-run-state"),
      { timeout: 60000, intervals: [250] }
    )
    .toMatch(/^(idle|blocked)$/);

  return { mine, before, after: await readNotebookSource(page) };
}

describe.runIf(availability.ok)("what a session does to the notebook", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 2 });
  });

  afterAll(async () => {
    await fx?.close();
  });

  it("writes nothing into it, at both ends", async () => {
    const [creator, joiner] = fx.peers;
    const WORK = "bytes deadbeef | encode hex | out $seed";

    // Minted inside, so each end's audience names the other for real. Two
    // passes rather than one shared list because the vault is per-context.
    const a = await startFromTheSheet(creator, fx.origin, "offer", "0".repeat(40), WORK);
    const b = await startFromTheSheet(joiner, fx.origin, "join", a.mine, WORK);

    for (const [who, seen] of Object.entries({ creator: a, joiner: b })) {
      // The work is still there and nothing was appended after it — the whole
      // claim, in one comparison. This used to assert the *presence* of
      // `quorum.offer`; a run walked into that cell and errored, which is why
      // the assertion is inverted rather than deleted.
      expect(seen.before, `${who} did not load the notebook`).toContain("out $seed");
      expect(seen.after, `${who}'s notebook was edited by pressing Start`).toBe(
        seen.before
      );
      expect(seen.after).not.toMatch(/quorum\.(offer|join)/);
      expect(seen.after).not.toMatch(/agent\.unlock/);
    }

    // And nobody's key is in the text. This is the disclosure the cells cost:
    // `recipeLinkDiscloses` counts `@peer` headers and deliberately not `to=`
    // params, so a notebook whose only fingerprints were in `quorum.offer to=`
    // told the reader it carried one key while the link carried the room.
    for (const fpr of [a.mine, b.mine]) {
      expect(a.after.toUpperCase()).not.toContain(fpr);
      expect(b.after.toUpperCase()).not.toContain(fpr);
    }
    // The compile the old premise was about, still asked: an untouched notebook
    // is a notebook that runs, which the appended one was not.
    for (const [who, seen] of Object.entries({ creator: a, joiner: b })) {
      const errors = compileRecipe(seen.after).validation.errors.map((e) => e.message);
      expect(errors, `${who}'s notebook does not compile:\n${seen.after}`).toEqual([]);
    }
  });

  it("leaves a joiner holding nothing, so the first share needs no press", async () => {
    // The consequence of writing nothing, and it is a behaviour change worth a
    // browser. `decideProposal` adopts without asking when there is no local
    // work to lose, and while Start appended cells a joiner was never empty —
    // so the creator's first notebook always arrived as a question. It arrives
    // as a notebook now. Asserted here as the *state* that makes it so; that
    // the adoption then happens silently is `room-ceremony.e2e.js`'s step 3,
    // where there is a real exchange to carry one.
    const [, joiner] = fx.peers;
    const b = await startFromTheSheet(joiner, fx.origin, "join", "0".repeat(40));
    expect(b.before, "the joiner started with work on the page").toBe("");
    expect(b.after, "pressing Join gave the joiner a notebook to lose").toBe("");
  });

  it("opens an invite that arrives while the toolkit is already up", async () => {
    // The likeliest way an invite is ever opened, and it did nothing: the two
    // of you are talking, they already have Basilisk open, the link arrives.
    // Changing only the hash is a same-document navigation, so the mount-only
    // effect that reads `#j=` never ran again — no sheet, no audience, and no
    // error to explain the silence.
    const [, joiner] = fx.peers;
    await joiner.page.goto(`${fx.origin}/toolkit`, { waitUntil: "load" });
    await joiner.page.waitForSelector(".toolkit-shell", { timeout: 20000 });
    expect(await joiner.page.locator("[data-session-sheet]").count()).toBe(0);

    const audience = ["A".repeat(40), "B".repeat(40)];
    await joiner.page.evaluate((h) => {
      window.location.hash = h;
    }, `#j=${audience.join(",")}`);

    const start = joiner.page.locator("[data-session-start]");
    await start.waitFor({ state: "visible", timeout: 15000 });
    expect(await start.getAttribute("data-session-start")).toBe("join");
    expect(await joiner.page.locator("[data-session-audience] li").count()).toBe(audience.length);
  });

  it("assigns a cell to a named room before any session exists", async () => {
    /**
     * The half of the report that was still open: nothing could be *assigned*
     * until the session was live, which is useless — a ceremony is written
     * first and run when the other person is free.
     *
     * This has to be a browser, and it has to be these presses. The peers come
     * from a draft audience that only the shell holds, the menu they appear in
     * is rendered into a portal, and the notebook they are written into is
     * serialized by the hook: there is no seam below the UI where any of that
     * can be observed. `relabel-drift.test.js` proves the rule; this proves a
     * person can reach it.
     *
     * Three fingerprints chosen for their sort order, because the sort *was*
     * the hazard. `LOWEST` is below both of the others, so adding it used to
     * renumber every label in the room — which is precisely the move that
     * changed what a written `@peer2` meant with nothing on screen to say so.
     * A peer is the whole key now, so the second half of this test asserts that
     * the same move changes nothing at all, in the notebook's own text.
     */
    const LOWEST = "0".repeat(40);
    const LOW = "1".repeat(40);
    const HIGH = "F".repeat(40);
    const [creator] = fx.peers;
    const { page } = creator;

    // A notebook first, through the link that carries one. An invite carries no
    // recipe by design, so the two hashes are used for the two things they are
    // each for.
    const recipe = hashForNotebook("random 32 | out $secret");
    expect(recipe.ok).toBe(true);
    await page.goto(`${fx.origin}/toolkit${recipe.hash}`, { waitUntil: "load" });
    // The context is shared with the tests above and one of them left a live
    // session on this page. `goto` to the same path with only the hash changed
    // is a same-document navigation, so React would never remount and this
    // would be asserting against `SessionLive` — the panel with no picker on
    // it. `startFromTheSheet` reloads for the same reason.
    await page.reload({ waitUntil: "load" });
    await page.waitForSelector(".toolkit-shell", { timeout: 20000 });

    const sheet = page.locator("[data-session-sheet]");
    const named = async (h) => {
      await page.evaluate((next) => {
        window.location.hash = next;
      }, h);
      await sheet.waitFor({ state: "visible", timeout: 15000 });
    };

    // The room is named and nobody has connected. This is the exact state the
    // assignment menu used to be empty in.
    await named(`#j=${LOW},${HIGH}`);
    expect(await page.locator(`[data-session-member="${LOW}"]`).count()).toBe(1);
    expect(await page.locator(`[data-session-member="${HIGH}"]`).count()).toBe(1);
    await page.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    // The menu prints the key grouped in fours, which is how this product
    // prints every fingerprint: a `DropdownMenuItem` cannot hold the
    // `Fingerprint` placard, and the degradation is the whole value rather than
    // a truncation. Finding the row by that spelling is also the assertion that
    // all of it is on screen.
    const printed = (fpr) => fpr.match(/.{1,4}/g).join(" ");
    const assign = page.locator("[data-cell-assign]").first();
    await assign.click();
    const second = page.getByRole("menuitem", { name: `@${printed(HIGH)}`, exact: false });
    await second.waitFor({ state: "visible", timeout: 10000 });
    // Both of them, from an audience nobody has joined — the assertion whose
    // absence shipped an empty menu.
    expect(
      await page.getByRole("menuitem", { name: `@${printed(LOW)}`, exact: false }).count()
    ).toBe(1);
    await second.click();

    await expect
      .poll(async () => await readNotebookSource(page), { timeout: 10000 })
      .toMatch(new RegExp(`^@${HIGH}$`, "m"));

    // Now the move that used to renumber the room, arriving the way it most
    // plausibly does: a corrected invite with one more person in it, whose key
    // sorts below both of the others.
    await named(`#j=${LOWEST},${LOW},${HIGH}`);
    expect(await page.locator(`[data-session-member="${LOWEST}"]`).count()).toBe(1);
    // **Nothing was said, because nothing happened.** Under the numbering this
    // was where the shell announced "cell 0 says @peer3 where it said @peer2";
    // the live region is still here and still empty, which is the assertion —
    // a narration for a rewrite that did not occur would be as wrong as silence
    // about one that did.
    expect(await page.locator("[data-relabel-note]").innerText()).toBe("");
    expect(await page.locator("[data-relabel-note]").getAttribute("data-relabel-note")).toBe("");
    await page.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    // And the header is the one the author wrote. It named `HIGH` before the
    // third person arrived and it names `HIGH` now — under the old numbering
    // this same text would have had to be rewritten from `@peer2` to `@peer3`
    // to go on meaning the same machine.
    expect(await readNotebookSource(page)).toMatch(new RegExp(`^@${HIGH}$`, "m"));
    expect(await readNotebookSource(page)).not.toMatch(/^@peer\d/m);
  });

});
