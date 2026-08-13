/**
 * A session leaves behind a notebook that still compiles.
 *
 * This is the assertion whose absence shipped a blocker. `startSession` does
 * not call the transport — it appends the two cells a person could have typed
 * and runs them, which is the design's whole claim about reproducibility. So
 * the notebook's *text* is a product of pressing Start, and the text is what
 * every other feature reads: Source view, Copy link, Workspace save, the run
 * planner, and the compiler that decides whether the notebook can run at all.
 *
 * It could not. `serializeStep` did not quote a comma, `quorum.offer`'s `to=`
 * is positional, and an audience is a comma-joined list that must hold at
 * least two fingerprints to be a room — so every session serialized to
 * `quorum.offer 9F2A…,D772… key=$me` and the notebook stopped compiling with
 * `Unexpected "," · Unexpected "<the next fingerprint's first character>"`.
 *
 * Nothing caught it because every layer was tested against the layer above it.
 * `sessionRecipe`'s output compiles — asserted. The registry example sweep in
 * `recipe-roundtrip.test.js` skips `quorum.offer`, whose example names a slot
 * an earlier cell registers. And no test had ever read what the *shell* was
 * holding after a press. That is this file.
 *
 * ## Why the UI, and not `page.evaluate`
 *
 * The sibling suites drive modules directly, correctly: they are about the
 * transport, and there is no UI for a DTLS fingerprint. This defect lives
 * between the widget and the notebook — in what a press writes and what the
 * shell then serializes — so evaluating `sessionRecipe` in the page would
 * reproduce the half that always worked. The press has to be a press.
 *
 * ## Why two contexts, and no mesh
 *
 * Both ends are checked because the user may be either, and the two write
 * different cells (`quorum.offer` / `quorum.join`). The joiner arrives through
 * `#j=`, so its audience is the one the *link* produced rather than one typed
 * by hand — the path with the most room to put something unexpected in the
 * text.
 *
 * They deliberately do not mesh. Joining is what made the user notice, but it
 * is not what wrote the text: the cells are on the page the instant Start is
 * pressed. A test that waited for a real handshake would be slower, would fail
 * for reasons that are not this one, and would assert nothing extra.
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
 * @param {import("../helpers/browser-peers.js").Peer} peer
 * @param {string} origin
 * @param {"offer"|"join"} role
 * @param {string} otherFpr the peer this browser is not
 */
async function startFromTheSheet(peer, origin, role, otherFpr) {
  const { page } = peer;
  await page.goto(`${origin}/toolkit`, { waitUntil: "load" });
  const mine = await page.evaluate(MINT_VAULT_KEY);

  // The audience arrives the way an invited person's does — through the link —
  // so the fingerprints in the notebook are the ones `parseToolkitHash`
  // produced rather than ones this test typed into a box.
  //
  // `goto` to the same path with only the hash changed is a *same-document*
  // navigation, so React never remounts. That is a real way to open an invite
  // and it is covered on its own below; here the intent is a cold arrival, so
  // the document is loaded for real.
  await page.goto(`${origin}/toolkit#j=${mine},${otherFpr}`, { waitUntil: "load" });
  await page.reload({ waitUntil: "load" });

  const sheet = page.locator("[data-session-sheet]");
  await sheet.waitFor({ state: "visible", timeout: 20000 });

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

  return { mine, source: await readNotebookSource(page) };
}

describe.runIf(availability.ok)("what a session writes into the notebook", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 2 });
  });

  afterAll(async () => {
    await fx?.close();
  });

  it("leaves a notebook that still compiles, at both ends", async () => {
    const [creator, joiner] = fx.peers;

    // Minted first so each end's audience can name the other for real. Two
    // passes rather than one shared list because the vault is per-context.
    const a = await startFromTheSheet(creator, fx.origin, "offer", "0".repeat(40));
    const b = await startFromTheSheet(joiner, fx.origin, "join", a.mine);
    const again = await startFromTheSheet(creator, fx.origin, "offer", b.mine);

    for (const [who, { source }] of Object.entries({
      creator: again,
      joiner: b,
    })) {
      expect(source, `${who} wrote no session cells`).toMatch(/quorum\.(offer|join)/);
      const errors = compileRecipe(source).validation.errors.map((e) => e.message);
      expect(errors, `${who}'s notebook does not compile:\n${source}`).toEqual([]);
    }
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
     * This has to be a browser, and it has to be these presses. The labels come
     * from a draft audience that only the shell holds, the menu they appear in
     * is rendered into a portal, and the notebook they are written into is
     * serialized by the hook: there is no seam below the UI where any of that
     * can be observed. `relabel-drift.test.js` proves the rule; this proves a
     * person can reach it.
     *
     * Three fingerprints chosen for their sort order, because the sort is the
     * hazard. `LOWEST` is below both of the others, so adding it renumbers
     * every label in the room — which is precisely the move that used to change
     * what a written `@peer2` meant with nothing on screen to say so.
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
    expect(await page.locator('[data-session-member="peer1"]').count()).toBe(1);
    expect(await page.locator('[data-session-member="peer2"]').count()).toBe(1);
    await page.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    const assign = page.locator("[data-cell-assign]").first();
    await assign.click();
    const second = page.getByRole("menuitem", { name: /@peer2/ });
    await second.waitFor({ state: "visible", timeout: 10000 });
    // Both of them, from an audience nobody has joined — the assertion whose
    // absence shipped an empty menu.
    expect(await page.getByRole("menuitem", { name: /@peer1/ }).count()).toBe(1);
    await second.click();

    await expect
      .poll(async () => await readNotebookSource(page), { timeout: 10000 })
      .toMatch(/^@peer2$/m);

    // Now the renumbering, arriving the way it most plausibly does: a corrected
    // invite with one more person in it.
    await named(`#j=${LOWEST},${LOW},${HIGH}`);
    await expect
      .poll(async () => await page.locator("[data-relabel-note]").innerText(), {
        timeout: 10000,
      })
      .toContain("@peer3");
    await page.keyboard.press("Escape");
    await sheet.waitFor({ state: "hidden", timeout: 10000 });

    // The header moved with the person: `HIGH` was peer2 in a room of two and
    // is peer3 in a room of three. A notebook that still said `@peer2` would be
    // addressing `LOW` — a different machine, silently.
    expect(await readNotebookSource(page)).toMatch(/^@peer3$/m);
  });

  it("keeps the audience readable as itself, not merely parseable", async () => {
    // Compiling is not enough. A value can survive the round trip truncated —
    // `{40,64}` on an unseparated pair yields one fabricated 64-character id —
    // and a notebook that compiles to the wrong room is worse than one that
    // does not compile, because nothing complains.
    const [creator] = fx.peers;
    const other = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
    const { mine, source } = await startFromTheSheet(creator, fx.origin, "offer", other);
    const step = compileRecipe(source)
      .ast.chains.flatMap((c) => c.steps || [])
      .find((s) => String(s.name).startsWith("quorum."));
    expect(String(step?.params?.to || "").split(",").sort()).toEqual([mine, other].sort());
  });
});
