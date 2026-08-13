/**
 * The two things a test needs from a running toolkit page before it can start
 * pressing buttons: a key in the vault, and a way to read what the shell is
 * actually holding.
 *
 * Both were written inside `session-source.e2e.js`, which is where they belong
 * if there is one caller. There are two now — `placed-journey.e2e.js` drives the
 * same page through a longer story — and `readNotebookSource` in particular is
 * the exact shape of thing that must not be copied: it carries a correction
 * (`!== null` on the `open` attribute) that a second, obvious-looking
 * reimplementation would not have, and the failure mode of getting it wrong is
 * an empty string read out of a panel the second call clicked shut. A test that
 * asserts a notebook is empty, against a reader that returns "" for a collapsed
 * panel, passes for the wrong reason forever.
 *
 * @module test/helpers/toolkit-ui
 */

/**
 * The notebook's own text, as the shell renders it under Source view.
 *
 * @param {import("playwright").Page} page
 * @returns {Promise<string>}
 */
export async function readNotebookSource(page) {
  const summary = page.locator("summary", { hasText: "Notebook source (text)" });
  await summary.waitFor({ state: "visible", timeout: 15000 });
  const details = summary.locator("xpath=..");
  // `!== null`, not truthiness. An open `<details>` carries `open=""`, which is
  // falsy — so a second call on the same page clicked the summary *closed* and
  // read an empty string out of a collapsed panel. Nothing noticed while every
  // caller loaded a fresh page first; the compose test reads twice.
  if ((await details.getAttribute("open")) === null) await summary.click();
  return (await details.locator("pre").innerText()).trim();
}

/**
 * In-page: put a key this test already holds into the shipped vault.
 *
 * A **string**, not a function, because Vitest rewrites `import()` in anything
 * it transforms into a module-runner binding that does not exist in a browser,
 * and `page.evaluate` compiles a string as an *expression* — so the arguments
 * are baked in with `JSON.stringify` rather than passed.
 *
 * The vault module is resolved out of the chunks the page already loaded, the
 * `LOAD_OPS` pattern the sibling suites use: importing a second copy of the
 * graph would put a different vault behind the same IndexedDB name, and the key
 * the picker lists would not be the key `agent.unlock` opens.
 *
 * `protection: "device"` because the key exists to be *choosable* — the picker
 * needs a row and Start needs a key that owes nothing further. A
 * passphrase-protected key is a different (refused) state with its own coverage,
 * and using one here would test that refusal instead of the journey.
 *
 * The armor comes from the caller rather than being generated in the page,
 * which is the whole reason this differs from `session-source.e2e.js`'s minting
 * expression: a session bootstraps by fetching the audience from a keyserver,
 * so the identity in the vault has to be one the fixture's directory can also
 * hand out. A key minted inside the browser is a key no directory has.
 *
 * @param {{ fingerprint: string, armoredPrivate: string, armoredPublic: string, uid?: string }} key
 * @returns {string} an expression for `page.evaluate`
 */
export function seedVaultKeyExpr(key) {
  return `(async () => {
  const key = ${JSON.stringify(key)};
  const paths = [...new Set(
    performance.getEntriesByType("resource")
      .map((x) => new URL(x.name).pathname)
      .filter((n) => /^\\/assets\\/.*\\.js$/.test(n))
  )];
  let vault = null;
  for (const p of paths) {
    let mod;
    try { mod = await import(p); } catch (_) { continue; }
    const ns = [mod, ...Object.values(mod)].filter((m) => m && typeof m === "object");
    for (const m of ns) {
      if (!vault && typeof m.saveKey === "function" && typeof m.listKeys === "function") vault = m;
    }
  }
  if (!vault) throw new Error("the toolkit page loaded no chunk exporting saveKey/listKeys");
  await vault.saveKey({
    fingerprint: key.fingerprint,
    armoredPrivate: key.armoredPrivate,
    publicArmored: key.armoredPublic,
    uid: key.uid || "",
    protection: "device",
    onConflict: "replace",
  });
  return (await vault.listKeys()).map((k) => k.fingerprint);
})()`;
}
