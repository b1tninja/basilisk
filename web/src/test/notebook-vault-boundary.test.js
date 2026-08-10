/**
 * The session layer never reaches for a stored secret.
 *
 * `lib/notebook/` handles bytes that arrived from a remote peer: signalling
 * envelopes, hellos, offers, key confirmations, relayed frames. `lib/vault.js`
 * and its two companions hold the opposite kind of material — long-term private
 * keys at rest, and the device KEK that unwraps them. One import statement is
 * all that separates "a peer sent us a frame" from "a peer sent us a frame and
 * the handler that parses it can also read the keyring", which is the shape a
 * parsing bug needs to become a key disclosure.
 *
 * The boundary already holds, but until now it held *by accident* — nothing
 * asserted it, and nothing about the directory layout prevented it. What keeps
 * it true by construction is that key material is **passed in**:
 * `unlockPrivateKey(armored, passphrase)` takes both from its caller, so the
 * mount and the ops decide what the session is allowed to see and the session
 * has no way to widen that on its own.
 *
 * This is a different rule from the one `notebook-layering.test.js` pins. That
 * file is about the layer *below* — who may drive an `RTCPeerConnection`. This
 * one is about a directory the session layer must not reach *sideways* into,
 * and the two can fail independently.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** @param {string} rel */
const dir = (rel) => fileURLToPath(new URL(rel, import.meta.url));

/**
 * Comments are stripped: this docstring and the ones in `lib/notebook/`
 * *discuss* the vault on purpose — `room.js` explains that its scope matches
 * the vault's WebAuthn RP id, and `crypto.js` names device KEKs when it
 * explains what it is not doing. Prose about a boundary is not a crossing of
 * it, and a matcher that could not tell the difference would push those
 * explanations out of the files that need them most.
 *
 * @returns {{ name: string, code: string }[]}
 */
function notebookModules() {
  const base = dir("../lib/notebook/");
  return readdirSync(base)
    .filter((f) => f.endsWith(".js"))
    .map((name) => ({
      name: `lib/notebook/${name}`,
      code: readFileSync(`${base}/${name}`, "utf8")
        .replace(/\r\n/g, "\n")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, ""),
    }));
}

const MODULES = notebookModules();

/**
 * Any module specifier ending in one of the three vault modules, in an `import`
 * or a dynamic `import()`. The optional `-session`/`-unlock` suffix is spelled
 * out rather than left to `vault[\w-]*` so that a future `vault-policy.js`
 * fails this test loudly instead of being silently covered or silently missed.
 */
const VAULT_IMPORT =
  /\bimport\b[^;]*?["'][^"']*\bvault(-session|-unlock)?\.js["']|\bimport\s*\(\s*["'][^"']*\bvault(-session|-unlock)?\.js["']/;

describe("the notebook session layer holds no vault import", () => {
  it("has modules to check", () => {
    // A readdir that silently returned nothing would make every assertion
    // below vacuously true — the failure mode this whole file exists to avoid.
    expect(MODULES.length).toBeGreaterThan(0);
    expect(MODULES.map((m) => m.name)).toContain("lib/notebook/session.js");
  });

  it.each(MODULES)("$name imports no vault module", ({ name, code }) => {
    expect(code, `${name} imports the vault`).not.toMatch(VAULT_IMPORT);
  });

  it("would catch the import coming back", () => {
    // The matcher proved against the thing it is meant to catch, so a green
    // run above is evidence about the source rather than about the regex.
    for (const relapse of [
      'import { openVault } from "../vault.js";',
      'import { deviceKek } from "../vault-session.js";',
      'import unlock from "@/lib/vault-unlock.js";',
      'const v = await import("../vault.js");',
    ]) {
      expect(VAULT_IMPORT.test(relapse), relapse).toBe(true);
    }
  });

  it("does not fire on prose or on unrelated modules", () => {
    // `room.js` and `crypto.js` both mention the vault in their docstrings, and
    // the roster imports nothing at all. Neither is a crossing.
    expect(VAULT_IMPORT.test("the vault.js device KEK is not used here")).toBe(false);
    expect(VAULT_IMPORT.test('import { shortFpr } from "./roster.js";')).toBe(false);
  });
});
