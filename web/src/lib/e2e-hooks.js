/**
 * Dev-only hooks for driving the toolkit from automation (agent tools,
 * Playwright, the Claude browser). Mounted by the toolkit page ONLY under
 * `import.meta.env.DEV` — the production build never imports this module.
 *
 * The centrepiece: mint an OpenPGP keypair that lives in the agent session
 * cache alone. Nothing touches IndexedDB, so an e2e run leaves no key
 * material behind — closing the tab (or the session TTL) is the cleanup.
 * `unlockVaultForUse` resolves session-only fingerprints, so every gpg
 * recipe and template that goes through the unlock path can use the minted
 * key exactly like a vault key.
 * @module lib/e2e-hooks
 */

import { generateKey, readKey } from "openpgp";
import { sessionEvict, sessionList, sessionPut } from "./vault-session.js";

/**
 * @param {{ name?: string, email?: string }} [opts]
 * @returns {Promise<{ fingerprint: string, publicKey: string, privateKey: string }>}
 */
async function mintSessionKey(opts = {}) {
  const email = String(opts.email || "e2e@example.test");
  const name = String(opts.name || "E2E session key");
  const { privateKey, publicKey } = await generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name, email }],
    format: "armored",
  });
  const key = await readKey({ armoredKey: publicKey });
  const fingerprint = key.getFingerprint().toUpperCase();
  // Unencrypted armor straight into the session cache — in memory, TTL'd,
  // wiped by Clear session like any unlocked key. Never written to the vault.
  sessionPut(fingerprint, privateKey);
  return { fingerprint, publicKey, privateKey };
}

export function mountE2eHooks() {
  if (typeof window === "undefined") return;
  /** @type {Record<string, unknown>} */
  const hooks = {
    mintSessionKey,
    sessionKeys: () => sessionList(),
    evictSessionKey: (fpr) => sessionEvict(String(fpr || "")),
  };
  Object.assign((window.__basiliskE2E ||= {}), hooks);
}

mountE2eHooks();
