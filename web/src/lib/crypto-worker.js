/**
 * Web Worker: OpenPGP keypair generation in an isolated heap.
 *
 * Generate: { id, type:"generate", name?, email, keyExpirationTime?, passphrase? }
 *           → { armoredPublic, armoredPrivate, fingerprint }
 *
 * ## One arm, because one arm is what anything posts
 *
 * This file used to handle `decrypt`, `encrypt` and `toolkit-run` as well. All
 * three were complete, none had a poster: `lib/generate-key.js` holds the only
 * `new Worker(new URL("./crypto-worker.js", …))` in the app, and the only
 * message it sends is `type:"generate"`.
 *
 * They were deleted rather than wired because the isolation they advertised was
 * not real. The worker's value for `generate` is concrete — `generate-key.js`
 * calls `terminate()` the moment the armored key comes back, so the heap that
 * held the freshly minted private key is destroyed with it, and nothing on the
 * main thread ever saw the key object. Nothing like that was true of the other
 * three: the toolkit holds unlocked private keys on the main thread throughout
 * (`lib/toolkit/agent-ops.js`, `engine.js`, `key-power.js`, `quorum-ops.js`
 * read or decrypt them there), so an arm doing the same work "in an isolated
 * heap" described a boundary the app does not have.
 *
 * That false appearance cost twice. `docs/CRYPTOGRAPHY.md` cited the
 * `toolkit-run` arm's FIPS gate as a protection in force, when nothing could
 * reach it; and `lib/pgp/intended-recipient.js` reasoned about the `decrypt`
 * arm as the natural home for its §13.12 check while the live decrypt path grew
 * one elsewhere.
 *
 * Routing the notebook *through* the worker is a defensible design — it is just
 * a different, larger one, and it needs its own argument rather than arriving as
 * a deletion's alternative. `src/test/crypto-worker-arms.test.js` holds the
 * invariant in the meantime: an arm here and a poster in the app are the same
 * list.
 */

import { generateKey, readKey } from "openpgp";

self.onmessage = async (ev) => {
  const msg = ev.data || {};
  const { id } = msg;
  try {
    if (msg.type === "generate") {
      const email = String(msg.email || "").trim();
      if (!email) throw new Error("Email is required for key generation");
      const name = String(msg.name || "").trim();
      const userIDs = [{ name: name || email, email }];
      /** @type {Parameters<typeof generateKey>[0]} */
      const genOpts = {
        type: "ecc",
        curve: "curve25519",
        userIDs,
        format: "armored",
      };
      if (msg.passphrase) {
        genOpts.passphrase = String(msg.passphrase);
      }
      if (msg.keyExpirationTime != null && msg.keyExpirationTime > 0) {
        genOpts.keyExpirationTime = Number(msg.keyExpirationTime);
      }
      const { privateKey: armoredPrivate, publicKey: armoredPublic } =
        await generateKey(genOpts);
      // Parse public key for fingerprint (never leave object keys lingering).
      const pub = await readKey({ armoredKey: String(armoredPublic) });
      const fingerprint = pub.getFingerprint().toUpperCase();
      self.postMessage({
        id,
        ok: true,
        armoredPublic: String(armoredPublic),
        armoredPrivate: String(armoredPrivate),
        fingerprint,
      });
    } else {
      self.postMessage({ id, ok: false, error: "Unknown worker message type" });
    }
  } catch (err) {
    self.postMessage({ id, ok: false, error: err?.message || String(err) });
  }
};
