/**
 * SSS (Shamir secret sharing) for the Basilisk toolkit.
 *
 * - GF(256) Shamir (same field as SLIP-39)
 * - Masters must be exactly 16 or 32 bytes (native SSS). Larger payloads
 *   use an explicit OpenPGP symencrypt step before sss.
 * - Optional passphrase XOR-mask before split / after combine
 *
 * Mnemonic word encoding lives in blip39.js — pipe `sss | blip39` to get
 * human-readable shares, or `shares | blip39 -d | recover` to rebuild.
 *
 * Legacy shares with ENVELOPE_FLAG (custom AES-GCM) can still be combined
 * when the old envelope blob is supplied; new splits never set that flag.
 *
 * Memory: masters stay as Uint8Array; wipe with inlined fill(0) after
 * combine/split paths that allocate ephemeral masters (see memory-safety.js).
 */

import {
  BLIP39_ENVELOPE_FLAG,
  decodeShareSet,
  encodeShareSet,
  validateShareMnemonic,
} from "./blip39.js";
import { combineSecret, splitSecret } from "./gf256.js";
import { WORDLIST } from "./wordlist.js";

/**
 * @typedef {object} RawShareSet
 * @property {"raw"} encoding
 * @property {{ index: number, data: Uint8Array }[]} raw
 * @property {number} threshold
 * @property {number} shares
 * @property {number} [flags]
 * @property {null} [envelope]
 * @property {boolean} [enveloped]
 */

/**
 * @typedef {object} MnemonicShareSet
 * @property {"mnemonic"} [encoding]
 * @property {string[]} mnemonics
 * @property {null} envelope
 * @property {number} threshold
 * @property {number} shares
 * @property {boolean} enveloped
 */

/**
 * Split `secret` into K-of-N raw SSS shares (no mnemonic encoding).
 * @param {Uint8Array} secret
 * @param {{ threshold: number, shares: number, passphrase?: string }} opts
 * @returns {Promise<RawShareSet>}
 */
export async function splitRawShares(secret, opts) {
  const threshold = Number(opts.threshold);
  const shares = Number(opts.shares);
  if (!(secret instanceof Uint8Array) || !secret.length) {
    throw new Error("Secret must be a non-empty Uint8Array");
  }
  if (threshold < 1 || shares < threshold || shares > 16) {
    throw new Error("Invalid threshold/shares (1 ≤ K ≤ N ≤ 16)");
  }
  if (secret.length !== 16 && secret.length !== 32) {
    throw new Error(
      `sss accepts only 16- or 32-byte masters (got ${secret.length}). ` +
        `For EC keys use "export scalar"; for PEM/arbitrary data use "symencrypt" first.`
    );
  }

  let master = secret;
  const flags = 0;

  if (opts.passphrase) {
    master = await maskWithPassphrase(master, opts.passphrase);
  }

  const raw = splitSecret(master, threshold, shares);
  if (opts.passphrase) {
    try {
      master.fill(0);
    } catch (_) {
      /* wipe */
    }
  }

  return {
    encoding: "raw",
    raw,
    threshold,
    shares,
    flags,
    envelope: null,
    enveloped: false,
  };
}

/**
 * Combine raw SSS shares to recover the secret.
 * @param {RawShareSet|{ raw: { index: number, data: Uint8Array }[], threshold?: number, flags?: number, envelope?: Uint8Array|null }} shareSet
 * @param {{ passphrase?: string, envelope?: Uint8Array|null }} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function combineRawShares(shareSet, opts = {}) {
  const raw = shareSet?.raw || [];
  if (!raw.length) throw new Error("recover expects raw SSS shares (use blip39 -d first)");
  const threshold = Number(shareSet.threshold) || raw.length;
  if (raw.length < threshold) {
    throw new Error(`Need at least ${threshold} shares, got ${raw.length}`);
  }

  let master = combineSecret(raw.slice(0, threshold));

  if (opts.passphrase) {
    master = await maskWithPassphrase(master, opts.passphrase);
  }

  const flags = Number(shareSet.flags) || 0;
  if (flags & BLIP39_ENVELOPE_FLAG) {
    const envelope = opts.envelope || shareSet.envelope || null;
    if (!envelope) {
      /**
       * What is true, rather than what would be convenient.
       *
       * This sentence used to ask for the legacy blob by filename, which named
       * an input the product cannot accept: the branch that read one was
       * deleted in `cb19c51` because nothing in the app ever wrote the field it
       * read, so there is no tray row, parameter or file picker a holder could
       * put the blob into. A remedy that cannot be performed is worse than none
       * — it sends somebody looking for a field that has never existed on any
       * screen of this product. The filename is not repeated even here, on the
       * same reasoning the deleted tray field's own sweep gives: naming a dead
       * input in prose is how it grows a second life as "the one we used to
       * take", and that sweep will not let this comment name it either.
       *
       * The second half of the old sentence was worse: `envelope.asc` is an
       * OpenPGP message on the live `gpg.symdecrypt` path, a different object
       * from an AES-GCM SSS envelope, and offering it beside the refusal read
       * as a conversion. There is no converter here and this says nothing
       * about the legacy format beyond the one bit its own header sets.
       *
       * Who made these shares is deducible and so it is deduced out loud:
       * `splitRawShares` a few lines above has had `const flags = 0` since this
       * file's first commit, so no set this product ever dealt can reach here.
       * That makes the producer the only party who can finish the recovery, and
       * naming it is the one thing said here that the holder can act on.
       */
      throw new Error(
        "These shares are marked enveloped — their header sets the envelope flag, so " +
          "recombining them yields the key to a separate blob rather than the secret " +
          "itself. This build cannot be handed that blob: nothing here reads one, and " +
          "nothing here ever wrote one — splitRawShares has set flags = 0 since its " +
          "first commit, so no share set this product dealt carries the mark and these " +
          "cards came from some other tool. The mnemonics are fine; it is the envelope " +
          "they unlock that has no way in. Recover the secret with the tool that made " +
          "them, which is the only thing that holds both halves."
      );
    }
    const plain = await aesGcmOpen(master, envelope);
    try {
      master.fill(0);
    } catch (_) {
      /* wipe */
    }
    return plain;
  }
  return master;
}

/**
 * Split `secret` into K-of-N BLIP39 mnemonic shares (sss + blip39 encode).
 * Prefer composing toolkit steps `sss | blip39` for new recipes.
 * @param {Uint8Array} secret
 * @param {{ threshold: number, shares: number, passphrase?: string }} opts
 * @returns {Promise<MnemonicShareSet>}
 */
export async function splitShares(secret, opts) {
  const rawSet = await splitRawShares(secret, opts);
  const encoded = encodeShareSet(rawSet);
  return {
    encoding: "mnemonic",
    mnemonics: encoded.mnemonics,
    envelope: null,
    threshold: encoded.threshold,
    shares: encoded.shares,
    enveloped: false,
  };
}

/**
 * Combine BLIP39 mnemonics (and optional legacy AES-GCM envelope) to recover the secret.
 * Prefer composing toolkit steps `blip39 -d | recover` for new recipes.
 * @param {string[]} mnemonics
 * @param {{ passphrase?: string, envelope?: Uint8Array|null }} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function combineShares(mnemonics, opts = {}) {
  if (!mnemonics?.length) throw new Error("No mnemonics provided");
  const rawSet = decodeShareSet(mnemonics);
  return combineRawShares(rawSet, opts);
}

/**
 * Legacy AES-GCM open for old enveloped share sets.
 * @param {Uint8Array} key
 * @param {Uint8Array} blob
 */
async function aesGcmOpen(key, blob) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "decrypt",
  ]);
  const iv = blob.subarray(0, 12);
  const ct = blob.subarray(12);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct)
  );
}

/**
 * Deterministic mask: PBKDF2-SHA256 → XOR (toggle with same passphrase).
 * @param {Uint8Array} data
 * @param {string} passphrase
 */
async function maskWithPassphrase(data, passphrase) {
  const passBytes = new TextEncoder().encode(passphrase);
  const saltBytes = new TextEncoder().encode("basilisk-slip39-mask-v1");
  try {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: saltBytes,
        iterations: 20_000,
      },
      baseKey,
      data.length * 8
    );
    const mask = new Uint8Array(bits);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) out[i] = data[i] ^ mask[i];
    try {
      mask.fill(0);
    } catch (_) {
      /* wipe */
    }
    return out;
  } finally {
    try {
      passBytes.fill(0);
    } catch (_) {
      /* wipe */
    }
  }
}

export { WORDLIST, validateShareMnemonic };
