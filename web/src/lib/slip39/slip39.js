/**
 * SLIP-39-inspired secret sharing for the Basilisk toolkit.
 *
 * - GF(256) Shamir (same field as SLIP-39)
 * - Official 1024-word SLIP-39 wordlist + RS1024 checksum
 * - Single-group K-of-N (group syntax reserved for later)
 * - Masters must be exactly 16 or 32 bytes (native SSS). Larger payloads
 *   use an explicit OpenPGP symencrypt step before slip39.
 *
 * Legacy shares with ENVELOPE_FLAG (custom AES-GCM) can still be combined
 * when the old envelope blob is supplied; new splits never set that flag.
 *
 * Tag for RS1024 customization: "basilisk-slip39-v1" (distinct from trezor
 * "shamir" so our mnemonic layout is not confused with full SLIP-39 wallets).
 *
 * Memory: masters stay as Uint8Array; wipe with inlined fill(0) after
 * combine/split paths that allocate ephemeral masters (see memory-safety.js).
 */

import { combineSecret, splitSecret } from "./gf256.js";
import { rs1024CreateChecksum, rs1024VerifyChecksum } from "./rs1024.js";
import { WORDLIST, wordAt, wordIndex } from "./wordlist.js";

const TAG = "basilisk-slip39-v1";
const VERSION = 1;
/** @deprecated Legacy only — new splits never set this. */
const ENVELOPE_FLAG = 0x01;

/**
 * @typedef {object} ShareResult
 * @property {string[]} mnemonics
 * @property {null} envelope  Always null for new splits (OpenPGP envelope is separate)
 * @property {number} threshold
 * @property {number} shares
 * @property {boolean} enveloped  Always false for new splits
 */

/**
 * Split `secret` into K-of-N mnemonic shares.
 * @param {Uint8Array} secret
 * @param {{ threshold: number, shares: number, passphrase?: string }} opts
 * @returns {Promise<ShareResult>}
 */
export async function splitShares(secret, opts) {
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
      `slip39 accepts only 16- or 32-byte masters (got ${secret.length}). ` +
        `For EC keys use "export scalar"; for PEM/arbitrary data use "symencrypt" first.`
    );
  }

  let master = secret;
  const flags = 0;

  // Optional passphrase: stretch and XOR-mask the master before sharing
  if (opts.passphrase) {
    master = await maskWithPassphrase(master, opts.passphrase);
  }

  const rawShares = splitSecret(master, threshold, shares);
  if (opts.passphrase) {
    try {
      master.fill(0);
    } catch (_) {
      /* wipe */
    }
  }

  const id = crypto.getRandomValues(new Uint8Array(2));
  const idBits = ((id[0] << 8) | id[1]) & 0x7fff;

  const mnemonics = rawShares.map((s) => {
    const mnemonic = encodeMnemonic({
      version: VERSION,
      id: idBits,
      index: s.index,
      threshold,
      shareCount: shares,
      flags,
      data: s.data,
    });
    // Share octets are now encoded into the mnemonic words — wipe the buffer.
    try {
      s.data.fill(0);
    } catch (_) {
      /* wipe */
    }
    return mnemonic;
  });

  return {
    mnemonics,
    envelope: null,
    threshold,
    shares,
    enveloped: false,
  };
}

/**
 * Combine mnemonics (and optional legacy AES-GCM envelope) to recover the secret.
 * @param {string[]} mnemonics
 * @param {{ passphrase?: string, envelope?: Uint8Array|null }} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function combineShares(mnemonics, opts = {}) {
  if (!mnemonics?.length) throw new Error("No mnemonics provided");
  const decoded = mnemonics.map(decodeMnemonic);
  const threshold = decoded[0].threshold;
  if (decoded.length < threshold) {
    throw new Error(`Need at least ${threshold} shares, got ${decoded.length}`);
  }
  for (const d of decoded) {
    if (d.id !== decoded[0].id) throw new Error("Share set ID mismatch");
    if (d.threshold !== threshold) throw new Error("Threshold mismatch across shares");
    if (d.flags !== decoded[0].flags) throw new Error("Flag mismatch across shares");
  }

  let master = combineSecret(
    decoded.slice(0, threshold).map((d) => ({ index: d.index, data: d.data }))
  );

  if (opts.passphrase) {
    master = await maskWithPassphrase(master, opts.passphrase);
  }

  if (decoded[0].flags & ENVELOPE_FLAG) {
    if (!opts.envelope) {
      throw new Error(
        "Legacy enveloped shares require the original envelope.bin.b64 blob. " +
          "New pipelines use OpenPGP symencrypt (envelope.asc) instead of slip39 envelopes."
      );
    }
    const plain = await aesGcmOpen(master, opts.envelope);
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
 * Lightweight share mnemonic check for UI (checksum + wordlist).
 * @param {string} mnemonic
 * @returns {{ ok: boolean, error?: string }}
 */
export function validateShareMnemonic(mnemonic) {
  try {
    decodeMnemonic(mnemonic);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err?.message || String(err) };
  }
}

/**
 * @param {object} meta
 * @param {number} meta.version
 * @param {number} meta.id
 * @param {number} meta.index
 * @param {number} meta.threshold
 * @param {number} meta.shareCount
 * @param {number} meta.flags
 * @param {Uint8Array} meta.data
 * @returns {string}
 */
function encodeMnemonic(meta) {
  /** @type {number[]} */
  const symbols = [];
  const headerBits = [];
  pushBits(headerBits, meta.version, 4);
  pushBits(headerBits, meta.flags & 0xf, 4);
  pushBits(headerBits, meta.threshold & 0xf, 4);
  pushBits(headerBits, meta.shareCount & 0xf, 4);
  pushBits(headerBits, meta.index & 0xff, 8);
  pushBits(headerBits, meta.id & 0x7fff, 15);
  pushBits(headerBits, 0, 1);
  while (headerBits.length % 10 !== 0) headerBits.push(0);
  for (let i = 0; i < headerBits.length; i += 10) {
    let v = 0;
    for (let b = 0; b < 10; b++) v = (v << 1) | headerBits[i + b];
    symbols.push(v);
  }

  const dataBits = [];
  for (const byte of meta.data) pushBits(dataBits, byte, 8);
  while (dataBits.length % 10 !== 0) dataBits.push(0);
  for (let i = 0; i < dataBits.length; i += 10) {
    let v = 0;
    for (let b = 0; b < 10; b++) v = (v << 1) | dataBits[i + b];
    symbols.push(v);
  }

  symbols.splice(4, 0, meta.data.length & 1023);

  const checksum = rs1024CreateChecksum(TAG, symbols);
  const all = [...symbols, ...checksum];
  return all.map((i) => wordAt(i)).join(" ");
}

/**
 * @param {string} mnemonic
 */
function decodeMnemonic(mnemonic) {
  const words = String(mnemonic || "")
    .trim()
    .toLowerCase()
    .split(/\s+/);
  if (words.length < 8) throw new Error("Mnemonic too short");
  const indices = words.map(wordIndex);
  if (!rs1024VerifyChecksum(TAG, indices)) {
    throw new Error("Invalid share checksum");
  }
  const symbols = indices.slice(0, -3);
  const headerSyms = symbols.slice(0, 4);
  const dataLen = symbols[4];
  const dataSyms = symbols.slice(5);

  const headerBits = [];
  for (const s of headerSyms) pushBits(headerBits, s, 10);
  let bitPos = 0;
  const version = readBits(headerBits, bitPos, 4);
  bitPos += 4;
  const flags = readBits(headerBits, bitPos, 4);
  bitPos += 4;
  const threshold = readBits(headerBits, bitPos, 4);
  bitPos += 4;
  const shareCount = readBits(headerBits, bitPos, 4);
  bitPos += 4;
  const index = readBits(headerBits, bitPos, 8);
  bitPos += 8;
  const id = readBits(headerBits, bitPos, 15);

  if (version !== VERSION) {
    throw new Error(`Unsupported share version ${version}`);
  }

  const dataBits = [];
  for (const s of dataSyms) pushBits(dataBits, s, 10);
  const data = new Uint8Array(dataLen);
  for (let i = 0; i < dataLen; i++) {
    data[i] = readBits(dataBits, i * 8, 8);
  }

  return { version, flags, threshold, shareCount, index, id, data };
}

/** @param {number[]} bits @param {number} value @param {number} n */
function pushBits(bits, value, n) {
  for (let i = n - 1; i >= 0; i--) bits.push((value >> i) & 1);
}

/** @param {number[]} bits @param {number} start @param {number} n */
function readBits(bits, start, n) {
  let v = 0;
  for (let i = 0; i < n; i++) v = (v << 1) | (bits[start + i] || 0);
  return v;
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

export { WORDLIST };
