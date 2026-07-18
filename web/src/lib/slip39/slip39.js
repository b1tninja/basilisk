/**
 * SLIP-39-inspired secret sharing for the Basilisk toolkit.
 *
 * - GF(256) Shamir (same field as SLIP-39)
 * - Official 1024-word SLIP-39 wordlist + RS1024 checksum
 * - Single-group K-of-N (group syntax reserved for later)
 * - Envelope mode for payloads ≠ 16/32 bytes: AES-256-GCM encrypt payload
 *   under a random 256-bit master secret, then split the master.
 *
 * Share mnemonics are recoverable with combineShares(). Envelope ciphertext
 * (when present) must be supplied alongside the mnemonics to unwrap the payload.
 *
 * Tag for RS1024 customization: "basilisk-slip39-v1" (distinct from trezor
 * "shamir" so our mnemonic layout is not confused with full SLIP-39 wallets).
 */

import { combineSecret, splitSecret } from "./gf256.js";
import { rs1024CreateChecksum, rs1024VerifyChecksum } from "./rs1024.js";
import { WORDLIST, wordAt, wordIndex } from "./wordlist.js";
import { zeroBuffer } from "../toolkit/encode.js";

const TAG = "basilisk-slip39-v1";
const VERSION = 1;
const ENVELOPE_FLAG = 0x01;

/**
 * @typedef {object} ShareResult
 * @property {string[]} mnemonics
 * @property {Uint8Array|null} envelope  AES-GCM blob (iv||ct) when payload was wrapped
 * @property {number} threshold
 * @property {number} shares
 * @property {boolean} enveloped
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

  let master = secret;
  /** @type {Uint8Array|null} */
  let envelope = null;
  let flags = 0;

  const nativeSized = secret.length === 16 || secret.length === 32;
  if (!nativeSized) {
    // Envelope: random 32-byte master encrypts the payload
    master = crypto.getRandomValues(new Uint8Array(32));
    envelope = await aesGcmSeal(master, secret);
    flags |= ENVELOPE_FLAG;
  }

  // Optional passphrase: stretch and XOR-mask the master before sharing
  if (opts.passphrase) {
    master = await maskWithPassphrase(master, opts.passphrase);
  }

  const rawShares = splitSecret(master, threshold, shares);
  if (opts.passphrase) zeroBuffer(master);

  const id = crypto.getRandomValues(new Uint8Array(2));
  const idBits = ((id[0] << 8) | id[1]) & 0x7fff;

  const mnemonics = rawShares.map((s) =>
    encodeMnemonic({
      version: VERSION,
      id: idBits,
      index: s.index,
      threshold,
      shareCount: shares,
      flags,
      data: s.data,
    })
  );

  return {
    mnemonics,
    envelope,
    threshold,
    shares,
    enveloped: !!(flags & ENVELOPE_FLAG),
  };
}

/**
 * Combine mnemonics (and optional envelope) to recover the secret.
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
  // Consistency checks
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
        "Envelope ciphertext required to recover this secret — paste the envelope.bin.b64 artifact that was emitted with the shares (required for PEM / non-16/32-byte payloads)"
      );
    }
    const plain = await aesGcmOpen(master, opts.envelope);
    zeroBuffer(master);
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
  // Pack metadata into 10-bit symbols, then data bytes as 10-bit stream, then checksum.
  /** @type {number[]} */
  const symbols = [];
  // symbol0: version(4) | flags(4) | threshold-1(2 high bits of later)
  // Compact header (5 symbols = 50 bits):
  //   version:4, flags:4, threshold:4, shareCount:4, index:8, id:15, pad:1
  const headerBits = [];
  pushBits(headerBits, meta.version, 4);
  pushBits(headerBits, meta.flags & 0xf, 4);
  pushBits(headerBits, meta.threshold & 0xf, 4);
  pushBits(headerBits, meta.shareCount & 0xf, 4);
  pushBits(headerBits, meta.index & 0xff, 8);
  pushBits(headerBits, meta.id & 0x7fff, 15);
  pushBits(headerBits, 0, 1); // pad to 40 → wait we have 4+4+4+4+8+15+1 = 40 bits = 4 symbols
  // 40 bits = 4 symbols of 10 bits
  while (headerBits.length % 10 !== 0) headerBits.push(0);
  for (let i = 0; i < headerBits.length; i += 10) {
    let v = 0;
    for (let b = 0; b < 10; b++) v = (v << 1) | headerBits[i + b];
    symbols.push(v);
  }

  // Data as bit stream → 10-bit symbols
  const dataBits = [];
  for (const byte of meta.data) pushBits(dataBits, byte, 8);
  while (dataBits.length % 10 !== 0) dataBits.push(0);
  for (let i = 0; i < dataBits.length; i += 10) {
    let v = 0;
    for (let b = 0; b < 10; b++) v = (v << 1) | dataBits[i + b];
    symbols.push(v);
  }

  // Length prefix so decoder knows data byte length: prepend as one symbol
  // (already have header; store dataLen in an extra symbol after header)
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
  // First 4 symbols = header (40 bits), then length symbol, then data
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
 * @param {Uint8Array} key
 * @param {Uint8Array} plaintext
 * @returns {Promise<Uint8Array>} iv(12) || ciphertext+tag
 */
async function aesGcmSeal(key, plaintext) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "encrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plaintext)
  );
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

/**
 * @param {Uint8Array} key
 * @param {Uint8Array} blob
 * @returns {Promise<Uint8Array>}
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
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new TextEncoder().encode("basilisk-slip39-mask-v1"),
      iterations: 20_000,
    },
    baseKey,
    data.length * 8
  );
  const mask = new Uint8Array(bits);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ mask[i];
  zeroBuffer(mask);
  return out;
}

export { WORDLIST };
