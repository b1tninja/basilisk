/**
 * BLIP39 — Basilisk mnemonic codec for SSS share payloads.
 *
 * Encodes/decodes GF(256) Shamir share octets as word phrases using the
 * official 1024-word SLIP-39 wordlist + RS1024 checksum. The checksum tag
 * remains `basilisk-slip39-v1` so existing mnemonics stay compatible.
 *
 * This module does not perform secret sharing — pair with `sss` / `recover`.
 */

import { rs1024CreateChecksum, rs1024VerifyChecksum } from "./rs1024.js";
import { WORDLIST, wordAt, wordIndex } from "./wordlist.js";

export const BLIP39_TAG = "basilisk-slip39-v1";
export const BLIP39_VERSION = 1;
/** @deprecated Legacy only — new encodes never set this. */
export const BLIP39_ENVELOPE_FLAG = 0x01;

/**
 * @typedef {object} Blip39ShareMeta
 * @property {number} version
 * @property {number} id
 * @property {number} index
 * @property {number} threshold
 * @property {number} shareCount
 * @property {number} flags
 * @property {Uint8Array} data
 */

/**
 * Encode one share's octets + set metadata into a BLIP39 mnemonic.
 * @param {Blip39ShareMeta} meta
 * @returns {string}
 */
export function encodeMnemonic(meta) {
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

  const checksum = rs1024CreateChecksum(BLIP39_TAG, symbols);
  const all = [...symbols, ...checksum];
  return all.map((i) => wordAt(i)).join(" ");
}

/**
 * Decode a BLIP39 mnemonic to share metadata + octets.
 * @param {string} mnemonic
 * @returns {Blip39ShareMeta}
 */
export function decodeMnemonic(mnemonic) {
  const words = String(mnemonic || "")
    .trim()
    .toLowerCase()
    .split(/\s+/);
  if (words.length < 8) throw new Error("Mnemonic too short");
  const indices = words.map(wordIndex);
  if (!rs1024VerifyChecksum(BLIP39_TAG, indices)) {
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

  if (version !== BLIP39_VERSION) {
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

/**
 * Encode a raw SSS share set into BLIP39 mnemonics (assigns a fresh set id).
 * @param {{
 *   raw: { index: number, data: Uint8Array }[],
 *   threshold: number,
 *   shares: number,
 *   flags?: number,
 * }} shareSet
 * @returns {{
 *   encoding: "mnemonic",
 *   mnemonics: string[],
 *   threshold: number,
 *   shares: number,
 *   id: number,
 *   flags: number,
 *   envelope: null,
 *   enveloped: boolean,
 * }}
 */
export function encodeShareSet(shareSet) {
  const raw = shareSet?.raw || [];
  if (!raw.length) throw new Error("blip39 encode expects raw SSS shares");
  const threshold = Number(shareSet.threshold);
  const shares = Number(shareSet.shares) || raw.length;
  const flags = Number(shareSet.flags) || 0;

  const idBytes = crypto.getRandomValues(new Uint8Array(2));
  const id = ((idBytes[0] << 8) | idBytes[1]) & 0x7fff;

  const mnemonics = raw.map((s) => {
    const mnemonic = encodeMnemonic({
      version: BLIP39_VERSION,
      id,
      index: s.index,
      threshold,
      shareCount: shares,
      flags,
      data: s.data,
    });
    try {
      s.data.fill(0);
    } catch (_) {
      /* wipe */
    }
    return mnemonic;
  });

  return {
    encoding: "mnemonic",
    mnemonics,
    threshold,
    shares,
    id,
    flags,
    envelope: null,
    enveloped: false,
  };
}

/**
 * Decode BLIP39 mnemonics into a raw SSS share set.
 * @param {string[]} mnemonics
 * @returns {{
 *   encoding: "raw",
 *   raw: { index: number, data: Uint8Array }[],
 *   threshold: number,
 *   shares: number,
 *   id: number,
 *   flags: number,
 *   envelope: null,
 *   enveloped: boolean,
 * }}
 */
export function decodeShareSet(mnemonics) {
  if (!mnemonics?.length) throw new Error("No mnemonics provided");
  const decoded = mnemonics.map(decodeMnemonic);
  const threshold = decoded[0].threshold;
  const flags = decoded[0].flags;
  const id = decoded[0].id;
  const shareCount = decoded[0].shareCount;

  for (const d of decoded) {
    if (d.id !== id) throw new Error("Share set ID mismatch");
    if (d.threshold !== threshold) throw new Error("Threshold mismatch across shares");
    if (d.flags !== flags) throw new Error("Flag mismatch across shares");
  }

  return {
    encoding: "raw",
    raw: decoded.map((d) => ({ index: d.index, data: d.data })),
    threshold,
    shares: shareCount,
    id,
    flags,
    envelope: null,
    enveloped: !!(flags & BLIP39_ENVELOPE_FLAG),
  };
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

export { WORDLIST };
