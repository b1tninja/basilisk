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
 * A set id as every surface writes it: four upper-case hex digits.
 *
 * One function rather than the same masking-and-padding expression in the
 * check panel and in the refusals below, because those two are read *against*
 * each other — a custodian compares the `set XXXX` a panel prints for one card
 * with the `set XXXX` a refusal names for a row, and two spellings of fifteen
 * bits would make that comparison silently meaningless.
 *
 * @param {number} id
 * @returns {string}
 */
export function formatSetId(id) {
  return ((Number(id) || 0) & 0x7fff).toString(16).toUpperCase().padStart(4, "0");
}

/**
 * What a mnemonic says about itself, or `null` for anything that is not one.
 *
 * The header is written before a word of data (`encodeMnemonic`), so which
 * share this is, how many recombine and which split it belongs to are all
 * carried *by the share* — a holder handed one over a wire has every one of
 * those facts in their hand. This is the non-throwing read for surfaces that
 * are labelling a value rather than recovering from it; anything that needs
 * the octets or the failure reason calls `decodeMnemonic` directly.
 *
 * @param {string} mnemonic
 * @returns {{ index: number, total: number, threshold: number, setId: string }|null}
 */
export function readShareHeader(mnemonic) {
  const text = String(mnemonic || "");
  // A cheap bound before the split, because this is called speculatively on
  // every piece of text that reaches an output tile and most of them are not
  // shares. The largest share this codec can encode is 1023 octets, which is
  // some 830 words; anything past this is text that happens to begin with
  // words, and lower-casing and splitting a megabyte of it to find that out
  // would be paid on every run.
  if (!text.trim() || text.length > 8192) return null;
  try {
    const m = decodeMnemonic(text);
    return {
      index: m.index,
      total: m.shareCount,
      threshold: m.threshold,
      setId: formatSetId(m.id),
    };
  } catch (_) {
    return null;
  }
}

/** `[1]` → "row 1"; `[1,2]` → "rows 1 and 2"; `[1,2,4]` → "rows 1, 2 and 4". */
function rowList(rows) {
  if (rows.length === 1) return `row ${rows[0]}`;
  return `rows ${rows.slice(0, -1).join(", ")} and ${rows[rows.length - 1]}`;
}

/**
 * Which pasted rows would not decode, said with the row numbers in it.
 *
 * The old message was `decodeMnemonic`'s own four words and nothing else, so a
 * custodian with two cards in front of them was told one of the two was wrong
 * and left to work out which — the one question the failure could have
 * answered and the only one they had. Row numbers, never words: a refusal that
 * quoted the mnemonic to show where it went wrong would put the share itself
 * in an error box, a log line and a screenshot.
 *
 * @param {{ row: number, why: string }[]} bad
 * @param {number} total  how many rows were pasted
 * @returns {string}
 */
function unreadableSharesMessage(bad, total) {
  const parts = [];
  if (bad.length === 1) {
    parts.push(`${cap(rowList([bad[0].row]))} of the ${total} pasted shares is not readable: ${bad[0].why}.`);
  } else {
    parts.push(
      `${bad.length} of the ${total} pasted shares are not readable — ` +
        `${bad.map((b) => `row ${b.row}: ${b.why}`).join("; ")}.`
    );
  }
  const good = total - bad.length;
  if (good > 0) {
    parts.push(`The other ${good === 1 ? "row decoded" : `${good} rows decoded`} cleanly.`);
  }
  parts.push(
    "A BLIP39 mnemonic carries a checksum so that one wrong or missing word is refused " +
      "here rather than becoming a different secret three steps later — re-read that card, " +
      "and mind that the words are ordinary English ones autocorrect likes to change."
  );
  return parts.join(" ");
}

/**
 * Which rows came from which split, when they did not all come from one.
 *
 * This is the only thing standing between a custodian and a wrong answer that
 * looks like a right one. Two mnemonics from two ceremonies each pass their own
 * checksum, so nothing before this objects, and `combineSecret` will happily
 * interpolate two points off two different polynomials and return thirty-two
 * bytes that are nobody's secret — observed, with no error anywhere, whenever
 * the two shares happen to carry different indices. So the refusal names the
 * rows and the sets rather than the fact of disagreement: comparing set ids is
 * the whole diagnosis, and every card is carrying its own.
 *
 * @param {Blip39ShareMeta[]} decoded  one per pasted row, in row order
 * @returns {string}
 */
function setMismatchMessage(decoded) {
  /** @type {Map<string, number[]>} */
  const bySet = new Map();
  decoded.forEach((d, i) => {
    const key = formatSetId(d.id);
    if (!bySet.has(key)) bySet.set(key, []);
    (bySet.get(key) || []).push(i + 1);
  });
  const listed = [...bySet.entries()]
    .map(([setId, rows]) => `${rowList(rows)} ${rows.length === 1 ? "is" : "are"} from set ${setId}`)
    .join(", ");
  return (
    `Share set ID mismatch: ${listed}. Shares recombine only with the others from their own ` +
    "split, so one of these cards was dealt at a different ceremony — take it out and put the " +
    "missing card from the set you are recovering in its place. This is caught here because it " +
    "is not caught later: combining across two sets returns a different secret rather than an error."
  );
}

/** @param {string} s */
function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
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
  // Every row is read before anything is thrown, where `.map` used to give up
  // on the first bad one. Which rows are wrong is only knowable if the rows
  // after the first failure are decoded too, and that is exactly what the
  // message below has to say.
  /** @type {Blip39ShareMeta[]} */
  const decoded = [];
  /** @type {{ row: number, why: string }[]} */
  const unreadable = [];
  mnemonics.forEach((m, i) => {
    try {
      decoded.push(decodeMnemonic(m));
    } catch (err) {
      unreadable.push({ row: i + 1, why: err instanceof Error ? err.message : String(err) });
    }
  });
  if (unreadable.length) {
    throw new Error(unreadableSharesMessage(unreadable, mnemonics.length));
  }
  const threshold = decoded[0].threshold;
  const flags = decoded[0].flags;
  const id = decoded[0].id;
  const shareCount = decoded[0].shareCount;

  if (decoded.some((d) => d.id !== id)) throw new Error(setMismatchMessage(decoded));
  for (const d of decoded) {
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
