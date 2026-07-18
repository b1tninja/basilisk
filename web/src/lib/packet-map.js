/**
 * Packet-boundary map + OpenPGP.js metadata enrichment for the decrypt inspector.
 * Parses binary OpenPGP (same length rules as basilisk/openpgp/packets.py).
 */

import { enums } from "openpgp";
import {
  AEAD,
  COMPRESSION,
  HASH,
  PUBLIC_KEY_ALGOS,
  SYMMETRIC,
  algoName,
  s2kTypeName,
} from "./pgp/algos.js";
import { keyIdHex } from "./pgp/identity.js";

const TAG_NAMES = {
  1: "PKESK",
  2: "Signature",
  3: "SKESK",
  4: "One-Pass Signature",
  8: "Compressed Data",
  9: "Symmetrically Encrypted Data",
  10: "Marker",
  11: "Literal Data",
  13: "User ID",
  14: "Public Subkey",
  17: "User Attribute",
  18: "SEIPD",
  19: "MDC",
  20: "Padding",
  21: "AEAD Encrypted Data",
};

/**
 * @param {Uint8Array} data
 * @param {number} offset
 * @returns {{ tag: number, headerLen: number, body: Uint8Array, next: number } | null}
 */
export function readPacket(data, offset) {
  if (offset >= data.length) return null;
  const first = data[offset];
  if ((first & 0x80) === 0) throw new Error("Invalid OpenPGP packet header");

  if (first & 0x40) {
    const tag = first & 0x3f;
    let hdr = offset + 1;
    if (hdr >= data.length) throw new Error("Truncated packet length");
    const lengthByte = data[hdr];
    let length;
    if (lengthByte < 192) {
      length = lengthByte;
      hdr += 1;
    } else if (lengthByte < 224) {
      if (hdr + 1 >= data.length) throw new Error("Truncated packet length");
      length = ((lengthByte - 192) << 8) + data[hdr + 1] + 192;
      hdr += 2;
    } else if (lengthByte === 255) {
      if (hdr + 4 >= data.length) throw new Error("Truncated packet length");
      length =
        (data[hdr + 1] << 24) |
        (data[hdr + 2] << 16) |
        (data[hdr + 3] << 8) |
        data[hdr + 4];
      hdr += 5;
    } else {
      throw new Error("Unsupported partial body length");
    }
    const body = data.subarray(hdr, hdr + length);
    return { tag, headerLen: hdr - offset, body, next: hdr + length };
  }

  const tag = (first >> 2) & 0x0f;
  const lengthType = first & 0x03;
  let hdr = offset + 1;
  let length;
  if (lengthType === 0) {
    length = data[hdr];
    hdr += 1;
  } else if (lengthType === 1) {
    length = (data[hdr] << 8) | data[hdr + 1];
    hdr += 2;
  } else if (lengthType === 2) {
    length =
      (data[hdr] << 24) | (data[hdr + 1] << 16) | (data[hdr + 2] << 8) | data[hdr + 3];
    hdr += 4;
  } else {
    const body = data.subarray(hdr);
    return { tag, headerLen: hdr - offset, body, next: data.length };
  }
  const body = data.subarray(hdr, hdr + length);
  return { tag, headerLen: hdr - offset, body, next: hdr + length };
}

/**
 * @param {Uint8Array} binary
 * @returns {Array<{ tag: number, name: string, headerStart: number, bodyStart: number, end: number, colorIndex: number }>}
 */
export function mapPacketSpans(binary) {
  const spans = [];
  let offset = 0;
  let colorIndex = 0;
  while (offset < binary.length) {
    const pkt = readPacket(binary, offset);
    if (!pkt) break;
    const bodyStart = offset + pkt.headerLen;
    spans.push({
      tag: pkt.tag,
      name: TAG_NAMES[pkt.tag] || `Tag ${pkt.tag}`,
      headerStart: offset,
      bodyStart,
      end: pkt.next,
      colorIndex: colorIndex % 8,
    });
    colorIndex += 1;
    offset = pkt.next;
  }
  return spans;
}

/**
 * Dearmor ASCII armor to binary (body only).
 * @param {string} armored
 * @returns {Uint8Array}
 */
export function dearmorToBytes(armored) {
  const text = String(armored || "");
  if (!text.includes("-----BEGIN PGP")) {
    // Assume already binary as base64-ish — try UTF-8 bytes of raw input
    return new TextEncoder().encode(text);
  }
  const lines = [];
  let inBody = false;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("-----BEGIN PGP")) {
      inBody = true;
      continue;
    }
    if (line.startsWith("-----END PGP")) break;
    if (!inBody) continue;
    if (!line || line.startsWith("=")) continue;
    lines.push(line.trim());
  }
  const b64 = lines.join("");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Enrich spans with OpenPGP.js packet objects (same order when parseable).
 * @param {ReturnType<typeof mapPacketSpans>} spans
 * @param {import("openpgp").PacketList | Iterable | null | undefined} packets
 */
export function enrichSpansWithPackets(spans, packets) {
  const list = packets ? [...packets] : [];
  return spans.map((span, i) => {
    const pkt = list[i] || null;
    const detail = describePacket(span, pkt);
    return { ...span, packet: pkt, detail };
  });
}

/**
 * @param {{ tag: number, name: string }} span
 * @param {any} pkt
 */
export function describePacket(span, pkt) {
  const lines = [];
  const warnings = [];

  if (!pkt) {
    lines.push(`${span.name} (binary span only)`);
    return { lines, warnings, sessionCipher: null };
  }

  if (span.tag === 1) {
    // PKESK
    const kid = keyIdHex(pkt.publicKeyID);
    const algo = algoName(PUBLIC_KEY_ALGOS, pkt.publicKeyAlgorithm);
    lines.push(`Public-Key Encrypted Session Key v${pkt.version ?? "?"}`);
    if (kid && !/^0+$/.test(kid)) {
      lines.push(`Recipient key ID: 0x${kid}`);
    } else {
      lines.push("Recipient: anonymous / hidden");
    }
    if (algo) lines.push(`Session key wrapped with: ${algo}`);
  } else if (span.tag === 3) {
    // SKESK
    const s2kType = s2kTypeName(pkt.s2k) || pkt.s2k?.constructor?.name || "unknown";
    lines.push(`Symmetric-Key Encrypted Session Key v${pkt.version ?? "?"}`);
    lines.push("Session key protected by passphrase (SKESK)");
    lines.push(`S2K: ${s2kType}`);
    if (s2kType === "iterated" || s2kType === "salted" || s2kType === "simple") {
      warnings.push("Iterated/salted S2K is weaker than Argon2 (RFC 9580 preference).");
    }
    const skAlgo = algoName(SYMMETRIC, pkt.sessionKeyAlgorithm ?? pkt.sessionKeyEncryptionAlgorithm);
    if (skAlgo) lines.push(`Encrypted session cipher hint: ${skAlgo}`);
  } else if (span.tag === 18) {
    const ver = pkt.version ?? 1;
    if (ver >= 2) {
      const cipher = algoName(SYMMETRIC, pkt.cipherAlgorithm) || "unknown";
      const aead = algoName(AEAD, pkt.aeadAlgorithm) || "unknown AEAD";
      lines.push(`SEIPD v${ver} — ${cipher}-${aead}`);
      if (pkt.chunkSizeByte != null) lines.push(`AEAD chunk size byte: ${pkt.chunkSizeByte}`);
    } else {
      lines.push("SEIPD v1 — CFB mode + MDC");
      lines.push("Symmetric cipher hidden until session key is decrypted");
    }
  } else if (span.tag === 2) {
    lines.push(`Signature packet`);
    if (pkt.version != null) lines.push(`Version: v${pkt.version}`);
    if (pkt.created instanceof Date) lines.push(`Created: ${pkt.created.toISOString()}`);
    const kid = keyIdHex(pkt.issuerKeyID);
    if (kid) lines.push(`Issuer key ID: 0x${kid}`);
    const hash = algoName(HASH, pkt.hashAlgorithm);
    if (hash) lines.push(`Hash: ${hash}`);
    if (pkt.publicKeyAlgorithm != null) {
      lines.push(`Public-key algo: ${algoName(PUBLIC_KEY_ALGOS, pkt.publicKeyAlgorithm)}`);
    }
    if (pkt.signatureType != null) lines.push(`Signature type: ${pkt.signatureType}`);
    // RFC 9580 §5.2.3.6 / §13.2 — salt field (v6) or OpenPGP.js salt notation on v4
    const saltBytes =
      pkt.salt instanceof Uint8Array && pkt.salt.length
        ? pkt.salt
        : null;
    const saltNotation = (pkt.rawNotations || []).find(
      (n) => n?.name === "salt@notations.openpgpjs.org"
    );
    if (saltBytes) {
      lines.push(`Salt: ${saltBytes.length} bytes (RFC 9580)`);
    } else if (saltNotation?.value?.length) {
      lines.push(
        `Salt: ${saltNotation.value.length} bytes (OpenPGP.js notation; not the v6 salt field)`
      );
    } else if (pkt.version === 4) {
      lines.push("v4 signature — no RFC 9580 salt field");
    } else if (pkt.version === 6) {
      warnings.push("v6 signature missing required salt field (RFC 9580 §5.2.3.6)");
    }
    const notationNames = [
      ...(pkt.rawNotations || []).map((n) => n?.name).filter(Boolean),
      ...Object.keys(pkt.notations || {}),
    ];
    const uniqueNotations = [...new Set(notationNames)].filter(
      (n) => n !== "salt@notations.openpgpjs.org"
    );
    if (uniqueNotations.length) {
      lines.push(`Notations: ${uniqueNotations.join(", ")}`);
    }
  } else if (span.tag === 11) {
    lines.push("Literal data");
    if (pkt.filename) lines.push(`Filename: ${pkt.filename}`);
    if (pkt.format != null) lines.push(`Format: ${pkt.format}`);
  } else if (span.tag === 8) {
    lines.push(`Compressed data (${algoName(COMPRESSION, pkt.algorithm) || "unknown"})`);
  } else {
    lines.push(span.name);
  }

  return { lines, warnings, sessionCipher: null };
}

/**
 * Apply post-decrypt session key info onto SEIPD span details.
 * @param {ReturnType<typeof enrichSpansWithPackets>} enriched
 * @param {Array<{ algorithm?: string, aeadAlgorithm?: string, data?: Uint8Array }>} sessionKeys
 */
export function applySessionKeyDetails(enriched, sessionKeys) {
  if (!sessionKeys?.length) return enriched;
  const sk = sessionKeys[0];
  const cipher = sk.algorithm || "unknown";
  const aead = sk.aeadAlgorithm;
  const bits = sk.data?.length ? sk.data.length * 8 : null;
  return enriched.map((span) => {
    if (span.tag !== 18) return span;
    const extra = aead
      ? `Session key: ${cipher.toUpperCase()}-${String(aead).toUpperCase()}${bits ? ` (${bits}-bit)` : ""}`
      : `Session key: ${String(cipher).toUpperCase()}${bits ? ` (${bits}-bit / ${sk.data.length} bytes)` : ""}`;
    const lines = [...(span.detail?.lines || []), extra];
    return {
      ...span,
      detail: { ...(span.detail || {}), lines, sessionCipher: cipher },
    };
  });
}

export function tagColorClass(colorIndex) {
  return `pkt-color-${colorIndex % 8}`;
}

/** Enums re-export for tests / UI labels. */
export const PACKET_LABELS = { TAG_NAMES, PUBLIC_KEY_ALGOS, SYMMETRIC, AEAD, HASH };
