/**
 * Minimal ZIP (store / no compression) for multi-file browser downloads.
 * @module lib/zip-store
 */

/** @type {Uint32Array|null} */
let crcTable = null;

function makeCrcTable() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
}

/**
 * @param {Uint8Array} data
 * @returns {number}
 */
export function crc32(data) {
  if (!crcTable) crcTable = makeCrcTable();
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    c = crcTable[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * @param {string} text
 * @returns {Uint8Array}
 */
function encodeUtf8(text) {
  return new TextEncoder().encode(String(text ?? ""));
}

/**
 * @param {DataView} view
 * @param {number} offset
 * @param {number} value
 */
function writeU16(view, offset, value) {
  view.setUint16(offset, value, true);
}

/**
 * @param {DataView} view
 * @param {number} offset
 * @param {number} value
 */
function writeU32(view, offset, value) {
  view.setUint32(offset, value, true);
}

/**
 * Build an uncompressed ZIP archive.
 * @param {Array<{ name: string, content: string|Uint8Array }>} files
 * @returns {Uint8Array}
 */
export function buildZipStore(files) {
  /** @type {Array<{ nameBytes: Uint8Array, data: Uint8Array, crc: number, localOffset: number }>} */
  const entries = [];
  let offset = 0;

  for (const file of files || []) {
    const name = String(file.name || "file.txt").replace(/\\/g, "/");
    const nameBytes = encodeUtf8(name.replace(/^\/+/, "") || "file.txt");
    const data =
      file.content instanceof Uint8Array
        ? file.content
        : encodeUtf8(file.content);
    const crc = crc32(data);
    entries.push({ nameBytes, data, crc, localOffset: offset });
    // local header 30 + name + data
    offset += 30 + nameBytes.length + data.length;
  }

  const centralSize = entries.reduce(
    (n, e) => n + 46 + e.nameBytes.length,
    0
  );
  const endSize = 22;
  const out = new Uint8Array(offset + centralSize + endSize);
  const view = new DataView(out.buffer);

  let pos = 0;
  for (const e of entries) {
    writeU32(view, pos, 0x04034b50);
    writeU16(view, pos + 4, 20); // version needed
    writeU16(view, pos + 6, 0x0800); // UTF-8 flag
    writeU16(view, pos + 8, 0); // store
    writeU16(view, pos + 10, 0);
    writeU16(view, pos + 12, 0);
    writeU32(view, pos + 14, e.crc);
    writeU32(view, pos + 18, e.data.length);
    writeU32(view, pos + 22, e.data.length);
    writeU16(view, pos + 26, e.nameBytes.length);
    writeU16(view, pos + 28, 0);
    out.set(e.nameBytes, pos + 30);
    out.set(e.data, pos + 30 + e.nameBytes.length);
    pos += 30 + e.nameBytes.length + e.data.length;
  }

  const centralOffset = pos;
  for (const e of entries) {
    writeU32(view, pos, 0x02014b50);
    writeU16(view, pos + 4, 20);
    writeU16(view, pos + 6, 20);
    writeU16(view, pos + 8, 0x0800);
    writeU16(view, pos + 10, 0);
    writeU16(view, pos + 12, 0);
    writeU16(view, pos + 14, 0);
    writeU32(view, pos + 16, e.crc);
    writeU32(view, pos + 20, e.data.length);
    writeU32(view, pos + 24, e.data.length);
    writeU16(view, pos + 28, e.nameBytes.length);
    writeU16(view, pos + 30, 0);
    writeU16(view, pos + 32, 0);
    writeU16(view, pos + 34, 0);
    writeU16(view, pos + 36, 0);
    writeU32(view, pos + 38, 0);
    writeU32(view, pos + 42, e.localOffset);
    out.set(e.nameBytes, pos + 46);
    pos += 46 + e.nameBytes.length;
  }

  writeU32(view, pos, 0x06054b50);
  writeU16(view, pos + 4, 0);
  writeU16(view, pos + 6, 0);
  writeU16(view, pos + 8, entries.length);
  writeU16(view, pos + 10, entries.length);
  writeU32(view, pos + 12, centralSize);
  writeU32(view, pos + 16, centralOffset);
  writeU16(view, pos + 20, 0);

  return out;
}

/**
 * Ensure unique ZIP entry names (share_1.txt, share_1 (2).txt, …).
 * @param {string[]} names
 * @returns {string[]}
 */
export function uniquifyFilenames(names) {
  /** @type {Map<string, number>} */
  const seen = new Map();
  return names.map((raw) => {
    const name = String(raw || "artifact.txt");
    const n = (seen.get(name) || 0) + 1;
    seen.set(name, n);
    if (n === 1) return name;
    const dot = name.lastIndexOf(".");
    if (dot > 0) {
      return `${name.slice(0, dot)} (${n})${name.slice(dot)}`;
    }
    return `${name} (${n})`;
  });
}

/**
 * Convert a user-supplied download name into a single safe filename.
 * This prevents path components in ZIP entries and removes characters that
 * are invalid on common desktop filesystems.
 * @param {unknown} value
 * @param {string} [fallback]
 * @returns {string}
 */
export function sanitizeFilename(value, fallback = "artifact.txt") {
  const clean = String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/[\\/:*?"<>|]/g, "-")
    .trim()
    .replace(/[. ]+$/g, "")
    .slice(0, 180);
  return clean && clean !== "." && clean !== ".." ? clean : fallback;
}
