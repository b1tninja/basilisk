/**
 * Minimal CBOR decoder for WebAuthn attestationObject (maps, bytes, text, arrays, ints).
 */

/**
 * @param {Uint8Array} data
 * @param {number} [offset]
 * @returns {{ value: *, offset: number }}
 */
export function decodeCbor(data, offset = 0) {
  if (offset >= data.length) throw new Error("CBOR: truncated");
  const ib = data[offset++];
  const major = ib >> 5;
  let additional = ib & 0x1f;
  let length;
  if (additional < 24) {
    length = additional;
  } else if (additional === 24) {
    length = data[offset++];
  } else if (additional === 25) {
    length = (data[offset] << 8) | data[offset + 1];
    offset += 2;
  } else if (additional === 26) {
    length =
      (data[offset] << 24) |
      (data[offset + 1] << 16) |
      (data[offset + 2] << 8) |
      data[offset + 3];
    offset += 4;
  } else {
    throw new Error(`CBOR: unsupported additional info ${additional}`);
  }

  if (major === 0) return { value: length, offset };
  if (major === 1) return { value: -1 - length, offset };
  if (major === 2) {
    const value = data.subarray(offset, offset + length);
    return { value, offset: offset + length };
  }
  if (major === 3) {
    const value = new TextDecoder().decode(data.subarray(offset, offset + length));
    return { value, offset: offset + length };
  }
  if (major === 4) {
    /** @type {*[]} */
    const arr = [];
    for (let i = 0; i < length; i++) {
      const next = decodeCbor(data, offset);
      arr.push(next.value);
      offset = next.offset;
    }
    return { value: arr, offset };
  }
  if (major === 5) {
    /** @type {Map<*, *>} */
    const map = new Map();
    for (let i = 0; i < length; i++) {
      const k = decodeCbor(data, offset);
      offset = k.offset;
      const v = decodeCbor(data, offset);
      offset = v.offset;
      map.set(k.value, v.value);
    }
    return { value: map, offset };
  }
  if (major === 7 && additional === 20) return { value: false, offset };
  if (major === 7 && additional === 21) return { value: true, offset };
  if (major === 7 && additional === 22) return { value: null, offset };
  throw new Error(`CBOR: unsupported major type ${major}`);
}

/**
 * Extract AAGUID (16 bytes → UUID string) from a WebAuthn attestationObject.
 * @param {ArrayBuffer|Uint8Array} attestationObject
 * @returns {{ aaguid: string, fmt: string, authData: Uint8Array } | null}
 */
export function parseAttestationObject(attestationObject) {
  try {
    const bytes =
      attestationObject instanceof Uint8Array
        ? attestationObject
        : new Uint8Array(attestationObject);
    const { value } = decodeCbor(bytes);
    if (!(value instanceof Map)) return null;
    const fmt = String(value.get("fmt") || "");
    const authData = value.get("authData");
    if (!(authData instanceof Uint8Array) || authData.length < 37) return null;
    const flags = authData[32];
    const at = (flags & 0x40) !== 0;
    if (!at || authData.length < 55) {
      return { aaguid: ZERO_AAGUID, fmt, authData };
    }
    const aaguidBytes = authData.subarray(37, 53);
    return { aaguid: bytesToUuid(aaguidBytes), fmt, authData };
  } catch {
    return null;
  }
}

export const ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";

/** @param {Uint8Array} b */
function bytesToUuid(b) {
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20)}`
  ).toLowerCase();
}
