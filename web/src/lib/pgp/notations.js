/**
 * Notation Data helpers (RFC 9580 §5.2.3.24).
 * @module lib/pgp/notations
 */

/**
 * @typedef {{ name: string, value: string, humanReadable: boolean, critical: boolean }} NotationEntry
 */

/**
 * Normalize OpenPGP.js notation maps / rawNotations into display rows.
 * @param {import("openpgp").SignaturePacket | null | undefined} sig
 * @returns {NotationEntry[]}
 */
export function notationsFromSignature(sig) {
  if (!sig) return [];
  /** @type {NotationEntry[]} */
  const out = [];
  const seen = new Set();

  for (const raw of sig.rawNotations || []) {
    const name = String(raw?.name || "");
    if (!name || name === "salt@notations.openpgpjs.org") continue;
    const key = `${name}\0${raw?.value || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let value = "";
    if (raw.value instanceof Uint8Array) {
      value = raw.humanReadable
        ? new TextDecoder().decode(raw.value)
        : Array.from(raw.value)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    } else {
      value = String(raw.value ?? "");
    }
    out.push({
      name,
      value,
      humanReadable: !!raw.humanReadable,
      critical: !!raw.critical,
    });
  }

  const map = sig.notations;
  if (map && typeof map === "object") {
    for (const [name, value] of Object.entries(map)) {
      if (!name || name === "salt@notations.openpgpjs.org") continue;
      const key = `${name}\0${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        name,
        value: String(value ?? ""),
        humanReadable: true,
        critical: false,
      });
    }
  }
  return out;
}

/**
 * Read notations from a key's primary self-signature.
 * @param {import("openpgp").Key | null | undefined} key
 * @param {Date} [date]
 * @returns {Promise<NotationEntry[]>}
 */
export async function readKeyNotations(key, date = new Date()) {
  if (!key) return [];
  try {
    const selfSig = await key.getPrimarySelfSignature(date);
    return notationsFromSignature(selfSig);
  } catch (_) {
    return [];
  }
}
