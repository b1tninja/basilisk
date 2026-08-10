/**
 * Mesh relay + health rules — pure decisions for NotebookSession's
 * channel-first signaling (p2p-dkg DESIGN §4: "existing members relay
 * introductions for newcomers over already-authenticated data channels, so
 * only the first join needs out-of-band signaling").
 *
 * Safety model: what rides a relay is the *sealed signaling envelope* —
 * audience-encrypted and PGP-signed end to end, its transcript bound to
 * room + identities + nonces (the RFC 8844 shape). A relaying member can
 * delay or drop it, never read, forge, or replant it in another session.
 * The rules below are only about loops and floods, not trust.
 * @module lib/notebook/relay
 */

/**
 * A frame can cross at most this many links. In a full mesh the direct path
 * is one hop and any introduction path is two (newcomer → member → target);
 * three tolerates one dead link during churn without permitting loops to
 * live long.
 */
export const MAX_RELAY_HOPS = 3;

/**
 * The honest ceiling for full mesh (DESIGN §1): the quadratic term is fine
 * for DKG-sized rooms (3-of-5, 5-of-7) and degrades past ~8 — say so
 * instead of pretending arbitrary N works.
 */
export const MESH_SOFT_CAP = 8;

/**
 * Whether a received envelope frame addressed to someone else should be
 * forwarded on.
 * @param {{ to: string, myFpr: string, hops: number }} x
 * @returns {boolean}
 */
export function shouldRelay({ to, myFpr, hops }) {
  if (!to || to === myFpr) return false;
  return hops < MAX_RELAY_HOPS;
}

/**
 * Classify a raw data-channel frame without trusting it: a signaling
 * envelope rides in plaintext (it is sealed end-to-end already), everything
 * else is session-encrypted `{ v, blob }` traffic.
 * @param {string} raw
 * @returns {{ kind: "envelope", env: string, hops: number }
 *   | { kind: "session", blob: string }
 *   | null}
 */
export function classifyChannelFrame(raw) {
  let parsed;
  try {
    parsed = JSON.parse(String(raw || ""));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  if (typeof parsed.env === "string" && parsed.env) {
    const hops = Number(parsed.hops);
    return {
      kind: "envelope",
      env: parsed.env,
      hops: Number.isFinite(hops) && hops >= 0 ? Math.trunc(hops) : 0,
    };
  }
  if (typeof parsed.blob === "string" && parsed.blob) {
    return { kind: "session", blob: parsed.blob };
  }
  return null;
}

/**
 * Bounded dedupe for relayed envelopes — an armored blob seen once is
 * dropped on every later arrival, and memory stays flat under flood.
 * @param {number} [cap]
 * @returns {{ seen: (key: string) => boolean }}
 */
export function createSeenSet(cap = 256) {
  /** @type {Set<string>} */
  const set = new Set();
  return {
    /** Returns true when already seen; records it otherwise. */
    seen(key) {
      if (set.has(key)) return true;
      set.add(key);
      if (set.size > cap) {
        // Sets iterate in insertion order — evict the oldest.
        const oldest = set.values().next().value;
        set.delete(oldest);
      }
      return false;
    },
  };
}

/**
 * @typedef {object} MeshHealth
 * @property {number} participants
 * @property {number} degree     links per member (N-1)
 * @property {number} links      total pairwise links (N(N-1)/2)
 * @property {boolean} overCap
 * @property {string} note       honest capacity statement, always present
 */

/**
 * @param {number} participants  room size including self
 * @returns {MeshHealth}
 */
export function meshHealth(participants) {
  const n = Math.max(0, Math.trunc(Number(participants) || 0));
  const degree = Math.max(0, n - 1);
  const links = (n * degree) / 2;
  const overCap = n > MESH_SOFT_CAP;
  return {
    participants: n,
    degree,
    links,
    overCap,
    note: overCap
      ? `${n} participants means ${links} pairwise links — full mesh degrades past ~${MESH_SOFT_CAP}; expect slow joins and churn`
      : `${links} pairwise link${links === 1 ? "" : "s"} — comfortably inside full-mesh range`,
  };
}
