/**
 * The `X-Basilisk-Proof` header the anti-abuse gate wants.
 *
 * `basilisk/security/proof.py` mints a challenge. When `difficulty` is 0 the
 * `hint` is the exact header value a caller must echo. That is a deliberately
 * cheap gate: it costs a round trip and makes a caller identifiable across a
 * request pair, which is what stops a script hammering an endpoint from nowhere.
 *
 * When `difficulty` is greater than 0 the header is
 * `nonce:timestamp:counter:signature`. `counter` is chosen here so
 * SHA-256(`nonce:timestamp:counter`) has that many leading zero hex digits.
 * The signature is still the HMAC from the challenge; it does not cover the
 * counter, which is what makes the search possible.
 *
 * Fetching is best-effort. When `BASILISK_REQUIRE_PROOF` is off the server
 * ignores the header entirely, so a challenge that fails to load must not stop
 * the request it was meant to accompany — the server, not this module, decides
 * whether a proof was required.
 *
 * @module lib/proof
 */

const MAX_PROOF_STEPS = 5_000_000;

/**
 * @param {string} text
 * @returns {Promise<string>} lowercase hex SHA-256
 */
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * @param {string} nonce
 * @param {string} timestamp
 * @param {number} difficulty
 * @returns {Promise<string>}
 */
async function grindCounter(nonce, timestamp, difficulty) {
  const prefix = "0".repeat(difficulty);
  for (let counter = 0; counter < MAX_PROOF_STEPS; counter += 1) {
    const digest = await sha256Hex(`${nonce}:${timestamp}:${counter}`);
    if (digest.startsWith(prefix)) return String(counter);
  }
  throw new Error("proof of work exceeded search bound");
}

/**
 * @returns {Promise<Record<string, string>>} headers to merge into a request
 */
export async function proofHeaders() {
  try {
    const r = await fetch("/pks/v2/challenge", { credentials: "include" });
    if (!r.ok) return {};
    const body = await r.json();
    const hint = typeof body?.hint === "string" ? body.hint : "";
    if (!hint) return {};
    const difficulty = Number(body?.difficulty) || 0;
    if (difficulty <= 0) return { "X-Basilisk-Proof": hint };
    const parts = hint.split(":");
    if (parts.length !== 3) return {};
    const [nonce, timestamp, signature] = parts;
    const counter = await grindCounter(nonce, timestamp, difficulty);
    return { "X-Basilisk-Proof": `${nonce}:${timestamp}:${counter}:${signature}` };
  } catch (_) {
    return {};
  }
}
