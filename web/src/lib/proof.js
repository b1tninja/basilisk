/**
 * The `X-Basilisk-Proof` header the anti-abuse gate wants.
 *
 * `basilisk/security/proof.py` mints a challenge whose `hint` is the exact
 * header value a caller must echo — the difficulty check and the signature are
 * both computed over material only the server holds, so there is no work for
 * the client to do beyond asking. That is a deliberately cheap gate: it costs
 * a round trip and makes a caller identifiable across a request pair, which is
 * what stops a script hammering an endpoint from nowhere.
 *
 * Fetching is best-effort. When `BASILISK_REQUIRE_PROOF` is off the server
 * ignores the header entirely, so a challenge that fails to load must not stop
 * the request it was meant to accompany — the server, not this module, decides
 * whether a proof was required.
 *
 * @module lib/proof
 */

/**
 * @returns {Promise<Record<string, string>>} headers to merge into a request
 */
export async function proofHeaders() {
  try {
    const r = await fetch("/pks/v2/challenge", { credentials: "include" });
    if (!r.ok) return {};
    const body = await r.json();
    const hint = typeof body?.hint === "string" ? body.hint : "";
    return hint ? { "X-Basilisk-Proof": hint } : {};
  } catch (_) {
    return {};
  }
}
