/**
 * Where a relay credential comes from — one request, made once, after a failure.
 *
 * The endpoint behind this is `POST /api/v1/turn/credentials`, which is gated by
 * proof of work and mints a short-lived credential server-side. Two things
 * follow from that shape and both are the point:
 *
 *  - **The long-term key is not here.** A page holding it could mint unlimited
 *    credentials against the deployment's relay egress. The server holds it and
 *    this module never sees it — what comes back is an `iceServers` list with a
 *    username and password good for minutes.
 *  - **Nothing is fetched ahead of time.** No prefetch, no cache, no warm
 *    credential kept in case one is needed. A credential obtained before the
 *    connection failed would mean a request to this app's own server on every
 *    call, and — because the server then calls the provider — a provider that
 *    learns a connection is being made. The whole arrangement is that neither
 *    hears about the connections that work.
 *
 * The request is same-origin, so `connect-src 'self'` covers it and the CSP
 * needs no relay host in it. That is the second reason the provider call is
 * server-side: reaching the provider's API from the page would widen the policy
 * for every page load, permanently, to serve the minority of connections that
 * fail.
 *
 * @module lib/webrtc/turn-credentials
 */

import { proofHeaders } from "../proof.js";
import { fetchJson } from "../utils.js";

/** Where the credential is minted. Same origin — see the module note. */
export const TURN_CREDENTIAL_URL = "/api/v1/turn/credentials";

/**
 * A minted relay grant, in the shape the endpoint promises.
 *
 * @typedef {object} RelayGrant
 * @property {number} v
 * @property {string} provider   who operates the relay — shown, never assumed
 * @property {RTCIceServer[]} iceServers
 * @property {number} ttl
 * @property {number} expires_at
 * @property {{ readsTraffic: boolean, seesAddresses: boolean, summary: string }} [disclosure]
 */

/**
 * Ask for a relay credential. Called at the moment of escalation and at no
 * other moment.
 *
 * The proof-of-work header rides along because the endpoint is gated the way
 * `/api/v1/quorum/negotiate` and the upload routes are. `proofHeaders` is
 * best-effort by design: the server, not the page, decides whether a proof was
 * required.
 *
 * A deployment with no relay configured answers 503, which arrives here as a
 * throw and is reported one layer up as "no relay available" rather than as a
 * failure — it is the shipped state, not a fault.
 *
 * @returns {Promise<RelayGrant>}
 */
export async function fetchRelayCredentials() {
  const headers = await proofHeaders();
  const grant = await fetchJson(TURN_CREDENTIAL_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: "{}",
  });
  const servers = Array.isArray(grant?.iceServers) ? grant.iceServers : [];
  if (!servers.length) throw new Error("relay: the credential endpoint returned no servers");
  return { ...grant, iceServers: servers };
}
