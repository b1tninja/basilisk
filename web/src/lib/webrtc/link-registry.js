/**
 * The inventory of live peer connections (§55a).
 *
 * One module-level map of **links** — the word is deliberate, because
 * "connection" already means three things here (`RTCPeerConnection`,
 * `connectionState`, `ConnectionsPanel`). A link is one managed
 * `RTCPeerConnection` plus whatever created it, held by an id a recipe can
 * name.
 *
 * Two things register into it and they have different security properties:
 *
 *  - **`quorum`** links are identity-bound. The far end proved possession of a
 *    PGP key, and the data channel carries a pairwise session key derived over
 *    a transcript that includes both DTLS fingerprints.
 *  - **`peer`** links are not. DTLS encrypts the wire, and whoever received the
 *    offer is on the far end.
 *
 * `origin` is the one place that distinction is recorded, so every surface that
 * draws a link — the panel, the `connstate` tile, an op's refusal — reads it
 * from here instead of deciding for itself.
 *
 * **Why `lib/webrtc/` and not the session layer, where it started.** An inventory
 * of `RTCPeerConnection`s is not the mesh's, and this module holds no
 * fingerprint, derives no key and drives no negotiation — `origin` is a label
 * its registrants supply. Filed under the session layer it made `peer.offer`, an op
 * with no PGP audience and no relay, unable to run without the module that
 * implements both; `lib/toolkit/peer-ops.js` imported the session layer that is
 * supposed to sit on top of it. Quorum registers into this, the same way
 * `peer.*` does.
 *
 * **Why a holder instead of copied fields.** A record stores the object that
 * owns the connection and reads `pc`/`channel` *through* it, rather than
 * copying them at registration. A channel does not exist when its
 * `RTCPeerConnection` is created, and `ondatachannel` may replace it on a
 * renegotiation — so a copied field would be stale from that moment onward, in
 * the exact direction that reads as "connected but no channel". `peer.*`
 * registers a holder of its own (it keeps an inbox and waiters beside the pair);
 * the mesh registers its `PeerLink`, which is a holder by construction and is
 * the only thing on that side of the boundary allowed to hold a connection.
 *
 * @module lib/webrtc/link-registry
 */

import { RELAY_OFF, armRelayFallback, relayCarriedTraffic } from "./relay-fallback.js";

/**
 * @typedef {object} LinkHolder
 * @property {RTCPeerConnection|null} pc
 * @property {RTCDataChannel|null} channel
 */

/**
 * @typedef {object} LinkRecord
 * @property {string} id
 * @property {"peer"|"quorum"} origin
 * @property {"offerer"|"answerer"} role
 * @property {string} label       data-channel label, for display
 * @property {LinkHolder} holder
 * @property {number} createdAt
 * @property {boolean} authenticated  far end proved an identity (quorum only)
 * @property {string} via         nominated candidate pair type, when known
 * @property {import("./relay-fallback.js").RelayFallback|null} relay
 *   the two-phase escalation supervisor, or null when the fallback is off —
 *   which is the shipped state, and means no relay will be contacted for this
 *   link under any circumstances
 * @property {RTCPeerConnection|null} pc      read through `holder`
 * @property {RTCDataChannel|null} channel    read through `holder`
 */

/** @type {Map<string, LinkRecord>} */
const links = new Map();

/** @type {Set<() => void>} */
const watchers = new Set();

/**
 * A link id is a recipe token: it is typed into `name=`, serialized back out,
 * and used as a React key. Restricting it is cheaper than discovering what a
 * space does to `serializeStep`'s bare-positional rules.
 * @param {unknown} raw
 * @param {string} op
 * @returns {string}
 */
export function normalizeLinkId(raw, op = "peer") {
  const id = String(raw ?? "").trim() || "default";
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id)) {
    // `$a` is the mistake worth naming, because everything else in this
    // language that threads a value between cells is a slot and the habit is
    // strong. A connection name is not a slot — it is not written by `out`, it
    // holds no value, and `in $a` would find nothing. Saying so beats a bare
    // charset complaint, which reads as "your name has a typo".
    // Both sigils, because a reader arriving from an older recipe still has
    // `@` in hand and the advice is identical either way.
    const sigil = /^[$@]/.test(id) ? id[0] : "";
    throw new Error(
      `${op}: "${id}" is not a usable connection name — ` +
        (sigil
          ? `write it without the ${sigil} (${op} ${id.slice(1) || "a"}). A connection name is not a slot: nothing writes it, and it holds no value to load.`
          : "letters, digits, dot, dash and underscore only, starting with a letter or digit.")
    );
  }
  return id;
}

/** Subscribe to inventory changes. Returns an unsubscribe. */
export function watchLinks(fn) {
  watchers.add(fn);
  // Returns nothing, for the reason in activity-log.js: an unsubscriber's
  // value is not meaningful, and Set.delete's boolean would leak out as one.
  return () => {
    watchers.delete(fn);
  };
}

/** Announce a change to watchers and to the page. */
export function emitLinks() {
  for (const fn of [...watchers]) {
    try {
      fn();
    } catch (_) {
      /* one broken watcher must not stop the others */
    }
  }
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent("basilisk:peer-links", { detail: { links: listLinkRows() } })
  );
}

/**
 * @param {{
 *   id: string,
 *   origin: "peer"|"quorum",
 *   role: "offerer"|"answerer",
 *   holder: LinkHolder,
 *   label?: string,
 *   authenticated?: boolean,
 *   iceServers?: RTCIceServer[],
 * }} spec
 * @returns {LinkRecord}
 */
export function registerLink(spec) {
  const id = normalizeLinkId(spec.id, spec.origin === "quorum" ? "quorum" : "peer");
  /** @type {LinkRecord} */
  const rec = {
    id,
    origin: spec.origin,
    role: spec.role,
    label: spec.label || "",
    holder: spec.holder,
    createdAt: Date.now(),
    authenticated: !!spec.authenticated,
    via: "",
    /** @type {import("./relay-fallback.js").RelayFallback|null} */
    relay: null,
    get pc() {
      return this.holder?.pc || null;
    },
    get channel() {
      return this.holder?.channel || null;
    },
  };
  links.set(id, rec);
  // `addEventListener`, never `pc.onconnectionstatechange =` — NotebookSession
  // already owns that property, and assigning it here would silently delete the
  // handler that drives the roster.
  const pc = rec.pc;
  if (pc && typeof pc.addEventListener === "function") {
    pc.addEventListener("connectionstatechange", emitLinks);
  }
  // The two-phase relay fallback (see `relay-fallback.js`). Null unless a user
  // has turned it on *and* a credential source exists, which is why registering
  // a link contacts nobody: the supervisor only reaches for a relay once this
  // connection has genuinely failed, and there is no supervisor at all by
  // default. The inventory is where it belongs because "this link failed" is a
  // fact about a link, and the inventory is what already watches for it.
  rec.relay = armRelayFallback(pc, { iceServers: spec.iceServers, onChange: emitLinks });
  emitLinks();
  return rec;
}

/**
 * @param {string} id
 * @returns {LinkRecord|null}
 */
export function getLink(id) {
  return links.get(String(id)) || null;
}

/** Every link, in registration order. @returns {LinkRecord[]} */
export function listLinks() {
  return [...links.values()];
}

/** @param {"peer"|"quorum"} origin @returns {LinkRecord[]} */
export function listLinksByOrigin(origin) {
  return listLinks().filter((l) => l.origin === origin);
}

/**
 * Update the facts the registry owns rather than reads through the holder.
 * @param {string} id
 * @param {Partial<Pick<LinkRecord, "authenticated"|"via"|"role">>} patch
 */
export function patchLink(id, patch) {
  const rec = links.get(String(id));
  if (!rec) return;
  Object.assign(rec, patch);
  emitLinks();
}

/**
 * Forget a link without touching its transport — for an owner (NotebookSession)
 * that is tearing its own connections down.
 * @param {string} id
 */
export function deregisterLink(id) {
  const rec = links.get(String(id));
  // The transport stays up — that is what distinguishes this from `closeLink`
  // — but a link nobody is holding must not still be escalating to a relay on
  // its own. Nothing would be watching the outcome.
  rec?.relay?.stop();
  if (links.delete(String(id))) emitLinks();
}

/**
 * Close a link's transport and forget it.
 *
 * Deregistering on a *deliberate* close mirrors `closeQuorumExchange`: a
 * session closed on purpose clears its roster, while one that failed keeps it
 * so the panel can show which links died. A failed link is therefore left in
 * the inventory by the state machine and removed only by this call.
 *
 * @param {string} id
 * @returns {boolean} whether a link was there to close
 */
export function closeLink(id) {
  const rec = links.get(String(id));
  if (!rec) return false;
  // Before the transport goes: the supervisor holds listeners on it, and a
  // closed connection reports `closed` rather than `failed` anyway.
  rec.relay?.stop();
  try {
    rec.channel?.close();
  } catch (_) {
    /* already gone */
  }
  try {
    rec.pc?.close();
  } catch (_) {
    /* already gone */
  }
  if (rec.holder) {
    rec.holder.channel = null;
    rec.holder.pc = null;
  }
  links.delete(rec.id);
  emitLinks();
  return true;
}

/**
 * Re-run ICE on one link — the per-row Restart in the Connections tab.
 *
 * Renegotiates in place, so the link keeps its name and its channel: what
 * failed is the transport, not the connection's identity. On a `peer` link the
 * new offer has nowhere automatic to go (there is no signalling channel — that
 * is the point of the layer), so this recovers a *recoverable* transport rather
 * than rebuilding a dead one; the honest fallback is `peer.close` and a fresh
 * exchange, which is why Close sits beside it on every row.
 *
 * @param {string} id
 * @returns {boolean} whether a restart was issued
 */
export function restartLink(id) {
  const pc = links.get(String(id))?.pc;
  // Unavailable on older engines; a link that cannot restart must not throw
  // out of a click handler.
  if (typeof pc?.restartIce !== "function") return false;
  try {
    pc.restartIce();
  } catch (_) {
    return false;
  }
  emitLinks();
  return true;
}

/**
 * Close every link of one origin. `peer.close` with no name uses this; it must
 * never reach the mesh's links, which belong to `quorum.close`.
 * @param {"peer"|"quorum"} origin
 * @returns {string[]} ids closed
 */
export function closeLinksByOrigin(origin) {
  const ids = listLinksByOrigin(origin).map((l) => l.id);
  for (const id of ids) closeLink(id);
  return ids;
}

/**
 * A link as a plain row — the shape the panel, `rtc.state` and the
 * `basilisk:peer-links` event all read.
 *
 * Pure over the record, so it is node-testable against a stub holder. Every
 * field is a fact the browser reports; nothing here is a verdict, because
 * verdicts belong to `connStateReadout` and a second copy of one is the defect
 * class this codebase has closed six times.
 *
 * @param {LinkRecord} rec
 */
export function linkRow(rec) {
  const pc = rec.pc;
  const ch = rec.channel;
  return {
    id: rec.id,
    origin: rec.origin,
    role: rec.role,
    label: rec.label,
    // `closed` rather than `new` when the connection is gone: an absent `pc` on
    // a record that still exists means it was torn down, and reporting `new`
    // would draw a dead link identically to one that has not started — the bug
    // `bfec72a` fixed one layer up.
    connectionState: pc ? String(pc.connectionState) : "closed",
    iceConnectionState: pc ? String(pc.iceConnectionState) : "closed",
    iceGatheringState: pc ? String(pc.iceGatheringState) : "complete",
    signalingState: pc ? String(pc.signalingState) : "closed",
    channelState: ch ? String(ch.readyState) : "closed",
    authenticated: !!rec.authenticated,
    via: rec.via || "",
    // Three separate facts, never collapsed into one: whether a relay is in
    // this connection's list, whether the fallback escalated to it, and
    // whether it ended up carrying the traffic. A link can escalate and then
    // connect through a reflexive candidate the restart happened to find, in
    // which case the relay allocated and forwarded nothing — reporting that as
    // "relayed" would overstate what a third party saw.
    relay: rec.relay ? rec.relay.status() : RELAY_OFF,
    relayed: relayCarriedTraffic(rec),
    createdAt: rec.createdAt,
  };
}

/** Every link as a row. */
export function listLinkRows() {
  return listLinks().map(linkRow);
}

/**
 * Test-only reset. Exported rather than reached through a back door because
 * the alternative is each suite reimplementing it against module internals.
 */
export function __resetLinks() {
  for (const rec of links.values()) rec.relay?.stop();
  links.clear();
  watchers.clear();
}
