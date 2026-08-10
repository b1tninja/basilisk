/**
 * The peer connection manager (§55).
 *
 * The layer between `rtc.*` (raw, one browser capability per op, inspection)
 * and `quorum.*` (an identity-bound mesh over a signalling relay). These ops
 * get two browsers connected with no OpenPGP audience, no derived room and no
 * relay — you carry one blob across and answer it.
 *
 * **What makes this different from the ops it replaces.** `rtc.offer` closed
 * its own `RTCPeerConnection` in a `finally` before returning, so its SDP named
 * a transport that no longer existed: the ICE ufrag/pwd is the credential the
 * far end puts in its STUN binding requests and the fingerprint is the
 * certificate it pins during DTLS, and all three are meaningless once the
 * object is gone. Two shipped templates described that flow anyway. Here the
 * connection *survives the op*, held in the link registry under a name, which
 * is the whole point and also the reason the registry has to exist (§54b).
 *
 * **What these links are not.** DTLS encrypts the wire, but nothing
 * authenticates the far end — whoever received the offer is on the other side.
 * That is a real difference from `quorum.*`, whose channels carry a pairwise
 * key derived over a transcript binding both DTLS fingerprints, and it is why
 * `quorum.send`/`quorum.recv` do not reach these links: they encrypt under that
 * pairwise key, and a link has none. `peer.send`/`peer.recv` are the verbs for
 * a channel with no exchange behind it, and their name is the warning.
 *
 * Main-thread only — `RTCPeerConnection` does not exist in workers.
 * @module lib/toolkit/peer-ops
 */

import {
  closeLink,
  closeLinksByOrigin,
  getLink,
  linkRow,
  listLinkRows,
  listLinksByOrigin,
  normalizeLinkId,
  patchLink,
  registerLink,
} from "../webrtc/link-registry.js";
import { selectedCandidateType } from "../webrtc/candidates.js";
import { connStateReadout } from "./artifact-readouts.js";
import { resolveIceServers, sdpRole, waitForGathering } from "./rtc-ops.js";

/** @param {string} op */
function requireWebRtc(op) {
  if (typeof RTCPeerConnection !== "function") {
    throw new Error(`${op}: WebRTC unavailable in this context`);
  }
}

/**
 * The link a `name=` refers to, or a refusal that names what is actually open.
 *
 * Listing the open links in the error is the difference between "unknown
 * connection b" and a message a user can act on — the usual cause is a typo or
 * a cell run out of order, and both are obvious the moment the real names are
 * on screen.
 *
 * @param {unknown} raw
 * @param {string} op
 */
function requireLink(raw, op) {
  const id = normalizeLinkId(raw, op);
  const link = getLink(id);
  if (!link) {
    const open = listLinksByOrigin("peer").map((l) => l.id);
    throw new Error(
      `${op}: no connection named "${id}"` +
        (open.length
          ? ` — open connections: ${open.join(", ")}`
          : " — nothing is open. Run peer.offer (or peer.answer) first.")
    );
  }
  return link;
}

/** @param {unknown} raw @param {string} op */
function refuseIfOpen(raw, op) {
  const id = normalizeLinkId(raw, op);
  if (getLink(id)) {
    throw new Error(
      `${op}: a connection named "${id}" is already open — peer.close ${id} first, or use a different name=.`
    );
  }
  return id;
}

/**
 * SDP out of a pipeline value, however it arrived.
 * @param {{ type?: string, data?: unknown, meta?: Record<string, unknown> }} value
 * @param {string} op
 */
function sdpFromValue(value, op) {
  const sdp =
    value?.type === "sdp" || value?.type === "text"
      ? String(value.data)
      : new TextDecoder().decode(/** @type {Uint8Array} */ (value?.data));
  if (!/^v=0/m.test(sdp)) {
    throw new Error(`${op} expects SDP as pipeline text`);
  }
  return sdp;
}

/**
 * A typed network value, matching `rtc-ops`' shape so both layers' artifacts
 * reach the same tiles.
 * @param {string} type
 * @param {unknown} data
 * @param {string} filename
 * @param {Record<string, unknown>} [meta]
 */
function netValue(type, data, filename, meta = {}) {
  return { type, data, meta: { sensitive: false, filename, ...meta } };
}

/** The inventory as a `connstate` value — what `peer.accept`/`peer.close` report. */
function inventoryValue(filename, meta = {}) {
  const rows = listLinkRows();
  return netValue(
    "connstate",
    { v: 1, room: "", peers: rows.map((r) => ({ ...r, peer: r.id })) },
    filename,
    { rtcConnState: true, ...meta }
  );
}

/**
 * Wire a data channel into a link's holder and inbox.
 * @param {{ pc: RTCPeerConnection|null, channel: RTCDataChannel|null, inbox: object[], waiters: Function[] }} holder
 * @param {RTCDataChannel} channel
 * @param {string} id
 */
function wireChannel(holder, channel, id) {
  holder.channel = channel;
  channel.addEventListener("message", (ev) => {
    const msg = {
      from: id,
      text: typeof ev.data === "string" ? ev.data : "",
      ts: Date.now(),
    };
    // A waiter that is already parked takes it; otherwise it queues. Same
    // arrangement as the quorum inbox, and for the same reason: `peer.recv`
    // must not lose a message that arrives between two reads.
    const waiter = holder.waiters.shift();
    if (waiter) waiter(msg);
    else holder.inbox.push(msg);
  });
}

/** A fresh holder for a managed link. */
function newHolder(pc) {
  return {
    pc,
    /** @type {RTCDataChannel|null} */
    channel: null,
    /** @type {{ from: string, text: string, ts: number }[]} */
    inbox: [],
    /** @type {((m: object|null) => void)[]} */
    waiters: [],
  };
}

/* ───────────────────────────── peer.offer ───────────────────────────── */

/**
 * Mint a managed link and emit its offer. **The connection stays live**, which
 * is the entire difference from the op this replaces.
 *
 * Gathering is awaited before the SDP is read, because the blob is carried by a
 * human: a trickle-ICE offer with no candidate lines is useless to whoever
 * receives it, and there is no signalling channel here to trickle the rest
 * over. That is also why `peer.*` has no trickle mode at all — if you have a
 * channel to trickle on, you want `quorum.*`.
 */
export async function execPeerOffer(params, bindings) {
  requireWebRtc("peer.offer");
  const id = refuseIfOpen(params?.name, "peer.offer");
  const iceServers = resolveIceServers(params, bindings, "peer.offer");
  const label = String(params?.label || "basilisk");
  const timeout = Math.max(500, Number(params?.timeout) || 5000);
  const pc = new RTCPeerConnection({ iceServers });
  const holder = newHolder(pc);
  try {
    wireChannel(holder, pc.createDataChannel(label, { ordered: true }), id);
    await pc.setLocalDescription(await pc.createOffer());
    await waitForGathering(pc, timeout);
  } catch (err) {
    // A half-built link must not be left in the inventory: it was never
    // registered, so closing the transport here is the whole cleanup.
    try {
      pc.close();
    } catch (_) {
      /* ignore */
    }
    throw err;
  }
  registerLink({ id, origin: "peer", role: "offerer", holder, label, iceServers });
  return {
    type: "sdp",
    data: String(pc.localDescription?.sdp || ""),
    meta: {
      sensitive: false,
      filename: `${id}-offer.sdp`,
      rtcSdp: "offer",
      which: "offer",
      link: id,
      linkOrigin: "peer",
    },
  };
}

/* ───────────────────────────── peer.answer ──────────────────────────── */

/** Refusal text for `peer.answer` handed the wrong half. Asserted by tests. */
export const ANSWER_NOT_AN_OFFER =
  "peer.answer expects the remote *offer*, but this SDP is already an answer " +
  "(a=setup:active/passive). Answering an answer produces a description no " +
  "peer asked for. If this is the answer to an offer you made, pipe it into " +
  "peer.accept instead.";

/**
 * Answer a remote offer, keeping the resulting link.
 * @param {{ type?: string, data?: unknown, meta?: Record<string, unknown> }} value
 */
export async function execPeerAnswer(value, params, bindings) {
  requireWebRtc("peer.answer");
  const sdp = sdpFromValue(value, "peer.answer");
  // The blob says which half it is; read it and refuse. An answer and an offer
  // are the same grammar, so `setRemoteDescription` accepts either as
  // `{ type: "offer" }` without complaint — measured, not assumed.
  if (value?.meta?.which === "answer" || sdpRole(sdp) === "answer") {
    throw new Error(ANSWER_NOT_AN_OFFER);
  }
  const id = refuseIfOpen(params?.name, "peer.answer");
  const iceServers = resolveIceServers(params, bindings, "peer.answer");
  const timeout = Math.max(500, Number(params?.timeout) || 5000);
  const pc = new RTCPeerConnection({ iceServers });
  const holder = newHolder(pc);
  try {
    pc.addEventListener("datachannel", (ev) => {
      // The label is the offerer's; the answerer only learns it here. Recording
      // it means both ends' rows say the same thing about one channel — an
      // empty label on the answering side is a fact the browser did report and
      // this side simply threw away.
      const rec = getLink(id);
      if (rec) rec.label = ev.channel.label || "";
      wireChannel(holder, ev.channel, id);
    });
    await pc.setRemoteDescription({ type: "offer", sdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await waitForGathering(pc, timeout);
  } catch (err) {
    try {
      pc.close();
    } catch (_) {
      /* ignore */
    }
    throw err;
  }
  registerLink({ id, origin: "peer", role: "answerer", holder, iceServers });
  return {
    type: "sdp",
    data: String(pc.localDescription?.sdp || ""),
    meta: {
      sensitive: false,
      filename: `${id}-answer.sdp`,
      rtcSdp: "answer",
      which: "answer",
      link: id,
      linkOrigin: "peer",
    },
  };
}

/* ───────────────────────────── peer.accept ──────────────────────────── */

/** Refusal text for `peer.accept` handed an offer. Asserted by tests. */
export const ACCEPT_NOT_AN_ANSWER =
  "peer.accept expects the remote *answer* to an offer this connection made, " +
  "but this SDP is an offer (a=setup:actpass). To answer someone else's offer " +
  "and open a second connection, use peer.answer.";

/**
 * Apply a remote answer to a named link.
 *
 * Signalling only: it does not wait for ICE. Folding the wait in here was
 * considered and rejected (§55e) — "this SDP is not an answer" and "ICE checked
 * every candidate pair and none worked" have different causes, different fixes
 * and different next steps, and one op would have to pick one sentence for
 * both. `peer.wait` owns the second question.
 *
 * @param {{ type?: string, data?: unknown, meta?: Record<string, unknown> }} value
 */
export async function execPeerAccept(value, params) {
  const sdp = sdpFromValue(value, "peer.accept");
  if (value?.meta?.which === "offer" || sdpRole(sdp) === "offer") {
    throw new Error(ACCEPT_NOT_AN_ANSWER);
  }
  const link = requireLink(params?.name, "peer.accept");
  const pc = link.pc;
  if (!pc) {
    throw new Error(
      `peer.accept: the connection "${link.id}" has already been torn down.`
    );
  }
  if (pc.signalingState !== "have-local-offer") {
    // Stale by construction, and worth naming rather than letting Chromium's
    // own wording surface: the usual cause is accepting twice, and "Called in
    // wrong state" says nothing about which cell to stop re-running.
    throw new Error(
      `peer.accept: "${link.id}" is not waiting for an answer (signalling state ${pc.signalingState}). ` +
        (pc.signalingState === "stable"
          ? "An answer has already been applied to it — this connection is negotiated."
          : "Only a connection that made an offer can accept one.")
    );
  }
  await pc.setRemoteDescription({ type: "answer", sdp });
  return inventoryValue(`${link.id}-accepted.json`, { link: link.id });
}

/* ────────────────────────────── peer.wait ───────────────────────────── */

/**
 * Block until a link is connected and its channel open — the ICE outcome, as
 * its own step.
 *
 * Emits the `channel` **handle**: this is the moment a live channel exists to
 * hand out, which is why the type belongs here rather than on `peer.offer`,
 * whose postcondition is "an offer exists and nothing is connected yet" (§56).
 *
 * Its refusal is `connStateReadout`'s sentence for whatever state the link
 * reached, so the error a recipe sees and the verdict the panel draws are the
 * same words from the same function.
 */
export async function execPeerWait(params) {
  const link = requireLink(params?.name, "peer.wait");
  const wait = Math.max(1000, Number(params?.wait) || 60000);
  const deadline = Date.now() + wait;

  for (;;) {
    const row = linkRow(link);
    if (row.connectionState === "connected" && row.channelState === "open") break;
    if (
      row.connectionState === "failed" ||
      row.connectionState === "closed" ||
      !link.pc
    ) {
      const read = connStateReadout(row);
      throw new Error(`peer.wait ${link.id}: ${read.headline}. ${read.why}` +
        (read.next ? ` ${read.next}` : ""));
    }
    if (Date.now() > deadline) {
      const read = connStateReadout(row);
      throw new Error(
        `peer.wait ${link.id}: still ${row.connectionState} after ${Math.round(wait / 1000)}s ` +
          `(channel ${row.channelState}). ${read.why}` +
          (read.next ? ` ${read.next}` : "")
      );
    }
    await new Promise((r) => setTimeout(r, 100));
  }

  // The nominated pair is only knowable once ICE has settled, which is exactly
  // now — so this is where `via` gets filled in for a direct link. `quorum-ops`
  // does the same enrichment for the mesh's rows, through the same function, so
  // "host" / "srflx" / "relay" means one thing across the whole inventory.
  patchLink(link.id, { via: await selectedCandidateType(link.pc) });

  const row = linkRow(link);
  return {
    // HANDLE: a live RTCDataChannel, meaningful only inside this run. The type
    // system refuses it as any computing op's input; what rides in `data` is a
    // summary for the tile, not the object.
    type: "channel",
    data: {
      v: 1,
      link: link.id,
      origin: link.origin,
      label: link.label,
      ordered: link.channel?.ordered ?? true,
      state: row.channelState,
      via: row.via,
    },
    meta: {
      sensitive: false,
      filename: `${link.id}-channel.json`,
      peerLink: link.id,
      linkOrigin: link.origin,
    },
  };
}

/* ────────────────────────── peer.send / peer.recv ───────────────────── */

/**
 * Write pipeline text to a link's channel, passing the value through.
 *
 * Not `quorum.send`. That op writes through `NotebookSession.sendChat`, which
 * encrypts under the pairwise session key before touching the channel; a
 * managed link has no such key. Sharing one verb between the two would either
 * throw somewhere confusing or — if anyone "fixed" the throw — put plaintext on
 * an unauthenticated channel under an op whose entire history is encrypted
 * traffic. The namespaces say which is which: `quorum.*` where a session key
 * exists, `peer.*` where only DTLS does.
 *
 * @param {{ type?: string, data?: unknown, meta?: Record<string, unknown> }} value
 */
export async function execPeerSend(value, params) {
  const link = requireLink(params?.name, "peer.send");
  const ch = link.channel;
  if (!ch || ch.readyState !== "open") {
    throw new Error(
      `peer.send: the channel on "${link.id}" is ${ch?.readyState || "absent"}, not open — ` +
        `run peer.wait ${link.id} first, which blocks until it is.`
    );
  }
  const text =
    value?.type === "text" || value?.type === "sdp"
      ? String(value.data)
      : new TextDecoder().decode(/** @type {Uint8Array} */ (value?.data));
  ch.send(text);
  return value;
}

/**
 * Read from a link's inbox. `count` picks the shape, exactly as `quorum.recv` does.
 *
 * Only a link this module opened has an inbox: `wireChannel` is what installs
 * the `message` listener that fills one. A **quorum** link is in the same
 * inventory and has no inbox at all — its traffic is decrypted under the
 * pairwise session key and delivered through the session's own `onChat`. So
 * this refuses by name rather than reading `undefined.length`, and sends the
 * reader to the op that can actually read that channel.
 */
export async function execPeerRecv(params) {
  const link = requireLink(params?.name, "peer.recv");
  const holder = /** @type {any} */ (link.holder);
  if (!Array.isArray(holder?.inbox) || !Array.isArray(holder?.waiters)) {
    throw new Error(
      `peer.recv: "${link.id}" is a ${link.origin} connection and does not deliver through peer.recv` +
        (link.origin === "quorum"
          ? " — its traffic is decrypted under the exchange's pairwise session key. Use quorum.recv."
          : ".")
    );
  }
  const wait = Math.max(1000, Number(params?.wait) || 60000);
  const deadline = Date.now() + wait;

  const countRaw = String(params?.count ?? "1").trim().toLowerCase();
  const drain = countRaw === "all";
  const want = drain ? Infinity : Math.max(1, Number(countRaw) || 1);
  const single = !drain && want === 1;

  /** @type {{ from: string, text: string, ts: number }[]} */
  const got = [];
  for (;;) {
    while (holder.inbox.length && got.length < want) got.push(holder.inbox.shift());
    if (got.length >= want || (drain && got.length)) break;

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      if (got.length) break;
      throw new Error(
        `peer.recv ${link.id}: no message within ${Math.round(wait / 1000)}s`
      );
    }
    const msg = await new Promise((resolve) => {
      // Removed by identity, so a timed-out read cannot leave a settled waiter
      // in the queue for the next message to be handed to and dropped — the
      // defect `quorum.recv` carried until 45e4ca7.
      const waiter = (m) => {
        clearTimeout(timer);
        resolve(m);
      };
      const timer = setTimeout(() => {
        const i = holder.waiters.indexOf(waiter);
        if (i >= 0) holder.waiters.splice(i, 1);
        resolve(null);
      }, Math.min(remaining, 250));
      holder.waiters.push(waiter);
    });
    if (msg) got.push(/** @type {any} */ (msg));
    else if (!getLink(link.id)) {
      throw new Error(`peer.recv ${link.id}: the connection was closed while waiting`);
    }
  }

  if (single) {
    return {
      type: "text",
      data: got[0].text,
      meta: { sensitive: true, from: got[0].from, ts: got[0].ts, link: link.id },
    };
  }
  const parts = got.map((m) => ({
    type: "text",
    data: m.text,
    meta: { sensitive: true, from: m.from, ts: m.ts },
  }));
  return {
    type: "bundle",
    data: { parts, count: parts.length },
    meta: { kind: "recv", count: parts.length, sensitive: true, link: link.id },
  };
}

/* ───────────────────────────── peer.close ───────────────────────────── */

/**
 * Close one managed link, or every one of them.
 *
 * Bounded to `peer`-origin links even when closing everything: the mesh's links
 * are in the same inventory and belong to `quorum.close`, which also has
 * session keys to zeroize and a signalling poll to stop. Tearing them down from
 * here would leave `NotebookSession` believing it still had a transport.
 */
export function execPeerClose(params) {
  const raw = String(params?.name ?? "").trim();
  if (!raw || raw === "all") {
    const ids = closeLinksByOrigin("peer");
    return inventoryValue("peer-closed.json", { closed: ids.length, closedIds: ids });
  }
  const link = requireLink(raw, "peer.close");
  closeLink(link.id);
  return inventoryValue(`${link.id}-closed.json`, { closed: 1, closedIds: [link.id] });
}
