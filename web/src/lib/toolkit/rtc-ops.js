/**
 * WebRTC primitive ops (design v2 §23a/23b/26a/26b/29a/29d/30d).
 *
 * The raw layer beneath `peer.*` and `quorum.*`: each op wraps one browser
 * WebRTC capability so ICE / DTLS / SCTP are inspectable outside a live
 * session. Running them standalone is what makes a later connectivity failure
 * explainable.
 *
 * **The diagnostics enumerate the link registry, not the quorum mesh (§57a).**
 * They used to open with `requireSession()` and walk `session.peers`, which
 * made the mesh the definition of "what is connected" — so a connection made
 * any other way was invisible to every diagnostic in the app, and a
 * hand-carried link got "no live exchange" from the five ops that exist to
 * explain a connection. `getLiveSession()` survives for the callers that
 * genuinely want the session object (the DKG transport, the roster
 * projection); it is no longer how this file answers that question.
 *
 * Main-thread only — `RTCPeerConnection` does not exist in workers.
 * @module lib/toolkit/rtc-ops
 */

import { DEFAULT_ICE_SERVERS } from "../quorum/rtc.js";
import { listLinkRows, listLinks } from "../quorum/link-registry.js";
import { getLiveSession, parseIceConfig } from "./quorum-ops.js";

/** @param {string} op */
function requireWebRtc(op) {
  if (typeof RTCPeerConnection !== "function") {
    throw new Error(`${op}: WebRTC unavailable in this context`);
  }
}

/**
 * Resolve an `ice=@slot` reference to RTCIceServer[], falling back to the
 * built-in STUN defaults.
 * @param {Record<string, unknown>} params
 * @param {{ resolveSlot?: (ref: string) => { type?: string, data?: unknown }|null }} bindings
 * @param {string} op
 * @returns {RTCIceServer[]}
 */
export function resolveIceServers(params, bindings, op) {
  const ref = String(params?.ice || "").trim();
  if (!ref) return DEFAULT_ICE_SERVERS;
  const resolve = bindings?.resolveSlot;
  if (typeof resolve !== "function") {
    throw new Error(`${op}: runtime slot resolver missing for ice=`);
  }
  const slot = resolve(ref);
  if (!slot) throw new Error(`${op}: unknown slot ${ref}`);
  // Structured `endpoint` data passes straight through; parseIceConfig still
  // accepts the legacy JSON-string form for older saved notebooks.
  return parseIceConfig(slot.data);
}

/**
 * Resolve once ICE gathering completes (or `timeout` elapses) so an emitted
 * SDP actually carries its candidates — a hand-carried offer/answer with an
 * empty candidate list is useless to the far side.
 *
 * Exported for `peer-ops.js`, which inherited the two SDP ops: the rule about
 * when a blob is carriable is the same rule wherever the blob is made, and a
 * second copy of this promise is a second thing to get wrong. (`rtc.gather`
 * originally awaited its gather promise *before* `setLocalDescription` and
 * returned zero candidates — gathering does not start until the local
 * description is set.)
 *
 * @param {RTCPeerConnection} pc
 * @param {number} timeout
 */
export function waitForGathering(pc, timeout = 5000) {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      pc.removeEventListener("icegatheringstatechange", onChange);
      resolve(undefined);
    };
    const onChange = () => {
      if (pc.iceGatheringState === "complete") done();
    };
    const timer = setTimeout(done, timeout);
    pc.addEventListener("icegatheringstatechange", onChange);
  });
}

/**
 * A typed network value. `data` stays structured (the engine renders it as
 * JSON when it hits `out`, exactly like `recipients` already does) so
 * downstream ops can read fields instead of re-parsing a string.
 * @param {import("./registry.js").IoType} type
 * @param {unknown} data
 * @param {string} filename
 * @param {Record<string, unknown>} [meta]
 */
function netValue(type, data, filename, meta = {}) {
  return { type, data, meta: { sensitive: false, filename, ...meta } };
}

/* ─────────────────────── rtc.gather (23a/26a) ─────────────────────── */

/**
 * Gather ICE candidates and report every one, typed.
 *
 * MDN lists four candidate types, not three: `host`, `prflx` (peer-reflexive,
 * only discovered mid-negotiation by trickle ICE), `srflx`, `relay` — 23a's
 * original three-type list was corrected by 26a. TCP candidates are real but
 * rare, so they carry a `protocol` field rather than being their own type.
 *
 * A missing `relay` row is the expected result of not configuring TURN, not a
 * failure — callers render it as an informational row.
 * @param {Record<string, unknown>} params
 * @param {object} bindings
 */
export async function execGatherCandidates(params, bindings) {
  requireWebRtc("rtc.gather");
  const iceServers = resolveIceServers(params, bindings, "rtc.gather");
  const timeout = Math.max(500, Number(params?.timeout) || 5000);
  const started = performance.now();
  const pc = new RTCPeerConnection({ iceServers });
  /** @type {{ type: string, address: string, port: number, protocol: string, foundation: string, priority: number, relatedAddress: string|null, ts: number }[]} */
  const candidates = [];
  try {
    pc.createDataChannel("probe");
    // Wire the listener and arm the timer BEFORE setLocalDescription —
    // gathering only starts once the local description is set, and a `host`
    // candidate can fire synchronously with it.
    const gathered = new Promise((resolve) => {
      const timer = setTimeout(resolve, timeout);
      pc.onicecandidate = (ev) => {
        const c = ev.candidate;
        if (!c) {
          // null candidate = gathering complete for this generation
          clearTimeout(timer);
          resolve(undefined);
          return;
        }
        candidates.push({
          type: c.type || "unknown",
          address: c.address || "",
          port: c.port ?? 0,
          protocol: (c.protocol || "udp").toLowerCase(),
          foundation: c.foundation || "",
          priority: c.priority ?? 0,
          relatedAddress: c.relatedAddress || null,
          ts: Math.round(performance.now() - started),
        });
      };
    });
    await pc.setLocalDescription(await pc.createOffer());
    await gathered;
  } finally {
    try {
      pc.close();
    } catch (_) {
      /* ignore */
    }
  }

  /** @type {Record<string, number>} */
  const byType = { host: 0, prflx: 0, srflx: 0, relay: 0 };
  for (const c of candidates) {
    byType[c.type] = (byType[c.type] || 0) + 1;
  }
  const notes = [];
  if (!byType.srflx) {
    notes.push("no srflx — STUN unreachable or all-host network");
  }
  if (!byType.relay) {
    notes.push("no relay — no TURN configured (informational, not a failure)");
  }
  return netValue(
    "candidate",
    {
      v: 1,
      candidates,
      byType,
      total: candidates.length,
      ms: Math.round(performance.now() - started),
      notes,
    },
    "candidates.json",
    { rtcCandidates: true, count: candidates.length }
  );
}

/* ────────────────────── rtc.check (23b/26b) ────────────────────── */

/**
 * Candidate-pair check matrix for the live exchange.
 *
 * ICE tests every local×remote pair, not the connection as a whole, so this
 * reports one row per pair with its state plus which pair was nominated —
 * and this peer's `controlling`/`controlled` role, which explains *why* ICE
 * chose the pair it did. Role is read-only: the protocol assigns it.
 */
export async function execCheckConnectivity() {
  const links = requireLinks("rtc.check");
  /** @type {{ peer: string, role: string, pairs: object[] }[]} */
  const peers = [];
  for (const link of links) {
    const fpr = link.id;
    const peer = link;
    if (!peer.pc) continue;
    const pairs = [];
    let role = "";
    /** @type {Map<string, RTCStats>} */
    const byId = new Map();
    const report = await peer.pc.getStats();
    report.forEach((s) => byId.set(s.id, s));
    report.forEach((s) => {
      if (s.type !== "candidate-pair") return;
      const local = byId.get(s.localCandidateId);
      const remote = byId.get(s.remoteCandidateId);
      pairs.push({
        local: describeCandidate(local),
        remote: describeCandidate(remote),
        // ICE spec states; `succeeded` pairs that were never nominated are the
        // "skipped" rows the matrix dims rather than hides.
        state: s.state || "waiting",
        nominated: !!s.nominated,
        rttMs: s.currentRoundTripTime != null
          ? Math.round(s.currentRoundTripTime * 1000)
          : null,
        bytesSent: s.bytesSent ?? 0,
        bytesReceived: s.bytesReceived ?? 0,
      });
    });
    try {
      // RTCIceTransport.role (§26b) — informational only. Chromium leaves this
      // `null` even on a fully connected transport, so in practice this is
      // usually blank; the UI shows nothing rather than guessing a role.
      const transport = peer.pc.sctp?.transport?.iceTransport;
      role = transport?.role && transport.role !== "unknown" ? transport.role : "";
    } catch (_) {
      /* not connected yet — report nothing rather than guessing */
    }
    peers.push({
      peer: fpr,
      origin: link.origin,
      role,
      pairs,
      nominatedCount: pairs.filter((p) => p.nominated).length,
    });
  }
  const allFailed =
    peers.length > 0 &&
    peers.every((p) => p.pairs.length > 0 && p.pairs.every((x) => x.state === "failed"));
  return netValue(
    "stats",
    {
      v: 1,
      peers,
      allFailed,
      note: allFailed
        ? "every candidate pair failed — a TURN relay is usually the fix (rtc.ice turn=)"
        : "",
    },
    "candidate-pairs.json",
    { rtcPairs: true, allFailed, statsKind: "candidate-pairs" }
  );
}

/**
 * @param {RTCStats|undefined} c
 * Note: Chrome reports `address`/`ip` as empty strings on *local* candidate
 * stats (mDNS privacy redaction) even while connected — so the matrix labels
 * pairs `type:port`, which is always populated, and leaves `address` blank
 * rather than inventing one.
 */
function describeCandidate(c) {
  if (!c) return { type: "unknown", label: "unknown", address: "", port: 0, protocol: "" };
  const type = c.candidateType || "unknown";
  const port = c.port ?? 0;
  return {
    type,
    label: `${type}:${port}`,
    address: c.address || c.ip || "",
    port,
    protocol: (c.protocol || "").toLowerCase(),
  };
}

/**
 * Every live link, or a refusal naming both ways to get one (§57a).
 *
 * The refusal is the reason this helper replaced `requireSession`. "No live
 * exchange — run quorum.offer or quorum.join first" was accurate when the mesh
 * was the only thing that could be connected, and became a false instruction
 * the moment `peer.offer` could produce a connection these ops can read. A
 * diagnostic that names the wrong op is worse than one that says nothing.
 *
 * @param {string} op
 */
function requireLinks(op) {
  const links = listLinks().filter((l) => l.pc);
  if (!links.length) {
    throw new Error(
      `${op}: no live connection — open one with peer.offer / peer.answer, or a mesh with quorum.offer / quorum.join`
    );
  }
  return links;
}

/* ───────────────────────── rtc.certificate (29a) ───────────────────────── */

/**
 * Generate a DTLS identity. Mirrors `genkey`'s shape: a source op emitting a
 * handle plus its fingerprint — the fingerprint the remote peer actually sees.
 * @param {Record<string, unknown>} params
 */
export async function execCertificate(params) {
  requireWebRtc("rtc.certificate");
  const alg = String(params?.alg || "ecdsa").toLowerCase();
  const algorithm =
    alg === "rsa"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        }
      : { name: "ECDSA", namedCurve: "P-256" };
  const cert = await RTCPeerConnection.generateCertificate(algorithm);
  const prints = (cert.getFingerprints?.() || []).map((f) => ({
    algorithm: f.algorithm,
    value: f.value,
  }));
  return netValue(
    "certificate",
    {
      v: 1,
      algorithm: alg === "rsa" ? "RSASSA-PKCS1-v1_5/2048" : "ECDSA/P-256",
      expires: cert.expires ? new Date(cert.expires).toISOString() : null,
      fingerprints: prints,
      note: "ephemeral unless pinned — quorum.offer mints its own throwaway certificate when this op isn't used",
    },
    "dtls-certificate.json",
    { rtcCertificate: true }
  );
}

/* ──────────────────── SDP: moved to peer-ops (§55c) ──────────────────── */

/*
 * `rtc.offer` and `rtc.answer` used to live here. They are now `peer.offer` and
 * `peer.answer` in `peer-ops.js`, retired and migrated rather than aliased.
 *
 * The reason is not tidiness. Both closed their own `RTCPeerConnection` in a
 * `finally` before returning, so the ICE ufrag/pwd and DTLS fingerprint in the
 * SDP named a transport that had already been torn down — two shipped templates
 * described a hand-carried flow that could not complete. Making the connection
 * outlive the op means something has to own it, and an op that allocates into a
 * registry is not "one browser capability, inspectable standalone", which is
 * what this module's header promises. So the layer boundary moved with them.
 *
 * `sdpRole` and `waitForGathering` stay here and are imported by `peer-ops`:
 * which half a blob is, and when a blob is carriable, are facts about SDP
 * rather than about the manager.
 */

/**
 * Which half of the offer/answer exchange an SDP blob is, by its DTLS role.
 *
 * Pure, and exported, for the same reason `offerCollisionAction` is: the rule
 * is the interesting part and it should be assertable without standing up an
 * `RTCPeerConnection`.
 *
 * RFC 8842 §5.1 (and RFC 5763 before it) require an offerer to advertise
 * `a=setup:actpass` — it does not yet know which side will be the DTLS client,
 * so it offers both. Only an *answer* commits to `active` or `passive`. So an
 * SDP whose every `a=setup:` line has already picked a side is an answer, and
 * nothing else is: that is the one field in the blob that distinguishes them.
 *
 * Absent an `a=setup:` line there is nothing to go on, and the honest answer is
 * `"unknown"` rather than a guess — a non-browser stack's offer must still be
 * answerable, so only a *positive* identification refuses.
 *
 * @param {string} sdp
 * @returns {"offer"|"answer"|"unknown"}
 */
export function sdpRole(sdp) {
  const roles = String(sdp).match(/^a=setup:(\S+)/gm) || [];
  if (!roles.length) return "unknown";
  if (roles.every((l) => /actpass/.test(l))) return "offer";
  if (roles.every((l) => /active|passive|holdconn/.test(l))) return "answer";
  return "unknown";
}

/* ─────────────────────── rtc.state (30d) ─────────────────────── */

/**
 * Observe-only state snapshot — never bindable as a crypto op's input.
 *
 * Reads the whole inventory (§57a), so a hand-carried `peer.*` link gets the
 * same verdict, three-stage track and terminal outcome the mesh's peers get,
 * with no new UI: `connStateReadout` keys off `connectionState`, and a link is
 * a link.
 */
export function execConnectionState() {
  const links = requireLinks("rtc.state");
  const peers = listLinkRows()
    .filter((r) => links.some((l) => l.id === r.id))
    .map((r) => ({
      ...r,
      // `peer` is the field name every existing consumer indexes on — the
      // `connstate` renderer, the catalog fixtures, the e2e assertions. The row
      // carries `id` too; this is the alias, not a second fact.
      peer: r.id,
      verified: r.authenticated,
    }));
  const session = getLiveSession();
  return netValue(
    "connstate",
    { v: 1, room: session?.roomId || "", peers },
    "connection-state.json",
    { rtcConnState: true }
  );
}

/* ─────────────────────── rtc.stats (30d) ─────────────────────── */

/** Back-pressure + counters: is `quorum.send` queueing behind a slow link? */
export async function execDataChannelStats() {
  const links = requireLinks("rtc.stats");
  const peers = [];
  for (const peer of links) {
    const ch = peer.channel;
    /** @type {Record<string, unknown>} */
    const row = {
      peer: peer.id,
      origin: peer.origin,
      readyState: ch?.readyState || "closed",
      bufferedAmount: ch?.bufferedAmount ?? 0,
      bufferedAmountLowThreshold: ch?.bufferedAmountLowThreshold ?? 0,
      ordered: ch?.ordered ?? null,
      maxRetransmits: ch?.maxRetransmits ?? null,
      maxPacketLifeTime: ch?.maxPacketLifeTime ?? null,
      messagesSent: 0,
      messagesReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
    };
    if (peer.pc) {
      const report = await peer.pc.getStats();
      report.forEach((s) => {
        if (s.type !== "data-channel") return;
        row.messagesSent = s.messagesSent ?? row.messagesSent;
        row.messagesReceived = s.messagesReceived ?? row.messagesReceived;
        row.bytesSent = s.bytesSent ?? row.bytesSent;
        row.bytesReceived = s.bytesReceived ?? row.bytesReceived;
      });
    }
    row.backPressured =
      Number(row.bufferedAmount) > Number(row.bufferedAmountLowThreshold || 65535);
    peers.push(row);
  }
  return netValue("stats", { v: 1, peers }, "datachannel-stats.json", {
    rtcChannelStats: true,
    statsKind: "data-channel",
  });
}

/* ───────────────────────── rtc.restart ───────────────────────── */

/**
 * ICE restart as a pipeline primitive — the same recovery the Connections
 * panel button performs, chainable: `rtc.restart | out @state` after a
 * `stun.check` that came back degraded, or scripted into a reconnect recipe.
 * Renegotiates in place: room, invite, and roster survive because the session
 * never closed — only its transport did. The new offers ride
 * onnegotiationneeded (perfect negotiation), channel-first where links are
 * still live, the mailbox where they are not.
 */
export async function execRtcRestart() {
  const links = requireLinks("rtc.restart");
  let restarted = 0;
  for (const peer of links) {
    if (typeof peer.pc?.restartIce !== "function") continue;
    try {
      peer.pc.restartIce();
      restarted += 1;
    } catch (_) {
      /* peer already torn down — nothing to restart */
    }
  }
  const state = /** @type {{ data: Record<string, unknown> }} */ (
    execConnectionState()
  );
  return netValue(
    "connstate",
    { ...state.data, restarted },
    "ice-restart.json",
    { rtcConnState: true, restarted }
  );
}

/* ───────────────────────── rtc.quality (29d) ───────────────────────── */

/**
 * Live quality numbers — RTT and throughput — per connected peer.
 *
 * **Not loss.** This used to report a `packetLossPct`, and it was never a
 * measurement. It read `packetsLost` off a `remote-inbound-rtp` stat and
 * divided it by `packetsSent + packetsReceived` from the nominated
 * `candidate-pair`, which is wrong twice over:
 *
 *  - `remote-inbound-rtp` does not exist on this connection, or any connection
 *    this app makes. Measured against a live peer in Chromium, the complete
 *    set of stat types on a data-channel-only connection is `candidate-pair`,
 *    `certificate`, `data-channel`, `local-candidate`, `peer-connection`,
 *    `remote-candidate` and `transport`. The quorum transport is SCTP over
 *    DTLS and never carries media, so there is no RTP to lose. `packetsLost`
 *    was therefore always its initial 0.
 *  - The two counters are different populations anyway. `packetsLost` would
 *    count RTP packets; the `candidate-pair` counters count STUN, DTLS and
 *    SCTP packets on the ICE path. Even with media present, one over the other
 *    is not a loss rate.
 *
 * So the figure was structurally 0, and `0% loss` is a claim — it reads as
 * "measured, and none was lost" on the one panel someone opens when a call is
 * going badly. `null` is the honest answer and the tile says so in words. The
 * RTP branch is gone rather than left guarding a stat type that cannot appear.
 */
export async function execStatsReport() {
  const links = requireLinks("rtc.quality");
  const peers = [];
  for (const peer of links) {
    const fpr = peer.id;
    if (!peer.pc) continue;
    let rttMs = null;
    let bytesSent = 0;
    let bytesReceived = 0;
    let packetsSent = 0;
    let packetsReceived = 0;
    const report = await peer.pc.getStats();
    report.forEach((s) => {
      if (s.type === "candidate-pair" && s.nominated) {
        if (s.currentRoundTripTime != null) {
          rttMs = Math.round(s.currentRoundTripTime * 1000);
        }
        bytesSent = s.bytesSent ?? bytesSent;
        bytesReceived = s.bytesReceived ?? bytesReceived;
        packetsSent = s.packetsSent ?? packetsSent;
        packetsReceived = s.packetsReceived ?? packetsReceived;
      }
    });
    peers.push({
      peer: fpr,
      origin: peer.origin,
      rttMs,
      bytesSent,
      bytesReceived,
      // ICE-path packets, which is what these are. Named as counters rather
      // than folded into a rate, because the rate they would imply is one
      // nothing here can compute.
      packetsSent,
      packetsReceived,
      packetLossPct: null,
    });
  }
  return netValue(
    "stats",
    {
      v: 1,
      peers,
      // Carried in the value, so a downloaded `stats-report.json` explains its
      // own null instead of looking like a field that failed to serialize.
      notes: [
        "packet loss is not measured: this transport is SCTP data channels, so no RTP statistics exist to lose packets from",
      ],
    },
    "stats-report.json",
    { rtcStats: true, statsKind: "quality" }
  );
}
