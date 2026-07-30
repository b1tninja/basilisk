/**
 * WebRTC primitive ops (design v2 §23a/23b/26a/26b/29a/29d/30d).
 *
 * The raw layer beneath `quorum.*`: each op wraps one browser WebRTC
 * capability so ICE / DTLS / SCTP are inspectable outside a live session.
 * `quorum.offer`/`join` compose these internally; running them standalone is
 * what makes a later connectivity failure explainable.
 *
 * Main-thread only — `RTCPeerConnection` does not exist in workers.
 * @module lib/toolkit/rtc-ops
 */

import { DEFAULT_ICE_SERVERS } from "../quorum/rtc.js";
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
 * @param {RTCPeerConnection} pc
 * @param {number} timeout
 */
function waitForGathering(pc, timeout = 5000) {
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
  const session = requireSession("rtc.check");
  /** @type {{ peer: string, role: string, pairs: object[] }[]} */
  const peers = [];
  for (const [fpr, peer] of session.peers) {
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
    peers.push({ peer: fpr, role, pairs, nominatedCount: pairs.filter((p) => p.nominated).length });
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

/** @param {string} op */
function requireSession(op) {
  const session = getLiveSession();
  if (!session) {
    throw new Error(`${op}: no live exchange — run quorum.offer or quorum.join first`);
  }
  return session;
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

/* ──────────────────── rtc.offer / rtc.answer (30d) ──────────────────── */

/**
 * Raw SDP offer — the escape hatch below `quorum.offer`. Signals nothing;
 * the caller carries the blob however they like.
 */
export async function execCreateOffer(params, bindings) {
  requireWebRtc("rtc.offer");
  const iceServers = resolveIceServers(params, bindings, "rtc.offer");
  const label = String(params?.label || "basilisk");
  const pc = new RTCPeerConnection({ iceServers });
  try {
    pc.createDataChannel(label);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await waitForGathering(pc);
    return {
      type: "sdp",
      data: String(pc.localDescription?.sdp || offer.sdp || ""),
      meta: { sensitive: false, filename: "offer.sdp", rtcSdp: "offer", which: "offer" },
    };
  } finally {
    try {
      pc.close();
    } catch (_) {
      /* ignore */
    }
  }
}

/**
 * Raw SDP answer for a piped offer.
 * @param {{ type: string, data: unknown }} value
 */
export async function execCreateAnswer(value, params, bindings) {
  requireWebRtc("rtc.answer");
  const sdp =
    value?.type === "sdp" || value?.type === "text"
      ? String(value.data)
      : new TextDecoder().decode(/** @type {Uint8Array} */ (value?.data));
  if (!/^v=0/m.test(sdp)) {
    throw new Error("rtc.answer expects an SDP offer as pipeline text");
  }
  const iceServers = resolveIceServers(params, bindings, "rtc.answer");
  const pc = new RTCPeerConnection({ iceServers });
  try {
    await pc.setRemoteDescription({ type: "offer", sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await waitForGathering(pc);
    return {
      type: "sdp",
      data: String(pc.localDescription?.sdp || answer.sdp || ""),
      meta: { sensitive: false, filename: "answer.sdp", rtcSdp: "answer", which: "answer" },
    };
  } finally {
    try {
      pc.close();
    } catch (_) {
      /* ignore */
    }
  }
}

/* ─────────────────────── rtc.state (30d) ─────────────────────── */

/** Observe-only state snapshot — never bindable as a crypto op's input. */
export function execConnectionState() {
  const session = requireSession("rtc.state");
  const peers = [];
  for (const [fpr, peer] of session.peers) {
    peers.push({
      peer: fpr,
      connectionState: peer.pc?.connectionState || "closed",
      iceConnectionState: peer.pc?.iceConnectionState || "closed",
      iceGatheringState: peer.pc?.iceGatheringState || "complete",
      signalingState: peer.pc?.signalingState || "closed",
      channelState: peer.channel?.readyState || "closed",
      // Basilisk's own overlay on top of the browser states.
      verified: !!peer.kcVerified,
      status: peer.status,
    });
  }
  return netValue("connstate", { v: 1, room: session.roomId, peers }, "connection-state.json", {
    rtcConnState: true,
  });
}

/* ─────────────────────── rtc.stats (30d) ─────────────────────── */

/** Back-pressure + counters: is `rtc.send` queueing behind a slow link? */
export async function execDataChannelStats() {
  const session = requireSession("rtc.stats");
  const peers = [];
  for (const [fpr, peer] of session.peers) {
    const ch = peer.channel;
    /** @type {Record<string, unknown>} */
    const row = {
      peer: fpr,
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
  const session = requireSession("rtc.restart");
  let restarted = 0;
  for (const [, peer] of session.peers) {
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

/** Live quality numbers — RTT, throughput, loss — per connected peer. */
export async function execStatsReport() {
  const session = requireSession("rtc.quality");
  const peers = [];
  for (const [fpr, peer] of session.peers) {
    if (!peer.pc) continue;
    let rttMs = null;
    let bytesSent = 0;
    let bytesReceived = 0;
    let packetsSent = 0;
    let packetsReceived = 0;
    let packetsLost = 0;
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
      if (s.type === "remote-inbound-rtp" && s.packetsLost != null) {
        packetsLost = s.packetsLost;
      }
    });
    const totalPackets = packetsSent + packetsReceived;
    peers.push({
      peer: fpr,
      rttMs,
      bytesSent,
      bytesReceived,
      packetsSent,
      packetsReceived,
      packetLossPct:
        totalPackets > 0 ? Number(((packetsLost / totalPackets) * 100).toFixed(2)) : 0,
    });
  }
  return netValue("stats", { v: 1, peers }, "stats-report.json", {
    rtcStats: true,
    statsKind: "quality",
  });
}
