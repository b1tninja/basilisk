/**
 * Quorum toolbox ops (design v2 §21a) — WebRTC/STUN/ICE transport steps plus
 * a RUN-SCOPED p2p exchange wrapping lib/quorum's QuorumSession.
 *
 * The run boundary is the session boundary: `quorum.offer`/`quorum.join`
 * create the exchange (pausing the run at that cell until peers mesh),
 * `quorum.send`/`quorum.recv` use it, and `quorum.close` — or the kernel's
 * Clear session — tears it down and zeroizes keys.
 *
 * Main-thread only: RTCPeerConnection does not exist in workers.
 *
 * UI coupling is one-way through window events so this module never imports
 * React and the shell never imports WebRTC:
 *  - dispatches `basilisk:quorum-state` with the current exchange snapshot
 *  - listens for `basilisk:quorum-cancel` (RunBar/SessionStrip Cancel)
 * @module lib/toolkit/quorum-ops
 */

import { QuorumSession, DEFAULT_ICE_SERVERS } from "../quorum/rtc.js";
import { deriveRoomId, canonicalAudience } from "../quorum/room.js";

/**
 * @typedef {object} QuorumExchangeState
 * @property {"idle"|"offering"|"waiting"|"connected"|"closed"|"failed"} phase
 * @property {string} room
 * @property {"creator"|"joiner"|""} role
 * @property {string} invite   short shareable line (room + audience count)
 * @property {number} connected
 * @property {number} expected
 * @property {string} status   last human-readable session status line
 */

/** @type {QuorumExchangeState} */
const IDLE_STATE = Object.freeze({
  phase: "idle",
  room: "",
  role: "",
  invite: "",
  connected: 0,
  expected: 0,
  status: "",
});

/**
 * The one live exchange for the current run/session.
 * @type {{
 *   session: QuorumSession,
 *   state: QuorumExchangeState,
 *   inbox: { from: string, text: string, ts: number }[],
 *   recvWaiters: ((msg: { from: string, text: string, ts: number } | null) => void)[],
 *   cancelled: boolean,
 * } | null}
 */
let current = null;

function emitState() {
  if (typeof window === "undefined") return;
  const detail = current ? { ...current.state } : { ...IDLE_STATE };
  window.dispatchEvent(new CustomEvent("basilisk:quorum-state", { detail }));
}

/** @param {Partial<QuorumExchangeState>} patch */
function patchState(patch) {
  if (!current) return;
  current.state = { ...current.state, ...patch };
  emitState();
}

/**
 * The live `QuorumSession` (or null) — lets the `rtc.*` diagnostic ops read
 * real `RTCPeerConnection`/`RTCDataChannel` state off the running exchange
 * without importing the mesh themselves (design v2 §23b/29d/30d).
 * @returns {QuorumSession|null}
 */
export function getLiveSession() {
  return current && !current.cancelled ? current.session : null;
}

/** Current exchange snapshot (UI polls this on mount, then follows events). */
export function getQuorumState() {
  return current ? { ...current.state } : { ...IDLE_STATE };
}

/** Close the live exchange (Clear session, quorum.close, Cancel). */
export function closeQuorumExchange(reason = "closed") {
  const ex = current;
  if (!ex) return;
  ex.cancelled = true;
  for (const w of ex.recvWaiters.splice(0)) w(null);
  try {
    ex.session.stop();
  } catch (_) {
    /* ignore */
  }
  ex.inbox.length = 0;
  ex.state = { ...ex.state, phase: reason === "failed" ? "failed" : "closed" };
  emitState();
  current = null;
}

if (typeof window !== "undefined") {
  window.addEventListener("basilisk:quorum-cancel", () =>
    closeQuorumExchange("closed")
  );
}

/* ────────────────────────────── rtc.ice ────────────────────────────── */

/**
 * Build an ICE server list from step params (pure config, no network).
 * @param {Record<string, unknown>} params
 * @returns {{ type: "text", data: string, meta: Record<string, unknown> }}
 */
export function execRtcIce(params) {
  /** @type {RTCIceServer[]} */
  const servers = [];
  const stunRaw = String(params?.stun || "").trim();
  const stunUrls = stunRaw
    ? stunRaw.split(/[\s,]+/).filter(Boolean)
    : DEFAULT_ICE_SERVERS.flatMap((s) =>
        Array.isArray(s.urls) ? s.urls : [s.urls]
      );
  for (const url of stunUrls) {
    if (!/^stuns?:/i.test(url)) {
      throw new Error(`rtc.ice: not a stun:/stuns: URL — ${url}`);
    }
    servers.push({ urls: url });
  }
  const turn = String(params?.turn || "").trim();
  if (turn) {
    if (!/^turns?:/i.test(turn)) {
      throw new Error(`rtc.ice: not a turn:/turns: URL — ${turn}`);
    }
    const username = String(params?.username || "");
    const credential = String(params?.credential || "");
    if (!username || !credential) {
      throw new Error("rtc.ice: TURN needs username= and credential=");
    }
    servers.push({ urls: turn, username, credential });
  }
  return {
    type: "endpoint",
    data: { v: 1, iceServers: servers },
    meta: { sensitive: !!turn, rtcIce: true, filename: "ice.json", kind: "ice-servers" },
  };
}

/**
 * Parse an `rtc.ice` slot value back into RTCIceServer[].
 * @param {string} text
 * @returns {RTCIceServer[]}
 */
export function parseIceConfig(text) {
  // Accepts either an `endpoint`-typed value's structured data or the legacy
  // JSON string form (a hand-written config, or an older saved notebook).
  const parsed =
    text && typeof text === "object" ? text : JSON.parse(String(text));
  const list = parsed?.iceServers;
  if (!Array.isArray(list) || !list.length) {
    throw new Error("ice=@slot does not hold rtc.ice output");
  }
  return list;
}

/* ───────────────────────────── stun.check ───────────────────────────── */

/**
 * One-shot NAT diagnostic — gather ICE candidates and report the
 * server-reflexive address. Real network, main-thread only.
 * @param {Record<string, unknown>} params
 */
export async function execStunCheck(params) {
  if (typeof RTCPeerConnection !== "function") {
    throw new Error("stun.check: WebRTC unavailable in this context");
  }
  const server = String(params?.server || "stun:stun.cloudflare.com:3478");
  const timeout = Math.max(500, Number(params?.timeout) || 4000);
  const started = performance.now();
  const pc = new RTCPeerConnection({ iceServers: [{ urls: server }] });
  /** @type {Record<string, number>} */
  const byType = {};
  /** @type {string[]} */
  const reflexive = [];
  try {
    pc.createDataChannel("probe");
    const done = new Promise((resolve) => {
      const timer = setTimeout(resolve, timeout);
      pc.onicecandidate = (ev) => {
        const c = ev.candidate;
        if (!c) {
          clearTimeout(timer);
          resolve(undefined);
          return;
        }
        const type = c.type || "unknown";
        byType[type] = (byType[type] || 0) + 1;
        if (type === "srflx" && c.address) {
          reflexive.push(`${c.address}:${c.port}`);
        }
      };
    });
    await pc.setLocalDescription(await pc.createOffer());
    await done;
  } finally {
    try {
      pc.close();
    } catch (_) {
      /* ignore */
    }
  }
  const ms = Math.round(performance.now() - started);
  const ok = reflexive.length > 0;
  return {
    type: "endpoint",
    data: {
      v: 1,
      server,
      ok,
      publicAddress: reflexive[0] || null,
      candidates: byType,
      ms,
      note: ok
        ? "STUN reachable — reflexive address discovered"
        : "no srflx candidate — STUN blocked or all-host network; consider a TURN relay (rtc.ice turn=)",
    },
    meta: { sensitive: false, stunCheck: true, filename: "stun-check.json" },
  };
}

/* ─────────────────────────── exchange steps ─────────────────────────── */

/**
 * @param {Record<string, unknown>} params
 * @param {import("openpgp").PrivateKey} privateKey decrypted, from key=@slot
 * @param {RTCIceServer[] | null} iceServers
 * @param {"creator"|"joiner"} role
 */
export async function execQuorumOpen(params, privateKey, iceServers, role) {
  if (typeof RTCPeerConnection !== "function") {
    throw new Error("quorum: WebRTC unavailable in this context");
  }
  if (current) {
    throw new Error(
      `quorum: an exchange is already live (room ${current.state.room}) — quorum.close it first`
    );
  }
  const audience = canonicalAudience(
    String(params?.to || "")
      .split(/[\s,]+/)
      .filter(Boolean)
  );
  if (audience.length < 2) {
    throw new Error("quorum: to= needs at least two fingerprints (including yours)");
  }
  const myFpr = privateKey.getFingerprint().toUpperCase();
  const room = await deriveRoomId(audience);
  const wait = Math.max(1000, Number(params?.wait) || 120000);
  const needPeers = Math.max(1, Number(params?.peers) || 1);

  const session = new QuorumSession({
    roomId: room,
    audienceFprs: audience,
    privateKey,
    myFingerprint: myFpr,
    role,
    iceServers: iceServers || undefined,
    onChat: (msg) => {
      const ex = current;
      if (!ex) return;
      const waiter = ex.recvWaiters.shift();
      if (waiter) waiter(msg);
      else ex.inbox.push(msg);
    },
    onRoster: (peers) => {
      const ex = current;
      if (!ex) return;
      let connected = 0;
      for (const p of peers.values()) {
        if (p.status === "connected" && p.kcVerified) connected++;
      }
      patchState({
        connected,
        phase:
          connected >= needPeers
            ? "connected"
            : ex.state.phase === "connected"
              ? "waiting"
              : ex.state.phase,
      });
    },
    onStatus: (status) => patchState({ status }),
    onError: () => {
      /* surfaced via status + timeout */
    },
  });

  current = {
    session,
    state: {
      phase: "offering",
      room,
      role,
      invite: `quorum ${room} · ${audience.length} keys · ${quorumHost()}`,
      connected: 0,
      expected: audience.length - 1,
      status: "starting…",
    },
    inbox: [],
    recvWaiters: [],
    cancelled: false,
  };
  emitState();

  try {
    await session.start();
    patchState({ phase: "waiting" });
    await waitForPeers(needPeers, wait);
  } catch (err) {
    closeQuorumExchange("failed");
    throw err;
  }

  const snapshot = getQuorumState();
  return {
    // A live handle, not data — the type system blocks it from being consumed
    // by a crypto op, and it means nothing outside this run (design v2 §25a).
    type: "session",
    data: { v: 1, room, role, audience, connected: snapshot.connected },
    meta: { sensitive: false, quorumSession: true, filename: "session.json" },
  };
}

function quorumHost() {
  try {
    return typeof location !== "undefined" ? location.hostname : "local";
  } catch (_) {
    return "local";
  }
}

/**
 * @param {number} needPeers
 * @param {number} wait
 */
function waitForPeers(needPeers, wait) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      const ex = current;
      if (!ex || ex.cancelled) {
        reject(new Error("quorum: exchange cancelled"));
        return;
      }
      if (ex.state.connected >= needPeers) {
        resolve(undefined);
        return;
      }
      if (Date.now() - started > wait) {
        reject(
          new Error(
            `quorum: no peer within ${Math.round(wait / 1000)}s — is the other side running quorum.${ex.state.role === "creator" ? "join" : "offer"}?`
          )
        );
        return;
      }
      setTimeout(tick, 250);
    };
    tick();
  });
}

/**
 * @param {{ type: string, data: unknown, meta?: Record<string, unknown> }} value
 */
export async function execQuorumSend(value) {
  const ex = requireExchange("quorum.send");
  const text =
    value?.type === "text"
      ? String(value.data)
      : new TextDecoder().decode(/** @type {Uint8Array} */ (value?.data));
  await ex.session.sendChat(text);
  return value;
}

/** @param {Record<string, unknown>} params */
export async function execQuorumRecv(params) {
  const ex = requireExchange("quorum.recv");
  const fromFilter = String(params?.from || "")
    .replace(/\s+/g, "")
    .toUpperCase();
  const wait = Math.max(1000, Number(params?.wait) || 120000);
  const deadline = Date.now() + wait;

  for (;;) {
    const queued = fromFilter
      ? ex.inbox.findIndex((m) => m.from.toUpperCase().startsWith(fromFilter))
      : ex.inbox.length
        ? 0
        : -1;
    if (queued >= 0) {
      const msg = ex.inbox.splice(queued, 1)[0];
      return {
        type: "text",
        data: msg.text,
        meta: { sensitive: true, from: msg.from, ts: msg.ts },
      };
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`quorum.recv: no message within ${Math.round(wait / 1000)}s`);
    }
    /** @type {{ from: string, text: string, ts: number } | null} */
    const msg = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        const i = ex.recvWaiters.indexOf(resolve);
        if (i >= 0) ex.recvWaiters.splice(i, 1);
        resolve(null);
      }, remaining);
      ex.recvWaiters.push((m) => {
        clearTimeout(timer);
        resolve(m);
      });
    });
    if (msg === null) {
      if (!current || current.cancelled) {
        throw new Error("quorum.recv: exchange closed while waiting");
      }
      continue; // timeout path re-checked at loop top
    }
    if (!fromFilter || msg.from.toUpperCase().startsWith(fromFilter)) {
      return {
        type: "text",
        data: msg.text,
        meta: { sensitive: true, from: msg.from, ts: msg.ts },
      };
    }
    ex.inbox.push(msg); // not for this filter — requeue for another recv
  }
}

/**
 * @param {{ type: string, data: unknown, meta?: Record<string, unknown> } | null} value
 */
export function execQuorumClose(value) {
  closeQuorumExchange("closed");
  return (
    value || {
      type: "text",
      data: JSON.stringify({ v: 1, closed: true }),
      meta: { sensitive: false },
    }
  );
}

/** @param {string} op */
function requireExchange(op) {
  if (!current || current.cancelled) {
    throw new Error(`${op}: no live exchange — run quorum.offer or quorum.join first`);
  }
  return current;
}
