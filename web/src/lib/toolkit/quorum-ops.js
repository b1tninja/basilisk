/**
 * Quorum toolbox ops (design v2 §21a) — WebRTC/STUN/ICE transport steps plus
 * a RUN-SCOPED p2p exchange wrapping lib/notebook's NotebookSession.
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

import { NotebookSession } from "../notebook/session.js";
import { iceServersOrDefault } from "../webrtc/ice.js";
import { deriveRoomId, canonicalAudience } from "../notebook/room.js";
import { projectRosterPeers } from "../notebook/roster.js";
import { DKG_COMMIT, DKG_SHARE } from "../quorum/dkg-run.js";
import { idFromFingerprint, scalarToHex } from "../quorum/vss.js";

/**
 * @typedef {object} QuorumExchangeState
 * @property {"idle"|"offering"|"waiting"|"connected"|"closed"|"failed"} phase
 * @property {string} room
 * @property {"creator"|"joiner"|""} role
 * @property {string} invite   short shareable line (room + audience count)
 * @property {number} connected
 * @property {number} expected
 * @property {string} status   last human-readable session status line
 * @property {import("../notebook/roster.js").ConnectionPeerRow[]} peers
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
  peers: Object.freeze([]),
});

/**
 * The one live exchange for the current run/session.
 * @type {{
 *   session: NotebookSession,
 *   state: QuorumExchangeState,
 *   inbox: { from: string, text: string, ts: number }[],
 *   recvWaiters: ((msg: { from: string, text: string, ts: number } | null) => void)[],
 *   cancelled: boolean,
 *   viaByFpr: Map<string, string>,
 *   viaPending: Set<string>,
 * } | null}
 */
let current = null;

/**
 * Roster → panel rows, plus best-effort ICE `via` enrichment.
 *
 * `getStats` is async while roster emits are not, so the first projection of a
 * newly connected peer has no `via`; the lookup patches it in when it lands.
 * Cached per exchange — the selected pair does not change without a
 * reconnection, and a reconnection makes a new exchange.
 *
 * @param {Map<string, import("../notebook/session.js").NotebookPeerState>} peersMap
 * @returns {import("../notebook/roster.js").ConnectionPeerRow[]}
 */
function projectPeers(peersMap) {
  const ex = current;
  if (!ex) return [];
  for (const [fpr, peer] of peersMap) {
    if (
      peer.status !== "connected" ||
      !peer.link ||
      ex.viaByFpr.has(fpr) ||
      ex.viaPending.has(fpr)
    ) {
      continue;
    }
    ex.viaPending.add(fpr);
    // Asked of the link, not of a connection handle read off the peer record —
    // the mesh has none. `peer.*` links answer the same question through the
    // same code, so "host"/"srflx"/"relay" means one thing across the inventory.
    void peer.link.selectedCandidateType().then((via) => {
      ex.viaPending.delete(fpr);
      if (!via || current !== ex || ex.cancelled) return;
      ex.viaByFpr.set(fpr, via);
      patchState({ peers: projectRosterPeers(peersMap, ex.viaByFpr) });
    });
  }
  return projectRosterPeers(peersMap, ex.viaByFpr);
}

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
 * The live `NotebookSession` (or null) — lets the `rtc.*` diagnostic ops read
 * real `RTCPeerConnection`/`RTCDataChannel` state off the running exchange
 * without importing the mesh themselves (design v2 §23b/29d/30d).
 * @returns {NotebookSession|null}
 */
export function getLiveSession() {
  return current && !current.cancelled ? current.session : null;
}

/**
 * Re-run ICE on every peer connection of the live exchange (design v2 §33a).
 *
 * Re-negotiates *in place*: the room code, the signed invite, and any mesh
 * roster survive, because the session itself never closed — only its transport
 * did. That is what separates this from Cancel + re-invite, and from 22b's
 * "Configure TURN", which fires before a session exists at all.
 *
 * @returns {number} peer connections restarted (0 when nothing is live)
 */
export function restartLiveIce() {
  const session = getLiveSession();
  if (!session) return 0;
  let n = 0;
  // `.values()`, because `session.peers` is a Map keyed by fingerprint and
  // iterating a Map directly yields `[fpr, peer]` entries. Reading the link off
  // an Array entry is `undefined`, so every peer failed the restart check and
  // this returned 0 for every live exchange there has ever been — the
  // Connections panel's Restart ICE button did nothing at all. `rtc.restart`
  // destructures the entry and always worked, which is how the two could
  // disagree unnoticed.
  for (const peer of session.peers?.values?.() || []) {
    const link = peer?.link;
    if (!link) continue;
    try {
      // The link says whether it issued one: `restartIce` is unavailable on
      // older engines, and a peer that cannot restart must not abort the ones
      // that can.
      if (link.restartIce()) n += 1;
    } catch {
      /* peer already torn down — nothing to restart */
    }
  }
  return n;
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
  // A failed exchange keeps its last roster so the panel can show *which*
  // links died; a clean close clears it — the session ended, nothing is live.
  ex.state = {
    ...ex.state,
    phase: reason === "failed" ? "failed" : "closed",
    peers: reason === "failed" ? ex.state.peers : [],
  };
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
 *
 * `stun=none` is how a user declines every third party. It exists because the
 * empty string could not mean it: empty is *nobody said*, which the defaults
 * fill, so before this word the only way to ask for host candidates only was
 * to write something that did not parse. A STUN binding request hands a public
 * IP to whoever answers it, and refusing that is a decision this app has to
 * let someone make and then keep — `iceServersOrDefault` is what stops the
 * session layer taking it back.
 *
 * `stun=none turn=…` is coherent and allowed: a relay you chose, and no
 * reflexive probe to anyone else.
 *
 * @param {Record<string, unknown>} params
 * @returns {{ type: "text", data: string, meta: Record<string, unknown> }}
 */
export function execRtcIce(params) {
  /** @type {RTCIceServer[]} */
  const servers = [];
  const stunRaw = String(params?.stun || "").trim();
  const declined = /^none$/i.test(stunRaw);
  const stunUrls = declined
    ? []
    : stunRaw
      ? stunRaw.split(/[\s,]+/).filter(Boolean)
      : // Through the same rule the session and the raw ops go through, so
        // "empty means the built-in list" is stated once for the whole app.
        iceServersOrDefault(null).flatMap((s) =>
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
    // Split like `stun=` does. It used to be taken whole, so `turn=turn:a,turn:b`
    // passed the scheme test on its first character and shipped one server whose
    // `urls` was two URLs — an artifact that reads as valid and then dies inside
    // `quorum.offer` with Chromium's "ICE server parsing failed: Invalid port",
    // a page away from the step that wrote it.
    const turnUrls = turn.split(/[\s,]+/).filter(Boolean);
    for (const url of turnUrls) {
      if (!/^turns?:/i.test(url)) {
        throw new Error(`rtc.ice: not a turn:/turns: URL — ${url}`);
      }
    }
    const username = String(params?.username || "");
    const credential = String(params?.credential || "");
    if (!username || !credential) {
      throw new Error("rtc.ice: TURN needs username= and credential=");
    }
    for (const url of turnUrls) servers.push({ urls: url, username, credential });
  }
  // `stun=","` splits to nothing and used to emit `{ iceServers: [] }` — an
  // artifact that reads as an empty panel and dies at `parseIceConfig` a page
  // later. The complaint still belongs at the step that wrote it. What changed
  // is that an empty list is no longer *only* reachable by accident: after
  // `stun=none` it is the requested answer, so the refusal is now for the
  // accident specifically and says which word to write instead.
  if (!servers.length && !declined) {
    throw new Error(
      "rtc.ice: no ICE servers — stun= matched no stun:/stuns: URL (write stun=none if that is what you meant)"
    );
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
  let parsed;
  if (text && typeof text === "object") {
    parsed = text;
  } else {
    try {
      parsed = JSON.parse(String(text));
    } catch {
      // Binding `ice=$somethingelse` is the common way to get here, and the
      // raw `Unexpected token 'h', "hunter2" is not valid JSON` that used to
      // surface named neither the parameter nor the step.
      throw new Error("ice=$slot does not hold rtc.ice output");
    }
  }
  const list = parsed?.iceServers;
  if (!Array.isArray(list)) {
    throw new Error("ice=$slot does not hold rtc.ice output");
  }
  // An empty list used to be refused here as malformed. `rtc.ice stun=none`
  // writes one deliberately, so it is now a legitimate config — but only from
  // a value that says it *is* one. `{"hello":1}` and a bare `[]` still name
  // the parameter rather than sliding through as "no third party", which
  // would turn a mis-bound slot into a silent connectivity change.
  if (!list.length && parsed?.v == null) {
    throw new Error("ice=$slot does not hold rtc.ice output");
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
  // Validated before the capability check, because a `server=` the step cannot
  // use is a fact about the recipe rather than about the engine running it.
  // Unvalidated, `stun.check server=http://x` reached the constructor and came
  // back as Chromium's `SyntaxError: Failed to construct 'RTCPeerConnection'`
  // — which names neither the step nor the parameter. `rtc.ice` has always
  // checked the scheme; this is the same check on the other STUN-taking op.
  const server =
    String(params?.server ?? "").trim() || "stun:stun.cloudflare.com:3478";
  if (!/^stuns?:/i.test(server)) {
    throw new Error(`stun.check: not a stun:/stuns: URL — ${server}`);
  }
  if (typeof RTCPeerConnection !== "function") {
    throw new Error("stun.check: WebRTC unavailable in this context");
  }
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
 * @param {import("openpgp").PrivateKey} privateKey decrypted, from key=$slot
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

  const session = new NotebookSession({
    roomId: room,
    audienceFprs: audience,
    privateKey,
    myFingerprint: myFpr,
    role,
    // `??`, not `||` — an empty list is the caller declining every third
    // party, and `undefined` is the session's cue to substitute defaults.
    // The two must not be spelled the same on the way in.
    iceServers: iceServers ?? undefined,
    onChat: (msg) => {
      const ex = current;
      if (!ex) return;
      // Protocol traffic gets first refusal. A tap that recognizes a message
      // consumes it, so DKG round chatter never lands in the inbox a user's
      // `quorum.recv` is reading — otherwise running a key generation would fill
      // their pipeline with JSON they did not ask for.
      for (const tap of ex.taps) {
        try {
          if (tap(msg) === true) return;
        } catch (_) {
          /* a broken tap must not swallow ordinary chat */
        }
      }
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
        peers: projectPeers(peers),
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
      peers: [],
    },
    inbox: [],
    recvWaiters: [],
    cancelled: false,
    viaByFpr: new Map(),
    viaPending: new Set(),
    /** @type {((msg: { from: string, text: string }) => boolean)[]} */
    taps: [],
  };
  const ex = current;
  emitState();

  try {
    await session.start();
    // Only when the roster has not already taken us further. `start()` awaits
    // the invite broadcast and the first meshing pass, and the signalling poll
    // ticks inside those awaits — so a peer *can* mesh before `start()`
    // returns. Announcing "waiting" unconditionally demoted a connected
    // exchange, and nothing ever promoted it back: `onRoster` only fires again
    // on the next roster change, and a meshed peer does not produce one. The
    // strip then read "waiting" for the rest of a session the step had already
    // returned from as connected.
    if (ex.state.phase === "offering") patchState({ phase: "waiting" });
    await waitForPeers(ex, needPeers, wait);
  } catch (err) {
    // Only if this call still owns the exchange — a Cancel that already tore
    // ours down may have been followed by someone else's `quorum.offer`, and
    // failing must not close a session this run never opened.
    if (current === ex) closeQuorumExchange("failed");
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
 * Wait for `ex` — the exchange this call opened — to mesh.
 *
 * Bound to the exchange rather than to whatever `current` happens to hold: the
 * loop ticks every 250 ms, and Cancel clears `current` so a *second*
 * `quorum.offer` may legitimately start inside that window. Reading the global
 * meant the abandoned call would then wait on, time out against, and close the
 * new exchange.
 *
 * @param {NonNullable<typeof current>} ex
 * @param {number} needPeers
 * @param {number} wait
 */
function waitForPeers(ex, needPeers, wait) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      if (current !== ex || ex.cancelled) {
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
export async function execQuorumSend(value, params) {
  const ex = requireExchange("quorum.send");
  const text =
    value?.type === "text"
      ? String(value.data)
      : new TextDecoder().decode(/** @type {Uint8Array} */ (value?.data));
  const to = String(params?.to || "").trim();
  // Addressed sends throw when no verified peer matches, rather than quietly
  // reaching nobody — see NotebookSession.sendChatTo.
  if (to) await ex.session.sendChatTo(to, text);
  else await ex.session.sendChat(text);
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

  // `count` decides both how many messages to gather and what shape comes out
  // (§30c). One message stays a plain `text` so the common two-party read is
  // unchanged; anything else is a `bundle`, because in a mesh "the next
  // message" is not a well-defined thing — several peers speak at once.
  const countRaw = String(params?.count ?? "1").trim().toLowerCase();
  const drain = countRaw === "all";
  const want = drain ? Infinity : Math.max(1, Number(countRaw) || 1);
  const single = !drain && want === 1;

  /** @type {{ from: string, text: string, ts: number }[]} */
  const got = [];

  /** Pull every already-queued message this call is allowed to take. */
  const takeQueued = () => {
    for (let i = 0; i < ex.inbox.length && got.length < want; ) {
      const m = ex.inbox[i];
      if (!fromFilter || m.from.toUpperCase().startsWith(fromFilter)) {
        got.push(m);
        ex.inbox.splice(i, 1);
      } else {
        i += 1;
      }
    }
  };

  for (;;) {
    takeQueued();
    // `all` returns as soon as it has anything — draining an inbox should not
    // then block for `wait` hoping for more.
    if (got.length >= want || (drain && got.length)) break;

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      if (got.length) break; // partial collection is still a result
      throw new Error(`quorum.recv: no message within ${Math.round(wait / 1000)}s`);
    }
    /** @type {{ from: string, text: string, ts: number } | null} */
    const msg = await new Promise((resolve) => {
      // The waiter is removed by identity, so the queue must be searched for
      // the function that was *pushed*. Looking for `resolve` instead never
      // matched, so a timed-out `quorum.recv` left a settled waiter in the queue
      // and `onChat` handed the next message to it — resolving an already
      // resolved promise, which drops the message on the floor instead of
      // queueing it for the next read.
      /** @param {{ from: string, text: string, ts: number } | null} m */
      const waiter = (m) => {
        clearTimeout(timer);
        resolve(m);
      };
      const timer = setTimeout(() => {
        const i = ex.recvWaiters.indexOf(waiter);
        if (i >= 0) ex.recvWaiters.splice(i, 1);
        resolve(null);
      }, remaining);
      ex.recvWaiters.push(waiter);
    });
    if (msg === null) {
      if (!current || current.cancelled) {
        throw new Error("quorum.recv: exchange closed while waiting");
      }
      continue; // timeout path re-checked at loop top
    }
    if (!fromFilter || msg.from.toUpperCase().startsWith(fromFilter)) {
      got.push(msg);
    } else {
      ex.inbox.push(msg); // not for this filter — requeue for another recv
    }
  }

  if (single) {
    const msg = got[0];
    return {
      type: "text",
      data: msg.text,
      meta: { sensitive: true, from: msg.from, ts: msg.ts },
    };
  }
  // Bundle parts mirror what `foreach` produces, so the existing collection
  // machinery (`foreach`, `[n]`, `at`) works on received messages with no
  // special-casing. `from` rides on each part, not on the bundle: in a mesh
  // the sender differs per message.
  const parts = got.map((m) => ({
    type: "text",
    data: m.text,
    meta: { sensitive: true, from: m.from, ts: m.ts },
  }));
  return {
    type: "bundle",
    data: { parts, count: parts.length },
    meta: { kind: "recv", count: parts.length, sensitive: true },
  };
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

/**
 * A `DkgTransport` over the live exchange.
 *
 * The mapping is direct because the mesh already provides what the protocol
 * needs: `sendChat` broadcasts to every verified peer, `sendChatTo` addresses
 * one over its own channel — which is why the rounds want a mesh rather than
 * an SFU — and the tap delivers inbound protocol messages without them
 * reaching a user's `quorum.recv`.
 *
 * Participants are identified by the scalar derived from their PGP
 * fingerprint, so the polynomial is indexed by the identities the room was
 * already built on rather than a second numbering everyone has to agree.
 *
 * @param {string} op  for error attribution
 * @returns {{
 *   transport: import("../quorum/dkg-run.js").DkgTransport,
 *   myId: string,
 *   ids: string[],
 *   release: () => void,
 * }}
 */
export function createExchangeTransport(op = "dkg.run") {
  const ex = requireExchange(op);
  const session = ex.session;
  const byId = new Map();
  for (const fpr of session.audienceFprs || []) {
    byId.set(scalarToHex(idFromFingerprint(fpr)), fpr);
  }
  const myId = scalarToHex(idFromFingerprint(session.myFpr));

  /** @type {((msg: object) => void)[]} */
  const handlers = [];
  const tap = (msg) => {
    let parsed;
    try {
      parsed = JSON.parse(String(msg?.text ?? ""));
    } catch {
      return false; // ordinary chat — leave it for quorum.recv
    }
    if (!parsed || typeof parsed !== "object") return false;
    if (parsed.t !== DKG_COMMIT && parsed.t !== DKG_SHARE) return false;
    // Trust the *channel* for provenance, not the envelope's own `from`: the
    // session already authenticated this peer, so stamping the id here means a
    // participant cannot deal under someone else's name.
    const fromId = scalarToHex(idFromFingerprint(String(msg.from || "")));
    for (const h of handlers) h({ ...parsed, from: fromId });
    return true;
  };
  ex.taps.push(tap);

  return {
    myId,
    ids: [...byId.keys()],
    transport: {
      broadcast: (m) => session.sendChat(JSON.stringify(m)),
      sendTo: (id, m) => {
        const fpr = byId.get(id);
        if (!fpr) throw new Error(`${op}: no participant with id ${id.slice(-8)}`);
        return session.sendChatTo(fpr, JSON.stringify(m));
      },
      subscribe: (handler) => {
        handlers.push(handler);
        return () => {
          const i = handlers.indexOf(handler);
          if (i >= 0) handlers.splice(i, 1);
        };
      },
    },
    release: () => {
      const i = ex.taps.indexOf(tap);
      if (i >= 0) ex.taps.splice(i, 1);
    },
  };
}

/** @param {string} op */
function requireExchange(op) {
  if (!current || current.cancelled) {
    throw new Error(`${op}: no live exchange — run quorum.offer or quorum.join first`);
  }
  return current;
}
