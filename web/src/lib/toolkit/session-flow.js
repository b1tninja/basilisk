/**
 * What a shared session is doing, said in sentences.
 *
 * The transport already knows every fact on this page — `quorum-ops.js` emits a
 * phase, a roster and a status line, and `NotebookSession` decides what
 * `kcVerified` means. None of that is re-derived here. What is missing is the
 * *reading*: a phase name is not an explanation, and "waiting" beside a room
 * code tells nobody why nothing is happening or what to do about it.
 *
 * It lives in `lib/` rather than inside the widgets for `artifact-readouts.js`'s
 * reason: tests here run in node with no DOM, so a read-out written inside a
 * component is a read-out with no tests. The widgets below are layout only.
 *
 * ## Three facts about this transport that the copy exists to carry
 *
 * 1. **The room is a name, not a place.** It is `SHA-256(hostname | sorted
 *    audience fingerprints)`, truncated — see `lib/notebook/room.js`. Nobody
 *    allocates it and nobody hands it out. Anyone who can name the same set of
 *    fingerprints on the same site derives the same room, and anyone who cannot
 *    derives a different one. So *who may join* is decided entirely by the
 *    audience, before a single byte moves, and an invite is a list of public
 *    fingerprints rather than a token.
 *
 * 2. **The signalling relay keeps no history.** Azure Web PubSub brokers to the
 *    connections that are in the group at the moment of the send; there is no
 *    backlog for a late arrival. `NotebookSession.start()` publishes the
 *    creator's signed invite exactly once, the instant its own room is joined
 *    — so a joiner who arrives afterwards is in the right room and will never
 *    see the introduction. That is the *whole* reason `sessionReadout` tells a
 *    creator to have the other side waiting first, and the reason the remedy
 *    for a stalled room is "start it again", not "wait longer".
 *
 * 3. **Key confirmation is automatic, and it is not a word you compare.**
 *    Peers exchange a `kc` frame carrying a `transcriptHash` that binds the
 *    room id, both PGP fingerprints, both ECDH thumbprints and both DTLS
 *    fingerprints (`derivePairwiseSessionKey` in `lib/notebook/crypto.js`). A
 *    mismatch means the frame is dropped and `kcVerified` stays false. There is
 *    no short authentication string and nothing for a person to read out, so
 *    this module never asks for one — it reports that confirmation happened, or
 *    says plainly that it has not.
 *
 * @module lib/toolkit/session-flow
 */

import { canonicalAudience } from "../notebook/room.js";

/**
 * What the invite carries, and what it does not.
 *
 * Two lists rather than one paragraph, and exported rather than written into
 * the card, because they are a security claim: everything in `INVITE_OMITS` is
 * something a reader might reasonably fear is in a link they are about to put
 * in a chat window. A claim a component owns is a claim no test can pin.
 */
export const INVITE_CARRIES = [
  "the public fingerprints of everyone in the room — the same ones a keyserver hands out",
  "this site's hostname, which is already in the address bar",
];

export const INVITE_OMITS = [
  "the room id — both ends derive it from the fingerprints, so it never travels",
  "any token or password — the invite admits nobody by itself",
  "your notebook, its inputs, and anything a run produced",
  "every private key, always",
];

/**
 * Joined, verified, and the two ways they differ.
 *
 * `joined` is who arrived, `verified` is who proved the channel is theirs, and
 * `ShareSheet`'s `RosterCount` exists because a single "2 peers" hides the gap
 * between them. `down` is the third number the other two cannot express: a link
 * that was up and is not, which reads as neither joined nor missing.
 *
 * @param {{ state?: string, authenticated?: boolean }[]} peers
 * @returns {{ joined: number, verified: number, pending: number, down: number }}
 */
export function rosterCounts(peers) {
  const rows = Array.isArray(peers) ? peers : [];
  let joined = 0;
  let verified = 0;
  let down = 0;
  for (const p of rows) {
    const state = String(p?.state || "");
    if (state === "failed" || state === "disconnected") {
      down += 1;
      continue;
    }
    if (state === "new" || state === "closed") continue;
    joined += 1;
    if (p?.authenticated) verified += 1;
  }
  return { joined, verified, pending: joined - verified, down };
}

/**
 * The stage a session is in, which is not the same as its phase.
 *
 * `quorum-ops` reports six phases and they are about the *transport*. Two of
 * them cover four situations a person needs told apart: `waiting` is either an
 * empty room or a room where somebody has arrived and not yet been confirmed,
 * and `connected` is either everybody confirmed or some of them. The second of
 * each pair is the dangerous one — a peer who is present and unproven — so it
 * gets a stage of its own rather than sharing a word with the safe case.
 *
 * @param {{ phase?: string, peers?: { state?: string, authenticated?: boolean }[] }} state
 * @returns {"idle"|"offering"|"waiting"|"unconfirmed"|"partial"|"verified"|"failed"|"closed"}
 */
export function sessionStage(state) {
  const phase = String(state?.phase || "idle");
  const { joined, verified, pending } = rosterCounts(state?.peers);
  if (phase === "idle") return "idle";
  if (phase === "failed") return "failed";
  if (phase === "closed") return "closed";
  if (phase === "offering") return "offering";
  if (phase === "waiting") return joined && pending ? "unconfirmed" : "waiting";
  // `connected`. A room of nobody cannot be verified, whatever the phase says.
  if (!joined) return "waiting";
  return verified === joined ? "verified" : "partial";
}

/**
 * @typedef {object} SessionReadout
 * @property {ReturnType<typeof sessionStage>} stage
 * @property {"brand"|"warn"|"error"|"muted"} tone
 * @property {string} headline
 * @property {string} why
 * @property {string|null} next  what the reader can do; null when nothing is asked of them
 */

/**
 * The whole session, in three sentences.
 *
 * Shaped like `connStateReadout` — headline, why, next — for the reason that
 * function gives: a panel and a tile holding two opinions about one failure is
 * how a reader ends up trusting the wrong one. This is the only place a session
 * stage is turned into prose.
 *
 * @param {{
 *   phase?: string,
 *   role?: string,
 *   status?: string,
 *   peers?: { state?: string, authenticated?: boolean }[],
 * }} state
 * @returns {SessionReadout}
 */
export function sessionReadout(state) {
  const stage = sessionStage(state);
  const { joined, verified, pending, down } = rosterCounts(state?.peers);
  const creator = String(state?.role || "") !== "joiner";
  const one = (n) => (n === 1 ? "" : "s");

  if (stage === "idle") {
    return {
      stage,
      tone: "muted",
      headline: "No session",
      why: "Nothing is open. A shared session is what lets a cell marked for somebody else actually run on their machine; without one, those cells are skipped and the run stops where it needs their answer.",
      next: "Name who is in the room and start it.",
    };
  }
  if (stage === "offering") {
    return {
      stage,
      tone: "muted",
      headline: "Publishing the invite",
      why: "Joining the signalling room, then broadcasting an invite signed with your key. The relay carries the envelope and cannot read it.",
      next: null,
    };
  }
  if (stage === "waiting") {
    return {
      stage,
      tone: "warn",
      headline: creator ? "Nobody has answered" : "Waiting for the invite",
      why: creator
        ? "The signed invite went out once, when this browser joined the room, and the relay keeps no history of it. Anyone who joins after that moment is in the right room and will never see the introduction."
        : "The creator's invite is broadcast once and not stored, so it only reaches whoever is already in the room. If they started before you, there is nothing left on the wire for you to verify.",
      next: creator
        ? "Have them open the invite and press Join, then start this again — the introduction has to be published while they are already listening."
        : "Stay here and ask them to start the session again; you are in the room now, so the next invite reaches you.",
    };
  }
  if (stage === "unconfirmed") {
    return {
      stage,
      tone: "warn",
      headline: `${joined} here, none confirmed yet`,
      why: "The transport is up and the key exchange has not finished. Confirmation is automatic — each side sends a hash binding the room, both keys and both transport certificates — so this normally clears in a second on its own.",
      next: "If it does not clear, the two ends disagree about something the hash covers. Nothing will run on an unconfirmed peer.",
    };
  }
  if (stage === "partial") {
    return {
      stage,
      tone: "error",
      headline: `${pending} of ${joined} unconfirmed`,
      why: "Being in the room and being who you say you are is not the same claim. An unconfirmed peer holds a working channel that nothing has bound to their key, and no cell will be placed on them.",
      next: "Wait for confirmation, or remove them from the room — that moves the room somewhere their token does not name.",
    };
  }
  if (stage === "verified") {
    return {
      stage,
      tone: "brand",
      headline: `${verified} peer${one(verified)} confirmed`,
      why: "Each one exchanged a hash binding the room id, both PGP fingerprints, both ephemeral ECDH keys and both transport certificates, and both sides matched it. There was nothing for you to compare and nothing to type.",
      next: down ? `${down} other link${one(down)} in this room is down.` : null,
    };
  }
  if (stage === "failed") {
    return {
      stage,
      tone: "error",
      headline: "Session lost",
      // The status line is the transport's own last word; quoting it beats
      // paraphrasing a failure this module did not observe.
      why:
        String(state?.status || "").trim() ||
        "The exchange ended without being closed. The roster below is the last one seen, so it says which link died.",
      next: "Restart the connection to renegotiate in place — the room and the roster survive that. Starting over derives the same room from the same audience.",
    };
  }
  return {
    stage,
    tone: "muted",
    headline: "Session closed",
    why: "The exchange was torn down and every pairwise key zeroized. Nothing further arrives on it.",
    next: "The room is derived from the audience, so starting again with the same people lands in the same room.",
  };
}

/**
 * One peer's confirmation, as a badge and a reason.
 *
 * Deliberately withheld while the link is still coming up, for the reason
 * `SessionStrip` gives: a peer mid-handshake has not *failed* confirmation, it
 * has not reached it, and badging every joining peer "unconfirmed" cries wolf
 * on every join.
 *
 * @param {{ state?: string, authenticated?: boolean }} peer
 * @returns {{ tone: "brand"|"warn"|"error"|"muted", verdict: string, why: string }}
 */
export function confirmationReadout(peer) {
  const state = String(peer?.state || "new");
  if (state === "failed" || state === "disconnected") {
    return {
      tone: "error",
      verdict: "link down",
      why: "The transport stopped. Whatever was confirmed before is no longer carrying anything.",
    };
  }
  if (state !== "connected") {
    return {
      tone: "muted",
      verdict: state,
      why: "Still connecting. Confirmation happens once the channel is open, without anyone being asked to do anything.",
    };
  }
  if (peer?.authenticated) {
    return {
      tone: "brand",
      verdict: "confirmed",
      why: "Their signed signalling proved the key, and a transcript hash over this room, both keys and both transport certificates proved the channel is the one that key is on.",
    };
  }
  return {
    tone: "warn",
    verdict: "unconfirmed",
    why: "The channel is open and nothing has bound it to their key. No cell will be placed here and nothing they send is believed.",
  };
}

/**
 * Why a session cannot be started yet — sentences, not a boolean.
 *
 * Every one of these is a condition `execQuorumOpen` or `NotebookSession` would
 * refuse a moment later, said before the press rather than after: the audience
 * must have at least two fingerprints and must include your own, because the
 * room is derived from a set you are in. Refusing early is not a second
 * opinion — the transport still refuses — it is the same refusal where the
 * reader can still act on it.
 *
 * @param {{ audience?: string[], keyFingerprint?: string, live?: boolean }} draft
 * @returns {string[]}
 */
export function startIssues(draft) {
  const issues = [];
  if (draft?.live) {
    issues.push(
      "A session is already open. Close it first — one exchange at a time, so a cell can never be ambiguous about which room it ran in."
    );
  }
  const audience = canonicalAudience(draft?.audience || []);
  const key = String(draft?.keyFingerprint || "")
    .replace(/\s+/g, "")
    .toUpperCase();
  if (!key) {
    issues.push("Choose the key you are joining as — it signs the invite and every envelope after it.");
  }
  if (audience.length < 2) {
    issues.push(
      "Name at least two people, including yourself. A room is derived from the whole audience, so a room of one is not a room."
    );
  } else if (key && !audience.includes(key)) {
    issues.push(
      "Your own fingerprint is not in the audience. The room is derived from the list, and a key outside it derives a different room."
    );
  }
  return issues;
}

/**
 * The cells that open a session.
 *
 * Text, not a call into the transport. Everything else in this notebook is a
 * recipe you can read, save, share and re-run, and a session started by a
 * hidden code path would be the one thing on screen that is not reproducible —
 * the same argument `CeremonySheet` makes about owning sequence and wording but
 * never execution. What this returns is what a user could have typed, and what
 * Source view will show them afterwards.
 *
 * `key=$me` rather than the fingerprint inline: `agent.unlock` is the step that
 * exports a private key into the run, and it is marked as such everywhere in
 * this app. Splitting it into its own cell keeps that mark where a reader
 * looks.
 *
 * @param {{ audience: string[], keyFingerprint: string, role?: "offer"|"join" }} draft
 * @returns {string}
 */
export function sessionRecipe(draft) {
  const audience = canonicalAudience(draft?.audience || []);
  const key = String(draft?.keyFingerprint || "")
    .replace(/\s+/g, "")
    .toUpperCase();
  const role = draft?.role === "join" ? "join" : "offer";
  return [
    `agent.unlock ${key} | out $me`,
    "",
    `quorum.${role} to="${audience.join(",")}" key=$me | out $session`,
  ].join("\n");
}

/**
 * Pull an audience out of whatever was pasted.
 *
 * Takes an invite URL, a bare `#j=` fragment, or somebody typing four
 * fingerprints into a box, because all three happen and none of them is wrong.
 * Anything that is not a 40- or 64-character hex fingerprint is dropped by
 * `canonicalAudience` rather than reported: this is a paste box, and a
 * complaint about the `https://` in front of the list would be a complaint
 * about the reader having pasted the thing they were sent.
 *
 * @param {string} text
 * @returns {string[]}
 */
export function parseInviteAudience(text) {
  const found = String(text || "").match(/[0-9a-fA-F]{40,64}/g) || [];
  return canonicalAudience(found);
}
