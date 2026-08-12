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
import { findFingerprints, findShortKeyIds } from "../pgp/verify-fpr.js";

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
 * @typedef {object} SessionKeyRow
 * @property {string} fingerprint
 * @property {string} [uid]
 * @property {"pgp"|"ssh"|"raw"|string} [kind]  absent means a legacy vault
 *   record, which is definitionally pgp — `agent-ops.js` reads it the same way
 * @property {string} [protection]  passphrase | passkey | device | session
 * @property {boolean|undefined} [locked]  `sessionList`'s answer for this key,
 *   or undefined when it is not loaded and nothing observed the armor
 */

/**
 * The keys that could actually open a session, out of everything held here.
 *
 * A session signs an OpenPGP invite and every envelope after it, so the only
 * candidates are OpenPGP keys. The vault holds three kinds — `agent.save`
 * stores openssh-key-v1 blocks and bare JWKs beside PGP armor — and the key
 * picker was listing all of them. Choosing one produced a live `CryptoKey` from
 * `agent.unlock` and then a failure in `resolveGpgPrivateKey`, which wants
 * armor, several steps after the choice was made.
 *
 * Exported so the picker, its suggestions and the count behind "there is
 * nothing to choose" cannot answer this differently. That count getting it
 * wrong is how the original report happened one layer up: a number that
 * included keys the list could not offer meant "you have not chosen yet" was
 * shown to someone with nothing to choose.
 *
 * @param {SessionKeyRow[]} rows
 * @returns {SessionKeyRow[]}
 */
export function sessionKeyChoices(rows) {
  return (Array.isArray(rows) ? rows : []).filter((k) => {
    const kind = String(k?.kind || "pgp");
    return kind === "pgp";
  });
}

/**
 * Whether this key still owes an OpenPGP passphrase before it can sign.
 *
 * Two locks, and only one of them is the vault's. `vault.unlockKey` opens the
 * device-bound envelope and returns armor that may still be S2K-protected, so
 * "unlocked" and "usable" are different claims about the same key — the
 * distinction `sessionPut` records and this reads.
 *
 * Observation beats intent: `locked` came from parsing the armor that
 * `decryptKey` will be handed, so where it disagrees with `protection` it wins.
 * `protection` answers for a key that is not loaded, because that is all there
 * is to go on before an unlock — and it is what the mode *means*
 * ("passphrase: OpenPGP S2K/Argon2 locks the armored key before wrapping").
 *
 * `undefined` where neither settles it, and callers must stay silent on it. A
 * sentence about a passphrase that may not be owed is a refusal naming a state
 * the reader is not in, which is the failure this whole repair is about.
 *
 * @param {SessionKeyRow|null|undefined} key
 * @returns {boolean|undefined}
 */
export function keyOwesPassphrase(key) {
  if (!key) return undefined;
  if (typeof key.locked === "boolean") return key.locked;
  const protection = String(key.protection || "");
  if (protection === "passphrase") return true;
  if (protection === "device" || protection === "passkey") return false;
  return undefined;
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
 * `keyCount` is separate from `keyFingerprint` because "you have not chosen
 * one yet" and "there is nothing to choose" are different states that had the
 * same sentence.
 *
 * The empty sentence names *which* store, because My Keys shows two and calls
 * both of them keys: “Your keys” is `/api/v1/me/keys`, the public keys on your
 * account, and “Your browser vault” is `vault.js`'s IndexedDB private keys.
 * Only the second can sign. Sending someone to My Keys without saying which is
 * how this was reported the second time -- three keys on screen and a session
 * insisting there were none. With an empty vault, "Choose the key you are joining as" is an
 * instruction nobody can follow, and the Start button sat disabled beside it
 * with no reason attached -- so pressing it did nothing and said nothing, which
 * is how this was reported.
 *
 * `keyCount` counts keys that could *open a session* — `sessionKeyChoices`,
 * not everything the vault holds. Counting the rest brings the same bug back
 * one layer down: an ssh key makes "there is nothing to choose" false while
 * leaving nothing choosable.
 *
 * The passphrase clause is the other half of the same report. A
 * passphrase-protected key is the mode this app recommends, and choosing one
 * used to pass every check here and die inside `resolveGpgPrivateKey` on
 * OpenPGP's own words, several steps after the press — the refusal furthest
 * from the decision that caused it. `keyOwesPassphrase` knows before the press,
 * and the field it names is the one `agent.unlock` reads.
 *
 * @param {{ audience?: string[], keyFingerprint?: string, live?: boolean,
 *   keyCount?: number, key?: SessionKeyRow|null, passphraseBound?: boolean }} draft
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
    // A session is signed, so it cannot start without a key at all. Say which
    // of the two situations this is, because only one of them is a choice.
    issues.push(
      Number(draft?.keyCount || 0) === 0
        ? "No private key in this browser. A session signs the invite and every envelope after it, so it needs a key held here — the ones under “Your keys” on My Keys are public keys on your account and cannot sign. Make or import one under “Your browser vault”."
        : "Choose the key you are joining as — it signs the invite and every envelope after it."
    );
  }
  if (key && keyOwesPassphrase(draft?.key) === true && !draft?.passphraseBound) {
    // Only when it is *known* to be owed. `keyOwesPassphrase` returns undefined
    // where nothing established it, and asking for a passphrase a device key
    // does not want would be the same defect pointing the other way.
    issues.push(
      "This key is passphrase-protected, and no key passphrase is bound. Opening it in the vault does not remove OpenPGP's own lock — the invite is signed with the key itself, so the passphrase is owed before anything can be signed. Type it under Inputs → Key passphrase."
    );
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
 * Anything that is not a fingerprint is dropped rather than reported here:
 * this is a paste box, and a complaint about the `https://` in front of the
 * list would be a complaint about the reader having pasted the thing they were
 * sent. What *is* said about a paste is `pasteReadout`'s job, below.
 *
 * The extraction itself belongs to `findFingerprints`, beside the normaliser
 * it has to agree with. It used to live here as a contiguous
 * `[0-9a-fA-F]{40,64}`, which is a stricter alphabet than
 * `normalizeFingerprintInput` accepts — so the grouped form this product
 * prints everywhere matched nothing and every such paste silently yielded an
 * empty audience.
 *
 * `pasteReadout` is what the product calls, because an audience is not an
 * answer to a person: this returns the same empty list for text with no
 * fingerprint in it, text holding a short key id, and a paste of people who
 * were already in the room. This is that reading, and the readout below is
 * built on it so the sentence and the room can never disagree.
 *
 * @param {string} text
 * @returns {string[]}
 */
export function parseInviteAudience(text) {
  return canonicalAudience(findFingerprints(text));
}

/**
 * The marker an invite link carries — see `hashForJoin`, which writes it.
 *
 * A test for the *shape*, not a second parser: the fingerprints still come out
 * of the one extractor, so a link and a bare list cannot be read as different
 * audiences. What the marker adds is the one thing the list alone cannot say —
 * that this text was sent by somebody who is starting the session, which
 * settles the role.
 */
const INVITE_MARKER = /[#&?]j=/;

/**
 * @typedef {object} PasteReadout
 * @property {"invite"|"fingerprints"|"short-id"|"nothing"} kind
 * @property {string[]} added     fingerprints this paste puts in the room
 * @property {string[]} already   fingerprints it named that were already there
 * @property {string[]} audience  the room after the paste, canonical
 * @property {"join"|null} role   the role this paste settles, or null to leave it
 * @property {"brand"|"warn"|"muted"} tone
 * @property {string} sentence
 */

/**
 * What a paste did, in a sentence — the half that was missing entirely.
 *
 * The box committed on blur, at a moment the reader did not choose, and said
 * nothing afterwards in any case. When it found nothing there was no message
 * and nothing to press again, so the only two outcomes a person could tell
 * apart were "the list grew" and "something is broken".
 *
 * Four states, because they ask for four different next moves:
 *
 * - **invite** — a link. It carries the whole audience *and* the fact that
 *   whoever sent it is the one publishing, so the role is settled here rather
 *   than left as a toggle the reader has to reason about.
 * - **fingerprints** — a list. Says how many were added and how many were
 *   already in the room, because "nothing appeared to happen" is otherwise
 *   indistinguishable from a paste that did nothing.
 * - **short-id** — 8, 16 or 32 hex characters. A short id is a suffix of a
 *   fingerprint, so it can name more than one key and no room can be derived
 *   from it. This read as nothing at all before, which is the worst reading:
 *   the reader pasted a real identifier and was told silence.
 * - **nothing** — says what a fingerprint looks like, that the spaces and
 *   colons in a printed one are fine, and that two of them need a delimiter
 *   between them, which is the one arrangement the extractor refuses.
 *
 * It lives here rather than in the widget for the reason at the top of this
 * module: a sentence written inside a component is a sentence no test can pin.
 *
 * @param {string} text
 * @param {{ audience?: string[] }} [opts] the room as it stands
 * @returns {PasteReadout}
 */
export function pasteReadout(text, opts = {}) {
  const current = canonicalAudience(opts?.audience || []);
  const inRoom = new Set(current);
  const raw = String(text || "");
  const found = parseInviteAudience(raw);
  const added = found.filter((fpr) => !inRoom.has(fpr));
  const already = found.filter((fpr) => inRoom.has(fpr));
  const audience = canonicalAudience([...current, ...found]);
  const people = (n) => `${n} ${n === 1 ? "person" : "people"}`;
  // "One was already in the room" rather than "1": these are people, and the
  // count is being read mid-sentence, not scanned in a table.
  const alreadySentence =
    already.length === 1
      ? "One was already in the room."
      : `${already.length} were already in the room.`;

  // An invite is checked first because the same text is also a list of
  // fingerprints, and the two readings differ in what they settle rather than
  // in what they contain.
  if (INVITE_MARKER.test(raw) && found.length >= 2) {
    return {
      kind: "invite",
      added,
      already,
      audience,
      role: "join",
      tone: "brand",
      sentence:
        `That invite names ${people(found.length)}. ` +
        (added.length ? `Added ${added.length}. ` : "They were all here already. ") +
        "You are set to joining, because whoever sent it is the one who publishes the invite — press Join before they start.",
    };
  }

  if (found.length) {
    return {
      kind: "fingerprints",
      added,
      already,
      audience,
      role: null,
      tone: added.length ? "brand" : "muted",
      sentence: added.length
        ? `Added ${added.length}.${already.length ? ` ${alreadySentence}` : ""}`
        : `Nothing new. ${alreadySentence}`,
    };
  }

  const shortIds = findShortKeyIds(raw);
  if (shortIds.length) {
    return {
      kind: "short-id",
      added,
      already,
      audience,
      role: null,
      tone: "warn",
      sentence:
        `${shortIds[0]} is a short key id, not a fingerprint. More than one key can end in the same ` +
        "characters, so it names a person only by luck — and a room is derived from full fingerprints, " +
        "so there is nothing here to derive one from. Paste the whole fingerprint, or search for them by name.",
    };
  }

  return {
    kind: "nothing",
    added,
    already,
    audience,
    role: null,
    tone: "warn",
    sentence:
      "No fingerprint in that. One is 40 hex characters, or 64 for a v6 key — the spaces, colons and " +
      "hyphens in a printed one are fine. For several, put each on its own line or separate them with " +
      "commas; two run together cannot be told apart.",
  };
}
