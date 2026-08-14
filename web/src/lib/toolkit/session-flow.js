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
 * 2. **The signalling relay keeps no history, and the protocol no longer needs
 *    it to.** Azure Web PubSub brokers to the connections that are in the group
 *    at the moment of the send; there is no backlog for a late arrival. That
 *    used to mean the ordering was load-bearing — the creator's invite went out
 *    exactly once, and a joiner arriving a second later was in the right room
 *    and never saw the introduction. `sessionReadout` said so, and told a
 *    stalled creator to start over with the other side already listening.
 *
 *    A joiner now announces itself when it joins (`NotebookSession._onKnock`)
 *    and the creator answers with the same invite, once per member. So the
 *    remedy for a silent room is no longer "start it again": if nothing is
 *    happening, nobody is there — the other end has not opened the room, or the
 *    two audiences differ and each side derived a room of its own. That is what
 *    the copy below has to say, because "restart it" would now be advice that
 *    fixes nothing and hides the real cause.
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
 * 4. **Confirmation and attestation are different claims about the same peer.**
 *    Confirmed means *this channel belongs to that key*, decided by the
 *    transport, automatically, about the present moment. Attested means *that
 *    key signed a document naming the manifest this notebook derives*, decided
 *    by a person pressing, about a notebook. A room can be fully confirmed and
 *    attested by nobody, and the two verdicts sit on one row precisely so that
 *    reading is available — `attestationVerdict` and `confirmationReadout` are
 *    deliberately separate functions returning separate badges, because a single
 *    "trusted" chip would merge two proofs that fail for different reasons.
 *
 * @module lib/toolkit/session-flow
 */

import { summarizeAttestation } from "./attest.js";
import { canonicalAudience } from "../notebook/room.js";
import { roomRoster } from "../notebook/roster.js";
import { findFingerprints, findShortKeyIds } from "../pgp/verify-fpr.js";
import { keyOwesPassphrase, keyPower, keyPowerReadout } from "./key-power.js";

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
        ? "Your signed invite is published, and it is published again for anyone who joins later and announces themselves — so this is not about who pressed first. An empty room means nobody has arrived: either they have not started their side, or their list of fingerprints differs from yours and derives a different room."
        : "You are in the room and you have announced yourself, so a creator who is here answers with a signed invite whether they started before you or after. Nothing is arriving, which means nobody is publishing one — they have not started, or their audience differs from yours and names another room.",
      next: creator
        ? "Check they pressed Join, and that their audience is the same list of fingerprints as yours — every one, including your own. Restarting this side changes nothing."
        : "Stay here; there is nothing to restart on this side. Check that their audience is the same list of fingerprints as yours — a list that differs by one puts each of you in a room of your own.",
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
 * Has this peer signed an attestation over the manifest *this* machine derives?
 *
 * `null` where there is nothing to compare against — no notebook, or a notebook
 * that does not compile, so no digest. That is not the same state as "they have
 * not attested" and must not be drawn as one: nobody has been asked yet, and a
 * row saying otherwise would report a refusal that never happened.
 *
 * The comparison is against the digest and nothing else. A peer who attested to
 * a different digest has attested to a different notebook, which is exactly the
 * drift this is worth showing — and it reads here as *not this one*, because
 * that is what it is.
 *
 * @param {{ attested?: { manifest?: string }[] }} peer  a roster row
 * @param {string} digest  the manifest digest this browser derived
 * @returns {{ tone: "brand"|"warn", verdict: string, why: string }|null}
 */
export function attestationVerdict(peer, digest) {
  const want = String(digest || "").trim().toLowerCase();
  if (!want) return null;
  const rows = Array.isArray(peer?.attested) ? peer.attested : [];
  const mine = rows.some((a) => String(a?.manifest || "").toLowerCase() === want);
  if (mine) {
    return {
      tone: "brand",
      verdict: "attested",
      why: "They signed a document naming this run's manifest digest, and this browser checked that signature against their key. It says they saw this notebook — not when, and not that they will run it.",
    };
  }
  const other = rows.length;
  return {
    tone: "warn",
    verdict: "not attested",
    why: other
      ? `They have attested to ${other} manifest${other === 1 ? "" : "s"}, none of them this one — so the notebook they saw is not the notebook here.`
      : "Nothing signed by them names this manifest. They may not have been asked, and attesting is theirs to press.",
  };
}

/**
 * @typedef {object} AttestationReadout
 * @property {"brand"|"warn"|"muted"} tone
 * @property {string} headline
 * @property {string} why
 * @property {string[]} attested peers with an attestation over this manifest
 * @property {string[]} missing  peers the manifest names with nothing over it
 * @property {number} total      how many the manifest expects; 0 means no
 *   fraction is drawable and coverage says nothing about who agreed
 */

/**
 * Attestation coverage for this run, in two sentences.
 *
 * The headline is `summarizeAttestation`'s, not a second one written here, for
 * `keyPowerReadout`'s reason: the check that decides coverage and the line that
 * reports it must not be able to disagree. What this adds is the reading —
 * `manifestAttestedBy` answers *is this covered* in the vocabulary of mismatched
 * fields, and a person is asking *who still has not*.
 *
 * **The caveats are not optional and are not a footnote.** `attest.js` is
 * explicit that an attestation is evidence its signer saw a digest and never
 * evidence of *when*, and that the ordering it supports holds among the people
 * in the room rather than for anybody shown the bundle afterwards. A coverage
 * badge with that sentence removed is the badge overclaiming, so they are
 * carried out of the result rather than re-typed here.
 *
 * **All of them, not the first.** The list is not decoration in a fixed order:
 * the second entry is either "the manifest lists no peers, so coverage is
 * vacuous" or "N attestations arrived with no attester", and both are the
 * report contradicting the number beside it. Printing `caveats[0]` and dropping
 * the rest is how a vacuous `true` reads as agreement.
 *
 * `total` is what the count on screen may divide by, and it is zero exactly when
 * the manifest expects nobody — in which case there is no fraction to draw and
 * the caveat is the whole of what this has to say.
 *
 * @param {Awaited<ReturnType<
 *   import("./attest.js").manifestAttestedBy>>|null|undefined} coverage
 * @returns {AttestationReadout|null}  null when there is nothing to report on
 */
export function attestationReadout(coverage) {
  if (!coverage?.digest) return null;
  const missing = [...(coverage.missing || [])];
  const attested = [...(coverage.attested || [])];
  const total = attested.length + missing.length;
  const caveats = (coverage.caveats || []).join(" ");
  if (coverage.ok) {
    return {
      tone: "brand",
      headline: summarizeAttestation(coverage),
      why: `Everyone this notebook names has signed over this manifest. ${caveats}`,
      attested,
      missing,
      total,
    };
  }
  return {
    tone: missing.length === total ? "muted" : "warn",
    headline: summarizeAttestation(coverage),
    why: missing.length
      ? `${missing.length} of ${total} in this notebook have signed nothing over this manifest. ${caveats}`
      : `The attestations held here are not all over this manifest. ${caveats}`,
    attested,
    missing,
    total,
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
 * **Expiry is the second half of the same rule**, and it was missing. An
 * expired OpenPGP key is `kind: "pgp"`, so it passed this filter, sat in the
 * chooser, unlocked without complaint — the vault stores no opinion about
 * validity — and then failed at the signature in OpenPGP's own words, at the
 * same distance from the choice as the ssh case above. `keyPower` calls both of
 * those `unusable` in one word, so this filter is now that word rather than a
 * second list of what cannot sign.
 *
 * Exported so the picker, its suggestions and the count behind "there is
 * nothing to choose" cannot answer this differently. That count getting it
 * wrong is how the original report happened one layer up: a number that
 * included keys the list could not offer meant "you have not chosen yet" was
 * shown to someone with nothing to choose.
 *
 * @param {SessionKeyRow[]} rows
 * @param {number} [now]  Unix milliseconds
 * @returns {SessionKeyRow[]}
 */
export function sessionKeyChoices(rows, now = Date.now()) {
  return (Array.isArray(rows) ? rows : []).filter(
    (k) => k && keyPower(k, now) !== "unusable"
  );
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
 * The empty sentence names *which* store, because there are two and both were
 * once called keys on one page: `/api/v1/me/keys` holds the public keys on your
 * account — `/published` now, and only that — while `vault.js`'s IndexedDB
 * holds the private keys, in the Keys tray. Only the second can sign. Pointing
 * somebody at "My Keys" without saying which half is how this was reported the
 * second time -- three keys on screen and a session insisting there were none.
 * With an empty vault, "Choose the key you are joining as" is an
 * instruction nobody can follow, and the Start button sat disabled beside it
 * with no reason attached -- so pressing it did nothing and said nothing, which
 * is how this was reported.
 *
 * `keyCount` counts keys that could *open a session* — `sessionKeyChoices`,
 * not everything the vault holds. Counting the rest brings the same bug back
 * one layer down: an ssh key makes "there is nothing to choose" false while
 * leaving nothing choosable.
 *
 * `heldCount` is what stops that correction from lying in the other direction.
 * Once `keyCount` excludes everything `unusable`, a browser holding only ssh
 * keys or only expired ones has `keyCount === 0` — and "No private key in this
 * browser" is then a sentence about a vault with keys in it, which is exactly
 * the class of refusal this module exists to stop. Three states, three
 * sentences: nothing held, nothing held that can sign, nothing chosen yet.
 *
 * The passphrase clause is the other half of the same report. A
 * passphrase-protected key is the mode this app recommends, and choosing one
 * used to pass every check here and die inside `resolveGpgPrivateKey` on
 * OpenPGP's own words, several steps after the press — the refusal furthest
 * from the decision that caused it. `keyOwesPassphrase` knows before the press,
 * and the field it names is the one `agent.unlock` reads.
 *
 * @param {{ audience?: string[], keyFingerprint?: string, live?: boolean,
 *   keyCount?: number, heldCount?: number, key?: SessionKeyRow|null,
 *   passphraseBound?: boolean }} draft
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
    // of the three situations this is, because only one of them is a choice.
    const choosable = Number(draft?.keyCount || 0);
    const held = Number(draft?.heldCount || 0);
    issues.push(
      choosable > 0
        ? "Choose the key you are joining as — it signs the invite and every envelope after it."
        : held > 0
          ? "None of the keys in this browser can open a session. A session signs an OpenPGP invite, so an SSH or raw key cannot open one and neither can an expired key — the Keys tray says which each of yours is. Generate or import an OpenPGP key there."
          : "No private key in this browser. A session signs the invite and every envelope after it, so it needs a key held here — the ones on Published are public keys on your account and cannot sign. Make or import one in the Keys tray, under “Your browser vault”."
    );
  }
  if (key && draft?.key && keyPower(draft.key) === "unusable") {
    // A chosen key the picker would not offer today. It reaches here because
    // the fingerprint is held in the draft while the *list* is re-derived every
    // render: a key that expires with the sheet open, or a choice made before
    // this filter existed, leaves a fingerprint selected that nothing can sign
    // with. Without this the picker refuses to show it and Start goes right on
    // being available — a refusal removed from the list is not a refusal.
    //
    // The sentence is `keyPowerReadout`'s, not a second one written here, so
    // the row in the tray and the blocker under Start say the same thing about
    // the same key.
    issues.push(keyPowerReadout(draft.key).why);
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
 * ## Both cells are placed on the person opening the session
 *
 * `agent.unlock` reaches the vault of *whoever runs it*, and `plan.js` already
 * asks about exactly that: a cell running a vault op under no `@peer` header
 * raises `vault-locality` — "a fingerprint in a recipe does not say whose vault
 * holds it. Which peer runs this cell? Write `@peer` at the head of it." This
 * used to ship a cell that tripped its own product's question and then answered
 * it nowhere, and the cost was paid by whoever received the notebook: these
 * cells travel with it (`notebook-share.js`), so a peer who adopted a shared
 * notebook and pressed Run stopped at `agent.unlock <the sender's fingerprint>`
 * with "Key not found in vault" — asked to open a key that is, correctly, not
 * theirs. The `quorum.` cell is placed for the same reason one step on: it is
 * this machine entering the room, and re-entering a room somebody else is
 * already in is not a cell anybody else can perform.
 *
 * So the header is written here, where the answer is known, and nothing about
 * how a notebook travels changes: both ends still hold *character-identical*
 * text, so every manifest and cell digest still meets, and the placement gate
 * that already declines a peer's cells declines these ones too. Stripping them
 * on the way out instead would break both halves of that — the two ends would
 * derive different manifests, and cell indices are the coordinate every offer
 * is addressed by, which a strip renumbers differently on each machine.
 *
 * The header is `roomRoster`'s answer for this key, which is now the key's own
 * fingerprint — so it is what every other browser in the room calls this
 * machine, with nothing carried between them to make it so. With no key of ours
 * in the audience `roomRoster` returns "" and no header is written: that is the
 * state `startIssues` refuses the press for, and a header naming nobody would be
 * a worse account of it than none.
 *
 * It reads `roomRoster` rather than the fingerprint in `keyFingerprint`
 * directly, although the two are now the same forty characters. The question
 * being asked is "what does the room call me", and answering it from the
 * roster is what keeps `sessionRecipe` writing whatever `planRun` will bind
 * against — including the empty answer for a key the audience does not contain,
 * which a direct read could not produce.
 *
 * A hand-typed `agent.unlock` is untouched by all of this. It is the author's
 * sentence about their own notebook: solo, it runs here as it always has;
 * placed, `planRun` puts the same `vault-locality` question to them and the
 * gate carries their answer. Guessing at one by matching the fingerprint would
 * be this module deciding what somebody else's cell meant.
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
  const { me } = roomRoster(audience, [], key);
  const header = me ? `@${me}\n` : "";
  return [
    `${header}agent.unlock ${key} | out $me`,
    "",
    `${header}quorum.${role} to="${audience.join(",")}" key=$me | out $session`,
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
