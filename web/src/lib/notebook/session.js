/**
 * The notebook's full-mesh WebRTC data-channel session.
 *
 * Creators post a PGP-signed invite proving key possession; joiners mesh only
 * after verifying that invite. Pairwise session keys use per-peer ephemeral
 * ECDH with transcript-bound HKDF and key confirmation (data-channel PFS).
 *
 * **This module is a consumer of `lib/webrtc/`, not a peer of it.** No WebRTC
 * built-in is constructed, driven, or *held* here. A peer's transport is a
 * `PeerLink` — an opaque handle from `webrtc/peer-link.js` — and everything
 * this layer does to it is a method on that handle. The connection inside it
 * is never unwrapped: there is no `pc` on a peer record, and
 * `src/test/notebook-layering.test.js` fails if one comes back.
 *
 * That is the difference between this and the first extraction, which moved the
 * driver out and then took the connection straight back off the link it
 * returned — nine `.pc` reads, `signalingState` and `close` among them, which is
 * the transport with two helpers factored out rather than a layer above it.
 *
 * SDP parsing lives in `webrtc/sdp.js`; the link inventory, the default ICE
 * server list, the glare rule and the selected-candidate stats in
 * `webrtc/link-registry.js`, `ice.js`, `negotiation.js` and `candidates.js`.
 * Deleting `lib/notebook/` leaves `peer.*` and `rtc.*` standing.
 *
 * **The room is not a place, it is a name.** Membership in the signalling
 * group is asserted by holding a token and re-asserted every time the relay
 * recycles (`signaling.js`); it is *withdrawn* by the room moving somewhere
 * the withdrawn party has no token and no way to derive one (`rotateRoom`).
 * Neither mechanism asks the signalling service to do anything it has an API
 * for, because it has none: no membership to list, no connection this
 * application can name, and no reason to hang up on a connection whose token
 * expired after it was already open.
 *
 * What stays is the protocol: the PGP audience, the signed invite, the relay,
 * the room, the roster, key derivation, key confirmation, and the mesh policy
 * that decides *which* links exist and who offers. The one piece of transport
 * this layer still touches directly is a live data channel's `send` and
 * `readyState` — because the frames on it are this layer's own, sealed under a key
 * this layer holds and the transport cannot read.
 *
 * **The session is a courier, not a signer.** Five more payload kinds ride the
 * `session` frame beside `kc` and `chat` — a signed run manifest, a signed
 * manifest attestation, a signed notebook proposal, a cell handoff offer and a
 * signed cell result. The four signed ones arrive already signed and leave
 * already signed: `publishManifest`, `shareNotebook` and `sendResult` refuse
 * anything that is not a cleartext-signed document, and there is no path from a
 * payload to `this.privateKey`. The private key is here to seal signalling
 * envelopes for a room this session is already in, and a commitment about what a
 * notebook will do is not that. `approval-gate.js` puts it as *"Grants are
 * minted only by a human clicking, never by a param."*
 *
 * The mirror of that rule is that **an arriving manifest runs nothing and
 * attests to nothing**. It is verified, parsed and handed to `onManifest` as an
 * object a person can look at — the same discipline as an `#r=` link, which
 * `useNotebook.loadFromHash` loads without running. Answering a manifest is a
 * recipe somebody types.
 *
 * **A notebook proposal is the one document that arrives before there is
 * anything to check it against, and it is signed for exactly that reason.**
 * `shareNotebook` broadcasts the recipe text a person pressed Share on, and
 * `_onDocument` verifies it against the sending peer's own key before anybody
 * sees it. Until it existed nothing in this product ever gave a joiner the
 * notebook: an invite carries an audience and no recipe, and `acceptHandoffOffer`
 * checks an arriving offer against the recipient's *own* text — so a joiner who
 * had never been handed any refused every offer with `unknown-manifest`, a
 * refusal whose own sentence names a step no code performed. Nothing about the
 * digest gate changed. Both ends still hold the same text and still prove it by
 * digest; one of them may now receive it, signed, instead of being required to
 * retype it. **Adopting is still a person's**, and it happens in the shell:
 * `onNotebook` hands up a parsed proposal and this class replaces nobody's
 * notebook.
 *
 * **A handoff offer runs nothing either, and it is not signed.** `sendOffer`
 * carries the JSON `lib/toolkit/handoff.js` built, to *one* confirmed peer,
 * because an offer is a delivery rather than a commitment: it asserts nothing
 * the recipient takes on trust, since every field of it is checked against the
 * recipient's own plan, their own notebook and a manifest they already hold.
 * Signing it would mean minting a document no recipe produces, which is the
 * temptation this layer refused for the manifest. What arrives is parsed and
 * handed to `onOffer` as something pending; **nothing here accepts it**, and
 * there is no method on this class that could — accepting registers slot
 * bindings, and that is a person's act in the shell above.
 *
 * **A result is signed, and arrives just as pending.** It is the answer to an
 * offer, and `_onResult` checks the signature against that one peer's key and
 * hands the document up. It does not check it against a plan, a manifest or a
 * record of what this peer offered, and it must not: whether a returned value is
 * one this machine asked for is `acceptCellResult`'s question, asked of a plan
 * and a notebook this layer does not have. **Nothing here registers a slot and
 * nothing here restarts a run** — a courier that resumed a stopped notebook
 * because a frame arrived would be the worst version of this whole exchange.
 * This class also keeps no record of the offers it *sent*: a record kept in
 * order to judge what comes back is a decision, and the deciding is done where
 * the plan is.
 *
 * All five kinds inherit `chat`'s refusal exactly: nothing is believed from a
 * peer whose key is not confirmed. `lib/notebook/documents.js` holds what
 * happens after that — above all, that a document is checked against *this*
 * peer's key and no other.
 *
 * **Why the driver could move, after two commits said it could not.**
 * `derivePairwiseSessionKey` binds **both DTLS fingerprints** into the
 * transcript, and the local one is minted from the local description *inside*
 * negotiation. Moving negotiation moves the instant that fingerprint becomes
 * known, and the failure mode of getting it subtly wrong is key confirmation
 * *succeeding anyway* over a transcript no longer bound to the transport —
 * green tests, broken binding (§59b). What made it safe was not care: it was
 * `src/test/notebook-dtls-binding.test.js`, a test that **fails when tampered**.
 * Two real sessions mesh over a fake transport; a signalling relay rewrites one
 * peer's fingerprint and re-seals under that peer's own key, so nothing in the
 * PGP layer can see it; both ends must end up unconfirmed. That test was
 * written and watched fail-when-tampered *before* the extraction, and it holds
 * the driver's return contract in place afterwards: a link's offer and its
 * `answerRemoteOffer` hand back `{ sdp, dtlsFingerprint }` together, so an SDP
 * cannot be signalled without the fingerprint that belongs to it.
 *
 * @module lib/notebook/session
 */

import {
  assertInvite,
  buildInvitePayload,
  combineDtlsFingerprints,
  derivePairwiseSessionKey,
  decryptSessionPayload,
  encryptSessionPayload,
  exportEcdhPublicJwk,
  fetchAudienceKeys,
  generateEcdhKeyPair,
  importEcdhPublicJwk,
  openSignalingEnvelope,
  randomNonceHex,
  requireSelfInAudience,
  sealSignalingEnvelope,
} from "./crypto.js";
import {
  assertDocumentFits,
  looksCleartextSigned,
  readHandoffOffer,
  readSignedAttestation,
  readSignedManifest,
  readSignedNotebook,
  readSignedResult,
} from "./documents.js";
import { canonicalAudience, deriveRoomMaterial, isValidRoomId } from "./room.js";
import { classifyChannelFrame, createSeenSet, shouldRelay } from "./relay.js";
import { openSignalingChannel } from "./signaling.js";
import { zeroKeyMaterial } from "../pgp/memory.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";
import { formatFingerprint } from "../utils.js";
import {
  deregisterLink,
  patchLink,
  registerLink,
} from "../webrtc/link-registry.js";
import { iceServersOrDefault } from "../webrtc/ice.js";
import { openPeerLink } from "../webrtc/peer-link.js";

/**
 * @typedef {object} NotebookPeerState
 * @property {string} fingerprint
 * @property {"unknown"|"verified"|"connecting"|"connected"|"failed"} status
 * @property {boolean} pgpVerified
 * @property {boolean} kcVerified
 * @property {boolean} isInitiator
 * @property {import("../webrtc/peer-link.js").PeerLink|null} link
 *   The transport, as a handle. What is inside it is the driver's business.
 * @property {RTCDataChannel|null} channel
 * @property {CryptoKey|null} sessionKey
 * @property {string|null} transcriptHash
 * @property {JsonWebKey|null} ecdhPublicJwk
 * @property {string|null} helloNonce
 * @property {string} localDtls
 * @property {string} remoteDtls
 * @property {CryptoKeyPair|null} localEcdh
 * @property {JsonWebKey|null} localEcdhJwk
 * @property {string|null} localHelloNonce
 * @property {boolean} kcSent
 * @property {boolean} polite      perfect negotiation: lower fingerprint yields on glare
 * @property {boolean} makingOffer
 * @property {boolean} ignoreOffer
 * @property {Set<string>} attested
 *   Manifest digests this peer has attested to, each established by a signature
 *   this session checked against this peer's own key. Bounded — see
 *   `ATTESTED_PER_PEER_CAP`.
 * @property {string|null} publishedManifest
 *   Digest of the last manifest this peer put in front of the room, or null.
 *   One slot rather than a list: a peer's commitment is whatever they last
 *   stood behind, and the documents themselves reach the application through
 *   `onManifest`.
 * @property {Set<string>} offered
 *   Cell handoff offers this peer has held out, as `manifest:cell`. A record
 *   that an offer arrived, never that it was taken — nothing in this class can
 *   take one. Bounded the same way `attested` is.
 * @property {Set<string>} returned
 *   Cell results this peer has signed and sent back, as `manifest:cell`, each
 *   established by a signature this session checked against this peer's own key.
 *   A record that a claim arrived, never that it was believed: whether the cell
 *   was theirs to run and whether the values may be registered are questions for
 *   a plan this layer does not hold. Bounded the same way `attested` is.
 */

/**
 * @typedef {object} NotebookSessionOpts
 * @property {string} roomId
 * @property {string[]} audienceFprs
 * @property {import("openpgp").PrivateKey} privateKey
 * @property {string} myFingerprint
 * @property {"creator"|"joiner"} [role]
 * @property {RTCIceServer[]} [iceServers]
 *   Omitted (or null) takes the built-in STUN defaults; `[]` is a deliberate
 *   *no third party* and is honoured as written — host candidates only.
 * @property {(peers: Map<string, NotebookPeerState>) => void} [onRoster]
 * @property {(msg: { from: string, text: string, ts: number }) => void} [onChat]
 * @property {(doc: {
 *   from: string, digest: string, signed: string, ts: number,
 *   manifest: import("../toolkit/manifest.js").RunManifest,
 * }) => void} [onManifest]
 *   A manifest that arrived, was checked against the sender's key, and parsed.
 *   Nothing has been run and nothing has been attested — this is a document
 *   somebody can now look at.
 * @property {(doc: {
 *   from: string, digest: string, signed: string, ts: number,
 *   attestation: import("../toolkit/attest.js").ManifestAttestation,
 * }) => void} [onAttestation]
 * @property {(doc: {
 *   from: string, signed: string, ts: number,
 *   proposal: import("../toolkit/notebook-share.js").NotebookProposal,
 * }) => void} [onNotebook]
 *   A notebook proposal that arrived, was checked against the sender's key, and
 *   parsed. **Nothing has been adopted**: this is recipe text somebody can now
 *   look at, and replacing a notebook with it is a decision made where a
 *   notebook exists — which is not here. The rule the shell above keeps is that
 *   an empty notebook adopts (that is the joiner's whole problem, and requiring
 *   a press to receive the first one would reproduce it) while a notebook with
 *   the local user's own work in it does not, and waits for one.
 * @property {(doc: {
 *   from: string, cell: number, manifest: string, ts: number,
 *   offer: import("../toolkit/handoff.js").HandoffOffer,
 * }) => void} [onOffer]
 *   A cell handoff offer that arrived from a confirmed peer and parsed. It is
 *   **pending**: nothing has been checked against a plan, no slot has been
 *   registered and no cell has run. Accepting is `acceptHandoffOffer` plus a
 *   person, in the shell above.
 * @property {(doc: {
 *   from: string, cell: number, manifest: string, signed: string, ts: number,
 *   result: import("../toolkit/handoff.js").CellResult,
 * }) => void} [onResult]
 *   A cell result that arrived from a confirmed peer, was checked against that
 *   peer's key and parsed. Equally **pending**: the signature says this peer
 *   made the claim, and nothing yet says the claim is about a cell this peer
 *   offered them or that the values may be registered. `acceptCellResult` plus
 *   a person answers both, and the run this result unblocks is restarted by
 *   whoever presses Run.
 * @property {(status: string) => void} [onStatus]
 * @property {() => void} [onOwnKeyElsewhere]
 *   Another session is signing as this session's key — see
 *   `_noteOwnKeyElsewhere`. Called at most once, and it changes nothing about
 *   the room: it is a fact the layer above needs in order to say why a wait is
 *   never going to end.
 * @property {(err: Error) => void} [onError]
 */

/**
 * How many distinct manifest digests one peer's attestations may occupy.
 *
 * A confirmed peer can still be a broken one, and every attestation is a fresh
 * 64-character string it chose. The cap keeps a peer's roster entry flat under
 * that, evicting oldest-first the way `createSeenSet` does; a room agreeing on
 * more than this many manifests at once has a different problem.
 */
const ATTESTED_PER_PEER_CAP = 64;

/**
 * What each broadcast document is called in a sentence a person reads.
 *
 * Two of the three are called what the wire calls them. `notebook` is not: the
 * wire kind names the *thing* being carried and the sentence has to name the
 * *document* carrying it, or a refusal reads as though a notebook were the file
 * that failed rather than the proposal about one.
 * @type {Record<string, string>}
 */
const DOCUMENT_NOUN = Object.freeze({
  manifest: "manifest",
  attestation: "attestation",
  notebook: "notebook proposal",
});

export class NotebookSession {
  /** @param {NotebookSessionOpts} opts */
  constructor(opts) {
    this.roomId = String(opts.roomId || "")
      .trim()
      .toUpperCase();
    if (!isValidRoomId(this.roomId)) throw new Error("Invalid room id");
    this.myFpr = normalizeFingerprintInput(opts.myFingerprint);
    this.audienceFprs = requireSelfInAudience(this.myFpr, opts.audienceFprs);
    this.privateKey = opts.privateKey;
    this.role = opts.role === "joiner" ? "joiner" : "creator";
    // `iceServersOrDefault`, not `?.length ?:` — an empty list is a user who
    // asked for no third party, and this layer is the last one that could
    // overrule them. It no longer can.
    this.iceServers = iceServersOrDefault(opts.iceServers);
    this.onRoster = opts.onRoster;
    this.onChat = opts.onChat;
    this.onManifest = opts.onManifest;
    this.onAttestation = opts.onAttestation;
    this.onNotebook = opts.onNotebook;
    this.onOffer = opts.onOffer;
    this.onResult = opts.onResult;
    this.onStatus = opts.onStatus;
    this.onOwnKeyElsewhere = opts.onOwnKeyElsewhere;
    this.onError = opts.onError;

    /**
     * Whether an envelope this session did not send has arrived signed by this
     * session's key — `_noteOwnKeyElsewhere` is what sets it, and it is latched
     * because the condition is a fact about who holds the key rather than a
     * state that comes and goes.
     */
    this.ownKeyElsewhere = false;

    /** @type {Map<string, NotebookPeerState>} */
    this.peers = new Map();
    /** @type {Map<string, import("openpgp").Key>} */
    this.audienceKeys = new Map();
    /** Invite-level ECDH (proof material in invite; not used for session KDF). */
    /** @type {CryptoKeyPair|null} */
    this._inviteEcdh = null;
    this.inviteNonce = "";
    /**
     * Audience members this session has already put an invite in front of, by
     * fingerprint.
     *
     * The bound on republishing, and it is a bound on *who* rather than on how
     * often: a peer is served once per session and never again, so a member
     * that re-announces — a relay recycle, a reload, a peer with a bug — gets
     * silence rather than another invite. A timer would have made the storm
     * slower instead of impossible, and two creators in one room would still
     * have answered each other forever.
     *
     * Empty for a joiner, always: a joiner holds the *nonce* of the invite it
     * verified but not the material to mint one, and re-signing the creator's
     * invite under its own key fails `assertInvite`'s "initiator must match
     * signer". Only the session that published an invite can publish it again.
     * @type {Set<string>}
     */
    this._invited = new Set();
    /**
     * Whether `stop()` has run. Read only by `_sealAndSend`, which explains
     * there why a torn-down session's late signalling is dropped in silence
     * while `_publish`'s refusal keeps its voice.
     */
    this._stopped = false;
    this.initiatorFpr = this.role === "creator" ? this.myFpr : "";
    this.inviteVerified = this.role === "creator";
    this._meshing = this.role === "creator";
    /** @type {import("./signaling.js").SignalingChannel|null} */
    this._relay = null;
    /**
     * Rotation counter. Epoch 0 is the room the audience derives to, so a
     * session that never rotates is byte-for-byte the room it always was.
     */
    this.epoch = 0;
    /**
     * The full room digest. `roomId` is its first 80 bits and is the part that
     * can be read aloud; this is the part that buys a token for the group
     * where signalling is broadcast, and it is never published — not in an
     * envelope, not to the signalling service, not to the portal.
     * @type {string}
     */
    this._roomKey = "";
    /**
     * Mixed into the room material from epoch 1 onward. Minted by whoever
     * rotates and delivered sealed to the members who stay, so the group the
     * room moves to is not derivable by the member it left behind.
     * @type {string}
     */
    this._rotationSecret = "";
    /** Set while `rotateRoom` is rearranging the room under us. */
    this._rotating = false;
    /**
     * Envelope dedupe — one armored blob is handled once, ever, whichever wire
     * delivered it. The mailbox's per-room sequence numbers used to serve this
     * on the relay path and the seen-set on the channel path; a relay that
     * echoes a publish back to its sender has no sequence to dedupe on, and
     * the two paths were never deduped against each other anyway.
     */
    this._envSeen = createSeenSet();
    /**
     * Inbound envelopes are handled one at a time, in arrival order.
     *
     * Both wires deliver in order — a data channel is ordered by default and
     * the relay serialises a group's broadcasts — and the handler used to
     * throw that away by starting each envelope as its own detached promise.
     * Mostly harmless, until an envelope *changes what the next one means*: a
     * rotation announcement moves the room, and the very next frame is
     * signalling for the room it moved to. Handled concurrently, that frame
     * arrives while `roomId` is still the old one and is rejected as belonging
     * to another room — after which nothing retries it.
     * @type {Promise<void>}
     */
    this._inbound = Promise.resolve();
    /**
     * Outbound envelopes leave in the order they were made, per peer.
     *
     * The mirror of `_inbound`, and it exists for a sharper reason. Sealing an
     * envelope is a few milliseconds of OpenPGP, so two `_sendTo` calls a
     * microtask apart seal *concurrently* and reach the wire in whichever order
     * their crypto finishes — and one pair is not free to be reordered. A
     * description and the ICE candidates gathered from it are made back to
     * back: `setLocalDescription` returns the answer and schedules the
     * candidates, so `answer` is sent first and `ice` a moment later. Arriving
     * the other way round, `addIceCandidate` runs against a peer connection
     * with no remote description, which is an `InvalidStateError` in the fake
     * transport and in every browser.
     *
     * Nothing held that order. Measured over 60 handshakes the answer won by
     * 0.5–3 ms, which is a coincidence of two seals of similar cost, not a
     * guarantee — one WebCrypto call landing on a busy thread inverts it, and
     * `notebook-signal-order.test.js` makes that inversion happen on purpose.
     * Keyed by peer so a slow send to one member cannot delay another's
     * handshake; ordering only ever mattered within a pair.
     * @type {Map<string, Promise<void>>}
     */
    this._outbound = new Map();
  }

  /**
   * Run `work` after every envelope that arrived before it.
   * @param {() => Promise<void>} work
   * @returns {Promise<void>}
   */
  _enqueue(work) {
    const next = this._inbound.then(work).catch((err) => {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
    });
    this._inbound = next;
    return next;
  }

  async start() {
    if (!this.audienceFprs.includes(this.myFpr)) {
      throw new Error("Local key must be in the room audience");
    }
    // Ahead of the keyserver round trip rather than next to the join: see
    // `_deriveRoom`.
    await this._deriveRoom();
    this.onStatus?.("Loading audience keys…");
    this.audienceKeys = await fetchAudienceKeys(this.audienceFprs);
    const missing = this.audienceFprs.filter((f) => !this.audienceKeys.has(f));
    if (missing.length) {
      // Every one, whole. This is the message that names who could not be
      // brought into a room, and eight characters of each was a list nobody
      // could act on — `findFingerprints` reads this back out of a pasted line,
      // and a comma is deliberately not a separator inside one fingerprint.
      throw new Error(
        `Missing public keys for: ${missing.map((f) => formatFingerprint(f)).join(", ")}`
      );
    }

    for (const fpr of this.audienceFprs) {
      if (fpr === this.myFpr) continue;
      this.peers.set(fpr, this._newPeer(fpr));
    }
    this._emitRoster();

    this.onStatus?.("Joining signalling room…");
    await this._openRelay();

    if (this.role === "creator") {
      this.onStatus?.("Publishing signed invite…");
      this._inviteEcdh = await generateEcdhKeyPair();
      this.inviteNonce = randomNonceHex(32);
      await this._publishInvite(null);
      await this._beginMeshing();
    } else {
      // Knock before waiting. The relay keeps no history, so a creator that
      // started first published its invite into a room this session was not in
      // yet — and nothing would ever say so, because a joiner that has verified
      // no invite sends nothing at all. That silence *was* the bug: both ends
      // waited, and the only way through it was to stop the creator and start
      // it again while this side was already listening.
      //
      // So the joiner speaks first, and a knock is the least it can say — no
      // ECDH key, no nonce, no transport claim, nothing this session would be
      // asserting before it has verified who it is talking to. It is a signed
      // envelope to the audience and its whole content is that an audience
      // member is here without an introduction.
      await this._broadcast({ type: "knock" });
      this.onStatus?.("Waiting for signed invite…");
    }
  }

  /**
   * Put this session's invite on the relay — the first time, and every time
   * after.
   *
   * **The nonce is minted once and reused for every copy**, which is the whole
   * decision here. An invite is a fact about this session rather than an event:
   * *I am this room's initiator, here is my invite ECDH, and here is the nonce
   * that binds this room's transcripts.* Two things break if a republish mints a
   * fresh one.
   *
   * The first is key agreement. `inviteNonce` is in the HKDF salt of every
   * pairwise key (`derivePairwiseSessionKey`), and `_maybeDeriveSession` reads
   * `this.inviteNonce` for *every* peer at the moment it derives. A new nonce
   * halfway through would leave a peer that already sent its `hello` deriving
   * over the old one while this side derives over the new one — a transcript
   * disagreement, which surfaces as key confirmation failing between two honest
   * peers.
   *
   * The second is `_noteOwnKeyElsewhere`, which tells a creator apart from a
   * second session holding its private key by exactly one test: *an invite
   * signed by my key carrying a nonce that is not the one I minted cannot have
   * come from me*. That is sound only while this session has minted one. With a
   * fresh nonce per republish, an echo or a gossiped copy of an earlier invite —
   * our own, correctly signed — would carry a nonce no longer equal to
   * `this.inviteNonce` and be read as proof of a stranger, which stops a run and
   * names the wrong cause. Reusing the nonce keeps that check as airtight as it
   * was: every invite this key ever puts on the wire carries the one nonce.
   *
   * What does differ per copy is the timestamp (`buildInvitePayload` stamps it,
   * and `assertInvite` enforces `INVITE_MAX_AGE_MS`, so a republish an hour
   * later must be freshly dated) and the OpenPGP session key, so the armor is
   * never byte-identical and `_envSeen` cannot mistake a republish for a replay.
   *
   * **The relay, not `_sendTo`.** A peer that needs an invite is by definition a
   * peer with no data channel, so the channel-first routing in `_sealAndSend`
   * has nothing to offer it — worse, it would hand the envelope to some *other*
   * meshed peer to forward and count that as sent, and that peer has no link to
   * the newcomer either. The relay is the only wire a knocker is on.
   *
   * @param {string|null} toFpr  the one member this copy is for, or null to
   *   broadcast it to whoever is in the room
   */
  async _publishInvite(toFpr) {
    if (!this._inviteEcdh || !this.inviteNonce) return;
    const inviteJwk = await exportEcdhPublicJwk(this._inviteEcdh.publicKey);
    const invite = buildInvitePayload({
      roomId: this.roomId,
      audience: this.audienceFprs,
      initiator: this.myFpr,
      ecdhPublicJwk: inviteJwk,
      nonce: this.inviteNonce,
    });
    // `to` last: `_broadcast` spreads these fields over its own `to: null`.
    // Addressed, so the members who already meshed drop it in `_onRelayEnvelope`
    // rather than re-running an introduction they finished long ago.
    await this._broadcast(toFpr ? { ...invite, to: toFpr } : invite);
  }

  /**
   * Derive this epoch's room material.
   *
   * The room id is checked against the audience rather than trusted: it is a
   * digest of exactly this audience under exactly this relying party, so a
   * caller that hands over a room id belonging to some other audience is
   * confused about which room it is in, and joining anyway would put sealed
   * envelopes in a group whose members cannot open them.
   *
   * Separate from `_openRelay` and always called well before it, because the
   * digest is an `await` and every await between "this peer decided to join"
   * and "this peer is in the group" is time spent outside the room. A joiner
   * that misses the creator's broadcast is no longer stranded by it — it knocks
   * and is answered (`_onKnock`) — but the shortest path is still the one where
   * nothing has to be re-sent, and a creator's own room must be joined before
   * its invite can be published into it at all.
   */
  async _deriveRoom() {
    const material = await deriveRoomMaterial(this.audienceFprs, {
      epoch: this.epoch,
      secret: this._rotationSecret,
    });
    if (this.epoch === 0 && material.roomId !== this.roomId) {
      throw new Error(
        "Room id does not match this audience (hostname + fingerprints)"
      );
    }
    this.roomId = material.roomId;
    this._roomKey = material.roomKey;
  }

  /** Join the signalling group this epoch's material names. */
  _openRelay() {
    const previous = this._relay;
    this._relay = openSignalingChannel({
      roomId: this.roomId,
      roomKey: this._roomKey,
      onMessage: (payload) => this._enqueue(() => this._onRelayEnvelope(payload)),
      onError: (err) => this.onError?.(err),
      onStatus: (status) => this.onStatus?.(status),
    });
    previous?.stop();
    // The creator's invite is the first thing on the wire, so the room has to
    // be joined before it is published — otherwise the broadcast lands in a
    // room this connection is not yet a member of and reaches nobody.
    return this._relay.ready;
  }

  /**
   * Move the room to its next epoch, leaving anyone in `remove` behind.
   *
   * **Why moving rather than evicting.** There is no eviction: the signalling
   * service has no API this application can reach to close someone else's
   * connection, no membership to enumerate, and no reason to hang up on a
   * connection whose token has expired. What it does have is groups, and a
   * group is only a name. So the room moves to a name derived from the epoch
   * and the *remaining* audience, everyone who stays mints a token for it, and
   * the party left behind holds a token whose two role strings name a group
   * nobody is in. Nothing had to be revoked, because nothing was granted twice.
   *
   * **What composes with it.** The room id is bound into the pairwise key
   * transcript (`derivePairwiseSessionKey`), so rotating it invalidates every
   * session key in the room by construction. Clearing the per-peer key state
   * below therefore does not *add* a verification step — it forces the one
   * that already exists to re-run over the new room, and a peer that did not
   * follow the rotation cannot produce a matching confirmation.
   *
   * @param {{ remove?: string[], announce?: boolean }} [opts]
   * @returns {Promise<{ epoch: number, roomId: string, audience: string[] }>}
   */
  async rotateRoom({ remove = [], announce = true } = {}) {
    if (this._rotating) throw new Error("Notebook room rotation is already running");
    const removed = new Set(
      (remove || []).map((f) => normalizeFingerprintInput(f)).filter(Boolean)
    );
    const next = this.audienceFprs.filter((f) => !removed.has(f));
    if (!next.includes(this.myFpr)) {
      throw new Error("Cannot rotate a room that no longer includes this key");
    }
    if (next.length < 2) {
      throw new Error("Notebook room requires at least two audience fingerprints");
    }
    const epoch = this.epoch + 1;
    const secret = randomNonceHex(32);

    this._rotating = true;
    try {
      // Announced first and over the links as they stand, because after the
      // move there is no shared group left to say it in. Sealed to the members
      // who stay and to nobody else: this envelope carries the one piece of
      // the new room's name that is not a function of public material, and a
      // copy the removed party could open would hand back exactly what the
      // rotation exists to take away.
      if (announce) {
        const staying = next.filter((f) => f !== this.myFpr);
        for (const fpr of staying) {
          try {
            await this._sendTo(
              fpr,
              { type: "rotate", epoch, remove: [...removed], secret },
              { recipients: next }
            );
          } catch (_) {
            // A peer that cannot be told will find the room empty and drop;
            // that is the same outcome as being removed, which is why one
            // unreachable member cannot hold the rotation up.
          }
        }
      }
      await this._applyRotation(epoch, removed, secret);
    } finally {
      this._rotating = false;
    }
    return { epoch: this.epoch, roomId: this.roomId, audience: [...this.audienceFprs] };
  }

  /**
   * @param {number} epoch
   * @param {Set<string>} removed
   * @param {string} secret
   */
  async _applyRotation(epoch, removed, secret) {
    // Checked before anything is torn down. A remove list that would leave
    // fewer than two members names a room that cannot be derived, and finding
    // that out halfway through would leave this session with its links closed
    // and no room to re-open them in.
    const next = this.audienceFprs.filter((f) => !removed.has(f));
    if (!next.includes(this.myFpr) || next.length < 2) {
      throw new Error("Notebook room requires at least two audience fingerprints");
    }
    for (const fpr of removed) {
      const peer = this.peers.get(fpr);
      if (!peer) continue;
      deregisterLink(fpr);
      try {
        peer.channel?.close();
      } catch (_) {
        /* ignore */
      }
      peer.link?.close();
      this.peers.delete(fpr);
    }
    this.audienceFprs = this.audienceFprs.filter((f) => !removed.has(f));
    this.epoch = epoch;
    this._rotationSecret = String(secret || "");
    for (const fpr of removed) this.audienceKeys.delete(fpr);

    // Every pairwise key was derived over the old room id and the old
    // audience. Both just changed, so the transcripts must be rebuilt — and
    // until they are, nobody in this room is confirmed.
    for (const [fpr, peer] of this.peers) {
      peer.sessionKey = null;
      peer.transcriptHash = null;
      peer.kcSent = false;
      peer.kcVerified = false;
      peer.ecdhPublicJwk = null;
      peer.helloNonce = null;
      peer.localEcdh = null;
      peer.localEcdhJwk = null;
      peer.localHelloNonce = null;
      if (peer.status === "connected") peer.status = "connecting";
      patchLink(fpr, { authenticated: false });
    }
    this._emitRoster();

    this.onStatus?.(`Rotating room (epoch ${epoch})…`);
    await this._deriveRoom();
    await this._openRelay();
    // `_beginMeshing` re-announces and re-offers; the existing transports are
    // kept (a live link is not torn down for a rename), so what actually
    // re-runs is the ECDH exchange, the transcript and the key confirmation.
    await this._beginMeshing();
  }

  stop() {
    // First, before the relay and the key go: everything below this line makes
    // an in-flight send fail, and this is what tells it not to try.
    this._stopped = true;
    this._relay?.stop();
    this._relay = null;
    this._roomKey = "";
    this._inviteEcdh = null;
    this.inviteNonce = "";
    this._invited.clear();
    for (const fpr of this.peers.keys()) {
      // Out of the shared inventory before the transports go: the session owns
      // these connections and is tearing them down itself, so `deregisterLink`
      // (forget) rather than `closeLink` (close *and* forget) — closing twice is
      // harmless, but routing a mesh teardown through the registry would put the
      // registry in charge of a lifecycle it does not manage.
      deregisterLink(fpr);
    }
    for (const peer of this.peers.values()) {
      try {
        peer.channel?.close();
      } catch (_) {
        /* ignore */
      }
      peer.link?.close();
      peer.channel = null;
      peer.link = null;
      peer.sessionKey = null;
      peer.transcriptHash = null;
      peer.localEcdh = null;
      peer.localEcdhJwk = null;
      peer.ecdhPublicJwk = null;
      peer.kcVerified = false;
      peer.status = "failed";
    }
    // Wipe OpenPGP privateParams while the object is still reachable.
    try {
      zeroKeyMaterial(this.privateKey);
    } catch (_) {
      /* ignore */
    }
    this.privateKey = /** @type {any} */ (null);
    this._emitRoster();
    this.onStatus?.("Disconnected");
  }

  /**
   * @param {string} text
   */
  async sendChat(text) {
    return this._sendChatFiltered(text, "");
  }

  /**
   * Chat to a single verified peer, by fingerprint prefix.
   *
   * Distinct from `_sendTo`, which goes over the signalling relay for
   * handshake traffic — this is the encrypted data channel. Each peer already
   * gets its own `sessionKey` in the broadcast loop, so addressing one is a
   * filter rather than a different code path.
   *
   * @param {string} toFpr  fingerprint or unambiguous prefix
   * @param {string} text
   * @returns {Promise<number>} peers written to (never 0 — throws instead)
   */
  async sendChatTo(toFpr, text) {
    const n = await this._sendChatFiltered(text, toFpr);
    if (!n) {
      // Silence here would be dangerous: the author asked to tell one peer and
      // would have no signal that nobody heard it.
      throw new Error(
        `quorum.send to=${toFpr}: no verified peer with that fingerprint is connected`
      );
    }
    return n;
  }

  /**
   * @param {string} text
   * @param {string} toFpr  empty = every verified peer
   * @returns {Promise<number>} peers written to
   */
  async _sendChatFiltered(text, toFpr) {
    const body = JSON.stringify({
      kind: "chat",
      text: String(text || ""),
      ts: Date.now(),
      from: this.myFpr,
    });
    const want = String(toFpr || "").replace(/\s+/g, "").toUpperCase();
    let sent = 0;
    // The map is keyed by fingerprint; the peer record itself carries no copy
    // of it, so the key is the only place to match on.
    for (const [fpr, peer] of this.peers) {
      if (
        !peer.channel ||
        peer.channel.readyState !== "open" ||
        !peer.sessionKey ||
        !peer.kcVerified
      ) {
        continue;
      }
      if (want && !String(fpr || "").toUpperCase().startsWith(want)) continue;
      const blob = await encryptSessionPayload(peer.sessionKey, body);
      peer.channel.send(JSON.stringify({ v: 1, blob }));
      sent += 1;
    }
    return sent;
  }

  /**
   * Put a signed run manifest in front of the room.
   *
   * Takes the **signed document**, not a manifest object, and that is the whole
   * design: the bytes are whatever `run.manifest | gpg.sign key=$me` produced,
   * chosen by someone who read the recipe. A `publishManifest(manifest)` that
   * reached for `this.privateKey` would be one line shorter and would mint a
   * commitment nobody made.
   *
   * @param {string} signed  armored cleartext-signed manifest
   * @returns {Promise<number>} peers written to
   */
  async publishManifest(signed) {
    return this._publishDocument("manifest", signed);
  }

  /**
   * Put a signed attestation in front of the room.
   * @param {string} signed  armored cleartext-signed attestation
   * @returns {Promise<number>} peers written to
   */
  async publishAttestation(signed) {
    return this._publishDocument("attestation", signed);
  }

  /**
   * Put the notebook itself in front of the room, signed.
   *
   * **Broadcast, unlike an offer.** An offer is addressed because it hands one
   * cell to one peer and the wire is the only place that addressing may live; a
   * notebook is the thing the whole room has to agree on before any offer can be
   * read at all, so every confirmed peer gets it. A peer who already holds this
   * text sees a proposal identical to what they have and adopts nothing — the
   * shell's own comparison, not this layer's.
   *
   * **Takes the signed document, not a proposal object**, exactly as
   * `publishManifest` does and for a sharper version of the same reason: a
   * `shareNotebook(proposal)` that reached for `this.privateKey` would put this
   * session's name on text nobody read, and the receiving end's whole decision
   * about whether to adopt is a decision about *whose* text it is.
   *
   * Returns a count, not a promise: only confirmed peers are written to, so a
   * room mid-handshake is a room this returns a smaller number for, and a caller
   * that needs everybody to hold the notebook must compare it against the
   * roster. Nothing here can make an unmeshed peer appear.
   *
   * @param {string} signed  armored cleartext-signed notebook proposal
   * @returns {Promise<number>} peers written to
   */
  async shareNotebook(signed) {
    return this._publishDocument("notebook", signed);
  }

  /**
   * Hand one cell handoff offer to one peer.
   *
   * **Addressed, not broadcast**, and that is the only place an offer is
   * addressed at all: the document deliberately names no assignee, because who
   * runs a cell is the recipient's plan's answer and a second answer in a field
   * the sender chose is a second thing that can be wrong. So the wire carries
   * the addressing, where it is transport and not a claim.
   *
   * Throws rather than returning 0, for `sendChatTo`'s reason: the author asked
   * to hand a cell to one peer, and silence would leave them believing it
   * landed.
   *
   * @param {string} toFpr  fingerprint or unambiguous prefix
   * @param {string} json   `offerToJson(offer)` — see `lib/toolkit/handoff.js`
   * @returns {Promise<number>} peers written to (never 0 — throws instead)
   */
  async sendOffer(toFpr, json) {
    const doc = String(json ?? "");
    // Refused before anything is encrypted, so an oversized offer fails in the
    // offerer's hands and not in the room.
    assertDocumentFits(doc, "handoff offer");
    const want = String(toFpr || "").replace(/\s+/g, "").toUpperCase();
    if (!want) {
      throw new Error(
        "notebook: a handoff offer goes to one peer — name the fingerprint it " +
          "is for. An offer says nothing about who runs the cell, so there is " +
          "nobody for an unaddressed one to reach."
      );
    }
    const body = JSON.stringify({ kind: "handoff", doc, ts: Date.now() });
    let sent = 0;
    for (const [fpr, peer] of this.peers) {
      if (!String(fpr || "").toUpperCase().startsWith(want)) continue;
      if (
        !peer.channel ||
        peer.channel.readyState !== "open" ||
        !peer.sessionKey ||
        !peer.kcVerified
      ) {
        continue;
      }
      const blob = await encryptSessionPayload(peer.sessionKey, body);
      peer.channel.send(JSON.stringify({ v: 1, blob }));
      sent += 1;
    }
    if (!sent) {
      throw new Error(
        `notebook: no verified peer with fingerprint ${want} is connected, so ` +
          "this cell was handed to nobody"
      );
    }
    return sent;
  }

  /**
   * Hand one signed cell result back to the peer that offered the cell.
   *
   * **Addressed like the offer it answers**, and for the same reason: the
   * document names no recipient, because who was waiting for a cell is something
   * the peer holding the run already knows from their own plan. The wire carries
   * the addressing, where it is transport rather than a claim, and this throws
   * rather than returning 0 so that an author is never left believing a value
   * landed.
   *
   * **Takes the signed document, not a result object.** The bytes are whatever
   * the author put through `gpg.sign`, and a `sendResult(result)` that reached
   * for `this.privateKey` would have this layer swear to work it never saw —
   * `publishManifest` refuses exactly that, and a result is the document where
   * the temptation is strongest, because the signature is the *only* thing
   * standing behind a claim nobody can check.
   *
   * @param {string} toFpr  fingerprint or unambiguous prefix
   * @param {string} signed  armored cleartext-signed result
   * @returns {Promise<number>} peers written to (never 0 — throws instead)
   */
  async sendResult(toFpr, signed) {
    const doc = String(signed ?? "");
    // Refused before anything is encrypted, so an oversized result fails in the
    // runner's hands and not in the room.
    assertDocumentFits(doc, "cell result");
    if (!looksCleartextSigned(doc)) {
      throw new Error(
        "notebook: a cell result must arrive here already signed — pipe it " +
          "through `gpg.sign key=$me` first. A result is a claim about work " +
          "done on this machine, and the session carries claims between peers " +
          "without making any."
      );
    }
    const want = String(toFpr || "").replace(/\s+/g, "").toUpperCase();
    if (!want) {
      throw new Error(
        "notebook: a cell result goes back to one peer — name the fingerprint " +
          "it is for. A result says nothing about who was waiting for it, so " +
          "there is nobody for an unaddressed one to reach."
      );
    }
    const body = JSON.stringify({ kind: "result", doc, ts: Date.now() });
    let sent = 0;
    for (const [fpr, peer] of this.peers) {
      if (!String(fpr || "").toUpperCase().startsWith(want)) continue;
      if (
        !peer.channel ||
        peer.channel.readyState !== "open" ||
        !peer.sessionKey ||
        !peer.kcVerified
      ) {
        continue;
      }
      const blob = await encryptSessionPayload(peer.sessionKey, body);
      peer.channel.send(JSON.stringify({ v: 1, blob }));
      sent += 1;
    }
    if (!sent) {
      throw new Error(
        `notebook: no verified peer with fingerprint ${want} is connected, so ` +
          "this cell's result went nowhere"
      );
    }
    return sent;
  }

  /**
   * Which peers have attested to a manifest digest.
   *
   * Fingerprints, because that is the session's vocabulary — it never learns
   * the peer *labels* a manifest is written in, and `attest.js` is explicit
   * that the label a signature resolves to is the caller's to supply. Turning
   * one into the other is the job of whoever holds the label→fingerprint
   * binding `peersSha` commits to, and it is not this layer.
   *
   * @param {string} digest
   * @returns {string[]} fingerprints, sorted
   */
  attestersOf(digest) {
    const want = String(digest || "").trim().toLowerCase();
    if (!want) return [];
    const out = [];
    for (const [fpr, peer] of this.peers) {
      if (peer.attested.has(want)) out.push(fpr);
    }
    return out.sort();
  }

  /**
   * Broadcast one already-signed document, encrypted once per peer.
   *
   * **Per peer, not per room.** `chat` is broadcast the same way and for the
   * same reason: there is no group key here, only a pairwise key for each peer,
   * derived from a transcript bound to that pair and to the transport carrying
   * it. Minting a room key so a document could be sealed once would throw that
   * binding away for a document whose entire value is that everyone knows who
   * stood behind it.
   *
   * Only confirmed peers are written to, so a room mid-handshake is a room this
   * returns a smaller number for. It is a count and not a promise — a caller
   * that needs everyone to have seen a manifest must compare it against the
   * roster, because nothing here can make an unmeshed peer appear.
   *
   * @param {"manifest"|"attestation"|"notebook"} kind
   * @param {string} signed
   * @returns {Promise<number>}
   */
  async _publishDocument(kind, signed) {
    const doc = String(signed ?? "");
    // The kind is the wire's word for the document; this is the reader's. They
    // differ for exactly one of the three, and letting the wire's word into a
    // sentence would produce "notebook: notebook must arrive already signed",
    // which names the module twice and the document never.
    const noun = DOCUMENT_NOUN[kind] || kind;
    // Refused before anything is encrypted, so an oversized document fails in
    // the author's hands and not in the room.
    assertDocumentFits(doc, noun);
    if (!looksCleartextSigned(doc)) {
      throw new Error(
        `notebook: ${noun} must arrive here already signed — pipe it through ` +
          "`gpg.sign key=$me` first. The session carries documents between " +
          "peers; it does not sign on anyone's behalf."
      );
    }
    const body = JSON.stringify({ kind, doc, ts: Date.now() });
    let sent = 0;
    for (const peer of this.peers.values()) {
      if (
        !peer.channel ||
        peer.channel.readyState !== "open" ||
        !peer.sessionKey ||
        !peer.kcVerified
      ) {
        continue;
      }
      const blob = await encryptSessionPayload(peer.sessionKey, body);
      peer.channel.send(JSON.stringify({ v: 1, blob }));
      sent += 1;
    }
    return sent;
  }

  /**
   * A sealed envelope off the signalling relay.
   * @param {string} armored
   */
  async _onRelayEnvelope(armored) {
    if (this._envSeen.seen(armored)) return;
    let opened;
    try {
      opened = await openSignalingEnvelope({
        armored,
        decryptionKey: this.privateKey,
        audienceKeyByFpr: this.audienceKeys,
        audienceFprs: this.audienceFprs,
        expectedRoomId: this.roomId,
      });
    } catch (err) {
      this.onError?.(
        err instanceof Error ? err : new Error(String(err))
      );
      return;
    }
    const { payload, signerFpr } = opened;
    if (signerFpr === this.myFpr) {
      this._noteOwnKeyElsewhere(payload);
      return;
    }
    // Everyone is in the same relay room — a message for someone else is
    // simply not ours; forwarding is a channel-path concern.
    if (payload.to && payload.to !== this.myFpr) return;
    await this._handleSignal(payload, signerFpr);
  }

  /**
   * A sealed envelope arriving over a data channel instead of the relay —
   * either addressed to us (channel-first signaling, mesh introductions) or
   * to be forwarded (we are the relaying member). Verification is identical
   * to the relay path: same sealed envelope, same checks, only the wire
   * differs.
   * @param {string} fromFpr peer whose channel delivered the frame
   * @param {{ env: string, hops: number }} frame
   */
  async _onChannelEnvelope(fromFpr, frame) {
    if (this._envSeen.seen(frame.env)) return;
    let opened;
    try {
      opened = await openSignalingEnvelope({
        armored: frame.env,
        decryptionKey: this.privateKey,
        audienceKeyByFpr: this.audienceKeys,
        audienceFprs: this.audienceFprs,
        expectedRoomId: this.roomId,
      });
    } catch (err) {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    const { payload, signerFpr } = opened;
    if (signerFpr === this.myFpr) {
      this._noteOwnKeyElsewhere(payload);
      return;
    }
    if (payload.to && payload.to !== this.myFpr) {
      // Not ours: pass it one link onward. Introductions ride only
      // authenticated links, directly to the target when we hold that link,
      // otherwise on to every other verified member (bounded by the hop cap
      // and the per-node dedupe — a small room drowns no one).
      if (!shouldRelay({ to: payload.to, myFpr: this.myFpr, hops: frame.hops })) {
        return;
      }
      const out = JSON.stringify({ v: 1, env: frame.env, hops: frame.hops + 1 });
      const target = this.peers.get(payload.to);
      if (target?.channel?.readyState === "open" && target.kcVerified) {
        target.channel.send(out);
        return;
      }
      for (const [fpr, p] of this.peers) {
        if (fpr === fromFpr) continue;
        if (p.channel?.readyState === "open" && p.kcVerified) {
          p.channel.send(out);
        }
      }
      return;
    }
    await this._handleSignal(payload, signerFpr);
  }

  /**
   * An envelope signed by this session's own key, which this session did not
   * send: somebody else is holding this private key and is in this room.
   *
   * **The drop above it stands.** Self is not a peer — the roster is the
   * audience minus this fingerprint — and meshing with a second session under
   * one identity would key-confirm a transcript against our own key and file
   * the result as a witness. What was missing is not a peer, it is a sentence:
   * both ends sat on "waiting for peer" while the one fact that explained it
   * was arriving, verified, every few seconds.
   *
   * **Why only an invite counts.** This has to be proof, not a guess, because
   * what the layer above does with it is stop a run. An invite is the one
   * payload whose provenance is decidable without trusting the dedupe set: a
   * joiner never publishes one at all, and a creator's own invite always
   * carries the nonce it minted a line before broadcasting it. So an invite
   * bearing this fingerprint and any other nonce cannot have come from here —
   * and it could only have been signed by this key. `hello`, `offer`, `answer`
   * and `ice` carry no such marker, and the copy of our own that a relay
   * echoes back looks exactly like a stranger's; those go on being dropped in
   * silence, which costs nothing, because the invite is published first and
   * reaches the same place.
   *
   * The most ordinary way to be here is two tabs of one browser: they share an
   * IndexedDB vault, so a tester opening a second tab to play the other side
   * can pick the same key without noticing. That is a fine thing to want and
   * it works — the two tabs must simply choose *different* keys — but it is
   * not a thing this layer can say. What is said, and where, is the caller's:
   * `quorum-ops.js` owns the sentence.
   *
   * @param {import("./crypto.js").NotebookEnvelopePayload} payload
   */
  _noteOwnKeyElsewhere(payload) {
    if (this.ownKeyElsewhere) return;
    if (payload?.type !== "invite") return;
    if (this.role === "creator" && payload.nonce === this.inviteNonce) return;
    this.ownKeyElsewhere = true;
    this.onOwnKeyElsewhere?.();
  }

  /**
   * Verified signaling payload → session/peer state. Shared by the mailbox
   * and channel paths.
   * @param {import("./crypto.js").NotebookEnvelopePayload} payload
   * @param {string} signerFpr
   */
  async _handleSignal(payload, signerFpr) {
    if (payload.type === "invite") {
      await this._handleInvite(payload, signerFpr);
      return;
    }

    if (!this._meshing) return;

    const peer = this.peers.get(signerFpr);
    if (!peer) return;
    peer.pgpVerified = true;
    if (signerFpr === this.initiatorFpr) peer.isInitiator = true;

    if (payload.helloNonce) peer.helloNonce = String(payload.helloNonce);
    if (payload.dtlsFingerprint) {
      peer.remoteDtls = String(payload.dtlsFingerprint);
    }
    if (payload.ecdhPublicJwk) {
      peer.ecdhPublicJwk = payload.ecdhPublicJwk;
      await this._maybeDeriveSession(signerFpr);
    }

    if (payload.type === "knock") {
      await this._onKnock(signerFpr);
      return;
    }

    if (payload.type === "rotate") {
      // Who may move the room: the peer that published the invite this
      // session locked onto, and only once we have confirmed a key with them.
      // A PGP signature proves an audience member wrote it; key confirmation
      // proves it is the audience member we are actually meshed with. Without
      // the second, a member being removed could answer their own eviction by
      // announcing a rotation of their own.
      if (signerFpr !== this.initiatorFpr || !peer.kcVerified) return;
      const epoch = Math.trunc(Number(payload.epoch) || 0);
      // Monotonic: an epoch we have already left is a replay, and the room it
      // names is one an old token still opens.
      if (epoch <= this.epoch) return;
      const removed = new Set(
        (payload.remove || []).map((f) => normalizeFingerprintInput(f)).filter(Boolean)
      );
      // Being told to remove ourselves is not a rotation we can follow. The
      // room leaves without us, which is what it means to be removed.
      if (removed.has(this.myFpr)) return;
      // Without the secret this peer would derive a different room and be
      // rotated into a group of one. Silence is the right answer: the room it
      // was in is still the room it is in until it is told where to go.
      const secret = String(payload.secret || "");
      if (!secret) return;
      if (this._rotating) return;
      this._rotating = true;
      try {
        await this._applyRotation(epoch, removed, secret);
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
      } finally {
        this._rotating = false;
      }
      return;
    }

    if (payload.type === "hello") {
      peer.status = peer.status === "connected" ? "connected" : "connecting";
      this._emitRoster();
      if (this.myFpr < signerFpr) {
        await this._ensurePeerConnection(signerFpr, true);
      }
      return;
    }

    if (payload.type === "offer" && payload.sdp) {
      await this._ensurePeerConnection(signerFpr, false);
      const p = this.peers.get(signerFpr);
      const link = p?.link;
      if (!link || !p) return;
      p.ignoreOffer = false;
      /** @type {import("../webrtc/peer-link.js").LocalDescriptionFacts|null} */
      let answer = null;
      try {
        answer = await link.answerRemoteOffer({
          sdp: payload.sdp,
          polite: p.polite,
          makingOffer: p.makingOffer,
        });
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      // Glare: our own offer is in flight and wins. Remembered because the
      // candidates for the offer we just dropped will fail on arrival, by
      // design.
      if (!answer) {
        p.ignoreOffer = true;
        return;
      }
      // The answer SDP and the fingerprint of the description it came from
      // arrive together and are signalled together — a peer that ever sent one
      // without the other would be claiming a transport it is not using.
      p.localDtls = answer.dtlsFingerprint;
      const local = await this._ensureLocalEcdh(signerFpr);
      await this._sendTo(signerFpr, {
        type: "answer",
        sdp: answer.sdp,
        dtlsFingerprint: p.localDtls,
        ecdhPublicJwk: local.jwk,
        helloNonce: local.helloNonce,
      });
      await this._maybeDeriveSession(signerFpr);
      peer.status = "connecting";
      this._emitRoster();
      return;
    }

    if (payload.type === "answer" && payload.sdp) {
      const p = this.peers.get(signerFpr);
      const link = p?.link;
      if (!link || !p) return;
      try {
        // An answer to an offer we rolled back arrives in a state that cannot
        // take it — stale by construction, dropped rather than surfaced.
        if (!(await link.applyRemoteAnswer(payload.sdp))) return;
      } catch (err) {
        this.onError?.(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      await this._maybeDeriveSession(signerFpr);
      peer.status = "connecting";
      this._emitRoster();
      return;
    }

    if (payload.type === "ice" && payload.candidate) {
      const p = this.peers.get(signerFpr);
      const link = p?.link;
      if (!link) return;
      try {
        await link.addRemoteCandidate(payload.candidate);
      } catch (err) {
        // Candidates for an offer we deliberately ignored fail by design.
        if (p?.ignoreOffer) return;
        this.onError?.(
          err instanceof Error ? err : new Error(String(err))
        );
      }
    }
  }

  /**
   * @param {import("./crypto.js").NotebookEnvelopePayload} payload
   * @param {string} signerFpr
   */
  async _handleInvite(payload, signerFpr) {
    try {
      const { inviteNonce, initiator } = await assertInvite(payload, {
        signerFpr,
        expectedRoomId: this.roomId,
        expectedAudience: this.audienceFprs,
      });
      if (this.inviteVerified && this.inviteNonce && this.inviteNonce !== inviteNonce) {
        // Already locked to first valid invite
        return;
      }
      this.inviteNonce = inviteNonce;
      this.initiatorFpr = initiator;
      this.inviteVerified = true;
      const initiatorPeer = this.peers.get(initiator);
      if (initiatorPeer) {
        initiatorPeer.isInitiator = true;
        initiatorPeer.pgpVerified = true;
      }
      this._emitRoster();
      if (!this._meshing) {
        await this._beginMeshing();
      }
    } catch (err) {
      this.onError?.(
        err instanceof Error ? err : new Error(String(err))
      );
    }
  }

  /**
   * An audience member is in this room and has not been introduced.
   *
   * The answer is this session's own invite again, addressed to them. Nothing
   * about what an invite *means* changes: same initiator, same invite ECDH, same
   * nonce, freshly signed and freshly dated — see `_publishInvite` for why the
   * nonce is the one that was minted at `start`, and what it would cost to mint
   * another.
   *
   * **Three things bound this, and none of them is a timer.**
   *
   * *Who may answer.* Only a session holding invite material, which is only the
   * session that published one. A joiner that has verified an invite is meshing
   * and reaches this line, and leaves on the first check — so a room of one
   * creator and four joiners has exactly one answerer however many knocks fly.
   *
   * *Who has been served.* `_invited` is a set of fingerprints, not a count and
   * not a clock. A member is answered once per session; knocking again gets
   * silence, so a peer stuck in a reconnect loop cannot pull an invite out of
   * this room on every pass.
   *
   * *Who is a member at all.* A knock from outside the audience never arrives
   * here to be refused: `openSignalingEnvelope` cannot name a signer it holds no
   * key for, and refuses it through `onError` with the sentence that says what a
   * room *is* — derived from its audience's fingerprints, admitting only those
   * keys. That refusal used to be unreachable, which is worth knowing here,
   * because this method is the first thing that leans on it. `_handleSignal`'s
   * own `peers.get` drops the one audience fingerprint left over: our own, which
   * is not a peer and is handled a layer up by `_noteOwnKeyElsewhere`.
   *
   * @param {string} peerFpr
   */
  async _onKnock(peerFpr) {
    // Not our introduction to give. Said before the served-set is touched, so a
    // joiner never records having answered something it cannot answer.
    if (!this._inviteEcdh || !this.inviteNonce) return;
    if (this._invited.has(peerFpr)) return;
    this._invited.add(peerFpr);
    // Everything already sent to this peer went into a room they were not in —
    // the invite, the `hello`, and (when this end is the offerer) an offer and
    // its candidates. The offer is the one that does not heal on its own:
    // `_ensurePeerConnection` will not rebuild a link that already exists, so
    // the `hello` this knock is about to earn would find a half-negotiated
    // connection aimed at nobody and make no second offer. A knock says nothing
    // this session sent has arrived, so the transport for that peer starts over.
    //
    // Never for a confirmed peer. Their link carries traffic under a key both
    // ends proved, and a knock is not proof of anything but presence — dropping
    // a working channel on it would let one audience member reset another's.
    const peer = this.peers.get(peerFpr);
    if (peer && !peer.kcVerified) this._resetPeerTransport(peerFpr, peer);
    // The prelude above set `pgpVerified` from the one fact a knock carries —
    // an audience member's signature over this room id — and the roster is the
    // only path that fact travels on.
    this._emitRoster();
    this.onStatus?.("Re-publishing signed invite for a late arrival…");
    await this._publishInvite(peerFpr);
  }

  /**
   * Drop one peer's transport and every key derived over it, keeping what a
   * signature established.
   *
   * The split is `_applyRotation`'s and it is the same rule: a session key says
   * which transport is live, a signature says what somebody put their name to,
   * and losing the first does not un-sign the second. So `attested`, `offered`,
   * `returned` and `publishedManifest` stay — they are records of documents this
   * session checked against this peer's own key, and an unauthenticated frame
   * must never be able to erase one.
   *
   * @param {string} peerFpr
   * @param {NotebookPeerState} peer
   */
  _resetPeerTransport(peerFpr, peer) {
    deregisterLink(peerFpr);
    try {
      peer.channel?.close();
    } catch (_) {
      /* ignore */
    }
    peer.link?.close();
    peer.channel = null;
    peer.link = null;
    peer.sessionKey = null;
    peer.transcriptHash = null;
    peer.kcSent = false;
    peer.kcVerified = false;
    peer.ecdhPublicJwk = null;
    peer.helloNonce = null;
    // Both halves of the ECDH and both DTLS fingerprints, because the next link
    // mints a new local certificate: a transcript that kept the old fingerprint
    // would bind to a transport that no longer exists, which is the one failure
    // `notebook-dtls-binding.test.js` exists to make impossible.
    peer.localEcdh = null;
    peer.localEcdhJwk = null;
    peer.localHelloNonce = null;
    peer.localDtls = "";
    peer.remoteDtls = "";
    peer.makingOffer = false;
    peer.ignoreOffer = false;
    peer.status = "unknown";
  }

  async _beginMeshing() {
    this._meshing = true;
    this.onStatus?.("Announcing presence…");
    for (const fpr of this.peers.keys()) {
      const local = await this._ensureLocalEcdh(fpr);
      await this._sendTo(fpr, {
        type: "hello",
        ecdhPublicJwk: local.jwk,
        helloNonce: local.helloNonce,
      });
    }
    for (const fpr of this.peers.keys()) {
      if (this.myFpr < fpr) {
        await this._ensurePeerConnection(fpr, true);
      }
    }
    this.onStatus?.(
      this.role === "creator"
        ? "Invite published — waiting for peers…"
        : "Invite verified — waiting for peers…"
    );
  }

  /**
   * @param {string} fpr
   * @returns {NotebookPeerState}
   */
  _newPeer(fpr) {
    return {
      fingerprint: fpr,
      status: "unknown",
      pgpVerified: false,
      kcVerified: false,
      isInitiator: fpr === this.initiatorFpr,
      link: null,
      channel: null,
      sessionKey: null,
      transcriptHash: null,
      ecdhPublicJwk: null,
      helloNonce: null,
      localDtls: "",
      remoteDtls: "",
      localEcdh: null,
      localEcdhJwk: null,
      localHelloNonce: null,
      kcSent: false,
      polite: this.myFpr < fpr,
      makingOffer: false,
      ignoreOffer: false,
      attested: new Set(),
      publishedManifest: null,
      offered: new Set(),
      returned: new Set(),
    };
  }

  /**
   * @param {string} peerFpr
   * @returns {Promise<{ jwk: JsonWebKey, helloNonce: string, pair: CryptoKeyPair }>}
   */
  async _ensureLocalEcdh(peerFpr) {
    const peer = this.peers.get(peerFpr);
    if (!peer) throw new Error("Unknown peer");
    if (!peer.localEcdh || !peer.localEcdhJwk || !peer.localHelloNonce) {
      peer.localEcdh = await generateEcdhKeyPair();
      peer.localEcdhJwk = await exportEcdhPublicJwk(peer.localEcdh.publicKey);
      peer.localHelloNonce = randomNonceHex(16);
    }
    return {
      jwk: peer.localEcdhJwk,
      helloNonce: peer.localHelloNonce,
      pair: peer.localEcdh,
    };
  }

  /**
   * @param {string} peerFpr
   * @param {boolean} asOfferer
   */
  async _ensurePeerConnection(peerFpr, asOfferer) {
    let peer = this.peers.get(peerFpr);
    if (!peer) return;
    // A link whose transport the inventory closed out from under it (the
    // Connections panel's Close nulls its holder's fields) is a husk, and this
    // peer is re-connectable — which is the question `peer.pc === null` used to
    // answer by reaching into the connection.
    if (peer.link && !peer.link.isTornDown()) return;
    const local = await this._ensureLocalEcdh(peerFpr);
    // The transport is the driver's; what it is *for* is this layer's. Every
    // callback below is either identity (which peer), protocol (what rides the
    // signalling envelope) or projection (the roster) — none of it is WebRTC,
    // and none of the WebRTC is here.
    const link = openPeerLink({
      iceServers: this.iceServers,
      onIceCandidate: (candidate) => {
        void this._sendTo(peerFpr, {
          type: "ice",
          candidate,
          ecdhPublicJwk: local.jwk,
          helloNonce: local.helloNonce,
        });
      },
      onMakingOffer: (making) => {
        peer.makingOffer = making;
      },
      // The offer and the fingerprint of the description it was made from
      // arrive in one object, and this is the only place `localDtls` is set on
      // the offering side. There is no window in which an offer has been
      // signalled but the transcript does not yet know what transport it
      // committed to — that ordering is what the DTLS binding rests on.
      onLocalOffer: async ({ sdp, dtlsFingerprint }) => {
        peer.localDtls = dtlsFingerprint;
        await this._sendTo(peerFpr, {
          type: "offer",
          sdp,
          dtlsFingerprint,
          ecdhPublicJwk: local.jwk,
          helloNonce: local.helloNonce,
        });
      },
      onConnectionState: (st) => {
        if (st === "connected") {
          if (!peer.kcVerified) peer.status = "connecting";
          else peer.status = "connected";
        } else if (st === "failed" || st === "closed" || st === "disconnected") {
          peer.status = st === "failed" ? "failed" : peer.status;
        }
        this._emitRoster();
      },
      onDataChannel: (channel) => {
        this._wireChannel(peerFpr, channel);
      },
      onError: (err) => this.onError?.(err),
    });
    peer.link = link;
    peer.status = "connecting";
    // Into the shared inventory (§57a). The **link** is the holder: the registry
    // reads `pc`/`channel` through it rather than copying them, which is why
    // registering here — before a channel exists — is correct, and why the peer
    // record no longer has to carry a connection it is not allowed to use. A
    // copied field would go stale from the first renegotiation onward, in the
    // exact direction that reads as "connected, no channel".
    //
    // What the mesh gives up is being the sole answer to "what is connected",
    // which it was never the right owner of: the five `rtc.*` diagnostics used
    // to refuse outright for any connection made another way.
    // `origin` and `label` stay `"quorum"`, and so does the channel label
    // below. None of the three is this module's name to change: `origin` is the
    // discriminant `link-registry.js` declares and `peer-ops.js`, the readouts
    // and the Connections panel switch on, and the channel label is negotiated
    // on the wire — both ends must spell it the same way or the channel the
    // answerer receives is not the one the offerer opened. They travel with the
    // `quorum.*` ops that create these links, so they move when those do.
    registerLink({
      id: peerFpr,
      origin: "quorum",
      role: asOfferer ? "offerer" : "answerer",
      holder: link,
      label: "quorum",
      authenticated: !!peer.kcVerified,
    });
    this._emitRoster();

    // Creating the channel is what starts negotiation, so it goes last —
    // after the connection is in the inventory and the roster has been told.
    if (asOfferer) link.openDataChannel("quorum");
  }

  /**
   * @param {string} peerFpr
   * @param {RTCDataChannel} channel
   */
  _wireChannel(peerFpr, channel) {
    const peer = this.peers.get(peerFpr);
    if (!peer) return;
    peer.channel = channel;
    channel.onopen = () => {
      void this._maybeSendKeyConfirm(peerFpr);
      this._emitRoster();
    };
    channel.onclose = () => {
      if (peer.status === "connected") peer.status = "failed";
      peer.kcVerified = false;
      patchLink(peerFpr, { authenticated: false });
      this._emitRoster();
    };
    channel.onmessage = (ev) => {
      const raw = String(ev.data || "");
      void this._enqueue(() => this._onChannelMessage(peerFpr, raw));
    };
  }

  /**
   * @param {string} peerFpr
   * @param {string} raw
   */
  async _onChannelMessage(peerFpr, raw) {
    const frame = classifyChannelFrame(raw);
    if (frame?.kind === "envelope") {
      await this._onChannelEnvelope(peerFpr, frame);
      return;
    }
    if (frame?.kind !== "session") return;
    const peer = this.peers.get(peerFpr);
    if (!peer?.sessionKey) return;
    try {
      const pt = await decryptSessionPayload(peer.sessionKey, frame.blob);
      const msg = JSON.parse(pt);
      if (msg.kind === "kc") {
        const th = String(msg.transcriptHash || "");
        const from = normalizeFingerprintInput(msg.fpr || "") || peerFpr;
        if (
          from === peerFpr &&
          String(msg.roomId || "") === this.roomId &&
          th &&
          th === peer.transcriptHash
        ) {
          peer.kcVerified = true;
          peer.status = "connected";
          peer.pgpVerified = true;
          // The inventory's `authenticated` is the mesh's own key-confirmation
          // fact, not a second opinion about it — the panel and the `connstate`
          // tile both read it from there.
          patchLink(peerFpr, { authenticated: true });
          this._emitRoster();
          this.onStatus?.("Peer verified — secure channel ready");
          await this._maybeSendKeyConfirm(peerFpr);
        } else {
          peer.status = "failed";
          this.onError?.(new Error("Key confirmation failed"));
          this._emitRoster();
        }
        return;
      }
      if (msg.kind === "chat") {
        if (!peer.kcVerified) return;
        this.onChat?.({
          from: normalizeFingerprintInput(msg.from) || peerFpr,
          text: String(msg.text || ""),
          ts: Number(msg.ts) || Date.now(),
        });
        return;
      }
      if (
        msg.kind === "manifest" ||
        msg.kind === "attestation" ||
        msg.kind === "notebook"
      ) {
        await this._onDocument(peerFpr, peer, msg);
        return;
      }
      if (msg.kind === "handoff") {
        this._onOffer(peerFpr, peer, msg);
        return;
      }
      if (msg.kind === "result") {
        await this._onResult(peerFpr, peer, msg);
      }
    } catch (err) {
      this.onError?.(
        err instanceof Error ? err : new Error(String(err))
      );
    }
  }

  /**
   * A signed manifest, attestation or notebook proposal off a peer's channel.
   *
   * **Dropped, not queued, before key confirmation.** The refusal is `chat`'s,
   * inherited on purpose: a peer whose key is not confirmed is not anyone in
   * particular, and a document's whole content is *who* stood behind it. There
   * is nothing to queue for, either. Both ends send `kc` the instant a key is
   * derived, a data channel is ordered, and `_enqueue` handles arrivals in the
   * order they came — so an honest peer's confirmation is always ahead of its
   * first document on the same channel. A document that overtakes it came from
   * a peer that skipped its own confirmation, which is the case the refusal is
   * for. Holding those bytes would mean keeping an unauthenticated stranger's
   * blob on the chance they authenticate later, and would put the refusal
   * behind a timing window.
   *
   * The payload deliberately carries no `from`. `chat` has one and tolerates it
   * disagreeing with the channel; a document must not, because "who signed
   * this" is the question the document exists to answer, and a second answer in
   * a field the sender chose is a second thing that can be wrong. The sender is
   * the peer whose pairwise key opened the frame, and the signature is checked
   * against that peer's key and no other — which is also why a peer cannot pass
   * on somebody else's signed manifest as if it were traffic: it verifies
   * against the original signer's key, not the forwarder's, and is refused.
   *
   * The third kind arrived here rather than beside it because that paragraph is
   * the whole argument for signing a notebook proposal, sharpened: a proposal is
   * the one carried document the recipient holds nothing to check against, since
   * it is what they will check everything else against. **Nothing is adopted
   * here.** The parsed proposal goes up through `onNotebook` and the notebook on
   * the machine is untouched, which is the same shape as a manifest arriving and
   * running nothing.
   *
   * Every failure here is reported and swallowed. A malformed document, a
   * signature from the wrong key, a manifest three versions old: each is one
   * peer's frame going nowhere, and none of them is a reason for a session
   * carrying four other peers to fall over.
   *
   * @param {string} peerFpr
   * @param {NotebookPeerState} peer
   * @param {{ kind: string, doc?: string, ts?: number }} msg
   */
  async _onDocument(peerFpr, peer, msg) {
    if (!peer.kcVerified) return;
    const kind = DOCUMENT_NOUN[msg.kind] ? msg.kind : "attestation";
    const doc = String(msg.doc ?? "");
    const ts = Number(msg.ts) || Date.now();
    const key = this.audienceKeys.get(peerFpr);
    try {
      if (kind === "notebook") {
        const { proposal } = await readSignedNotebook(doc, { key, fpr: peerFpr });
        // Verified, parsed, and that is all. Nothing here replaces a notebook,
        // and this class has none to replace.
        this.onNotebook?.({ from: peerFpr, proposal, signed: doc, ts });
        return;
      }
      if (kind === "manifest") {
        const { manifest, digest } = await readSignedManifest(doc, {
          key,
          fpr: peerFpr,
        });
        peer.publishedManifest = digest;
        this._emitRoster();
        // Parsed, and that is all. Nothing here runs a cell, pins a clock or
        // answers with an attestation; those are recipes a person types.
        this.onManifest?.({ from: peerFpr, digest, manifest, signed: doc, ts });
        return;
      }
      const { attestation, digest } = await readSignedAttestation(doc, {
        key,
        fpr: peerFpr,
      });
      this._rememberAttestation(peer, digest);
      // The roster is the one notification path for peer state, so who has
      // attested travels with everything else the roster says about a peer
      // rather than beside it.
      this._emitRoster();
      this.onAttestation?.({ from: peerFpr, digest, attestation, signed: doc, ts });
    } catch (err) {
      this.onError?.(
        new Error(
          `notebook: ${DOCUMENT_NOUN[kind]} from ${formatFingerprint(peerFpr)} ` +
            `refused — ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }
  }

  /**
   * A cell handoff offer off a peer's channel.
   *
   * The same key-confirmation refusal the documents inherit, for the same
   * reason: an unconfirmed peer is not anyone in particular, and an offer is a
   * peer proposing to put values into this machine's slots.
   *
   * Everything past that is shape. The offer is parsed — which refuses any
   * field beyond the seven it may carry — and handed on **pending**. Nothing
   * here checks it against a plan, and nothing here could: this layer has no
   * notebook, no plan and no slot registry, which is exactly why it is safe for
   * it to be the courier. `acceptHandoffOffer` does the checking, in the shell,
   * for a person who clicked.
   *
   * Failures are reported and swallowed, as the documents' are. A malformed
   * offer is one peer's frame going nowhere.
   *
   * @param {string} peerFpr
   * @param {NotebookPeerState} peer
   * @param {{ doc?: string, ts?: number }} msg
   */
  _onOffer(peerFpr, peer, msg) {
    if (!peer.kcVerified) return;
    const doc = String(msg.doc ?? "");
    const ts = Number(msg.ts) || Date.now();
    try {
      const offer = readHandoffOffer(doc);
      this._rememberOffer(peer, `${offer.manifest}:${offer.cell}`);
      this._emitRoster();
      this.onOffer?.({
        from: peerFpr,
        cell: offer.cell,
        manifest: offer.manifest,
        offer,
        ts,
      });
    } catch (err) {
      this.onError?.(
        new Error(
          `notebook: handoff offer from ${formatFingerprint(peerFpr)} refused — ${
            err instanceof Error ? err.message : String(err)
          }`
        )
      );
    }
  }

  /**
   * A signed cell result off a peer's channel.
   *
   * The signature is checked here because that is `documents.js`'s discipline
   * and this is the layer that knows which fingerprint opened the frame: the
   * document is verified against **that peer's key and no other**, and parsed
   * out of the bytes the signature covers. A result whose signature is good but
   * somebody else's is refused, which is the replay a `verify against everyone`
   * check waves through — here it would be one peer returning another peer's
   * work as their own answer to an offer.
   *
   * Everything past the signature is somebody else's question. This layer has no
   * plan, no notebook, no registry and no record of which cells this peer handed
   * out, so it cannot tell whether the result was asked for, whether the cell is
   * that peer's to run, or whether the values may be registered — and that is
   * why it is safe for it to be the courier. `acceptCellResult` answers all
   * three, in the shell, for a person who clicked.
   *
   * Failures are reported and swallowed, as every other document's are.
   *
   * @param {string} peerFpr
   * @param {NotebookPeerState} peer
   * @param {{ doc?: string, ts?: number }} msg
   */
  async _onResult(peerFpr, peer, msg) {
    if (!peer.kcVerified) return;
    const doc = String(msg.doc ?? "");
    const ts = Number(msg.ts) || Date.now();
    const key = this.audienceKeys.get(peerFpr);
    try {
      const { result } = await readSignedResult(doc, { key, fpr: peerFpr });
      this._rememberReturn(peer, `${result.manifest}:${result.cell}`);
      this._emitRoster();
      this.onResult?.({
        from: peerFpr,
        cell: result.cell,
        manifest: result.manifest,
        result,
        signed: doc,
        ts,
      });
    } catch (err) {
      this.onError?.(
        new Error(
          `notebook: cell result from ${formatFingerprint(peerFpr)} refused — ${
            err instanceof Error ? err.message : String(err)
          }`
        )
      );
    }
  }

  /**
   * Record that a peer held out an offer. Bounded exactly as `attested` is, and
   * for the same reason: a confirmed peer can still be a broken one.
   * @param {NotebookPeerState} peer
   * @param {string} key
   */
  _rememberOffer(peer, key) {
    if (peer.offered.has(key)) return;
    peer.offered.add(key);
    while (peer.offered.size > ATTESTED_PER_PEER_CAP) {
      const oldest = peer.offered.values().next().value;
      peer.offered.delete(oldest);
    }
  }

  /**
   * Record that a peer returned a result. Bounded exactly as `offered` is.
   * @param {NotebookPeerState} peer
   * @param {string} key
   */
  _rememberReturn(peer, key) {
    if (peer.returned.has(key)) return;
    peer.returned.add(key);
    while (peer.returned.size > ATTESTED_PER_PEER_CAP) {
      const oldest = peer.returned.values().next().value;
      peer.returned.delete(oldest);
    }
  }

  /**
   * Record that a peer attested to a digest.
   *
   * Survives rotation and a dropped channel, unlike everything in
   * `_applyRotation`'s reset: a session key says which transport is live, and a
   * signature says what somebody put their name to. Rotating a room does not
   * un-sign a document.
   *
   * @param {NotebookPeerState} peer
   * @param {string} digest
   */
  _rememberAttestation(peer, digest) {
    const sha = String(digest || "").toLowerCase();
    if (!sha || peer.attested.has(sha)) return;
    peer.attested.add(sha);
    while (peer.attested.size > ATTESTED_PER_PEER_CAP) {
      // Sets iterate in insertion order — evict the oldest, as `createSeenSet`
      // does for envelopes.
      const oldest = peer.attested.values().next().value;
      peer.attested.delete(oldest);
    }
  }

  /** @param {string} peerFpr */
  async _maybeDeriveSession(peerFpr) {
    const peer = this.peers.get(peerFpr);
    if (
      !peer?.ecdhPublicJwk ||
      !peer.localEcdh ||
      !peer.localEcdhJwk ||
      !peer.localHelloNonce ||
      !peer.helloNonce ||
      !this.inviteNonce ||
      !peer.localDtls ||
      !peer.remoteDtls ||
      peer.sessionKey
    ) {
      return;
    }
    const peerPub = await importEcdhPublicJwk(peer.ecdhPublicJwk);
    const dtls = combineDtlsFingerprints(peer.localDtls, peer.remoteDtls);
    const { aesKey, transcriptHash } = await derivePairwiseSessionKey({
      privateKey: peer.localEcdh.privateKey,
      peerPublicKey: peerPub,
      roomId: this.roomId,
      myFpr: this.myFpr,
      peerFpr,
      audienceFprs: this.audienceFprs,
      myEcdhJwk: peer.localEcdhJwk,
      peerEcdhJwk: peer.ecdhPublicJwk,
      inviteNonce: this.inviteNonce,
      myHelloNonce: peer.localHelloNonce,
      peerHelloNonce: peer.helloNonce,
      dtlsFingerprint: dtls,
    });
    peer.sessionKey = aesKey;
    peer.transcriptHash = transcriptHash;
    await this._maybeSendKeyConfirm(peerFpr);
  }

  /** @param {string} peerFpr */
  async _maybeSendKeyConfirm(peerFpr) {
    const peer = this.peers.get(peerFpr);
    if (
      !peer?.sessionKey ||
      !peer.transcriptHash ||
      !peer.channel ||
      peer.channel.readyState !== "open" ||
      peer.kcSent
    ) {
      return;
    }
    peer.kcSent = true;
    const body = JSON.stringify({
      kind: "kc",
      fpr: this.myFpr,
      roomId: this.roomId,
      transcriptHash: peer.transcriptHash,
      ts: Date.now(),
    });
    const blob = await encryptSessionPayload(peer.sessionKey, body);
    peer.channel.send(JSON.stringify({ v: 1, blob }));
  }

  /**
   * @param {Partial<import("./crypto.js").NotebookEnvelopePayload>} fields
   */
  async _broadcast(fields) {
    const audienceKeys = [...this.audienceKeys.values()];
    const payload = {
      v: 1,
      from: this.myFpr,
      to: null,
      roomId: this.roomId,
      ts: Date.now(),
      ...fields,
    };
    const armored = await sealSignalingEnvelope({
      payload: /** @type {import("./crypto.js").NotebookEnvelopePayload} */ (
        payload
      ),
      signingKey: this.privateKey,
      audienceKeys,
    });
    await this._publish(armored);
  }

  /**
   * Put a sealed envelope on the relay.
   *
   * Our own copy is marked seen first: the relay may echo a publish back to
   * the connection that made it, and re-handling our own invite would look
   * like a second creator.
   * @param {string} armored
   */
  async _publish(armored) {
    this._envSeen.seen(armored);
    // A stopped session, before an absent relay: two different facts, and only
    // one of them is anybody's news.
    //
    // The refusal below is a sentence somebody reads — `rotateRoom` reaches it
    // through `_broadcast`, `removeFromRoom` in `quorum-ops.js` awaits that, and
    // a person who pressed Remove while the relay was down is owed the reason.
    // So it stays, and it keeps meaning what it says: this session is running
    // and has no signalling.
    //
    // A send arriving after `stop()` is not that. The session tore its own
    // links down; what is still arriving is their late callbacks — an ICE
    // candidate gathered between `close()` and the connection actually going
    // (`onIceCandidate` is a bare `void this._sendTo`), a `_publishInvite` that
    // was already in `_handleSignal`'s queue. Nobody awaits those and nobody can
    // read an answer from them, so throwing only produces an unhandled rejection
    // blamed on whichever test happened to be running. Nothing a person presses
    // gets here after `stop()`: the private key is zeroed and the sealing above
    // would fail on it first.
    if (this._stopped) return;
    if (!this._relay) throw new Error("Notebook signalling is not connected");
    await this._relay.send(armored);
  }

  /**
   * @param {string} toFpr
   * @param {Partial<import("./crypto.js").NotebookEnvelopePayload>} fields
   * @param {{ recipients?: string[] }} [opts] seal to these audience members
   *   only. Signalling is sealed to the whole audience by default because a
   *   relaying member has to open an envelope to learn who it is for; naming
   *   recipients narrows that, at the cost of the envelope being unreadable
   *   (and therefore unrelayable) by everyone else.
   */
  async _sendTo(toFpr, fields, opts = {}) {
    const prior = this._outbound.get(toFpr) || Promise.resolve();
    // `then(work, work)` rather than `finally`: a send that failed still had
    // its turn, and the next one in line is owed the wire either way.
    const run = prior.then(
      () => this._sealAndSend(toFpr, fields, opts),
      () => this._sealAndSend(toFpr, fields, opts)
    );
    // The chain remembers only that the turn is over. A rejection belongs to
    // whoever asked for that send — carrying it forward would fail the next
    // one for something it did not do.
    this._outbound.set(
      toFpr,
      run.then(
        () => {},
        () => {}
      )
    );
    return run;
  }

  /**
   * Seal one envelope and put it on whichever wire will take it.
   *
   * Split from `_sendTo` so the ordering above wraps the whole seal-and-send,
   * not just the send: it is the seal that varies in length, so serialising
   * only the last step would leave the race exactly where it was.
   *
   * @param {string} toFpr
   * @param {Partial<import("./crypto.js").NotebookEnvelopePayload>} fields
   * @param {{ recipients?: string[] }} opts
   */
  async _sealAndSend(toFpr, fields, opts) {
    // Checked here as well as in `_publish`, and for a second reason: sealing
    // *signs*, and `stop()` zeroes this session's private key in place. A late
    // ICE candidate that got as far as the seal did not merely fail to send, it
    // signed with wiped material and surfaced as OpenPGP's "Invalid keyData" —
    // the same teardown race wearing a different error. Refusing before the
    // signature means the key is never reached at all. `_publish` carries the
    // argument for why this is silence rather than a refusal.
    if (this._stopped) return;
    const only = opts.recipients
      ? new Set(opts.recipients.map((f) => normalizeFingerprintInput(f)))
      : null;
    const audienceKeys = [...this.audienceKeys.entries()]
      .filter(([fpr]) => !only || only.has(fpr))
      .map(([, key]) => key);
    const payload = {
      v: 1,
      from: this.myFpr,
      to: toFpr,
      roomId: this.roomId,
      ts: Date.now(),
      ...fields,
    };
    const armored = await sealSignalingEnvelope({
      payload: /** @type {import("./crypto.js").NotebookEnvelopePayload} */ (
        payload
      ),
      signingKey: this.privateKey,
      audienceKeys,
    });
    // Channel-first: once links exist, signaling rides them and the relay
    // becomes the bootstrap-only path — a renegotiation survives the relay
    // dying, and a newcomer's introduction reaches peers it cannot signal
    // directly. The envelope is sealed end to end either way; the wire
    // carries nothing a relay can read or alter.
    if (this._sendEnvelopeViaChannel(toFpr, armored)) return;
    await this._publish(armored);
  }

  /**
   * @param {string} toFpr
   * @param {string} armored
   * @returns {boolean} whether any channel accepted it
   */
  _sendEnvelopeViaChannel(toFpr, armored) {
    // Never re-handle our own frame if a copy gossips back.
    this._envSeen.seen(armored);
    const frame = JSON.stringify({ v: 1, env: armored, hops: 0 });
    const direct = this.peers.get(toFpr);
    // Direct link: any open channel on a *live* connection will do —
    // pre-verification traffic is exactly what signaling is, and the envelope
    // carries its own proof. The liveness check matters during ICE failure: a
    // dying channel still reads "open" and would swallow the very restart offer
    // meant to revive it — that case must reach the mailbox.
    if (direct?.channel?.readyState === "open" && direct.link?.isLive()) {
      try {
        direct.channel.send(frame);
        return true;
      } catch (_) {
        /* fall through to relay / mailbox */
      }
    }
    // Relay: only over authenticated links (relayed introductions must ride
    // links whose far end is proven, DESIGN §7 step 4).
    let sent = false;
    for (const [fpr, p] of this.peers) {
      if (fpr === toFpr) continue;
      if (p.channel?.readyState === "open" && p.kcVerified && p.link?.isLive()) {
        try {
          p.channel.send(frame);
          sent = true;
        } catch (_) {
          /* this member just dropped — try the next */
        }
      }
    }
    return sent;
  }

  _emitRoster() {
    this.onRoster?.(this.peers);
  }
}

export { requireSelfInAudience, canonicalAudience };
