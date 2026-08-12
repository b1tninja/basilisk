/**
 * The DKG session, as a state model — **design-ahead of the op layer.**
 *
 * `lib/quorum/dkg.js` implements the arithmetic (`round1` / `verifyShare` /
 * `finalize`). What does not exist, deliberately, is an op that runs those
 * rounds over the live exchange. This module is the shape of the session such
 * an op would drive, written now because the *failure* path is where the design
 * work is, and designing it after the transport exists means designing it under
 * pressure to make the transport look good.
 *
 * Nothing here talks to a peer, a channel, or the registry. It is a pure
 * projection from "what have I received from whom" to "what should this person
 * be told", and it is tested as such. See `redesign/CAPABILITY-SURFACES.md` for
 * what is assumed versus built.
 *
 * ## The protocol, in the two sentences the UI has to convey
 *
 * Everyone deals a secret nobody else chose, and everyone adds up the shares
 * they were dealt. The key that results was never assembled anywhere, which is
 * the point — and also why there is no "download the key" step to look forward
 * to, and why the UI must not imply one.
 *
 * ## Why the refusal path dominates this file
 *
 * `finalize` refuses on a bad share and names the dealer. There is **no
 * complaint round**. Three consequences the UI has to carry, none of which are
 * obvious from a stack trace:
 *
 * 1. **A refusal is total.** There is no partial key, no "continue without
 *    them" that preserves what has been done. The group restarts from round 1.
 * 2. **Only the recipient sees it.** Feldman commitments are broadcast, but the
 *    shares are pairwise. A dealer who sends one bad share corrupts exactly one
 *    participant's view — so "X dealt badly" is, from everyone else's seat,
 *    indistinguishable from "you are claiming X dealt badly".
 * 3. **Therefore the remedy is social, not mechanical.** Excluding a
 *    participant on one accuser's word is precisely the attack a complaint
 *    round exists to prevent. The UI offers a restart, and says plainly that
 *    the group has to establish what happened out of band first. Offering
 *    "Exclude them" as a confident button would be building the eviction
 *    primitive without the adjudication that makes it safe.
 *
 * @module lib/quorum/dkg-session
 */

/**
 * @typedef {"waiting"|"commitments"|"share"|"verified"|"bad"} ParticipantRound
 *   What has arrived *from this participant, to me*, in order. `verified` means
 *   their share checks against their own broadcast commitments; `bad` means it
 *   does not, which is the only terminal state a participant can be put into by
 *   evidence rather than by time.
 */

/**
 * @typedef {object} DkgParticipant
 * @property {string} id           short room-scoped label
 * @property {string} [fingerprint]
 * @property {boolean} [self]
 * @property {ParticipantRound} round
 * @property {import("../../toolkit/widgets/ConnectionsPanel").ConnectionPeer["state"]} [state]
 * @property {boolean} [authenticated]
 */

/** @typedef {"assembling"|"dealing"|"collecting"|"finalizing"|"complete"|"refused"} DkgPhase */

/**
 * @typedef {object} DkgStage
 * @property {DkgPhase} id
 * @property {string} title
 * @property {string} blurb
 */

/** @type {readonly DkgStage[]} */
export const DKG_STAGES = Object.freeze([
  {
    id: "assembling",
    title: "Gather the participants",
    blurb:
      "Everyone who will hold a share has to be present and authenticated before round 1 starts. Adding someone later is a different key.",
  },
  {
    id: "dealing",
    title: "Deal",
    blurb:
      "Each participant picks a secret nobody else knows, publishes commitments to it, and sends every other participant one share of it.",
  },
  {
    id: "collecting",
    title: "Collect and check",
    blurb:
      "Each share you receive is checked against its dealer's published commitments as it arrives. A share that fails is checked again at finalize; there is nowhere for a bad one to hide.",
  },
  {
    id: "finalizing",
    title: "Finalize",
    blurb:
      "Add the verified shares together. Your share of the joint key is that sum; the joint public key is the sum of everyone's commitments. Nobody computes the secret, then or ever.",
  },
  {
    id: "complete",
    title: "Done",
    blurb:
      "The group holds a key that was never assembled. This is a shared key, not threshold signing — signing with it still requires reconstructing it somewhere.",
  },
  {
    id: "refused",
    title: "Refused",
    blurb:
      "A share did not match its dealer's commitments. Nothing usable was produced, and no part of this run can be salvaged.",
  },
]);

/** @param {DkgPhase} id */
export function stageFor(id) {
  return DKG_STAGES.find((s) => s.id === id) || DKG_STAGES[0];
}

const ROUND_ORDER = ["waiting", "commitments", "share", "verified"];

/**
 * How far a participant has got, as a number, for progress arithmetic only.
 * `bad` is deliberately not on the scale — it is not "less far along".
 * @param {ParticipantRound} round
 */
function rank(round) {
  const i = ROUND_ORDER.indexOf(round);
  return i < 0 ? -1 : i;
}

/**
 * Progress toward a milestone, in the form the UI states it.
 *
 * The denominator is every participant *other than me*, because I do not wait
 * on myself — a "3 of 5 commitments" line that silently counts my own is off by
 * one in the direction of looking healthier than it is.
 *
 * @param {DkgParticipant[]} participants
 * @param {"commitments"|"share"|"verified"} milestone
 * @returns {{ have: number, need: number, label: string, complete: boolean }}
 */
export function roundProgress(participants, milestone) {
  const others = (participants || []).filter((p) => !p.self);
  const want = rank(milestone);
  const have = others.filter((p) => p.round !== "bad" && rank(p.round) >= want).length;
  const need = others.length;
  const noun =
    milestone === "commitments"
      ? "commitments"
      : milestone === "share"
        ? "shares"
        : "verified shares";
  return {
    have,
    need,
    complete: need > 0 && have === need,
    label: need ? `${have} of ${need} ${noun}` : `no other participants yet`,
  };
}

/**
 * Which participants dealt something that does not check out.
 * @param {DkgParticipant[]} participants
 * @returns {DkgParticipant[]}
 */
export function badDealers(participants) {
  return (participants || []).filter((p) => p.round === "bad");
}

/**
 * Can `finalize` be attempted?
 *
 * Every other participant verified, and none bad. Not "enough of them" —
 * joint-Feldman sums *all* contributions, so a missing one is a different key,
 * not a smaller quorum. Threshold governs later reconstruction, not this.
 *
 * @param {DkgParticipant[]} participants
 * @returns {boolean}
 */
export function canFinalize(participants) {
  const others = (participants || []).filter((p) => !p.self);
  if (!others.length) return false;
  return others.every((p) => p.round === "verified");
}

/**
 * The same question, answered in a sentence — why finalize is not offered yet.
 *
 * `canFinalize` returns a boolean, and a boolean is what a control has to
 * render as a dead button with nothing to read. The two states behind that
 * false are not alike: nobody has dealt to you yet, or somebody's shares have
 * not checked out — and the second is the one where waiting is the wrong thing
 * to do. It counts rather than naming, because the roster above the button
 * already names every participant and their round.
 *
 * Kept beside `canFinalize` so the condition and its explanation cannot drift;
 * `startIssues` in `session-flow.js` sets the pattern.
 *
 * @param {DkgParticipant[]} participants
 * @returns {string|null} null when finalize is possible
 */
export function finalizeIssue(participants) {
  const others = (participants || []).filter((p) => !p.self);
  if (!others.length) {
    return "Nobody else is in this session. A joint key sums every participant's contribution, so there is nothing to finalize on your own.";
  }
  const unverified = others.filter((p) => p.round !== "verified");
  if (!unverified.length) return null;
  const bad = unverified.filter((p) => p.round === "bad").length;
  if (bad) {
    return `${bad} of ${others.length} dealt shares that do not check against their commitments. Finalizing would fold a bad contribution into the key — start a new session rather than waiting.`;
  }
  return `${unverified.length} of ${others.length} have not dealt shares that check out yet. Every contribution is summed into the joint key, so a missing one makes a different key rather than a smaller quorum.`;
}

/**
 * The phase, derived rather than tracked.
 *
 * Derived because a stored phase and a participant list can disagree, and when
 * they do the stored one wins on screen while the real one governs the
 * protocol. There is exactly one source of truth here and it is what arrived.
 *
 * @param {{ participants: DkgParticipant[], started?: boolean, jointPublicKey?: string }} x
 * @returns {DkgPhase}
 */
export function dkgPhase({ participants, started = false, jointPublicKey = "" }) {
  if (jointPublicKey) return "complete";
  if (badDealers(participants).length) return "refused";
  if (!started) return "assembling";
  if (canFinalize(participants)) return "finalizing";
  const commits = roundProgress(participants, "commitments");
  return commits.complete ? "collecting" : "dealing";
}

/**
 * What to say when `finalize` refuses.
 *
 * The wording is the deliverable. A raw `dkg: share from 4f2a… does not match
 * their commitments` is accurate and tells a non-expert nothing about what just
 * happened, what it cost, or what they are allowed to conclude — and the thing
 * they are *not* allowed to conclude is the one that matters, because acting on
 * it evicts a possibly honest participant.
 *
 * @param {{ dealer: DkgParticipant|null, participants: DkgParticipant[] }} x
 * @returns {{ headline: string, what: string, cost: string, remedy: string, caution: string }}
 */
export function refusalReport({ dealer, participants }) {
  const who = dealer?.id || "a participant";
  const others = (participants || []).filter((p) => !p.self);
  return {
    headline: `Key generation refused — the share from ${who} does not match their commitments.`,
    what:
      `${who} published commitments to a secret, then sent you a share of something else. ` +
      "That is either a deliberately malformed deal or a bug on their side; the arithmetic " +
      "cannot tell the two apart, and neither can you from here.",
    cost:
      `Nothing usable came out of this run. The joint key is the sum of all ${others.length + 1} ` +
      "contributions, so one bad contribution is not a share short — it is a different key that " +
      "nobody can reconstruct. There is no partial result to keep.",
    remedy:
      `Start again without ${who}. Everyone has to restart together: a participant who runs ` +
      "round 1 again while others hold their old state ends up in a third key that matches nobody.",
    // The part a stack trace could never say, and the reason there is no
    // one-click "exclude" here.
    caution:
      `Only you saw this. Commitments are broadcast, but shares are sent one to one, so ${who} ` +
      "could have dealt honestly to everyone else — and from their seat, your accusation and a " +
      "genuine fault look the same. This build has no complaint round to settle it. Compare notes " +
      "with the other participants out of band before anyone is excluded on your word alone.",
  };
}

/**
 * The standing disclaimer. Rendered on the panel in every phase, including
 * `complete`, because that is the phase in which someone decides what to
 * protect with the thing they just made.
 */
export const DKG_EXPERIMENTAL_NOTE =
  "Experimental. This produces a key the group jointly controls; it does not produce threshold " +
  "signing — using the key still means reconstructing it somewhere, on one machine, at which " +
  "point one machine holds it. It has not been independently reviewed. Do not put anything " +
  "unrecoverable behind it.";
