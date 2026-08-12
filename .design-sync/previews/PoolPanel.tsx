import { PoolPanel } from "basilisk-portal";

/*
 * Randomness the room drew together, while it is being drawn.
 *
 * `entropy.pool` blocks its cell for up to two minutes across two rounds:
 * everyone commits to a number, and only when every commitment is in does
 * anyone reveal. That ordering is the whole protocol — reveal while a
 * commitment is outstanding and whoever has not committed can pick theirs after
 * seeing a contribution, which is the last-mover advantage committing exists to
 * remove.
 *
 * So the panel's job is the two questions a person actually has while a cell
 * sits there: **is it still going, and who is it waiting on.** A single
 * "running…" answers neither, and a round stalls on *one* participant.
 *
 * **`revealed` and `checked` are different states here, and the panel keeps
 * them apart.** Reveals are verified all at once at the end, so until the round
 * opens, a revealed participant has handed over bytes nobody has checked. The
 * chip says "revealed, unchecked" and stays muted — deliberately not a tick,
 * because the one thing this ceremony catches is a participant whose reveal
 * does not open their commitment.
 *
 * **No buttons.** Not because the op happens to do everything, but because the
 * only control anyone could want — "reveal now" — is an affordance for the one
 * act the protocol forbids. The cell's own Run starts it.
 */

const MARA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const OKAFOR = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

const you = { id: "you", fingerprint: MARA, self: true, state: "verified" as const };

/**
 * Round one. Two of three have committed and `@lin` has not, so nobody may
 * reveal yet — the sentence under the counts says why, because a person
 * watching a stalled cell will otherwise assume it is broken rather than
 * waiting on somebody.
 */
export const Committing = () => (
  <PoolPanel
    phase="running"
    round="committing"
    participants={[
      you,
      { id: "@okafor", fingerprint: OKAFOR, state: "committed" },
      { id: "@lin", fingerprint: LIN, state: "waiting" },
    ]}
  />
);

/**
 * **The state the design turns on.** Every commitment is in, so reveals are
 * flowing — and `@okafor`'s reads *"revealed, unchecked"*, muted, not a tick.
 *
 * Nothing has verified it. `openEntropyPool` checks every reveal against its
 * commitment at the end, together, and a reveal that does not open its
 * commitment is the exact attack this ceremony exists to catch. A chip that
 * said "revealed ✓" here would be the same lie as marking a DKG share checked
 * on arrival, and it would be told at the moment it matters most.
 */
export const Revealing = () => (
  <PoolPanel
    phase="running"
    round="revealing"
    participants={[
      you,
      { id: "@okafor", fingerprint: OKAFOR, state: "revealed" },
      { id: "@lin", fingerprint: LIN, state: "committed" },
    ]}
  />
);

/**
 * Done — and the last paragraph is the only thing this panel asks of a person.
 *
 * A participant who sends different commitments to different peers splits the
 * room, and each half computes a pool the other does not have. `pool-run.js`
 * says plainly that it cannot detect that and the participants can, by
 * comparing digests. So the value is shown whole and selectable, and the copy
 * says what two different numbers in one room would mean.
 */
export const Complete = () => (
  <PoolPanel
    phase="complete"
    participants={[
      you,
      { id: "@okafor", fingerprint: OKAFOR, state: "verified" },
      { id: "@lin", fingerprint: LIN, state: "verified" },
    ]}
    digest="9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021"
  />
);

/**
 * A reveal that does not open its commitment: a contribution chosen after
 * seeing the others. The round is refused **whole** — there is no pooling
 * without them, because a value drawn without a participant is a value the rest
 * of the room chose, which is the outcome committing first prevents.
 *
 * Note what is absent: no "exclude and retry". The same argument as the DKG's
 * missing eviction button applies, and the remedy is the cell's Run once the
 * room has sorted it out.
 */
export const Refused = () => (
  <PoolPanel
    phase="refused"
    participants={[
      you,
      { id: "@okafor", fingerprint: OKAFOR, state: "verified" },
      { id: "@lin", fingerprint: LIN, state: "broken" },
    ]}
    message="entropy pool: @lin revealed a nonce that does not open their commitment. That is a contribution chosen after seeing the others, which is the one thing committing first was for — so the round is refused rather than pooled without them."
  />
);

/**
 * Committed, then gone — drawn as its own state and its own colour, because it
 * is a different event from a bad reveal. Somebody offline is not somebody who
 * cheated, and the room has to be able to tell them apart; pooling without
 * either would hand the value to whoever decided to stop waiting.
 */
export const CommittedThenGone = () => (
  <PoolPanel
    phase="refused"
    participants={[
      you,
      { id: "@okafor", fingerprint: OKAFOR, state: "revealed" },
      { id: "@lin", fingerprint: LIN, state: "silent" },
    ]}
    message="entropy pool: @lin committed and did not reveal. The round is not complete, and pooling without them would let whoever is left choose the value."
  />
);
