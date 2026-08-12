import { DkgPanel } from "basilisk-portal";

/*
 * Distributed key generation across a live session: every participant deals a
 * contribution, verifies what they receive, and sums — so the private key is
 * never assembled anywhere, and any `threshold` of the room can reconstruct it
 * later.
 *
 * The panel's job is making a multi-round protocol legible while it runs. Each
 * participant carries their own `round`, because a DKG stalls on *one* peer
 * and a single session-level progress bar would hide which. The rounds run
 * `waiting → commitments → share → verified`, with `bad` as the terminal
 * failure.
 *
 * There is no complaint round: a bad share aborts the run and names the
 * dealer, and the group restarts without them. That is why `bad` is a state
 * the design must handle rather than an edge case — it is the only way this
 * protocol ends badly, and it ends the whole run.
 */

const frame = { maxWidth: 560 };

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

/**
 * Before the run. Everyone is present and authenticated, nobody has dealt yet
 * — the only state in which starting is a sensible offer, which is why Start
 * is the single control.
 */
export const Default = () => (
  <div style={frame}>
    <DkgPanel
      threshold={2}
      participants={[
        { id: "@ada", fingerprint: ADA, self: true, round: "waiting", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "waiting", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "waiting", state: "connected", authenticated: true },
      ]}
      onStart={() => {}}
    />
  </div>
);

/**
 * Mid-run, and unevenly. Two peers have verified what they received while a
 * third is still dealing commitments.
 *
 * This is the state the per-participant rounds exist for: the run is neither
 * finished nor stuck, and the only useful thing on screen is *which* peer the
 * rest are waiting on.
 */
export const InProgress = () => (
  <div style={frame}>
    <DkgPanel
      started
      threshold={2}
      participants={[
        { id: "@ada", fingerprint: ADA, self: true, round: "verified", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "verified", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "commitments", state: "connected", authenticated: true },
      ]}
      onRestart={() => {}}
    />
  </div>
);

/**
 * Everyone verified, ready to finalize. The joint public key is the run's
 * product and the only artifact that leaves it — the private half exists
 * nowhere, which is the entire point of doing this rather than generating a
 * key and sharing it.
 */
export const ReadyToFinalize = () => (
  <div style={frame}>
    <DkgPanel
      started
      threshold={2}
      participants={[
        { id: "@ada", fingerprint: ADA, self: true, round: "verified", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "verified", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "verified", state: "connected", authenticated: true },
      ]}
      onFinalize={() => {}}
      onRestart={() => {}}
    />
  </div>
);

/**
 * Complete, with the joint key. Nothing here is secret — the public key is
 * exactly what everyone is meant to walk away with.
 */
export const Complete = () => (
  <div style={frame}>
    <DkgPanel
      started
      threshold={2}
      jointPublicKey="039f26bbd060841e88d4995e4e376491319474d5e51101bd108334ede83086f706"
      participants={[
        { id: "@ada", fingerprint: ADA, self: true, round: "verified", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "verified", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "verified", state: "connected", authenticated: true },
      ]}
      onRestart={() => {}}
    />
  </div>
);

/**
 * A bad share, which ends the run.
 *
 * `@lin` is marked `bad` and the whole ceremony is over — there is no round in
 * which the group negotiates about it. The design has to carry that finality,
 * because the recovery is social rather than technical: decide whether that
 * peer was faulty or hostile, then restart without them.
 */
export const BadShare = () => (
  <div style={frame}>
    <DkgPanel
      started
      threshold={2}
      participants={[
        { id: "@ada", fingerprint: ADA, self: true, round: "verified", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "verified", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "bad", state: "connected", authenticated: true },
      ]}
      onRestart={() => {}}
    />
  </div>
);

/**
 * **How the shell actually mounts it, and why there are no buttons.**
 *
 * The stories above draw a session someone hand-cranks, which is what this
 * panel was designed for. What shipped is `dkg.run`: one op that deals every
 * round, finalizes itself, and blocks its cell for up to two minutes. Two of
 * the three buttons have nothing to call and the third would be a restart the
 * op layer does not offer — so `ToolkitShell` passes no handlers, and every
 * handler being optional means none of them render.
 *
 * This is the state a person actually sits with: a cell that has been busy for
 * ninety seconds, and the answer to *is it still going* and *who is it waiting
 * on*. `@lin` has dealt nothing yet and is the reason this run has not
 * finished; a session-level progress bar would have hidden that, which is why
 * `round` is per participant.
 *
 * The buttons are waiting on a decision, not broken. Whether a DKG should also
 * be drivable a round at a time needs a session that outlives a cell, and that
 * is a question about the op layer — to be answered because a ceremony needs
 * it, not because a panel has affordances drawn for it.
 */
export const AsTheShellMountsIt = () => (
  <div style={frame}>
    <DkgPanel
      started
      threshold={2}
      participants={[
        { id: "you", fingerprint: ADA, self: true, round: "verified", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "share", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "waiting", state: "connected", authenticated: true },
      ]}
    />
  </div>
);

/**
 * A refusal, as the shell shows it — and the button that is **not** here.
 *
 * `dkg.run` throws when a share does not check, and the panel is the only place
 * that says what that means: the run is over, there is no partial key, and the
 * group restarts from round 1. It offers a restart and nothing else.
 *
 * There is deliberately no *Exclude them*. Feldman commitments are broadcast
 * but shares are pairwise, so a dealer who sends one bad share corrupts exactly
 * one participant's view — which makes "@lin dealt badly" indistinguishable,
 * from every other seat, from "you are claiming @lin dealt badly". A confident
 * eviction button would be the adjudication primitive without the adjudication.
 * The remedy is people talking to each other, and the last paragraph says so.
 */
export const RefusedInTheShell = () => (
  <div style={frame}>
    <DkgPanel
      started
      threshold={2}
      participants={[
        { id: "you", fingerprint: ADA, self: true, round: "verified", state: "connected", authenticated: true },
        { id: "@grace", fingerprint: GRACE, round: "verified", state: "connected", authenticated: true },
        { id: "@lin", fingerprint: LIN, round: "bad", state: "connected", authenticated: true },
      ]}
    />
  </div>
);
