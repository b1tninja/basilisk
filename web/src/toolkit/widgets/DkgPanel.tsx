import { Button } from "@/components/ui/button";
import { meshHealth } from "@/lib/notebook/relay.js";
import {
  DKG_EXPERIMENTAL_NOTE,
  DKG_STAGES,
  badDealers,
  dkgPhase,
  finalizeIssue,
  refusalReport,
  roundProgress,
  stageFor,
  type DkgParticipant,
  type DkgPhase,
} from "../../lib/quorum/dkg-session.js";

export type DkgPanelProps = {
  participants: DkgParticipant[];
  /** Round 1 has been dealt. Before that the session is still assembling. */
  started?: boolean;
  /** Set once `finalize` succeeded — the compressed joint public key. */
  jointPublicKey?: string;
  /** Threshold that will govern later reconstruction, for the summary line. */
  threshold?: number;
  onStart?: () => void;
  onFinalize?: () => void;
  onRestart?: () => void;
};

/**
 * Distributed key generation, as a session.
 *
 * Three axes are reported separately for each participant and never merged:
 * **connected** (the pipe), **authenticated** (who is on the other end), and
 * **round** (what they have contributed). They are genuinely independent — a
 * fully connected, fully verified participant can still have dealt a share that
 * does not check out, and that is exactly the case the panel exists for.
 *
 * `lib/quorum/dkg-session.js` owns every sentence and every phase; nothing here
 * decides what state the session is in.
 *
 * ## Mounted as a progress view, with its buttons unrendered
 *
 * This was designed ahead of the op layer and sat in the catalog for a while,
 * which is why it draws a session someone hand-cranks: *Deal round 1*,
 * *Finalize*, *Start a new session*. What shipped instead is `dkg.run` — one op
 * that deals every round, finalizes itself, and blocks its cell for up to two
 * minutes.
 *
 * So `ToolkitShell` mounts it with **no handlers**, and every handler is
 * optional, so none of those buttons render. That is not a gap being papered
 * over: a person watching a cell block for two minutes needs to know it is
 * still going and who it is waiting on, and this answers both. The start button
 * is the cell's own Run.
 *
 * The buttons are waiting on a decision, not broken. Whether a DKG should also
 * be drivable a round at a time is a question about the op layer — it would
 * need a session that outlives a cell — and it should be answered because a
 * ceremony needs it, not because a panel has affordances drawn for it.
 *
 * What must not appear, whatever is decided: an **Exclude them** button. A
 * refusal is total, and pairwise shares make "X dealt badly" indistinguishable
 * from "you are claiming X dealt badly" from every other seat, so the remedy is
 * social and the panel offers a restart and says so. `dkg-session.js` states
 * the whole argument.
 */
export function DkgPanel({
  participants,
  started = false,
  jointPublicKey = "",
  threshold = 0,
  onStart,
  onFinalize,
  onRestart,
}: DkgPanelProps) {
  const phase: DkgPhase = dkgPhase({ participants, started, jointPublicKey });
  const stage = stageFor(phase);
  const commits = roundProgress(participants, "commitments");
  const shares = roundProgress(participants, "verified");
  const bad = badDealers(participants);
  const health = meshHealth(participants.length);

  return (
    <section className="dkg-panel" data-phase={phase}>
      <header className="dkg-head">
        <span className="dkg-phase">{stage.title}</span>
        <span className="dkg-count">{participants.length} participants</span>
      </header>
      <p className="dkg-blurb">{stage.blurb}</p>

      {/* The same soft cap ConnectionsPanel states, for the same reason: a DKG
          is a full mesh, and full meshes are quadratically wrong past ~8. */}
      <p className="dkg-mesh" data-mesh-health={health.overCap ? "over-cap" : "ok"}>
        mesh · {health.note}
      </p>

      {phase === "refused" ? (
        <RefusalBanner participants={participants} dealer={bad[0] ?? null} />
      ) : null}

      {phase === "complete" ? (
        <div className="dkg-result">
          <p className="dkg-result-headline">
            The group holds a key nobody assembled.
          </p>
          <dl className="dkg-facts">
            <dt>Joint public key</dt>
            <dd>
              <code className="dkg-key">{jointPublicKey}</code>
            </dd>
            {threshold ? (
              <>
                <dt>Reconstruction</dt>
                <dd>
                  any {threshold} of {participants.length} shares
                </dd>
              </>
            ) : null}
          </dl>
          {/* There is no "download the key" here on purpose: the secret does
              not exist, and offering a button implying otherwise would misstate
              the whole protocol. */}
          <p className="dkg-note">
            Your share is held by this session and nothing else. There is no secret to
            export — that is the property you were buying.
          </p>
        </div>
      ) : null}

      {started && phase !== "complete" && phase !== "refused" ? (
        <ul className="dkg-progress">
          <li data-complete={commits.complete ? "yes" : "no"}>
            Commitments · {commits.label}
          </li>
          <li data-complete={shares.complete ? "yes" : "no"}>
            Checked shares · {shares.label}
          </li>
        </ul>
      ) : null}

      <ul className="dkg-roster">
        {participants.map((p) => (
          <li className="dkg-row" key={p.fingerprint || p.id}>
            <span className="peer-dot" data-peer-state={p.state || "new"} aria-hidden />
            <code className="dkg-id" title={p.fingerprint || undefined}>
              {p.id}
              {p.self ? " (you)" : ""}
            </code>
            <span className="dkg-auth" data-auth={p.authenticated ? "yes" : "no"}>
              {p.authenticated ? "verified" : "unverified"}
            </span>
            <span className="dkg-round" data-round={p.round}>
              {roundLabel(p)}
            </span>
          </li>
        ))}
      </ul>

      <p className="dkg-experimental">{DKG_EXPERIMENTAL_NOTE}</p>

      <div className="dkg-actions">
        {phase === "assembling" && onStart ? (
          <Button
            onClick={onStart}
            // Not "needs 2" — the number is what the reader can already count
            // in the roster above. What they cannot see is why one is not
            // enough, and that is a property of the protocol, not a minimum.
            disabledReason={
              participants.length < 2
                ? `Only ${participants.length === 1 ? "you are" : "nobody is"} in this session. A joint key is the sum of every participant's contribution, so dealing to yourself would produce an ordinary key with extra steps — wait for at least one more.`
                : undefined
            }
          >
            Deal round 1
          </Button>
        ) : null}
        {phase === "finalizing" && onFinalize ? (
          <Button onClick={onFinalize} disabledReason={finalizeIssue(participants) ?? undefined}>
            Finalize
          </Button>
        ) : null}
        {phase === "refused" && onRestart ? (
          <Button variant="secondary" onClick={onRestart}>
            Start a new session
          </Button>
        ) : null}
      </div>
    </section>
  );
}

/** Words per round state, from this participant's point of view. */
function roundLabel(p: DkgParticipant): string {
  if (p.self) return "you";
  switch (p.round) {
    case "commitments":
      return "commitments in";
    case "share":
      return "share in";
    case "verified":
      return "checked";
    case "bad":
      return "does not check";
    default:
      return "waiting";
  }
}

/**
 * The refusal.
 *
 * Four paragraphs rather than one, because the reader has four separate things
 * to learn and the last one — that they may be wrong about who is at fault — is
 * the one a single-sentence error would drop.
 */
function RefusalBanner({
  participants,
  dealer,
}: {
  participants: DkgParticipant[];
  dealer: DkgParticipant | null;
}) {
  const r = refusalReport({ dealer, participants });
  return (
    <div className="dkg-refusal">
      <strong className="dkg-refusal-headline">{r.headline}</strong>
      <p>{r.what}</p>
      <p>{r.cost}</p>
      <p>{r.remedy}</p>
      <p className="dkg-refusal-caution">{r.caution}</p>
    </div>
  );
}
