import { Button } from "@/components/ui/button";
import { meshHealth } from "@/lib/notebook/relay.js";
import {
  DKG_EXPERIMENTAL_NOTE,
  DKG_STAGES,
  badDealers,
  canFinalize,
  dkgPhase,
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
 * **Designed ahead of the op layer** — `lib/quorum/dkg.js` has the rounds,
 * nothing yet runs them over the live exchange, and this panel is deliberately
 * not wired into the shell. It is here so that the failure path is designed
 * before the transport is, and so the catalog can show what "waiting for 2 of 5
 * commitments" and "refused, and here is why that is not simply someone's
 * fault" look like. `lib/quorum/dkg-session.js` owns every sentence.
 *
 * Three axes are reported separately for each participant and never merged:
 * **connected** (the pipe), **authenticated** (who is on the other end), and
 * **round** (what they have contributed). They are genuinely independent — a
 * fully connected, fully verified participant can still have dealt a share that
 * does not check out, and that is exactly the case the panel exists for.
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
          <Button onClick={onStart} disabled={participants.length < 2}>
            Deal round 1
          </Button>
        ) : null}
        {phase === "finalizing" && onFinalize ? (
          <Button onClick={onFinalize} disabled={!canFinalize(participants)}>
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
