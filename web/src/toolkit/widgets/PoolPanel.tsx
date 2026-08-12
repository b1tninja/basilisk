export type PoolRound = "committing" | "revealing";
export type PoolPhase = "running" | "complete" | "refused" | "failed";

/** What has arrived *from this participant, to me*, in order. */
export type PoolParticipantState =
  | "waiting"
  | "committed"
  | "revealed"
  | "verified"
  | "broken"
  | "silent";

export type PoolParticipant = {
  /** Short room-scoped label. */
  id: string;
  fingerprint?: string;
  self?: boolean;
  state: PoolParticipantState;
};

export type PoolPanelProps = {
  phase: PoolPhase;
  /** Which half is outstanding. Only meaningful while `running`. */
  round?: PoolRound;
  participants: PoolParticipant[];
  /** The pooled value, once the round opened. */
  digest?: string;
  /** Whatever failed, in the words the pool layer used. */
  message?: string;
};

/**
 * Entropy the room drew together, while it is being drawn.
 *
 * `entropy.pool` blocks its cell for up to two minutes across two rounds, and
 * the person watching has two questions: is it still going, and who is it
 * waiting on. A single "running…" would answer neither, and a round that stalls
 * stalls on *one* participant.
 *
 * **`revealed` and `verified` are different states and this panel keeps them
 * apart.** A reveal arriving is not a reveal that opens its commitment —
 * `openEntropyPool` checks every one of them at the end, together — so until
 * the round opens, a revealed participant has handed over bytes nobody has
 * checked. Drawing them as verified would be the same lie as calling a DKG
 * share checked on arrival, and it matters more here: the whole ceremony exists
 * because a participant may choose their contribution after seeing the others,
 * and that is exactly what the check catches.
 *
 * ## No buttons, and why
 *
 * `entropy.pool` is one op that runs both rounds and returns the value. There is
 * nothing for a "reveal now" to call — revealing early is the one thing the
 * protocol must not let anybody do — and a restart is the cell's own Run. So
 * this takes no handlers and renders no controls. It is a progress view, and the
 * only thing it asks of a person is the last line: compare the digest.
 *
 * That comparison is not decoration. A participant who sends different
 * commitments to different peers splits the room, and each half computes a pool
 * the other does not have. `pool-run.js` says plainly that it cannot detect
 * this and the participants can — by comparing digests. This is where they read
 * the one they got.
 */
export function PoolPanel({
  phase,
  round = "committing",
  participants,
  digest = "",
  message = "",
}: PoolPanelProps) {
  const others = participants.filter((p) => !p.self);
  const committed = others.filter((p) => RANK[p.state] >= RANK.committed).length;
  const revealed = others.filter((p) => RANK[p.state] >= RANK.revealed).length;
  const waitingOn = others.filter((p) =>
    round === "committing" ? p.state === "waiting" : RANK[p.state] < RANK.revealed
  );

  return (
    <section className="pool-panel" data-phase={phase}>
      <header className="pool-head">
        <span className="pool-phase">{HEADLINE[phase]}</span>
        <span className="pool-count">{participants.length} participants</span>
      </header>
      <p className="pool-blurb">{BLURB[phase]}</p>

      {phase === "running" ? (
        <ul className="pool-progress">
          <li data-complete={others.length && committed === others.length ? "yes" : "no"}>
            Committed · {committed} of {others.length}
          </li>
          {/* Named "handed over", not "checked". Nothing has checked these. */}
          <li data-complete={others.length && revealed === others.length ? "yes" : "no"}>
            Revealed · {revealed} of {others.length}
          </li>
        </ul>
      ) : null}

      {phase === "running" && waitingOn.length ? (
        <p className="pool-waiting" data-pool-waiting>
          Waiting on {waitingOn.map((p) => p.id).join(", ")} to{" "}
          {round === "committing" ? "commit" : "reveal"}. Nobody reveals until every
          commitment is in — a value drawn without them would be one the rest of us chose.
        </p>
      ) : null}

      <ul className="pool-roster">
        {participants.map((p) => (
          <li className="pool-row" key={p.fingerprint || p.id}>
            <span className="peer-dot" data-peer-state={DOT[p.state]} aria-hidden />
            <code className="pool-id" title={p.fingerprint || undefined}>
              {p.id}
              {p.self ? " (you)" : ""}
            </code>
            <span className="pool-state" data-pool-state={p.state}>
              {LABEL[p.state]}
            </span>
          </li>
        ))}
      </ul>

      {phase === "complete" && digest ? (
        <div className="pool-result">
          <dl className="pool-facts">
            <dt>Pooled value</dt>
            <dd>
              <code className="pool-digest">{digest}</code>
            </dd>
          </dl>
          {/* The one thing this panel asks of a person, and the only defence
              against a split view — see the module note. */}
          <p className="pool-note">
            Read this to the others. Everyone who took part computed the same number;
            two different numbers in one room means somebody committed differently to
            different people, and nothing here can see that from one seat.
          </p>
        </div>
      ) : null}

      {phase === "refused" || phase === "failed" ? (
        <p className="pool-refusal" data-pool-refusal>
          {message}
        </p>
      ) : null}
    </section>
  );
}

/** Order the states arrive in, so "at least committed" is one comparison. */
const RANK: Record<PoolParticipantState, number> = {
  waiting: 0,
  silent: 0,
  committed: 1,
  broken: 1,
  revealed: 2,
  verified: 3,
};

const LABEL: Record<PoolParticipantState, string> = {
  waiting: "waiting",
  committed: "committed",
  // Deliberately not "revealed ✓". Nothing has checked it yet.
  revealed: "revealed, unchecked",
  verified: "checked",
  broken: "does not open",
  silent: "committed, then gone",
};

/** Reuses ConnectionsPanel's dot vocabulary rather than inventing a second one. */
const DOT: Record<PoolParticipantState, string> = {
  waiting: "new",
  committed: "connecting",
  revealed: "connecting",
  verified: "connected",
  broken: "failed",
  silent: "disconnected",
};

const HEADLINE: Record<PoolPhase, string> = {
  running: "Drawing a value together",
  complete: "The room drew a value nobody chose",
  refused: "Refused — the round was not honest",
  failed: "The round did not finish",
};

const BLURB: Record<PoolPhase, string> = {
  running:
    "Everyone commits to a number before anyone reveals one, so nobody can pick theirs after seeing the rest.",
  complete:
    "The value is a digest over every contribution. Change one and it is a different number, which is what makes it nobody's choice.",
  refused:
    "Nothing was pooled. A value drawn without a participant is a value the rest of the room chose, which is the outcome committing first exists to prevent.",
  failed: "Nothing was pooled.",
};
