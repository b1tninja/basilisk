import { cn } from "@/lib/cn";
import { PEER_SIGIL, SLOT_SIGIL } from "../../lib/toolkit/recipe-parse.js";
import type { RunPlan, PlannedCell } from "../../lib/toolkit/plan.js";

/**
 * Labels travel through the plan bare (`a`, `mara`); the notebook language
 * writes them `$a` and `@mara`. The sigils are added here from the same
 * constants the parser uses, rather than spelled out — the `@`→`$` slot
 * migration is exactly the kind of change a hardcoded sigil in a widget would
 * survive without noticing.
 *
 * They are not decoration. The plan's own sentences are rendered verbatim
 * beside these labels and they carry the sigils ("runs on `@mara` because it
 * reads $a"), so a row reading a bare `mara` next to a `why` reading `@mara`
 * puts two spellings of one name on one line.
 */
const slot = (label: string) => `${SLOT_SIGIL}${label}`;
const peer = (label: string) => `${PEER_SIGIL}${label}`;

export type PlanPanelProps = {
  /** A `planRun` result, whole. */
  plan: RunPlan;
  className?: string;
};

/**
 * Where every cell runs, and why — the shared notebook's commitment, before
 * anything runs.
 *
 * `planRun` already answers this from the recipe text and a roster. Nothing
 * here re-derives it: every sentence on screen is the plan's own `why`,
 * `message` or `question`, rendered verbatim. A panel that paraphrased would
 * become a second opinion about placement, and two opinions eventually
 * disagree — which is exactly how a key leaves a machine it was never supposed
 * to leave. `placement.js` refuses to be that second opinion for the same
 * reason; this is the display half of the same rule.
 *
 * Three things the layout insists on:
 *
 * - **Refusals come first and are not collapsible.** `ok: false` means the run
 *   cannot start, so a reader scrolling past a cell list to discover that has
 *   already been misled about what this notebook is going to do. Each refusal
 *   carries the sentence naming its own remedy.
 * - **Empty cells are counted, not hidden.** The plan's six buckets sum to
 *   `cells.length` precisely because `empty` exists, and a panel that dropped
 *   blank cells would renumber every cell after the first blank — the defect
 *   the cell-index work closed at the manifest layer, reintroduced at the
 *   display layer.
 * - **`unknownPeers` is stated on its own line.** The recipe naming someone who
 *   is not in the room is not a per-cell problem; it is a fact about the
 *   notebook, and burying it in one cell's `why` makes it look local.
 *
 * **Cell numbers are the plan's, not this panel's.** They are printed as
 * `cell.index` with nothing added. Displaying `index + 1` to look 1-based put
 * two numbering schemes on one screen: a refusal whose own `path` reads
 * `cell 1` and whose message reads "Cell 1 says `@okafor` … (cell 0)" sat
 * directly above a row this panel had relabelled `cell 2`. The planner's
 * sentences are rendered verbatim, so its indices have to be too — the same
 * rule, one layer down, that made a cell index mean one thing everywhere.
 */
export function PlanPanel({ plan, className }: PlanPanelProps) {
  const placed = plan.play === "placed";
  return (
    <section
      className={cn("flex flex-col gap-2.5 text-[12px]", className)}
      data-plan-panel
      data-play={plan.play}
    >
      <header className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          {PLAY_TITLE[plan.play]}
        </span>
        {plan.me ? (
          <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
            you are {peer(plan.me)}
          </span>
        ) : null}
        {/* A roster is what turns a label into a person. Without one the
            labels are still parsed and still shown — they just do not mean
            anybody yet, and saying so is more useful than hiding the plan.
            Only when the notebook actually names somebody, though: on a solo
            notebook there are no labels to be unbound, and the line read as a
            warning about nothing. */}
        {!plan.bound && plan.peers.length ? (
          <span className="text-[10px] text-[var(--muted-foreground)]">
            no roster yet — labels name nobody
          </span>
        ) : null}
      </header>

      {plan.unknownPeers.length ? (
        <p className="text-[11px] text-[var(--error)]" data-unknown-peers>
          {plan.unknownPeers.map(peer).join(", ")}{" "}
          {plan.unknownPeers.length === 1 ? "is named" : "are named"} by this
          notebook and {plan.unknownPeers.length === 1 ? "is" : "are"} not in the
          room.
        </p>
      ) : null}

      {plan.refusals.length ? (
        <ul className="flex list-none flex-col gap-1.5 p-0" data-refusals>
          {plan.refusals.map((r, i) => (
            <li
              key={`${r.path}-${r.reason}-${i}`}
              className="border-l-2 border-[var(--error)] pl-2"
            >
              <p className="text-[11px] text-[var(--error)]">{r.message}</p>
              <p className="font-mono text-[10px] text-[var(--muted-foreground)]">
                {r.path} · {r.field} · expected {r.expected}, got {r.actual}
              </p>
            </li>
          ))}
        </ul>
      ) : null}

      {plan.asks.length ? (
        <ul className="flex list-none flex-col gap-1 p-0" data-asks>
          {plan.asks.map((a, i) => (
            <li key={`${a.cell}-${a.reason}-${i}`} className="text-[11px]">
              <span className="text-[var(--foreground)]">{a.question}</span>{" "}
              {a.choices.length ? (
                <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
                  {a.choices.join(" · ")}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}

      <ol className="flex list-none flex-col gap-1 p-0" data-cells>
        {plan.cells.map((c) => (
          <CellRow key={c.index} cell={c} placed={placed} play={plan.play} />
        ))}
      </ol>

      {plan.waits.length ? (
        <ul className="flex list-none flex-col gap-1 p-0" data-waits>
          {plan.waits.map((w, i) => (
            <li
              key={`${w.cell}-${w.on}-${i}`}
              className="font-mono text-[10px] text-[var(--muted-foreground)]"
            >
              cell {w.cell} waits for cell {w.on} on{" "}
              {w.peer === "*" ? "everyone" : peer(w.peer)}
              {w.slot ? ` — ${slot(w.slot)}` : ""}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

const PLAY_TITLE: Record<RunPlan["play"], string> = {
  solo: "Runs here",
  mirrored: "Every participant runs all of it",
  placed: "Cells are placed",
};

/**
 * One cell.
 *
 * `runsOn` empty means every participant, which is a different statement from
 * a named peer and is drawn as one. `mine` is the only emphasis the row
 * carries — in a placed notebook the reader's question is which of these are
 * theirs to do, and everything else is context.
 */
function CellRow({
  cell,
  placed,
  play,
}: {
  cell: PlannedCell;
  placed: boolean;
  play: RunPlan["play"];
}) {
  const runner = who(cell, play);
  return (
    <li
      className="flex flex-col gap-0.5 border-l-2 border-[var(--border)] pl-2"
      data-cell={cell.index}
      data-mine={cell.mine ? "yes" : "no"}
      data-kind={cell.kind}
    >
      <span className="flex flex-wrap items-baseline gap-x-2">
        <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
          cell {cell.index}
        </span>
        {runner ? (
          <span
            className={cn(
              "font-mono text-[11px]",
              cell.mine
                ? "font-semibold text-[var(--foreground)]"
                : "text-[var(--muted-foreground)]"
            )}
          >
            {runner}
          </span>
        ) : null}
        {/* What leaves, not merely that something does. A cell that publishes
            one of the three things it writes says which one here, because
            "publishes" beside a verifiable split is the sentence a reader most
            needs to be exact. */}
        {cell.publishes.length ? (
          <span className="text-[10px] text-[var(--muted-foreground)]">
            {cell.publishes.length < cell.produces.length
              ? `publishes ${cell.publishes.map(slot).join(" · ")}`
              : "publishes"}
          </span>
        ) : null}
        {/* `declared` and `forced` are different claims: a header said so, and
            the data said so. A cell that is forced without being declared is
            the interesting one — nobody wrote it down, and it can still only
            run in one place. */}
        {cell.forced && !cell.declared ? (
          <span className="text-[10px] text-[var(--muted-foreground)]">
            forced by its input
          </span>
        ) : null}
      </span>
      <span className="text-[11px] text-[var(--muted-foreground)]">{cell.why}</span>
      {placed && cell.produces.length ? (
        <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
          {cell.produces.map(slot).join(" · ")}
        </span>
      ) : null}
    </li>
  );
}

/**
 * The plan's own vocabulary: `""` is everyone, `*` is a rendezvous.
 *
 * A solo notebook gets nothing at all. `runsOn` is empty there for the same
 * reason it is empty in a mirrored run — nobody was named — but "every
 * participant" beside a `why` reading "this notebook names no peer, so the
 * cell runs here" is a straight contradiction, and there is no third party to
 * be a participant. The header already answers where a solo run happens.
 */
function who(cell: PlannedCell, play: RunPlan["play"]): string {
  if (play === "solo") return "";
  if (cell.kind === "rendezvous" || cell.peer === "*") return "everyone, together";
  if (!cell.runsOn.length) return "every participant";
  return cell.runsOn.map(peer).join(", ");
}
