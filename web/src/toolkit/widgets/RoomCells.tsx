import { cn } from "@/lib/cn";
import { Fingerprint } from "@/components/ui/fingerprint";

/**
 * What the room is running, cell by cell, as it happens.
 *
 * ## The gap this draws
 *
 * Nine payload kinds crossed the document channel and none of them said "I ran
 * cell N". `handoff` asks somebody to run one, `result` returns a cell they
 * were handed, `attestation` signs a whole finished run afterwards — so a peer
 * running their **own** cells was invisible to everyone else. In a shared
 * ceremony that meant nobody could see the deal cell run: the holders' screens
 * were indistinguishable from a dealer who had walked away, right up until a
 * share happened to land in a tile.
 *
 * ## Live, and only live
 *
 * Every row here arrived as an announcement while it was happening. There is no
 * replay, no catch-up on join, and nothing to ask. A peer who joined late, or
 * whose channel dropped and came back, has no row for what they missed — and
 * the heading says so, because a table that quietly looked complete would be
 * the worst version of this: a reader would take an empty stretch as *nothing
 * ran* rather than *nobody told me*.
 *
 * The record and the receipt on the machine that ran the cells are the ledger,
 * and they are untouched by any of this. This is the ticker.
 *
 * ## Face up, face down, not dealt
 *
 * `cell-state.js` holds the model and the copy; what this file is responsible
 * for is not undoing it:
 *
 * - **Not dealt** is the absence of a row. Never a row saying "not yet" — that
 *   would be a claim about a run this browser has heard nothing about.
 * - **Face down** names the slot and says it is not here. It names no remedy,
 *   because there is none: nothing on this wire requests a value, and a button
 *   here would be a control whose whole effect is to make a reader believe they
 *   had done something.
 * - **Face up** is a slot this machine actually holds, and it reads as one.
 *   Possession is the local registry's answer and never the announcement's, so
 *   a row cannot turn face up on somebody's say-so.
 *
 * A refusal shows the state and no sentence. The reason a peer's cell refused
 * can name their slots, their keys or their files, and none of that crosses;
 * the row says as much rather than leaving a reader hunting for a reason that
 * is not on this screen.
 */

export type SlotFace = { slot: string; here: boolean };

export type PeerCellRow = {
  from: string;
  cell: number;
  state: "running" | "done" | "refused";
  slots: string[];
  ts: number;
  faces: SlotFace[];
};

/** What the state column says. Short, present tense, and never a remedy. */
const STATE_WORD: Record<PeerCellRow["state"], string> = {
  running: "running",
  done: "done",
  refused: "refused",
};

export function RoomCells({
  rows,
  className,
}: {
  rows: PeerCellRow[];
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)} data-room-cells>
      <h4 className="text-[11px] font-bold text-[var(--foreground)]">
        What the room is running
      </h4>
      {rows.length ? (
        <ul className="flex flex-col gap-1">
          {rows.map((row) => (
            <li
              key={`${row.from}·${row.cell}`}
              className="flex flex-col gap-0.5 rounded border border-[var(--border)] px-2 py-1"
              data-room-cell
              data-room-cell-peer={row.from}
              data-room-cell-index={row.cell}
              data-room-cell-state={row.state}
            >
              <div className="flex flex-wrap items-baseline gap-x-1.5 text-[10.5px]">
                {/* Whole, never a compact form. The roster is identity-mapped
                    — a peer *is* their key — so this is the only name this
                    person has here, and the row that says who just did
                    something is the last place to print part of it. */}
                <Fingerprint fpr={row.from} />
                <span className="text-[var(--muted-foreground)]">
                  cell {row.cell}
                </span>
                <span className="font-semibold text-[var(--foreground)]">
                  {STATE_WORD[row.state]}
                </span>
              </div>
              {row.state === "refused" ? (
                <p className="text-[10px] text-[var(--muted-foreground)]">
                  The reason stayed on their machine.
                </p>
              ) : null}
              {row.state === "done" && row.faces.length ? (
                <ul className="flex flex-wrap gap-x-2 gap-y-0.5 text-[10px]">
                  {row.faces.map((face) => (
                    <li
                      key={face.slot}
                      className="flex items-baseline gap-1"
                      data-room-cell-slot={face.slot}
                      data-room-cell-face={face.here ? "up" : "down"}
                    >
                      <code
                        className={cn(
                          "font-mono",
                          face.here
                            ? "text-[var(--foreground)]"
                            : "text-[var(--muted-foreground)]"
                        )}
                      >
                        ${face.slot}
                      </code>
                      <span className="text-[var(--muted-foreground)]">
                        {face.here
                          ? "here"
                          : "on their machine — it did not come here"}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
          Nobody has said they are running anything. A row appears when a peer
          starts one of their own cells.
        </p>
      )}
      <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
        Announced as it happens, and never caught up: a cell that ran before you
        joined has no row here, and an empty stretch means nobody told you rather
        than nothing ran. Slot names only — no value crosses for this. The run
        record and the receipt on the machine that ran a cell are what the end of
        a ceremony is checked against.
      </p>
    </div>
  );
}
