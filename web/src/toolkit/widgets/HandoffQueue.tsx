import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { PEER_SIGIL, SLOT_SIGIL } from "../../lib/toolkit/recipe-parse.js";

/** One document a peer sent that is still waiting on a person. */
export type HandoffRow = {
  id: string;
  kind: "offer" | "result";
  /** Sender's fingerprint — the session verified it; no label is known here. */
  from: string;
  cell: number;
  manifest: string;
  ts: number;
};

/** A cell this run declined because it belongs to somebody else. */
export type PlacedAway = {
  cell: number;
  /** The label the plan says owns it. */
  peer: string;
  produces: string[];
};

/** A cell run here on somebody else's behalf, whose answer is owed back. */
export type OwedBack = {
  cell: number;
  /** Their fingerprint — `sendCellResult` addresses by label, so this carries both. */
  to: string;
  label: string;
};

export type HandoffQueueProps = {
  /** Whether an exchange is open at all — decides which empty state is honest. */
  live: boolean;
  pending: HandoffRow[];
  placedAway: PlacedAway[];
  owedBack: OwedBack[];
  onAccept: (id: string) => void;
  onOffer: (cell: number) => void;
  onSendResult: (cell: number, label: string) => void;
  /** The last attempt's outcome, in the words the handoff layer used. */
  note?: string | null;
  className?: string;
};

const slot = (label: string) => `${SLOT_SIGIL}${label}`;
const peer = (label: string) => `${PEER_SIGIL}${label}`;

function shortFpr(fpr: string): string {
  const f = String(fpr || "").toUpperCase();
  return f.length > 12 ? `${f.slice(0, 8)}…${f.slice(-4)}` : f;
}

/**
 * Cells crossing between machines, and the press each one is waiting for.
 *
 * Everything under it already existed and could not be reached. `planRun`
 * decides where a cell runs, `placementGate` declines the ones that are not
 * ours, `buildOfferFor` packs what a declined cell needs, `acceptHandoffOffer`
 * and `acceptCellResult` check what arrives — and `useNotebook` exposes all
 * five as `offerCell`, `acceptHandoff`, `sendCellResult` and `skippedCells`,
 * which nothing rendered. A finished mechanism with no entry point is the
 * defect this codebase keeps closing; this is the entry point.
 *
 * **Three lists, because there are three different waits**, and a single
 * "pending" would hide which of them is on you:
 *
 * - *You are waiting on them* — a cell the run declined. The press hands it
 *   over; nothing happens until they accept it.
 * - *They are waiting on you* — an offer or a result that arrived. It is
 *   **pending and nothing more**: the session parses it, checks the signature
 *   on a result against that one peer's key, and registers nothing. Accepting
 *   is what puts values in the registry, and it is a person's act by design.
 * - *You owe them an answer* — a cell you accepted and ran. The result is
 *   signed with the key the session was opened under, because `sendResult`
 *   refuses anything that is not cleartext-signed.
 *
 * A result is the more dangerous of the two arrivals and is drawn as such: a
 * result that resumed a run on a peer's say-so would continue *this* machine on
 * values nobody looked at. The signature says who made the claim; it does not
 * say the claim is about a cell you asked for, and only the accept checks that.
 */
export function HandoffQueue({
  live,
  pending,
  placedAway,
  owedBack,
  onAccept,
  onOffer,
  onSendResult,
  note,
  className,
}: HandoffQueueProps) {
  const empty = !pending.length && !placedAway.length && !owedBack.length;
  return (
    <section
      className={cn("flex flex-col gap-2", className)}
      data-handoff-queue={live ? "live" : "idle"}
    >
      <h4 className="text-[11px] font-bold text-[var(--foreground)]">
        Cells crossing between machines
      </h4>

      {empty ? (
        <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
          {live
            ? "Nothing is waiting on anybody. Give a cell an @peer header and run — the cells that are not yours are declined here and offered to whoever owns them."
            : "No session, so nothing can cross. A cell with an @peer header is still planned and still declined at run time; it just has nowhere to go."}
        </p>
      ) : null}

      {placedAway.length ? (
        <ul className="flex list-none flex-col gap-1 p-0" data-handoff-outgoing>
          {placedAway.map((c) => (
            <li
              key={`away-${c.cell}`}
              className="flex flex-col gap-1 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5"
            >
              <span className="text-[11px] text-[var(--foreground)]">
                Cell {c.cell} is {peer(c.peer)}&apos;s
                {c.produces.length ? ` — it writes ${c.produces.map(slot).join(" · ")}` : ""}.
              </span>
              <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                Handing it over sends the values that cell reads and nothing
                else. Nothing runs until they accept it.
              </span>
              <div className="flex flex-wrap gap-1.5">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={!live}
                  onClick={() => onOffer(c.cell)}
                >
                  Hand cell {c.cell} to {peer(c.peer)}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {pending.length ? (
        <ul className="flex list-none flex-col gap-1 p-0" data-handoff-pending>
          {pending.map((h) => (
            <li
              key={h.id}
              className="flex flex-col gap-1 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5"
              data-handoff-kind={h.kind}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className="peer-verdict"
                  data-verdict={h.kind === "result" ? "warn" : "muted"}
                >
                  {h.kind === "result" ? "result" : "offer"}
                </span>
                <span className="text-[11px] text-[var(--foreground)]">
                  cell {h.cell}
                </span>
                <code
                  className="min-w-0 flex-1 truncate font-mono text-[10px] text-[var(--muted-foreground)]"
                  title={h.from}
                >
                  from {shortFpr(h.from)}
                </code>
              </div>
              <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                {h.kind === "result"
                  ? "Signed by that peer and checked against their key. That says who made the claim — not that it answers a cell you handed out, and not that the values may be used. Accepting is what checks both and registers them."
                  : "Parsed and held. Nothing has been checked against your plan and no cell has run. Accepting checks it and registers what it carries."}
              </span>
              <div className="flex flex-wrap gap-1.5">
                <Button size="sm" variant="secondary" onClick={() => onAccept(h.id)}>
                  Review and accept
                </Button>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {owedBack.length ? (
        <ul className="flex list-none flex-col gap-1 p-0" data-handoff-owed>
          {owedBack.map((o) => (
            <li
              key={`owed-${o.cell}-${o.to}`}
              className="flex flex-col gap-1 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5"
            >
              <span className="text-[11px] text-[var(--foreground)]">
                Cell {o.cell} ran here for {peer(o.label)}.
              </span>
              <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                Sending it back signs what the cell wrote with the key this
                session was opened under — their end refuses an unsigned result,
                because otherwise it is a value from whoever reached the channel.
              </span>
              <div className="flex flex-wrap gap-1.5">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={!live}
                  onClick={() => onSendResult(o.cell, o.label)}
                >
                  Send cell {o.cell} back
                </Button>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {note ? (
        <p
          className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
          data-handoff-note
        >
          {note}
        </p>
      ) : null}
    </section>
  );
}
