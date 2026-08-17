import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
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
  /**
   * What the run itself already did about it.
   *
   * `none` is not "not yet" — the run decides as it ends, so by the time this
   * list is on screen the attempt has happened or been ruled out. It means the
   * run was stopped by hand, or the session went away before the run did.
   *
   * `aside` is the run having decided *not* to send: the cell needs nothing this
   * machine produced and writes nothing this notebook goes on to read, so an
   * offer would carry nothing and answer nothing. It is a different sentence
   * from `none` because it points at a different remedy — none at all, unless
   * the peer asks.
   */
  offered: "sent" | "refused" | "aside" | "none";
  /** The handoff layer's own sentence, when `offered` is `refused`. */
  why?: string;
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
  onDismiss: (id: string) => void;
  onOffer: (cell: number) => void;
  onSendResult: (cell: number, label: string) => void;
  /**
   * What accepting each row was refused for, by handoff id.
   *
   * Session-scoped shell state, like `owedBack` beside it and for the same
   * reason — nothing about a document a peer sent is written down past the
   * exchange it arrived on.
   *
   * A row is here because `acceptHandoff` refused it and **did not consume
   * it**: a refusal leaves the document pending, so the remedy its sentence
   * names is one the reader can still perform. That makes "pending" ambiguous
   * in a way it was not before — a row that has been refused once looks
   * exactly like one nobody has touched — and this is what separates them.
   */
  refusals?: Record<string, string>;
  /** The last attempt's outcome, in the words the handoff layer used. */
  note?: string | null;
  className?: string;
};

/**
 * Why nothing can be handed over — one string for both directions.
 *
 * It names the session rather than the button, because the button is fine: the
 * cell is still planned, still declined at run time, and still theirs. There is
 * simply no channel, and the remedy is one flight up in Share.
 */
const NO_SESSION =
  "No session is open, so there is nowhere to send this. The cell stays planned and stays theirs — open a shared session under Share, and this becomes one press.";

const slot = (label: string) => `${SLOT_SIGIL}${label}`;
const peer = (label: string) => `${PEER_SIGIL}${label}`;

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
 * - *You are waiting on them* — a cell the run declined. **The run hands over
 *   the ones this machine is an end of, as it ends**; the button is the retry,
 *   for a peer who was not in the room at the time, and the override for a cell
 *   the run set aside. Nothing happens on their machine until they accept it.
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
 *
 * ## Why the first list sends itself and the third does not
 *
 * The asymmetry is deliberate and is the reason this panel now has two
 * different kinds of row. An outgoing offer is bounded by the run that produced
 * it: the gate wrote that cell into the run's own skipped list because the
 * notebook places it on somebody else, and the reader asked for that notebook
 * to run. Sending it restates a decision already made and starts nothing.
 *
 * The third list has no such bound. `runFrom` runs every cell from an index
 * onward, so a cell accepted from a peer runs again on every later press of Run
 * — for reasons that have nothing to do with the peer waiting — and nothing
 * anywhere records *why* a cell ran. An automatic send back could not tell the
 * two apart, so the result stays a press, and this list is what asks for it.
 *
 * ## Why some rows in the first list have not been sent either
 *
 * "The gate declined it" is a weaker fact than the sentence above needs. It
 * means the cell is not this machine's to *perform*, and the run only sends the
 * ones this machine is an end of: a cell that reads a value made here, or writes
 * one this notebook goes on to read. The rest are drawn as `aside`, which is not
 * a failure and not a wait — the creator's own session cells, replayed on a
 * joiner's machine, and a holder's `quorum.recv` seen from the dealer's. They
 * keep the button because the plan can be wrong about a person's intent and this
 * panel should not be the place that decides they may not send it.
 */
export function HandoffQueue({
  live,
  pending,
  placedAway,
  owedBack,
  onAccept,
  onDismiss,
  onOffer,
  onSendResult,
  note,
  refusals,
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
        <>
          <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
            {live
              ? "Nothing is waiting on anybody. Give a cell an @peer header and run — the cells that are not yours are declined here, and the ones this machine is an end of are handed to whoever owns them as the run ends: a cell that needs a value made here, or writes one this notebook goes on to read. A declined cell that is neither is listed and left alone, because an offer for it would carry nothing and answer nothing. Nothing runs on their machine until they accept, and what they send back waits here for you."
              : "No session, so nothing can cross. A cell with an @peer header is still planned and still declined at run time; it just has nowhere to go."}
          </p>
          {/* The third list is shell state built when a person presses accept,
              and a reload ends it. Persisting it is the wrong fix: it would put
              a record of who sent you what somewhere `quorum-ops` and the
              session both deliberately keep it out of. The recovery is real
              and unaided — `offerCell` does not consume the skipped cell — so
              the honest move is to say where it went and what to ask for. */}
          <p
            className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
            data-handoff-reload
          >
            If you accepted a cell before a reload, the answer you owed is not
            listed here and will not come back: nothing wrote down what you took.
            Sending an offer does not spend it, so the cell is still theirs and
            their plan still says so — ask them to hand it over again, and
            accepting it puts the answer back in this list.
          </p>
        </>
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
              {/* Three sentences for three states, because the button under
                  them means something different in each. A row that said
                  "handing it over sends the values that cell reads" beside a
                  cell the run had *already* handed over would invite a press
                  for work that is done — the reader would be reading the panel
                  from before this run sent anything by itself. */}
              <span
                className="text-[10px] leading-snug text-[var(--muted-foreground)]"
                data-offer-state={c.offered}
              >
                {c.offered === "sent"
                  ? `Handed to ${peer(c.peer)} when the run finished, carrying the values that cell reads and nothing else. Nothing runs there until they accept it. Send it again only if they say it never arrived.`
                  : c.offered === "refused"
                    ? `The run tried to hand this over and could not. ${c.why || "The handoff was refused and gave no reason."}`
                    : c.offered === "aside"
                      ? `Left alone, and nothing here is waiting on it: this cell reads no value made on this machine, and nothing in this notebook reads what it writes. It is ${peer(c.peer)}'s to run on their own copy. Hand it over anyway if they ask — it would carry nothing, and nothing would run until they accept it.`
                      : "Nothing has gone out for this cell. Handing it over sends the values that cell reads and nothing else, and nothing runs until they accept it."}
              </span>
              <div className="flex flex-wrap gap-1.5">
                <Button
                  size="sm"
                  variant="secondary"
                  disabledReason={live ? undefined : NO_SESSION}
                  onClick={() => onOffer(c.cell)}
                >
                  Hand cell {c.cell} to {peer(c.peer)}
                  {c.offered === "sent" || c.offered === "refused" ? " again" : ""}
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
                {/* Whole, because nothing here names this key. `HandoffRow.from`
                    is a bare fingerprint the session verified and no label is
                    known for it — so there is no compact form to reach for, and
                    the row that decides whether to accept somebody's values is
                    the last place to print part of who they are. */}
                <span className="min-w-0 flex-1 text-[10px] text-[var(--muted-foreground)]">
                  from <Fingerprint fpr={h.from} />
                </span>
              </div>
              <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                {h.kind === "result"
                  ? "Signed by that peer and checked against their key. That says who made the claim — not that it answers a cell you handed out, and not that the values may be used. Accepting is what checks both and registers them."
                  : "Parsed and held. Nothing has been checked against your plan and no cell has run. Accepting checks it and registers what it carries."}
              </span>
              {/* The refusal this row already collected, kept on the row rather
                  than only in the note at the foot of the panel. The note holds
                  one sentence for the whole queue, so a second press anywhere
                  would overwrite the reason this particular document is still
                  sitting here — and it is sitting here *because* it was refused,
                  which is a thing the reader has to be able to see next to it
                  rather than remember. */}
              {refusals?.[h.id] ? (
                <span
                  className="text-[10px] leading-snug text-[var(--error)]"
                  data-handoff-refusal
                >
                  {refusals[h.id]}
                </span>
              ) : null}
              <div className="flex flex-wrap gap-1.5">
                <Button size="sm" variant="secondary" onClick={() => onAccept(h.id)}>
                  Review and accept
                </Button>
                {/* Named for what it does to the document rather than "Dismiss",
                    which would read as dismissing the *notice*. It discards a
                    thing another person is waiting on the answer to, so the
                    label says which of the two presses this is.

                    It tells nobody, and the sentence under it says so: there is
                    no decline on this wire by design — `offerAwaiting` argues it
                    — and a button that let a reader believe the other end had
                    been informed would be the lie this panel is built to avoid. */}
                <Button size="sm" variant="ghost" onClick={() => onDismiss(h.id)}>
                  Dismiss without accepting
                </Button>
              </div>
              <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                Dismissing drops it on this machine and sends nothing — there is
                no decline message on this wire, so from their end a document you
                put down and one you have not read yet look the same. Accepting
                is the only press that registers anything, and a refused document
                stays here until you dismiss it.
              </span>
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
              {/* Why this one is not sent for you, said where the wait is. The
                  outgoing list above goes by itself and this does not, and a
                  reader who noticed that difference deserves the reason rather
                  than a missing feature. */}
              <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                Sending it back signs what the cell wrote with the key this
                session was opened under — their end refuses an unsigned result,
                because otherwise it is a value from whoever reached the channel.
                This one is not sent for you: Run runs every cell from where you
                started, so this cell runs again whenever you run your own
                notebook, and nothing here can tell a run made for them from a
                run made for you.
              </span>
              <div className="flex flex-wrap gap-1.5">
                <Button
                  size="sm"
                  variant="secondary"
                  disabledReason={live ? undefined : NO_SESSION}
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
