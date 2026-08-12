import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/cn";
import { PEER_SIGIL, SLOT_SIGIL } from "../../lib/toolkit/recipe-parse.js";

export type CellAssignProps = {
  /** The cell's current header, or null when it has none. */
  peer: string | null;
  /** The `publish` modifier — only meaningful alongside a peer. */
  publish: boolean;
  /**
   * Labels that can be chosen: everyone in the room, plus every label this
   * notebook already names. Both, because a notebook is written before anyone
   * joins and a header has to be typeable against a peer who is not here yet.
   */
  choices: string[];
  /**
   * Every `out` slot this cell writes, at any depth. The menu can only offer to
   * publish a slot the cell actually has, and the cell is the only thing that
   * knows — a `tee` branch's `out` and a `foreach` body's `out` are both this
   * cell's output.
   */
  outSlots?: string[];
  /**
   * Which of them the header names. Empty means the header names none, which
   * is the bare `publish`: every one of them.
   */
  publishSlots?: string[];
  onAssign: (peer: string | null, publish: boolean, publishSlots: string[]) => void;
  /**
   * Start with the menu open. For a catalog, which cannot press the trigger —
   * the same reason `ShareSheet` takes `defaultQrOpen` and `OtpCodeCard` takes
   * an injectable `nowMs`. A menu that only exists after a click is a menu no
   * sheet can photograph, and the items are the whole of what this control is.
   */
  defaultOpen?: boolean;
  className?: string;
};

/**
 * Who runs this cell, and what of it leaves.
 *
 * The `@peer` header decides where a cell runs, and until this existed the
 * only way to write one was to know the grammar and type it into the source
 * view. Every other layer was already complete — the parser reads it,
 * `serializeChain` writes it, `planRun` places by it, `placementGate` enforces
 * it — so placement was a finished feature with no entry point.
 *
 * This sets the same fields the text sets. There is one representation and
 * two surfaces onto it, so the views cannot disagree about where a cell runs.
 *
 * **`publish` is offered only once a peer is chosen.** It says this cell's
 * output may leave the machine that made it, which is a statement about a
 * boundary that does not exist until there is somebody on the other side of
 * it. Offering it on an unassigned cell would be asking permission to cross a
 * line nobody has drawn.
 *
 * **Naming slots is offered only once the cell writes more than one.** A cell
 * with a single `out` has nothing to choose between, and `publish=$only` and
 * `publish` are the same claim spelled at different lengths. With several, they
 * are not: a verifiable split writes commitments a room needs and shares that
 * must not leave, and "publish its output" cannot mean both. Each slot is
 * therefore its own item, named by the change it makes — `Publish $x` /
 * `Keep $x here` — matching the "Stop publishing its output" line above it.
 *
 * Turning the last named slot off is *not* the same as not publishing: an empty
 * list is the bare `publish`, meaning all of them. So the item that would empty
 * the list is not offered; stopping altogether is the line above.
 */
export function CellAssign({
  peer,
  publish,
  choices,
  outSlots = [],
  publishSlots = [],
  onAssign,
  defaultOpen = false,
  className,
}: CellAssignProps) {
  const label = peer ? `${PEER_SIGIL}${peer}` : "anyone";
  // A cell that publishes everything shows every slot as published, because it
  // does. The list is only a *narrowing*, so the empty list and the full list
  // mean the same thing and the menu says so.
  const named = publishSlots.length ? publishSlots : outSlots;
  const publishes = (slot: string) => named.includes(slot);
  // The header text on the trigger, so a reader scanning a notebook for what
  // leaves their machine does not have to open a menu to find out.
  const modifier = !publish
    ? ""
    : publishSlots.length
      ? `publish=${publishSlots.map((s) => `${SLOT_SIGIL}${s}`).join(",")}`
      : "publish";
  return (
    <DropdownMenu defaultOpen={defaultOpen} modal={false}>
      <DropdownMenuTrigger asChild>
        <Button
          size="sm"
          variant="ghost"
          className={cn("font-mono", className)}
          data-cell-assign={peer ?? ""}
          title="Who runs this cell"
        >
          {label}
          {modifier ? (
            <span className="ml-1 text-[10px] text-[var(--muted-foreground)]">
              {modifier}
            </span>
          ) : null}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        <DropdownMenuLabel>Runs on</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => onAssign(null, false, [])}>
          anyone — wherever the notebook runs
        </DropdownMenuItem>
        {choices.length ? <DropdownMenuSeparator /> : null}
        {choices.map((c) => (
          <DropdownMenuItem
            key={c}
            onSelect={() =>
              c === peer
                ? onAssign(c, publish, publishSlots)
                : onAssign(c, false, [])
            }
          >
            {PEER_SIGIL}
            {c}
          </DropdownMenuItem>
        ))}
        {peer ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => onAssign(peer, !publish, [])}>
              {publish ? "Stop publishing its output" : "Publish its output"}
            </DropdownMenuItem>
          </>
        ) : null}
        {peer && publish && outSlots.length > 1 ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>What leaves this machine</DropdownMenuLabel>
            {outSlots.map((slot) => {
              const on = publishes(slot);
              // Never down to nothing: an empty list is the bare `publish`, so
              // an item that emptied it would silently publish everything —
              // which is why the refusal has to say what it is protecting.
              // "Keep here" greyed out with nothing beside it reads as a bug,
              // and the state it is in is the exact opposite of what a reader
              // assumes a dead row means.
              const lastOne = on && named.length === 1;
              const next = on
                ? named.filter((s) => s !== slot)
                : outSlots.filter((s) => named.includes(s) || s === slot);
              return (
                <DropdownMenuItem
                  key={slot}
                  disabledReason={
                    lastOne
                      ? `${SLOT_SIGIL}${slot} is the only value this cell still publishes. Keeping it here too would leave an empty list, which the notebook writes as a bare \`publish\` — every output, rather than none. Send the cell to nobody instead.`
                      : undefined
                  }
                  onSelect={() =>
                    // A list of everything is the bare `publish` written long.
                    // Collapsing it keeps the header as short as the claim, and
                    // keeps one spelling for one meaning in the notebook text.
                    onAssign(peer, true, next.length === outSlots.length ? [] : next)
                  }
                >
                  {on ? "Keep" : "Publish"} {SLOT_SIGIL}
                  {slot}
                  {on ? " here" : ""}
                </DropdownMenuItem>
              );
            })}
          </>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
