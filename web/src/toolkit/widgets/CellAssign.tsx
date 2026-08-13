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
import { PEER_SIGIL, SLOT_SIGIL, peerIsFingerprint } from "../../lib/toolkit/recipe-parse.js";
import { formatFingerprint } from "../../lib/utils.js";

/**
 * One peer a cell can be assigned to, and who they are.
 *
 * **The key is the value and the name is the caption**, never the other way
 * round: the whole fingerprint is what goes in the notebook, is what `planRun`
 * binds and is what the other browser reads, while the name is this browser's
 * private knowledge of whose key it is. Two people can hold different names for
 * the same key and still agree about every header in the notebook — which used
 * to be the property a positional label was invented to buy, and is now free,
 * because both notebooks name the key itself.
 *
 * `name` is a uid or a trust mark and **nothing derived from the fingerprint**.
 * `components/ui/fingerprint.tsx` argues at length why a shortened key is not
 * an identifier a person may be asked to compare, and a menu row is exactly the
 * dense column that has historically argued itself into one. A peer this
 * browser knows no name for carries no `name` and says as much; the key behind
 * it is drawn here in full, and again in the session sheet's room list, where
 * it can be copied and marked.
 */
export type PeerChoice = {
  /**
   * What a header writes, with no sigil: a whole fingerprint for anybody the
   * room binds, or whatever name a hand-written header used.
   */
  label: string;
  /** Whose key it is, when this browser has a name for it. */
  name?: string;
  /** This browser's own key — the reader is "you" to themselves. */
  self?: boolean;
  /**
   * Set when the room binds this peer to a key. Absent for a peer the notebook
   * names and the room does not — typed by hand, or a `@peer1` left in a
   * notebook written before a peer was a key — which is a real state and a
   * different sentence.
   */
  fingerprint?: string;
};

export type CellAssignProps = {
  /** The cell's current header, or null when it has none. */
  peer: string | null;
  /** The `publish` modifier — only meaningful alongside a peer. */
  publish: boolean;
  /**
   * Labels that can be chosen: everyone in the room, plus every label this
   * notebook already names. Both, because a notebook is written before anyone
   * joins and a header has to be typeable against a peer who is not here yet.
   *
   * "The room" includes a room that has only been *named* — an audience picked
   * in the session sheet with nobody connected yet. That is the ordinary case
   * for this menu, not an edge of it: a ceremony is written first and run when
   * the other person is free.
   */
  choices: PeerChoice[];
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
 * The line under a peer, saying who they are.
 *
 * Exported for the reason `fingerprintActions` is: the rows live in a portal,
 * so nothing short of a browser can read them, and a sentence no test can
 * assert is a sentence that quietly becomes wrong. The component renders
 * exactly this — it is not a second opinion about it.
 *
 * Four states and no fifth, and each names the one it is actually in. "In the
 * room, and this browser has never put a name to the key" is a different fact
 * from "the notebook names this peer and the room does not", and a reader about
 * to hand a cell to one of them is owed the difference: the first will run, the
 * second is waiting for somebody who has not been invited.
 *
 * The fourth state is the one a notebook written before this change lands in. A
 * `@peer1` header is still a legal peer and still compiles; nothing in the room
 * answers to it, `planRun` refuses the cell as `unknown-peer`, and this row is
 * where the reader is told so at the moment they can fix it.
 */
export function peerCaption(choice: PeerChoice): string {
  if (choice.self) return "you — the key you are joining as";
  if (choice.name) return choice.name;
  if (choice.fingerprint) {
    return "in the room; no name for this key in this browser";
  }
  return "not in the room — this notebook names them and the audience does not";
}

/**
 * A peer as a trigger or a menu row can print it.
 *
 * **Neither of those two places can hold a placard, and the reason is
 * structural rather than a layout preference.** `Fingerprint` is a button plus
 * its own `DropdownMenu`; the trigger below is already a `DropdownMenuTrigger
 * asChild` wrapping a `Button`, and the rows below that are
 * `DropdownMenuItem`s inside a Radix menu. Nesting an interactive element in
 * either one produces a button inside a button and a menu inside a menu item —
 * invalid markup, and a keyboard trap where Radix's roving focus meets a second
 * focusable child.
 *
 * So both degrade the same way, and the degradation is **never a truncation**:
 * the whole value, grouped exactly as `Fingerprint` prints it, with the name on
 * a caption line of its own. What is lost is the *actions* — copy, trust,
 * keyserver — and they are one press away on the same key in the session
 * sheet's room list, which is a placard in full.
 *
 * A hand-written name is returned untouched: `formatFingerprint` groups hex in
 * fours and would make nonsense of `alice`.
 */
export function peerPrinted(peer: string): string {
  const s = String(peer || "");
  return peerIsFingerprint(s) ? formatFingerprint(s) : s;
}

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
  const label = peer ? `${PEER_SIGIL}${peerPrinted(peer)}` : "anyone";
  // The name beside the key, where this browser has one. The trigger is the one
  // place in the notebook that says who runs a cell without the reader opening
  // anything, so a header of forty hex characters and nothing else would be a
  // regression in exactly the thing this change is for. Both are drawn: the
  // value the notebook holds, and who it is.
  const who = choices.find((c) => c.label === peer);
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
          className={cn("cell-assign-trigger font-mono", className)}
          data-cell-assign={peer ?? ""}
          title={peer ? `Who runs this cell: ${peerPrinted(peer)}` : "Who runs this cell"}
        >
          <span className="cell-assign-peer">{label}</span>
          {who?.name || who?.self ? (
            <span className="ml-1 text-[10px] text-[var(--muted-foreground)]">
              {who.self ? "you" : who.name}
            </span>
          ) : null}
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
        {/* Key over name, in that order and that weight. The key is what the
            cell will say and what the other end will read; the name is how this
            reader recognises it. Reversing them would put the private fact
            first and leave somebody comparing notebooks with no idea which line
            was the one that travels.

            Not a `Fingerprint` placard: see `peerPrinted` for why a
            `DropdownMenuItem` cannot hold one, and for what is given up. The
            whole value is printed, wrapped rather than cut. */}
        {choices.map((c) => (
          <DropdownMenuItem
            key={c.label}
            onSelect={() =>
              c.label === peer
                ? onAssign(c.label, publish, publishSlots)
                : onAssign(c.label, false, [])
            }
          >
            <span className="flex min-w-0 flex-col gap-[2px]">
              <span className="cell-assign-peer font-mono">
                {PEER_SIGIL}
                {peerPrinted(c.label)}
              </span>
              <span className="text-[10px] text-[var(--muted-foreground)]">
                {peerCaption(c)}
              </span>
            </span>
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
