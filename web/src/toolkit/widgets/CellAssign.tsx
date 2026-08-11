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
import { PEER_SIGIL } from "../../lib/toolkit/recipe-parse.js";

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
  onAssign: (peer: string | null, publish: boolean) => void;
  className?: string;
};

/**
 * Who runs this cell.
 *
 * The `@peer` header decides where a cell runs, and until this existed the
 * only way to write one was to know the grammar and type it into the source
 * view. Every other layer was already complete — the parser reads it,
 * `serializeChain` writes it, `planRun` places by it, `placementGate` enforces
 * it — so placement was a finished feature with no entry point.
 *
 * This sets the same two fields the text sets. There is one representation and
 * two surfaces onto it, so the views cannot disagree about where a cell runs.
 *
 * **`publish` is offered only once a peer is chosen.** It says this cell's
 * output may leave the machine that made it, which is a statement about a
 * boundary that does not exist until there is somebody on the other side of
 * it. Offering it on an unassigned cell would be asking permission to cross a
 * line nobody has drawn.
 *
 * The unassigned label is "anyone", not "unassigned" or a blank: a cell with
 * no header genuinely runs wherever the notebook runs, which is a real answer
 * and not an absence of one.
 */
export function CellAssign({ peer, publish, choices, onAssign, className }: CellAssignProps) {
  const label = peer ? `${PEER_SIGIL}${peer}` : "anyone";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          size="sm"
          variant="ghost"
          className={cn("font-mono", className)}
          data-cell-assign={peer ?? ""}
          title="Who runs this cell"
        >
          {label}
          {publish ? (
            <span className="ml-1 text-[10px] text-[var(--muted-foreground)]">publish</span>
          ) : null}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        <DropdownMenuLabel>Runs on</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => onAssign(null, false)}>
          anyone — wherever the notebook runs
        </DropdownMenuItem>
        {choices.length ? <DropdownMenuSeparator /> : null}
        {choices.map((c) => (
          <DropdownMenuItem
            key={c}
            onSelect={() => onAssign(c, c === peer ? publish : false)}
          >
            {PEER_SIGIL}
            {c}
          </DropdownMenuItem>
        ))}
        {peer ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => onAssign(peer, !publish)}>
              {publish ? "Stop publishing its output" : "Publish its output"}
            </DropdownMenuItem>
          </>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
