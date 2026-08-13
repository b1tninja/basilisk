import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SessionLive, type SessionLiveProps } from "./SessionLive";
import { SessionStart, type SessionStartProps } from "./SessionStart";

export type SessionSheetProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * The live exchange, or null when there is none.
   *
   * Null is not "loading" — it is the ordinary state of this app, and it is what
   * decides which half of the sheet is shown. One exchange at a time is the
   * transport's own rule (`execQuorumOpen` refuses a second), so this is a
   * nullable object rather than a list.
   */
  live: Omit<SessionLiveProps, "className"> | null;
  start: Omit<SessionStartProps, "className">;
};

/**
 * The shared session, start to finish — a `Sheet`, per the handoff's rule that
 * a design needing a window is a `Sheet`.
 *
 * Its own window rather than a fourth row inside `ShareSheet`, because the two
 * answer different questions. `ShareSheet` is about *what leaves this machine*
 * and each of its rows is one transfer; a session is not a transfer at all —
 * nothing of the notebook crosses it. Both sides arrive at the same recipe text
 * independently, which is what makes a shared run a reproducible build rather
 * than a screen share, and only offers, results and attestations ever move. So
 * the "Run it together" row hands off to this, and this is where the room, the
 * roster and the lifecycle live.
 *
 * The split inside is the session's own: before one exists there is a room to
 * name, and after it exists there is a room to watch. Nothing switches back —
 * closing the session is what returns this to the naming half, which is the
 * honest shape, because a closed exchange leaves nothing to observe and the
 * same audience derives the same room again.
 */
export function SessionSheet({ open, onOpenChange, live, start }: SessionSheetProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-lg"
        onOpenAutoFocus={(e) => e.preventDefault()}
        data-session-sheet={live ? "live" : "idle"}
      >
        <SheetHeader>
          <SheetTitle>Run it together</SheetTitle>
          <SheetDescription>
            Cells marked for somebody else run on their machine. Your notebook
            crosses signed when you press Share, and replaces nothing anybody
            has written without their say-so; offers, results and attestations
            cross the same way. Private keys never leave this browser.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-3 overflow-y-auto px-4 pb-4">
          {live ? <SessionLive {...live} /> : <SessionStart {...start} />}
        </div>
      </SheetContent>
    </Sheet>
  );
}
