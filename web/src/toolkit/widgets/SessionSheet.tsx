import { useEffect, useRef } from "react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SessionLive, type SessionLiveProps } from "./SessionLive";
import { SessionStart, type SessionStartProps } from "./SessionStart";
import { RoomRecovery, type RoomRecoveryProps } from "./RoomRecovery";

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
  /**
   * The recovery generator's section — under *both* halves, deliberately.
   *
   * The deal's picker lives inside `SessionStart` because a deal cannot be
   * written before the room exists. A recovery is the opposite way round: it
   * is most often written while the original room is live (the recoverer is
   * standing in it, dealer present or not), and the cold custodian who needs
   * the paste path has no session at all — so pinning the section to either
   * half would hide it from the reader the other half serves.
   */
  recovery?: Omit<RoomRecoveryProps, "className">;
  /**
   * Which section the sheet was opened *for*, when it was opened for one.
   *
   * The Templates gallery's room entries are the reason this exists: choosing
   * "Put a dealt secret back together" opens this window, and the first thing
   * in it is the deal picker. Landing a person on the panel above the one they
   * asked for is the exact failure the handoff was meant to remove, so the
   * named section is scrolled to. Null for the three doors that open the sheet
   * as a whole — the Share tier, the Connections tab and an invite link — none
   * of which asked for a part of it.
   */
  focus?: "ceremony" | "recovery" | null;
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
export function SessionSheet({
  open,
  onOpenChange,
  live,
  start,
  recovery,
  focus = null,
}: SessionSheetProps) {
  const body = useRef<HTMLDivElement | null>(null);

  /**
   * Scroll the asked-for section into view once the sheet has drawn it.
   *
   * Queried out of the DOM by the `data-` attribute the section already
   * carries, rather than by a ref threaded through two widgets: those
   * attributes exist because the e2e suite drives these panels by them, so the
   * selector here and the selector a test uses are the same string, and a
   * renamed section breaks both at once instead of silently only this.
   *
   * Deliberately not `focus()`: moving focus into a panel a person did not
   * type into steals it from the sheet's own close button and re-announces the
   * whole dialog. The section is brought on screen and the reader is left
   * where the dialog put them.
   */
  useEffect(() => {
    if (!open || !focus) return;
    // A task later, not on this commit. The sheet's content is portalled behind
    // Radix's presence wrapper, so on the commit that flips `open` the div this
    // ref points at is not in the document yet — the scroll ran against `null`
    // and did nothing, which is this handoff's own failure mode one layer down.
    // Driven in a browser to establish it: pressed on the open commit the
    // container stayed at `scrollTop: 0` with the section 578px below the fold;
    // deferred, it lands on it.
    //
    // `setTimeout` rather than `requestAnimationFrame`, for a reason worth
    // recording: a tab that is not compositing produces no frames and never
    // runs a rAF callback at all, so the rAF spelling of this was
    // indistinguishable from no scroll in a browser that was not on screen —
    // the same "silently did nothing" the deferral exists to fix.
    const t = setTimeout(() => {
      const el = body.current?.querySelector(
        focus === "ceremony" ? "[data-room-ceremony]" : "[data-room-recovery]"
      );
      if (el instanceof HTMLElement) {
        el.scrollIntoView({ block: "start", behavior: "auto" });
      }
    }, 0);
    return () => clearTimeout(t);
  }, [open, focus, live]);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-lg"
        onOpenAutoFocus={(e) => e.preventDefault()}
        data-session-sheet={live ? "live" : "idle"}
        data-session-focus={focus || ""}
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

        <div ref={body} className="flex flex-col gap-3 overflow-y-auto px-4 pb-4">
          {live ? <SessionLive {...live} /> : <SessionStart {...start} />}
          {recovery ? <RoomRecovery {...recovery} /> : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}
