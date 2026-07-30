import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

export type SessionStripState = "offering" | "waiting" | "connected" | "closed";

type Props = {
  state: SessionStripState;
  /** Short room code shown truncated (e.g. "KJ8X…9FQ"). */
  room?: string;
  /** Shareable invite line — Copy invite puts this on the clipboard. */
  invite?: string;
  /** Verified-peer count while connected. */
  connected?: number;
  onCopyInvite?: () => void;
  onCancel?: () => void;
  className?: string;
};

const STATE_TEXT: Record<SessionStripState, string> = {
  offering: "Publishing signed invite…",
  waiting: "Waiting for peer to join…",
  connected: "Connected",
  closed: "Session closed",
};

function shortRoom(room: string): string {
  if (room.length <= 8) return room;
  return `${room.slice(0, 4)}…${room.slice(-3)}`;
}

/**
 * Cell-level live-exchange region (design v2 §21a) — same slot pattern as the
 * READINESS row. Pulsing dot while the run is paused waiting for a peer.
 */
export function SessionStrip({
  state,
  room = "",
  invite = "",
  connected = 0,
  onCopyInvite,
  onCancel,
  className,
}: Props) {
  const live = state === "offering" || state === "waiting";
  const tone =
    state === "closed"
      ? "var(--muted-foreground)"
      : state === "connected"
        ? "var(--brand)"
        : "var(--caret)";
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-[7px] border px-2.5 py-2",
        state === "connected"
          ? "border-[color-mix(in_srgb,var(--brand)_30%,transparent)] bg-[color-mix(in_srgb,var(--brand)_7%,transparent)]"
          : "border-[color-mix(in_srgb,var(--caret)_30%,transparent)] bg-[color-mix(in_srgb,var(--caret)_7%,transparent)]",
        state === "closed" && "opacity-60",
        className
      )}
      data-session-strip={state}
    >
      <span
        className={cn(
          "h-[7px] w-[7px] shrink-0 rounded-full",
          live && "animate-pulse"
        )}
        style={{
          background: tone,
          boxShadow: live ? `0 0 0 3px color-mix(in srgb, ${tone} 20%, transparent)` : undefined,
        }}
        aria-hidden
      />
      <span className="text-[length:11px] text-[var(--foreground)]">
        {state === "connected" && connected
          ? `Connected · ${connected} peer${connected === 1 ? "" : "s"}`
          : STATE_TEXT[state]}
      </span>
      {room ? (
        <code
          className="ml-auto font-mono text-[10px] text-[var(--muted-foreground)]"
          title={room}
        >
          {shortRoom(room)}
        </code>
      ) : null}
      {live && invite && onCopyInvite ? (
        <Button
          size="sm"
          variant="secondary"
          className="h-[22px] shrink-0 rounded-[5px] px-2 text-[10px]"
          onClick={(e) => {
            e.stopPropagation();
            onCopyInvite();
          }}
        >
          Copy invite
        </Button>
      ) : null}
      {live && onCancel ? (
        <Button
          size="sm"
          variant="ghost"
          className="h-[22px] shrink-0 rounded-[5px] px-2 text-[10px] text-[var(--muted-foreground)]"
          onClick={(e) => {
            e.stopPropagation();
            onCancel();
          }}
        >
          Cancel
        </Button>
      ) : null}
    </div>
  );
}
