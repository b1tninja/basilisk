import { Cable, Copy, RotateCw, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { meshHealth } from "@/lib/quorum/relay.js";
import type { SessionStripState } from "./SessionStrip";

/**
 * Live connection management (design v2 §34).
 *
 * Deliberately *not* folded into Outputs. The two answer different questions:
 * Outputs holds at-rest artifacts grouped by the cell that made them; this
 * holds whatever is currently open, with the actions that close or repair it.
 * Merging them would force every artifact row to carry a management control it
 * never needs.
 *
 * It is also the only surface that can answer the three questions a mesh
 * raises — who is in the room, which links are up, and which are authenticated
 * — none of which the per-cell `SessionStrip` can express, because that widget
 * assumes one session with one peer.
 */

export type ConnectionPeer = {
  /** Short label — room-scoped id, or a verified identity once authenticated. */
  id: string;
  /** Full key fingerprint when the row comes from a live quorum roster. */
  fingerprint?: string;
  state: "new" | "connecting" | "connected" | "disconnected" | "failed" | "closed";
  /** Verified against a published key, per the signed-transcript design. */
  authenticated?: boolean;
  /** Transport actually selected by ICE, when known. */
  via?: string;
};

export type ConnectionsSession = {
  phase: SessionStripState | "idle";
  room?: string;
  role?: string;
  invite?: string;
  connected?: number;
  expected?: number;
  peers?: ConnectionPeer[];
};

type Props = {
  session: ConnectionsSession;
  onCopyInvite?: () => void;
  onClose?: () => void;
  onRestartIce?: () => void;
  className?: string;
};

function PeerRow({ peer }: { peer: ConnectionPeer }) {
  return (
    <li className="flex items-center gap-2 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5">
      {/* Colour comes from `[data-peer-state]` rules in toolkit.css, never an
          inline style prop: the page runs under `style-src 'self'`, which
          blocks every `element.style` write — including the ones React makes
          from a style object. The state set is closed, so a stylesheet can
          enumerate it. */}
      <span
        className="peer-dot h-[7px] w-[7px] shrink-0 rounded-full"
        data-peer-state={peer.state}
        aria-hidden
      />
      <code
        className="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--foreground)]"
        title={peer.fingerprint || undefined}
      >
        {peer.id}
      </code>
      {peer.via ? (
        <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
          {peer.via}
        </span>
      ) : null}
      {/* Authentication is reported separately from connectivity on purpose: a
          peer can be fully connected and completely unverified, and conflating
          the two is how you end up trusting the wrong end of a working pipe. */}
      <span
        className={cn(
          "shrink-0 rounded-[4px] px-1.5 py-px text-[9.5px] font-semibold",
          peer.authenticated
            ? "bg-[color-mix(in_srgb,var(--brand)_16%,transparent)] text-[var(--brand)]"
            : "bg-[color-mix(in_srgb,var(--warn)_14%,transparent)] text-[var(--warn)]"
        )}
      >
        {peer.authenticated ? "verified" : "unverified"}
      </span>
      <span className="shrink-0 text-[9.5px] text-[var(--muted-foreground)]">{peer.state}</span>
    </li>
  );
}

export function ConnectionsPanel({
  session,
  onCopyInvite,
  onClose,
  onRestartIce,
  className,
}: Props) {
  const idle = !session || session.phase === "idle";
  const peers = session?.peers || [];

  if (idle) {
    return (
      <div className={cn("flex flex-col items-start gap-2 p-3", className)} data-connections>
        <Cable size={20} strokeWidth={2} aria-hidden className="text-[var(--muted-foreground)] opacity-30" />
        <p className="text-[11px] text-[var(--muted-foreground)]">
          No live session. Run a cell with{" "}
          <code className="font-mono">quorum.offer</code> to publish an invite, or{" "}
          <code className="font-mono">quorum.join</code> to accept one.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col gap-2 p-3", className)} data-connections>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="text-[11px] font-bold text-[var(--foreground)]">{session.phase}</span>
        {session.room ? (
          <code className="font-mono text-[10px] text-[var(--muted-foreground)]" title={session.room}>
            {session.room.length > 12 ? `${session.room.slice(0, 6)}…${session.room.slice(-4)}` : session.room}
          </code>
        ) : null}
        {session.role ? (
          <span className="text-[10px] text-[var(--muted-foreground)]">{session.role}</span>
        ) : null}
        {session.expected ? (
          <span className="ml-auto font-mono text-[10px] text-[var(--muted-foreground)]">
            {session.connected ?? 0}/{session.expected}
          </span>
        ) : null}
      </div>

      {session.expected ? (() => {
        // The honest mesh line (p2p-dkg DESIGN §1): full mesh is the right
        // topology for DKG-sized rooms and quadratically wrong past ~8 —
        // state the degree instead of pretending arbitrary N is fine.
        const health = meshHealth((session.expected ?? 0) + 1);
        return (
          <p
            className={cn(
              "text-[10px]",
              health.overCap ? "font-semibold text-[var(--warn)]" : "text-[var(--muted-foreground)]"
            )}
            data-mesh-health={health.overCap ? "over-cap" : "ok"}
          >
            mesh · {health.participants} participants · {health.note}
          </p>
        );
      })() : null}

      {peers.length ? (
        <ul className="flex flex-col gap-1">
          {peers.map((p) => (
            <PeerRow key={p.fingerprint || p.id} peer={p} />
          ))}
        </ul>
      ) : (
        <p className="text-[10.5px] italic text-[var(--muted-foreground)]">
          No peers yet — the invite has been published and is waiting to be accepted.
        </p>
      )}

      <div className="flex flex-wrap gap-1.5">
        {session.invite && onCopyInvite ? (
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-[5px] border border-[var(--border)] bg-[var(--surface-raised)] px-2 py-1 text-[10px] font-semibold text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            onClick={onCopyInvite}
          >
            <Copy size={11} strokeWidth={2} aria-hidden />
            Copy invite
          </button>
        ) : null}
        {session.phase === "failed" && onRestartIce ? (
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-[5px] bg-[var(--error)] px-2 py-1 text-[10px] font-bold text-[#1a0505] hover:opacity-90"
            onClick={onRestartIce}
          >
            <RotateCw size={11} strokeWidth={2.5} aria-hidden />
            Restart connection
          </button>
        ) : null}
        {onClose ? (
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-[5px] border border-[var(--border)] px-2 py-1 text-[10px] font-semibold text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            onClick={onClose}
          >
            <X size={11} strokeWidth={2} aria-hidden />
            Close session
          </button>
        ) : null}
      </div>
    </div>
  );
}
