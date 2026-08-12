import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { cn } from "@/lib/cn";
import type { ConnectionPeer } from "./ConnectionsPanel";

export type SessionStripState =
  | "offering"
  | "waiting"
  | "connected"
  | "closed"
  | "failed";

type Props = {
  state: SessionStripState;
  /** Short room code shown truncated (e.g. "KJ8X…9FQ"). */
  room?: string;
  /** Shareable invite line — Copy invite puts this on the clipboard. */
  invite?: string;
  /** Verified-peer count while connected. */
  connected?: number;
  /**
   * Live roster (p2p-dkg DESIGN §6 — "per-peer, not per-session").
   *
   * A session-level summary is a lie in a mesh: "Connected · 3 peers" reads
   * identically whether every link is healthy or one died, which is exactly
   * the state a ceremony needs to notice. Given a roster the strip lists each
   * peer; without one it stays the two-party summary it always was, so no
   * caller is forced to supply it.
   *
   * Reuses `ConnectionPeer` rather than a parallel shape — same rows the
   * Connections tab renders, same `.peer-dot` CSS.
   */
  peers?: ConnectionPeer[];
  onCopyInvite?: () => void;
  onCancel?: () => void;
  /**
   * Re-negotiate in place (§33a). Distinct from 22b's "Configure TURN", which
   * fires *before* a session exists; by the time this shows there is a live
   * connection whose transport dropped, so the room code and mesh roster stay
   * put and only ICE is restarted.
   */
  onRestartIce?: () => void;
  className?: string;
};

const STATE_TEXT: Record<SessionStripState, string> = {
  offering: "Publishing signed invite…",
  waiting: "Waiting for peer to join…",
  connected: "Connected",
  closed: "Session closed",
  failed: "Connection lost",
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
  peers,
  onCopyInvite,
  onCancel,
  onRestartIce,
  className,
}: Props) {
  const live = state === "offering" || state === "waiting";
  const roster = peers || [];
  // A link that died while the session as a whole still reports connected —
  // the case the session-level summary cannot express.
  const brokenPeers = roster.filter(
    (p) => p.state === "failed" || p.state === "disconnected"
  ).length;
  const unverifiedPeers = roster.filter(
    (p) => p.state === "connected" && !p.authenticated
  ).length;
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-[7px] border px-2.5 py-2",
        state === "connected"
          ? "border-[color-mix(in_srgb,var(--brand)_30%,transparent)] bg-[color-mix(in_srgb,var(--brand)_7%,transparent)]"
          : state === "failed"
            ? "border-[color-mix(in_srgb,var(--error)_30%,transparent)] bg-[color-mix(in_srgb,var(--error)_7%,transparent)]"
            : "border-[color-mix(in_srgb,var(--caret)_30%,transparent)] bg-[color-mix(in_srgb,var(--caret)_7%,transparent)]",
        // Not `opacity-60`. A closed session is over, not unreadable, and
        // fading the whole strip took its text to 4.12:1 measured — the row
        // you look at to confirm a ceremony ended cleanly. The muted border
        // and background already say "past"; the words stay full strength.
        state === "closed" && "session-strip-closed",
        className
      )}
      data-session-strip={state}
    >
      {/* Tone comes from `[data-session-tone]` rules in toolkit.css, never a
          style prop: `style-src 'self'` blocks every element.style write, and
          the state set is closed. `failed` reads as a break in the connected
          lineage, so it takes the error accent rather than a new tone. */}
      <span
        className={cn(
          "session-dot h-[7px] w-[7px] shrink-0 rounded-full",
          live && "animate-pulse"
        )}
        data-session-tone={state}
        data-session-live={live ? "1" : undefined}
        aria-hidden
      />
      <span className="text-[length:11px] text-[var(--foreground)]">
        {state === "connected" && connected
          ? `Connected · ${connected} peer${connected === 1 ? "" : "s"}`
          : STATE_TEXT[state]}
      </span>
      {/* Partial failure has to surface on the summary line too — the roster
          below may be scrolled out of view, and "Connected" alone would read
          as success while a custodian's link is down. */}
      {/* Both chips take their tint from `--tile-tint` rather than a
          hand-written 14%: measured at 14% they read 3.77:1 and 3.59:1 in
          light against a 4.5 bar, and these two are the summary line's whole
          reason for existing — the warning that "Connected" is not the
          complete story. */}
      {brokenPeers ? (
        <span className="peer-verdict" data-verdict="error" data-session-degraded>
          {brokenPeers} link{brokenPeers === 1 ? "" : "s"} down
        </span>
      ) : null}
      {unverifiedPeers ? (
        <span className="peer-verdict" data-verdict="warn" data-session-unverified>
          {unverifiedPeers} unverified
        </span>
      ) : null}
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
          className="session-action shrink-0 rounded-[5px] px-2 text-[10px]"
          onClick={(e) => {
            e.stopPropagation();
            onCopyInvite();
          }}
        >
          Copy invite
        </Button>
      ) : null}
      {state === "failed" && onRestartIce ? (
        <Button
          size="sm"
          className="session-action shrink-0 rounded-[5px] bg-[var(--error)] px-2 text-[10px] font-bold text-[#1a0505] hover:opacity-90"
          onClick={(e) => {
            e.stopPropagation();
            onRestartIce();
          }}
        >
          Restart connection
        </Button>
      ) : null}
      {live && onCancel ? (
        <Button
          size="sm"
          variant="ghost"
          className="session-action shrink-0 rounded-[5px] px-2 text-[10px] text-[var(--muted-foreground)]"
          onClick={(e) => {
            e.stopPropagation();
            onCancel();
          }}
        >
          Cancel
        </Button>
      ) : null}

      {/* Per-peer rows: the mesh answer to "who is actually here". Only when
          a roster was supplied and the session is not already closed — a
          closed session's last roster belongs in the Connections tab's
          history, not here where it would read as still-live. */}
      {roster.length && state !== "closed" ? (
        <ul className="mt-0.5 flex w-full flex-col gap-0.5" data-session-peers>
          {roster.map((p) => (
            <li
              key={p.fingerprint || p.id}
              className="flex items-center gap-1.5 pl-[15px]"
              data-session-peer={p.state}
            >
              <span
                className="peer-dot h-[5px] w-[5px] shrink-0 rounded-full"
                data-peer-state={p.state}
                aria-hidden
              />
              {/* Label and key in one control, for the reason ConnectionsPanel
                  gives. This strip is the tightest row in the app, which is
                  exactly where the elided fingerprint used to be argued for —
                  and the compact form is *shorter* than what it replaced. */}
              {p.fingerprint ? (
                <Fingerprint
                  className="min-w-0 flex-1 text-[10px] text-[var(--foreground)]"
                  fpr={p.fingerprint}
                  variant="compact"
                  label={p.id}
                />
              ) : (
                <code className="min-w-0 flex-1 truncate font-mono text-[10px] text-[var(--foreground)]">
                  {p.id}
                </code>
              )}
              {p.via ? (
                <span className="shrink-0 font-mono text-[9px] text-[var(--muted-foreground)]">
                  {p.via}
                </span>
              ) : null}
              {/* Connectivity and authentication stay separate here for the
                  same reason as in ConnectionsPanel: a peer can be fully
                  connected and completely unverified.
                  The verdict is withheld until the link is up, though — a peer
                  mid-handshake has not *failed* verification, it has not
                  reached it, and badging every joining peer "unverified"
                  cries wolf on every join. These rows show no state text
                  (only the dot), so an unqualified badge would be the only
                  thing a reader sees. */}
              {p.state === "connected" || p.state === "failed" ? (
                // Same ink as the summary chip above, from the same rule —
                // `text-[var(--brand)]`/`text-[var(--warn)]` straight from the
                // token measured 4.42:1 and 4.26:1 at 9px in light.
                <span
                  className="peer-ink shrink-0 text-[9px] font-semibold"
                  data-verified={p.authenticated ? "1" : "0"}
                >
                  {p.authenticated ? "verified" : "unverified"}
                </span>
              ) : (
                <span className="shrink-0 text-[9px] text-[var(--muted-foreground)]">
                  {p.state}
                </span>
              )}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
