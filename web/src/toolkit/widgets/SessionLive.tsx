import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";
import { InviteCard } from "./InviteCard";
import {
  confirmationReadout,
  rosterCounts,
  sessionReadout,
} from "../../lib/toolkit/session-flow.js";
import type { ConnectionPeer } from "./ConnectionsPanel";

export type SessionLiveState = {
  phase: "idle" | "offering" | "waiting" | "connected" | "closed" | "failed";
  role: "creator" | "joiner" | "";
  room: string;
  /** The last human-readable line the transport emitted. */
  status: string;
  /** Fingerprints the room was derived from — the invite, and who may join. */
  audience: string[];
  /** Which fingerprint this browser is. */
  self: string;
  peers: ConnectionPeer[];
};

export type SessionLiveProps = {
  state: SessionLiveState;
  /** The link for this room's audience, or null when one cannot be built. */
  inviteUrl: string | null;
  onCopyInvite?: () => void;
  /** Renegotiate ICE in place — the room, the audience and the roster survive. */
  onRestartIce?: () => void;
  onClose?: () => void;
  /**
   * Move the room, leaving one fingerprint behind. Absent hides the control
   * entirely rather than dimming it: a disabled button takes its reason with
   * it, and this is the one action on this panel that cannot be undone by
   * pressing it again.
   */
  onRemove?: (fingerprint: string) => void;
  className?: string;
};

/**
 * The live session: what it is doing, who is in it, and what confirmation
 * actually proved.
 *
 * Every sentence is `session-flow.js`'s. Nothing is derived twice — `PlanPanel`
 * refuses to be a second opinion about placement for the same reason, and two
 * opinions about whether a peer is confirmed would be considerably worse than
 * two about where a cell runs.
 *
 * **Confirmation is reported, never requested.** Peers exchange a `kc` frame
 * carrying a transcript hash over the room id, both PGP fingerprints, both
 * ephemeral ECDH keys and both DTLS certificates; a mismatch drops the frame
 * and the peer simply stays unconfirmed. There is no short string for two
 * people to read to each other, so this panel does not invent one — asking for
 * a comparison the protocol does not make would be a lie about what the code
 * does, and a convincing one.
 *
 * **The invite stays visible while the room is short-handed.** Waiting and
 * half-confirmed are exactly the states where somebody still has to be brought
 * in, and hiding the link behind a Share sheet at that moment is how the one
 * action the screen is asking for becomes the hardest to find. It goes away
 * once everyone is confirmed, because then there is nobody to send it to.
 */
export function SessionLive({
  state,
  inviteUrl,
  onCopyInvite,
  onRestartIce,
  onClose,
  onRemove,
  className,
}: SessionLiveProps) {
  const read = sessionReadout(state);
  const counts = rosterCounts(state.peers);
  const wanting =
    read.stage === "waiting" ||
    read.stage === "offering" ||
    read.stage === "unconfirmed" ||
    read.stage === "partial";

  return (
    <div
      className={cn("flex flex-col gap-3", className)}
      data-session-live={read.stage}
    >
      <section
        className="flex flex-col gap-1 rounded-[8px] border border-[var(--border)] p-2.5"
        data-session-readout={read.stage}
      >
        <div className="flex flex-wrap items-center gap-2">
          <span
            className="session-dot h-[7px] w-[7px] shrink-0 rounded-full"
            data-session-tone={state.phase}
            aria-hidden
          />
          <h4 className="text-[12.5px] font-semibold text-[var(--foreground)]">
            {read.headline}
          </h4>
          <span className="peer-verdict ml-auto" data-verdict={read.tone}>
            {counts.verified}/{counts.joined || state.peers.length} confirmed
          </span>
        </div>
        <p className="text-[11px] leading-relaxed text-[var(--muted-foreground)]">
          {read.why}
        </p>
        {read.next ? (
          <p
            className="text-[11px] leading-relaxed text-[var(--foreground)]"
            data-session-next
          >
            {read.next}
          </p>
        ) : null}
      </section>

      <section className="flex flex-col gap-1.5" data-session-roster>
        <h4 className="text-[11px] font-bold text-[var(--foreground)]">
          Who is here
        </h4>
        {state.peers.length ? (
          <ul className="flex list-none flex-col gap-1 p-0">
            {state.peers.map((p) => {
              const verdict = confirmationReadout(p);
              return (
                <li
                  key={p.fingerprint || p.id}
                  className="flex flex-col gap-1 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5"
                  data-session-peer={p.state}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="peer-dot h-[7px] w-[7px] shrink-0 rounded-full"
                      data-peer-state={p.state}
                      aria-hidden
                    />
                    {/* The placard, degraded only where this browser has a name to
                        degrade to. `compact` prints a name and never a piece of
                        the key, so it is right exactly when `name` is set and
                        wrong when it is not: a peer is the whole fingerprint
                        now, and passing that as the "name" would print the key
                        while claiming to print something that is not the key.
                        With no name, the full form. */}
                    {p.fingerprint && p.name ? (
                      <Fingerprint
                        className="min-w-0 flex-1 text-[11px] text-[var(--foreground)]"
                        fpr={p.fingerprint}
                        variant="compact"
                        label={p.name}
                      />
                    ) : p.fingerprint ? (
                      <Fingerprint
                        className="min-w-0 flex-1 text-[11px] text-[var(--foreground)]"
                        fpr={p.fingerprint}
                      />
                    ) : (
                      <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--foreground)]">
                        {p.id}
                      </code>
                    )}
                    {p.via ? (
                      <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
                        {p.via}
                      </span>
                    ) : null}
                    <span className="peer-verdict shrink-0" data-verdict={verdict.tone}>
                      {verdict.verdict}
                    </span>
                  </div>
                  <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                    {verdict.why}
                  </p>
                  {onRemove && p.fingerprint ? (
                    <div className="flex flex-wrap gap-1.5">
                      <button
                        type="button"
                        className="link-action"
                        aria-label={`Remove ${formatFingerprint(p.fingerprint || p.id)} from the room`}
                        onClick={() => onRemove(p.fingerprint as string)}
                      >
                        Remove from room
                      </button>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="text-[10.5px] italic text-[var(--muted-foreground)]">
            Nobody has meshed yet. The audience below is who may — the room is
            derived from exactly those fingerprints, so nobody else can reach it.
          </p>
        )}
      </section>

      {/* Removal, explained once rather than per row. It is the only control
          here that is not reversible by pressing it again, and what it does is
          unusual enough that "Remove" alone would be read as an eviction the
          service performs — which no signalling service this app can reach
          offers. */}
      {onRemove ? (
        <p
          className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
          data-session-removal-note
        >
          Removing somebody moves the room rather than evicting them: the
          remaining members re-derive it under a new epoch and a secret they are
          sent sealed, so the name it moves to is not something the removed key
          can compute. Every pairwise key is rebuilt, and everyone is briefly
          unconfirmed again while that happens.
        </p>
      ) : null}

      {wanting ? (
        <InviteCard
          url={inviteUrl}
          audience={state.audience}
          self={state.self}
          room={state.room}
          onCopy={onCopyInvite}
        />
      ) : null}

      <div className="flex flex-wrap gap-1.5">
        {/* Restart only where the transport actually gave up. Offering it on a
            healthy session would invite a renegotiation nothing asked for. */}
        {state.phase === "failed" && onRestartIce ? (
          <Button size="sm" variant="secondary" onClick={onRestartIce}>
            Restart connection
          </Button>
        ) : null}
        {onClose && state.phase !== "closed" ? (
          <Button size="sm" variant="ghost" onClick={onClose}>
            Close session
          </Button>
        ) : null}
      </div>
    </div>
  );
}
