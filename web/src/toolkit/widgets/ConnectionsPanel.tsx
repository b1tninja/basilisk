import { Cable, Copy, RotateCw, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { Fingerprint } from "@/components/ui/fingerprint";
import { meshHealth } from "@/lib/notebook/relay.js";
import {
  connStateReadout,
  linkOriginNote,
  relayFallbackReadout,
} from "@/lib/toolkit/artifact-readouts.js";
import { peerVerdictBadge } from "@/lib/toolkit/session-flow.js";
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
  /**
   * What a cell header addresses this peer as — the whole fingerprint, upper
   * case, for a row from a live quorum roster. A direct `peer.*` link has no
   * identity at all and carries its connection name here instead, which is why
   * this is a separate field from `fingerprint` and not the same string twice.
   */
  id: string;
  /** The whole key fingerprint when the row comes from a live quorum roster. */
  fingerprint?: string;
  /**
   * A name this browser has for the key — a uid or a trust mark, never
   * anything derived from the fingerprint. Absent where it knows none, and the
   * row says so rather than inventing something to fill the column.
   */
  name?: string;
  state: "new" | "connecting" | "connected" | "disconnected" | "failed" | "closed";
  /** Verified against a published key, per the signed-transcript design. */
  authenticated?: boolean;
  /**
   * Attestations this key has signed over a run manifest, as the session
   * checked them. A different claim from `authenticated` and carried separately
   * for that reason: confirmed says the channel is theirs, attested says they
   * put their name to a notebook. Absent for a `peer.*` link, which has no
   * identity to have signed with.
   */
  attested?: { manifest?: string }[];
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

/** One managed connection from the link registry (§57a). */
export type ConnectionLink = {
  id: string;
  origin: "peer" | "quorum";
  role: "offerer" | "answerer";
  label?: string;
  connectionState: ConnectionPeer["state"];
  channelState?: string;
  authenticated?: boolean;
  via?: string;
  /**
   * The two-phase relay fallback's state on this link (§22c). `off` — the
   * shipped default — means no relay will be contacted for it under any
   * circumstances.
   */
  relay?: {
    phase: "off" | "armed" | "escalating" | "escalated" | "exhausted" | "unavailable";
    configured?: boolean;
    reason?: string;
  };
  /** Whether the relay ended up carrying the traffic — `via === "relay"`. */
  relayed?: boolean;
};

type Props = {
  session: ConnectionsSession;
  /**
   * Every live link, mesh included. Only the `peer`-origin ones are drawn here
   * — the mesh's are the roster above, and drawing both would be one
   * connection in two rows.
   */
  links?: ConnectionLink[];
  onCopyInvite?: () => void;
  onClose?: () => void;
  onRestartIce?: () => void;
  onCloseLink?: (id: string) => void;
  onRestartLink?: (id: string) => void;
  className?: string;
};

function PeerRow({ peer }: { peer: ConnectionPeer }) {
  const verdict = peerVerdictBadge(peer);
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
      {/* The placard. A peer is the key now, so the row and the notebook name
          the same value and there is nothing to reconcile between them — which
          is what `variant="compact"` used to do here, standing a positional
          label in for the key. There is no label left to stand in.

          `Fingerprint` brings the rest of the placard with it: Copy, the trust
          mark, the keyserver page. The name beside it is this browser's own
          knowledge and never part of the key.

          Rows with no fingerprint (a direct link, no identity) keep the plain
          id: there is nothing to copy and nothing to act on. */}
      {peer.fingerprint ? (
        <span className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-1.5">
          <Fingerprint
            className="text-[11px] text-[var(--foreground)]"
            fpr={peer.fingerprint}
          />
          <span className="min-w-0 truncate text-[10px] text-[var(--muted-foreground)]">
            {peer.name || "no name for this key in this browser"}
          </span>
        </span>
      ) : (
        <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--foreground)]">
          {peer.id}
        </code>
      )}
      {peer.via ? (
        <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
          {peer.via}
        </span>
      ) : null}
      {/* Authentication is reported separately from connectivity on purpose: a
          peer can be fully connected and completely unverified, and conflating
          the two is how you end up trusting the wrong end of a working pipe.

          What that argument left open is the other direction, and it is what
          `peerVerdictBadge` closes: a peer can be *confirmed* and completely
          disconnected, and a badge reading only `verified` beside a dead link
          invites the reader to hear it as "this link is good". Confirmation
          stays true — it is a fact about a key, not about a transport — so the
          badge keeps the word and pairs it with where the link stands, which
          is `sent · unconfirmed`'s shape one surface over.

          `data-verified` is deliberately still the confirmation bit alone. It
          is the *history*, the same claim it always was, and the presence half
          is `data-peer-state` on the dot and the state text beside it. */}
      {/* Tint from `--tile-tint`, not a hand-written 14%/16%. The two were
          written before the token existed and measured 3.90:1 and 3.92:1 in
          light against a 4.5 bar — the token is 6% there precisely so an
          accent keeps its contrast under its own wash. Same rule now as every
          other badge in the app (`.peer-verdict` in toolkit.css). */}
      <span className="peer-verdict shrink-0" data-verified={verdict.verified ? "1" : "0"}>
        {verdict.label}
      </span>
      <span className="shrink-0 text-[9.5px] text-[var(--muted-foreground)]">{peer.state}</span>
    </li>
  );
}

/**
 * One direct connection (§58a).
 *
 * Four fields, deliberately the same four the quorum rows above carry — dot,
 * id, transport, verdict, state. The first draft also had the negotiation role
 * and a `direct` origin badge; both were cut in review. The role answers no
 * question this panel exists to answer and belongs on the `connstate` tile,
 * which opens full-width; the badge repeated the section title once per row.
 * Between them they were squeezing the `id`, which is the only element that
 * says *which* connection a row is.
 *
 * `connectionState` stays as text beside the dot because the dot is
 * `aria-hidden` and colour-only — the text is what satisfies 1.4.1.
 */
function LinkRow({
  link,
  onCloseLink,
  onRestartLink,
}: {
  link: ConnectionLink;
  onCloseLink?: (id: string) => void;
  onRestartLink?: (id: string) => void;
}) {
  const note = linkOriginNote(link.origin);
  const state = link.connectionState;
  const settled = state === "connected";
  // Restart only where ICE has actually given up. Absent, not dimmed: a
  // disabled button removes itself from the tab order and takes its reason
  // with it (§47), and `SessionStrip` already gates its own Restart this way.
  const canRestart = state === "failed" || state === "disconnected";
  const read = settled ? null : connStateReadout(link);
  // Drawn only once a relay is actually in the picture. On the default — the
  // fallback off, no relay anywhere near this connection — a row saying "no
  // relay" on every link would be noise about a third party that is not there,
  // and the panel's job is to report the ones that are.
  const relay = link.relay && link.relay.phase !== "off" ? relayFallbackReadout(link) : null;
  return (
    <li
      className="flex flex-col gap-1 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5"
      data-link-id={link.id}
      data-link-origin={link.origin}
    >
      <div className="flex items-center gap-2">
        <span
          className="peer-dot h-[7px] w-[7px] shrink-0 rounded-full"
          data-peer-state={state}
          aria-hidden
        />
        <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--foreground)]">
          {link.id}
        </code>
        {link.via ? (
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            {link.via}
          </span>
        ) : null}
        <span className="peer-verdict shrink-0" data-verdict={note.tone}>
          {note.label}
        </span>
        <span className="shrink-0 text-[9.5px] text-[var(--muted-foreground)]">{state}</span>
      </div>

      {/* The verdict is `connStateReadout`'s, never a second copy — the same
          function the `connstate` tile calls, so the panel and the tile cannot
          hold two opinions about why a connection failed. */}
      {read ? (
        <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
          <span className="font-semibold">{read.headline}.</span>{" "}
          {read.next || read.why}
        </p>
      ) : null}

      {/* The relay line. `relayFallbackReadout` keeps *configured*, *escalated*
          and *carried the traffic* as three facts, so a relay that was added
          and then not used is not reported as having seen anything. The
          disclosure rides with it, in `RELAY_DISCLOSURE`'s words, because a
          connection that is being relayed is exactly when the terms matter. */}
      {relay ? (
        <p
          className="text-[10px] leading-snug text-[var(--muted-foreground)]"
          data-relay-phase={link.relay?.phase}
        >
          <span className="peer-verdict mr-1" data-verdict={relay.tone}>
            {relay.verdict}
          </span>
          {relay.why}
          {relay.disclosure ? <span className="relay-disclosure block">{relay.disclosure}</span> : null}
        </p>
      ) : null}

      <div className="flex flex-wrap gap-1.5">
        {canRestart && onRestartLink ? (
          <button
            type="button"
            className="link-action"
            // The visible label stays short; the accessible name carries the
            // object. Three rows of a button labelled only "Restart" is three
            // identical announcements with nothing to tell them apart (4.1.2).
            aria-label={`Restart connection ${link.id}`}
            onClick={() => onRestartLink(link.id)}
          >
            <RotateCw size={10} strokeWidth={2.5} aria-hidden />
            Restart
          </button>
        ) : null}
        {onCloseLink ? (
          <button
            type="button"
            className="link-action"
            aria-label={`Close connection ${link.id}`}
            onClick={() => onCloseLink(link.id)}
          >
            <X size={10} strokeWidth={2} aria-hidden />
            Close
          </button>
        ) : null}
      </div>
    </li>
  );
}

export function ConnectionsPanel({
  session,
  links,
  onCopyInvite,
  onClose,
  onRestartIce,
  onCloseLink,
  onRestartLink,
  className,
}: Props) {
  const idle = !session || session.phase === "idle";
  const peers = session?.peers || [];
  // Mesh links are the roster above; drawing them here too would be one
  // connection in two rows.
  const direct = (links || []).filter((l) => l.origin === "peer");
  const directNote = linkOriginNote("peer");

  const directSection = direct.length ? (
    <section className="flex flex-col gap-1.5" data-direct-links>
      <h4
        id="connections-direct-heading"
        className="text-[11px] font-bold text-[var(--foreground)]"
      >
        Direct connections
      </h4>
      {/* The caution once, on the header. The row carries the *label*
          (`unauthenticated`); this carries the *why*. Repeating the sentence
          per row would read as an alarm and stop being read — but omitting it
          per row entirely was the first draft's mistake, because the quorum
          rows report authentication per row and the less safe section would
          have looked the cleaner one. */}
      <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
        {directNote.why}
      </p>
      <ul className="flex flex-col gap-1" aria-labelledby="connections-direct-heading">
        {direct.map((l) => (
          <LinkRow
            key={l.id}
            link={l}
            onCloseLink={onCloseLink}
            onRestartLink={onRestartLink}
          />
        ))}
      </ul>
    </section>
  ) : null;

  if (idle) {
    return (
      <div className={cn("flex flex-col gap-3 p-3", className)} data-connections>
        {directSection}
        {directSection ? null : (
          <div className="flex flex-col items-start gap-2">
            <Cable
              size={20}
              strokeWidth={2}
              aria-hidden
              className="text-[var(--muted-foreground)] opacity-30"
            />
            {/* The most valuable copy on this panel: it is the only place a
                reader learns the low-ceremony path exists, so it comes
                first. */}
            <p className="text-[11px] leading-snug text-[var(--muted-foreground)]">
              Nothing is connected. Run a cell with{" "}
              <code className="font-mono">peer.offer</code> to open a direct
              connection you carry the offer for yourself — or{" "}
              <code className="font-mono">quorum.offer</code> /{" "}
              <code className="font-mono">quorum.join</code> for an
              identity-verified room.
            </p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col gap-2 p-3", className)} data-connections>
      {/* A real heading, not a bold span: the panel had no heading structure at
          all, so two sections would be two undifferentiated runs of list and
          heading navigation is a primary screen-reader movement (1.3.1). */}
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <h4
          id="connections-session-heading"
          className="text-[11px] font-bold text-[var(--foreground)]"
        >
          {session.phase}
        </h4>
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
        <ul className="flex flex-col gap-1" aria-labelledby="connections-session-heading">
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
            className="session-action inline-flex items-center gap-1 rounded-[5px] border border-[var(--border)] bg-[var(--surface-raised)] px-2 text-[10px] font-semibold text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            onClick={onCopyInvite}
          >
            <Copy size={11} strokeWidth={2} aria-hidden />
            Copy invite
          </button>
        ) : null}
        {session.phase === "failed" && onRestartIce ? (
          <button
            type="button"
            className="session-action inline-flex items-center gap-1 rounded-[5px] bg-[var(--error)] px-2 text-[10px] font-bold text-[#1a0505] hover:opacity-90"
            onClick={onRestartIce}
          >
            <RotateCw size={11} strokeWidth={2.5} aria-hidden />
            Restart connection
          </button>
        ) : null}
        {onClose ? (
          <button
            type="button"
            className="session-action inline-flex items-center gap-1 rounded-[5px] border border-[var(--border)] px-2 text-[10px] font-semibold text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            onClick={onClose}
          >
            <X size={11} strokeWidth={2} aria-hidden />
            Close session
          </button>
        ) : null}
      </div>

      {/* Below the session, because the tray reads top-down in order of
          ceremony: the identity-verified room first, the connections you
          carried by hand after it. */}
      {directSection}
    </div>
  );
}
