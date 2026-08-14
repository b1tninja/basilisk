import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";
import { InviteCard } from "./InviteCard";
import {
  attestationReadout,
  attestationVerdict,
  confirmationReadout,
  rosterCounts,
  sessionReadout,
} from "../../lib/toolkit/session-flow.js";
import type { AttestationCoverage } from "../useNotebook";
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
  /**
   * Who has signed over the manifest this notebook derives — `manifestAttestedBy`'s
   * own answer, or null when there is no manifest to have been attested to.
   */
  attestation?: AttestationCoverage | null;
  /** Sign *I saw this manifest* and put it in front of the room. */
  onAttest?: () => void;
  /** Why attesting declines right now, or undefined while it is available. */
  attestRefusal?: string;
  /** What the last press did, in the words of the layer that answered it. */
  attestNote?: string | null;
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
 *
 * **Attestation is the second verdict on every row, and it is not confirmation.**
 * Confirmed is the transport's answer about a channel and arrives on its own;
 * attested is a person's answer about a *notebook* — that this key signed a
 * document naming the manifest this browser derives — and arrives because
 * somebody pressed. They are drawn as two chips rather than one because they
 * fail for unrelated reasons, and a room can be perfectly confirmed with nobody
 * having looked at what it is about to run. This panel is where both belong: it
 * is already the one surface that answers "who is here", the roster it draws is
 * the only path attestations take out of the session, and the press that answers
 * for this browser has to sit beside the count it moves.
 */
export function SessionLive({
  state,
  inviteUrl,
  onCopyInvite,
  attestation,
  onAttest,
  attestRefusal,
  attestNote,
  onRestartIce,
  onClose,
  onRemove,
  className,
}: SessionLiveProps) {
  const read = sessionReadout(state);
  const counts = rosterCounts(state.peers);
  const attested = attestationReadout(attestation);
  const digest = String(attestation?.digest || "");
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
              // Null while there is no manifest to compare against — no chip,
              // rather than a chip saying they have not attested to a document
              // that does not exist.
              const attests = attestationVerdict(p, digest);
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
                    {attests ? (
                      <span
                        className="peer-verdict shrink-0"
                        data-verdict={attests.tone}
                        data-peer-attested={attests.verdict === "attested" ? "1" : "0"}
                      >
                        {attests.verdict}
                      </span>
                    ) : null}
                  </div>
                  <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                    {verdict.why}
                  </p>
                  {attests ? (
                    <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
                      {attests.why}
                    </p>
                  ) : null}
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

      {/* What this room has agreed it is about to run, and the one press that
          answers for this browser. Below the roster because it reads as a
          verdict over the rows above it, and it is: every chip up there is one
          entry in this count. Hidden entirely when there is no manifest —
          `attestationReadout` returns null then, and a section headlined "not
          attested" for a notebook that does not compile would be blaming a
          signature for a syntax error. */}
      {attested ? (
        <section className="flex flex-col gap-1.5" data-session-attestation={attested.tone}>
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="text-[11px] font-bold text-[var(--foreground)]">
              Who has seen this run
            </h4>
            {/* A fraction only where there is something to divide by. A
                manifest that names nobody expects nobody, so "0/0 attested"
                would be a number standing where the reason there is no number
                belongs — the readout's caveat says it in words instead. */}
            {attested.total ? (
              <span className="peer-verdict ml-auto" data-verdict={attested.tone}>
                {attested.attested.length}/{attested.total} attested
              </span>
            ) : null}
          </div>
          <p
            className="text-[11px] leading-relaxed text-[var(--foreground)]"
            data-attestation-headline
          >
            {attested.headline}
          </p>
          <p className="text-[10.5px] leading-relaxed text-[var(--muted-foreground)]">
            {attested.why}
          </p>
          {/* The digest, whole. It is what the signature is over, so a reader
              comparing two machines has to be able to read all of it — the same
              rule `components/ui/fingerprint.tsx` holds for a key, for the same
              reason: there is no press here to reveal the rest. */}
          <code className="cell-assign-peer font-mono text-[10px] text-[var(--muted-foreground)]">
            {digest}
          </code>
          {onAttest ? (
            <div className="flex flex-wrap gap-1.5">
              <Button
                size="sm"
                variant="secondary"
                disabledReason={attestRefusal}
                onClick={onAttest}
              >
                Attest to this manifest
              </Button>
            </div>
          ) : null}
          {attestNote ? (
            <p
              className="text-[10.5px] leading-snug text-[var(--foreground)]"
              data-attest-note
              role="status"
            >
              {attestNote}
            </p>
          ) : null}
          <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
            Attesting signs a four-field document naming the digest above — no
            recipe text, no fingerprint, no promise to run anything. It says you
            saw this notebook. It does not say when, and it is not consent.
          </p>
        </section>
      ) : null}

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
