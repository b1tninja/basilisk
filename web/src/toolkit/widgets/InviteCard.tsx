import { useId } from "react";
import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { cn } from "@/lib/cn";
import { INVITE_CARRIES, INVITE_OMITS } from "../../lib/toolkit/session-flow.js";

/**
 * Why there is no link yet — the card's line and Copy's refusal, one string.
 *
 * It names the audience rule rather than the link, because the link is derived:
 * a room is its audience, so "there is no link" is never the state to fix.
 */
/**
 * Why there is no link yet, shared with the shell's Copy-invite handler.
 * Exported so the card's disabled reason and the refusal a press raises are
 * one sentence rather than two that can drift apart.
 */
export const NO_LINK_YET =
  "Name at least two people, including yourself, and there is a link to send.";

export type InviteCardProps = {
  /** The link, or why there is not one yet. */
  url: string | null;
  /** Everyone the room is derived from, canonical order — including you. */
  audience: string[];
  /** Your own fingerprint, so the list can say which row is you. */
  self?: string;
  /**
   * The derived room id, once a session exists. Absent before one does, which
   * is honest rather than a gap: the room is a digest of the audience and the
   * hostname, so before anything is opened there is a *predictable* room and no
   * *open* one, and printing a code for a room nobody is in would invite
   * someone to read it out as if it meant a meeting.
   */
  room?: string;
  onCopy?: () => void;
  className?: string;
};

/**
 * The invite — a list of public fingerprints, and a promise about everything it
 * is not.
 *
 * There is no room code in it and no token. The room is
 * `SHA-256(hostname | sorted audience)` truncated, so both ends compute the
 * same name from the same list and the name itself never travels; admission is
 * *being in the list and holding the key it names*, which is decided before a
 * byte moves. That is a genuinely unusual property for a link somebody is about
 * to paste into a chat window, and a reader will assume the ordinary thing —
 * that this is a bearer token and forwarding it lets a stranger in — unless it
 * is said.
 *
 * So the two lists are the component. `INVITE_CARRIES` and `INVITE_OMITS` are
 * exported constants rather than copy written here, because they are a security
 * claim and a claim a component owns is a claim no test can pin.
 *
 * The audience is drawn in full, not counted. "3 keys" is the number a person
 * cannot check; the fingerprints are the thing they compare against the ones
 * they meant to invite, and inviting the wrong key is the one mistake this
 * screen can still make after everything above it has been proved.
 *
 * "In full" was, until now, a claim this card did not honour: the paragraph
 * above was already written and the list underneath it printed
 * `AABBCCDD…EEFF`. Twelve of forty characters is not the thing anybody compares
 * against an invitation, and on the one card whose whole argument is that the
 * reader should check the list, it was the worst place in the product to
 * shorten. Each row is a whole fingerprint now.
 */
export function InviteCard({
  url,
  audience,
  self,
  room,
  onCopy,
  className,
}: InviteCardProps) {
  const me = String(self || "").toUpperCase();
  const blockedId = useId();
  return (
    <section
      className={cn(
        "flex flex-col gap-2 rounded-[8px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5",
        className
      )}
      data-invite-card
    >
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <h4 className="text-[12.5px] font-semibold text-[var(--foreground)]">
          The invite
        </h4>
        {room ? (
          <code
            className="font-mono text-[10px] text-[var(--muted-foreground)]"
            title={room}
            data-invite-room
          >
            room {room.length > 12 ? `${room.slice(0, 6)}…${room.slice(-4)}` : room}
          </code>
        ) : null}
      </div>

      <ul className="flex list-none flex-col gap-0.5 p-0" data-invite-audience>
        {audience.map((fpr) => (
          <li
            key={fpr}
            className="flex items-baseline gap-1.5"
            data-invite-member={fpr.toUpperCase() === me ? "self" : "peer"}
          >
            <Fingerprint
              className="min-w-0 flex-1 text-[10.5px] text-[var(--foreground)]"
              fpr={fpr}
            />
            {fpr.toUpperCase() === me ? (
              <span className="shrink-0 text-[9.5px] text-[var(--muted-foreground)]">you</span>
            ) : null}
          </li>
        ))}
      </ul>

      {url ? (
        <code
          className="block truncate rounded-[6px] border border-[var(--border)] px-2 py-1 font-mono text-[10px] text-[var(--muted-foreground)]"
          data-invite-url
          title={url}
        >
          {url}
        </code>
      ) : (
        <p
          id={blockedId}
          className="text-[10.5px] text-[var(--muted-foreground)]"
          data-invite-blocked
          data-disabled-reason
        >
          {NO_LINK_YET}
        </p>
      )}

      {/* Carries first, omits second. The reader's question is "what am I about
          to send", and answering "not your keys" before answering "what then"
          is a reassurance about a question nobody asked yet. */}
      <dl className="m-0 flex flex-col gap-1 text-[10.5px] leading-snug">
        <dt className="font-semibold text-[var(--foreground)]">It carries</dt>
        <dd className="m-0">
          <ul className="flex list-none flex-col gap-0.5 p-0 text-[var(--muted-foreground)]">
            {INVITE_CARRIES.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </dd>
        <dt className="font-semibold text-[var(--foreground)]">It does not carry</dt>
        <dd className="m-0">
          <ul className="flex list-none flex-col gap-0.5 p-0 text-[var(--muted-foreground)]">
            {INVITE_OMITS.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </dd>
      </dl>

      <div className="flex flex-wrap gap-1.5">
        <Button
          size="sm"
          variant="outline"
          onClick={onCopy}
          // The card already says this above; the button borrows it rather
          // than printing a second copy under itself.
          disabledReason={url ? undefined : NO_LINK_YET}
          reasonId={url ? undefined : blockedId}
        >
          Copy invite
        </Button>
      </div>
    </section>
  );
}
