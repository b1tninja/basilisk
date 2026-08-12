import * as React from "react";
import { cn } from "@/lib/cn";
import { copyText, formatFingerprint } from "@/lib/utils.js";
import { normalizeFingerprintInput } from "@/lib/pgp/verify-fpr.js";
import { clearTrust, getTrust, setTrust, type TrustLevel } from "@/lib/trust.js";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./dropdown-menu";

/**
 * A fingerprint, and the only way one is ever put in front of a reader.
 *
 * **The abbreviation carries no bits of the key.** Six surfaces each kept a
 * private `shortFpr` printing `AABBCCDD…EEFF` — eight hex characters, an
 * ellipsis, four more — while the search page told the same reader that "short
 * (8-character) key IDs are collision-prone; confirm the full fingerprint out of
 * band before trusting a key". Twelve hex characters is 48 bits rather than the
 * short id's 32, and raising the number is not the fix. Two things are wrong
 * with the form and only one of them is arithmetic:
 *
 * 1. 48 bits is 65 536× more work than the 32 that were forged wholesale in
 *    2016, which is a real improvement and still not a margin anybody should be
 *    asked to stake a key exchange on.
 * 2. The reader cannot tell. `AABBCCDD…EEFF` shows the two ends of the value —
 *    exactly the characters a person compares out loud — and says nothing about
 *    the 112 bits behind the ellipsis. Whatever number is chosen, a form built
 *    from the fingerprint's own characters is a form that will be compared, and
 *    the comparison will be of a part while the reader believes it was of the
 *    whole.
 *
 * So this component does not pick a safer number of characters; it declines to
 * publish a number of characters at all. `full` prints every one of the 40 or
 * 64, grouped, and `compact` prints **nothing derived from the key** — it
 * prints a name the row already has for it, which is why `label` is required
 * rather than optional. A caller with no name for a key has no compact form,
 * and that is deliberate: "it fits the column" is the argument that produced
 * the elided form in the first place.
 *
 * **Copy always writes the whole value, never what is on screen.** That is the
 * point of the exercise — a compact fingerprint is a door to the fingerprint,
 * not a substitute for it — and it is what makes the abbreviation safe to show
 * at all. The printed spelling is `formatFingerprint`'s, the same one
 * `findFingerprints` is built to recover, so anything this copies pastes back
 * into the invite box and names the same key. `fingerprint-roundtrip.test.js`
 * pins that as a property of this component rather than of two functions that
 * happen to agree today.
 *
 * **The actions were all built and none of them were reachable from a
 * fingerprint.** The keyserver key page, `getTrust`/`setTrust`, and adding
 * somebody to a room already existed; a reader looking at the key they wanted
 * to act on had no way to get from it to any of them. This is that consumer.
 *
 * @module components/ui/fingerprint
 */

/**
 * Why adding refuses when the key is already a member.
 *
 * Exported because `SessionStart` has its own one-press add beside the search
 * hits and must refuse in the same words — one condition, one explanation.
 */
export const ALREADY_IN_ROOM =
  "This key is already in the room, so there is nothing to add.";

/**
 * Why the OpenPGP actions refuse, in the words of the state they are in.
 *
 * Two states, not one, because a refusal has to name the state the reader is
 * actually in. An `SHA256:` id from the SSH cards is a real fingerprint of a
 * real key and copying the whole of one matters exactly as much — it simply has
 * no keyserver page, no trust mark and no room, all three of which are keyed by
 * OpenPGP hex. Anything else that is not 40 or 64 hex characters is a different
 * problem entirely: it is not a fingerprint of anything, and telling that
 * reader they are looking at an SSH key would be a confident lie.
 *
 * The trust map is the one worth naming out loud: `cleanFpr` strips every
 * non-hex character, so marking an `SHA256:` id would file the mark under the
 * wreckage of a base64 digest and it would answer to a key nobody holds.
 */
const NOT_OPENPGP = Object.freeze({
  ssh: "This is an SSH key fingerprint. The keyserver, the trust marks and the room are all keyed by OpenPGP fingerprint, so there is nothing here to open, mark or invite.",
  malformed:
    "This is not a whole OpenPGP fingerprint — those are 40 characters for v4 and 64 for v6 — so there is no key here to open, mark or invite.",
});

/** Which of the two refusals a value earns, or "" when it earns neither. */
function notOpenPgp(fpr: string): string {
  if (openPgpHex(fpr)) return "";
  return /^(spki:)?SHA256:/.test(String(fpr || "").trim())
    ? NOT_OPENPGP.ssh
    : NOT_OPENPGP.malformed;
}

type FingerprintCore = {
  /** The whole value — v4/v6 hex, or an `SHA256:` id from the SSH cards. */
  fpr: string;
  /**
   * Put this key in the room being assembled. Absent on surfaces that have no
   * room to add to, which is most of them.
   */
  onAddToAudience?: (fpr: string) => void;
  /** Already a member — the add refuses and says so rather than disappearing. */
  inAudience?: boolean;
  /** Told after a mark is written here, so a caller re-reading `getTrust` sees it. */
  onTrustChange?: (fpr: string, level: TrustLevel | null) => void;
  className?: string;
};

/**
 * `compact` requires a name, and that is the whole rule in the type system.
 *
 * The elided form existed because a roster row could not hold 49 characters. It
 * still cannot — but every one of those rows already carries something that
 * names the key: a peer label a cell header addresses, or a uid. Compact renders
 * *that*, so the row is shorter than it was and publishes nothing to compare.
 * Where no name exists there is no compact variant to reach for, which is what
 * keeps the next dense column from inventing a truncation of its own.
 */
export type FingerprintProps = FingerprintCore &
  (
    | { variant?: "full"; label?: never }
    | { variant: "compact"; label: string }
  );

/** v4/v6 hex, or "" for anything that is not a whole OpenPGP fingerprint. */
function openPgpHex(fpr: string): string {
  const hex = normalizeFingerprintInput(fpr);
  return hex.length === 40 || hex.length === 64 ? hex : "";
}

/** One row of the menu — a label, where it leads, and why it declines. */
export type FingerprintAction = {
  id: "copy" | "keyserver" | "trusted" | "never" | "clear" | "audience";
  label: string;
  /** Set on the rows that are links rather than presses. */
  href?: string;
  /** Why it declines, or undefined while it does not. */
  refusal?: string;
};

/**
 * Every action a fingerprint offers, and the reason behind each refusal.
 *
 * Derived here rather than inline in the menu for the reason `session-flow.js`
 * gives about its own sentences: a menu lives in a portal, so the rows are
 * unreachable to anything that is not a browser, and a refusal nothing can
 * assert is a refusal that will quietly become "Unavailable". The component
 * renders exactly this list — it is not a second opinion about it.
 */
export function fingerprintActions(state: {
  fpr: string;
  /** The local mark, as `getTrust` reads it. */
  trust?: TrustLevel | null;
  /** Whether this surface has a room to add to at all. */
  canAdd?: boolean;
  /** Whether this key is already a member of it. */
  inAudience?: boolean;
}): FingerprintAction[] {
  const hex = openPgpHex(state.fpr);
  const notPgp = notOpenPgp(state.fpr);
  const trust = state.trust ?? null;
  const rows: FingerprintAction[] = [
    { id: "copy", label: "Copy the whole fingerprint" },
    {
      id: "keyserver",
      label: "Open this key on the keyserver",
      ...(hex ? { href: `/key?fpr=${encodeURIComponent(hex)}` } : { refusal: notPgp }),
    },
    {
      id: "trusted",
      label: "Mark trusted",
      refusal:
        notPgp ||
        (trust === "trusted"
          ? "This key is already marked trusted in this browser."
          : undefined),
    },
    {
      id: "never",
      label: "Mark never trust",
      refusal:
        notPgp ||
        (trust === "never"
          ? "This key is already marked never trust in this browser."
          : undefined),
    },
    {
      id: "clear",
      label: "Clear the trust mark",
      refusal: trust
        ? undefined
        : "There is no trust mark on this key in this browser, so there is nothing to clear.",
    },
  ];
  // Absent, not refused, where there is no room: a surface with no session has
  // not declined anything and owes no sentence.
  if (state.canAdd) {
    rows.push({
      id: "audience",
      label: "Add to the room",
      refusal: notPgp || (state.inAudience ? ALREADY_IN_ROOM : undefined),
    });
  }
  return rows;
}

export function Fingerprint(props: FingerprintProps) {
  const { fpr, onAddToAudience, inAudience, onTrustChange, className } = props;
  const compact = props.variant === "compact";
  const label = props.variant === "compact" ? props.label : "";

  /** The one printed spelling, and the only thing Copy ever writes. */
  const printed = formatFingerprint(fpr);
  const hex = openPgpHex(fpr);
  /** How long the thing being copied is — the sentence says so after a copy. */
  const characters = printed.replace(/\s/g, "").length;

  /**
   * Trust is read once and then tracked here, because writing a mark from this
   * menu has to change this menu. Reading it on every render instead would work
   * and would also make every fingerprint on a page touch localStorage on every
   * keystroke somewhere else.
   */
  const [trust, setLevel] = React.useState<TrustLevel | null>(
    () => getTrust(fpr)?.level ?? null
  );
  /** What the last press did, said out loud and on screen. */
  const [said, setSaid] = React.useState("");
  /**
   * Set when the clipboard refused, and it is the whole value — a compact
   * fingerprint whose copy failed leaves the reader with a name and no way to
   * reach what the name stands for, which is the defect this component exists
   * to remove arriving through the back door.
   */
  const [fallback, setFallback] = React.useState(false);

  const mark = (level: TrustLevel | null) => {
    if (level) setTrust(fpr, level);
    else clearTrust(fpr);
    setLevel(level);
    setFallback(false);
    setSaid(
      level
        ? `Marked ${level} in this browser only, like GnuPG ownertrust. Nothing was uploaded.`
        : "Cleared the trust mark in this browser. Nothing was uploaded."
    );
    onTrustChange?.(fpr, level);
  };

  const copy = async () => {
    try {
      await copyText(printed);
      setFallback(false);
      setSaid(
        compact
          ? `Copied the whole fingerprint — all ${characters} characters, not the name shown here.`
          : `Copied the whole fingerprint — all ${characters} characters.`
      );
    } catch (_) {
      setFallback(true);
      setSaid(
        "The clipboard refused. The whole fingerprint is below — select it and copy it by hand."
      );
    }
  };

  const actions = fingerprintActions({
    fpr,
    trust,
    canAdd: !!onAddToAudience,
    inAudience,
  });

  /** The menu's rows, doing what they say. Links follow themselves. */
  const run = (action: FingerprintAction) => {
    if (action.refusal) return; // `DropdownMenuItem` already stopped it; belt.
    if (action.id === "copy") void copy();
    else if (action.id === "trusted") mark("trusted");
    else if (action.id === "never") mark("never");
    else if (action.id === "clear") mark(null);
    else if (action.id === "audience") onAddToAudience?.(hex);
  };

  return (
    <span
      className={cn("fingerprint", className)}
      data-fingerprint={compact ? "compact" : "full"}
    >
      {/* The value is the control. `title` carries the whole thing on hover so
          the compact form is never the only copy on the page, and it is what a
          test reads to check that what is copied is not what is shown. */}
      <button
        type="button"
        className="fingerprint-value"
        title={printed}
        aria-label={
          compact
            ? `Copy the whole fingerprint of ${label} — all ${characters} characters`
            : `Copy this whole fingerprint — all ${characters} characters`
        }
        onClick={() => void copy()}
      >
        {compact ? label : printed}
      </button>

      <DropdownMenu>
        <DropdownMenuTrigger
          className="fingerprint-actions"
          aria-label={
            compact ? `Actions for ${label}'s key` : "Actions for this fingerprint"
          }
        >
          {/* Drawn, not typed. A `⋯` character is text content, and this sits
              inside the element several tests and one e2e read a fingerprint
              out of — `portal-search.e2e.js` caught it immediately, comparing
              the search result against the key's 40 characters and finding 41.
              An icon is the honest shape for a control that is not a word, and
              it keeps the fingerprint the only text in the element. */}
          <svg viewBox="0 0 16 4" width="12" height="4" aria-hidden focusable="false">
            <circle cx="2" cy="2" r="1.5" fill="currentColor" />
            <circle cx="8" cy="2" r="1.5" fill="currentColor" />
            <circle cx="14" cy="2" r="1.5" fill="currentColor" />
          </svg>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="fingerprint-menu">
          {/* The whole value, in the menu, because a compact fingerprint's
              reader may want to *read* it rather than copy it — and because a
              menu of actions about a key should say which key. */}
          <DropdownMenuLabel className="fingerprint-menu-value">
            {printed}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {actions.map((action) => (
            <DropdownMenuItem
              key={action.id}
              asChild={!!action.href && !action.refusal}
              disabledReason={action.refusal}
              onSelect={() => run(action)}
            >
              {action.href && !action.refusal ? (
                <a href={action.href} target="_blank" rel="noopener noreferrer">
                  {action.label}
                </a>
              ) : (
                action.label
              )}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Rendered text, not `sr-only`: a control that copies has to say what it
          copied, and the reports that produced `refusal.tsx` were all from
          someone looking straight at the control. */}
      <span className="fingerprint-said" role="status">
        {said}
      </span>
      {fallback ? <code className="fingerprint-fallback">{printed}</code> : null}
    </span>
  );
}
