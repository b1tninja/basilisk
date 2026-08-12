import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/cn";
import { InviteCard } from "./InviteCard";

export type SessionKeyChoice = {
  fingerprint: string;
  uid?: string;
};

export type SessionStartProps = {
  /**
   * Which end this browser is. Not a mode toggle for its own sake: the creator
   * publishes the signed invite and the joiner verifies it, and the relay keeps
   * no history — so which one presses first decides whether anybody meets at
   * all. See the note on the ordering line below.
   */
  role: "offer" | "join";
  onRole: (role: "offer" | "join") => void;
  /** Keys this browser can open a session as — the same vault rows the Keyring lists. */
  keys: SessionKeyChoice[];
  keyFingerprint: string;
  onKeyFingerprint: (fpr: string) => void;
  /** Everyone in the room, canonical, including you. */
  audience: string[];
  /** Fingerprints this notebook already knows about — one press each to add. */
  suggestions?: SessionKeyChoice[];
  onAudience: (audience: string[]) => void;
  /** Whatever was pasted into the invite box, parsed into an audience. */
  onPaste: (text: string) => void;
  /** `startIssues` output — every reason this cannot start yet, as sentences. */
  issues: string[];
  /** The link this audience would produce, or null while it would produce none. */
  inviteUrl: string | null;
  onCopyInvite?: () => void;
  /** The cells Start will write — `sessionRecipe`'s text, shown before it runs. */
  recipe: string;
  onStart: () => void;
  className?: string;
};

/** `AABBCCDD…EEFF`, matching `shortFpr` in the roster projection. */
function shortFpr(fpr: string): string {
  const f = String(fpr || "").toUpperCase();
  return f.length > 12 ? `${f.slice(0, 8)}…${f.slice(-4)}` : f;
}

/**
 * Starting a shared session — naming the room, which is the only decision here.
 *
 * **A room is its audience.** `deriveRoomMaterial` hashes this site's hostname
 * with the sorted fingerprints, so choosing who is in the list *is* choosing
 * which room this is; there is nothing else to configure and no code to
 * allocate. Everything on this panel is therefore about the list and the key
 * that proves you belong in it.
 *
 * **Start writes cells.** It does not call the transport — it appends
 * `agent.unlock` and `quorum.offer`/`quorum.join` to the notebook and runs
 * them, so the session is reproducible, visible in Source view, and shareable
 * as recipe text like everything else here. `CeremonySheet` owns sequence and
 * wording without ever touching the engine for the same reason; this is that
 * rule applied to the one flow that could most easily have become a hidden code
 * path.
 *
 * **The ordering line is not a tip.** The relay brokers to whoever is in the
 * group at the instant of a send and stores nothing, and the creator's invite
 * is published exactly once, in `start()`. A joiner arriving a second later is
 * in the right room and will never see the introduction. So who presses first
 * is a correctness question, not a preference, and it is stated where the
 * choice is made rather than discovered as a timeout two minutes later.
 */
export function SessionStart({
  role,
  onRole,
  keys,
  keyFingerprint,
  onKeyFingerprint,
  audience,
  suggestions = [],
  onAudience,
  onPaste,
  issues,
  inviteUrl,
  onCopyInvite,
  recipe,
  onStart,
  className,
}: SessionStartProps) {
  const [pasted, setPasted] = useState("");
  const [showRecipe, setShowRecipe] = useState(false);
  const issuesId = useId();
  const inRoom = new Set(audience.map((f) => f.toUpperCase()));
  const offering = role === "offer";

  return (
    <div className={cn("flex flex-col gap-3", className)} data-session-start={role}>
      {/* Two roles, side by side, because the difference between them is not
          "advanced": one publishes an invite and one waits for it, and picking
          the wrong one is a room where both ends wait forever. */}
      <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0" data-session-role>
        <legend className="p-0 text-[11px] font-bold text-[var(--foreground)]">
          Which end are you
        </legend>
        <div className="flex flex-wrap gap-1.5">
          <Button
            size="sm"
            variant={offering ? "secondary" : "ghost"}
            aria-pressed={offering}
            onClick={() => onRole("offer")}
          >
            I am starting it
          </Button>
          <Button
            size="sm"
            variant={offering ? "ghost" : "secondary"}
            aria-pressed={!offering}
            onClick={() => onRole("join")}
          >
            I was invited
          </Button>
        </div>
        <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
          {offering
            ? "You publish a signed invite the moment your room is joined, and it is published once — the relay keeps no history of it. Whoever you invited has to be here already, so let them press Join first."
            : "You wait for the creator's signed invite and mesh only after verifying it. Press Join before they start; an invite broadcast before you arrived is gone."}
        </p>
      </fieldset>

      <label className="flex flex-col gap-1" data-session-key>
        <span className="text-[11px] font-bold text-[var(--foreground)]">
          Joining as
        </span>
        {/* Live even with nothing in it. Disabling it was the second half of
            the original report: the chooser went grey, the Start button went
            grey, and neither said the vault was empty — while the one string
            that would have explained both was sitting in the option below. A
            select holding one honest line is reachable, focusable, and says
            what it knows. */}
        <select
          className="rounded-[6px] border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] text-[var(--foreground)]"
          value={keyFingerprint}
          onChange={(e) => onKeyFingerprint(e.currentTarget.value)}
        >
          {/* The empty case says which emptiness it is. A lone "Choose a key…"
              over no options reads as a control that has not loaded, and it
              was the visible half of a Start button that did nothing. */}
          <option value="">
            {keys.length ? "Choose a key…" : "No private key in this browser"}
          </option>
          {keys.map((k) => (
            <option key={k.fingerprint} value={k.fingerprint}>
              {k.uid || shortFpr(k.fingerprint)}
            </option>
          ))}
        </select>
        <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
          This key signs the invite and every signalling envelope after it. It
          has to be one of the fingerprints in the room, because the room is
          derived from that list.
        </span>
      </label>

      <div className="flex flex-col gap-1.5" data-session-audience>
        <span className="text-[11px] font-bold text-[var(--foreground)]">Who is in the room</span>
        {audience.length ? (
          <ul className="flex list-none flex-col gap-0.5 p-0">
            {audience.map((fpr) => (
              <li key={fpr} className="flex items-center gap-1.5">
                <code
                  className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-[var(--foreground)]"
                  title={fpr}
                >
                  {shortFpr(fpr)}
                </code>
                <button
                  type="button"
                  className="link-action"
                  aria-label={`Remove ${shortFpr(fpr)} from the room`}
                  onClick={() => onAudience(audience.filter((f) => f !== fpr))}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[10.5px] text-[var(--muted-foreground)]">
            Nobody yet. Add yourself and at least one other key.
          </p>
        )}

        {suggestions.length ? (
          <div className="flex flex-wrap gap-1.5" data-session-suggestions>
            {suggestions
              .filter((s) => !inRoom.has(s.fingerprint.toUpperCase()))
              .map((s) => (
                <button
                  key={s.fingerprint}
                  type="button"
                  className="link-action"
                  onClick={() => onAudience([...audience, s.fingerprint])}
                >
                  + {s.uid || shortFpr(s.fingerprint)}
                </button>
              ))}
          </div>
        ) : null}

        {/* One box for both directions. A person who was sent an invite pastes
            a URL; a person building one pastes fingerprints out of an email.
            `parseInviteAudience` takes either, because refusing the `https://`
            in front of a list would be complaining that they pasted what they
            were sent. */}
        <Textarea
          className="min-h-[52px] font-mono text-[10.5px]"
          placeholder="Paste an invite link, or fingerprints"
          value={pasted}
          aria-label="Paste an invite link or fingerprints"
          onChange={(e) => setPasted(e.currentTarget.value)}
          onBlur={() => {
            if (pasted.trim()) onPaste(pasted);
          }}
        />
      </div>

      <InviteCard
        url={inviteUrl}
        audience={audience}
        self={keyFingerprint}
        onCopy={onCopyInvite}
      />

      {/* The list Start points at. `startIssues` already writes one sentence
          per blocker, in the register this panel wants, and it is already on
          screen — so the button borrows it rather than emitting a copy, which
          would put the same refusal on the page twice and announce it twice. */}
      {issues.length ? (
        <ul
          id={issuesId}
          className="flex list-none flex-col gap-1 p-0"
          data-session-issues
          data-disabled-reason
        >
          {issues.map((issue) => (
            <li
              key={issue}
              className="border-l-2 border-[var(--warn)] pl-2 text-[10.5px] leading-snug text-[var(--muted-foreground)]"
            >
              {issue}
            </li>
          ))}
        </ul>
      ) : null}

      {/* The cells, before they are written. Not a debug affordance: this is the
          claim that a session is an ordinary recipe, and a reader who cannot see
          the recipe has only our word for it. */}
      <div className="flex flex-col gap-1">
        <button
          type="button"
          className="self-start text-[10.5px] text-[var(--brand)] underline"
          aria-expanded={showRecipe}
          onClick={() => setShowRecipe((v) => !v)}
        >
          {showRecipe ? "Hide" : "Show"} the cells this writes
        </button>
        {showRecipe ? (
          <pre
            className="overflow-x-auto rounded-[6px] border border-[var(--border)] bg-[var(--surface)] p-2 font-mono text-[10px] text-[var(--muted-foreground)]"
            data-session-recipe
          >
            {recipe}
          </pre>
        ) : null}
      </div>

      <Button
        onClick={onStart}
        // Every sentence, not the first. `startIssues` orders nothing, and
        // fixing the one blocker a button chose to name only to find the
        // button still dead is the report this panel already generated once.
        disabledReason={issues.length ? issues.join(" ") : undefined}
        reasonId={issues.length ? issuesId : undefined}
      >
        {offering ? "Start shared session" : "Join shared session"}
      </Button>
    </div>
  );
}
