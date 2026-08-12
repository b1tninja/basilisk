import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/cn";
import { pasteReadout } from "../../lib/toolkit/session-flow.js";
import { InviteCard } from "./InviteCard";

export type SessionKeyChoice = {
  fingerprint: string;
  uid?: string;
};

/** Somebody who could be in the room — a trusted mark, or a search hit. */
export type RecipientChoice = {
  fingerprint: string;
  /** Their uid or email. Absent for a key nothing local knows a name for. */
  label?: string;
};

/** What `pasteReadout` hands back — the sentence and what it did. */
export type PasteResult = ReturnType<typeof pasteReadout>;

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
  /**
   * Peers you have marked trusted, resolved from the device key cache.
   *
   * The suggestion list used to be this browser's *own* vault keys, which is
   * the one group that is mostly not the people you are meeting: your own key
   * joins the room the moment you choose it above, so every remaining
   * suggestion was a second identity of yours. These are the keys you have
   * actually met.
   */
  trusted?: RecipientChoice[];
  /**
   * Look somebody up by name, email or fingerprint.
   *
   * A callback rather than a search this component performs, so this widget
   * still takes plain props and reads no store — the rule `ds-entry.ts` states
   * for everything on the design surface.
   */
  onSearch?: (query: string) => Promise<RecipientChoice[]>;
  onAudience: (audience: string[]) => void;
  /** What the paste box found, as `pasteReadout` read it. */
  onPaste: (result: PasteResult) => void;
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

/** The paste readout's tone, in this app's tokens. */
const PASTE_TONE: Record<string, string> = {
  brand: "text-[var(--brand)]",
  warn: "text-[var(--warn)]",
  muted: "text-[var(--muted-foreground)]",
};

/**
 * Starting a shared session — naming the room, which is the only decision here.
 *
 * **A room is its audience.** `deriveRoomMaterial` hashes this site's hostname
 * with the sorted fingerprints, so choosing who is in the list *is* choosing
 * which room this is; there is nothing else to configure and no code to
 * allocate. Everything on this panel is therefore about the list and the key
 * that proves you belong in it.
 *
 * **Naming the room is a picker, not a hex prompt.** The room is derived from
 * fingerprints, so a box wanting fingerprints is the shape the derivation
 * suggests — and it is the wrong shape for a person, who knows the name of who
 * they are meeting and not their key. So the order here is: your own key, which
 * joins the room when you choose it; the peers you have marked trusted, one
 * press each; a search; and only then a paste box, for somebody who was sent
 * something. Every one of those hands back a whole fingerprint — a truncated
 * form is only ever a label here, never an identity.
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
  trusted = [],
  onSearch,
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
  const [read, setRead] = useState<PasteResult | null>(null);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<RecipientChoice[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState("");
  const [showRecipe, setShowRecipe] = useState(false);
  const inRoom = new Set(audience.map((f) => f.toUpperCase()));
  const offering = role === "offer";

  /** The pick *is* the add. A picker that then wants a confirm is a form. */
  const add = (fpr: string) => {
    const clean = String(fpr || "").toUpperCase();
    if (!clean || inRoom.has(clean)) return;
    onAudience([...audience, clean]);
  };

  const runSearch = async () => {
    const q = query.trim();
    if (!onSearch || !q) return;
    setSearching(true);
    setSearchError("");
    try {
      setHits(await onSearch(q));
    } catch (err) {
      setHits(null);
      setSearchError(err instanceof Error ? err.message : "Could not search for keys.");
    } finally {
      setSearching(false);
    }
  };

  /**
   * Parse on the press, and say what happened either way.
   *
   * The box used to commit on blur — at a moment the reader did not choose,
   * and with no message afterwards, so a paste that found nothing left nothing
   * to read and nothing to press again.
   */
  const addPasted = () => {
    const result = pasteReadout(pasted, { audience });
    setRead(result);
    onPaste(result);
    // Cleared only when it took something. Text that yielded nothing is text
    // the reader is about to fix.
    if (result.added.length) setPasted("");
  };

  const offerable = trusted.filter((t) => !inRoom.has(t.fingerprint.toUpperCase()));

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
        <select
          className="rounded-[6px] border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] text-[var(--foreground)]"
          value={keyFingerprint}
          disabled={!keys.length}
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

      <div className="flex flex-col gap-1.5">
        <span className="text-[11px] font-bold text-[var(--foreground)]">Who is in the room</span>
        {/* The room itself. Nothing else may put an `li` in here — the roster
            e2e counts them against the audience. */}
        <div data-session-audience>
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
            /* Never a bare hex prompt. The first person in the room is you, and
               choosing the key above is what puts you there — saying so is the
               difference between an empty list and an empty list you know how
               to fill. */
            <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
              Nobody yet. Choosing the key you are joining as puts you in the
              room; add at least one other person below.
            </p>
          )}
        </div>

        {offerable.length ? (
          <div className="flex flex-col gap-1" data-session-trusted>
            <span className="text-[10px] font-bold text-[var(--muted-foreground)]">
              Keys you have marked trusted
            </span>
            <div className="flex flex-wrap gap-1.5">
              {offerable.map((t) => (
                <button
                  key={t.fingerprint}
                  type="button"
                  className="link-action"
                  title={t.fingerprint}
                  onClick={() => add(t.fingerprint)}
                >
                  + {t.label || shortFpr(t.fingerprint)}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {onSearch ? (
          <div className="flex flex-col gap-1" data-session-search>
            <label
              className="text-[10px] font-bold text-[var(--muted-foreground)]"
              htmlFor="session-recipient-search"
            >
              Find someone
            </label>
            <div className="flex flex-wrap items-center gap-1.5">
              <input
                id="session-recipient-search"
                type="search"
                autoComplete="off"
                className="min-w-[180px] flex-1 rounded-[6px] border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] text-[var(--foreground)]"
                placeholder="Name, email, or fingerprint"
                value={query}
                onChange={(e) => setQuery(e.currentTarget.value)}
                onKeyDown={(e) => {
                  // Every other search field on this site submits on Enter, and
                  // the recipient binder's did not until somebody reported it
                  // as the binder being broken.
                  if (e.key === "Enter" && !e.nativeEvent.isComposing) {
                    e.preventDefault();
                    void runSearch();
                  }
                }}
              />
              <Button
                size="sm"
                variant="ghost"
                disabled={!query.trim() || searching}
                onClick={() => void runSearch()}
              >
                {searching ? "Searching…" : "Search"}
              </Button>
            </div>
            {searchError ? (
              <p className="text-[10.5px] leading-snug text-[var(--warn)]">{searchError}</p>
            ) : null}
            {hits && !searchError ? (
              hits.length ? (
                <div className="flex flex-col gap-0.5" data-session-hits>
                  {hits.map((hit) => {
                    const here = inRoom.has(hit.fingerprint.toUpperCase());
                    return (
                      <button
                        key={hit.fingerprint}
                        type="button"
                        className="flex items-center gap-1.5 text-left link-action"
                        disabled={here}
                        title={hit.fingerprint}
                        onClick={() => add(hit.fingerprint)}
                      >
                        <span className="min-w-0 truncate">
                          {hit.label || shortFpr(hit.fingerprint)}
                        </span>
                        <code className="font-mono text-[10px] text-[var(--muted-foreground)]">
                          {shortFpr(hit.fingerprint)}
                        </code>
                        <span className="text-[10px] text-[var(--muted-foreground)]">
                          {here ? "in the room" : "add"}
                        </span>
                      </button>
                    );
                  })}
                </div>
              ) : (
                <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
                  No key here answers to that. They may not have published one to
                  this site — a fingerprint they send you works below.
                </p>
              )
            ) : null}
          </div>
        ) : null}

        {/* One box for both directions, and last, because it is the fallback:
            a person who was sent an invite pastes a URL; a person building one
            pastes fingerprints out of an email. `pasteReadout` takes either,
            because refusing the `https://` in front of a list would be
            complaining that they pasted what they were sent. */}
        <div className="flex flex-col gap-1" data-session-paste>
          <Textarea
            className="min-h-[52px] font-mono text-[10.5px]"
            placeholder="Paste an invite link, or fingerprints"
            value={pasted}
            aria-label="Paste an invite link or fingerprints"
            onChange={(e) => setPasted(e.currentTarget.value)}
          />
          <div className="flex flex-wrap items-center gap-1.5">
            <Button size="sm" variant="ghost" disabled={!pasted.trim()} onClick={addPasted}>
              Add
            </Button>
            <span className="text-[10px] text-[var(--muted-foreground)]">
              A printed fingerprint pastes as it is shown — spaces and all.
            </span>
          </div>
          {/* Always rendered once a press has happened, whatever it found. The
              live region is what makes "nothing was found" an answer rather
              than the silence it used to be. */}
          <p
            aria-live="polite"
            data-paste-kind={read?.kind || ""}
            className={cn(
              "text-[10.5px] leading-snug",
              PASTE_TONE[read?.tone || "muted"]
            )}
          >
            {read?.sentence || ""}
          </p>
        </div>
      </div>

      <InviteCard
        url={inviteUrl}
        audience={audience}
        self={keyFingerprint}
        onCopy={onCopyInvite}
      />

      {issues.length ? (
        <ul className="flex list-none flex-col gap-1 p-0" data-session-issues>
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

      <Button onClick={onStart} disabled={issues.length > 0}>
        {offering ? "Start shared session" : "Join shared session"}
      </Button>
    </div>
  );
}
