import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/cn";
import { RefusalLayout, useRefusal } from "@/components/ui/refusal";
import { ALREADY_IN_ROOM, Fingerprint } from "@/components/ui/fingerprint";
import { pasteReadout } from "../../lib/toolkit/session-flow.js";
import { formatFingerprint } from "../../lib/utils.js";
import { InviteCard } from "./InviteCard";

export type SessionKeyChoice = {
  fingerprint: string;
  uid?: string;
  /**
   * What this key will ask of you if you pick it — `keyPowerReadout`'s label.
   *
   * "ready", "needs an unlock", "open, needs its passphrase". The chooser used
   * to list every candidate identically, so the difference between a key that
   * signs immediately and one that will stop the run to ask for a passphrase
   * was invisible at the moment of the choice and discovered afterwards.
   * Nothing `unusable` reaches this list at all — `sessionKeyChoices` filters
   * it — and the reason for that appears under Start, not as a silent absence.
   */
  note?: string;
};

/** Somebody who could be in the room — a trusted mark, or a search hit. */
export type RecipientChoice = {
  fingerprint: string;
  /** Their uid or email. Absent for a key nothing local knows a name for. */
  label?: string;
};

/**
 * Why a key you marked "never" is not put in a room.
 *
 * `quorum-mount.js` asked this with a `confirm()` — "Key … is marked "never"
 * trust. Add to audience anyway?" — which is a dialog that names a state and
 * offers to ignore it in the same breath, from a control that had said nothing
 * until it was pressed. The mark is a decision the reader already made about
 * this key, so the honest shape is a refusal that names the mark and points at
 * where it can be changed, not a prompt that treats it as a speed bump.
 *
 * A module constant because two controls refuse with it — the row's button and
 * the fingerprint's own menu — and one condition gets one explanation.
 */
export const NEVER_TRUSTED =
  "You marked this key “never” — this browser's own trust mark, the same thing GnuPG calls ownertrust. A room is derived from its audience, so adding it would build the room around a key you decided not to believe. Change the mark on the key itself if that was wrong.";

/**
 * Why a hit the keyserver returned still cannot go in the room.
 *
 * `mergeSearchHits` admits a result at sixteen characters, and a room is
 * derived from whole fingerprints — so these were filtered out of the list
 * before it was drawn. That made the *empty* case lie: "No key here answers to
 * that" was printed to somebody whose search had matched, which is a refusal
 * naming a state they were not in. The hit is shown now and refuses on its own
 * behalf, which is the difference between a search that found nothing and a
 * search that found something unusable.
 */
export const SHORT_ID_HIT =
  "This result carries only a short key id, not a whole fingerprint. More than one key can end in the same characters, and a room is derived from full fingerprints — so there is nothing here to derive one from. Open the key and copy its fingerprint, or ask them for it.";

/** A room is derived from whole fingerprints: 40 for v4, 64 for v6. */
function wholeFingerprint(fpr: string): boolean {
  return /^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(String(fpr || "").toUpperCase());
}

/** What `pasteReadout` hands back — the sentence and what it did. */
export type PasteResult = ReturnType<typeof pasteReadout>;

export type SessionStartProps = {
  /**
   * Which end this browser is. Not a mode toggle for its own sake: the creator
   * publishes the signed invite and the joiner verifies it, and a room with two
   * creators or two joiners is a room where nobody is introduced. It is no
   * longer an *ordering* question — a joiner announces itself on arrival and the
   * creator republishes to it — so the line below says what each role does and
   * stops telling the reader who has to press first.
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
   * Fingerprint → a name this browser has for that key, where it has one.
   *
   * **This prop used to carry the labels and now carries the names**, which is
   * the same slot answering the opposite half of the question. A `@peer` header
   * is the key itself now, so the row already holds everything the notebook
   * will say; what it cannot derive is who the key *belongs* to, and that comes
   * from the two lists the shell already loads — the trusted marks and the
   * vault's uids.
   *
   * Passed in rather than looked up, for the rule this widget is held to —
   * plain props, no store — and for the stronger reason `ToolkitShell` gives
   * where the map is built: a placard that resolved a name some other way would
   * be a second opinion about whose key this is, one component away from the
   * first.
   *
   * A key with no entry is drawn with no name and says so. There is no fallback
   * derived from the fingerprint, ever.
   */
  names?: Record<string, string>;
  /**
   * What the last change to this list did to the notebook's placements.
   *
   * Only removals produce one now. Adding somebody used to renumber everyone
   * who sorted below them — a peer was a position — and every header had to be
   * rewritten to keep meaning the same person; a peer is the key itself, so an
   * add disturbs nothing. What survives is the cell placed on somebody who has
   * *left*, which will never run and is handed back to the author
   * (`peer-relabel.js` argues it). Those cells are not on screen from here, so
   * a change nobody narrates is a change nobody can check.
   */
  relabelNote?: string;
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
  /**
   * Fingerprints this browser has marked `never`, upper-case.
   *
   * A list rather than a flag on each choice, because the add has two doors —
   * the row's button and the fingerprint's own actions menu — and only a check
   * inside `add` covers both. A flag would leave the menu route open, which is
   * how the original `confirm()` was bypassed by the one path nobody tested.
   */
  neverTrusted?: string[];
  onAudience: (audience: string[]) => void;
  /** What the paste box found, as `pasteReadout` read it. */
  onPaste: (result: PasteResult) => void;
  /**
   * The ceremony this exact room would get, and the press that writes it.
   *
   * **It lives on the picker because the picker is what decides it.** A split
   * ceremony needs one send cell and one receive cell per holder, a `shares`
   * count equal to the room, and a whole fingerprint in every header and every
   * `to=` — none of which can be written down before the audience exists. That
   * is the chicken-and-egg this answers: choose who is in the room here, and the
   * notebook falls out of the list rather than being composed against people who
   * have not been named yet.
   *
   * Everything in it is computed by `lib/toolkit/room-ceremony.js`, which is
   * where the arithmetic and the copy are argued. This widget takes plain props
   * and reads no store, so the numbers in the sentences and the numbers in the
   * recipe arrive together and cannot disagree.
   */
  ceremony?: {
    /** `roomCeremonySummary` — one sentence per fact, each about this room. */
    summary: string[];
    /** `roomCeremonyIssues` — why it cannot be written, naming the count. */
    issues: string[];
    /** The notebook as `serializeRecipe` will hold it, headers and all. */
    text: string;
    /**
     * One line per cell, in cell order, with the phase it belongs to.
     *
     * The recipe below it is the truth and this is the reading of it, and both
     * are needed: eleven cells of forty-character fingerprints is not a thing a
     * person can scan for "which of these run now and which run when I want the
     * secret back" — which is the half of the product owner's report that is
     * about *running* the ceremony rather than composing it.
     */
    cells: { phase: "deal" | "recover"; why: string }[];
    threshold: number;
    shares: number;
    onWrite: () => void;
    /** What the last press did, or "" — a live region, like `relabelNote`. */
    note?: string;
  };
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
 * something. Every one of those hands back a whole fingerprint, and every one
 * of them shows a whole fingerprint or a name somebody already gave the key —
 * never part of one. See `components/ui/fingerprint.tsx` for why there is no
 * middle setting.
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
/**
 * A search hit, as its own component so `useRefusal` is called once per row.
 *
 * Hooks cannot vary in number across renders, so the refusal could not live
 * inside the `.map`. Already-in-the-room is a refusal rather than a hidden
 * row: the reader should see that the search found them, and be told why
 * pressing it would do nothing.
 */
function SearchHitRow({
  hit,
  here,
  never,
  onAdd,
}: {
  hit: { fingerprint: string; label?: string };
  here: boolean;
  /** Marked `never` in this browser — refused, and told before the press. */
  never: boolean;
  onAdd: (fpr: string) => void;
}) {
  const short = !wholeFingerprint(hit.fingerprint);
  const refusal = useRefusal(
    here ? ALREADY_IN_ROOM : short ? SHORT_ID_HIT : never ? NEVER_TRUSTED : undefined
  );
  return (
    <RefusalLayout note={refusal.note} className="w-full">
      <span className="flex flex-wrap items-baseline gap-1.5">
        {/* The name if the keyserver gave one, and the whole fingerprint under
            it either way. A hit is a key this browser has never met, chosen
            from a list of strangers — the row where somebody decides that this
            is the Ada they meant is the one row that has to show all of it. */}
        {hit.label ? (
          <span className="min-w-0 truncate text-[11px] text-[var(--foreground)]">
            {hit.label}
          </span>
        ) : null}
        <Fingerprint
          className="text-[10px] text-[var(--muted-foreground)]"
          fpr={hit.fingerprint}
          onAddToAudience={onAdd}
          inAudience={here}
        />
        {/* The one-press add stays. The menu is the uniform home for a
            fingerprint's actions; this is the primary task of this panel, and
            burying it a press deeper for consistency's sake would be paying for
            the rule with the flow it exists to protect. Both refuse in the same
            words, from the same constant. */}
        <button
          type="button"
          className="link-action"
          {...refusal.aria}
          aria-label={`${
            here
              ? "Already in the room"
              : short
                ? "Short key id"
                : never
                  ? "Marked never"
                  : "Add to the room"
          }: ${hit.label || formatFingerprint(hit.fingerprint)}`}
          onClick={refusal.guard(() => onAdd(hit.fingerprint))}
        >
          {here
            ? "in the room"
            : short
              ? "short key id"
              : never
                ? "marked never"
                : "Add to the room"}
        </button>
      </span>
    </RefusalLayout>
  );
}

export function SessionStart({
  role,
  onRole,
  keys,
  keyFingerprint,
  onKeyFingerprint,
  audience,
  names = {},
  relabelNote = "",
  trusted = [],
  onSearch,
  neverTrusted = [],
  onAudience,
  onPaste,
  ceremony,
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
  const [showCeremony, setShowCeremony] = useState(false);
  /**
   * The sentence an add refused with, or "".
   *
   * The refusal is already on the row's own button, and this is the half that
   * covers the *other* door: `Fingerprint`'s actions menu offers "add to the
   * room" too, and a guard there that silently did nothing would be the dead
   * control this whole mechanism exists to stop. It is a live region, so a
   * screen reader hears it whichever door was used.
   */
  const [addRefusal, setAddRefusal] = useState("");
  const issuesId = useId();
  const ceremonyIssuesId = useId();
  const inRoom = new Set(audience.map((f) => f.toUpperCase()));
  const refused = new Set(neverTrusted.map((f) => f.toUpperCase()));
  const offering = role === "offer";
  /**
   * A name for a key, out of what this panel was already given.
   *
   * The vault rows and the trusted marks — the two lists on this screen that
   * already carry a name somebody chose. Nothing is looked up: a key with no
   * name here simply shows its label and its fingerprint, which are both true.
   */
  const nameOf = (fpr: string): string => {
    const hex = String(fpr || "").toUpperCase();
    return (
      trusted.find((t) => t.fingerprint.toUpperCase() === hex)?.label ||
      keys.find((k) => k.fingerprint.toUpperCase() === hex)?.uid ||
      ""
    );
  };

  /** The pick *is* the add. A picker that then wants a confirm is a form. */
  const add = (fpr: string) => {
    const clean = String(fpr || "").toUpperCase();
    if (!clean || inRoom.has(clean)) return;
    if (!wholeFingerprint(clean)) {
      // `canonicalAudience` would drop it a moment later and the press would
      // read as a control that does nothing, which is what it did.
      setAddRefusal(SHORT_ID_HIT);
      return;
    }
    if (refused.has(clean)) {
      setAddRefusal(NEVER_TRUSTED);
      return;
    }
    setAddRefusal("");
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
          the wrong one is a room where both ends wait forever. Which one presses
          first is no longer part of that — a joiner announces itself when it
          arrives and the creator publishes the invite again for it — so this
          copy names the two jobs and asks nothing of the reader's timing. */}
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
            ? "You publish a signed invite the moment your room is joined, and again for anyone who arrives after that and announces themselves. Press whenever you like — the order the two of you press in does not decide whether you meet."
            : "You wait for the creator's signed invite and mesh only after verifying it. Arriving late costs nothing: you announce yourself when you join, and an invite already published is republished for you."}
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
          {/* An `<option>` is text, and nothing else — no control, no menu, no
              copy. So it carries the whole fingerprint where the vault knows no
              uid: a chooser is not a place anybody confirms a key, and the row
              in the room below is where this key gets checked. */}
          {keys.map((k) => (
            <option key={k.fingerprint} value={k.fingerprint}>
              {k.uid || formatFingerprint(k.fingerprint)}
              {k.note ? ` — ${k.note}` : ""}
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
            <ul className="flex list-none flex-col gap-1 p-0">
              {audience.map((fpr) => {
                const hex = fpr.toUpperCase();
                const name = names[hex] || nameOf(fpr);
                return (
                  <li
                    key={fpr}
                    className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5"
                    data-session-member={hex}
                  >
                    {/* The placard, and the whole key in it. This row is where a
                        member of the room is identified, and a `@peer` header is
                        now this exact value — so the row and the notebook say
                        the same forty characters and nothing has to be
                        reconciled between them. `variant="compact"` is what used
                        to be drawn here, standing in a peer label for the key;
                        there is no label left to stand in, and the compact form
                        exists precisely so that nobody reaches for a truncation
                        when the column is tight. It is not tight: the row wraps.

                        `Fingerprint` carries the rest of the placard on its own
                        — the trust mark, the keyserver page, Copy — because it
                        is the one component in this app entitled to act on a
                        key. */}
                    <Fingerprint
                      className="text-[10.5px] text-[var(--foreground)]"
                      fpr={fpr}
                    />
                    <span
                      className="min-w-0 flex-1 truncate text-[10.5px] text-[var(--muted-foreground)]"
                      data-session-member-name={name ? "1" : ""}
                    >
                      {name || "no name for this key in this browser"}
                    </span>
                    {/* The accessible name carries the whole fingerprint too. A
                        list of buttons all called "Remove" is one announcement
                        repeated (4.1.2), and naming twelve of forty characters
                        here would put the elided form back into the one place a
                        screen-reader user has no way to check it. */}
                    <button
                      type="button"
                      className="link-action"
                      aria-label={`Remove ${formatFingerprint(fpr)} from the room`}
                      onClick={() => onAudience(audience.filter((f) => f !== fpr))}
                    >
                      Remove
                    </button>
                  </li>
                );
              })}
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

        {/* Said once, where the labels are, because it is the one thing about
            them a reader cannot work out by looking: the order is over key
            material, not over this list, so it is neither the order they were
            added in nor anything they chose. Without this the rewrite below
            reads as the app losing track of an assignment. */}
        {audience.length ? (
          <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
            A cell header addresses one of these keys, in full — assign work to
            somebody now and it runs on their key when the session opens.
            Removing somebody leaves their cells assigned to nobody, and the
            line below says which.
          </p>
        ) : null}

        {/* What that move actually did, cell by cell. Always rendered, for the
            reason the refusal below is: a live region created at the moment of
            its first message is a message some screen readers never announce. */}
        <p
          aria-live="polite"
          data-relabel-note={relabelNote ? "1" : ""}
          className="text-[10.5px] leading-snug text-[var(--brand)]"
        >
          {relabelNote}
        </p>

        {/* Whichever door the add came through. Always rendered so the region
            is there before it has anything to say — a live region created at
            the moment of its first message is a message some screen readers
            never announce. */}
        <p
          aria-live="polite"
          data-add-refusal={addRefusal ? "never" : ""}
          className="text-[10.5px] leading-snug text-[var(--warn)]"
        >
          {addRefusal}
        </p>

        {offerable.length ? (
          <div className="flex flex-col gap-1" data-session-trusted>
            <span className="text-[10px] font-bold text-[var(--muted-foreground)]">
              Keys you have marked trusted
            </span>
            {/* A trusted mark is a key this browser has already met and the
                reader already decided about, so the name they gave it is the
                honest thing to show — and the fingerprint is one press away in
                its own menu. Where there is no name there is nothing to be
                compact about, and the whole value is drawn. */}
            <ul className="flex list-none flex-col gap-1 p-0">
              {offerable.map((t) => (
                <li key={t.fingerprint} className="flex flex-wrap items-baseline gap-1.5">
                  {t.label ? (
                    <Fingerprint
                      className="text-[10.5px] text-[var(--foreground)]"
                      fpr={t.fingerprint}
                      variant="compact"
                      label={t.label}
                      onAddToAudience={add}
                    />
                  ) : (
                    <Fingerprint
                      className="text-[10.5px] text-[var(--foreground)]"
                      fpr={t.fingerprint}
                      onAddToAudience={add}
                    />
                  )}
                  <button
                    type="button"
                    className="link-action"
                    aria-label={`Add ${t.label || formatFingerprint(t.fingerprint)} to the room`}
                    onClick={() => add(t.fingerprint)}
                  >
                    Add to the room
                  </button>
                </li>
              ))}
            </ul>
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
                {...(searching
                  ? { busy: true }
                  : {
                      disabledReason: query.trim()
                        ? undefined
                        : "Type a name, an address or a fingerprint to search for.",
                    })}
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
                  {hits.map((hit) => (
                    <SearchHitRow
                      key={hit.fingerprint}
                      hit={hit}
                      here={inRoom.has(hit.fingerprint.toUpperCase())}
                      never={refused.has(hit.fingerprint.toUpperCase())}
                      onAdd={add}
                    />
                  ))}
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
            {/* The box is empty, which is a different thing from a paste that
                found nothing — that one produces a sentence in the readout. */}
            <Button
              size="sm"
              variant="ghost"
              disabledReason={
                pasted.trim() ? undefined : "Paste an invite link or some fingerprints first."
              }
              onClick={addPasted}
            >
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

      {/* The ceremony for these people, offered where they were chosen.

          Above the invite rather than below it, because that is the order the
          two acts happen in: the notebook has to exist before Share has
          anything to send, and Share is what carries it to everyone the invite
          brought in. Below the room list rather than beside the Start button,
          because what it is generated *from* is the list — a reader who adds a
          person watches the numbers in these sentences change. */}
      {ceremony ? (
        <section className="flex flex-col gap-1.5" data-room-ceremony>
          <span className="text-[11px] font-bold text-[var(--foreground)]">
            A split-key ceremony for this room
          </span>

          {/* Every sentence names something true of this room and this many
              people. The one that corrects a wrong assumption — that this is
              distributed key generation — is in the list rather than behind a
              disclosure, because a reader who never opens the disclosure is
              exactly the reader who will assume it. */}
          {ceremony.summary.length ? (
            <ul className="flex list-none flex-col gap-1 p-0" data-room-ceremony-summary>
              {ceremony.summary.map((line) => (
                <li
                  key={line}
                  className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
                >
                  {line}
                </li>
              ))}
            </ul>
          ) : null}

          {/* The refusals, drawn as their own list for the reason the Start
              issues below are: the button borrows all of them rather than
              choosing one to name, so fixing the one it picked and finding it
              still dead cannot happen. */}
          {ceremony.issues.length ? (
            <ul
              id={ceremonyIssuesId}
              className="flex list-none flex-col gap-1 p-0"
              data-room-ceremony-issues
              data-disabled-reason
            >
              {ceremony.issues.map((issue) => (
                <li
                  key={issue}
                  className="border-l-2 border-[var(--warn)] pl-2 text-[10.5px] leading-snug text-[var(--muted-foreground)]"
                >
                  {issue}
                </li>
              ))}
            </ul>
          ) : null}

          {/* The cells before they are written, on the same principle as "Show
              the cells this writes" below: a generated notebook that could not
              be read before it replaced yours would be the one thing in this
              app you had to take on trust. The whole fingerprints are in it and
              stay whole — a `pre` scrolls rather than eliding. */}
          {ceremony.text ? (
            <div className="flex flex-col gap-1">
              <button
                type="button"
                className="self-start text-[10.5px] text-[var(--brand)] underline"
                aria-expanded={showCeremony}
                onClick={() => setShowCeremony((v) => !v)}
              >
                {showCeremony ? "Hide" : "Show"} the {ceremony.cells.length} cells this
                writes
              </button>
              {showCeremony ? (
                <>
                  {/* The two phases, named and counted, before the recipe. A
                      ceremony that could only be understood by reading eleven
                      pipelines is the complaint this whole feature answers, and
                      the ordering — deal now, recover when you need it — is the
                      part of it that is about running rather than composing.

                      Numbered from **zero**, because that is what the badge on
                      the cell says. The notebook draws `[0]` on its first cell,
                      so a list numbered from one would be a reading of the
                      notebook that disagreed with the notebook by one row all
                      the way down — worse than no numbers at all. */}
                  {(["deal", "recover"] as const).map((phase) => {
                    const rows = ceremony.cells
                      .map((c, i) => ({ ...c, at: i }))
                      .filter((c) => c.phase === phase);
                    if (!rows.length) return null;
                    return (
                      <div key={phase} className="flex flex-col gap-0.5">
                        <span className="text-[10px] font-bold text-[var(--muted-foreground)]">
                          {phase === "deal"
                            ? `Dealing — ${rows.length} cells, run once, together`
                            : `Recovering — ${rows.length} cells, run when the secret is wanted back`}
                        </span>
                        <ol
                          className="flex list-none flex-col gap-0.5 p-0"
                          data-room-ceremony-phase={phase}
                        >
                          {rows.map((c) => (
                            <li
                              key={c.at}
                              className="text-[10px] leading-snug text-[var(--muted-foreground)]"
                            >
                              <span className="font-mono">[{c.at}]</span> {c.why}
                            </li>
                          ))}
                        </ol>
                      </div>
                    );
                  })}
                  <pre
                    className="overflow-x-auto rounded-[6px] border border-[var(--border)] bg-[var(--surface)] p-2 font-mono text-[10px] text-[var(--muted-foreground)]"
                    data-room-ceremony-recipe
                  >
                    {ceremony.text}
                  </pre>
                </>
              ) : null}
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              size="sm"
              variant="secondary"
              // Every sentence, and pointed at the list above rather than
              // printed again — the same arrangement Start has below, for the
              // same reason: one refusal, on screen once, announced once.
              disabledReason={
                ceremony.issues.length ? ceremony.issues.join(" ") : undefined
              }
              reasonId={ceremony.issues.length ? ceremonyIssuesId : undefined}
              onClick={ceremony.onWrite}
            >
              {ceremony.issues.length
                ? "Write the ceremony"
                : `Write the ${ceremony.threshold}-of-${ceremony.shares} ceremony`}
            </Button>
            {/* Named rather than implied. This replaces the notebook, and a
                control that quietly discards what somebody was writing is the
                one kind of press this app does not make. */}
            <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
              Replaces the notebook you have open.
            </span>
          </div>

          {/* Always rendered, for the reason the two live regions above are: a
              region created at the moment of its first message is a message
              some screen readers never announce. */}
          <p
            aria-live="polite"
            data-room-ceremony-note={ceremony.note ? "1" : ""}
            className="text-[10.5px] leading-snug text-[var(--brand)]"
          >
            {ceremony.note || ""}
          </p>
        </section>
      ) : null}

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
