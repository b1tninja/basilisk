import { useId, type DragEvent } from "react";
import {
  TOOLBOX_META,
  getShelfMeta,
  pairDirection,
} from "../../lib/toolkit/registry.js";
import { decodeTwinToken, pairTokenParts } from "../../lib/toolkit/step-names.js";
import { cn } from "@/lib/cn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useRefusal } from "@/components/ui/refusal";
import { Glyph, glyphIdFor } from "./Glyph";
import { ToolCard, type ToolCardOp } from "./ToolCard";
import { STEP_MIME, stepDragPayload } from "./mime";

export type OpsTileOp = ToolCardOp;

type Props = {
  /** The pair's forward (encode/primary) op — also the row's display name and docs. */
  op: OpsTileOp;
  /** Reverse-direction op, when distinct from `op` (e.g. a `conjugate`, not a `decodeTwin`). */
  reverseOp?: OpsTileOp;
  /**
   * What the two ops are together — `listDrawerRows`' `caption`, which is the
   * step's `pairCaption` or a `forward / reverse` fallback.
   *
   * Computed for all 22 browse-tree pair rows since it was written and read by
   * nobody. It lands in the two places a name belongs and neither costs a pixel
   * of the row: the row's accessible name as a group, and the eyebrow on the
   * card a pointer opens.
   *
   * Still worth its keep now that the row prints `gpg` and its handles print
   * `encrypt` and `decrypt`, because a caption is rarely the two tokens run
   * together: `age (age-encryption.org/v1)`, `JWS (RFC 7515)`, `Build / read a
   * Key URI`. Those are the human name of the pair and the row shows none of
   * them. Where a caption *is* mechanical — `Sign / verify` — it is redundant
   * with what the buttons now say, and that costs a reader a repeated phrase
   * rather than a wrong one.
   */
  caption?: string;
  /** Row has a working forward (→) direction. Default true. */
  hasForward?: boolean;
  /** Row has a working reverse (←) direction. Default: true if `op.decodeTwin` or `reverseOp` given. */
  hasReverse?: boolean;
  fit?: { forward: boolean; reverse: boolean };
  /**
   * Per-direction dim reason while a caret is active (§20c) — set for a
   * direction that doesn't fit; renders an 8.5px caption under that arrow
   * and dims just that handle instead of the whole row.
   */
  needs?: { forward?: string; reverse?: string };
  /** Whole-row dim — neither direction fits the caret. */
  dim?: boolean;
  showTooltip?: boolean;
  onAppend: (name: string, opts?: { decode?: boolean }) => void;
  className?: string;
};

// Direction is always color-coded (§19a/19b): encode → blue, decode ← purple.
// `fit` only brightens the handle's background/border toward its own hue.
// Class strings must stay literal so Tailwind's scanner can see them.
function directionButtonClass(active: boolean, fit: boolean, kind: "encode" | "decode") {
  if (!active) {
    return "border-dashed border-[var(--border)] bg-transparent text-transparent cursor-not-allowed";
  }
  if (kind === "decode") {
    return cn(
      "cursor-grab active:cursor-grabbing text-[var(--decode)] hover:border-[var(--decode)]",
      fit
        ? "border-[color-mix(in_srgb,var(--decode)_40%,transparent)] bg-[color-mix(in_srgb,var(--decode)_14%,transparent)]"
        : "border-[var(--border)] bg-[var(--surface-raised)]"
    );
  }
  return cn(
    "cursor-grab active:cursor-grabbing text-[var(--caret)] hover:border-[var(--caret)]",
    fit
      ? "border-[color-mix(in_srgb,var(--caret)_40%,transparent)] bg-[color-mix(in_srgb,var(--caret)_14%,transparent)]"
      : "border-[var(--border)] bg-[var(--surface-raised)]"
  );
}

/** Merged encode/decode row — one dot, one name, up to two direction handles (§19b). */
export function OpsTile({
  op,
  reverseOp,
  caption,
  hasForward = true,
  hasReverse = !!(op.decodeTwin || reverseOp),
  fit = { forward: false, reverse: false },
  needs,
  dim = false,
  showTooltip = true,
  onAppend,
  className,
}: Props) {
  const forwardName = op.name;
  // A distinct conjugate (e.g. wrap/unwrap) appends its own name with no decode flag;
  // everything else — decodeTwin ops, and same-name cipher-dispatch kits — appends
  // this op's own name with decode:true.
  const reverseIsDistinctConjugate = !!reverseOp && !op.decodeTwin;
  const reverseName = reverseIsDistinctConjugate ? reverseOp!.name : op.name;
  const reverseDecode = !reverseIsDistinctConjugate;
  const reverseDisplayName = op.decodeTwin ? decodeTwinToken(op, true) : reverseName;
  const forwardPayload = stepDragPayload(forwardName, false);
  const reversePayload = stepDragPayload(reverseName, reverseDecode);
  const forwardDir = pairDirection(op, { decode: false, pairRole: "forward" });
  const reverseDir = pairDirection(reverseOp || op, {
    decode: reverseDecode,
    pairRole: "reverse",
  });

  /**
   * What a direction handle wears, and why it is not always the arrow.
   *
   * The chevrons say "forwards" and "backwards", which this row already says
   * twice: encode is always the left handle and always drawn in `--caret`,
   * decode always the right one in `--decode`. So the mark inside the square
   * is the third copy of the one fact, and the only slot on the row that could
   * carry anything else.
   *
   * `STEP_GLYPHS` decides what it carries, because it is the file that knows
   * whether a pair is one thing run either way. Its own comment says
   * conjugates share one asset — and 17 of the 22 browse-tree pairs do, from
   * `wrap`/`unwrap` to `age.encrypt`/`age.decrypt` — but five are given two,
   * and those five are the ones where the two directions are not each other's
   * inverse. `gpg.encrypt` is a sink and `gpg.decrypt` is a source: pressing
   * one appends a step that consumes the pipe, pressing the other appends one
   * that *discards* what is upstream of it and starts the value afresh
   * (`recipe.js` warns in exactly those words). A closed padlock and an opened
   * one say that; two mirrored chevrons say the opposite, that the second
   * handle runs the first one backwards.
   *
   * Where the registry gives the pair one asset, drawing it twice would say
   * nothing and cost the arrows, so the arrows stay. The rule is legible on
   * the row itself: two different marks mean two ops, two mirrored arrows mean
   * two directions of one.
   */
  const forwardGlyph = glyphIdFor(op);
  const reverseGlyph = reverseOp ? glyphIdFor(reverseOp) : forwardGlyph;
  const perOpGlyphs = reverseGlyph !== forwardGlyph;

  /**
   * What the row prints: the family on the left, the two directions on the
   * buttons that run them.
   *
   * The mono column used to print the forward op's whole name while the two
   * handles were wordless squares, which made the row a claim about one of its
   * two ops — `gpg.encrypt` beside a `«` that runs `gpg.decrypt`. It now prints
   * `gpg`, and the handles print `encrypt` and `decrypt`. The column stopped
   * being a whole token and the *row* did not: `gpg` beside a button reading
   * `encrypt` is `gpg.encrypt` laid out across the row, and every string on it
   * is still spelled the way a recipe spells it.
   *
   * Three OpenPGP rows now print the same word in that column, which is the
   * objection this arrangement has to answer, and the buttons answer it: `gpg`
   * with `encrypt`/`decrypt`, `gpg` with `sign`/`verify`, `gpg` with
   * `symencrypt`/`symdecrypt`. That is not a claim about these three — no two
   * rows anywhere in the shelf print the same three words, and
   * `toolkit-shelves.test.js` sweeps the registry to keep it that way. The two
   * places it is tightest are worth naming: four rows offer `sign` / `verify`
   * (WebCrypto's, `gpg.sign`, `ssh.sign`, `jose.sign`) and are separated by
   * their families alone, while `vss.split` and `sss.split` are separated only
   * by *these* families — both are toolbox `sss`, so a row labelled by its
   * module rather than its stem would collide exactly there.
   *
   * A pair whose tokens share nothing — `wrap`/`unwrap`, `pem`/`der`,
   * `input`/`out` — prints no family, and that is the same rule rather than a
   * gap in it: the column says what the two ops have in common, and those have
   * only their toolbox in common, which the section header above the row is
   * already printing. Repeating it on every row underneath would buy nothing.
   *
   * The split runs on the tokens a *twin* row would spell too, which is why
   * `blip39` reads `blip39` + `encode` / `decode` rather than repeating itself:
   * `decodeTwinToken` is the function that knows an encoding twin serialises
   * as `blip39.encode`, and a cipher twin as `aes-gcm` / `aes-gcm -d`.
   *
   * Nothing became unfindable. The shelf matches a query against op names and
   * now follows a match on a reverse op back to the row that draws it, so
   * `gpg.encrypt`, `gpg.decrypt` and `symdecrypt` all land here — see
   * `pairRowMatches`.
   */
  const forwardDisplayName = op.decodeTwin ? decodeTwinToken(op, false) : forwardName;
  const parts = pairTokenParts(forwardDisplayName, reverseDisplayName);

  /**
   * One reason, stated once.
   *
   * Both handles used to carry their own 8.5px caption, and for the great
   * majority of pairs those captions read identically ("needs bytes" twice
   * under one row), which doubled the row's height and its noise for no extra
   * information. When the two directions genuinely want different inputs the
   * captions still split per handle; otherwise the row states it inline,
   * right-aligned, in exactly the place a solo row states it — so the same
   * fact sits in the same place whichever kind of row you are looking at.
   */
  /**
   * A handle that doesn't fit is now actually inert.
   *
   * It used to render `cursor-not-allowed opacity-40` and stay fully live:
   * clicking it appended the step anyway, and it stayed in the tab order.
   * Meanwhile the solo rows in the shelf deleted their control outright for
   * the same condition. Three behaviours for one state — looks disabled and
   * works, looks disabled and is gone, looks enabled and works — is worse
   * than any one of them consistently applied.
   */
  const forwardLive = hasForward && !needs?.forward;
  const reverseLive = hasReverse && !needs?.reverse;

  const sharedNeed =
    needs?.forward && needs.forward === needs.reverse ? needs.forward : null;
  const splitNeeds = sharedNeed ? undefined : needs;
  const hasCaptions = !!(splitNeeds?.forward || splitNeeds?.reverse);

  const sharedNeedId = useId();
  const forwardNeedId = useId();
  const reverseNeedId = useId();
  /**
   * The refusal for each handle, and the caption that already carries it.
   *
   * Two conditions are folded into one sentence each, deliberately. A handle
   * with `needs` set is refused because the caret is holding the wrong thing —
   * fixable, and the caption says what it wants. A handle with no direction at
   * all (`hasForward === false`) is not a control the reader can do anything
   * about, and it is `aria-hidden` and empty: an omission, not a refusal
   * (§33d), so it gets no sentence and none is invented for it.
   */
  const forwardRefusal = useRefusal(
    hasForward && needs?.forward
      ? `${forwardName} encodes ${needs.forward.replace(/^needs\s+/, "")}, and the caret is holding something else.`
      : undefined,
    { reasonId: sharedNeed ? sharedNeedId : forwardNeedId }
  );
  const reverseRefusal = useRefusal(
    hasReverse && needs?.reverse
      ? `${reverseDisplayName} decodes ${needs.reverse.replace(/^needs\s+/, "")}, and the caret is holding something else.`
      : undefined,
    { reasonId: sharedNeed ? sharedNeedId : reverseNeedId }
  );

  const row = (
    <div
      /*
       * Two controls and one name between them is a group, and it had none —
       * a reader walking the shelf heard `gpg.encrypt` and then
       * `gpg.decrypt` with nothing saying they were one row, let
       * alone what the row was. The caption is that name. `role="group"`
       * rather than a heading because the row is furniture around two
       * buttons, and a group is announced on entry and left alone otherwise.
       */
      role={caption ? "group" : undefined}
      aria-label={caption || undefined}
      /*
       * How two named handles fit a 220px panel, and what they do at 160.
       *
       * They do not fit, at the worst case: `gpg` with `symencrypt` and
       * `symdecrypt` wants 210px of a 191px line. So the row wraps — the two
       * handles move together to a second line, and if that line is still too
       * narrow for both they stack. Nothing is ever clipped, which is the
       * point: a handle reading `symencry…` is a control naming a step you
       * cannot type, and this repo does not truncate a fingerprint for the
       * same reason.
       *
       * It falls out of `flex-wrap` and costs no measurement and no
       * breakpoint. The handles are one flex item whose own content is
       * wrapped, so the line-breaking algorithm sees a single box the width of
       * both buttons and moves it whole.
       *
       * The family is `shrink-0` rather than the old `min-w-0 truncate`, and
       * that is a statement of intent rather than the reason anything fits: a
       * mutation back to `truncate` renders identically at 160, 220 and 520,
       * because a family is one dotted segment — `stream` is the longest at
       * 38px against the 131px line the 160px minimum leaves — and never runs
       * out of room at any width the panel allows. `shrink-0` is here so that
       * if one ever did, it would push the handles down rather than quietly
       * spend characters keeping them up.
       */
      className={cn(
        "flex flex-wrap justify-end gap-x-2 gap-y-1 rounded-md px-1.5 py-[3px] hover:bg-[color-mix(in_srgb,var(--brand)_5%,transparent)]",
        hasCaptions ? "items-start" : "items-center",
        className
      )}
    >
      {/* Identity is the glyph. Verification is not per-op — it lives on the
          toolbox header, one light per suite. */}
      <Glyph
        id={forwardGlyph}
        size={16}
        className={cn("shrink-0", dim ? "opacity-45" : "opacity-80", hasCaptions && "mt-[3px]")}
      />
      <code
        className={cn(
          "grow shrink-0 font-mono text-[11.5px] font-medium",
          // Dimming by opacity took this to 1.97:1 and the caption under it to
          // 1.59:1 in the production build. A colour step is a larger
          // perceptual drop and still legible; see OPS_DIM_TEXT in OpsShelf.
          dim ? "text-[var(--muted-foreground)]" : "text-[var(--foreground)]",
          hasCaptions && "pt-[2px]"
        )}
      >
        {parts.stem}
      </code>
      {sharedNeed ? (
        <span
          id={sharedNeedId}
          data-disabled-reason
          className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]"
        >
          {sharedNeed}
        </span>
      ) : null}
      {/* The pair, as one box the row can move. See the row's own comment:
          `flex-wrap` here is what lets the two handles stack rather than
          either of them losing characters.

          Shrinkable on purpose, unlike every other item on the row. Line
          breaking asks for this box's *unwrapped* width, so the pair still
          moves down as a unit; once it is down there and the line is still too
          narrow — `symencrypt` and `symdecrypt` want 166px of a 131px line at
          the 160px minimum — shrinking is what lets it reach its min-content
          width, which is one handle, which is the second wrap. Pinned to
          `shrink-0` it simply hung over the panel edge with the `s` of
          `symencrypt` cut off. */}
      <span className="flex flex-wrap items-start justify-end gap-1">
      <span className="flex shrink-0 flex-col items-center gap-[2px]">
        <button
          type="button"
          draggable={forwardLive}
          {...forwardRefusal.aria}
          data-dir={forwardDir}
          aria-hidden={!hasForward}
          // A row with no encode direction draws an empty square to keep the
          // two handles aligned. It is a spacer, not a refused control: §33d
          // omission rather than a disabled state, so it says nothing and —
          // being aria-hidden — must not be reachable by Tab either.
          tabIndex={hasForward ? undefined : -1}
          className={cn(
            // `min-w` rather than `w`: the square is the floor a handle with
            // no name to print falls back to, so the empty spacer on a row
            // with one direction still lines up with the handles above it.
            "flex h-5 min-w-[22px] shrink-0 items-center justify-center gap-1 rounded-[4px] border px-1 font-mono text-[10px] font-medium transition-colors",
            directionButtonClass(hasForward, fit.forward, "encode"),
            needs?.forward && "cursor-not-allowed opacity-60"
          )}
          /* `forwardDisplayName`, not `forwardName`, so a decode twin says
             the token it serialises as. The reverse handle has always
             announced `blip39.decode`; the forward one announced the bare
             `blip39`, which left the row unable to spell its own forward op
             out of the family it prints and the word on the button. Both
             halves are the same step either way — only the spelling moved. */
          /* The name is the op and nothing else.
           *
           * It used to end ` — encode`, which was the only way a *wordless*
           * chevron could say which direction it was. The button carries the
           * word now, so that suffix stopped informing and started lying: it
           * read `blip39.encode — encode`, saying it twice, and
           * `gpg.encrypt — encode`, saying "encode" about an op that
           * encrypts. `encode`/`decode` is this row's slot vocabulary, not
           * the op's verb, and a name is the wrong place for a slot.
           *
           * WCAG 2.5.3 still holds without it, and by construction rather
           * than by luck: the visible word is the op's last dotted segment,
           * so `gpg.encrypt` contains `encrypt` and `blip39.encode` contains
           * `encode`. The direction stays announced as the description,
           * through `title`. */
          aria-label={
            hasForward
              ? needs?.forward
                ? `${forwardDisplayName}, unavailable: ${needs.forward}`
                : forwardDisplayName
              : undefined
          }
          title={hasForward ? needs?.forward || "Encode" : undefined}
          onClick={
            hasForward
              ? forwardRefusal.guard(() => onAppend(forwardName, { decode: false }))
              : undefined
          }
          onDragStart={
            forwardLive
              ? (e: DragEvent<HTMLButtonElement>) => {
                  e.dataTransfer.setData(STEP_MIME, forwardPayload);
                  e.dataTransfer.setData("text/plain", forwardDisplayName);
                  e.dataTransfer.effectAllowed = "copy";
                }
              : undefined
          }
        >
          {/* 12px, not the 16 this handle drew when the glyph was the whole
              button: the art is now beside a word rather than standing in for
              one, and at 16 it outweighs the 10px name it is labelling. */}
          {hasForward ? <Glyph id={perOpGlyphs ? forwardGlyph : "encode"} size={12} /> : null}
          {hasForward ? <span className="whitespace-nowrap">{parts.forward}</span> : null}
        </button>
        {splitNeeds?.forward ? (
          <span
            id={forwardNeedId}
            data-disabled-reason
            className="whitespace-nowrap text-[8.5px] text-[var(--muted-foreground)]"
          >
            {splitNeeds.forward}
          </span>
        ) : null}
      </span>
      <span className="flex shrink-0 flex-col items-center gap-[2px]">
        <button
          type="button"
          draggable={reverseLive}
          {...reverseRefusal.aria}
          data-dir={reverseDir}
          aria-hidden={!hasReverse}
          tabIndex={hasReverse ? undefined : -1}
          className={cn(
            "flex h-5 min-w-[22px] shrink-0 items-center justify-center gap-1 rounded-[4px] border px-1 font-mono text-[10px] font-medium transition-colors",
            directionButtonClass(hasReverse, fit.reverse, "decode"),
            needs?.reverse && "cursor-not-allowed opacity-60"
          )}
          aria-label={
            hasReverse
              ? needs?.reverse
                ? `${reverseDisplayName}, unavailable: ${needs.reverse}`
                : reverseDisplayName
              : undefined
          }
          title={hasReverse ? needs?.reverse || "Decode" : undefined}
          onClick={
            hasReverse
              ? reverseRefusal.guard(() => onAppend(reverseName, { decode: reverseDecode }))
              : undefined
          }
          onDragStart={
            reverseLive
              ? (e: DragEvent<HTMLButtonElement>) => {
                  e.dataTransfer.setData(STEP_MIME, reversePayload);
                  e.dataTransfer.setData("text/plain", reverseDisplayName);
                  if (reverseDecode) {
                    e.dataTransfer.setData("application/x-basilisk-decode", "1");
                  }
                  e.dataTransfer.effectAllowed = "copy";
                }
              : undefined
          }
        >
          {hasReverse ? <Glyph id={perOpGlyphs ? reverseGlyph : "decode"} size={12} /> : null}
          {hasReverse ? <span className="whitespace-nowrap">{parts.reverse}</span> : null}
        </button>
        {splitNeeds?.reverse ? (
          <span
            id={reverseNeedId}
            data-disabled-reason
            className="whitespace-nowrap text-[8.5px] text-[var(--muted-foreground)]"
          >
            {splitNeeds.reverse}
          </span>
        ) : null}
      </span>
      </span>
    </div>
  );

  if (!showTooltip) return row;

  return (
    <Tooltip delayDuration={280}>
      <TooltipTrigger asChild>{row}</TooltipTrigger>
      <TooltipContent
        side="right"
        sideOffset={10}
        className="max-w-none border-0 bg-transparent p-0 text-left text-[var(--text)] shadow-none"
      >
        {/* The card behind a pair row documented the forward op and said so
            in its title — hovering the OpenPGP row opened a card headed
            `gpg.encrypt`, `Recipe gpg.encrypt`, `Outputs`, on a row whose
            other half is a source called `gpg.decrypt`. It still documents the
            forward op, because that is the op whose params are on it; it no
            longer claims to be the row. */}
        <ToolCard
          op={op}
          pair={caption ? { caption, reverse: reverseDisplayName } : undefined}
          className="w-[300px] max-w-[min(300px,calc(100vw-2rem))]"
        />
      </TooltipContent>
    </Tooltip>
  );
}

export { TOOLBOX_META, getShelfMeta };
