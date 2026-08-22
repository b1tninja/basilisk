import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type DragEvent,
  type ReactNode,
} from "react";
import {
  TOOLBOX_META,
  getShelfMeta,
  getStep,
  listDrawerRows,
  listOpCollections,
  pairRowMatches,
  KEY_FORMAT_PICKS,
  KEY_FORMAT_META,
  formatDirectionForTip,
  instantiateFormatPick,
  instantiateCipherPick,
  type StepSpec,
} from "../../lib/toolkit/registry.js";
import { CIPHER_DISPATCH_TARGETS } from "../../lib/toolkit/step-names.js";
import { listTypes, type TypeMeta } from "../../lib/toolkit/type-registry.js";
import type { RecipeParams } from "../../lib/toolkit/recipe.js";
import { toolboxToSuite } from "../../lib/toolkit/suite-gate.js";
import type { SuiteStatusMap } from "../../lib/toolkit/suite-gate.js";
import { TypeCard } from "./TypeCard";
import { cn } from "@/lib/cn";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { useRefusal } from "@/components/ui/refusal";
import { CastDot, Glyph, glyphIdFor } from "./Glyph";
import { NeedCaption, OpsTile, type OpsNeed } from "./OpsTile";
import { STEP_MIME, stepDragPayload } from "./mime";
import type { ToolCardOp } from "./ToolCard";

export type OpsShelfOp = ToolCardOp;

export type OpsShelfTip = {
  base?: string;
  kind?: string;
  encoding?: string;
} | null;

export type OpsAppendOpts = {
  decode?: boolean;
  /** A step's params, as the parser defines them — scalars, not arbitrary values. */
  params?: RecipeParams;
};

type Props = {
  ops: OpsShelfOp[];
  filter: string;
  onFilter: (q: string) => void;
  onAppend: (name: string, opts?: OpsAppendOpts) => void;
  /** Tip-fit step names (others dim when set). */
  tipFit?: Set<string> | null;
  /** Current pipeline tip (Formats kit direction). */
  tip?: OpsShelfTip;
  className?: string;
  /** Hide outer aside chrome (for embedding in legacy drawer host). */
  bare?: boolean;
  /** Use an external search field (legacy #ops-filter). */
  hideSearch?: boolean;
  /** Caret banner — where the next append/insert lands, named so it agrees with the pipeline gap. */
  caretBanner?: ReactNode;
  /** Suite self-test map (CAST). Lights the status dot on each toolbox header. */
  castStatus?: SuiteStatusMap | null;
  /** Append a literal step built from the Types tab's constructor. */
  onInsertLiteral?: (step: { name: string; params: RecipeParams }) => void;
};

function asStep(op: OpsShelfOp): StepSpec {
  return op as unknown as StepSpec;
}

/**
 * Footer kit bar entries (§20a) — the single entry point for kit-only ops.
 * "Base" is this registry's fourth kit (base64/hex… are kitOnly members of
 * the encoding collection); the design's three-button mock reflects its
 * fictional registry, the decision — footer as sole kit entry — is what binds.
 */
export type KitId = "ciphers" | "base" | "formats" | "hmac";
const KIT_DEFS: ReadonlyArray<{ id: KitId; label: string }> = [
  { id: "ciphers", label: "AES / RSA" },
  { id: "base", label: "Base" },
  { id: "formats", label: "Formats" },
  { id: "hmac", label: "HMAC" },
];

/**
 * The search field's accelerator, spelled for the machine it is on.
 *
 * The badge in the field read "⌘K" everywhere and nothing listened for it —
 * a keyboard hint that is both wrong about the key and attached to no
 * behaviour, on Windows and Linux where ⌘ is not a key at all. The design's
 * full command palette (turn 40b) is a larger piece of work; the honest
 * minimum is that the badge sitting inside the search field focuses the
 * search field.
 */
const searchAccel =
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || "")
    ? "⌘K"
    : "Ctrl K";

/**
 * How an op that doesn't fit the caret is de-emphasised.
 *
 * It used to be `opacity-[.32]` on the whole row, which took the name to
 * 1.97:1 against the shelf and the "needs bytes" caption under it to 1.59:1
 * — measured in the production build, light theme. That caption is the one
 * piece of text explaining *why* the op is unavailable, so the thing a
 * confused user most needs to read was the least readable thing on screen.
 *
 * Stepping the name down from `--foreground` to `--muted-foreground` is a
 * bigger perceptual drop than the opacity was (13:1 to 4.6:1) and stays above
 * the 4.5:1 floor, and it leaves the caption alone instead of multiplying
 * into it. Opacity survives only on the glyph, which carries no text.
 *
 * Literal class strings — Tailwind's scanner reads source text, so these must
 * never be assembled at runtime.
 */
const OPS_DIM_TEXT = "text-[var(--muted-foreground)]";

/**
 * Plain-language reason a dimmed op doesn't fit the current caret tip, and
 * the type those words name.
 *
 * The type rides along so the caption can draw its mark — see `OpsNeed`. It
 * is `step.input` and nothing else, so the pictogram and the words come from
 * one source and a row can never print one type and draw another.
 *
 * **`any` is not a type, and this is where that stopped being said out loud.**
 * Nine rows on the default page — `text`, `out`, `publish`, `select`,
 * `inspect`, `tee`, `peek`, `clipboard.write`, `file.save` — declare
 * `input: "any"`, and on an empty notebook every one of them printed `needs
 * any`. That names a constraint none of them has: `any` is the *absence* of
 * one, it is not in the type registry's own list of twenty-three, and the
 * only reason those rows are refused is that the caret is holding nothing
 * for them to take. So they say that instead, and they carry no glyph,
 * because a pictogram for "anything" would have to look like something.
 *
 * The other `any` case is `tee` inside a `foreach` body, which is refused by
 * a nesting rule rather than by the caret's type — `tipFitFor` drops it, and
 * this function is not told. It gets the caret-shaped sentence too, which is
 * why that branch says only that the row does not fit here: it is the one
 * claim true in both, and it promises no remedy the reader cannot perform.
 *
 * @param tip What the caret is holding — the same value the fit filter is built from.
 */
function needsFor(
  step: { input?: string } | null | undefined,
  tip?: OpsShelfTip
): OpsNeed {
  const input = step?.input;
  if (!input || input === "none") return { text: "needs input" };
  if (input === "any") {
    const empty = !tip?.base || tip.base === "none";
    return { text: empty ? "needs a value" : "does not fit here" };
  }
  return { text: `needs ${input}`, type: input };
}

/**
 * Which CAST suite qualifies a toolbox's ops — the suite, never the module.
 *
 * The owner asked to see a module validated before using its tools, and the
 * honest answer is that modules are not what CAST validates. Three suites
 * cover fourteen toolboxes: `ssh` maps to **webcrypto**, because SSH's maths
 * is SubtleCrypto and @noble and that is what the self-test exercises, while
 * `age`, `jose`, `otp`, `file`, `io`, `encoding` and the rest map to nothing
 * at all. A header that printed the module would have said "SSH" and left a
 * reader to assume an SSH self-test exists.
 *
 * **The null case is the whole point and is printed, not hidden.** `CastDot`
 * renders nothing for a toolbox with no suite, which is right for a *status*
 * light — there is no status — but it means the absence of a CAST claim and
 * the absence of a rendered dot look identical, and "no self-test covers
 * these ops" is exactly the fact a reader weighing a toolbox needs. So this
 * says it in words.
 *
 * Static, and deliberately not wired to `suiteStatus`: which suite qualifies
 * an op is a fact about the registry and true before the page boots, while
 * whether that suite is currently green is live state the dot beside this
 * already carries. Two channels, one fact each.
 */
function suiteChipText(toolbox: string): string {
  const suite = toolboxToSuite(toolbox);
  return suite ? `CAST ${suite}` : "no CAST suite";
}

/**
 * The chip itself.
 *
 * A `span` of plain text, so it lands in the header button's accessible name
 * as content rather than being announced through a `role="img"` label that
 * would replace the words a sighted reader has. `CAST openpgp` under a header
 * reading "OpenPGP" repeats a word, and that is the honest cost of a uniform
 * rule: two of the fourteen toolboxes share their name with the suite that
 * qualifies them, and dropping the chip on those two is what would make
 * `SSH — CAST webcrypto` look like a special case instead of the fact.
 *
 * Literal class strings, no inline style: `style-src 'self'` refuses a style
 * attribute in production, and Tailwind's scanner reads source text.
 */
function SuiteChip({ toolbox }: { toolbox: string }) {
  const suite = toolboxToSuite(toolbox);
  return (
    <span
      data-suite-chip={suite || "none"}
      /* Lower case, not the header label's `uppercase`: `openpgp`,
         `webcrypto` and `sss` are the ids `suite-gate.js` returns, and this
         panel's rule is that a token it prints is the token you can type —
         `WEBCRYPTO` is not one. */
      className={cn(
        "shrink-0 rounded-[3px] px-1 py-px font-mono text-[8.5px] font-semibold",
        suite
          ? "bg-[color-mix(in_srgb,var(--brand)_12%,transparent)] text-[var(--muted-foreground)]"
          : "border border-dashed border-[color-mix(in_srgb,var(--muted-foreground)_35%,transparent)] text-[var(--muted-foreground)]"
      )}
    >
      {suiteChipText(toolbox)}
    </span>
  );
}

/** Reverse-direction input for a pair row — conjugate's own input, or the twin's decode io (§20c). */
function pairReverseInput(
  forward: OpsShelfOp,
  reverse: OpsShelfOp | null | undefined
): { input?: string } {
  if (reverse && !forward.decodeTwin) return { input: reverse.input };
  try {
    const io = forward.effectiveIo?.({ decode: true });
    if (io?.input) return { input: io.input };
  } catch {
    /* fall through */
  }
  return { input: forward.output };
}

/** One toolbox item — glyph, name, and a right-aligned action (arrows / add / disabled reason). */
function OpsRow({
  op,
  name,
  hint,
  dim,
  action,
  className,
}: {
  op: { toolbox?: string };
  name: string;
  hint?: OpsNeed;
  dim?: boolean;
  /**
   * A function of the hint's id, because on a row that doesn't fit the caret
   * the hint *is* the action's refusal — right-aligned, already on screen, in
   * the same words. The control describes itself with it instead of hiding the
   * sentence in a `title` on a 22-pixel square, which is what it did.
   */
  action: (hintId: string | undefined) => ReactNode;
  className?: string;
}) {
  const hintId = useId();
  return (
    <div
      /*
       * The solo row wraps, for the reason 3ef6526 made the pair row wrap.
       *
       * That commit measured the conjugate rows and left these alone, and
       * they were already losing text: at the panel's 160px minimum, eleven
       * of them — `clipboard.write` wants 95px of a 77px column,
       * `recipients.merge` 101 — printed a shortened op name with *no caret
       * active at all*, because `min-w-0 truncate` will spend characters
       * before it will spend a line. A row reading `recipients.mer…` names a
       * step you cannot type, which is the thing this repo does not do to a
       * fingerprint and should not do to an op.
       *
       * Adding the type's mark to the caption made it worse rather than
       * caused it, so the fix is the one already in the file: the caption and
       * the `+` are one box that moves to a second line together, and the
       * name is `shrink-0` so it can never be the thing that gives way.
       *
       * It is bought with height and the price is measured. On the default
       * page — a caret is active, so the captions are live — the committed
       * shelf clipped **8** of these names at 220px and **36** at 160, with
       * `agent.save` rendering into zero pixels and `foreach` into six. None
       * clips now; 13 rows take a second line at 220 and 39 at 160, and the
       * whole tree is 8% taller at 220 and 26% at 160. Thirty-six names for a
       * quarter of the scroll at the width someone chose deliberately.
       *
       * `gap-x-1.5` rather than the `gap-2` every other row here uses: two
       * pixels either side of the name is what four of those rows at 220 were
       * short by, and a 6px channel between a glyph and the word it labels is
       * the same channel `NeedCaption` uses inside itself.
       */
      className={cn(
        "flex flex-wrap items-center justify-end gap-x-1.5 gap-y-1 rounded-md px-1.5 py-[3px] hover:bg-[color-mix(in_srgb,var(--brand)_5%,transparent)]",
        className
      )}
    >
      {/* Identity is the glyph. Verification is not per-op — it lives on the
          toolbox header, one light per suite. */}
      <Glyph
        id={glyphIdFor(op)}
        size={16}
        className={cn("shrink-0", dim ? "opacity-45" : "opacity-80")}
      />
      <code
        className={cn(
          "grow shrink-0 font-mono text-[11.5px] font-medium",
          dim ? OPS_DIM_TEXT : "text-[var(--foreground)]"
        )}
      >
        {name}
      </code>
      {/* Shrinkable, unlike the name: line breaking asks for this box's
          unwrapped width, so it moves down whole, and once it is down there
          it may still need to give way to the `+` beside it. */}
      <span className="flex min-w-0 items-center gap-1.5">
        {hint ? (
          <NeedCaption
            id={hintId}
            need={hint}
            className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]"
          />
        ) : null}
        {action(hint ? hintId : undefined)}
      </span>
    </div>
  );
}

/**
 * The action for an op with no direction.
 *
 * Deliberately the same 22×20 square as the direction handles on a pair row.
 * It used to be a wider pill reading "add", so a list mixing solo and
 * conjugate ops presented two different-looking controls for the same
 * gesture — insert this op — and the word implied the arrows did something
 * else. One shape, one meaning; the glyph says which direction when there is
 * a choice to make.
 */
function AddButton({
  onClick,
  name,
  description,
  dragName,
  disabledReason,
  reasonId,
}: {
  onClick: () => void;
  /**
   * What this button adds, in the words printed beside it.
   *
   * The accessible name is built from this and nothing else. It used to be
   * built from `title`, which every solo row filled with the op's registry
   * doc — so a glyph-only `+` announced a 245-character paragraph about
   * WebCrypto curves that never once said the word `genkey`. Measured on the
   * shipped bundle at 1440×900: 38 of the shelf's 75 add buttons named
   * themselves with over 100 characters of prose, 29 of them with over 200,
   * the longest 1039. A control whose name does not name the control is
   * 07d4eea's defect wearing different clothes.
   */
  name?: string;
  /**
   * Prose about it — the registry doc, or the refusal's own sentence. Stays
   * in `title`, which is both the hover tooltip a pointer already relies on
   * (a solo row has no ToolCard behind it, unlike a pair) and, now that
   * `aria-label` supplies the name, the accessible *description*: announced
   * after the name rather than instead of it.
   */
  description?: string;
  /**
   * Step name to put on the drag payload. Omitted only where there is no
   * single step to drag (the HMAC kit's sugar rows).
   */
  dragName?: string;
  /**
   * Doesn't fit the caret — refuses both gestures, and says which type the
   * caret is holding. It was `disabled: boolean` with the sentence passed
   * separately as `title`, which is the arrangement that let a row go dead
   * with its explanation reachable only by hovering a 22×20 square.
   */
  disabledReason?: string;
  /** The row's own caption, where it is already printing this sentence. */
  reasonId?: string;
}) {
  const refusal = useRefusal(disabledReason, { reasonId });
  // Name first, the way the pair rows say `base64 — encode`: one vocabulary
  // across the two kinds of row in one shelf, and the word you are hunting
  // for arrives before the phrase you already know.
  const label = name ? `${name} — add to the recipe` : "Add to the recipe";
  return (
    <button
      type="button"
      title={description || label}
      aria-label={label}
      {...refusal.aria}
      draggable={!refusal.refused && !!dragName}
      onClick={refusal.guard(onClick)}
      onDragStart={
        !refusal.refused && dragName
          ? (e: DragEvent<HTMLButtonElement>) => {
              e.dataTransfer.setData(STEP_MIME, stepDragPayload(dragName, false));
              e.dataTransfer.setData("text/plain", dragName);
              e.dataTransfer.effectAllowed = "copy";
            }
          : undefined
      }
      className={cn(
        "flex h-5 w-[22px] shrink-0 items-center justify-center rounded-[4px] border text-[12px] font-bold leading-none transition-colors",
        refusal.refused
          ? "cursor-not-allowed border-dashed border-[var(--border)] bg-transparent text-[color-mix(in_srgb,var(--muted-foreground)_55%,transparent)]"
          : "cursor-grab border-[var(--border)] bg-[var(--surface-raised)] text-[var(--muted-foreground)] hover:border-[var(--brand)] hover:text-[var(--brand)] active:cursor-grabbing"
      )}
    >
      +
    </button>
  );
}

/**
 * Section header — chevron, label, CAST light, item count (design v2 §18b/19a).
 *
 * There used to be a second 6px mark out at the right margin carrying the
 * toolbox's identity colour. On the WebCrypto and OpenPGP headers that put a
 * 6px green circle (`--success`, "self-test passed") and a 6px green rounded
 * square (`#4cde82`, "this is the WebCrypto toolbox") in the same 26px row —
 * the exact conflation ee81d62 set out to remove, relocated rather than
 * resolved. Identity is already stated twice on this header, once in words
 * and once per row in the op glyphs, so the colour square was the redundant
 * one. What remains is the single bit you cannot read from the text.
 */
function SectionHeader({
  label,
  count,
  fitCount,
  toolbox,
  castStatus,
  open,
  onToggle,
}: {
  label: string;
  count: number;
  /** Ops in this toolbox that fit the caret tip — set only while tipFit is active (§19a). */
  fitCount?: number | null;
  /** Toolbox id — decides whether this suite makes a CAST claim at all. */
  toolbox: string;
  /** Suite self-test map; absent while the POST is still running. */
  castStatus?: SuiteStatusMap | null;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-expanded={open}
      /* Not dimmed at zero fit any more. This is a live button and the only
         way back into a collapsed toolbox; `opacity-40` took its label to
         1.82:1. The count already reads "0 fit", which is the fact.

         `flex-wrap`, because the suite chip is 50–66px of a 143px line at the
         panel's 160px minimum and "Input / output" is 88 of it. The chip drops
         to a second line there rather than pushing the count off the edge —
         the same answer the pair row gives, and it costs no breakpoint. */
      className="flex w-full flex-wrap items-center gap-x-1.5 gap-y-0.5 px-1 py-[5px] text-left"
    >
      <span className="text-[8px] text-[var(--muted-foreground)]" aria-hidden>
        {open ? "▾" : "▸"}
      </span>
      <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
        {label}
      </span>
      {/* CAST belongs here rather than on each op: the self-test qualifies a
          suite, so one light per toolbox states the fact once instead of
          repeating it down twenty identical rows.

          The dot and the chip beside it are the two halves of one question.
          The dot says whether the suite is green *this session*; the chip says
          which suite that is, and — where there is none — that nothing
          self-tests these ops, which is the half the dot cannot say because
          it renders nothing at all in that case. */}
      <CastDot op={{ toolbox }} status={castStatus} />
      <SuiteChip toolbox={toolbox} />
      <span className="font-mono text-[10px] text-[var(--muted-foreground)]">
        {fitCount == null ? count : `${fitCount} fit`}
      </span>
    </button>
  );
}

/** Searchable toolbox → shelf → row list (+ collection / Formats / HMAC kits). */
export function OpsShelf({
  ops,
  filter,
  onFilter,
  onAppend,
  tipFit: tipFitProp = null,
  tip = null,
  className,
  bare = false,
  hideSearch = false,
  caretBanner = null,
  castStatus = null,
  onInsertLiteral,
}: Props) {
  /**
   * Ops and types are peers, not a filter over one another — a type is not an
   * op, so it cannot live in the footer kit bar (which filters the op tree).
   */
  const [mode, setMode] = useState<"ops" | "types">("ops");
  const [openType, setOpenType] = useState<string | null>(null);
  const [kitOpen, setKitOpen] = useState<Record<string, boolean>>({
    aes: true,
    rsa: true,
    encoding: true,
  });
  const [formatOpen, setFormatOpen] = useState<"export" | "import" | null>(null);
  const [tbOverride, setTbOverride] = useState<Record<string, boolean>>({});
  /** §20a — footer kit bar is the one kit entry point; null = browse tree. */
  const [kitFilter, setKitFilter] = useState<KitId | null>(null);
  /**
   * §20b — "Show all N" suspends fit dimming for the current caret only.
   * Local state; resets whenever the caret's fit set changes identity, so it
   * can never leak into the next gap's session.
   */
  const [showAll, setShowAll] = useState(false);
  /**
   * The heading the panel is named by, when it draws one.
   *
   * `bare` embeds the shelf in a host that owns the chrome, and `hideSearch`
   * takes the block the name lives in with it; in either case there is no
   * heading to point at and the landmark goes unnamed rather than being given
   * a second name nobody can see.
   */
  const headingId = useId();
  const namesItself = !bare && !hideSearch;
  useEffect(() => {
    setShowAll(false);
  }, [tipFitProp]);
  const tipFit = showAll ? null : tipFitProp;

  /**
   * Make the accelerator real. Bound at the window because the point of the
   * shortcut is reaching the field from anywhere in the shell; the field's
   * own handler would only work once you were already in it.
   */
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (hideSearch) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "k" && e.key !== "K") return;
      if (!e.metaKey && !e.ctrlKey) return;
      if (e.altKey || e.shiftKey) return;
      const el = searchRef.current;
      if (!el) return;
      e.preventDefault();
      el.focus();
      el.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [hideSearch]);

  const grouped = useMemo(() => {
    const q = filter.trim().toLowerCase();
    // `pairRowMatches` is why the row survives a query that only names its
    // reverse half — see its comment in the registry. This is the second of
    // the two places the shelf's op list is cut by the same query.
    const hit = (op: { name: string; doc?: string; label?: string }) =>
      op.name.toLowerCase().includes(q) ||
      (op.doc || "").toLowerCase().includes(q) ||
      (op.label || "").toLowerCase().includes(q);
    const filtered = q ? ops.filter((op) => pairRowMatches(asStep(op), hit)) : ops;

    const byTb = new Map<string, OpsShelfOp[]>();
    for (const op of filtered) {
      if (op.kitOnly) continue;
      const tb = op.toolbox || "io";
      if (!byTb.has(tb)) byTb.set(tb, []);
      byTb.get(tb)!.push(op);
    }
    return [...byTb.entries()]
      .sort(
        (a, b) =>
          ((TOOLBOX_META as Record<string, { order?: number }>)[a[0]]?.order ?? 9) -
          ((TOOLBOX_META as Record<string, { order?: number }>)[b[0]]?.order ?? 9)
      )
      .map(([tb, items]) => {
        const byShelf = new Map<string, OpsShelfOp[]>();
        for (const op of items) {
          const shelf = op.shelf || "_";
          if (!byShelf.has(shelf)) byShelf.set(shelf, []);
          byShelf.get(shelf)!.push(op);
        }
        const shelves = [...byShelf.entries()].sort(
          (a, b) => getShelfMeta(a[0]).order - getShelfMeta(b[0]).order
        );
        return {
          tb,
          count: items.length,
          items,
          shelves: shelves.map(([shelf, shelfItems]) => ({
            shelf,
            rows: listDrawerRows(shelfItems.map(asStep)),
          })),
        };
      });
  }, [ops, filter]);

  const q = filter.trim().toLowerCase();
  // "AES / RSA" = webcrypto cipher collections; "Base" = the encoding
  // collection (its members — base64, hex… — are kitOnly, so this footer
  // button is their only entry point).
  const allCollections = listOpCollections();
  const kitCollections: Record<"ciphers" | "base", typeof allCollections> = {
    ciphers: allCollections.filter((c) => c.toolbox === "webcrypto"),
    base: allCollections.filter((c) => c.toolbox === "encoding"),
  };
  const collections =
    kitFilter === "base" ? kitCollections.base : kitCollections.ciphers;

  const impliedFormat = formatDirectionForTip(tip || undefined);
  const formatDirection = formatOpen || impliedFormat;

  const kitCounts: Record<KitId, number> = {
    ciphers: kitCollections.ciphers.reduce((n, c) => n + c.members.length, 0),
    base: kitCollections.base.reduce((n, c) => n + c.members.length, 0),
    formats: KEY_FORMAT_PICKS.length * 2,
    hmac: 2,
  };
  const activeKit = KIT_DEFS.find((k) => k.id === kitFilter) || null;

  // §21c — when a browse-mode query matches nothing, suggest whichever kit
  // (footer-only, kitOnly ops) does match, instead of a bare "no results".
  const kitSearchTerms: Record<KitId, string[]> = {
    ciphers: kitCollections.ciphers.flatMap((c) => [
      c.label.toLowerCase(),
      ...c.members.map((m) => m.name.toLowerCase()),
    ]),
    base: kitCollections.base.flatMap((c) => [
      c.label.toLowerCase(),
      ...c.members.map((m) => m.name.toLowerCase()),
    ]),
    formats: ["format", "export", "import", ...KEY_FORMAT_PICKS],
    hmac: ["hmac", "mac", "sign", "verify"],
  };
  const suggestedKit =
    q && !kitFilter
      ? KIT_DEFS.find((k) => kitSearchTerms[k.id].some((t) => t.includes(q) || q.includes(t))) ||
        null
      : null;

  const appendCollectionMember = (name: string, decode: boolean) => {
    if (CIPHER_DISPATCH_TARGETS.has(name)) {
      try {
        const pick = instantiateCipherPick(name, decode);
        onAppend(pick.name, {
          decode: !!pick.params.decode,
          params: pick.params,
        });
      } catch {
        /* ignore */
      }
      return;
    }
    onAppend(name, { decode });
  };

  const shownTypes = useMemo<TypeMeta[]>(() => {
    const q = filter.trim().toLowerCase();
    const all = listTypes();
    if (!q) return all;
    return all.filter(
      (t) =>
        t.base.toLowerCase().includes(q) ||
        t.label.toLowerCase().includes(q) ||
        t.summary.toLowerCase().includes(q)
    );
  }, [filter]);

  const body = (
    <>
      {!hideSearch ? (
        <div className={cn("border-b border-[var(--border)] px-2.5 py-2", bare && "px-0")}>
          {!bare ? (
            /* The shelf already printed its own name here; it was a `<p>`, so
               the page's outline had nothing in it and the `<aside>` around it
               was an unnamed landmark. Same six pixels of type, now a heading
               — the box is declared in toolkit.css because site.css sizes h2
               for a document and its element rule is unlayered, which beats
               any utility class regardless of specificity. */
            <h2 id={headingId} className="ops-shelf-heading">
              Toolkit
            </h2>
          ) : null}
          <div
            role="tablist"
            aria-label="Browse operations or types"
            className="mb-2 flex gap-1 rounded-[6px] bg-[var(--surface-raised)] p-[2px]"
          >
            {(["ops", "types"] as const).map((m) => (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={mode === m}
                className={cn(
                  "flex-1 rounded-[4px] px-2 py-[3px] text-[10.5px] font-semibold capitalize transition-colors",
                  mode === m
                    ? "bg-[var(--surface)] text-[var(--foreground)] shadow-sm"
                    : "text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                )}
                onClick={() => setMode(m)}
              >
                {m}
              </button>
            ))}
          </div>
          {activeKit ? (
            <button
              type="button"
              className="mb-2 flex w-fit items-center gap-1.5 rounded-full border border-[color-mix(in_srgb,var(--brand)_35%,transparent)] bg-[color-mix(in_srgb,var(--brand)_10%,transparent)] px-2 py-[3px] text-[10px] font-medium text-[var(--brand)]"
              onClick={() => setKitFilter(null)}
              aria-label={`Clear ${activeKit.label} filter`}
            >
              {activeKit.label}
              <span className="text-[9px]" aria-hidden>
                ✕
              </span>
            </button>
          ) : null}
          <div className="relative flex items-center">
            <span
              className="pointer-events-none absolute left-[9px] text-[11px] text-[var(--muted-foreground)]"
              aria-hidden
            >
              ⌕
            </span>
            <Input
              ref={searchRef}
              className="h-[30px] rounded-[6px] pl-[26px] pr-[36px] text-[11.5px]"
              placeholder={
                mode === "types"
                  ? `Search ${listTypes().length} types`
                  : `Search ${activeKit ? kitCounts[activeKit.id] : ops.length} operations`
              }
              value={filter}
              onChange={(e) => onFilter(e.target.value)}
              aria-label={`Search toolkit (${searchAccel})`}
            />
            <span
              className="pointer-events-none absolute right-[7px] rounded-[3px] bg-[var(--surface-raised)] px-[4px] py-[1px] font-mono text-[9px] font-semibold text-[var(--muted-foreground)]"
              aria-hidden
            >
              {searchAccel}
            </span>
          </div>
        </div>
      ) : null}
      {/*
        One band, not two. The caret banner and the show-all control each drew
        their own bottom border, caret-blue left rule and 6%-caret wash, so
        where the caret is and what the shelf is filtered to — one fact and
        its escape hatch — read as two unrelated announcements stacked on top
        of each other. They share a container now; the divider between them is
        a hairline inside it.
      */}
      {caretBanner || tipFitProp ? (
        <div className="border-b border-l-2 border-[var(--border)] border-l-[var(--caret)] bg-[color-mix(in_srgb,var(--caret)_6%,transparent)]">
          {caretBanner}
          {tipFitProp ? (
            <div
              className={cn(
                "px-2.5 py-1.5 text-[length:10.5px] text-[var(--muted-foreground)]",
                caretBanner && "border-t border-[color-mix(in_srgb,var(--caret)_18%,transparent)]"
              )}
            >
              {showAll ? (
                <>
                  Showing{" "}
                  <strong className="text-[var(--foreground)]">
                    all {ops.length} operations
                  </strong>
                  .{" "}
                  <button
                    type="button"
                    className="text-[var(--caret)] underline"
                    onClick={() => setShowAll(false)}
                  >
                    Fit to {tip?.base || "tip"} only
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className="text-[var(--caret)] underline"
                  onClick={() => setShowAll(true)}
                >
                  Show all {ops.length}
                </button>
              )}
            </div>
          ) : null}
        </div>
      ) : null}
      <ScrollArea className={cn("min-h-0 flex-1 px-2 py-1.5", bare && "px-0")}>
        {mode === "types" ? (
          <div className="flex flex-col gap-1 pb-4">
            {shownTypes.map((t) => {
              const open = openType === t.base;
              return (
                <div key={t.base}>
                  <button
                    type="button"
                    aria-expanded={open}
                    data-type-row={t.base}
                    className={cn(
                      "flex w-full flex-col items-start gap-0.5 rounded-[6px] border px-2 py-1.5 text-left transition-colors",
                      open
                        ? "border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_8%,transparent)]"
                        : "border-transparent hover:border-[var(--border)] hover:bg-[var(--surface-raised)]"
                    )}
                    onClick={() => setOpenType(open ? null : t.base)}
                  >
                    <span className="flex w-full items-center gap-1.5">
                      <code className="font-mono text-[11.5px] font-bold text-[var(--foreground)]">
                        {t.label}
                      </code>
                      {t.literal ? (
                        <span
                          className="rounded-[4px] bg-[color-mix(in_srgb,var(--brand)_16%,transparent)] px-1 py-px text-[9px] font-semibold text-[var(--brand)]"
                          title="Can be written directly as a literal"
                        >
                          literal
                        </span>
                      ) : null}
                      <span className="ml-auto text-[10px] text-[var(--muted-foreground)]" aria-hidden>
                        {open ? "▾" : "▸"}
                      </span>
                    </span>
                    <span className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
                      {t.summary}
                    </span>
                  </button>
                  {open ? (
                    <TypeCard
                      meta={t}
                      className="mt-1"
                      /* Default to the ordinary append path — the same route
                         format/cipher picks take — so a literal lands at the
                         caret with the same insert semantics as any op. */
                      onInsertLiteral={
                        onInsertLiteral ||
                        ((step) => onAppend(step.name, { params: step.params }))
                      }
                      onPickOp={(name) => onAppend(name)}
                    />
                  ) : null}
                </div>
              );
            })}
            {!shownTypes.length ? (
              <p className="px-2 py-3 text-[11px] italic text-[var(--muted-foreground)]">
                No types match “{filter.trim()}”.
              </p>
            ) : null}
          </div>
        ) : kitFilter === "ciphers" || kitFilter === "base" ? (
          <div className="flex flex-col pb-4">
            {collections.map((col) => {
              const members = q
                ? col.members.filter((m) => m.name.toLowerCase().includes(q))
                : col.members;
              if (!members.length) return null;
              return (
                <ModeShelfKit
                  key={`${col.id}-kit`}
                  dataShelf={col.id}
                  title={col.label}
                  toolbox={col.toolbox}
                  modes={members}
                  tip={tip}
                  tipFit={tipFit}
                  expanded={kitOpen[col.id] !== false}
                  onToggleExpand={() =>
                    setKitOpen((prev) => ({
                      ...prev,
                      [col.id]: !(prev[col.id] !== false),
                    }))
                  }
                  onPick={appendCollectionMember}
                />
              );
            })}
          </div>
        ) : kitFilter === "formats" ? (
          <div className="flex flex-col pb-4">
            <FormatKit
              tip={tip}
              direction={formatDirection}
              open={formatOpen}
              toolbox="webcrypto"
              onToggle={(dir) =>
                setFormatOpen((prev) => (prev === dir ? null : dir))
              }
              onPick={(fmt) => {
                const dir = formatOpen || impliedFormat || "export";
                try {
                  const pick = instantiateFormatPick(dir, fmt);
                  setFormatOpen(null);
                  onAppend(pick.name, { params: pick.params });
                } catch {
                  /* ignore */
                }
              }}
            />
          </div>
        ) : kitFilter === "hmac" ? (
          <div className="flex flex-col pb-4">
            <MacKit onAppend={onAppend} />
          </div>
        ) : (
        <div className="flex flex-col pb-4">
          {grouped.map(({ tb, count, items, shelves }) => {
            const meta = (TOOLBOX_META as Record<string, { label?: string; color?: string }>)[
              tb
            ] || { label: tb };
            const fitCount = tipFit
              ? items.filter((op) => tipFit.has(op.name)).length
              : null;
            const hasFit = fitCount == null || fitCount > 0;
            const open = tbOverride[tb] ?? hasFit;
            return (
              <div key={tb} className="ops-category" data-toolbox={tb}>
                <SectionHeader
                  label={meta.label || tb}
                  count={count}
                  fitCount={fitCount}
                  toolbox={tb}
                  castStatus={castStatus}
                  open={open}
                  onToggle={() =>
                    setTbOverride((prev) => ({ ...prev, [tb]: !open }))
                  }
                />
                {!open ? null : (
                  <div className="ops-icon-grid flex flex-col gap-0.5 pb-2 pl-1">
                    {/* §20a: kit blocks no longer render inline — the footer bar is the kit entry point. */}
                    {shelves.map(({ shelf, rows }) => {
                      if (!rows.length) return null;
                      const shelfLabel = getShelfMeta(shelf).label;
                      return (
                          <div key={`${tb}:${shelf}`} data-shelf={shelf}>
                            {shelfLabel && shelves.length > 1 ? (
                              <p className="mt-1 px-1.5 pb-0.5 text-[9px] font-bold uppercase tracking-wider text-[color-mix(in_srgb,var(--muted-foreground)_70%,transparent)]">
                                {shelfLabel}
                              </p>
                            ) : null}
                            {rows.map((row, i) => {
                              if (row.type === "solo" && row.step) {
                                const fit = !tipFit || tipFit.has(row.step.name);
                                const unfit = !!tipFit && !fit;
                                return (
                                  <OpsRow
                                    key={`${row.step.name}-${i}`}
                                    op={row.step}
                                    name={row.step.name}
                                    dim={unfit}
                                    hint={unfit ? needsFor(row.step, tip) : undefined}
                                    /* The control stays put when the op
                                       doesn't fit, disabled and saying why.
                                       Removing it made rows jump sideways as
                                       the caret moved, and left the row with
                                       no explanation of its own state. */
                                    action={(why) => (
                                      <AddButton
                                        disabledReason={
                                          unfit
                                            ? `${row.step!.name} ${needsFor(row.step!, tip).text} — the caret is holding something else. Move the caret, or pick a row that fits.`
                                            : undefined
                                        }
                                        reasonId={why}
                                        dragName={row.step!.name}
                                        name={row.step!.name}
                                        description={
                                          unfit
                                            ? `${row.step!.name} ${needsFor(row.step!, tip).text}`
                                            : row.step!.doc
                                        }
                                        onClick={() => onAppend(row.step!.name)}
                                      />
                                    )}
                                  />
                                );
                              }
                              if (row.type !== "pair" || !row.forward) return null;
                              const key = row.forward.name + (row.reverse?.name || "-d");
                              const fitFwd = !tipFit || tipFit.has(row.forward.name);
                              const revName = row.reverse?.name || row.forward.name;
                              const fitRev = !tipFit || tipFit.has(revName);
                              return (
                                <OpsTile
                                  key={key}
                                  op={row.forward}
                                  reverseOp={row.reverse}
                                  /* `listDrawerRows` has computed this for
                                     every pair row since it was written and
                                     nothing read it, so the row was named by
                                     whichever of its two ops the registry
                                     happened to list first. */
                                  caption={row.caption}
                                  hasReverse={!!(row.decodeTwin || row.reverse)}
                                  fit={{ forward: fitFwd, reverse: fitRev }}
                                  needs={
                                    tipFit
                                      ? {
                                          forward: fitFwd
                                            ? undefined
                                            : needsFor(row.forward, tip),
                                          reverse: fitRev
                                            ? undefined
                                            : needsFor(
                                                pairReverseInput(row.forward, row.reverse),
                                                tip
                                              ),
                                        }
                                      : undefined
                                  }
                                  dim={!!tipFit && !fitFwd && !fitRev}
                                  onAppend={onAppend}
                                />
                              );
                            })}
                          </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
          {grouped.length === 0 && suggestedKit ? (
            <button
              type="button"
              className="flex items-center gap-1.5 rounded-[7px] border border-dashed border-[color-mix(in_srgb,var(--brand)_35%,transparent)] bg-[color-mix(in_srgb,var(--brand)_6%,transparent)] px-[9px] py-2 text-left"
              onClick={() => setKitFilter(suggestedKit.id)}
            >
              <span className="text-[11px] text-[var(--muted-foreground)]">
                Not in browse mode. Try the
              </span>
              <span className="text-[11px] font-semibold text-[var(--brand)]">
                {suggestedKit.label}
              </span>
              <span className="text-[11px] text-[var(--muted-foreground)]">kit ▸</span>
            </button>
          ) : null}
        </div>
        )}
      </ScrollArea>
      {/* Kit bar filters the op tree, so it has nothing to act on in Types. */}
      <div
        className={cn(
          "flex gap-1.5 border-t border-[var(--border)] px-2.5 py-2",
          bare && "px-0",
          mode === "types" && "hidden"
        )}
      >
        {KIT_DEFS.map((k) => {
          const active = kitFilter === k.id;
          return (
            <button
              key={k.id}
              type="button"
              aria-pressed={active}
              className={cn(
                "flex-1 rounded-[6px] border px-1 py-[7px] text-[10px] transition-colors",
                active
                  ? "border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] font-semibold text-[var(--brand)]"
                  : "border-[color-mix(in_srgb,var(--border)_60%,transparent)] bg-[var(--surface-raised)] font-medium text-[var(--muted-foreground)] hover:border-[var(--border)]"
              )}
              onClick={() => setKitFilter(active ? null : k.id)}
            >
              {k.label}
            </button>
          );
        })}
      </div>
    </>
  );

  if (bare) {
    return <div className={cn("flex min-h-0 flex-1 flex-col", className)}>{body}</div>;
  }

  return (
    <aside
      aria-labelledby={namesItself ? headingId : undefined}
      className={cn(
        "flex min-h-0 w-[220px] shrink-0 flex-col border-r border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))]",
        className
      )}
    >
      {body}
    </aside>
  );
}

/** Collapsible kit — header row (dot + title + chevron), body of mode rows (dot + name + arrows). */
function ModeShelfKit({
  dataShelf,
  title,
  toolbox,
  modes,
  tip,
  tipFit,
  expanded,
  onToggleExpand,
  onPick,
}: {
  dataShelf: string;
  title: string;
  /** Toolbox id — dot colour enumerated per id in toolkit.css. */
  toolbox: string;
  modes: { id: string; name: string; label: string; title?: string }[];
  /** What the caret is holding — decides how an `any`-input refusal reads. */
  tip?: OpsShelfTip;
  tipFit?: Set<string> | null;
  expanded: boolean;
  onToggleExpand: () => void;
  onPick: (name: string, decode: boolean) => void;
}) {
  return (
    <div data-shelf={dataShelf}>
      <button
        type="button"
        onClick={onToggleExpand}
        aria-expanded={expanded}
        /* Wraps for the same reason the section header does — the chip is
           the last thing on a line that already carries a collection's whole
           label. */
        className="flex w-full flex-wrap items-center gap-x-1.5 gap-y-0.5 rounded-md px-1.5 py-[3px] text-left hover:bg-[color-mix(in_srgb,var(--brand)_5%,transparent)]"
      >
        <span
          className="toolbox-dot h-[5px] w-[5px] shrink-0 rounded-full"
          data-toolbox-dot={toolbox}
          aria-hidden
        />
        <span className="min-w-0 grow truncate font-mono text-[11.5px] font-medium text-[var(--foreground)]">
          {title}
        </span>
        {/* The kits are reached from the footer bar and never show a section
            header, so without this the `Base` kit — every `encoding` op in the
            registry, and the one place a reader is most likely to assume a
            self-test — would be the one surface that says nothing about CAST
            at all. */}
        <SuiteChip toolbox={toolbox} />
        <span className="shrink-0 text-[9px] text-[var(--muted-foreground)]" aria-hidden>
          {expanded ? "▾" : "▸"}
        </span>
      </button>
      {expanded ? (
        <div className="pl-3">
          {modes.map((m) => {
            const step = getStep(m.name);
            if (!step) return null;
            const fit = !tipFit || tipFit.has(m.name);
            return (
              <OpsTile
                key={m.id}
                op={step}
                hasReverse
                fit={{ forward: fit, reverse: fit }}
                needs={
                  tipFit && !fit
                    ? {
                        forward: needsFor(step, tip),
                        reverse: needsFor(pairReverseInput(step, null), tip),
                      }
                    : undefined
                }
                dim={!!tipFit && !fit}
                onAppend={(name, opts) => onPick(name, !!opts?.decode)}
              />
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function FormatKit({
  tip,
  direction,
  open,
  toolbox,
  onToggle,
  onPick,
}: {
  tip: OpsShelfTip;
  direction: "export" | "import" | null;
  open: "export" | "import" | null;
  /** Toolbox id — dot colour enumerated per id in toolkit.css. */
  toolbox: string;
  onToggle: (dir: "export" | "import") => void;
  onPick: (fmt: string) => void;
}) {
  const showPicks = !!direction;
  return (
    <div data-format-kit>
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 px-1.5 py-[3px]">
        <span
          className="toolbox-dot h-[5px] w-[5px] shrink-0 rounded-full"
          data-toolbox-dot={toolbox}
          aria-hidden
        />
        <span className="grow font-mono text-[11.5px] font-semibold text-[var(--foreground)]">
          Key formats
        </span>
        {/* Every pick under this header is a `webcrypto` op, so the kit makes
            one CAST claim and says it once. */}
        <SuiteChip toolbox={toolbox} />
        <div className="flex shrink-0 gap-1">
          <button
            type="button"
            title="Export — choose PKCS#8, SPKI, JWK, raw, or scalar"
            aria-pressed={open === "export"}
            onClick={() => onToggle("export")}
            className={cn(
              "h-5 rounded-[4px] border px-[7px] text-[10px] font-bold transition-colors",
              open === "export"
                ? "border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] text-[var(--brand)]"
                : "border-[var(--border)] bg-[var(--surface-raised)] text-[var(--muted-foreground)] hover:border-[var(--brand)]"
            )}
          >
            Export
          </button>
          <button
            type="button"
            title="Import — choose PKCS#8, SPKI, JWK, raw, or scalar"
            aria-pressed={open === "import"}
            onClick={() => onToggle("import")}
            className={cn(
              "h-5 rounded-[4px] border px-[7px] text-[10px] font-bold transition-colors",
              open === "import"
                ? "border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] text-[var(--brand)]"
                : "border-[var(--border)] bg-[var(--surface-raised)] text-[var(--muted-foreground)] hover:border-[var(--brand)]"
            )}
          >
            Import
          </button>
        </div>
      </div>
      {showPicks ? (
        <div className="pl-3" role="listbox" aria-label="Choose key format">
          <p className="px-1.5 pb-0.5 text-[9px] font-bold uppercase tracking-wider text-[color-mix(in_srgb,var(--muted-foreground)_70%,transparent)]">
            {direction} — pick a format
          </p>
          {KEY_FORMAT_PICKS.map((fmt) => {
            const meta = KEY_FORMAT_META[fmt] || { label: fmt, title: fmt };
            const fit =
              direction === "export"
                ? tip?.base === "keypair" || tip?.base === "key"
                : tip?.base === "bytes" ||
                  tip?.base === "text" ||
                  tip?.base === "none" ||
                  !tip;
            /* The solo rows print this to the right of the name; these did
               not, so the only thing saying why the + was dead was a `title`.
               Same words, same place, now on both kinds of row.
               The type rides along so these captions wear the same mark the
               tree's do — `export` wants a `key`, `import` wants `bytes`, and
               both are names `KIND_GLYPHS` draws. */
            const needs: OpsNeed =
              direction === "export"
                ? { text: "needs a key", type: "key" }
                : { text: "needs bytes", type: "bytes" };
            const whyId = `key-format-why-${direction}-${fmt}`;
            return (
              <div
                key={fmt}
                /* Wraps, like the tree's rows. Measured on the committed
                   bundle before any of this: at the panel's 160px minimum all
                   five of these names — `PKCS#8`, `SPKI`, `JWK`, `raw`,
                   `scalar` — were rendering into a column of *zero* width
                   while the caption and the `+` beside them kept theirs, so
                   the kit showed five rows of glyph, "needs a key" and a
                   plus, with the format gone. Putting the type's mark in the
                   caption made the row overflow outright, which is how it was
                   found. Same fix as `OpsRow`: name first and unshrinkable,
                   the caption and the button one box that moves down. */
                className="flex flex-wrap items-center justify-end gap-x-1.5 gap-y-1 rounded-md px-1.5 py-[3px] hover:bg-[color-mix(in_srgb,var(--brand)_5%,transparent)]"
              >
                {/* The kit's rows all share one toolbox, so a toolbox-colour
                    bullet here was a constant — the direction glyph is what
                    actually differs between an export and an import row, and
                    it is the same vocabulary the tree uses. */}
                <Glyph
                  id={direction === "import" ? "decode" : "encode"}
                  size={16}
                  className={cn("shrink-0", fit ? "opacity-80" : "opacity-45")}
                />
                <code
                  className={cn(
                    "grow shrink-0 font-mono text-[11.5px] font-medium",
                    fit ? "text-[var(--foreground)]" : OPS_DIM_TEXT
                  )}
                >
                  {meta.label}
                </code>
                <span className="flex min-w-0 items-center gap-1.5">
                {fit ? null : (
                  <NeedCaption
                    id={whyId}
                    need={needs}
                    className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]"
                  />
                )}
                <AddButton
                  disabledReason={
                    fit
                      ? undefined
                      : `${direction} ${meta.label} ${needs.text}, and the caret is holding something else. Move the caret to a step that produces one.`
                  }
                  reasonId={fit ? undefined : whyId}
                  name={`${direction} ${meta.label}`}
                  description={
                    fit
                      ? `${direction}: ${meta.title}`
                      : `${direction} ${meta.label} does not fit here`
                  }
                  onClick={() => onPick(fmt)}
                />
                </span>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="px-1.5 pb-1 text-[10px] text-[var(--muted-foreground)]">
          Choose Export or Import, then a format.
        </p>
      )}
    </div>
  );
}

function MacKit({ onAppend }: { onAppend: Props["onAppend"] }) {
  return (
    <div data-mac-kit>
      <OpsRow
        op={{ toolbox: "webcrypto" }}
        name="hmac"
        action={() => (
          <AddButton
            dragName="sign"
            name="sign"
            description="Insert sign (HMAC keys via genkey hmac/sha256)"
            onClick={() => onAppend("sign")}
          />
        )}
      />
      <OpsRow
        op={{ toolbox: "webcrypto" }}
        name="verify"
        action={() => (
          <AddButton
            dragName="verify"
            name="verify"
            description="Insert verify (recipe sugar: hmac.verify)"
            onClick={() => onAppend("verify")}
          />
        )}
      />
    </div>
  );
}
