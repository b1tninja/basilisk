import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/cn";
import { KindGlyph, badgeFamily, badgeTier } from "./kind-glyphs";
import { ArtifactAction, type ActionTier } from "./ArtifactAction";
import { ConsequenceBanner, type ConsequenceSpec } from "./ConsequenceBanner";
import { actionsFor, gatedRowReason } from "../../lib/toolkit/artifact-actions.js";
import {
  addPrivateKeyToMyKeys,
  vaultAvailable,
} from "../../lib/toolkit/keyring-service.js";
import { downloadArtifactFile } from "../../lib/toolkit/download-service.js";
import { recordActivity } from "../../lib/toolkit/activity-log.js";
import {
  ARTIFACT_KINDS,
  FALLBACK_KIND,
  type ToolkitArtifactKind,
} from "../artifact-kinds/registry";
import { badgeNameFor, resolveArtifactKind } from "../artifact-kinds/resolve";
import {
  bytesToBase32,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
} from "../../lib/toolkit/encode.js";

/** One cell-output artifact row (design v2 §20h/21b/22b). */
export type OutputArtifact = {
  /** Slot / filename / label shown in mono — e.g. "ciphertext", "signature.asc". */
  label: string;
  /** Value kind badge — "text", "bytes", "key"… uppercased in the row. */
  kind: string;
  /**
   * What the artifact *is* — the identity the kind registry matches on (§32b).
   *
   * Distinct from `kind` above, which is the badge string. These were missing
   * from this type, so the resolver saw role-less objects and every artifact
   * fell through to the fallback kind in the live UI, while an engine-backed
   * test resolved real artifacts and passed. A mapped-shape gap between the
   * two is invisible to both ends unless something carries it.
   */
  role?: string;
  tags?: string[];
  traits?: Record<string, unknown>;
  /**
   * The name the engine already gave this artifact — `public.asc`,
   * `kp-private.jwk.json`, `share-2.txt`. Download's filename comes from here
   * rather than from a second namer in the widget layer (see
   * `downloadNameFor`); the two could only ever disagree about the same
   * object. It was missing from this type, which is why it also had to be
   * added to both of the shell's mappings — a field this projection does not
   * list is dropped, silently, on the way in.
   */
  filename?: string;
  /** The engine's content type, used to build the download blob. */
  mime?: string;
  sizeBytes: number;
  sensitive?: boolean;
  onCopy: () => void;
  /**
   * The route to this site's directory, when there is one.
   *
   * Its *presence* is what makes Publish available; which artifacts may be
   * published is the kind table's answer (`key.publish` is declared on
   * `openpgp-public` alone, §38b), not a `publishable` flag the shell
   * recomputes beside it. The two used to disagree in exactly the way the
   * badge mapping did.
   */
  onPublish?: () => Promise<{ fingerprint?: string; directoryUrl?: string } | void>;
  /** Host named on the confirmation's "Where" line — this site, never an upstream. */
  directoryHost?: string;
  /** Slot this artifact was already published to — replaces the Publish button. */
  publishedAs?: string;
  /** Directory URL once published — the row's link icon copies this. */
  directoryUrl?: string;
  /** One-shot diagnostic action (§22b) — e.g. stun.check's "Configure TURN". */
  diagnosticAction?: { label: string; onClick: () => void };
  /**
   * One-line content preview, truncated by the caller — shown directly under
   * the row (and as the row's hover title). Omit for sensitive artifacts;
   * the row shows "sensitive — value not shown" instead, matching the Slots
   * tray's convention for secret values.
   */
  preview?: string;
  /**
   * Network/WebRTC artifacts (design v2 §23a/23b/29d/30d) render as a manager
   * widget instead of a JSON preview — the pipeline type picks the renderer.
   */
  netType?: string;
  netKind?: string;
  netData?: unknown;
  /** Structured `inspect` body — renders as a typed inspector, not text. */
  inspectSnapshot?: unknown;
  /**
   * JOSE body from a `jose.*` op — renders as the JWT reader rather than a
   * base64url blob. Carries the op's verification verdict, which the UI
   * cannot re-derive from the token text.
   */
  jose?: unknown;
  /** Full serialized content, for types that are text on the wire (SDP). */
  content?: string;
  /**
   * Whether a sensitive value may be unmasked on request. Set by the engine
   * only for tiles a user explicitly asked to see (`out`, `text`, `inspect`);
   * incidental tiles omit it and stay masked, so nothing is exposed implicitly.
   */
  revealable?: boolean;
  /** 22b — wired through to the pair matrix's all-failed CTA. */
  onConfigureTurn?: () => void;
};

/** Representations an artifact can be re-rendered in, after the fact. */
export const ARTIFACT_FORMATS = ["raw", "hex", "base64", "base64url", "base32"] as const;
export type ArtifactFormat = (typeof ARTIFACT_FORMATS)[number];

/**
 * Re-encode an artifact's content for display.
 *
 * Representation is a *view* concern once the value has been computed — the
 * pipeline already decided the bytes, and looking at them as hex rather than
 * base64 should not require editing and re-running the recipe. `raw` is
 * whatever the step produced; the rest re-encode the UTF-8 bytes of that text.
 *
 * Returns null when the content cannot be reinterpreted, so the caller can
 * fall back to `raw` rather than render an error.
 */
export function formatArtifact(content: string, format: ArtifactFormat): string | null {
  if (format === "raw") return content;
  try {
    const bytes = new TextEncoder().encode(content);
    if (format === "hex") return bytesToHex(bytes);
    if (format === "base64") return bytesToBase64(bytes);
    if (format === "base64url") return bytesToBase64Url(bytes);
    if (format === "base32") return bytesToBase32(bytes);
    return null;
  } catch {
    return null;
  }
}

/**
 * Whether a row has enough body to be worth its own window (§32c).
 *
 * Expand was originally network-only, but a keypair inspector body or a large
 * hexdump has exactly the same problem — too much value for a list row. The
 * threshold is deliberately generous: below it, the inline body is already
 * fully readable and a window would be ceremony.
 */
const EXPANDABLE_CONTENT_CHARS = 512;

export function canExpand(a: OutputArtifact): boolean {
  // §32d: expandability is a property of the *kind*, declared in the table,
  // not a third list of body-shape predicates kept in sync by hand. Falling
  // back to the size rule is what an unclaimed artifact gets.
  const kind = resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND);
  if (kind.expandable) return true;
  return (a.content?.length ?? 0) > EXPANDABLE_CONTENT_CHARS;
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** Segmented alphabet picker for one artifact row. */
function FormatBar({
  value,
  onChange,
}: {
  value: ArtifactFormat;
  onChange: (f: ArtifactFormat) => void;
}) {
  return (
    <span role="tablist" aria-label="Display format" className="flex gap-px">
      {ARTIFACT_FORMATS.map((f) => (
        <button
          key={f}
          type="button"
          role="tab"
          aria-selected={f === value}
          className={cn(
            "rounded-[3px] px-1 py-px font-mono text-[9px] transition-colors",
            f === value
              ? "bg-[color-mix(in_srgb,var(--brand)_var(--tile-tint),transparent)] font-semibold text-[var(--brand)]"
              : "text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          )}
          onClick={() => onChange(f)}
        >
          {f}
        </button>
      ))}
    </span>
  );
}

/**
 * Render a kind's body, degrading rather than blanking a cell (§32d).
 *
 * A view parses data the engine handed it, so a malformed body must fall back
 * to the raw text path — the tile below renders `a.content` when this returns
 * null. Throwing here would convert a computation that succeeded into a
 * user-visible failure, which inverts the severity.
 */
export function renderKindView(
  kind: ToolkitArtifactKind,
  artifact: Parameters<ToolkitArtifactKind["view"]>[0]["artifact"],
  masked: boolean
) {
  try {
    // §33e/§35d: while masked, only a kind's declared `publicView` may draw —
    // the body it renders derives solely from public material. Without one,
    // a masked tile shows nothing but the masked line, as before. The full
    // `view` never runs on a masked value; that is the mask, not a styling
    // choice.
    const render = masked ? kind.publicView : kind.view;
    return render ? render({ artifact, masked }) : null;
  } catch {
    return null;
  }
}

/**
 * One entry of the action table, as this file consumes it.
 *
 * The table is JS with JSDoc types, so this is the structural shape rather
 * than an import — narrow on purpose, listing only what the tile actually
 * calls, so a table field the tile ignores cannot start looking load-bearing.
 */
type ArtifactActionSpec = {
  id: string;
  label: string;
  tier: ActionTier;
  available: (ctx: unknown) => true | { disabled: string };
  confirm?: (ctx: unknown) => ConsequenceSpec | null;
  run: (ctx: unknown) => Promise<{ receipt?: string; detail?: string } | void>;
};

type PendingConfirm = { action: ArtifactActionSpec; spec: ConsequenceSpec };

type ArtifactTileProps = {
  artifact: OutputArtifact;
  /** Draws the divider under every row but the last (§40a). */
  divided: boolean;
  /** Reveal state lives in the list, because the auto-hide timer is list-wide. */
  revealed: boolean;
  onReveal: () => void;
  onHide: () => void;
  /** Bumps the list's auto-hide timer — reading a value counts as looking at it. */
  onKeepRevealed: () => void;
  format: ArtifactFormat;
  onFormatChange: (f: ArtifactFormat) => void;
  /** Opens the list's Sheet on this row. Absent when the row cannot expand. */
  onExpand?: () => void;
};

/**
 * One artifact tile: identity line, body, action row, receipt line (§33a).
 *
 * Lifted out of `OutputList`'s map body, unchanged — the anatomy worked, it
 * just had no name and no seam. Two things it buys immediately. The kind
 * registry, the action table and the mask gate now compose in one place
 * instead of inside a list, so §34c's confirmation has somewhere to live that
 * is not "the list that happens to render rows". And the catalog can mount a
 * single tile in a state the notebook cannot reach, which is how the empty and
 * failed bodies get seen at all.
 *
 * What stays in `OutputList`: the list chrome, the reveal set and its 15s
 * timer, the format map, and the Sheet. All three are *list*-scoped — the
 * timer in particular re-masks every revealed row at once, so pushing it down
 * per tile would turn one timer into N and change the behaviour, which is
 * exactly what a refactor may not do.
 */
export function ArtifactTile({
  artifact: a,
  divided,
  revealed,
  onReveal,
  onHide,
  onKeepRevealed,
  format,
  onFormatChange,
  onExpand,
}: ArtifactTileProps) {
  /**
   * The pending confirmation, its in-flight flag and the last thrown message
   * (§34c/§33f). One at a time by construction: an action that has raised a
   * banner is the only thing the tile is asking about, so a second click on a
   * different action cannot stack a second question.
   */
  const [pending, setPending] = useState<PendingConfirm | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /**
   * Unique per mounted tile, for the row-gate sentence's id.
   *
   * `useId` for `ArtifactAction`'s reason: the tray mounts a **second copy** of
   * every row, so any id derived from the artifact's own label would collide
   * across the document and every `aria-describedby` would resolve to whichever
   * pane rendered first. That is not hypothetical here — it is the defect
   * `501cf4f` fixed, in the same feature, one component down.
   */
  const uid = useId();
  // §32e: one resolver call, computed once. The kind is decided by the
  // artifact's identity; `kindBody` is null when this kind has no body
  // to draw, and the raw path below renders instead.
  const resolvedKind = resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND);
  const kindBody = renderKindView(resolvedKind, a, false);
  const masked = !!a.sensitive && !revealed;
  const services = {
    // The existing handler, not a re-implementation: it fires the shipped
    // clipboard toast and knows this artifact's own serialization. The table
    // makes its *gating* uniform.
    copyArtifact: () => a.onCopy(),
    clipboard: { write: (t: string) => navigator.clipboard.writeText(t) },
    // Injected, never imported by the table: the action decides the *name*,
    // the service decides how bytes reach the disk. Unconditional, like
    // `clipboard` and unlike `vault` — a rendered tile implies a document, so
    // there is no environment fact for `available()` to report, and the
    // service says so itself in the one case there is.
    download: (file: { name: string; content?: string; mime?: string }) =>
      downloadArtifactFile(file),
    // Injected only when the caller supplied a publish route, so `available()`
    // reports "no connection to this site's directory" rather than the tile
    // deciding by omission whether the button exists at all.
    directory: a.onPublish
      ? { host: a.directoryHost || "this site", publish: () => a.onPublish!() }
      : undefined,
    // Same shape, same reason: injected only where a vault can exist, so
    // `available()` reports the environment fact ("My Keys is unavailable in
    // this browser") instead of the tile deciding by omission whether the
    // button is there at all. The service does the storing; the table below
    // never imports a vault.
    vault: vaultAvailable()
      ? { add: (body: { content?: string; alg?: unknown }) => addPrivateKeyToMyKeys(body as never) }
      : undefined,
  };
  const ctx = { artifact: a, kind: resolvedKind, masked, services };

  /**
   * The row as it will actually render, and whether all of it refuses.
   *
   * §33f drops an outward action once its result exists — a published key has
   * no Publish button — so the filter runs *before* the gate is computed: an
   * action nobody can see is not a refusal the row should speak for.
   *
   * Expand and the diagnostic button are the other two things in this row, and
   * neither comes from the action table. Where either is present the row is not
   * dead, so there is nothing to explain and the buttons keep their own private
   * descriptions.
   */
  const rowActions = (actionsFor(resolvedKind) as ArtifactActionSpec[]).filter(
    (action) => !(action.tier === "outward" && a.publishedAs)
  );
  const rowGate =
    onExpand || a.diagnosticAction ? null : gatedRowReason(rowActions, ctx);
  const rowGateId = rowGate ? `artifact-row-gate-${uid}` : undefined;

  /**
   * Run an action, log it, and surface what it did (§33f, §36).
   *
   * Logging lives here — the one place every action passes through — so a
   * newly declared action cannot forget. Only on success: an action that threw
   * moved nothing, and recording it as though it had would make the log lie in
   * the direction that matters least forgivably.
   */
  const runAction = (action: ArtifactActionSpec) => {
    setBusy(true);
    setError(null);
    void Promise.resolve(action.run(ctx))
      .then((result) => {
        setPending(null);
        return recordActivity({
          action: action.id,
          label: action.label,
          artifact: a.label,
          tier: action.tier,
          content: a.content,
          detail: result?.detail,
          receipt: result?.receipt,
        });
      })
      .catch((e: unknown) => {
        // Verbatim, and the button stays live: a failed publish is retryable,
        // and "something went wrong" is the one outcome worse than the failure.
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setBusy(false));
  };

  return (
    <div
      data-artifact-kind={resolvedKind.id}
      className={cn(
        "relative flex flex-col gap-1 px-2.5 py-2",
        divided && "border-b border-[color-mix(in_srgb,var(--border)_55%,transparent)]"
      )}
    >
      <div className="flex items-center gap-2.5" title={a.preview}>
        {/* §35 — glyph in front of the existing label. `a.kind` is already
            the lookup key, so no new prop; the same map backs TypeCard and
            the Types shelf so one kind never shows two icons.

            The tint is `badgeFamily`'s answer, rendered by an enumerated rule
            set in toolkit.css. It was a ternary here, naming `key` and
            `keypair` by hand — so the four key roles added after it were
            tinted as though they were plain text, which is what the catalog's
            key section makes visible. Where the family lives is the fix; a
            fifth branch would have been the same defect one role later.

            `data-badge-tier` is the second axis, added the same way rather
            than folded into the first: the family says *what* (one hue for
            all six key roles, which is right — they wear one glyph), the tier
            says *whether it is secret*. Making the family answer both was the
            old defect's shape, where "which two roles existed when the tint
            was written" stood in for a real axis. The kind declares the tier
            where it knows; `key` does not, and defers to the artifact.

            Both attributes stay keyed on `a.kind` — the **role** — on purpose.
            What the chip *says* moved to the kind below, and these two answer
            a different question ("is this key material", "is it secret") that
            the role is still the right input for. Repointing them at the
            rendered string would tie a colour to a name. */}
        <span
          className="artifact-badge inline-flex shrink-0 items-center gap-1 rounded-[3px] px-[5px] py-[2px] text-[9px] font-medium uppercase tracking-wider"
          data-badge-family={badgeFamily(a.kind)}
          data-badge-tier={badgeTier(resolvedKind.sensitivity, a.sensitive)}
        >
          {/* The kind's declared glyph, falling back to the role's.
              `resolvedKind.glyph` was declared on fourteen kinds, validated by
              a test, and rendered by nothing — so a `token` (role `token`,
              unmapped) drew no glyph at all while declaring `signature`, and
              an OTP code drew AlignLeft. */}
          <KindGlyph kind={resolvedKind.glyph || a.kind} />
          {/* Not `a.kind`. The role is what the *resolver* matched on, so a
              TOTP code badged TEXT: true, and the least useful true thing on
              the row. `badgeNameFor` falls back to the role, which is already
              short and mostly right — see `ArtifactKind.badge` for why the
              prose `label` is not the default. */}
          {badgeNameFor(resolvedKind, a, a.kind)}
        </span>
        {/* `title` on the label, not only on the row.
            The row's title is the *preview* — the body — and the label is a
            different fact that also truncates. Most labels are short slot
            names, but not all are sentences by accident: the engine names the
            recovery envelope "OpenPGP envelope — required for recovery (not a
            share)", and in a narrow panel the row cut it at "OpenPGP envelope
            — required f…", losing the clause the label exists for. A witness
            who reads that as a share destroys a ceremony by counting it toward
            the threshold, so the half that gets cut is the load-bearing half.
            Same treatment `RecipientsCard` gives a truncated fingerprint. */}
        <code
          className="artifact-label min-w-0 flex-1 truncate font-mono font-medium text-[var(--foreground)]"
          title={a.label}
        >
          {a.label}
        </code>
        {/* Kept, and recoloured into the tier rather than dropped.

            It is redundant with the badge on four of the six key roles, and
            the tempting cut was to delete it there. The other two are why it
            stays: `KEY` and `KEYPAIR` name no half, so on those tiles this
            chip is the only place the word "sensitive" appears at all — the
            only carrier for a screen reader, and the only non-colour channel
            for a reader who cannot see the hue split. Redundancy on the four
            is the WCAG 1.4.1 belt beside the braces; absence on the two would
            be a hole. What it stops being is a *third amber*: it now speaks
            the same `--secret` the badge does, so a secret row says one thing
            in one colour twice instead of three things in one colour. */}
        {a.sensitive ? (
          <Badge variant="warn" className="artifact-sensitive normal-case tracking-normal">
            sensitive
          </Badge>
        ) : null}
        <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
          {fmtSize(a.sizeBytes)}
        </span>
      </div>

      {/* §36a — actions on their own line. The identity line above answers
          "what is this"; this one answers "what can I do to it". Eight
          controls sharing one flex row gave a plain text artifact the same
          visual weight as a publishable key with five affordances. */}
      <div className="flex flex-wrap items-center gap-1.5">
        {a.diagnosticAction ? (
          <Button
            size="sm"
            className="h-[22px] shrink-0 rounded-[5px] bg-[var(--warn)] px-2 text-[10px] font-bold text-[#1a1405] hover:opacity-90"
            onClick={(e) => {
              e.stopPropagation();
              a.diagnosticAction?.onClick();
            }}
          >
            {a.diagnosticAction.label}
          </Button>
        ) : null}
        {onExpand ? (
          <ArtifactAction label="Expand" tier="inert" onClick={onExpand} />
        ) : null}
        {/* §33c: the kind names its actions, the table defines them once,
            and this row renders them. "Copy" gates the same way on every
            tile because there is only one Copy — the churn this whole
            abstraction exists to stop is each tile growing its own. */}
        {/* §33f: an outward action is replaced by its result. Once the key is
            published the button is gone, which is the only one of the three
            receipt weights that makes re-firing an irreversible action
            structurally impossible. That filter is `rowActions`, above, so the
            row gate is computed against the buttons that render. */}
        {rowActions.map((action) => {
          const availability = action.available(ctx);
          const reason = availability === true ? undefined : availability.disabled;
          const confirmSpec = availability === true ? action.confirm?.(ctx) : null;
          return (
            <ArtifactAction
              key={action.id}
              label={action.label}
              tier={action.tier}
              reason={reason}
              describedBy={rowGateId}
              busy={busy && pending?.action.id === action.id}
              busyLabel={`${action.label}…`}
              onClick={() => {
                // §34c: an action that declares consequences asks first, in
                // the banner — never in a popover, so the tile it is about
                // stays visible and a click elsewhere cannot dismiss it.
                if (confirmSpec) {
                  setError(null);
                  setPending({ action, spec: confirmSpec });
                  return;
                }
                runAction(action);
              }}
            />
          );
        })}
        {a.publishedAs ? (
          <span className="flex shrink-0 items-center gap-1">
            <code className="artifact-meta font-mono text-[var(--brand)]">{a.publishedAs}</code>
            {a.directoryUrl ? (
              <button
                type="button"
                className="text-[10px] text-[var(--muted-foreground)] hover:text-[var(--brand)]"
                aria-label="Copy directory link"
                title="Copy directory link"
                onClick={(e) => {
                  e.stopPropagation();
                  void navigator.clipboard.writeText(a.directoryUrl!);
                }}
              >
                🔗
              </button>
            ) : null}
          </span>
        ) : null}
      </div>

      {/* A row that refuses in its entirety, for one reason, says it once.
          `secret-key` is the tile this exists for: Copy and Download are its
          whole row, both gate on the mask, and the control that lifts the gate
          — Reveal — is drawn *below* the row it unlocks, so a masked symmetric
          key showed two dead buttons and no visible account of why. It is
          guarded, not broken.

          Not a new string: it is `ACTION_REASONS`' own sentence, the one both
          buttons were already carrying in a `title`. And both point their
          `aria-describedby` at this element rather than emitting private
          copies, so one refusal is announced once rather than three times. */}
      {rowGate ? (
        <p className="artifact-row-gate" id={rowGateId} data-row-gate>
          {rowGate}
        </p>
      ) : null}

      {/* §43d: inline, directly under the action row. The tile grows; nothing
          overlays. A floating layer that closes when you click away trains
          dismissal, and the context — which tile, which artifact — is exactly
          what a consequence question needs kept on screen. */}
      {pending ? (
        <ConsequenceBanner
          className="mt-1 rounded-[6px]"
          spec={pending.spec}
          busy={busy}
          error={error}
          onCancel={() => {
            setPending(null);
            setError(null);
          }}
          onConfirm={() => runAction(pending.action)}
        />
      ) : null}
      {/* An error from an action that asked nothing still has to land
          somewhere, and the tile is where it belongs (§33f). */}
      {!pending && error ? (
        <p className="text-[length:10px] text-[var(--error)]" data-action-error>
          {error}
        </p>
      ) : null}
      {masked ? (
        <span className="flex flex-col gap-1 pl-[1px]">
          {/* §35d: a masked private key is no longer a blank tile — its
              algorithm, fingerprint and public line are public facts. */}
          {renderKindView(resolvedKind, a, true)}
          {/* The masked line is about a *body*, so a tile with no body does
              not get one.

              The keypair tile said "nothing here" twice, stacked, in the same
              10px italic mono muted: its own withheld line ("private half not
              shown — add `out $kp` …") and then this. The second was not a
              quieter restatement of the first, it was false — `keypair` has
              no body to mask, `view` and `publicView` are the same function
              for exactly that reason, and there is no reveal that could ever
              change what this tile shows. A mask drawn over nothing teaches
              that something is behind it.

              `a.content` is the right gate rather than `revealable`, because
              the sentence is a claim about the body, not about permission —
              and the Reveal button below already requires both, so no tile
              loses a control it had. */}
          {a.content ? (
            <span className="flex items-center gap-2">
              <span className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
                sensitive — value not shown
              </span>
              {/* Only tiles produced by an explicit `out` / `text` / `inspect`
                  offer this. A value that merely passed through was never
                  asked to be displayed, so there is nothing to reveal.

                  Its amber moved to `--secret` (see `.artifact-reveal`): this
                  is a local, reversible unmask that the list re-hides after
                  15s, and it was wearing the outward tier's exact outline —
                  the one `Publish` wears to promise "this leaves the
                  machine". */}
              {a.revealable && a.content ? (
                <button
                  type="button"
                  className="artifact-reveal"
                  title="Show this value in the clear"
                  onClick={onReveal}
                >
                  Reveal
                </button>
              ) : null}
            </span>
          ) : null}
        </span>
      ) : kindBody ? (
        /* §32e: one resolver call where three bespoke predicates used to
           chain. The kind comes from the artifact's identity (role +
           tags), and the view reads the body — so a token whose body
           failed to decode is still a token showing its empty state,
           rather than falling through and rendering as untyped text.
           Reached only past the sensitive gate above, so a freshly signed
           value still masks until it is revealed. */
        kindBody
      ) : a.content ? (
        <span
          className="flex flex-col gap-1 pl-[1px]"
          /* Reading or reformatting a revealed value counts as still
             looking at it, so the auto-hide timer restarts. */
          onMouseMove={a.sensitive ? onKeepRevealed : undefined}
          onFocus={a.sensitive ? onKeepRevealed : undefined}
        >
          <span className="flex items-center gap-2">
            <FormatBar
              value={format}
              onChange={(f) => {
                onKeepRevealed();
                onFormatChange(f);
              }}
            />
            {a.sensitive ? (
              <button
                type="button"
                className="rounded-[4px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-1.5 py-px text-[9px] font-semibold text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                onClick={onHide}
              >
                Hide
              </button>
            ) : null}
          </span>
          <code
            className={cn(
              "artifact-body block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono",
              a.sensitive
                ? "text-[var(--foreground)]"
                : "text-[var(--muted-foreground)]"
            )}
          >
            {formatArtifact(a.content, format) ?? a.content}
          </code>
        </span>
      ) : a.preview ? (
        <code className="artifact-body truncate pl-[1px] font-mono text-[var(--muted-foreground)]">
          {a.preview}
        </code>
      ) : null}
    </div>
  );
}
