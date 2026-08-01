import { producersOf } from "../../lib/toolkit/type-registry.js";
import { cn } from "@/lib/cn";
import { expectedTypeFrom } from "../../lib/toolkit/type-error-hints.js";

/**
 * Per-cell type-error banner (design v2 §33c).
 *
 * Type errors were the most common failure in the toolkit and had no designed
 * presentation: the validator knew a pipeline was ill-typed, but nothing said
 * so until the engine threw mid-run. This puts them under the chip row, where
 * the RunBar's blocked state already lives — a banner, not a tooltip, because
 * a message you must hover to find is not a message you will read before
 * hitting Run.
 *
 * The offending step is named and clickable so the fix starts one gesture from
 * the complaint.
 */

export type CellTypeError = {
  message: string;
  /** Index of the offending stem step, or -1 when the validator did not say. */
  stepIndex: number;
};

/**
 * The button six error messages already name.
 *
 * `legacyRemovalHint` and `RETIRED_PARAM_VALUES` both end their sentence with
 * "(or Upgrade recipe to migrate)", and until this landed there was no such
 * control anywhere in the app — the wording was copied from one hint to the
 * next and nothing was ever wired. A remedy that names a control the reader
 * cannot find is the `723b95b` defect (an SSH passphrase message naming an
 * Inputs field that did not exist), and it is worse than no remedy.
 *
 * Matched on the message rather than on a flag, because the message is where
 * the promise is made — a hint that stops offering the upgrade stops rendering
 * the button, in one place, with no second list to keep in step. Whether the
 * migrator has anything to *do* is the caller's question (`recipeUpgrade`), so
 * a matching message with no rewrite behind it renders nothing.
 */
const OFFERS_UPGRADE = /Upgrade recipe/;

type Props = {
  errors: CellTypeError[];
  steps: { name?: string }[];
  /** Focus the offending chip for editing. */
  onFocusStep?: (stepIndex: number) => void;
  /**
   * Run the migrator over this cell. Passed only when it would actually
   * rewrite something, so the button is absent rather than inert (§33d).
   */
  onUpgradeRecipe?: () => void;
  className?: string;
};

export function CellTypeErrors({
  errors,
  steps,
  onFocusStep,
  onUpgradeRecipe,
  className,
}: Props) {
  if (!errors.length) return null;
  return (
    <div className={cn("flex flex-col gap-1", className)} data-cell-type-errors>
      {errors.map((e, i) => {
        const step = e.stepIndex >= 0 ? steps[e.stepIndex] : null;
        const expected = expectedTypeFrom(e.message);
        // Only offer a fix when the registry actually knows an op that makes
        // the wanted type — a generic "insert a cast" that resolves nothing
        // is worse than no suggestion at all.
        const producers = expected ? producersOf(expected) : [];
        const fix = producers.find((p) => p !== step?.name) || "";
        return (
          <div
            key={i}
            role="alert"
            className="flex flex-wrap items-baseline gap-x-2 gap-y-1 rounded-[7px] border border-[color-mix(in_srgb,var(--error)_35%,transparent)] bg-[color-mix(in_srgb,var(--error)_8%,transparent)] px-2.5 py-1.5"
          >
            {step?.name ? (
              <button
                type="button"
                className="shrink-0 rounded-[4px] bg-[color-mix(in_srgb,var(--error)_16%,transparent)] px-1.5 py-px font-mono text-[10px] font-semibold text-[var(--error)] hover:underline"
                onClick={() => onFocusStep?.(e.stepIndex)}
                title="Edit this step"
              >
                {step.name}
              </button>
            ) : null}
            <span className="min-w-0 flex-1 text-[length:11px] leading-snug text-[var(--foreground)]">
              {e.message}
            </span>
            {fix ? (
              <span className="shrink-0 text-[10px] text-[var(--muted-foreground)]">
                makes <code className="font-mono">{expected}</code>:{" "}
                <code className="font-mono text-[var(--foreground)]">{fix}</code>
              </span>
            ) : null}
            {onUpgradeRecipe && OFFERS_UPGRADE.test(e.message) ? (
              <button
                type="button"
                className="shrink-0 rounded-[4px] border border-[color-mix(in_srgb,var(--error)_35%,transparent)] px-1.5 py-px text-[10px] font-semibold text-[var(--error)] hover:bg-[color-mix(in_srgb,var(--error)_12%,transparent)]"
                onClick={onUpgradeRecipe}
                data-upgrade-recipe
              >
                Upgrade recipe
              </button>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
