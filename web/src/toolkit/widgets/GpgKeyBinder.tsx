import { KeyRound } from "lucide-react";
import { cn } from "@/lib/cn";
import { expiryNote } from "../../lib/toolkit/artifact-readouts.js";
import { formatFingerprint } from "../../lib/utils.js";
import type { VaultKeyRow } from "../notebook-types";

/**
 * Pick an OpenPGP key **you hold** (design v2 §39b).
 *
 * Easy to conflate with recipient binding, and worth stating the difference
 * plainly because the two have opposite directions:
 *
 *  - *Recipients* are public keys you are encrypting **to** (`gpg.encrypt`),
 *    resolved from a keyserver or pasted armor. You need no secret for them.
 *  - *This* picks a key you can act **as** — `gpg.sign`, `gpg.decrypt` — which
 *    means a private half must be present.
 *
 * It reads the same vault the Keys tray renders rather than keeping a list of
 * its own, so there is nothing to fall out of sync: a key deleted from the
 * vault stops being offered here by construction.
 */

type Props = {
  /** The vault's keys, exactly as the Keys tray receives them. */
  keys: VaultKeyRow[];
  /** Currently bound fingerprint (or `$slot` ref). */
  value?: string;
  onChange?: (fingerprint: string) => void;
  /** Verb for the header — "Sign with", "Decrypt with". */
  label?: string;
  className?: string;
};

/**
 * `expiryNote` and `daysUntilExpiry` are `artifact-readouts.js`' now.
 *
 * They were written here, for this list, and were view-local while this was
 * their only consumer. `OpenPgpKeyCard` and the certificate panel now ask the
 * same question of the same instant — three consumers of one derivation — and
 * the representation layer is where that answer is allowed to live. Nothing in
 * the verdict changed; this file just stopped owning it.
 */

/*
 * This is one of two places a fingerprint is drawn without `<Fingerprint>`
 * around it, and the reason is structural rather than a judgement about space.
 *
 * Every row here *is* a control — the whole card is the button that selects the
 * key, which is what makes this a picker rather than a list with a picker in
 * it. A `<button>` cannot contain a `<button>`, so an interactive fingerprint
 * inside a row would be invalid markup, and pulling it out into a sibling would
 * shrink the click target to the words beside it.
 *
 * What that costs is the copy control and the actions menu. What it does not
 * cost is the rule those exist to serve: this printed `…{last 16}` — sixty-four
 * bits with the rest hidden — and it prints the whole value now. Where a key
 * has a uid the row leads with that, exactly as `variant="compact"` would.
 */

export function GpgKeyBinder({
  keys,
  value = "",
  onChange,
  label = "Sign with",
  className,
}: Props) {
  return (
    <div className={cn("flex flex-col gap-1", className)} data-gpg-key-binder>
      <p className="text-[length:10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
        {label}
      </p>
      {keys.length ? (
        keys.map((k) => {
          const selected = !!value && (value === k.fingerprint || value === `@${k.fingerprint}`);
          const note = expiryNote(k.expires);
          return (
            <button
              key={k.fingerprint}
              type="button"
              aria-pressed={selected}
              data-key-row={k.fingerprint}
              className={cn(
                "flex items-center gap-2 rounded-[6px] border px-2 py-1.5 text-left transition-colors",
                selected
                  ? "border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_10%,transparent)]"
                  : "border-[color-mix(in_srgb,var(--border)_70%,transparent)] hover:border-[var(--border)] hover:bg-[var(--surface-raised)]"
              )}
              onClick={() => onChange?.(k.fingerprint)}
            >
              <KeyRound
                size={12}
                strokeWidth={2}
                aria-hidden
                className={selected ? "text-[var(--brand)]" : "text-[var(--muted-foreground)]"}
              />
              {/* `break-all`, not `truncate`: clipping a fingerprint to its
                  column is the elided form with the browser holding the knife
                  — a prefix whose length depends on the window, and no way for
                  the reader to tell how much is gone. */}
              <span className="min-w-0 flex-1">
                <code className="block break-all font-mono text-[11px] text-[var(--foreground)]">
                  {k.uid || k.email || formatFingerprint(k.fingerprint)}
                </code>
                {k.uid || k.email ? (
                  <code className="block break-all font-mono text-[9.5px] text-[var(--muted-foreground)]">
                    {formatFingerprint(k.fingerprint)}
                  </code>
                ) : null}
              </span>
              {note ? (
                <span
                  className={cn(
                    "shrink-0 text-[9.5px] font-semibold",
                    note.severity === "error" ? "text-[var(--error)]" : "text-[var(--warn)]"
                  )}
                >
                  {note.text}
                </span>
              ) : null}
              {selected ? (
                <span className="shrink-0 text-[9.5px] font-semibold text-[var(--brand)]">
                  selected
                </span>
              ) : null}
            </button>
          );
        })
      ) : (
        // Not "no keys" — say what to do. The vault being empty is the normal
        // first-run state, not an error.
        <p className="rounded-[6px] border border-dashed border-[var(--border)] px-2 py-2 text-[11px] italic text-[var(--muted-foreground)]">
          No keys with a private half yet — generate or import one in the Keys tray, or run{" "}
          <code className="font-mono not-italic">gpg.genkey</code>.
        </p>
      )}
    </div>
  );
}
