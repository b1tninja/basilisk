import { KeyRound } from "lucide-react";
import { cn } from "@/lib/cn";
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
  /** Currently bound fingerprint (or `@slot` ref). */
  value?: string;
  onChange?: (fingerprint: string) => void;
  /** Verb for the header — "Sign with", "Decrypt with". */
  label?: string;
  className?: string;
};

/** Days until `expires`, or null when it never expires. */
export function daysUntilExpiry(expires: number | null | undefined, now = Date.now()): number | null {
  if (expires == null) return null;
  return Math.ceil((expires - now) / 86_400_000);
}

/**
 * Expiry note for a key row, or null when it is not worth saying.
 *
 * Only speaks up inside a month. A key expiring in a year is not news, and a
 * warning shown on every row would train people to ignore the one that counts.
 */
export function expiryNote(expires: number | null | undefined, now = Date.now()): {
  text: string;
  severity: "warn" | "error";
} | null {
  const days = daysUntilExpiry(expires, now);
  if (days == null) return null;
  if (days < 0) return { text: "expired", severity: "error" };
  if (days === 0) return { text: "expires today", severity: "error" };
  if (days <= 30) {
    return {
      text: `expires in ${days} day${days === 1 ? "" : "s"}`,
      severity: days <= 7 ? "error" : "warn",
    };
  }
  return null;
}

function shortFpr(fpr: string): string {
  const clean = String(fpr || "").replace(/\s+/g, "");
  return clean.length > 16 ? `…${clean.slice(-16)}` : clean;
}

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
              <span className="min-w-0 flex-1">
                <code className="block truncate font-mono text-[11px] text-[var(--foreground)]">
                  {k.uid || k.email || shortFpr(k.fingerprint)}
                </code>
                {k.uid || k.email ? (
                  <code className="block truncate font-mono text-[9.5px] text-[var(--muted-foreground)]">
                    {shortFpr(k.fingerprint)}
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
          No keys with a private half yet — generate or import one on My Keys, or run{" "}
          <code className="font-mono not-italic">gpg.genkey</code>.
        </p>
      )}
    </div>
  );
}
