import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";
import { sshIdentityFromJwk } from "../../lib/toolkit/ssh-ops.js";

/**
 * The key read-out (§35c, design_handoff_artifact_actions).
 *
 * A keypair used to render as two JWK blobs and nothing else — the densest,
 * least readable form of the one artifact people most need to *recognise*.
 * Nothing is taken away here: the raw JWK is still one toggle down. It just
 * stops being the only thing offered.
 *
 * Every line is derived, never re-stated from the blob:
 *
 * - **Algorithm** comes from `traits.alg` — the `genkey`-style tag the recipe
 *   actually named (`ed25519`, `ec/p256`), not a guess reconstructed from JWK
 *   fields. The value the user wrote is the value to show them.
 * - **Fingerprint in kind shape** (§28a): an SSH key prints `SHA256:` +
 *   unpadded base64 exactly as `ssh-keygen -lf` does, so it can be compared
 *   against a server's log line character for character; OpenPGP prints
 *   grouped hex. The copy affordance copies what is displayed, never a
 *   normalized variant.
 * - **Public line** for SSH-mappable algorithms only, computed by the shipped
 *   codec — the same bytes `ssh.encode` emits, no new crypto. For x25519, AES
 *   and HMAC the row is **absent** rather than disabled: SSH has no key type
 *   for them, and an empty row would imply one exists (§33d).
 *
 * `publicOnly` is what makes a masked private-key tile useful instead of
 * blank. Algorithm, fingerprint and public line are all derived from public
 * material, so they may render while the secret stays masked — that is the
 * §34b rule, which is about *where a value lands*, not how sensitive it is.
 *
 * **`half` is not `publicOnly`.** They were one flag, and the flag was doing
 * two unrelated jobs: hiding the raw toggle, and captioning the card. So the
 * masked private-key tile — `publicView: keyCardFor(true)` — captioned itself
 * "public half", and the least-specific `key` kind captioned every lone key
 * "keypair". Both are the same defect as the one this file's card was written
 * to fix, one layer up. `publicOnly` now means only "do not offer the raw
 * body"; `half` says what the artifact *is*, and a kind that cannot know says
 * nothing rather than guessing.
 */
export function KeyCard({
  content,
  jwk: jwkSource,
  alg,
  fingerprint,
  comment,
  half,
  withheld,
  publicOnly = false,
  className,
}: {
  /** The JWK text the artifact carries. */
  content: string;
  /**
   * The public JWK to derive the id and public line from, when it is not the
   * body. A keypair tip has no body at all — its public half rides `traits`,
   * because materializing the private one is what `out` is for.
   */
  jwk?: string;
  /** `traits.alg` — the genkey-style tag the recipe named. */
  alg?: string;
  /** Pre-computed id (OpenPGP hex); SSH ids are derived from the JWK below. */
  fingerprint?: string;
  comment?: string;
  /**
   * Which half this artifact holds. Omitted where the kind cannot know.
   *
   * `secret` is not a half — it is a symmetric key, which has none — and the
   * caption says so in words rather than calling it the "secret half".
   */
  half?: "public" | "private" | "both" | "secret";
  /** What is deliberately not shown, and the recipe edit that would show it. */
  withheld?: string;
  publicOnly?: boolean;
  className?: string;
}) {
  const [ssh, setSsh] = useState<{ publicLine: string; fingerprint: string } | null>(
    null
  );
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let live = true;
    let jwk: Record<string, unknown> | null = null;
    try {
      jwk = JSON.parse(jwkSource || content);
    } catch {
      jwk = null;
    }
    if (!jwk) {
      setSsh(null);
      return;
    }
    // Strip the private half before deriving anything: a public line and a
    // fingerprint are public facts, and computing them from a copy without
    // `d` means no private field can reach this component's state.
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk as Record<
      string,
      unknown
    >;
    void _d;
    void _p;
    void _q;
    void _dp;
    void _dq;
    void _qi;
    sshIdentityFromJwk(pub as JsonWebKey, comment || "")
      .then((id) => {
        if (live) setSsh(id ? { publicLine: id.publicLine, fingerprint: id.fingerprint } : null);
      })
      .catch(() => {
        if (live) setSsh(null);
      });
    return () => {
      live = false;
    };
  }, [content, jwkSource, comment]);

  const shownFingerprint = ssh?.fingerprint || (fingerprint ? formatFingerprint(fingerprint) : null);

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-key-card>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          {alg || "key"}
        </span>
        {half ? (
          <span
            className="text-[10px] text-[var(--muted-foreground)]"
            data-key-half={half}
          >
            {half === "both"
              ? "public + private halves"
              : half === "secret"
                ? "symmetric — no public half"
                : `${half} half`}
          </span>
        ) : null}
      </div>

      {shownFingerprint ? (
        <code className="artifact-body block break-all font-mono text-[var(--muted-foreground)]">
          {shownFingerprint}
        </code>
      ) : null}

      {ssh?.publicLine ? (
        <code className="artifact-body block truncate font-mono text-[var(--muted-foreground)]">
          {ssh.publicLine}
        </code>
      ) : null}

      {/* Absence with a stated reason, never silent absence: the private half
          is here, it is deliberately not shown, and the sentence names the
          recipe edit that would show it — `ACTION_REASONS.neverAskedFor`'s
          register, on the tile rather than on a disabled button's tooltip. */}
      {withheld ? (
        <p
          className="font-mono text-[10px] italic text-[var(--muted-foreground)]"
          data-key-withheld
        >
          {withheld}
        </p>
      ) : null}

      {/* The JWK is still here — one toggle down rather than the whole tile. */}
      {publicOnly || !content ? null : (
        <div className="flex flex-col gap-1">
          <button
            type="button"
            className="self-start text-[10px] text-[var(--brand)] underline"
            onClick={() => setShowRaw((v) => !v)}
          >
            {showRaw ? "hide raw" : "raw"}
          </button>
          {showRaw ? (
            <code className="artifact-body block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-[var(--muted-foreground)]">
              {content}
            </code>
          ) : null}
        </div>
      )}
    </div>
  );
}
