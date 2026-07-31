import { useState } from "react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";
import type {
  ApprovalDecision,
  ApprovalRequest,
} from "../../lib/toolkit/approval-gate.js";

/**
 * The approval moment (§27b/§27c, design_handoff_agent_ssh).
 *
 * Every line here is data the engine held at the moment of the request —
 * nothing inferred, nothing decorative. That is the point: this banner is
 * the only thing standing between "agent" and "rubber stamp", so anything
 * on it that a user learns to skim is a liability.
 *
 * It renders inline at the requesting cell rather than as a modal. A modal
 * hides the very context needed to judge the request — which step, in which
 * recipe, is asking — and trains click-through. Inline, the requesting chip
 * is visible directly above the question.
 *
 * The three outcomes are deliberately not three equal buttons: Deny is
 * ghost weight, "Approve once" is the visually primary action, and the
 * session grant is a *checkbox modifying it*, so the strong default stays
 * the easy path.
 */
export function ApprovalBanner({
  request,
  onDecide,
  className,
}: {
  request: ApprovalRequest;
  onDecide: (decision: ApprovalDecision) => void;
  className?: string;
}) {
  const [showPayload, setShowPayload] = useState(false);
  const [forSession, setForSession] = useState(false);

  const remaining =
    request.runTotal && request.runTotal > request.requestIndex
      ? request.runTotal - request.requestIndex
      : 0;
  const verb = request.use === "sign" ? "sign" : "decrypt";

  return (
    <div
      className={cn(
        "border-l-2 border-[var(--border)] border-l-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_8%,transparent)] px-3.5 py-2.5",
        className
      )}
      data-approval-ask={request.use}
      role="alertdialog"
      aria-label={`${request.stepName} wants to use a key`}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-[length:11.5px] font-semibold text-[var(--foreground)]">
          <code>{request.stepName}</code> wants to use a key
        </span>
        <span className="ml-auto font-mono text-[length:10px] text-[var(--muted-foreground)]">
          {request.runTotal
            ? `request ${request.requestIndex} of ${request.runTotal} this run`
            : `request ${request.requestIndex} this run`}
        </span>
      </div>

      <dl className="mt-2 grid grid-cols-[68px_minmax(0,1fr)] gap-x-2 gap-y-1 text-[length:10.5px]">
        <dt className="font-semibold text-[var(--muted-foreground)]">Step</dt>
        <dd className="min-w-0 break-all font-mono text-[var(--foreground)]">
          {request.cellIndex != null ? `cell ${request.cellIndex + 1} · ` : ""}
          {request.stepText}
        </dd>

        <dt className="font-semibold text-[var(--muted-foreground)]">Key</dt>
        <dd className="min-w-0">
          <span className="key-kind-badge" data-key-kind={request.keyKind}>
            {request.keyKind.toUpperCase()}
          </span>
          <span className="text-[var(--foreground)]">{request.keyLabel}</span>
          <span className="ml-1.5 text-[var(--muted-foreground)]">
            {request.keyProtection}
          </span>
          <div className="break-all font-mono text-[length:10px] text-[var(--muted-foreground)]">
            {request.keyId}
          </div>
        </dd>

        <dt className="font-semibold text-[var(--muted-foreground)]">
          {request.use === "decrypt" ? "Ciphertext" : "Payload"}
        </dt>
        <dd className="min-w-0">
          <span className="font-mono text-[var(--foreground)]">
            {request.payloadBytes} bytes · sha256 {request.payloadSha256.slice(0, 16)}…
          </span>
          {request.payloadPreview != null ? (
            <button
              type="button"
              className="ml-2 text-[var(--brand)] underline"
              onClick={() => setShowPayload((v) => !v)}
            >
              {showPayload ? "hide payload" : "show payload"}
            </button>
          ) : (
            // A digest alone is honest but unauditable; when there is no
            // text to show, say so rather than implying one was withheld.
            <span className="ml-2 text-[var(--muted-foreground)]">
              {request.use === "decrypt" ? "ciphertext — digest only" : "binary payload — digest only"}
            </span>
          )}
          {showPayload && request.payloadPreview != null ? (
            <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-[6px] border border-[var(--border)] bg-[var(--surface-raised)] p-1.5 font-mono text-[length:10px] text-[var(--foreground)]">
              {request.payloadPreview}
            </pre>
          ) : null}
        </dd>

        {request.namespace ? (
          <>
            <dt className="font-semibold text-[var(--muted-foreground)]">Namespace</dt>
            <dd className="min-w-0">
              <code className="text-[var(--foreground)]">{request.namespace}</code>
              <span className="ml-1.5 text-[var(--muted-foreground)]">
                what a verifier must ask for — a <code>{request.namespace}</code>{" "}
                signature cannot be replayed under another namespace
              </span>
            </dd>
          </>
        ) : request.mode ? (
          <>
            <dt className="font-semibold text-[var(--muted-foreground)]">Mode</dt>
            <dd className="min-w-0 text-[var(--foreground)]">
              <code>{request.mode}</code>
            </dd>
          </>
        ) : null}
      </dl>

      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="ghost" onClick={() => onDecide("deny")}>
          Deny
        </Button>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => onDecide(forSession ? "session" : "once")}
        >
          Approve once
        </Button>
        <label className="flex items-center gap-1.5 text-[length:10.5px] text-[var(--muted-foreground)]">
          <input
            type="checkbox"
            checked={forSession}
            onChange={(e) => setForSession(e.currentTarget.checked)}
          />
          for this session (5 min)
        </label>
        {remaining > 0 ? (
          // §27d: offered only now, after a real payload and the loop's true
          // count have been shown — so a recipe cannot pre-authorize itself.
          <Button size="sm" variant="ghost" onClick={() => onDecide("run")}>
            Approve the remaining {remaining}
          </Button>
        ) : null}
      </div>
      {forSession ? (
        <p className="mt-1.5 text-[length:10px] text-[var(--warn)]">
          While this lasts, recipes in this notebook can {verb} with this key without
          asking. It expires in 5 minutes, and the Keyring row counts every use.
        </p>
      ) : null}
    </div>
  );
}
