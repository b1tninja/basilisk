import { useState } from "react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";
import { GateBanner, GateFact } from "./GateBanner";
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
 *
 * The chrome — border, ground, header, the 68px facts grid, the actions row —
 * now comes from `GateBanner` (§43a), shared with the tile's consequence
 * confirmations. Nothing about this component's behaviour moved with it: no
 * focus is taken on mount and Escape still does nothing here, both of which
 * were true before and neither of which a signing gate should acquire as a
 * side effect of a refactor.
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
    <GateBanner
      className={cn(className)}
      data-approval-ask={request.use}
      label={`${request.stepName} wants to use a key`}
      heading={
        <>
          <code>{request.stepName}</code> wants to use a key
        </>
      }
      meta={
        request.runTotal
          ? `request ${request.requestIndex} of ${request.runTotal} this run`
          : `request ${request.requestIndex} this run`
      }
      facts={
        <>
          <GateFact term="Step" detailClassName="break-all font-mono text-[var(--foreground)]">
            {request.cellIndex != null ? `cell ${request.cellIndex + 1} · ` : ""}
            {request.stepText}
          </GateFact>

          <GateFact term="Key">
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
          </GateFact>

          <GateFact term={request.use === "decrypt" ? "Ciphertext" : "Payload"}>
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
          </GateFact>

          {request.namespace ? (
            <GateFact term="Namespace">
              <code className="text-[var(--foreground)]">{request.namespace}</code>
              <span className="ml-1.5 text-[var(--muted-foreground)]">
                what a verifier must ask for — a <code>{request.namespace}</code>{" "}
                signature cannot be replayed under another namespace
              </span>
            </GateFact>
          ) : request.mode ? (
            <GateFact term="Mode" detailClassName="text-[var(--foreground)]">
              <code>{request.mode}</code>
            </GateFact>
          ) : null}
        </>
      }
      actions={
        <>
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
        </>
      }
      footnote={
        forSession ? (
          <p className="mt-1.5 text-[length:10px] text-[var(--warn)]">
            While this lasts, recipes in this notebook can {verb} with this key without
            asking. It expires in 5 minutes, and the Keyring row counts every use.
          </p>
        ) : null
      }
    />
  );
}
