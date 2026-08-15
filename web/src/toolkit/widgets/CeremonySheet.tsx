import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { formatFingerprint } from "../../lib/utils.js";
import { ShareCards, type ShareCardArtifact } from "./ShareCards";
import { ShareCheck } from "./ShareCheck";
import {
  CEREMONY_STAGES,
  ceremonyIssues,
  ceremonyNotes,
  nextStage,
  prevStage,
  stageIndex,
  verificationResult,
  type CeremonyStageId,
} from "../../lib/toolkit/ceremony.js";

export type CeremonyRunState = "idle" | "running" | "done" | "error";

export type CeremonySheetProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  stage: CeremonyStageId;
  onStage: (stage: CeremonyStageId) => void;
  /** Quorum + label, owned by the caller so the recipes stay reproducible. */
  threshold: number;
  shares: number;
  label: string;
  qr: boolean;
  onParams: (patch: {
    threshold?: number;
    shares?: number;
    label?: string;
    qr?: boolean;
  }) => void;
  /** Vault keys offered for signing the receipt. */
  signingKeys?: { fingerprint: string; uid?: string }[];
  signWith?: string;
  onSignWith?: (fingerprint: string) => void;
  /** Runs the cells this stage owns; resolves when the notebook has run. */
  onRunStage: (stage: CeremonyStageId) => void | Promise<void>;
  runState: CeremonyRunState;
  runError?: string;
  /** Digest hex from the split cell's `$expected` tile. */
  expectedDigest: string;
  /** Digest hex from the verify cell's `$recovered` tile. */
  recoveredDigest: string;
  shareArtifacts: ShareCardArtifact[];
  /** JSON from the split cell's `$commitments` tile — the public half. */
  commitmentsText?: string;
  /**
   * The signed playbook from the cards cell's `$playbook` tile.
   *
   * Separate from `receiptText` because they answer different questions and
   * leave the room by different routes: a receipt records what happened and
   * stays with the dealer, a playbook says what to do next and goes in the
   * envelope with the cards.
   */
  playbookText?: string;
  receiptText: string;
  /** `file.read | qr.scan`, supplied by the host; absent hides the scan button. */
  onScanQr?: () => Promise<string>;
};

/**
 * The guided key ceremony — a Sheet, per the handoff's rule that a design
 * needing a window is a `Sheet`.
 *
 * It owns sequence and wording, not execution: every stage's work is ordinary
 * notebook cells run through `useNotebook`, so the ceremony is reproducible by
 * hand, visible in Source view, and shareable as recipe text. This component
 * never touches the engine.
 *
 * The order is the product. Verification sits before printing because proving
 * the shares recombine after the room has dispersed is not a ceremony, and the
 * verify panel reports a match from two SHA-256 digests without ever putting
 * the secret back on screen.
 */
export function CeremonySheet({
  open,
  onOpenChange,
  stage,
  onStage,
  threshold,
  shares,
  label,
  qr,
  onParams,
  signingKeys = [],
  signWith = "",
  onSignWith,
  onRunStage,
  runState,
  runError = "",
  expectedDigest,
  recoveredDigest,
  shareArtifacts,
  commitmentsText = "",
  playbookText = "",
  receiptText,
  onScanQr,
}: CeremonySheetProps) {
  const [advanced, setAdvanced] = useState(false);
  const [checking, setChecking] = useState(false);
  const [showPlaybook, setShowPlaybook] = useState(false);
  const issues = ceremonyIssues({ threshold, shares });
  const current = CEREMONY_STAGES[stageIndex(stage)] ?? CEREMONY_STAGES[0];
  const verification = verificationResult(expectedDigest, recoveredDigest);
  const busy = runState === "running";

  /**
   * Why this stage will not hand over to the next — a sentence, not a boolean.
   *
   * It was `canAdvance`, and every stage collapsed a different situation into
   * the same dead button: an impossible threshold, a split that had not run, a
   * digest that did not match. The last of those is the one that mattered — a
   * mismatch means *do not distribute these cards*, and the control that knew
   * it said nothing at all. Each branch now speaks in the words its own stage
   * already uses, so the button and the panel above it cannot disagree.
   */
  const advanceIssue: string | null =
    stage === "setup"
      ? issues.length
        ? issues.join(" ")
        : null
      : stage === "split"
        ? expectedDigest
          ? null
          : "The split has not produced a digest of the original secret yet, and the next step is a comparison against it. Run this stage first."
        : stage === "verify"
          ? verification.status === "match"
            ? null
            : verification.message
          : stage === "cards"
            ? null
            : "This is the last stage — there is nothing after the receipt.";

  /**
   * A stage's cells are running. Separate from `advanceIssue` because it is a
   * different kind of no: nothing is wrong and nothing needs fixing, the answer
   * simply is not in yet. The wording is the stage's own status line.
   */
  const runningNote = busy
    ? `${
        CEREMONY_STAGES[stageIndex(stage)]?.title ?? "This stage"
      } is still running. Its cells decide what the next stage is given, so it has to finish first.`
    : null;

  const advanceLabel =
    stage === "setup"
      ? "Start the split"
      : stage === "split"
        ? "Prove the shares work"
        : stage === "verify"
          ? "Print the cards"
          : stage === "cards"
            ? "Sign a receipt"
            : "";

  const goNext = () => {
    const next = nextStage(stage);
    if (!next) return;
    onStage(next);
    const meta = CEREMONY_STAGES[stageIndex(next)];
    if (meta?.runsCells) void onRunStage(next);
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Key ceremony</SheetTitle>
          <SheetDescription>
            Split a fresh secret into shares, prove they recombine without showing it
            again, print a card per holder, and sign a receipt of what happened.
          </SheetDescription>
        </SheetHeader>

        <ol className="ceremony-steps">
          {CEREMONY_STAGES.map((s, i) => {
            const at = stageIndex(stage);
            const state = i < at ? "done" : i === at ? "current" : "todo";
            return (
              <li key={s.id} className="ceremony-step" data-state={state}>
                <span className="ceremony-step-dot">{i + 1}</span>
                <span className="ceremony-step-title">{s.title}</span>
              </li>
            );
          })}
        </ol>

        <Separator />

        <div className="ceremony-body">
          <h3 className="ceremony-stage-title">{current.title}</h3>
          <p className="ceremony-stage-blurb">{current.blurb}</p>

          {stage === "setup" ? (
            <div className="ceremony-fields">
              <label className="ceremony-field">
                <span>Ceremony label</span>
                <Input
                  value={label}
                  placeholder="Board key, Q3 root key, room name…"
                  onChange={(e) => onParams({ label: e.target.value })}
                />
                <small>Printed on every card and recorded in the receipt.</small>
              </label>

              <div className="ceremony-quorum">
                <label className="ceremony-field">
                  <span>Shares to make</span>
                  <Input
                    type="number"
                    min={2}
                    max={16}
                    value={shares}
                    onChange={(e) => onParams({ shares: Number(e.target.value) })}
                  />
                </label>
                <label className="ceremony-field">
                  <span>Needed to recover</span>
                  <Input
                    type="number"
                    min={1}
                    max={16}
                    value={threshold}
                    onChange={(e) => onParams({ threshold: Number(e.target.value) })}
                  />
                </label>
              </div>

              {/*
                Only stated for a quorum that can exist. Rendering it
                unconditionally put "Any 5 of 3 cards will reconstruct the
                secret" on screen beside the error saying it cannot — the
                summary must never restate an impossible quorum as fact.
              */}
              {issues.length ? null : (
                <p className="ceremony-quorum-note">
                  Any <strong>{threshold}</strong> of <strong>{shares}</strong> cards will
                  reconstruct the secret. Fewer than {threshold} reveal nothing at all.
                </p>
              )}

              {/*
                A legal quorum can still deserve a warning: K-of-K recombines
                and has no redundancy at all, and the word "quorum" invites the
                reader to assume some. `ceremonyNotes` owns the sentence so the
                compiler-side refusals and this note come from one module.
              */}
              {ceremonyNotes({ threshold, shares }).map((note) => (
                <p key={note} className="ceremony-quorum-note" data-tone="warn">
                  {note}
                </p>
              ))}

              <label className="ceremony-toggle">
                <input
                  type="checkbox"
                  checked={qr}
                  onChange={(e) => onParams({ qr: e.target.checked })}
                />
                <span>Print a QR code beside each mnemonic</span>
              </label>

              {issues.length ? (
                <ul className="ceremony-issues">
                  {issues.map((i) => (
                    <li key={i}>{i}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}

          {stage === "split" ? (
            <div className="ceremony-panel">
              {busy ? <p className="ceremony-status">Drawing and splitting…</p> : null}
              {expectedDigest ? (
                <>
                  <p className="ceremony-status" data-tone="ok">
                    {shareArtifacts.filter((a) => a.role === "share").length} shares
                    created. The secret itself was never written to a tile — only its
                    digest.
                  </p>
                  <dl className="ceremony-digest">
                    <dt>Digest of the secret</dt>
                    <dd>
                      <code>{expectedDigest}</code>
                    </dd>
                  </dl>
                  {/*
                    The public half, stated as an instruction rather than shown
                    as an artifact. Commitments that stay in the notebook make
                    the split verifiable in principle and unverifiable in
                    practice — a custodian cannot check a share against a
                    document they were never given, and this is the only moment
                    where everyone who needs it is still in the room.
                  */}
                  {commitmentsText ? (
                    <div className="ceremony-commitments">
                      <p className="ceremony-status" data-tone="pending">
                        Publish these commitments. They reveal nothing about the secret
                        and they are what lets each holder check their own card later,
                        alone, without any other share. Send them by a different route
                        than the cards.
                      </p>
                      <pre className="ceremony-receipt">{commitmentsText}</pre>
                    </div>
                  ) : null}
                </>
              ) : null}
            </div>
          ) : null}

          {stage === "verify" ? (
            <div className="ceremony-panel">
              {busy ? <p className="ceremony-status">Recombining the shares…</p> : null}
              <p className="ceremony-status" data-tone={
                verification.status === "match"
                  ? "ok"
                  : verification.status === "mismatch"
                    ? "error"
                    : "pending"
              }>
                {verification.message}
              </p>
              <dl className="ceremony-digest">
                <dt>Original</dt>
                <dd>
                  <code>{verification.expected || "—"}</code>
                </dd>
                <dt>Recombined</dt>
                <dd>
                  <code>{verification.recovered || "—"}</code>
                </dd>
              </dl>
              {verification.status === "mismatch" ? (
                <Button variant="secondary" onClick={() => void onRunStage("verify")}>
                  Try again
                </Button>
              ) : null}
            </div>
          ) : null}

          {stage === "cards" ? (
            <div className="ceremony-panel">
              <ShareCards
                artifacts={shareArtifacts}
                label={label}
                threshold={threshold}
                commitments={commitmentsText || null}
              />
              {/*
                The rehearsal. Verification at stage 3 proved the *set*
                recombines; this proves one card, the way its holder will have
                to prove it — alone, from the printed words, against the
                published commitments. Doing it once here is how a custodian
                learns the check exists at all, and it is the last moment the
                dealer is available to answer for a card that fails.
              */}
              <button
                type="button"
                className="ceremony-disclosure"
                onClick={() => setChecking((v) => !v)}
              >
                {checking ? "Hide" : "Check a card the way its holder will"}
              </button>
              {checking ? (
                <ShareCheck
                  initialCommitments={commitmentsText}
                  onScanQr={onScanQr}
                />
              ) : null}

              {/*
                The playbook. A card names the split, the threshold and the op
                that recombines; it has no room for the order of the steps or
                what to do with the secret once it is back, and that is what a
                custodian is missing years later when the dealer is gone. It
                prints with the cards because the envelope is the only storage
                that outlives the browser, the machine and the author.
              */}
              <div className="ceremony-playbook">
                {playbookText ? (
                  <>
                    <p className="ceremony-status" data-tone="ok">
                      Playbook written. It holds the recipe and the instructions —
                      no shares, no secret, no fingerprints. Print it and put it in
                      the envelope with the cards.
                    </p>
                    <button
                      type="button"
                      className="ceremony-disclosure"
                      onClick={() => setShowPlaybook((v) => !v)}
                    >
                      {showPlaybook ? "Hide" : "Show"} playbook
                    </button>
                    {showPlaybook ? (
                      <pre className="ceremony-receipt">{playbookText}</pre>
                    ) : null}
                  </>
                ) : (
                  <>
                    <p className="ceremony-status" data-tone="pending">
                      No playbook yet. Without one the cards say <em>what</em> they
                      are and nothing says <em>how</em> to use them.
                    </p>
                    <Button
                      variant="secondary"
                      onClick={() => void onRunStage("cards")}
                      busy={busy}
                    >
                      Write the playbook
                    </Button>
                  </>
                )}
              </div>
            </div>
          ) : null}

          {stage === "receipt" ? (
            <div className="ceremony-panel">
              {signingKeys.length ? (
                <label className="ceremony-field">
                  <span>Sign with</span>
                  <select
                    className="ceremony-select"
                    value={signWith}
                    onChange={(e) => onSignWith?.(e.target.value)}
                  >
                    <option value="">Do not sign</option>
                    {/* The other place a fingerprint is not a control: an
                        `<option>` is text and cannot hold one. It carries the
                        whole value instead of the last sixteen characters,
                        which is the rule that actually mattered here. */}
                    {signingKeys.map((k) => (
                      <option key={k.fingerprint} value={k.fingerprint}>
                        {k.uid || formatFingerprint(k.fingerprint)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <p className="ceremony-status" data-tone="pending">
                  No unlocked key — the receipt will be made unsigned. An unsigned
                  receipt is still a usable record.
                </p>
              )}

              {busy ? <p className="ceremony-status">Writing the receipt…</p> : null}

              {receiptText ? (
                <>
                  <p className="ceremony-status" data-tone="ok">
                    Receipt written. It holds the recipe, timestamps, and a digest of
                    every output — no shares, no secret.
                  </p>
                  <button
                    type="button"
                    className="ceremony-disclosure"
                    onClick={() => setAdvanced((v) => !v)}
                  >
                    {advanced ? "Hide" : "Show"} receipt
                  </button>
                  {advanced ? (
                    <pre className="ceremony-receipt">{receiptText}</pre>
                  ) : null}
                </>
              ) : (
                <Button onClick={() => void onRunStage("receipt")} busy={busy}>
                  Write the receipt
                </Button>
              )}
            </div>
          ) : null}

          {runError ? (
            <p className="ceremony-status" data-tone="error">
              {runError}
            </p>
          ) : null}
        </div>

        <SheetFooter>
          {prevStage(stage) ? (
            <Button
              variant="secondary"
              onClick={() => onStage(prevStage(stage) as CeremonyStageId)}
              // Not `busy`: Back is not what is running. Going back mid-stage
              // would leave cells writing into a stage the reader has left.
              disabledReason={runningNote ?? undefined}
            >
              Back
            </Button>
          ) : null}
          {advanceLabel ? (
            <Button onClick={goNext} disabledReason={runningNote ?? advanceIssue ?? undefined}>
              {advanceLabel}
            </Button>
          ) : (
            <Button onClick={() => onOpenChange(false)}>Done</Button>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
