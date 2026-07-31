import { useCallback, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  checkShare,
  shareCheckRecipe,
  type ShareCheckVerdict,
} from "../../lib/toolkit/share-check.js";
import { qrScanSupported } from "../../lib/toolkit/qr-scan.js";

export type ShareCheckProps = {
  /** Prefilled when the ceremony hands a custodian straight into the check. */
  initialShare?: string;
  initialCommitments?: string;
  /**
   * `file.read | qr.scan` on a photo of the card. Supplied by the host so this
   * widget stays free of engine calls; absent means the button is not offered.
   */
  onScanQr?: () => Promise<string>;
  /** Overridden only by the catalog, which has no `BarcodeDetector` to speak of. */
  scanSupported?: boolean;
};

/**
 * The custodian verification surface.
 *
 * Someone is holding one card, months after the room emptied, on a machine
 * with no notebook state. The panel answers one question and refuses to imply
 * it has answered more than that — see `lib/toolkit/share-check.js`, which owns
 * every verdict string, for why "well-formed" and "genuine" are kept violently
 * apart.
 *
 * Three things are deliberate in the layout:
 *
 * - **The verdict is above the fields, not below them.** The custodian is here
 *   for one sentence; making them scroll past their own secret to reach it
 *   inverts the priority.
 * - **The share field is `type=password`-ish only in spirit** — it is a
 *   textarea holding words the custodian is reading off paper in front of
 *   them, and masking input they are actively transcribing produces errors
 *   rather than privacy. The reveal gate exists for artifacts the toolkit
 *   *produced*; this is input the person already has.
 * - **The equivalent recipe is shown, always.** A custodian who does not trust
 *   a form should be able to run the same check as notebook cells; a custodian
 *   who does trust it should still see that the form is not doing anything
 *   else.
 */
export function ShareCheck({
  initialShare = "",
  initialCommitments = "",
  onScanQr,
  scanSupported,
}: ShareCheckProps) {
  const [shareText, setShareText] = useState(initialShare);
  const [commitmentsText, setCommitmentsText] = useState(initialCommitments);
  const [scanError, setScanError] = useState("");
  const [scanning, setScanning] = useState(false);

  const verdict: ShareCheckVerdict = useMemo(
    () => checkShare({ shareText, commitmentsText }),
    [shareText, commitmentsText]
  );

  const canScan = scanSupported ?? qrScanSupported();

  const scan = useCallback(async () => {
    if (!onScanQr) return;
    setScanError("");
    setScanning(true);
    try {
      setShareText(await onScanQr());
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
    }
  }, [onScanQr]);

  return (
    <section className="share-check" data-status={verdict.status}>
      <p className="share-check-verdict" data-tone={verdict.tone}>
        <strong className="share-check-headline">
          {verdict.headline || "Nothing to check yet."}
        </strong>
        <span className="share-check-detail">{verdict.detail}</span>
      </p>

      {verdict.share || verdict.split ? (
        <dl className="share-check-facts">
          {verdict.share ? (
            <>
              <dt>Card</dt>
              <dd>
                share {verdict.share.index} of {verdict.share.total} · any{" "}
                {verdict.share.threshold} recombine · set{" "}
                <code>{verdict.share.setId}</code>
              </dd>
            </>
          ) : null}
          {verdict.split ? (
            <>
              <dt>Split</dt>
              <dd>
                <code>{verdict.split.splitId}</code> · degree {verdict.split.degree}
              </dd>
            </>
          ) : null}
        </dl>
      ) : null}

      <label className="share-check-field">
        <span>
          Your share
          <small>The words printed on the card. They stay on this device.</small>
        </span>
        <Textarea
          className="share-check-input"
          rows={3}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          value={shareText}
          placeholder="acid academic acne …"
          onChange={(e) => setShareText(e.target.value)}
        />
      </label>

      {onScanQr ? (
        <div className="share-check-scan">
          {canScan ? (
            <Button variant="secondary" onClick={() => void scan()} disabled={scanning}>
              {scanning ? "Reading…" : "Scan a photo of the card"}
            </Button>
          ) : (
            <p className="share-check-note" data-tone="warn">
              This browser cannot read QR codes — it has no <code>BarcodeDetector</code>,
              which today means anything other than Chrome or Edge. Type the words instead;
              the checksum will catch a slip.
            </p>
          )}
          {scanError ? (
            <p className="share-check-note" data-tone="error">
              {scanError}
            </p>
          ) : null}
        </div>
      ) : null}

      <label className="share-check-field">
        <span>
          Published commitments
          <small>
            Public by design — the ceremony was supposed to hand these out openly, by a
            different route than the cards.
          </small>
        </span>
        <Textarea
          className="share-check-input"
          rows={4}
          spellCheck={false}
          value={commitmentsText}
          placeholder='{"v":1,"commitments":["02…","03…"]}'
          onChange={(e) => setCommitmentsText(e.target.value)}
        />
      </label>

      <details className="share-check-recipe">
        <summary>Do this by hand instead</summary>
        <p>
          The panel runs the same op a notebook cell would. Paste your share into the{" "}
          <code>shares</code> panel, the commitments into <code>@commitments</code>, and run:
        </p>
        <pre>{shareCheckRecipe()}</pre>
      </details>
    </section>
  );
}
