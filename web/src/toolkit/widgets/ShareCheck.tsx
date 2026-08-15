import { useCallback, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  checkShare,
  shareCheckRecipe,
  type ShareCheckVerdict,
  type ShareScheme,
} from "../../lib/toolkit/share-check.js";
import { qrScanSupported } from "../../lib/toolkit/qr-scan.js";
import { ModeToggle } from "./ModeToggle";

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
  /**
   * Which road to open on, when the caller knows better than the default.
   *
   * The default reads the evidence — commitments in hand means a checkable
   * split — and that is right for every real caller, so this exists for the
   * catalog, which has to draw both roads for the *same* fixture in order to
   * show them side by side. A ceremony handing a custodian in passes nothing
   * and gets the split it actually dealt.
   */
  initialScheme?: ShareScheme;
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
  initialScheme,
}: ShareCheckProps) {
  const [shareText, setShareText] = useState(initialShare);
  const [commitmentsText, setCommitmentsText] = useState(initialCommitments);
  const [scanError, setScanError] = useState("");
  const [scanning, setScanning] = useState(false);
  /**
   * Which kind of split dealt the card — asked, because the card cannot say.
   *
   * `share-check.js` carries the argument: `vss.split` and `sss.split` emit the
   * same share shape and go through the same BLIP39 encoder, so the mnemonic
   * has no scheme field and no amount of reading it will produce one.
   *
   * The opening position is the evidence, not a guess. Arriving with
   * commitments in hand is only possible for a checkable split — the ceremony
   * hands a custodian straight in with them — so that starts on the VSS road.
   * Arriving with nothing but a card starts on the SSS road, because that is
   * the ceremony this product ships: `room-ceremony.js` deals with
   * `sss.split`, and defaulting the other way is what sent every custodian it
   * produced looking for a document that does not exist.
   */
  const [scheme, setScheme] = useState<ShareScheme>(
    initialScheme || (initialCommitments ? "vss" : "sss")
  );

  const verdict: ShareCheckVerdict = useMemo(
    () => checkShare({ shareText, commitmentsText, scheme }),
    [shareText, commitmentsText, scheme]
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
    <section className="share-check" data-status={verdict.status} data-scheme={scheme}>
      <p className="share-check-verdict" data-tone={verdict.tone}>
        <strong className="share-check-headline">
          {verdict.headline || "Nothing to check yet."}
        </strong>
        <span className="share-check-detail">{verdict.detail}</span>
      </p>

      {/* **The question the panel used to answer by assuming.** It sits above
          the fields rather than beside the commitments box because it decides
          whether that box is drawn at all — a control that changes what is on
          screen has to be readable before the thing it removes.

          The labels name the op, not a piece of jargon: a custodian may not
          know "verifiable secret sharing" but the ceremony they attended
          printed a recipe, and `sss.split` / `vss.split` is what was in it.
          The line under it says the consequence in plain words, because that
          is what the choice is really about — whether a document exists. */}
      <fieldset className="share-check-scheme" data-share-check-scheme>
        <legend>Which split dealt this card?</legend>
        <ModeToggle
          value={scheme}
          ariaLabel="Which split dealt this card"
          options={[
            {
              value: "sss",
              label: "sss.split",
              title: "Plain Shamir — no commitments were published",
            },
            {
              value: "vss",
              label: "vss.split",
              title: "Verifiable — the dealer published commitments",
            },
          ]}
          onChange={(v) => setScheme(v as ShareScheme)}
        />
        <small>
          {scheme === "sss"
            ? "Plain Shamir. There are no commitments for this card and there never will be, so nothing here can check it against the split it came from. What is below is what the card says about itself."
            : "Verifiable. The dealer published commitments by some other route; paste them below and the check is real arithmetic against them, run here."}
        </small>
      </fieldset>

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
            <Button variant="secondary" onClick={() => void scan()} busy={scanning}>
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

      {/* Not drawn on the plain-Shamir road at all. The old label stated as
          settled fact that the ceremony "was supposed to hand these out
          openly", and for every card `room-ceremony.js` deals that was never
          true — so the field asked for a document that does not exist, under a
          sentence blaming whoever ran the ceremony for not sending it. A field
          nobody can fill is a remedy nobody can perform, and the honest form
          of it is its absence. */}
      {scheme === "vss" ? (
        <label className="share-check-field">
          <span>
            Published commitments
            <small>
              Public by design — a verifiable split hands these out openly, by a different
              route than the cards.
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
      ) : null}

      {/* Two different offers under one fold, because the two roads have
          different next acts. On the VSS road this is the panel's own
          arithmetic written out, so a custodian who distrusts the form can run
          it. On the SSS road there is no check to write out — so what is
          printed is the *recovery*, which is the thing that can actually be
          done with cards and the one place the deal's `$expected` digest gets
          compared against anything. */}
      <details className="share-check-recipe">
        <summary>Do this by hand instead</summary>
        {scheme === "vss" ? (
          <p>
            The panel runs the same op a notebook cell would. Paste your share into the{" "}
            <code>shares</code> panel, the commitments into <code>$commitments</code>, and run:
          </p>
        ) : (
          <p>
            There is no single-card check to run — this is the recovery instead, for when
            enough holders are together. Paste every card into the <code>shares</code> panel
            and run it; <code>$recovered</code> is a SHA-256 of the result, which is what the
            deal&apos;s <code>$expected</code> is there to be compared against. It proves the
            recombination, not any one card.
          </p>
        )}
        <pre>{shareCheckRecipe(scheme)}</pre>
      </details>
    </section>
  );
}
