import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  checkLine,
  collectShareCards,
  quorumLine,
  recoveryLine,
  revealWarning,
  type ShareCard,
} from "../../lib/toolkit/share-cards.js";

export type ShareCardArtifact = {
  label?: string;
  filename?: string;
  content?: string;
  role?: string;
  sensitive?: boolean;
  shareIndex?: number;
  mime?: string;
  traits?: { shareOf?: number; threshold?: number };
};

export type ShareCardsProps = {
  artifacts: ShareCardArtifact[];
  /** Ceremony / room label printed on every card. */
  label?: string;
  /** Overrides the split's own threshold when the recipe did not record one. */
  threshold?: number;
  /**
   * The published commitments, when the caller knows where its own tile is.
   * Omitted, they are looked for among `artifacts`.
   */
  commitments?: string[] | string | null;
  date?: string;
  /**
   * Start revealed. Only for the widget catalog — the production surface always
   * begins masked so that reaching the cleartext takes a deliberate click.
   */
  defaultRevealed?: boolean;
  onPrint?: () => void;
};

/**
 * Print-ready cards for a split's shares — one card per share, each carrying
 * its mnemonic, QR, index, threshold, ceremony label, and date.
 *
 * This is an **explicit reveal surface**, and the only one in the toolkit that
 * exists to put a secret on paper. Everything about it is arranged around that:
 * the cards render masked, the button that unmasks them states plainly what
 * printing does (spooling, print servers) rather than saying "Show", and
 * `Print` is only reachable once revealed. The reveal is per-mount — navigating
 * away and back re-arms it, because "I already agreed once" is not a thing a
 * ceremony should remember.
 *
 * Layout is CSS-only (`toolkit.css`, `.share-card*` plus its `@media print`
 * block): no inline styles, so the production CSP cannot break the one view
 * whose entire job is to render correctly on a page you cannot re-open.
 */
export function ShareCards({
  artifacts,
  label = "",
  threshold,
  commitments = null,
  date,
  defaultRevealed = false,
  onPrint,
}: ShareCardsProps) {
  const [revealed, setRevealed] = useState(defaultRevealed);
  const cards: ShareCard[] = useMemo(
    () => collectShareCards(artifacts, { label, threshold, date, commitments }),
    [artifacts, label, threshold, date, commitments]
  );

  if (!cards.length) {
    return (
      <p className="share-cards-empty">
        No shares in this cell yet — run a split (<code>sss.split … | blip39 | foreach</code>)
        first.
      </p>
    );
  }

  return (
    <section className="share-cards" data-revealed={revealed ? "yes" : "no"}>
      <header className="share-cards-bar">
        <div className="share-cards-bar-text">
          <strong>
            {cards.length} share {cards.length === 1 ? "card" : "cards"}
            {label ? ` · ${label}` : ""}
          </strong>
          <p className="share-cards-warning">{revealWarning(cards.length)}</p>
        </div>
        <div className="share-cards-actions">
          {revealed ? (
            <>
              <Button
                variant="secondary"
                onClick={() => setRevealed(false)}
                aria-label="Hide share mnemonics"
              >
                Hide
              </Button>
              <Button onClick={() => (onPrint ? onPrint() : window.print())}>
                Print cards
              </Button>
            </>
          ) : (
            <Button variant="secondary" onClick={() => setRevealed(true)}>
              Reveal for printing
            </Button>
          )}
        </div>
      </header>

      <ol className="share-card-sheet">
        {cards.map((card) => (
          <li className="share-card" key={card.index}>
            <div className="share-card-head">
              <span className="share-card-index">
                {card.index}
                <span className="share-card-of">/{card.total}</span>
              </span>
              <div className="share-card-meta">
                <span className="share-card-label">{card.label || "Key ceremony"}</span>
                <span className="share-card-date">{card.date}</span>
              </div>
            </div>

            <p className="share-card-quorum">{quorumLine(card)}</p>
            {/* The split id is printed whether or not the set is verifiable, so
                the absence of one is itself legible on paper: a card with no
                split line came from a split nobody can check. */}
            <p className="share-card-split" data-verifiable={card.verifiable ? "yes" : "no"}>
              {card.verifiable ? (
                <>
                  Split <code>{card.splitId}</code>
                </>
              ) : (
                "Unverifiable split"
              )}
            </p>

            <div className="share-card-body">
              {card.qrSvg ? (
                <div
                  className="share-card-qr"
                  aria-label={`QR code for share ${card.index}`}
                  // The SVG is produced by our own `qr` op from our own bytes —
                  // it never round-trips through a network or the clipboard, so
                  // this is not untrusted markup. Rendering it as an <img> with
                  // a data: URI would be blocked by the production CSP.
                  dangerouslySetInnerHTML={{ __html: card.qrSvg }}
                />
              ) : (
                <div className="share-card-qr share-card-qr-missing">
                  <span>
                    no QR — add <code>qr</code> to the foreach body
                  </span>
                </div>
              )}
              <div className="share-card-mnemonic">
                {revealed ? (
                  <code>{card.mnemonic}</code>
                ) : (
                  <span className="share-card-masked">
                    {card.mnemonic
                      .split(/\s+/)
                      .map(() => "••••")
                      .join(" ")}
                  </span>
                )}
              </div>
            </div>

            <footer className="share-card-foot">
              <span className="share-card-check">{checkLine(card)}</span>
              <span>
                Recover with any {card.threshold > 0 ? card.threshold : "K"} cards:
                <code> {recoveryLine(card)}</code>
              </span>
            </footer>
          </li>
        ))}
      </ol>
    </section>
  );
}
