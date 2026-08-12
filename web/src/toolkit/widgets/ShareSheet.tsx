import { useId, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { cn } from "@/lib/cn";
import { QrArtifact } from "./QrArtifact";

/** `hashForNotebook`'s answer, carried whole so the refusal keeps its reason. */
export type RecipeLink =
  | { ok: true; url: string }
  /**
   * `tone` because the two ways this fails are not alike. The secret guard
   * saying no is a refusal; an empty notebook having nothing to send is a
   * not-yet, and painting it red makes a blank page look like a fault.
   */
  | { ok: false; reason: string; tone?: "refused" | "not-yet" };

/**
 * One string for one condition — the section prints it and the button refuses
 * with it. Two copies would be two places for one sentence to drift, which is
 * what `artifact-reasons.js` exists to prevent one layer down.
 */
const NO_PROOF_YET =
  "No proof in this notebook yet — add run.manifest and run.receipt cells, then run it.";

export type ShareSheetProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  recipeLink: RecipeLink;
  onCopyRecipeLink?: () => void;
  /**
   * The link as a QR, or why it is not one.
   *
   * A QR holds roughly 2,950 bytes and a notebook link may be up to 6,000, so
   * "show a QR" is a request that can genuinely fail. It fails with a sentence
   * rather than a broken image, and the file fallback sits beside it, because
   * both are the same errand: getting the notebook across a gap with no
   * network on either side.
   */
  recipeQr?: { ok: true; svg: string } | { ok: false; reason: string } | null;
  /** Writes the notebook to a file — the air-gap path with no size limit. */
  onSaveRecipe?: () => void;
  /**
   * Start with the code shown. For a catalog, which cannot press the button —
   * the same reason `OtpCodeCard` takes an injectable `nowMs`. A QR that only
   * exists after a click is a QR no sheet can photograph, and the refusal is
   * the state most worth showing.
   */
  defaultQrOpen?: boolean;
  /** A finished run's proof. Absent means nothing has been run yet. */
  proof?: { manifest: string; receipt: string; signedBy?: string } | null;
  onExportProof?: () => void;
  /**
   * The live session. `joined` and `verified` are deliberately two numbers —
   * see the note on `Tier` below.
   */
  session?: {
    room: string;
    invite: string;
    joined: number;
    expected?: number;
    verified: number;
  } | null;
  onStartSession?: () => void;
  onCopyInvite?: () => void;
  className?: string;
};

/**
 * Share this notebook — three things, not one.
 *
 * "Share" is a single word covering three transfers that differ in what
 * actually crosses the wire, and therefore in what trust they need:
 *
 * - **The recipe** — text, in the URL fragment, which never reaches a server.
 *   No trust required; the reader gets an identical, unrun notebook.
 * - **A run's proof** — the signed manifest and receipt. Still nobody online;
 *   the reader needs your public key to check it.
 * - **The doing of it** — a live session where cells placed with `@peer`
 *   headers run on their own machine. **Nothing private moves at all**: only
 *   offers, results and attestations cross.
 *
 * One button covering all three would make the safe case and the case needing
 * mutual verification look identical at the moment of clicking. So each is its
 * own row, named by what moves.
 *
 * The recipe still travels by the first mechanism even when a session exists.
 * The session does not carry the notebook — both sides arrive at the same text
 * independently, which is what makes this a reproducible build rather than a
 * screen share, and it is the same layering as the quorum sitting on top of
 * the transport rather than replacing it.
 *
 * **An unavailable row says why.** Hiding the proof row until a run exists
 * teaches nobody what it is, and hiding the recipe row when the secret guard
 * refuses it looks like a bug. `hashForNotebook` already returns its reason;
 * this is the surface that keeps it rather than flashing it past in a status
 * line.
 */
export function ShareSheet({
  open,
  onOpenChange,
  recipeLink,
  onCopyRecipeLink,
  recipeQr,
  onSaveRecipe,
  defaultQrOpen = false,
  proof,
  onExportProof,
  session,
  onStartSession,
  onCopyInvite,
  className,
}: ShareSheetProps) {
  const [showQr, setShowQr] = useState(defaultQrOpen);
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className={className}
        onOpenAutoFocus={(e) => e.preventDefault()}
        data-share-sheet
      >
        <SheetHeader>
          <SheetTitle>Share this notebook</SheetTitle>
          <SheetDescription>
            Three different things, each needing different trust. Nothing here
            uploads the notebook.
          </SheetDescription>
        </SheetHeader>

        {/* Hoisted, because the tier that carries this sits third and fell
            below the fold — the one state this sheet exists to make visible
            was the one needing a scroll to find. The tiers stay in their
            order: they are a ladder of increasing trust, and shuffling the
            live session to the top when it happens to exist would make the
            sheet's structure change shape under the reader. The urgent fact
            gets promoted instead of the section that holds it. */}
        {session && session.verified < session.joined ? (
          <p
            className="rounded-[6px] border border-[var(--error)] px-2 py-1.5 text-[11px] text-[var(--error)]"
            data-unverified-warning
          >
            {session.joined - session.verified} of {session.joined} who joined
            are still unconfirmed. Confirmation is automatic and there is
            nothing for you to compare — until it lands, a label names nobody
            and no cell will run on them.
          </p>
        ) : null}

        <div className="flex flex-col gap-3 overflow-y-auto py-1">
          <Tier
            title="Send the recipe"
            what="The notebook text, carried in the link's fragment — it never reaches a server. They open an identical, unrun notebook."
            trust="No trust needed"
            blocked={recipeLink.ok ? null : recipeLink.reason}
            tone={recipeLink.ok ? undefined : (recipeLink.tone ?? "refused")}
            value={recipeLink.ok ? recipeLink.url : ""}
          >
            {(why) => (
              <>
                {/* `hashForNotebook`'s own words, carried whole: the secret
                    guard refusing and an empty notebook having nothing to send
                    are different states, and this row must not flatten them. */}
                <Button
                  onClick={onCopyRecipeLink}
                  disabledReason={recipeLink.ok ? undefined : recipeLink.reason}
                  reasonId={why}
                >
                  Copy link
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setShowQr((v) => !v)}
                  disabledReason={recipeLink.ok ? undefined : recipeLink.reason}
                  reasonId={why}
                  aria-expanded={showQr}
                >
                  {showQr ? "Hide QR" : "QR"}
                </Button>
                <Button
                  variant="outline"
                  onClick={onSaveRecipe}
                  disabledReason={recipeLink.ok ? undefined : recipeLink.reason}
                  reasonId={why}
                >
                  Save file
                </Button>
                {showQr ? <RecipeQr qr={recipeQr} /> : null}
              </>
            )}
          </Tier>

          <Tier
            title="Send what you ran"
            what="The signed manifest and receipt alongside the recipe, so they can check your run reproduced. Nobody needs to be online."
            trust="They need your public key to check it"
            blocked={proof ? null : NO_PROOF_YET}
            tone="not-yet"
            value={
              proof
                ? `manifest ${proof.manifest} · receipt ${proof.receipt}${
                    proof.signedBy ? ` · signed ${proof.signedBy}` : ""
                  }`
                : ""
            }
          >
            {(why) => (
              <Button
                onClick={onExportProof}
                disabledReason={proof ? undefined : NO_PROOF_YET}
                reasonId={why}
              >
                Export proof
              </Button>
            )}
          </Tier>

          <Tier
            title="Run it together"
            what="A live session. Cells you place on a peer run on their machine — no private value moves. The recipe still travels by the link above."
            trust="Both sides verify each other"
            blocked={null}
            value={session ? `room ${session.room}` : ""}
          >
            {() =>
              session ? (
                <>
                  <Button variant="outline" onClick={onCopyInvite}>
                    Copy invite
                  </Button>
                  <RosterCount
                    joined={session.joined}
                    verified={session.verified}
                    expected={session.expected}
                  />
                </>
              ) : (
                <Button onClick={onStartSession}>Start shared session</Button>
              )
            }
          </Tier>
        </div>
      </SheetContent>
    </Sheet>
  );
}

/**
 * The link as a scannable code, or the reason it is not one.
 *
 * The refusal is the interesting half. A QR tops out near 2,950 bytes and a
 * notebook link may be twice that, so a long notebook cannot cross an air gap
 * this way — and a broken image, or a code that scans to a truncated link,
 * would be a worse answer than a sentence. The sentence names the file
 * instead, which is the same errand without the size limit.
 *
 * White background, always. A QR is read by a camera, not by a person, and
 * inverting it under a dark theme is a real scanning failure rather than a
 * styling preference — `QrArtifact` renders the SVG the encoder produced.
 */
function RecipeQr({ qr }: { qr: ShareSheetProps["recipeQr"] }) {
  if (!qr) return null;
  if (!qr.ok) {
    return (
      <p className="w-full text-[10.5px] text-[var(--muted-foreground)]" data-qr-refused>
        {qr.reason}
      </p>
    );
  }
  return (
    <div className="w-full pt-1" data-qr>
      <QrArtifact content={qr.svg} label="this notebook's link" />
    </div>
  );
}

/**
 * One transfer.
 *
 * `blocked` is a sentence rather than a boolean because every way this can be
 * unavailable has a different reason a reader can act on, and "Export proof
 * (disabled)" tells them none of them.
 */
function Tier({
  title,
  what,
  trust,
  blocked,
  tone = "refused",
  value,
  children,
}: {
  title: string;
  what: string;
  trust: string;
  blocked: string | null;
  /**
   * Why it is unavailable, which is not one thing. `refused` is the guard
   * saying no — sharing this would hand over a key — and earns the error
   * colour. `not-yet` is an absence the reader has done nothing wrong to
   * cause; painting "nothing has been run yet" red makes an ordinary empty
   * state look like a fault.
   */
  tone?: "refused" | "not-yet";
  value: string;
  /**
   * A function of the blocked sentence's id, not a node, so this row's buttons
   * can point at the sentence the section already prints. Three buttons each
   * emitting their own copy of "no proof in this notebook yet" would be one
   * refusal said four times on one card.
   */
  children: (reasonId: string | undefined) => ReactNode;
}) {
  const blockedId = useId();
  return (
    <section
      className={cn(
        "flex flex-col gap-1.5 rounded-[8px] border border-[var(--border)] p-2.5",
        blocked && "opacity-70"
      )}
      data-tier={title}
      data-blocked={blocked ? "yes" : "no"}
    >
      <h4 className="text-[12.5px] font-semibold text-[var(--foreground)]">{title}</h4>
      <p className="text-[11px] leading-relaxed text-[var(--muted-foreground)]">{what}</p>
      {value ? (
        <code className="block truncate rounded-[6px] border border-[var(--border)] px-2 py-1 font-mono text-[10px] text-[var(--muted-foreground)]">
          {value}
        </code>
      ) : null}
      {blocked ? (
        <p
          id={blockedId}
          className={cn(
            "text-[10.5px]",
            tone === "refused" ? "text-[var(--error)]" : "text-[var(--muted-foreground)]"
          )}
          data-blocked-reason
          data-disabled-reason
          data-tone={tone}
        >
          {blocked}
        </p>
      ) : (
        <p className="text-[10px] text-[var(--muted-foreground)]">{trust}</p>
      )}
      <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
        {children(blocked ? blockedId : undefined)}
      </div>
    </section>
  );
}

/**
 * Joined and verified, as two numbers.
 *
 * They are never the same claim. Someone opening the invite link is *joined*;
 * what makes them *verified* is a `kc` frame whose transcript hash binds the
 * room id, both PGP fingerprints, both ephemeral ECDH keys and both DTLS
 * certificates — see `session-flow.js`, which owns every sentence this app says
 * about confirmation. A single "2 peers" hides exactly the gap an attacker
 * holding a forwarded link would sit in. The session layer already refuses to
 * place cells on an unverified peer; this is that distinction, said out loud,
 * at the moment the invite is being handed out.
 *
 * **Nothing here is read out by a person.** This note and the warning above it
 * both used to send the reader off to match a short code against their peer —
 * an errand no code path in this app produces and nobody could have completed.
 * `session-flow.js` states the absence three times over, and its guard covered
 * its own module, so the false instruction lived two files away for as long as
 * it took someone to read it. The guard now reads this file too.
 */
function RosterCount({
  joined,
  verified,
  expected,
}: {
  joined: number;
  verified: number;
  expected?: number;
}) {
  const pending = joined - verified;
  return (
    <span className="font-mono text-[10px] text-[var(--muted-foreground)]" data-roster-count>
      {joined} joined{expected ? ` of ${expected}` : ""} ·{" "}
      <span className={pending > 0 ? "text-[var(--error)]" : undefined}>
        {verified} verified
      </span>
      {pending > 0 ? ` · ${pending} still to confirm` : ""}
    </span>
  );
}
