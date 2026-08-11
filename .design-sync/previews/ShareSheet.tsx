import { ShareSheet } from "basilisk-portal";

/*
 * Share this notebook — three transfers, named by what actually moves.
 *
 * The reason this is not one button: the recipe is text and needs no trust, a
 * proof needs your public key to check, and a live session needs both sides to
 * verify each other. One "Share" would make the safe case and the case
 * requiring mutual verification look identical at the moment of clicking.
 *
 * Every cell renders `open` — a closed sheet photographs as an empty frame —
 * and suppresses autofocus so the first control is not captured mid-focus.
 *
 * The refusal strings are real. `hashForNotebook` returns `{ok: false, reason}`
 * for a notebook it will not put in a URL, and today that reason flashes past
 * in a status line; here it is a state the row keeps.
 */

const LINK = {
  ok: true as const,
  url: "https://basilisk.pages.dev/toolkit#n=eJyrVkrLz1eyUlAqSS0uKUpNzlaqBQAyMwZ9",
};

const PROOF = {
  manifest: "4C1D-9E07-B8A2",
  receipt: "9F86-D081-884C",
  signedBy: "@ada",
};

/**
 * A notebook nobody has run yet, with no session. The recipe can go out
 * immediately; the proof row explains that a proof describes a run that
 * happened, rather than sitting there greyed and unexplained; and the session
 * is offered.
 */
export const Default = () => (
  <ShareSheet open onOpenChange={() => {}} recipeLink={LINK} onStartSession={() => {}} />
);

/**
 * The secret guard has refused the link.
 *
 * `recipeLooksSecret` catches private armor, a private JWK, and a fingerprint
 * written where a peer belongs. This is the one row that must never quietly
 * disable itself: a notebook that cannot be shared because it contains a key
 * is a fact the author needs, and the remedy is theirs to choose.
 */
export const RecipeRefused = () => (
  <ShareSheet
    open
    onOpenChange={() => {}}
    recipeLink={{
      ok: false,
      reason:
        "This notebook has a PGP private key block in it — a link carries the text, so sharing it would hand over the key. Move it to a slot with agent.unlock first.",
    }}
    onStartSession={() => {}}
  />
);

/**
 * After a run. The proof row now carries the manifest and receipt digests and
 * who signed them, which is the whole of what a reader needs to check the run
 * reproduced without anybody being online.
 */
export const AfterARun = () => (
  <ShareSheet
    open
    onOpenChange={() => {}}
    recipeLink={LINK}
    proof={PROOF}
    onExportProof={() => {}}
    onStartSession={() => {}}
  />
);

/**
 * **The state this sheet exists to make visible.** Two people have opened the
 * invite and neither has been verified.
 *
 * A single "2 peers" would read as success. Joined and verified are different
 * claims, and the gap between them is exactly where somebody holding a
 * forwarded link sits — so the count says both numbers and colours the
 * shortfall. The session layer already refuses to place cells on an unverified
 * peer; this is that refusal said out loud while the invite is being handed
 * out, rather than discovered later when a run will not start.
 */
export const SessionJoinedNotVerified = () => (
  <ShareSheet
    open
    onOpenChange={() => {}}
    recipeLink={LINK}
    proof={PROOF}
    session={{
      room: "KJ8X…9FQ",
      invite: "https://basilisk.pages.dev/toolkit#s=KJ8X4M2Q7T9FQ&k=mDMEZHhhDBYJKwYB",
      joined: 2,
      expected: 3,
      verified: 0,
    }}
    onCopyInvite={() => {}}
    onExportProof={() => {}}
  />
);

/**
 * Everyone verified. The count stops colouring anything and drops the "still
 * to confirm" clause — there is nothing outstanding to name, and a warning
 * that never clears is a warning nobody reads.
 */
export const SessionVerified = () => (
  <ShareSheet
    open
    onOpenChange={() => {}}
    recipeLink={LINK}
    proof={PROOF}
    session={{
      room: "KJ8X…9FQ",
      invite: "https://basilisk.pages.dev/toolkit#s=KJ8X4M2Q7T9FQ&k=mDMEZHhhDBYJKwYB",
      joined: 3,
      expected: 3,
      verified: 3,
    }}
    onCopyInvite={() => {}}
    onExportProof={() => {}}
  />
);
