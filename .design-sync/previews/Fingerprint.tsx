import { Fingerprint } from "basilisk-portal";

/*
 * A fingerprint, and the argument for why it never appears in halves.
 *
 * The product used to print `AABBCCDD…EEFF` in six places while the search page
 * told the same reader that "short (8-character) key IDs are collision-prone —
 * confirm the full fingerprint out of band before trusting a key". Twelve hex
 * characters is 48 bits rather than 32, which is 65 536× more work for an
 * attacker and still not a margin to stake a key exchange on. The decisive
 * problem is not the arithmetic though: the form shows the two ends, which are
 * exactly the characters people read to each other, and says nothing about the
 * 112 bits behind the ellipsis. Whatever number were chosen, a form built from
 * the key's own characters is a form that gets compared — and the comparison is
 * of a part while the reader believes it was of the whole.
 *
 * So there are two states and no third. `Whole` prints every character.
 * `Compact` prints a name the row already had and **nothing derived from the
 * key**, which is why `label` is required by the type rather than optional: a
 * caller with no name for a key has no compact form, deliberately. "It fits the
 * column" is the argument that produced the elided form in the first place.
 *
 * In both states pressing the value copies the whole fingerprint — never what
 * is on screen — and the menu is where the actions live: the keyserver page,
 * the local trust mark, and adding the key to a room being assembled.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
/** A v6 fingerprint — 64 characters, and the same rules. */
const V6 = "1AE7F1E4B2C6D0938A5F47B3C1D9E2064F8A3B5C7D1E9F02A4B6C8D0E2F41537";
/** What `ssh-keygen -lf` prints, which is a fingerprint of another shape. */
const SSH = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

/**
 * The default, and what most surfaces use: all forty characters, grouped in
 * fours the way this product has always printed a fingerprint, wrapping rather
 * than clipping. `overflow-wrap`, never `text-overflow: ellipsis` — a clipped
 * fingerprint is the elided form with the browser holding the knife, a prefix
 * whose length depends on the window.
 */
export const Whole = () => <Fingerprint fpr={ADA} />;

/**
 * A v6 key. Sixty-four characters, on a component that has no opinion about how
 * many there are: the sentence after a copy counts them and says so.
 */
export const V6Key = () => <Fingerprint fpr={V6} />;

/**
 * The dense case — a roster row, where the elided form was always argued for.
 *
 * `peer2` is the label a cell header addresses (`@peer2`), stable across every
 * machine in the room because it is ordered by the canonical audience. It names
 * the key without being derived from it, so it can be compared, mistyped and
 * read aloud without any of that meaning anything about a key. The row is
 * *shorter* than the one it replaced, which carried the label and twelve hex
 * characters side by side.
 */
export const Compact = () => <Fingerprint fpr={ADA} variant="compact" label="peer2" />;

/**
 * The same idea where the keyserver gave a name. A uid is what the reader
 * already thinks of this key as, and it is the honest thing to put in a
 * column — with the whole value one press away, as always.
 */
export const CompactWithUid = () => (
  <Fingerprint fpr={GRACE} variant="compact" label="grace@example.org" />
);

/**
 * Assembling a room, where adding is one of the actions.
 *
 * The menu row appears only when the surface has a room to add to; a page with
 * no session does not offer it and does not refuse it either, because it has
 * declined nothing.
 */
export const CanJoinARoom = () => (
  <Fingerprint fpr={GRACE} onAddToAudience={() => {}} />
);

/**
 * **Already a member, which is a refusal and names itself.** The row stays in
 * the menu and stays reachable — `aria-disabled`, never the `disabled`
 * attribute, so the sentence is not put out of reach of the people it was
 * written for — and it says "this key is already in the room, so there is
 * nothing to add" rather than going quietly grey.
 */
export const AlreadyInTheRoom = () => (
  <Fingerprint fpr={GRACE} onAddToAudience={() => {}} inAudience />
);

/**
 * **An SSH key fingerprint, where three of the actions have no answer.**
 *
 * It is a fingerprint and copying the whole of one matters exactly as much — so
 * copy works, and copies it verbatim, ungrouped, because that is what
 * `ssh-keygen -lf` prints and what an `allowed_signers` line is compared
 * against character for character. What it has no answer to is the keyserver,
 * whose pages are `/key?fpr=` over hex; the local trust map, keyed by hex; and
 * a room, whose name is a digest of OpenPGP fingerprints. Three refusals, one
 * cause, stated once.
 */
export const SshKeyFingerprint = () => (
  <Fingerprint fpr={SSH} onAddToAudience={() => {}} />
);
