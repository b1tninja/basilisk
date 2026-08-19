import { RecipientsCard } from "basilisk-portal";

/*
 * The five fields the engine serializes for a `recipients` artifact — the same
 * shape `hkp.search` hands downstream — over four real OpenPGP keys.
 *
 * `encryptCapable` has **three** states and every fixture below is one of them
 * honestly. `true` and `false` were asked: each key was generated and then
 * asked `getEncryptionKey()`, and the last one is a genuine signing-only key
 * with no encryption subkey, so it genuinely answers false. `null` is the state
 * nothing asked — a keyserver search hit. It is the same real certificate; what
 * differs is that the directory stores no column for encryption capability, so
 * a row that arrived from a search carries no answer rather than a cheerful
 * one. The fingerprints are the real ones for those keys throughout.
 */

const ADA = {
  fingerprint: "85D9A6ACABD26AB2CECE7BEDABBB06C6A3C592E0",
  label: "Ada Lovelace",
  email: "ada.lovelace@example.org",
};
const GRACE = {
  fingerprint: "7218D1BCD7830008AE847FA68D297C55D0CE4CEC",
  label: "Grace Hopper",
  email: "grace.hopper@example.org",
};
const KATHERINE = {
  fingerprint: "6BC96A340B91A25D90D631098B76B24CF9C15B84",
  label: "Katherine Johnson",
  email: "k.johnson@example.org",
};
const BOT = {
  fingerprint: "DAA2E8D529834C42326DEC02E75594932C6BF5BD",
  label: "Release Signing Bot",
  email: "release@example.org",
};

const body = (rows: unknown[]) => JSON.stringify(rows, null, 2);

/** Four certificates something has read — `hkp.get`, or the device cache. */
const LIST = body([
  { ...ADA, approvalState: "approved", encryptCapable: true },
  { ...GRACE, approvalState: "approved", encryptCapable: true },
  { ...KATHERINE, approvalState: "approved", encryptCapable: true },
  { ...BOT, approvalState: "upstream", encryptCapable: false },
]);

/**
 * The same four, straight off a directory search, before anything read them.
 *
 * `recipientFromSearchHit` decides capability only where the payload proves it
 * — revoked and expired are `false` — and everything else is `null`, because
 * whether a certificate carries an encryption subkey is a fact about its
 * packets and the portal holds no column for it.
 */
const SEARCH_HITS = body([
  { ...ADA, approvalState: "approved", encryptCapable: null },
  { ...GRACE, approvalState: "approved", encryptCapable: null },
  { ...KATHERINE, approvalState: "unapproved", encryptCapable: null },
  { ...BOT, approvalState: "upstream", encryptCapable: null },
]);

/** All three states in one table: two read, two never asked. */
const MIXED = body([
  { ...ADA, approvalState: "approved", encryptCapable: true },
  { ...GRACE, approvalState: "approved", encryptCapable: null },
  { ...KATHERINE, approvalState: "unapproved", encryptCapable: null },
  { ...BOT, approvalState: "upstream", encryptCapable: false },
]);

/** What `hkp.filter encrypt=true` leaves of `MIXED`: only the proven-false goes. */
const AFTER_FILTER = body([
  { ...ADA, approvalState: "approved", encryptCapable: true },
  { ...GRACE, approvalState: "approved", encryptCapable: null },
  { ...KATHERINE, approvalState: "unapproved", encryptCapable: null },
]);

/**
 * Who this is about to be encrypted to.
 *
 * The artifact is a JSON array — the one form in which nobody checks a
 * recipient list, which is the only reason to look at one. The table is the
 * same five fields, laid out so the check is possible: name, fingerprint in
 * the grouped hex a reader compares, approval state.
 *
 * Watch the last row. `cannot encrypt` is a stated fact in warn, not an error
 * tone: a key with no encryption-capable subkey is a perfectly good signing
 * key. But `gpg.encrypt` will silently skip that row, so anyone choosing
 * recipients has to see it. It gets its own line rather than a second clause,
 * because measured in the real pane "approved · cannot encrypt" lost its
 * second half — and the half that gets cut is the one that changes behaviour.
 */
export const WhoCanOpenThis = () => <RecipientsCard content={LIST} />;

/**
 * A search result, before anything asked the keys.
 *
 * Every row says `encryption unverified` — in the ordinary muted tone, not
 * warn, because nothing is wrong with these keys. What is missing is a
 * reading, and `hkp.get` is what takes it. This is the commonest recipient
 * list in the product, and until the third state existed it drew identically
 * to the fully-checked list above: capability that had never been asked was
 * shown the same way as capability that had been asked and passed.
 */
export const StraightOffTheDirectory = () => <RecipientsCard content={SEARCH_HITS} />;

/**
 * `hkp.filter encrypt=true`, before and after — and the reason it is a
 * half-answer.
 *
 * The filter drops only what the rows *prove* incapable: the signing-only bot
 * goes, and the two unverified rows stay, because a filter cannot drop a key
 * for a fact it does not have. Three states are visible in the first table and
 * two survive into the second, which is why the op reports an
 * `encryptUnverified` count beside the result rather than letting a shorter
 * list imply that what remains was checked.
 */
export const BeforeAndAfterFilter = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 18 }}>
    <RecipientsCard content={MIXED} />
    <RecipientsCard content={AFTER_FILTER} />
  </div>
);
