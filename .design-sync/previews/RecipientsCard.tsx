import { RecipientsCard } from "basilisk-portal";

/*
 * The five fields the engine serializes for a `recipients` artifact — the same
 * shape `hkp.search` hands downstream — over four real OpenPGP keys.
 *
 * `encryptCapable` is not asserted here: each key was generated and then asked
 * `getEncryptionKey()`. The last one is a genuine signing-only key with no
 * encryption subkey, so it genuinely answers false, and the fingerprints are
 * the real ones for those keys.
 */

const LIST = JSON.stringify(
  [
    {
      fingerprint: "85D9A6ACABD26AB2CECE7BEDABBB06C6A3C592E0",
      label: "Ada Lovelace",
      email: "ada.lovelace@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "7218D1BCD7830008AE847FA68D297C55D0CE4CEC",
      label: "Grace Hopper",
      email: "grace.hopper@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "6BC96A340B91A25D90D631098B76B24CF9C15B84",
      label: "Katherine Johnson",
      email: "k.johnson@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "DAA2E8D529834C42326DEC02E75594932C6BF5BD",
      label: "Release Signing Bot",
      email: "release@example.org",
      approvalState: "upstream",
      encryptCapable: false,
    },
  ],
  null,
  2
);

const APPROVED_ONLY = JSON.stringify(
  [
    {
      fingerprint: "85D9A6ACABD26AB2CECE7BEDABBB06C6A3C592E0",
      label: "Ada Lovelace",
      email: "ada.lovelace@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "7218D1BCD7830008AE847FA68D297C55D0CE4CEC",
      label: "Grace Hopper",
      email: "grace.hopper@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "6BC96A340B91A25D90D631098B76B24CF9C15B84",
      label: "Katherine Johnson",
      email: "k.johnson@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
  ],
  null,
  2
);

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
 * `hkp.filter`'s default is approved plus encrypt-capable, and this is the
 * before and after. Exactly one row disappears — the one whose warn line said
 * it would — and the card is how you notice that the list you are encrypting
 * to is not the list you searched for.
 */
export const BeforeAndAfterFilter = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 18 }}>
    <RecipientsCard content={LIST} />
    <RecipientsCard content={APPROVED_ONLY} />
  </div>
);
