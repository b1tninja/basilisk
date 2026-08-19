/**
 * A message signed by a **signing subkey**, from real GnuPG.
 *
 * `matchSigner` resolves a signature's key id to the primary fingerprint two
 * ways: the primary's own fingerprint ending with the key id, and — failing
 * that — `getKeyIDs()`, which enumerates the subkeys. The second branch had no
 * coverage and its control mutation survived, because openpgp.js signs with
 * the primary key, so every fixture this suite could mint took the first
 * branch and the fallback was never entered.
 *
 * GnuPG prefers a signing subkey when one exists, so this fixture is the one
 * thing the JS library cannot produce. Made with GnuPG 2.4.9:
 *
 *   gpg --quick-gen-key "Ada Fixture <ada@fixture.test>" ed25519 cert 0
 *   gpg --quick-add-key <fpr> ed25519 sign 0
 *   gpg --quick-add-key <fpr> cv25519 encr 0
 *   echo "sealed payload" | gpg --sign --encrypt -r <fpr>
 *
 * The key is a throwaway with an empty passphrase and exists only here.
 *
 * Measured, so the premise cannot rot: the signature's key id is
 * D0FA677B683331C9 (the signing subkey) and the primary is
 * 3F8C269E9661ADF747CC7AB8FA0AE8CB2F7DFBFC, which does **not** end with it.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { decrypt, readKey, readMessage, readPrivateKey } from "openpgp";
import { decryptSignatureVerdict } from "../lib/pgp/decrypt-verify.js";
import { formatFingerprint } from "../lib/utils.js";

const fx = (n) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), "utf8");

const PRIMARY = "3F8C269E9661ADF747CC7AB8FA0AE8CB2F7DFBFC";
const SUBKEY_ID = "D0FA677B683331C9";

async function openFixture() {
  const pub = await readKey({ armoredKey: fx("ada-pub.asc") });
  const sec = await readPrivateKey({ armoredKey: fx("ada-sec.asc") });
  const r = await decrypt({
    message: await readMessage({ armoredMessage: fx("sealed.asc") }),
    decryptionKeys: sec,
    verificationKeys: pub,
    expectSigned: false,
  });
  return { pub, signatures: r.signatures };
}

describe("a signature made by a signing subkey", () => {
  it("really is signed by the subkey, not the primary", async () => {
    // The premise. If GnuPG ever stops preferring the subkey this fails here,
    // loudly, rather than the fallback test quietly passing for a new reason.
    const { pub, signatures } = await openFixture();
    expect(signatures[0].keyID.toHex().toUpperCase()).toBe(SUBKEY_ID);
    expect(pub.getFingerprint().toUpperCase()).toBe(PRIMARY);
    expect(PRIMARY.endsWith(SUBKEY_ID)).toBe(false);
    expect(pub.getKeyIDs().map((k) => k.toHex().toUpperCase())).toContain(SUBKEY_ID);
  });

  it("resolves to the primary fingerprint the recipe named", async () => {
    const { pub, signatures } = await openFixture();
    const verdict = await decryptSignatureVerdict({
      signatures,
      keyByFpr: new Map([[PRIMARY, pub]]),
      against: "signers",
      what: "gpg.decrypt",
    });
    // Whole fingerprint of the *primary*, never the subkey's id: a person
    // named the key, and a subkey is that key.
    expect(verdict.state).toBe("verified");
    expect(verdict.signer).toBe(PRIMARY);
    // Spaced groups on screen, whole either way — `formatFingerprint` is the
    // one spelling a reader sees, and no part of it is dropped.
    expect(verdict.sentence).toContain(formatFingerprint(PRIMARY));
  });

  it("reports unverified when there is no key to check the subkey against", async () => {
    // The fallback widens which key ids match a key that is present; it must
    // not invent a key that is not. Written with an empty set rather than a
    // wrong-named one: `matchSigner` reads each key's own fingerprint, so the
    // map's key is a label and naming it wrongly proves nothing.
    const { signatures } = await openFixture();
    const verdict = await decryptSignatureVerdict({
      signatures,
      keyByFpr: new Map(),
      against: "none",
      what: "gpg.decrypt",
    });
    expect(verdict.state).toBe("unverified");
    expect(verdict.signer).toBe("");
  });
});
