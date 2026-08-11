import { ApprovalBanner } from "basilisk-portal";

/*
 * The approval moment: a recipe is asking to use a key, and this banner is
 * where a person decides. It is the highest-consequence surface in the
 * toolkit, which is why every fixture below is a *complete* request — the
 * digest, the byte count, and the exact serialized step are the three things
 * that make consent informed rather than ceremonial.
 *
 * `payloadSha256` is the load-bearing field. It is the digest of the exact
 * bytes about to be signed, so a person can compare it against what they
 * expected to sign; a banner that asks "sign with this key?" without it is
 * asking for a blank cheque.
 *
 * `use` never crosses between sign and decrypt — a grant to sign is not a
 * grant to decrypt — so the two are shown as different requests, not one
 * request with a mode.
 */

const frame = { maxWidth: 560 };

const BASE = {
  keyId: "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388",
  keyLabel: "Ada Lovelace <ada.lovelace@example.org>",
  keyKind: "pgp" as const,
  keyProtection: "passphrase",
  requestIndex: 1,
  runTotal: 1,
};

/**
 * One signature, text payload. The preview shows what is being signed, so the
 * decision is made against content rather than a filename — the digest proves
 * the bytes, the preview makes them legible, and neither substitutes for the
 * other.
 */
export const Default = () => (
  <div style={frame}>
    <ApprovalBanner
      request={{
        ...BASE,
        use: "sign",
        stepName: "agent.sign",
        stepText: "agent.sign key=$ada mode=cleartext",
        cellIndex: 3,
        mode: "cleartext",
        payloadBytes: 148,
        payloadSha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        payloadPreview:
          "release 2.4.0 — reproducible build, manifest 4c1d…\nbuilt 2026-08-10T09:14:00Z",
      }}
      onDecide={() => {}}
    />
  </div>
);

/**
 * Decryption rather than signing, on a passkey-protected key.
 *
 * `payloadPreview` is `null` because ciphertext has no legible preview, and
 * the banner must not invent one — showing base64 as though it were content
 * would imply a reader had checked something they cannot check. The digest and
 * the size carry the whole of what is knowable here.
 */
export const DecryptRequest = () => (
  <div style={frame}>
    <ApprovalBanner
      request={{
        ...BASE,
        use: "decrypt",
        stepName: "agent.decrypt",
        stepText: "agent.decrypt key=$ada",
        cellIndex: 7,
        keyProtection: "passkey",
        payloadBytes: 4096,
        payloadSha256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        payloadPreview: null,
      }}
      onDecide={() => {}}
    />
  </div>
);

/**
 * The dangerous shape: one request out of many in a single run.
 *
 * `requestIndex`/`runTotal` exist so a `foreach` cannot smuggle 200 signatures
 * past someone who believes they are approving one. "3 of 200" is what turns
 * the run-wide grant from a convenience into an informed choice, and it is the
 * reason the count is on the banner rather than in a log.
 */
export const OneOfManyInARun = () => (
  <div style={frame}>
    <ApprovalBanner
      request={{
        ...BASE,
        use: "sign",
        stepName: "agent.sign",
        stepText: "foreach $files | agent.sign key=$ada mode=detached",
        cellIndex: 11,
        mode: "detached",
        payloadBytes: 2310,
        payloadSha256: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        payloadPreview: null,
        requestIndex: 3,
        runTotal: 200,
      }}
      onDecide={() => {}}
    />
  </div>
);

/**
 * An SSH key signing with a namespace. `namespace` is sshsig-only and is shown
 * because it scopes what the signature is valid *for* — a signature made under
 * `git` is not a file signature, and a reader approving one should not be
 * approving the other.
 */
export const SshWithNamespace = () => (
  <div style={frame}>
    <ApprovalBanner
      request={{
        ...BASE,
        use: "sign",
        stepName: "agent.sign",
        stepText: "agent.sign key=$id namespace=git",
        cellIndex: 2,
        keyId: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
        keyLabel: "id_ed25519 (laptop)",
        keyKind: "ssh",
        keyProtection: "device",
        namespace: "git",
        payloadBytes: 62,
        payloadSha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        payloadPreview: "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
      }}
      onDecide={() => {}}
    />
  </div>
);
