/**
 * Web Worker: encrypt / private-key decrypt / keygen in an isolated heap.
 *
 * Decrypt:  { id, type:"decrypt", armoredMessage, privateKeyArmored, passphrase?, verificationKeysArmored? }
 * Encrypt:  { id, type:"encrypt", recipientKeysArmored[], passwords[], payloads[], profile, hideRecipients? }
 * Generate: { id, type:"generate", name?, email, keyExpirationTime?, passphrase? }
 *           → { armoredPublic, armoredPrivate, fingerprint }
 */

import {
  decrypt,
  decryptKey,
  decryptSessionKeys,
  generateKey,
  readKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
import { encryptArtifacts } from "./pgp/encrypt.js";
import { intendedRecipientsFromSigPacket } from "./pgp/intended-recipient.js";
import { zeroKeyMaterial } from "./pgp/memory.js";
import { runRecipe } from "./toolkit/engine.js";

/**
 * Unlock an armored private key for signing (worker-local; wiped after use).
 * @param {string} armored
 * @param {string} [passphrase]
 */
async function unlockSigningKey(armored, passphrase) {
  let key = await readPrivateKey({ armoredKey: armored });
  if (!key.isDecrypted()) {
    key = await decryptKey({ privateKey: key, passphrase: passphrase || "" });
  }
  return key;
}

self.onmessage = async (ev) => {
  const msg = ev.data || {};
  const { id } = msg;
  let privateKey = null;
  try {
    if (msg.type === "decrypt") {
      privateKey = await readPrivateKey({ armoredKey: msg.privateKeyArmored });
      if (!privateKey.isDecrypted()) {
        privateKey = await decryptKey({
          privateKey,
          passphrase: msg.passphrase || "",
        });
      }
      // Message objects are stateful in OpenPGP.js — decryptSessionKeys
      // consumes internal packet state, so each call needs a fresh read.
      // Reusing the same object yields: "Cannot destructure property 'V' of 'e' as it is null".
      const verificationKeys = [];
      for (const armored of msg.verificationKeysArmored || []) {
        try {
          verificationKeys.push(await readKey({ armoredKey: armored }));
        } catch (_) {
          /* skip */
        }
      }
      let sessionKeys = [];
      try {
        sessionKeys = await decryptSessionKeys({
          message: await readMessage({ armoredMessage: msg.armoredMessage }),
          decryptionKeys: privateKey,
        });
      } catch (_) {
        sessionKeys = [];
      }
      const result = await decrypt({
        message: await readMessage({ armoredMessage: msg.armoredMessage }),
        decryptionKeys: privateKey,
        ...(verificationKeys.length ? { verificationKeys } : {}),
        config: { allowInsecureDecryptionWithSigningKeys: true },
      });
      const plaintext =
        typeof result.data === "string"
          ? result.data
          : new TextDecoder().decode(result.data);
      const sigStatuses = [];
      for (const s of result.signatures || []) {
        let ok = false;
        try {
          await s.verified;
          ok = true;
        } catch (_) {
          ok = false;
        }
        /** @type {string[]} */
        let intendedRecipients = [];
        try {
          const sigObj = await s.signature;
          for (const pkt of sigObj?.packets || []) {
            intendedRecipients.push(...intendedRecipientsFromSigPacket(pkt));
          }
          intendedRecipients = [...new Set(intendedRecipients)];
        } catch (_) {
          intendedRecipients = [];
        }
        sigStatuses.push({
          keyID: s.keyID?.toHex?.() || "",
          verified: ok,
          intendedRecipients,
        });
      }
      self.postMessage({
        id,
        ok: true,
        plaintext,
        signatures: sigStatuses,
        sessionKeys: (sessionKeys || []).map((sk) => ({
          algorithm: sk.algorithm,
          aeadAlgorithm: sk.aeadAlgorithm,
          length: sk.data?.length || 0,
        })),
      });
    } else if (msg.type === "encrypt") {
      const recipients = [];
      for (const armored of msg.recipientKeysArmored || []) {
        recipients.push(await readKey({ armoredKey: armored }));
      }
      /** @type {import("./pgp/types.js").EncryptPayload[]} */
      const payloads = [];
      for (const p of msg.payloads || []) {
        if (p.kind === "text") {
          payloads.push({ kind: "text", text: p.text || "" });
        } else if (p.kind === "file") {
          const bytes =
            p.bytes instanceof ArrayBuffer
              ? new Uint8Array(p.bytes)
              : p.bytes instanceof Uint8Array
                ? p.bytes
                : null;
          if (!bytes) throw new Error("File payload requires bytes.");
          payloads.push({
            kind: "file",
            bytes,
            filename: p.filename || "file",
          });
        }
      }
      /** @type {import("openpgp").PrivateKey[]} */
      const signingKeys = [];
      if (msg.signingKeyArmored) {
        signingKeys.push(
          await unlockSigningKey(msg.signingKeyArmored, msg.signingKeyPassphrase || "")
        );
      }
      try {
        const artifacts = await encryptArtifacts({
          recipients,
          passwords: msg.passwords || [],
          payloads,
          profile: msg.profile,
          hideRecipients: !!msg.hideRecipients,
          signingKeys,
        });
        // Wipe any remaining payload buffers (encryptArtifacts already zeroes file bytes).
        for (const p of payloads) {
          if (p.bytes instanceof Uint8Array) {
            try {
              p.bytes.fill(0);
            } catch (_) {
              /* wipe */
            }
          }
        }
        self.postMessage({ id, ok: true, artifacts });
      } finally {
        for (const sk of signingKeys) {
          try {
            zeroKeyMaterial(sk);
          } catch (_) {
            /* ignore */
          }
        }
      }
    } else if (msg.type === "toolkit-run") {
      // Execute a toolkit recipe AST; return encoded artifacts only.
      // Recipient keys and optional decrypt private key arrive as armored strings.
      /** @type {import("openpgp").Key[]} */
      const recipients = [];
      for (const armored of msg.recipientKeysArmored || []) {
        recipients.push(await readKey({ armoredKey: armored }));
      }
      /** @type {import("./toolkit/engine.js").RuntimeBindings["inputs"]} */
      const inputs = msg.inputs || {};
      // Prefer a top-level private key field so the worker finally-block can zero it.
      if (msg.privateKeyArmored && inputs.gpg) {
        inputs.gpg = {
          ...inputs.gpg,
          privateKeyArmored: String(msg.privateKeyArmored),
          passphrase: msg.passphrase || inputs.gpg.passphrase || "",
        };
        privateKey = await readPrivateKey({
          armoredKey: String(msg.privateKeyArmored),
        });
      }
      try {
        const artifacts = await runRecipe(msg.ast, {
          recipients,
          recipientFingerprints: msg.recipientFingerprints || [],
          inputs,
          encryption: msg.encryption,
        });
        self.postMessage({ id, ok: true, artifacts });
      } finally {
        // Drop armored private key string from the inputs binding.
        if (inputs.gpg) inputs.gpg.privateKeyArmored = "";
      }
    } else if (msg.type === "generate") {
      const email = String(msg.email || "").trim();
      if (!email) throw new Error("Email is required for key generation");
      const name = String(msg.name || "").trim();
      const userIDs = [{ name: name || email, email }];
      /** @type {Parameters<typeof generateKey>[0]} */
      const genOpts = {
        type: "ecc",
        curve: "curve25519",
        userIDs,
        format: "armored",
      };
      if (msg.passphrase) {
        genOpts.passphrase = String(msg.passphrase);
      }
      if (msg.keyExpirationTime != null && msg.keyExpirationTime > 0) {
        genOpts.keyExpirationTime = Number(msg.keyExpirationTime);
      }
      const { privateKey: armoredPrivate, publicKey: armoredPublic } =
        await generateKey(genOpts);
      // Parse public key for fingerprint (never leave object keys lingering).
      const pub = await readKey({ armoredKey: String(armoredPublic) });
      const fingerprint = pub.getFingerprint().toUpperCase();
      self.postMessage({
        id,
        ok: true,
        armoredPublic: String(armoredPublic),
        armoredPrivate: String(armoredPrivate),
        fingerprint,
      });
    } else {
      self.postMessage({ id, ok: false, error: "Unknown worker message type" });
    }
  } catch (err) {
    self.postMessage({ id, ok: false, error: err?.message || String(err) });
  } finally {
    zeroKeyMaterial(privateKey);
    privateKey = null;
  }
};
