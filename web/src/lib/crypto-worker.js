/**
 * Web Worker: encrypt / private-key decrypt in an isolated heap.
 *
 * Decrypt: { id, type:"decrypt", armoredMessage, privateKeyArmored, passphrase?, verificationKeysArmored? }
 * Encrypt: { id, type:"encrypt", recipientKeysArmored[], passwords[], payloads[], profile, hideRecipients? }
 *          File payloads may include transferable ArrayBuffer `bytes`.
 */

import {
  decrypt,
  decryptKey,
  decryptSessionKeys,
  readKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
import { encryptArtifacts } from "./pgp/encrypt.js";
import { zeroKeyMaterial } from "./pgp/memory.js";

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
      const message = await readMessage({ armoredMessage: msg.armoredMessage });
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
          message,
          decryptionKeys: privateKey,
        });
      } catch (_) {
        sessionKeys = [];
      }
      const result = await decrypt({
        message,
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
        sigStatuses.push({
          keyID: s.keyID?.toHex?.() || "",
          verified: ok,
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
      const artifacts = await encryptArtifacts({
        recipients,
        passwords: msg.passwords || [],
        payloads,
        profile: msg.profile,
        hideRecipients: !!msg.hideRecipients,
      });
      // Wipe any remaining payload buffers (encryptArtifacts already zeroes file bytes).
      for (const p of payloads) {
        if (p.bytes instanceof Uint8Array) {
          try {
            p.bytes.fill(0);
          } catch (_) {
            /* ignore */
          }
        }
      }
      self.postMessage({ id, ok: true, artifacts });
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
