/**
 * Web Worker: private-key decrypt in an isolated heap.
 * Main thread posts { id, armoredMessage, privateKeyArmored, passphrase?, verificationKeysArmored? }
 * Worker replies { id, ok, plaintext?, signatures?, sessionKeys?, error? }
 */

import {
  decrypt,
  decryptKey,
  decryptSessionKeys,
  readKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
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
