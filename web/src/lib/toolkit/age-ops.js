/**
 * age file encryption (age-encryption.org/v1) — real interop, not a lookalike.
 *
 * These ops go through **typage**, the TypeScript implementation by age's own
 * author, rather than a reimplementation of the spec. That choice is the whole
 * point: a half-compatible format that emits `age-encryption.org/v1` in its
 * header and then diverges is worse than no interop at all, because the
 * failure only shows up on someone else's machine. What this toolkit writes is
 * what `age` and `rage` on the command line read, and vice versa.
 *
 * ```text
 * age.keygen | out @id                        # AGE-SECRET-KEY-1…  (secret)
 * in @id | age.recipient | out @pub           # age1…              (shareable)
 *
 * file.read | age.encrypt to=@pub | file.save name=doc.age
 * file.read | age.decrypt key=@id | file.save
 * ```
 *
 * | Recipe | CLI equivalent |
 * |---|---|
 * | `age.keygen` | `age-keygen` |
 * | `age.encrypt to=age1…` | `age -r age1… -o doc.age doc` |
 * | `age.encrypt to=… armor=true` | `age -a -r age1… -o doc.age doc` |
 * | `age.encrypt passphrase=…` | `age -p -o doc.age doc` |
 * | `age.decrypt key=@id` | `age -d -i key.txt doc.age` |
 *
 * Contrast `stream.seal`: that is the toolkit's own chunked AEAD, keyed by any
 * AES slot the notebook holds, and it is explicitly **not** age (see
 * `stream-aead.js` for the divergence table). Use these ops when the file has
 * to leave Basilisk.
 *
 * Worker- and main-thread safe — typage rides WebCrypto plus audited noble
 * primitives, and falls back to JS X25519 where WebCrypto lacks the curve.
 * @module lib/toolkit/age-ops
 */

import {
  Decrypter,
  Encrypter,
  armor as ageArmor,
  generateX25519Identity,
  identityToRecipient,
} from "age-encryption";

/** Bech32 with the age HRPs — uppercase for identities, lowercase for recipients. */
const IDENTITY_RE = /^AGE-SECRET-KEY-1[0-9A-Z]+$/;
const RECIPIENT_RE = /^age1[0-9a-z]+$/;

const ARMOR_HEAD = "BEGIN AGE ENCRYPTED FILE";

/**
 * Resolve a `to=` / `key=` param that may be literal text or an `@slot` ref.
 * Slot values may be text (the usual case) or bytes (a `file.read` of a
 * key file), so both are decoded to a trimmed string.
 * @param {Record<string, unknown>} params
 * @param {string} name
 * @param {{ resolveSlot?: (ref: string) => { data?: unknown } | null }} bindings
 * @returns {string}
 */
function paramText(params, name, bindings) {
  const raw = String(params?.[name] ?? "").trim();
  if (!raw.startsWith("@")) return raw;
  const resolve = bindings?.resolveSlot;
  if (typeof resolve !== "function") {
    throw new Error(`age: runtime slot resolver missing for ${name}=`);
  }
  const slot = resolve(raw);
  if (!slot) throw new Error(`age: unknown slot ${raw}`);
  const data = slot.data;
  if (data instanceof Uint8Array) return new TextDecoder().decode(data).trim();
  return String(data ?? "").trim();
}

/**
 * @param {{ type?: string, data?: unknown } | null | undefined} value
 * @returns {Uint8Array}
 */
function valueBytes(value) {
  if (value?.data instanceof Uint8Array) return value.data;
  if (typeof value?.data === "string") return new TextEncoder().encode(value.data);
  throw new Error("age: expected text or bytes on the pipeline");
}

/**
 * `age-keygen`. The identity is the secret; the recipient rides along in meta
 * so the tile can show something shareable while the identity itself stays
 * masked behind the usual reveal gate.
 */
export async function execAgeKeygen() {
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  return {
    type: "text",
    data: identity,
    meta: {
      sensitive: true,
      ageIdentity: true,
      recipient,
      filename: "age-identity.txt",
      mime: "text/plain; charset=utf-8",
    },
  };
}

/**
 * Identity → recipient: the one honest projection age has. Derived, publishable,
 * and never invertible. An `age1…` on the stem passes through unchanged so
 * `… | age.recipient` is safe to write when you are not sure which half you hold.
 * @param {{ type?: string, data?: unknown }} value
 */
export async function execAgeRecipient(value) {
  const text = String(value?.data ?? "").trim();
  if (RECIPIENT_RE.test(text)) {
    return {
      type: "text",
      data: text,
      meta: { sensitive: false, ageRecipient: true, filename: "age-recipient.txt" },
    };
  }
  if (!IDENTITY_RE.test(text)) {
    throw new Error(
      "age.recipient expects an AGE-SECRET-KEY-1… identity (or an age1… recipient to pass through)"
    );
  }
  const recipient = await identityToRecipient(text);
  return {
    type: "text",
    data: recipient,
    meta: { sensitive: false, ageRecipient: true, filename: "age-recipient.txt" },
  };
}

/**
 * @param {{ type?: string, data?: unknown }} value
 * @param {Record<string, unknown>} params
 * @param {object} bindings
 */
export async function execAgeEncrypt(value, params, bindings) {
  const plaintext = valueBytes(value);
  const enc = new Encrypter();
  const passphrase = String(params?.passphrase ?? "");
  const toRaw = paramText(params, "to", bindings);
  if (passphrase) {
    if (toRaw) {
      throw new Error(
        "age.encrypt: choose recipients (to=) or a passphrase, not both — the age format does not mix them"
      );
    }
    enc.setPassphrase(passphrase);
  } else {
    const entries = toRaw.split(/[\s,]+/).filter(Boolean);
    if (!entries.length) {
      throw new Error("age.encrypt: to=<age1… | @slot> (or passphrase=) is required");
    }
    for (const entry of entries) {
      // Handing an identity where a recipient belongs is a common slip with an
      // unambiguous safe reading: encrypt to its public half.
      const recipient = IDENTITY_RE.test(entry)
        ? await identityToRecipient(entry)
        : entry;
      if (!RECIPIENT_RE.test(recipient)) {
        throw new Error(`age.encrypt: not an age recipient — ${entry.slice(0, 24)}…`);
      }
      enc.addRecipient(recipient);
    }
  }
  const ciphertext = await enc.encrypt(plaintext);
  const sourceName = String(value?.meta?.filename ?? "").trim();
  if (String(params?.armor ?? "") === "true") {
    return {
      type: "text",
      data: ageArmor.encode(ciphertext),
      meta: {
        sensitive: false,
        ageCiphertext: true,
        filename: sourceName ? `${sourceName}.age.txt` : "message.age.txt",
        mime: "text/plain; charset=utf-8",
      },
    };
  }
  return {
    type: "bytes",
    data: ciphertext,
    meta: {
      sensitive: false,
      kind: "opaque",
      ageCiphertext: true,
      filename: sourceName ? `${sourceName}.age` : "message.age",
      mime: "application/octet-stream",
    },
  };
}

/**
 * @param {{ type?: string, data?: unknown }} value
 * @param {Record<string, unknown>} params
 * @param {object} bindings
 */
export async function execAgeDecrypt(value, params, bindings) {
  /** @type {Uint8Array} */
  let ciphertext;
  if (typeof value?.data === "string" && value.data.includes(ARMOR_HEAD)) {
    ciphertext = ageArmor.decode(value.data);
  } else {
    ciphertext = valueBytes(value);
    // An armored `.age.txt` read off disk arrives as bytes; de-armor it rather
    // than failing on a header the user can plainly see is an age file.
    const head = new TextDecoder().decode(ciphertext.subarray(0, 40));
    if (head.includes("BEGIN AGE")) {
      ciphertext = ageArmor.decode(new TextDecoder().decode(ciphertext));
    }
  }
  const dec = new Decrypter();
  const passphrase = String(params?.passphrase ?? "");
  const key = paramText(params, "key", bindings);
  if (passphrase) dec.addPassphrase(passphrase);
  if (key) {
    if (!IDENTITY_RE.test(key)) {
      throw new Error("age.decrypt: key= must hold an AGE-SECRET-KEY-1… identity");
    }
    dec.addIdentity(key);
  }
  if (!passphrase && !key) {
    throw new Error("age.decrypt: key=@identity (or passphrase=) is required");
  }
  const plaintext = await dec.decrypt(ciphertext, "uint8array");
  const sourceName = String(value?.meta?.filename ?? "").trim();
  return {
    type: "bytes",
    data: plaintext,
    meta: {
      sensitive: true,
      kind: "opaque",
      filename: sourceName.replace(/\.age(\.txt)?$/i, "") || "decrypted.bin",
    },
  };
}
