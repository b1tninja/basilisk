/**
 * Formal JSDoc data contracts for the basilisk PGP client module.
 * Runtime: no exports — import this file only for editor/typecheck tooling, or
 * re-export typedefs via `@typedef` references from other modules.
 */

/**
 * Encryption algorithm profile selected in the encrypt UI.
 * @typedef {object} EncryptProfile
 * @property {"aes128"|"aes192"|"aes256"} cipher
 * @property {null|"gcm"|"ocb"|"eax"} aead  null = SEIPD v1 (CFB+MDC)
 * @property {"uncompressed"|"zlib"|"zip"} compression
 * @property {"argon2"|"iterated"} s2k  only applied when passwords are present
 */

/**
 * One plaintext payload to encrypt.
 * @typedef {object} EncryptPayload
 * @property {"text"|"file"} kind
 * @property {string} [text]  required when kind === "text"
 * @property {Uint8Array} [bytes]  required when kind === "file"
 * @property {string} [filename]  literal filename for file payloads
 */

/**
 * Request to produce one or more armored ciphertext artifacts.
 * @typedef {object} EncryptRequest
 * @property {import("openpgp").Key[]} recipients
 * @property {string[]} passwords
 * @property {EncryptPayload[]} payloads
 * @property {EncryptProfile} profile
 * @property {boolean} [hideRecipients]  wildcard PKESK key IDs (anonymous recipients)
 */

/**
 * One armored ciphertext artifact ready for download/copy.
 * @typedef {object} EncryptArtifact
 * @property {string} label
 * @property {string} filename
 * @property {string} armored
 */

/**
 * Signature issuer metadata extracted from signature packets.
 * @typedef {object} SigDetail
 * @property {string} keyId
 * @property {string} fingerprint
 * @property {Date|null} created
 */

/**
 * Result of inspecting an armored PGP message without decrypting.
 * @typedef {object} MessageAnalysis
 * @property {"empty"|"encrypted"|"message"|"cleartext"|"detached"} type
 * @property {string[]} recipientKeyIDs
 * @property {SigDetail[]} sigDetails
 * @property {string} cleartext
 * @property {import("openpgp").Message|import("openpgp").CleartextMessage|import("openpgp").Signature|null} message
 * @property {boolean} hasSkesk
 * @property {boolean} hasPkesk
 * @property {string} armored
 */

/**
 * Main-thread → crypto worker decrypt request.
 * @typedef {object} WorkerDecryptRequest
 * @property {string|number} id
 * @property {"decrypt"} type
 * @property {string} armoredMessage
 * @property {string} privateKeyArmored
 * @property {string} [passphrase]
 * @property {string[]} [verificationKeysArmored]
 * @property {string} [messagePassphrase]  SKESK passphrase when present
 */

/**
 * Crypto worker → main-thread decrypt response.
 * @typedef {object} WorkerDecryptResponse
 * @property {string|number} id
 * @property {boolean} ok
 * @property {string} [plaintext]
 * @property {Array<{ keyID?: string, fingerprint?: string, verified?: boolean, valid?: boolean }>} [signatures]
 * @property {Array<{ algorithm?: string, aeadAlgorithm?: string, data?: Uint8Array }>} [sessionKeys]
 * @property {string} [error]
 */

/**
 * Serializable encrypt request for the crypto worker (armored keys, transferable buffers).
 * @typedef {object} WorkerEncryptRequest
 * @property {string|number} id
 * @property {"encrypt"} type
 * @property {string[]} recipientKeysArmored
 * @property {string[]} passwords
 * @property {Array<{ kind: "text"|"file", text?: string, bytes?: ArrayBuffer, filename?: string }>} payloads
 * @property {EncryptProfile} profile
 * @property {boolean} [hideRecipients]
 */

/**
 * Crypto worker → main-thread encrypt response.
 * @typedef {object} WorkerEncryptResponse
 * @property {string|number} id
 * @property {boolean} ok
 * @property {EncryptArtifact[]} [artifacts]
 * @property {string} [error]
 */

export {};
