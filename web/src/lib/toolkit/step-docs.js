/**
 * Reference links for registry steps and pipeline types.
 *
 * Kept out of `registry.js` deliberately: a URL is documentation, not part of
 * a step's contract, and threading ~60 more string fields through the STEPS
 * array would bury the parts that actually drive parsing and execution. Steps
 * that implement the same spec share one entry here instead of repeating it.
 *
 * Every link points at the *normative* source for what the step does — the MDN
 * page for the exact WebCrypto/WebRTC/WebAuthn call it makes, or the RFC that
 * defines the wire format. Basilisk-specific plumbing (`in`, `out`, `tee`,
 * `agent.*`) has no external spec and is intentionally absent; `docsUrlFor`
 * returns null and the tool card simply omits the row.
 */

const MDN = "https://developer.mozilla.org/en-US/docs/Web/API";
const RFC = "https://www.rfc-editor.org/rfc";

/** @typedef {{ url: string, label: string }} DocRef */

/**
 * Step name → reference. Names match `StepSpec.name` exactly (case-sensitive).
 * @type {Record<string, DocRef>}
 */
const STEP_DOCS = {
  // ── WebCrypto — each maps to one SubtleCrypto method or its params dict ──
  genkey: { url: `${MDN}/SubtleCrypto/generateKey`, label: "MDN · SubtleCrypto.generateKey()" },
  export: { url: `${MDN}/SubtleCrypto/exportKey`, label: "MDN · SubtleCrypto.exportKey()" },
  import: { url: `${MDN}/SubtleCrypto/importKey`, label: "MDN · SubtleCrypto.importKey()" },
  digest: { url: `${MDN}/SubtleCrypto/digest`, label: "MDN · SubtleCrypto.digest()" },
  sign: { url: `${MDN}/SubtleCrypto/sign`, label: "MDN · SubtleCrypto.sign()" },
  verify: { url: `${MDN}/SubtleCrypto/verify`, label: "MDN · SubtleCrypto.verify()" },
  "aes-gcm": { url: `${MDN}/AesGcmParams`, label: "MDN · AesGcmParams" },
  "aes-cbc": { url: `${MDN}/AesCbcParams`, label: "MDN · AesCbcParams" },
  "aes-ctr": { url: `${MDN}/AesCtrParams`, label: "MDN · AesCtrParams" },
  "rsa-oaep": { url: `${MDN}/RsaOaepParams`, label: "MDN · RsaOaepParams" },
  "rsa-pkcs1": { url: `${MDN}/SubtleCrypto/sign`, label: "MDN · SubtleCrypto.sign()" },
  hkdf: { url: `${MDN}/HkdfParams`, label: "MDN · HkdfParams" },
  pbkdf2: { url: `${MDN}/Pbkdf2Params`, label: "MDN · Pbkdf2Params" },
  ecdh: { url: `${MDN}/EcdhKeyDeriveParams`, label: "MDN · EcdhKeyDeriveParams" },
  wrap: { url: `${MDN}/SubtleCrypto/wrapKey`, label: "MDN · SubtleCrypto.wrapKey()" },
  unwrap: { url: `${MDN}/SubtleCrypto/unwrapKey`, label: "MDN · SubtleCrypto.unwrapKey()" },

  // ── Encoding — the RFC that defines the alphabet/framing, not a JS API ──
  pem: { url: `${RFC}/rfc7468`, label: "RFC 7468 · PEM" },
  der: { url: "https://www.itu.int/rec/T-REC-X.690", label: "ITU-T X.690 · DER" },
  base64: { url: `${RFC}/rfc4648#section-4`, label: "RFC 4648 §4 · Base64" },
  base64url: { url: `${RFC}/rfc4648#section-5`, label: "RFC 4648 §5 · Base64url" },
  base32: { url: `${RFC}/rfc4648#section-6`, label: "RFC 4648 §6 · Base32" },
  encode: { url: `${RFC}/rfc4648`, label: "RFC 4648 · Base encodings" },
  decode: { url: `${RFC}/rfc4648`, label: "RFC 4648 · Base encodings" },
  utf8: { url: `${MDN}/TextEncoder`, label: "MDN · TextEncoder" },

  // ── I/O ──
  random: { url: `${MDN}/Crypto/getRandomValues`, label: "MDN · Crypto.getRandomValues()" },
  // The receipt ops have no protocol of their own; what *is* normative about
  // them is the deterministic serialization the digest and the signature are
  // taken over, so both point at JCS rather than at nothing.
  "run.receipt": { url: `${RFC}/rfc8785`, label: "RFC 8785 · JSON Canonicalization" },
  "run.verify": { url: `${RFC}/rfc8785`, label: "RFC 8785 · JSON Canonicalization" },
  passphrase: { url: "https://en.wikipedia.org/wiki/Diceware", label: "Diceware" },

  // ── OpenPGP — one spec covers the whole toolbox ──
  "gpg.encrypt": { url: `${RFC}/rfc9580`, label: "RFC 9580 · OpenPGP" },
  "gpg.decrypt": { url: `${RFC}/rfc9580`, label: "RFC 9580 · OpenPGP" },
  "gpg.symencrypt": { url: `${RFC}/rfc9580`, label: "RFC 9580 · OpenPGP" },
  "gpg.symdecrypt": { url: `${RFC}/rfc9580`, label: "RFC 9580 · OpenPGP" },
  "gpg.sign": { url: `${RFC}/rfc9580#section-5.2`, label: "RFC 9580 §5.2 · Signatures" },
  "gpg.verify": { url: `${RFC}/rfc9580#section-5.2`, label: "RFC 9580 §5.2 · Signatures" },
  "gpg.genkey": { url: `${RFC}/rfc9580#section-5.5`, label: "RFC 9580 §5.5 · Key material" },
  "gpg.inspect": { url: `${RFC}/rfc9580#section-5`, label: "RFC 9580 §5 · Packets" },

  // ── HKP keyserver protocol ──
  "hkp.get": {
    url: "https://www.ietf.org/archive/id/draft-shaw-openpgp-hkp-00.txt",
    label: "draft-shaw-openpgp-hkp-00",
  },
  "hkp.search": {
    url: "https://www.ietf.org/archive/id/draft-shaw-openpgp-hkp-00.txt",
    label: "draft-shaw-openpgp-hkp-00",
  },

  // ── Secret sharing ──
  "sss.split": {
    url: "https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing",
    label: "Shamir's Secret Sharing",
  },
  "sss.combine": {
    url: "https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing",
    label: "Shamir's Secret Sharing",
  },
  blip39: {
    url: "https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki",
    label: "BIP-39 · Mnemonic wordlist",
  },

  // ── WebAuthn ──
  "webauthn.caps": { url: `${MDN}/Web_Authentication_API`, label: "MDN · Web Authentication API" },
  "webauthn.create": {
    url: `${MDN}/CredentialsContainer/create`,
    label: "MDN · CredentialsContainer.create()",
  },
  "webauthn.get": {
    url: `${MDN}/CredentialsContainer/get`,
    label: "MDN · CredentialsContainer.get()",
  },
  "webauthn.prf": {
    url: `${MDN}/Web_Authentication_API/WebAuthn_extensions#prf`,
    label: "MDN · WebAuthn PRF extension",
  },
  "webauthn.attest": {
    url: "https://www.w3.org/TR/webauthn-3/#sctn-attestation",
    label: "W3C WebAuthn L3 · Attestation",
  },
  "webauthn.mds": {
    url: "https://fidoalliance.org/metadata/",
    label: "FIDO Alliance · Metadata Service",
  },

  // ── JOSE — each op points at the RFC that defines its serialization ──
  "jose.sign": { url: `${RFC}/rfc7515`, label: "RFC 7515 · JSON Web Signature" },
  "jose.verify": { url: `${RFC}/rfc7515#section-5.2`, label: "RFC 7515 §5.2 · Validating a JWS" },
  "jose.encrypt": { url: `${RFC}/rfc7516`, label: "RFC 7516 · JSON Web Encryption" },
  "jose.decrypt": { url: `${RFC}/rfc7516#section-5.2`, label: "RFC 7516 §5.2 · Decrypting a JWE" },
  "jose.decode": { url: `${RFC}/rfc7519`, label: "RFC 7519 · JSON Web Token" },

  // ── WebRTC ──
  "rtc.ice": {
    url: `${MDN}/RTCPeerConnection/RTCPeerConnection#iceservers`,
    label: "MDN · RTCConfiguration.iceServers",
  },
  "stun.check": { url: `${RFC}/rfc8489`, label: "RFC 8489 · STUN" },
  "rtc.gather": { url: `${MDN}/RTCIceCandidate`, label: "MDN · RTCIceCandidate" },
  "rtc.check": { url: `${RFC}/rfc8445#section-7`, label: "RFC 8445 §7 · ICE checks" },
  "rtc.certificate": { url: `${MDN}/RTCCertificate`, label: "MDN · RTCCertificate" },
  "rtc.offer": {
    url: `${MDN}/RTCPeerConnection/createOffer`,
    label: "MDN · RTCPeerConnection.createOffer()",
  },
  "rtc.answer": {
    url: `${MDN}/RTCPeerConnection/createAnswer`,
    label: "MDN · RTCPeerConnection.createAnswer()",
  },
  "rtc.state": {
    url: `${MDN}/RTCPeerConnection/connectionState`,
    label: "MDN · RTCPeerConnection.connectionState",
  },
  "rtc.restart": {
    url: `${MDN}/RTCPeerConnection/restartIce`,
    label: "MDN · RTCPeerConnection.restartIce()",
  },
  "rtc.stats": {
    url: `${MDN}/RTCDataChannel/bufferedAmount`,
    label: "MDN · RTCDataChannel.bufferedAmount",
  },
  "rtc.quality": {
    url: `${MDN}/RTCPeerConnection/getStats`,
    label: "MDN · RTCPeerConnection.getStats()",
  },
  "quorum.offer": { url: `${MDN}/RTCDataChannel`, label: "MDN · RTCDataChannel" },
  "quorum.join": { url: `${MDN}/RTCDataChannel`, label: "MDN · RTCDataChannel" },
  "rtc.send": { url: `${MDN}/RTCDataChannel/send`, label: "MDN · RTCDataChannel.send()" },
  "rtc.recv": {
    url: `${MDN}/RTCDataChannel/message_event`,
    label: "MDN · RTCDataChannel message event",
  },
  "quorum.close": { url: `${MDN}/RTCDataChannel/close`, label: "MDN · RTCDataChannel.close()" },
  "qr.scan": {
    url: `${MDN}/BarcodeDetector`,
    label: "MDN · BarcodeDetector",
  },
  "clipboard.read": {
    url: `${MDN}/Clipboard/readText`,
    label: "MDN · Clipboard.readText()",
  },
  "clipboard.write": {
    url: `${MDN}/Clipboard/writeText`,
    label: "MDN · Clipboard.writeText()",
  },

  // ── File I/O — the picker APIs, not a wire format ──
  "file.read": {
    url: `${MDN}/Window/showOpenFilePicker`,
    label: "MDN · Window.showOpenFilePicker()",
  },
  "file.save": {
    url: `${MDN}/Window/showSaveFilePicker`,
    label: "MDN · Window.showSaveFilePicker()",
  },

  // ── Chunked AEAD — the paper that defines the construction, since this
  //    format is Basilisk's own and has no RFC to point at ──
  "stream.seal": {
    url: "https://eprint.iacr.org/2015/189",
    label: "Hoang–Reyhanitabar–Rogaway–Vizár · Online AE (STREAM)",
  },
  "stream.open": {
    url: "https://eprint.iacr.org/2015/189",
    label: "Hoang–Reyhanitabar–Rogaway–Vizár · Online AE (STREAM)",
  },

  // ── age — one spec covers the toolbox ──
  "age.keygen": {
    url: "https://github.com/C2SP/C2SP/blob/main/age.md",
    label: "C2SP · age-encryption.org/v1",
  },
  "age.recipient": {
    url: "https://github.com/C2SP/C2SP/blob/main/age.md#the-x25519-recipient-type",
    label: "C2SP · age X25519 recipient",
  },
  "age.encrypt": {
    url: "https://github.com/C2SP/C2SP/blob/main/age.md",
    label: "C2SP · age-encryption.org/v1",
  },
  "age.decrypt": {
    url: "https://github.com/C2SP/C2SP/blob/main/age.md",
    label: "C2SP · age-encryption.org/v1",
  },

  // ── Literals ──
  bytes: {
    url: `${MDN}/Uint8Array`,
    label: "MDN · Uint8Array",
  },
};

/**
 * Reference link for a step, or null when no external spec applies.
 * @param {{ name?: string }|string|null|undefined} step  StepSpec or step name
 * @returns {DocRef|null}
 */
export function docsUrlFor(step) {
  const name = typeof step === "string" ? step : step?.name;
  if (!name) return null;
  return STEP_DOCS[name] || null;
}

/** @returns {Record<string, DocRef>} */
export function listStepDocs() {
  return { ...STEP_DOCS };
}
