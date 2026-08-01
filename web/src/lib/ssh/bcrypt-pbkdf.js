/**
 * `bcrypt_pbkdf` — the KDF that opens a passphrase-protected openssh-key-v1
 * file (§29f, design_handoff_agent_ssh).
 *
 * A transcription of OpenBSD's `lib/libutil/bcrypt_pbkdf.c`. It is neither
 * bcrypt nor PBKDF2, and mistaking it for either is the whole difficulty:
 *
 *  - The PRF is bcrypt with four deliberate changes (Ted Unangst's own list):
 *    password and salt arrive pre-hashed with SHA-512, the output is 256 bits
 *    rather than 192, the magic string is the longer
 *    `"OxychromaticBlowfishSwatDynamite"`, and the schedule is a fixed 64
 *    rounds instead of bcrypt's `2^cost`. It also writes its output words
 *    **little-endian** where bcrypt writes big-endian — the one difference
 *    that is not documented as a difference, and the one that silently
 *    produces a wrong-but-plausible key.
 *  - The outer loop is PBKDF2-shaped but *interleaves* its output instead of
 *    concatenating blocks: byte `i` of block `count` lands at
 *    `i * stride + (count - 1)`. The comment in the original explains why
 *    (an attacker who wants only the first subkey would otherwise get to run
 *    the outer loop once), and the practical consequence here is that a
 *    48-byte derivation is not "block 1 then block 2" — the two blocks are
 *    shuffled together, and getting this wrong yields key material that looks
 *    perfectly random and decrypts nothing.
 *
 * SHA-512 comes from WebCrypto, which is why this is async; the caller needs
 * to be async regardless, since the cipher it feeds is `crypto.subtle` too.
 * See `bcrypt-pbkdf.test.js` for the published vectors this is held to.
 */

import { blfEnc, expand0State, expandState, initState, stream2word } from "./blowfish.js";

/** 32 bytes, 8 words — the string bcrypt_pbkdf enciphers. */
const MAGIC = new TextEncoder().encode("OxychromaticBlowfishSwatDynamite");

/** BCRYPT_HASHSIZE: the PRF's output width, and the outer loop's block size. */
const HASH_SIZE = 32;

/** @param {Uint8Array} bytes */
async function sha512(bytes) {
  // Copy through a fresh ArrayBuffer: a subarray view of a larger buffer is a
  // legal BufferSource, but passing one is the sort of thing that works until
  // someone hands this a pooled buffer.
  const buf = await crypto.subtle.digest("SHA-512", bytes.slice());
  return new Uint8Array(buf);
}

/**
 * The modified bcrypt hash: 64 rounds of expensive key schedule over the
 * pre-hashed password and salt, then 64 encipherments of the magic string.
 *
 * @param {Uint8Array} sha2pass  SHA-512 of the password
 * @param {Uint8Array} sha2salt  SHA-512 of the (counted) salt
 * @returns {Uint8Array} 32 bytes
 */
function bcryptHash(sha2pass, sha2salt) {
  const state = initState();
  expandState(state, sha2salt, sha2pass);
  for (let i = 0; i < 64; i++) {
    expand0State(state, sha2salt);
    expand0State(state, sha2pass);
  }

  const cdata = new Int32Array(8);
  const cur = new Int32Array(1);
  for (let i = 0; i < 8; i++) cdata[i] = stream2word(MAGIC, cur);
  for (let i = 0; i < 64; i++) blfEnc(state, cdata);

  // Little-endian on purpose — see the header note.
  const out = new Uint8Array(HASH_SIZE);
  for (let i = 0; i < 8; i++) {
    const v = cdata[i];
    out[4 * i + 0] = v & 0xff;
    out[4 * i + 1] = (v >>> 8) & 0xff;
    out[4 * i + 2] = (v >>> 16) & 0xff;
    out[4 * i + 3] = (v >>> 24) & 0xff;
  }
  return out;
}

/**
 * Derive `keylen` bytes from a passphrase.
 *
 * @param {Uint8Array} pass  The passphrase, already UTF-8 encoded.
 * @param {Uint8Array} salt
 * @param {number} keylen
 * @param {number} rounds
 * @returns {Promise<Uint8Array>}
 */
export async function bcryptPbkdf(pass, salt, keylen, rounds) {
  if (!(rounds >= 1)) throw new Error("bcrypt_pbkdf: rounds must be at least 1");
  if (pass.length === 0) throw new Error("bcrypt_pbkdf: empty passphrase");
  if (salt.length === 0) throw new Error("bcrypt_pbkdf: empty salt");
  if (keylen === 0 || keylen > HASH_SIZE * HASH_SIZE) {
    throw new Error(`bcrypt_pbkdf: keylen must be 1..${HASH_SIZE * HASH_SIZE}`);
  }

  const origKeylen = keylen;
  const key = new Uint8Array(origKeylen);
  const stride = Math.floor((keylen + HASH_SIZE - 1) / HASH_SIZE);
  let amt = Math.floor((keylen + stride - 1) / stride);

  const countsalt = new Uint8Array(salt.length + 4);
  countsalt.set(salt, 0);
  const sha2pass = await sha512(pass);

  for (let count = 1; keylen > 0; count++) {
    countsalt[salt.length + 0] = (count >>> 24) & 0xff;
    countsalt[salt.length + 1] = (count >>> 16) & 0xff;
    countsalt[salt.length + 2] = (count >>> 8) & 0xff;
    countsalt[salt.length + 3] = count & 0xff;

    // First round hashes the salt; every round after hashes the last output,
    // and the results are XORed together — ordinary PBKDF2 chaining.
    let sha2salt = await sha512(countsalt);
    let tmpout = bcryptHash(sha2pass, sha2salt);
    const out = tmpout.slice();
    for (let i = 1; i < rounds; i++) {
      sha2salt = await sha512(tmpout);
      tmpout = bcryptHash(sha2pass, sha2salt);
      for (let j = 0; j < HASH_SIZE; j++) out[j] ^= tmpout[j];
    }

    // The deviation: scatter, do not append.
    amt = Math.min(amt, keylen);
    let i = 0;
    for (; i < amt; i++) {
      const dest = i * stride + (count - 1);
      if (dest >= origKeylen) break;
      key[dest] = out[i];
    }
    keylen -= i;
  }
  return key;
}
