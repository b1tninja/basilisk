/**
 * Chunked AEAD (`stream.seal` / `stream.open`) — the STREAM construction, so a
 * file larger than memory can be authenticated-encrypted with WebCrypto.
 *
 * ## Why this exists
 *
 * `SubtleCrypto.encrypt` is one-shot: the whole plaintext must be a single
 * `BufferSource`, and the single GCM tag is only checked after the last byte.
 * That is fine for a message and wrong for a file — you cannot stream it, you
 * cannot bound memory, and a decrypting reader has no safe output until the
 * end. Splitting into independently-tagged chunks fixes all three, but naively
 * chunked AEAD is broken in three well-known ways: an attacker can drop the
 * tail (truncation), reorder chunks, or splice chunks between two files.
 *
 * STREAM (Hoang–Reyhanitabar–Rogaway–Vizár, "Online AE") fixes those by
 * binding position into the nonce: nonce = big-endian chunk counter with a
 * final-chunk flag byte. Reorder and splice change the counter, so the tag
 * fails; truncation removes the chunk whose flag byte is 1, so the reader
 * knows the file ended early. This is the construction `age` uses.
 *
 * ## Divergences from age (deliberate, and this format is NOT age)
 *
 * | | age v1 | `stream.seal` |
 * |---|---|---|
 * | AEAD | ChaCha20-Poly1305 | **AES-256-GCM** (WebCrypto has no ChaCha) |
 * | Chunk | 64 KiB fixed | 64 KiB default, `chunk=` selectable |
 * | Key delivery | recipient stanzas (X25519 / scrypt) + HMAC'd header | one AES-GCM-wrapped file key under the `key=$slot` you supply |
 * | Header MAC | HMAC-SHA-256 over the header, keyed by the file key | header is the AAD of the file-key wrap |
 * | Armor | PEM-style `BEGIN AGE ENCRYPTED FILE` | none — bytes; pipe through `base64` if you need text |
 *
 * For files the `age` CLI can actually read, use the `age.*` ops. This one is
 * a toolkit-native primitive: it takes any AES key the notebook already holds
 * (`genkey aes/256`, `hkdf`, `webauthn.prf`, an `ecdh` output) rather than
 * requiring an age identity.
 *
 * ## Wire format (v1)
 *
 * ```
 * header (72 bytes)
 *   0..7    magic        "BSKSTRM1"
 *   8..11   chunkSize    uint32 big-endian, plaintext bytes per chunk
 *   12..23  wrapNonce    12 random bytes
 *   24..71  wrappedKey   AES-GCM(keyEncryptionKey, wrapNonce, fileKey[32],
 *                                aad = header[0..11])   → 32 + 16 tag
 * payload
 *   chunk i = AES-GCM(fileKey, nonce_i, plaintext_i)     → len + 16 tag
 *   nonce_i = counter_i as 11-byte big-endian || (i is last ? 0x01 : 0x00)
 * ```
 *
 * The file key is fresh random per file, which is what makes counter nonces
 * safe: the `key=$slot` you pass may be reused across many files (it usually
 * is), and reusing a counter nonce under a reused key would be catastrophic
 * for GCM. Wrapping a per-file key is the same move age makes for the same
 * reason. It also means the supplied key never needs to be extractable —
 * WebCrypto wraps with it directly.
 *
 * Every chunk except the last is exactly `chunkSize` plaintext. A final chunk
 * of zero length is only legal when the whole plaintext is empty (age has the
 * same rule); otherwise it is a truncation artifact and rejected.
 *
 * @module lib/toolkit/stream-aead
 */

/** Magic + version. Eight bytes so the header stays 4-byte aligned. */
export const STREAM_MAGIC = new Uint8Array([0x42, 0x53, 0x4b, 0x53, 0x54, 0x52, 0x4d, 0x31]); // "BSKSTRM1"

/** Header is fixed-size: magic(8) + chunkSize(4) + nonce(12) + wrappedKey(48). */
export const STREAM_HEADER_LEN = 8 + 4 + 12 + 48;

/** GCM tag, in bytes. Fixed at the full 128 bits — this format has no reason to shorten it. */
export const STREAM_TAG_LEN = 16;

/** age's chunk size, and a sane default: 64 KiB of plaintext per tag. */
export const STREAM_DEFAULT_CHUNK = 64 * 1024;

/** Bounds on `chunk=`. Below 1 KiB the tag overhead dominates; above 4 MiB a decrypting reader's buffer stops being "bounded" in any useful sense. */
export const STREAM_MIN_CHUNK = 1024;
export const STREAM_MAX_CHUNK = 4 * 1024 * 1024;

/**
 * STREAM nonce: 11-byte big-endian counter, then the final-chunk flag.
 *
 * 11 bytes of counter is far more than AES-GCM's safe chunk budget, so the
 * ceiling that matters is `2^32` chunks, checked by the caller.
 * @param {number} counter
 * @param {boolean} last
 * @returns {Uint8Array}
 */
export function streamNonce(counter, last) {
  const nonce = new Uint8Array(12);
  let n = counter;
  for (let i = 10; i >= 0 && n > 0; i--) {
    nonce[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  nonce[11] = last ? 1 : 0;
  return nonce;
}

/**
 * @param {unknown} raw
 * @returns {number}
 */
export function normalizeChunkSize(raw) {
  const n = Number(raw);
  if (!raw && raw !== 0) return STREAM_DEFAULT_CHUNK;
  if (!Number.isFinite(n) || Math.trunc(n) !== n) {
    throw new Error("stream: chunk= must be a whole number of bytes");
  }
  if (n < STREAM_MIN_CHUNK || n > STREAM_MAX_CHUNK) {
    throw new Error(
      `stream: chunk= must be between ${STREAM_MIN_CHUNK} and ${STREAM_MAX_CHUNK} bytes`
    );
  }
  return n;
}

/**
 * Import 32 raw bytes as an AES-GCM key.
 * @param {Uint8Array} raw
 */
async function importFileKey(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * @param {number} chunkSize
 * @returns {Uint8Array}  the 12 bytes covered by the wrap's AAD
 */
function headerPrefix(chunkSize) {
  const prefix = new Uint8Array(12);
  prefix.set(STREAM_MAGIC, 0);
  new DataView(prefix.buffer).setUint32(8, chunkSize, false);
  return prefix;
}

/**
 * Seal plaintext into the v1 chunked format.
 * @param {CryptoKey} kek  key-encryption key (the caller's `key=$slot`)
 * @param {Uint8Array} plaintext
 * @param {{ chunk?: number }} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function streamSeal(kek, plaintext, opts = {}) {
  const chunkSize = normalizeChunkSize(opts.chunk);
  const chunks = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  if (chunks > 0xffffffff) {
    throw new Error("stream.seal: too many chunks — raise chunk=");
  }

  const prefix = headerPrefix(chunkSize);
  const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
  const fileKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  let wrapped;
  try {
    wrapped = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: wrapNonce, additionalData: prefix, tagLength: 128 },
        kek,
        fileKeyRaw
      )
    );
  } catch (err) {
    throw new Error(
      `stream.seal: could not wrap the file key with key= — ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }
  const fileKey = await importFileKey(fileKeyRaw);
  fileKeyRaw.fill(0);

  const out = new Uint8Array(
    STREAM_HEADER_LEN + plaintext.length + chunks * STREAM_TAG_LEN
  );
  out.set(prefix, 0);
  out.set(wrapNonce, 12);
  out.set(wrapped, 24);

  let off = STREAM_HEADER_LEN;
  for (let i = 0; i < chunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, plaintext.length);
    const last = i === chunks - 1;
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: streamNonce(i, last), tagLength: 128 },
        fileKey,
        plaintext.subarray(start, end)
      )
    );
    out.set(sealed, off);
    off += sealed.length;
  }
  return out;
}

/**
 * @typedef {object} StreamHeader
 * @property {number} chunkSize
 * @property {Uint8Array} wrapNonce
 * @property {Uint8Array} wrappedKey
 * @property {Uint8Array} prefix
 */

/**
 * Parse and sanity-check the fixed header. Split out so `stream.open` and any
 * future inspector agree on what a malformed file looks like.
 * @param {Uint8Array} bytes
 * @returns {StreamHeader}
 */
export function parseStreamHeader(bytes) {
  if (bytes.length < STREAM_HEADER_LEN) {
    throw new Error("stream.open: not a chunked-AEAD file (shorter than the header)");
  }
  for (let i = 0; i < STREAM_MAGIC.length; i++) {
    if (bytes[i] !== STREAM_MAGIC[i]) {
      throw new Error(
        "stream.open: bad magic — this is not a BSKSTRM1 file (age files need the `age.*` ops)"
      );
    }
  }
  const chunkSize = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  ).getUint32(8, false);
  if (chunkSize < STREAM_MIN_CHUNK || chunkSize > STREAM_MAX_CHUNK) {
    throw new Error(`stream.open: header declares an out-of-range chunk size (${chunkSize})`);
  }
  return {
    chunkSize,
    prefix: bytes.slice(0, 12),
    wrapNonce: bytes.slice(12, 24),
    wrappedKey: bytes.slice(24, STREAM_HEADER_LEN),
  };
}

/**
 * Open a v1 chunked file.
 *
 * Failure modes are named rather than collapsed into "decryption failed",
 * because they mean different things to whoever is holding the file: a bad tag
 * is tampering or the wrong key; a missing final flag is a truncated download.
 * @param {CryptoKey} kek
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>}
 */
export async function streamOpen(kek, bytes) {
  const header = parseStreamHeader(bytes);
  let fileKeyRaw;
  try {
    fileKeyRaw = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: header.wrapNonce,
          additionalData: header.prefix,
          tagLength: 128,
        },
        kek,
        header.wrappedKey
      )
    );
  } catch (_) {
    throw new Error(
      "stream.open: wrong key, or the header was modified — the wrapped file key did not authenticate"
    );
  }
  const fileKey = await importFileKey(fileKeyRaw);
  fileKeyRaw.fill(0);

  const body = bytes.subarray(STREAM_HEADER_LEN);
  const sealedChunk = header.chunkSize + STREAM_TAG_LEN;
  if (body.length < STREAM_TAG_LEN) {
    throw new Error("stream.open: truncated — no payload chunks after the header");
  }

  /** @type {Uint8Array[]} */
  const parts = [];
  let total = 0;
  let off = 0;
  let counter = 0;
  while (off < body.length) {
    const remaining = body.length - off;
    // The last chunk is the one that does not fill a whole sealed chunk. A
    // file whose length happens to land exactly on the boundary still has its
    // final chunk here, because a full-size final chunk is followed by nothing.
    const last = remaining <= sealedChunk;
    const take = last ? remaining : sealedChunk;
    if (take < STREAM_TAG_LEN) {
      throw new Error("stream.open: truncated — a trailing fragment is shorter than one tag");
    }
    if (last && take === STREAM_TAG_LEN && counter > 0) {
      // An empty final chunk after real data is what a truncator leaves behind
      // when it cuts on a chunk boundary and re-tags; it is never produced by
      // `stream.seal` (which only emits an empty chunk for empty input).
      throw new Error("stream.open: truncated — empty final chunk after data");
    }
    let plain;
    try {
      plain = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: streamNonce(counter, last), tagLength: 128 },
          fileKey,
          body.subarray(off, off + take)
        )
      );
    } catch (_) {
      throw new Error(
        last
          ? `stream.open: chunk ${counter} failed to authenticate — the file was modified, truncated, or its chunks reordered`
          : `stream.open: chunk ${counter} failed to authenticate — the file was modified or its chunks reordered`
      );
    }
    parts.push(plain);
    total += plain.length;
    off += take;
    counter++;
    if (counter > 0xffffffff) throw new Error("stream.open: chunk counter overflow");
  }

  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
