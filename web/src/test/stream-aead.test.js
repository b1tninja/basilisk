/**
 * `stream.seal` / `stream.open` — the chunked AEAD format.
 *
 * Round-tripping is the easy half. The half worth testing is the reason the
 * STREAM construction exists at all: naive chunked AEAD lets an attacker drop
 * the tail, reorder chunks, or splice chunks in from another file, and every
 * individual tag still verifies. Each of those is a case below, exercised
 * across a chunk boundary so the multi-chunk path is the one under test.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  STREAM_DEFAULT_CHUNK,
  STREAM_HEADER_LEN,
  STREAM_MAGIC,
  STREAM_TAG_LEN,
  normalizeChunkSize,
  parseStreamHeader,
  streamNonce,
  streamOpen,
  streamSeal,
} from "../lib/toolkit/stream-aead.js";

/** Small enough that a few KiB of plaintext spans several chunks. */
const CHUNK = 1024;

/** @type {CryptoKey} */
let key;
/** @type {CryptoKey} */
let otherKey;

async function freshKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Deterministic filler, so a failure names a byte you can find. */
function plaintext(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 7 + 11) & 0xff;
  return out;
}

beforeAll(async () => {
  key = await freshKey();
  otherKey = await freshKey();
});

describe("round trip", () => {
  it("survives an empty plaintext", async () => {
    const sealed = await streamSeal(key, new Uint8Array(0), { chunk: CHUNK });
    // One chunk, and that chunk is nothing but its tag.
    expect(sealed.length).toBe(STREAM_HEADER_LEN + STREAM_TAG_LEN);
    expect(await streamOpen(key, sealed)).toEqual(new Uint8Array(0));
  });

  it("survives a single sub-chunk payload", async () => {
    const pt = plaintext(100);
    const sealed = await streamSeal(key, pt, { chunk: CHUNK });
    expect(sealed.length).toBe(STREAM_HEADER_LEN + 100 + STREAM_TAG_LEN);
    expect(await streamOpen(key, sealed)).toEqual(pt);
  });

  it("survives a payload spanning several chunks", async () => {
    const pt = plaintext(CHUNK * 3 + 17);
    const sealed = await streamSeal(key, pt, { chunk: CHUNK });
    expect(sealed.length).toBe(STREAM_HEADER_LEN + pt.length + 4 * STREAM_TAG_LEN);
    expect(await streamOpen(key, sealed)).toEqual(pt);
  });

  it("survives a payload that lands exactly on a chunk boundary", async () => {
    // The boundary case is where an off-by-one in "is this the last chunk"
    // hides: the final chunk is full-size and followed by nothing.
    const pt = plaintext(CHUNK * 2);
    const sealed = await streamSeal(key, pt, { chunk: CHUNK });
    expect(sealed.length).toBe(STREAM_HEADER_LEN + pt.length + 2 * STREAM_TAG_LEN);
    expect(await streamOpen(key, sealed)).toEqual(pt);
  });

  it("defaults to age's 64 KiB chunk", async () => {
    const pt = plaintext(1000);
    const sealed = await streamSeal(key, pt);
    expect(parseStreamHeader(sealed).chunkSize).toBe(STREAM_DEFAULT_CHUNK);
    expect(await streamOpen(key, sealed)).toEqual(pt);
  });

  it("is randomized per file — two seals of one plaintext differ", async () => {
    const pt = plaintext(200);
    const a = await streamSeal(key, pt, { chunk: CHUNK });
    const b = await streamSeal(key, pt, { chunk: CHUNK });
    expect(a).not.toEqual(b);
    // …because the file key is fresh, which is exactly what makes the counter
    // nonces safe under a reused `key=`.
    expect(a.slice(12)).not.toEqual(b.slice(12));
  });
});

describe("tampering", () => {
  /** @param {Uint8Array} sealed @param {number} i */
  function flip(sealed, i) {
    const copy = sealed.slice();
    copy[i] ^= 0x40;
    return copy;
  }

  it("rejects a flipped bit in the first chunk's ciphertext", async () => {
    const sealed = await streamSeal(key, plaintext(CHUNK * 2 + 5), { chunk: CHUNK });
    await expect(streamOpen(key, flip(sealed, STREAM_HEADER_LEN + 3))).rejects.toThrow(
      /chunk 0 failed to authenticate/
    );
  });

  it("rejects a flipped bit in a middle chunk, not just the last", async () => {
    // The failure a one-shot AEAD would also catch is uninteresting; this is
    // the one that only chunk-level tags catch at the right position.
    const sealed = await streamSeal(key, plaintext(CHUNK * 3), { chunk: CHUNK });
    const at = STREAM_HEADER_LEN + (CHUNK + STREAM_TAG_LEN) + 10;
    await expect(streamOpen(key, flip(sealed, at))).rejects.toThrow(
      /chunk 1 failed to authenticate/
    );
  });

  it("rejects a flipped bit in a chunk's tag", async () => {
    const sealed = await streamSeal(key, plaintext(50), { chunk: CHUNK });
    await expect(streamOpen(key, flip(sealed, sealed.length - 2))).rejects.toThrow(
      /failed to authenticate/
    );
  });

  it("rejects a modified header — the chunk size is bound into the wrap's AAD", async () => {
    const sealed = await streamSeal(key, plaintext(CHUNK * 2), { chunk: CHUNK });
    const forged = sealed.slice();
    // Rewrite the declared chunk size to 2048 and leave everything else.
    new DataView(forged.buffer).setUint32(8, 2048, false);
    await expect(streamOpen(key, forged)).rejects.toThrow(
      /wrong key, or the header was modified/
    );
  });

  it("rejects a modified wrapped key", async () => {
    const sealed = await streamSeal(key, plaintext(50), { chunk: CHUNK });
    await expect(streamOpen(key, flip(sealed, 30))).rejects.toThrow(
      /wrong key, or the header was modified/
    );
  });

  it("rejects the wrong key without leaking which chunk failed", async () => {
    const sealed = await streamSeal(key, plaintext(50), { chunk: CHUNK });
    await expect(streamOpen(otherKey, sealed)).rejects.toThrow(
      /wrong key, or the header was modified/
    );
  });
});

describe("truncation", () => {
  it("rejects a file cut exactly on a chunk boundary", async () => {
    // The attack the final-chunk flag exists for: every remaining chunk still
    // has a valid tag, so only the flag byte in the nonce reveals the cut.
    const sealed = await streamSeal(key, plaintext(CHUNK * 3), { chunk: CHUNK });
    const cut = sealed.slice(0, STREAM_HEADER_LEN + 2 * (CHUNK + STREAM_TAG_LEN));
    await expect(streamOpen(key, cut)).rejects.toThrow(/failed to authenticate/);
  });

  it("rejects a file cut mid-chunk", async () => {
    const sealed = await streamSeal(key, plaintext(CHUNK * 2 + 500), { chunk: CHUNK });
    await expect(streamOpen(key, sealed.slice(0, sealed.length - 40))).rejects.toThrow(
      /failed to authenticate/
    );
  });

  it("rejects a file with nothing after the header", async () => {
    const sealed = await streamSeal(key, plaintext(100), { chunk: CHUNK });
    await expect(streamOpen(key, sealed.slice(0, STREAM_HEADER_LEN))).rejects.toThrow(
      /truncated — no payload chunks/
    );
  });

  it("rejects bytes appended after the real final chunk", async () => {
    // Extension is the mirror of truncation and the flag catches it the same
    // way: the chunk that was sealed as final is now read as non-final, so its
    // nonce no longer matches.
    const sealed = await streamSeal(key, plaintext(CHUNK * 2), { chunk: CHUNK });
    const extra = new Uint8Array(sealed.length + 4);
    extra.set(sealed, 0);
    await expect(streamOpen(key, extra)).rejects.toThrow(
      /chunk 1 failed to authenticate/
    );
  });

  it("rejects an empty final chunk after real data", async () => {
    // What a truncator leaves when it cuts on a boundary and re-tags: a
    // zero-length final chunk, which `stream.seal` only ever emits for empty
    // input. Caught before any decryption, by shape alone.
    const sealed = await streamSeal(key, plaintext(CHUNK * 2), { chunk: CHUNK });
    const stride = CHUNK + STREAM_TAG_LEN;
    const forged = new Uint8Array(STREAM_HEADER_LEN + stride + STREAM_TAG_LEN);
    forged.set(sealed.subarray(0, STREAM_HEADER_LEN + stride), 0);
    await expect(streamOpen(key, forged)).rejects.toThrow(
      /truncated — empty final chunk after data/
    );
  });
});

describe("reordering and splicing", () => {
  it("rejects two chunks swapped", async () => {
    const sealed = await streamSeal(key, plaintext(CHUNK * 3), { chunk: CHUNK });
    const stride = CHUNK + STREAM_TAG_LEN;
    const forged = sealed.slice();
    const first = sealed.slice(STREAM_HEADER_LEN, STREAM_HEADER_LEN + stride);
    const second = sealed.slice(
      STREAM_HEADER_LEN + stride,
      STREAM_HEADER_LEN + 2 * stride
    );
    forged.set(second, STREAM_HEADER_LEN);
    forged.set(first, STREAM_HEADER_LEN + stride);
    await expect(streamOpen(key, forged)).rejects.toThrow(
      /chunk 0 failed to authenticate/
    );
  });

  it("rejects a duplicated chunk", async () => {
    const sealed = await streamSeal(key, plaintext(CHUNK * 3), { chunk: CHUNK });
    const stride = CHUNK + STREAM_TAG_LEN;
    const forged = sealed.slice();
    forged.set(
      sealed.slice(STREAM_HEADER_LEN, STREAM_HEADER_LEN + stride),
      STREAM_HEADER_LEN + stride
    );
    await expect(streamOpen(key, forged)).rejects.toThrow(
      /chunk 1 failed to authenticate/
    );
  });

  it("rejects a chunk spliced in from another file sealed under the same key", async () => {
    // Both files' chunk 1 has a valid tag *for its own file key*; the whole
    // point of wrapping a per-file key is that they are not interchangeable.
    const stride = CHUNK + STREAM_TAG_LEN;
    const a = await streamSeal(key, plaintext(CHUNK * 3), { chunk: CHUNK });
    const b = await streamSeal(key, plaintext(CHUNK * 3), { chunk: CHUNK });
    const forged = a.slice();
    forged.set(
      b.slice(STREAM_HEADER_LEN + stride, STREAM_HEADER_LEN + 2 * stride),
      STREAM_HEADER_LEN + stride
    );
    await expect(streamOpen(key, forged)).rejects.toThrow(
      /chunk 1 failed to authenticate/
    );
  });
});

describe("format", () => {
  it("starts with the BSKSTRM1 magic, which is not age's", async () => {
    const sealed = await streamSeal(key, plaintext(10), { chunk: CHUNK });
    expect(sealed.slice(0, 8)).toEqual(STREAM_MAGIC);
    expect(new TextDecoder().decode(sealed.slice(0, 8))).toBe("BSKSTRM1");
    // If this ever starts with age's header, the divergence documented in the
    // module has become a lie.
    expect(new TextDecoder().decode(sealed.slice(0, 21))).not.toContain(
      "age-encryption.org"
    );
  });

  it("refuses a file that is not this format", async () => {
    const notOurs = new Uint8Array(STREAM_HEADER_LEN + 32);
    notOurs.set(new TextEncoder().encode("age-encryption.org/v1"), 0);
    await expect(streamOpen(key, notOurs)).rejects.toThrow(/bad magic/);
    expect(() => parseStreamHeader(notOurs)).toThrow(/bad magic/);
  });

  it("refuses a file shorter than the header", async () => {
    await expect(streamOpen(key, new Uint8Array(20))).rejects.toThrow(
      /shorter than the header/
    );
  });

  it("refuses an out-of-range chunk size, in the param and in the header", async () => {
    await expect(streamSeal(key, plaintext(10), { chunk: 8 })).rejects.toThrow(
      /chunk= must be between/
    );
    await expect(
      streamSeal(key, plaintext(10), { chunk: 1024 * 1024 * 64 })
    ).rejects.toThrow(/chunk= must be between/);
    expect(() => normalizeChunkSize(1.5)).toThrow(/whole number/);
    expect(normalizeChunkSize(undefined)).toBe(STREAM_DEFAULT_CHUNK);

    const sealed = await streamSeal(key, plaintext(10), { chunk: CHUNK });
    const forged = sealed.slice();
    new DataView(forged.buffer).setUint32(8, 4, false);
    await expect(streamOpen(key, forged)).rejects.toThrow(/out-of-range chunk size/);
  });
});

describe("STREAM nonce", () => {
  it("is a big-endian counter with the final-chunk flag last", () => {
    expect(streamNonce(0, false)).toEqual(new Uint8Array(12));
    expect([...streamNonce(0, true)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect([...streamNonce(1, false)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    expect([...streamNonce(256, false)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
  });

  it("gives the same index different nonces for last and not-last", () => {
    // This inequality is the whole truncation defence.
    expect(streamNonce(7, false)).not.toEqual(streamNonce(7, true));
  });

  it("never repeats a nonce across a plausible chunk range", () => {
    const seen = new Set();
    for (let i = 0; i < 2000; i++) {
      for (const last of [false, true]) {
        seen.add(streamNonce(i, last).join(","));
      }
    }
    expect(seen.size).toBe(4000);
  });
});
