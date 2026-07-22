/**
 * Best-effort wipe of decrypted private-key material from OpenPGP.js key objects.
 *
 * ── Browser constraints (read before “improving” this) ─────────────────────
 * WebCrypto / OpenPGP.js expose private scalars as Uint8Array (or MPI wrappers)
 * once a key is decrypted in JS. We can overwrite those views with fill(0).
 * We cannot:
 *   - force the UA to zeroize non-extractable CryptoKey handles (W3C WebCrypto
 *     § Security considerations for developers — no normative zeroization);
 *   - erase immutable JS string copies of armored key blocks;
 *   - scrub JIT/GC ghost copies of the same ArrayBuffer.
 *
 * Keep secrets in typed arrays for as long as they exist in script, wipe in
 * finally{}, and drop references. Prefer extractable:false WebCrypto keys when
 * the algorithm path allows it so raw bytes never enter JS at all.
 *
 * @param {import("openpgp").PrivateKey | null | undefined} key
 */
export function zeroKeyMaterial(key) {
  if (!key) return;
  const wipePacket = (pkt) => {
    const params = pkt?.privateParams;
    if (!params || typeof params !== "object") return;
    for (const v of Object.values(params)) {
      if (v instanceof Uint8Array) {
        v.fill(0);
      } else if (v && v.data instanceof Uint8Array) {
        // MPI wrapper (used by RSA / legacy keys)
        v.data.fill(0);
      }
    }
  };
  try {
    wipePacket(key.keyPacket);
    for (const sk of key.subkeys || []) {
      wipePacket(sk?.keyPacket);
    }
  } catch (_) {
    // Best-effort only — never throw from a cleanup path
  }
}
