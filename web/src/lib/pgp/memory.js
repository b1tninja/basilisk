/**
 * Best-effort wipe of decrypted private-key material from OpenPGP.js key objects.
 * Does not guarantee the runtime has not already copied material into JIT code,
 * GC survivor spaces, or CPU registers.
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
