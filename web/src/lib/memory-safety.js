/**
 * Browser memory-safety policy for secret material (keys, masters, plaintext).
 *
 * This module is documentation only — it deliberately exports nothing.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * WHY NO shared zeroBuffer() HELPER
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A single wipe function is an attractive debugger breakpoint: every secret
 * buffer destined for erasure arrives as an argument on one stack frame.
 * Prefer the inlined idiom at each call site so there is no central chokepoint
 * to trap “pointers about to be scrubbed”.
 *
 * Inline idiom (Uint8Array — preferred):
 *
 *   try { secret.fill(0); } catch (_) { /* never throw from cleanup */ }
 *
 * Inline idiom (ArrayBuffer | Uint8Array):
 *
 *   try {
 *     (buf instanceof Uint8Array ? buf : new Uint8Array(buf)).fill(0);
 *   } catch (_) { /* never throw from cleanup */ }
 *
 * After postMessage(…, [bytes.buffer]) transfer, the sender view is detached
 * (byteLength → 0). If a live view remains:
 *
 *   try { if (bytes?.byteLength > 0) bytes.fill(0); } catch (_) {}
 *
 * OpenPGP private key objects: use zeroKeyMaterial() in pgp/memory.js (walks
 * privateParams; unavoidable shared helper for that structure).
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * WHY WIPE AT ALL (browser limits)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Basilisk runs in a browser sandbox. We cannot mlock(2), cannot force the JS
 * engine to scrub GC survivor spaces, and WebCrypto places no normative duty
 * on UAs to zeroize CryptoKey material when the last reference is dropped:
 *
 *   W3C Web Cryptography API — Security considerations for developers
 *   https://www.w3.org/TR/webcrypto/#security-developers
 *
 * Non-extractable CryptoKey handles (`extractable: false`) keep raw key bytes
 * inside the crypto engine — the strongest browser-native option for long-lived
 * keys. Anything we *export* into JS (JWK.d, PKCS#8, SLIP-39 masters, OpenPGP
 * privateParams) lands in ordinary ArrayBuffers that we *can* overwrite — but
 * only if we keep them as mutable typed arrays.
 *
 * fill(0) is best-effort: it overwrites the reachable backing store, but does
 * not prove that no earlier GC copies or CPU caches remain.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * HARD RULES (do not regress without an explicit security review)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * 1. Prefer Uint8Array / ArrayBuffer for secret octets — never rely on a
 *    JS string as the only copy of key material. Strings are immutable; once
 *    created they cannot be wiped, and the engine may intern / rope / JIT-
 *    cache them indefinitely.
 *
 * 2. Wipe with the inlined fill(0) idiom (above) in a finally block as soon as
 *    a secret buffer is no longer needed. Do not reintroduce a shared
 *    zeroBuffer() export “for convenience”.
 *
 * 3. When moving secret bytes across realms (Workers, Encrypt popout via
 *    postMessage), prefer transferring the ArrayBuffer (structured-clone
 *    transfer list) over copying. Transfer detaches the sender’s buffer
 *    (byteLength → 0). See MDN “Transferable objects”:
 *    https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Transferable_objects
 *
 * 4. Recipe sinks decide Encrypt disposition — do not reintroduce content
 *    sniffing (hex/base64/armor → “message”) that would encourage storing
 *    secrets only as display strings:
 *      text / print  → disposition "message" (compose; string unavoidable)
 *      out name=…    → disposition "file"   (attachment; keep artifact.bytes)
 *
 * 5. Destroy / idle scrub must drop references AND clear DOM fields. Worker
 *    terminate() discards that heap wholesale — prefer it over hoping GC
 *    collects CryptoKey / OpenPGP objects promptly.
 *
 * 6. Never put secret octets in URLs, localStorage, sessionStorage, or
 *    IndexedDB unless wrapped under a vault scheme with extractable:false
 *    wrapping keys (see vault.js).
 *
 * ── Related: module-load integrity (CDN skew / tampering) ──────────────────
 * Secret wiping does not cover “wrong code loaded”. That is Subresource
 * Integrity: entry tags + /importmaps/importmap-*.json (see
 * web/scripts/externalize-importmaps.js). On hash mismatch the UA refuses
 * the module — fail closed; do not strip those maps to “fix” CSP.
 */

export {};
