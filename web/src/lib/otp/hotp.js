/**
 * HOTP (RFC 4226) and TOTP (RFC 6238) — the whole algorithm, in the two
 * primitives the toolkit already ships: an HMAC and a Base32 alphabet.
 *
 * Nothing here touches the DOM or the vault, so every `otp.*` op runs
 * headlessly in the CLI the way the `ssh.*` family does.
 *
 * The parts implementations get wrong, and where they are handled:
 *
 *  - **The counter is eight bytes, big-endian, always.** Not "as many bytes as
 *    the number needs" — RFC 4226 §5.1 fixes the message length, so a
 *    four-byte counter agrees with everyone else right up until 2038.
 *    `counterBytes` builds all eight from a BigInt.
 *  - **Dynamic truncation reads the *last* nibble for its offset**, then four
 *    bytes from there with the top bit cleared (so the value is positive on
 *    every platform, signed integers included). See `truncate`.
 *  - **Verification needs a window.** Clocks drift, and a user takes a few
 *    seconds to type. `verifyTotp` scans ±N steps in order of increasing
 *    drift so the reported `delta` is the closest match, not the first one
 *    scanned. HOTP's window is look-*ahead* only: a server's counter never
 *    moves backwards, so accepting a code from a past counter would accept a
 *    replay.
 *
 * @see https://www.rfc-editor.org/rfc/rfc4226 — HOTP
 * @see https://www.rfc-editor.org/rfc/rfc6238 — TOTP
 */

/** @typedef {"SHA1"|"SHA256"|"SHA512"} OtpAlgorithm */

/** Canonical algorithm names, in the spelling the `otpauth://` URI uses. */
export const OTP_ALGORITHMS = /** @type {const} */ (["SHA1", "SHA256", "SHA512"]);

/** URI spelling → WebCrypto digest name. */
const WEB_HASH = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

/**
 * Canonical algorithm name from anything a user or a URI might write
 * (`sha-1`, `SHA1`, `sha_256`).
 *
 * SHA-1 is not a mistake here: RFC 4226 specifies HMAC-SHA-1, and HMAC does
 * not inherit SHA-1's collision weakness — the `digest alg=sha-1` warning is
 * about a bare hash, which is a different question.
 *
 * @param {string|undefined|null} name
 * @returns {OtpAlgorithm}
 */
export function normalizeAlgorithm(name) {
  const key = String(name ?? "SHA1").trim().toUpperCase().replace(/[-_\s]/g, "");
  if (key === "SHA1" || key === "SHA256" || key === "SHA512") return key;
  throw new Error(
    `OTP: unknown algorithm "${name}" — the Key URI Format names SHA1, SHA256 and SHA512`
  );
}

/**
 * Code length, bounded to what RFC 4226 §5.3 allows.
 * @param {number|string|undefined|null} digits
 * @returns {number}
 */
export function normalizeDigits(digits) {
  const n = Number(digits ?? 6);
  if (!Number.isInteger(n) || n < 6 || n > 8) {
    throw new Error(`OTP: digits must be 6, 7 or 8 (got ${digits})`);
  }
  return n;
}

/**
 * Seconds per time step.
 * @param {number|string|undefined|null} period
 * @returns {number}
 */
export function normalizePeriod(period) {
  const n = Number(period ?? 30);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`OTP: period must be a whole number of seconds above zero (got ${period})`);
  }
  return n;
}

/**
 * The shared secret as bytes, refusing an empty one.
 * @param {Uint8Array} secret
 * @returns {Uint8Array}
 */
function secretBytes(secret) {
  if (!(secret instanceof Uint8Array)) {
    throw new Error("OTP: the shared secret must be bytes");
  }
  if (secret.length === 0) {
    throw new Error("OTP: the shared secret is empty — nothing to key the HMAC with");
  }
  return secret;
}

/**
 * The counter as the 8-byte big-endian block RFC 4226 §5.1 hashes.
 * @param {number|bigint} counter
 * @returns {Uint8Array}
 */
export function counterBytes(counter) {
  let c =
    typeof counter === "bigint"
      ? counter
      : BigInt(Math.trunc(Number(counter)));
  if (c < 0n) throw new Error("OTP: the counter cannot be negative");
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  if (c !== 0n) throw new Error("OTP: the counter does not fit in eight bytes");
  return out;
}

/**
 * HMAC over one counter block.
 * @param {Uint8Array} secret
 * @param {Uint8Array} message
 * @param {OtpAlgorithm} algorithm
 * @returns {Promise<Uint8Array>}
 */
async function hmac(secret, message, algorithm) {
  const params = { name: "HMAC", hash: WEB_HASH[algorithm] };
  const key = await crypto.subtle.importKey("raw", secret, params, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
}

/**
 * Dynamic truncation (RFC 4226 §5.3) — the MAC's last nibble picks a byte
 * offset, four bytes from there become a 31-bit number, and the low `digits`
 * decimal places of that number are the code.
 *
 * @param {Uint8Array} mac
 * @param {number} digits  6–8, already normalized
 * @returns {string}  zero-padded, because `053019` is a perfectly good code
 */
export function truncate(mac, digits) {
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

/**
 * HOTP — RFC 4226.
 * @param {Uint8Array} secret
 * @param {number|bigint} counter
 * @param {{ algorithm?: string, digits?: number }} [opts]
 * @returns {Promise<string>}
 */
export async function hotp(secret, counter, opts = {}) {
  const algorithm = normalizeAlgorithm(opts.algorithm);
  const digits = normalizeDigits(opts.digits);
  const mac = await hmac(secretBytes(secret), counterBytes(counter), algorithm);
  return truncate(mac, digits);
}

/**
 * The time-step number for a wall-clock instant: `floor((T − T0) / X)`.
 * @param {number} seconds  Unix seconds
 * @param {number} [period]  X, seconds per step
 * @param {number} [t0]  T0, the epoch the count starts from
 * @returns {bigint}
 */
export function timeCounter(seconds, period = 30, t0 = 0) {
  const x = normalizePeriod(period);
  const t = Number(seconds);
  if (!Number.isFinite(t)) throw new Error(`OTP: "${seconds}" is not a time`);
  const steps = Math.floor((t - Number(t0)) / x);
  if (steps < 0) {
    throw new Error("OTP: that time is before T0 — there is no step number for it");
  }
  return BigInt(steps);
}

/**
 * TOTP — RFC 6238. HOTP over the current time step.
 * @param {Uint8Array} secret
 * @param {{ algorithm?: string, digits?: number, period?: number, t0?: number, seconds?: number }} [opts]
 * @returns {Promise<string>}
 */
export async function totp(secret, opts = {}) {
  const period = normalizePeriod(opts.period);
  const seconds = opts.seconds == null ? Date.now() / 1000 : Number(opts.seconds);
  return hotp(secret, timeCounter(seconds, period, opts.t0 ?? 0), opts);
}

/**
 * Seconds left in the current time step — what a countdown ring draws.
 * @param {{ period?: number, t0?: number, seconds?: number }} [opts]
 * @returns {number}
 */
export function secondsRemaining(opts = {}) {
  const period = normalizePeriod(opts.period);
  const seconds = opts.seconds == null ? Date.now() / 1000 : Number(opts.seconds);
  const elapsed = (seconds - Number(opts.t0 ?? 0)) % period;
  return Math.ceil(period - (elapsed < 0 ? elapsed + period : elapsed));
}

/**
 * The submitted code, as digits. Authenticators display `123 456`, and users
 * paste what they see.
 * @param {string} code
 * @returns {string}
 */
export function normalizeCode(code) {
  const clean = String(code ?? "").replace(/[\s-]/g, "");
  if (!/^[0-9]+$/.test(clean)) {
    throw new Error(`OTP: "${code}" is not a code — a code is 6 to 8 digits`);
  }
  return clean;
}

/**
 * Length-checked, data-independent string compare. The codes are short and
 * public-ish, but comparing them with `===` is the habit that leaks longer
 * secrets elsewhere, so it is not the habit this file teaches.
 * @param {string} a
 * @param {string} b
 */
function equalInTime(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Window as a non-negative whole number of steps.
 * @param {number|string|undefined|null} window
 * @returns {number}
 */
export function normalizeWindow(window) {
  const n = Number(window ?? 1);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`OTP: window must be a whole number of steps, zero or more (got ${window})`);
  }
  return n;
}

/**
 * Drifts to try, closest first: 0, −1, +1, −2, +2 … Ordered so that when two
 * steps would both match (they will not, but the ordering is the contract)
 * the reported `delta` is the smallest.
 * @param {number} window
 * @returns {number[]}
 */
function driftOrder(window) {
  const out = [0];
  for (let i = 1; i <= window; i++) out.push(-i, i);
  return out;
}

/**
 * @typedef {object} OtpVerdict
 * @property {boolean} ok
 * @property {number|null} delta  steps between the accepted code and now
 *   (negative = the code was from a past step, i.e. the client is behind)
 * @property {bigint|null} counter  the counter that matched
 */

/**
 * Verify a TOTP code against ±`window` time steps.
 *
 * @param {string} code
 * @param {Uint8Array} secret
 * @param {{ algorithm?: string, digits?: number, period?: number, t0?: number, seconds?: number, window?: number }} [opts]
 * @returns {Promise<OtpVerdict>}
 */
export async function verifyTotp(code, secret, opts = {}) {
  const submitted = normalizeCode(code);
  const digits = normalizeDigits(opts.digits);
  const period = normalizePeriod(opts.period);
  const window = normalizeWindow(opts.window);
  const seconds = opts.seconds == null ? Date.now() / 1000 : Number(opts.seconds);
  const base = timeCounter(seconds, period, opts.t0 ?? 0);
  for (const delta of driftOrder(window)) {
    const counter = base + BigInt(delta);
    if (counter < 0n) continue;
    const expected = await hotp(secret, counter, { ...opts, digits });
    if (equalInTime(submitted, expected)) return { ok: true, delta, counter };
  }
  return { ok: false, delta: null, counter: null };
}

/**
 * Verify a HOTP code, looking *ahead* up to `window` counters.
 *
 * Deliberately one-sided. A HOTP server's counter only ever advances, so
 * scanning backwards would accept a code the client already spent — the
 * resynchronisation window in RFC 4226 §7.4 is a look-ahead, and `delta` is
 * how far the client has run ahead of the server.
 *
 * @param {string} code
 * @param {Uint8Array} secret
 * @param {number|bigint} counter
 * @param {{ algorithm?: string, digits?: number, window?: number }} [opts]
 * @returns {Promise<OtpVerdict>}
 */
export async function verifyHotp(code, secret, counter, opts = {}) {
  const submitted = normalizeCode(code);
  const digits = normalizeDigits(opts.digits);
  const window = normalizeWindow(opts.window);
  const base = typeof counter === "bigint" ? counter : BigInt(Math.trunc(Number(counter)));
  for (let delta = 0; delta <= window; delta++) {
    const at = base + BigInt(delta);
    const expected = await hotp(secret, at, { ...opts, digits });
    if (equalInTime(submitted, expected)) return { ok: true, delta, counter: at };
  }
  return { ok: false, delta: null, counter: null };
}
