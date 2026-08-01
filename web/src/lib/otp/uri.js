/**
 * The `otpauth://` Key URI Format — build and parse.
 *
 * This is the enrolment wire format: the string behind every QR code an
 * authenticator app scans. It has no RFC; the normative description is
 * Google's Key URI Format page, and what everyone actually implements is
 * whatever Google Authenticator accepts.
 *
 *     otpauth://totp/Big%20Corp:alice%40example.com
 *       ?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corp
 *       &algorithm=SHA1&digits=6&period=30
 *
 * Parsing is the half that earns its keep, because people paste these:
 *
 *  - **The label is `issuer:account`, both percent-encoded, and the separator
 *    may itself arrive as `%3A`.** Decoding the path first and then splitting
 *    turns an account name containing a colon into a phantom issuer, so the
 *    split happens on the *encoded* text (`splitLabel`).
 *  - **`issuer=` and the label's issuer must agree.** The Key URI Format says
 *    a reader should treat a disagreement as invalid rather than silently
 *    picking one — two different issuers is two different accounts.
 *  - **`counter=` is required for `hotp` and meaningless for `totp`.** A HOTP
 *    URI without one cannot produce a code at all, so it is refused at parse
 *    rather than defaulted to zero, which would hand back a wrong code.
 *  - **The scheme and type are case-insensitive, but the host is not
 *    lowercased for us.** `otpauth:` is a non-special scheme, so `URL` leaves
 *    `OTPAUTH://TOTP/…` with a host of `TOTP`.
 *
 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */

import { base32ToBytes, bytesToBase32 } from "../toolkit/encode.js";
import { normalizeAlgorithm, normalizeDigits, normalizePeriod } from "./hotp.js";

/** The two OTP flavours a URI can name. */
export const OTP_TYPES = /** @type {const} */ (["totp", "hotp"]);

/**
 * @typedef {object} OtpUriRecord
 * @property {"totp"|"hotp"} type
 * @property {string} secret  Base32, uppercase, unpadded
 * @property {string} issuer  may be ""
 * @property {string} account
 * @property {import("./hotp.js").OtpAlgorithm} algorithm
 * @property {number} digits
 * @property {number} period  seconds per step (carried for hotp too, unused there)
 * @property {number} counter  hotp only; 0 for totp
 */

/**
 * Base32 as the URI carries it: uppercase, no padding, no spaces — and only
 * after proving it decodes, so a typo is caught here rather than as a wrong
 * code six steps later.
 * @param {string} secret
 * @returns {string}
 */
export function normalizeSecret(secret) {
  const raw = String(secret ?? "").trim();
  if (!raw) throw new Error("otpauth: secret= is required — it is the shared key");
  let bytes;
  try {
    bytes = base32ToBytes(raw);
  } catch (_) {
    throw new Error(`otpauth: secret= is not Base32 ("${raw.slice(0, 16)}…")`);
  }
  if (!bytes.length) throw new Error("otpauth: secret= decodes to nothing");
  return bytesToBase32(bytes);
}

/**
 * @param {string|undefined|null} type
 * @returns {"totp"|"hotp"}
 */
export function normalizeType(type) {
  const t = String(type ?? "totp").trim().toLowerCase();
  if (t === "totp" || t === "hotp") return t;
  throw new Error(`otpauth: unknown type "${type}" — the URI names totp or hotp`);
}

/**
 * Build an `otpauth://` URI.
 *
 * `algorithm`, `digits` and `period` are always emitted even at their
 * defaults. They are optional in the format, but the defaults readers assume
 * are not uniform in the wild, and a URI that states them cannot be read two
 * ways.
 *
 * @param {Partial<OtpUriRecord>} rec
 * @returns {string}
 */
export function buildOtpauthUri(rec = {}) {
  const type = normalizeType(rec.type);
  const secret = normalizeSecret(rec.secret);
  const issuer = String(rec.issuer ?? "").trim();
  const account = String(rec.account ?? "").trim();
  const algorithm = normalizeAlgorithm(rec.algorithm);
  const digits = normalizeDigits(rec.digits);
  const period = normalizePeriod(rec.period);
  if (!account) {
    throw new Error(
      "otpauth: account= is required — the label is the line your authenticator lists"
    );
  }
  if (issuer.includes(":")) {
    throw new Error('otpauth: issuer= cannot contain ":" — it is the label separator');
  }
  const label = issuer
    ? `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`
    : encodeURIComponent(account);
  const params = new URLSearchParams();
  params.set("secret", secret);
  if (issuer) params.set("issuer", issuer);
  params.set("algorithm", algorithm);
  params.set("digits", String(digits));
  if (type === "hotp") {
    const counter = Number(rec.counter ?? 0);
    if (!Number.isInteger(counter) || counter < 0) {
      throw new Error(`otpauth: hotp needs a whole counter, zero or more (got ${rec.counter})`);
    }
    params.set("counter", String(counter));
  } else {
    params.set("period", String(period));
  }
  // `URLSearchParams` encodes a space as "+", which is form encoding, not URI
  // encoding — readers that percent-decode the query turn `Big+Corp` into
  // `Big+Corp`. %20 is what every authenticator emits.
  return `otpauth://${type}/${label}?${params.toString().replace(/\+/g, "%20")}`;
}

/**
 * Split an encoded label into its issuer and account halves at the first
 * separator, whether that separator is a literal `:` or `%3A`.
 * @param {string} encodedPath  the URI path, still percent-encoded, no leading /
 * @returns {{ issuer: string, account: string }}
 */
function splitLabel(encodedPath) {
  const match = /:|%3a/i.exec(encodedPath);
  if (!match) {
    return { issuer: "", account: decodeURIComponent(encodedPath) };
  }
  const left = encodedPath.slice(0, match.index);
  const right = encodedPath.slice(match.index + match[0].length);
  return {
    issuer: decodeURIComponent(left),
    // "Issuer: account" with a space after the colon is legal and common.
    account: decodeURIComponent(right).replace(/^\s+/, ""),
  };
}

/**
 * Parse an `otpauth://` URI into its parts, refusing the ambiguous ones.
 * @param {string} text
 * @returns {OtpUriRecord}
 */
export function parseOtpauthUri(text) {
  const raw = String(text ?? "").trim();
  if (!/^otpauth:\/\//i.test(raw)) {
    throw new Error(
      'otpauth: not a Key URI — it starts with "otpauth://totp/" or "otpauth://hotp/"'
    );
  }
  let url;
  try {
    url = new URL(raw);
  } catch (_) {
    throw new Error("otpauth: the URI is malformed");
  }
  // `otpauth:` is a non-special scheme, so the host keeps its case.
  const type = normalizeType(url.host);
  const { issuer: labelIssuer, account } = splitLabel(url.pathname.replace(/^\//, ""));
  if (!account) {
    throw new Error("otpauth: the label has no account name");
  }
  const q = url.searchParams;
  const paramIssuer = q.get("issuer");
  if (paramIssuer != null && labelIssuer && paramIssuer !== labelIssuer) {
    throw new Error(
      `otpauth: issuer= says "${paramIssuer}" but the label says "${labelIssuer}" — ` +
        "two issuers is two accounts, so this URI is ambiguous"
    );
  }
  const rec = {
    type,
    secret: normalizeSecret(q.get("secret")),
    issuer: (paramIssuer ?? labelIssuer ?? "").trim(),
    account,
    algorithm: normalizeAlgorithm(q.get("algorithm") ?? "SHA1"),
    digits: normalizeDigits(q.get("digits") ?? 6),
    period: normalizePeriod(q.get("period") ?? 30),
    counter: 0,
  };
  if (type === "hotp") {
    const counter = q.get("counter");
    if (counter == null || counter.trim() === "") {
      throw new Error(
        "otpauth: a hotp URI must carry counter= — without it there is no code to compute"
      );
    }
    const n = Number(counter);
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(`otpauth: counter= must be a whole number, zero or more (got "${counter}")`);
    }
    rec.counter = n;
  }
  return rec;
}

/**
 * Whether a string looks like a Key URI, without committing to parsing it.
 * @param {string} text
 */
export function isOtpauthUri(text) {
  return /^\s*otpauth:\/\//i.test(String(text ?? ""));
}
