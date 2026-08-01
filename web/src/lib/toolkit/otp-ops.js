/**
 * Toolkit `otp.*` ops — the registry surface over lib/otp/.
 *
 * Pure JS + SubtleCrypto, no DOM and no vault, so all four ops run headlessly
 * in the CLI the way the `ssh.*` family does.
 *
 * The one policy decision that lives here rather than in the library:
 *
 *   **A shared secret is a credential, so anything carrying one is marked
 *   `sensitive`.** That is the `otpauth://` URI as much as the Base32 string
 *   — the URI *is* the secret, plus a label. `execSshEncode`'s private branch
 *   sets the same flag for the same reason, and the mask that follows from it
 *   is the difference between a demo and a defect.
 *
 *   The **code** is deliberately not marked sensitive. It is six digits that
 *   expire in half a minute and exist to be read off the screen and typed
 *   somewhere else; masking it would hide the only useful thing the op
 *   produced, and there is nothing durable behind the mask to protect.
 *
 * The other convention worth stating once, because three ops share it:
 * `otp.code` and `otp.verify` accept **either** an `otpauth://` URI or a bare
 * Base32 secret. Handed a URI they take the algorithm, digits, period and
 * counter *from the URI* and ignore their own params, because a URI that
 * says `digits=8` and a step that says `digits=6` cannot both be obeyed and
 * the URI is the thing the other side is holding. To override, strip the URI
 * down to its secret first — that is exactly what `otp.parse` is for.
 */

import { base32ToBytes, bytesToBase32 } from "./encode.js";
import {
  hotp,
  normalizeAlgorithm,
  normalizeDigits,
  normalizePeriod,
  normalizeWindow,
  secondsRemaining,
  timeCounter,
  totp,
  verifyHotp,
  verifyTotp,
} from "../otp/hotp.js";
import {
  buildOtpauthUri,
  isOtpauthUri,
  normalizeSecret,
  normalizeType,
  parseOtpauthUri,
} from "../otp/uri.js";

/** Unix seconds for an `at=` param — 0 (the default) means "now". */
function secondsFrom(params) {
  const at = Number(params?.at ?? 0);
  if (!Number.isFinite(at) || at < 0) {
    throw new Error(`otp: at= must be Unix seconds, zero for now (got ${params?.at})`);
  }
  return at === 0 ? Date.now() / 1000 : at;
}

/**
 * The Base32 secret behind a pipeline value: raw bytes are encoded, text is
 * taken as Base32 and checked.
 * @param {import("./engine.js").PipelineValue|null|undefined} value
 * @param {string} op
 * @returns {string}
 */
function base32From(value, op) {
  if (value?.type === "bytes" && value.data instanceof Uint8Array) {
    if (!value.data.length) throw new Error(`${op}: the secret is empty`);
    return bytesToBase32(value.data);
  }
  if (value?.type === "text") return normalizeSecret(String(value.data));
  throw new Error(`${op} expects a Base32 secret (text) or raw secret bytes`);
}

/**
 * Everything needed to compute a code, from the value on the stem plus the
 * step's params. A URI on the stem wins over the params; a bare secret leaves
 * the params in charge.
 *
 * @param {import("./engine.js").PipelineValue|null|undefined} value
 * @param {Record<string, *>} params
 * @param {string} op
 */
function otpSettings(value, params, op) {
  if (value?.type === "text" && isOtpauthUri(String(value.data))) {
    const rec = parseOtpauthUri(String(value.data));
    return {
      secret: base32ToBytes(rec.secret),
      mode: rec.type,
      algorithm: rec.algorithm,
      digits: rec.digits,
      period: rec.period,
      counter: rec.counter,
      fromUri: true,
      label: rec.issuer ? `${rec.issuer}: ${rec.account}` : rec.account,
    };
  }
  const counter = Number(params.counter ?? 0);
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error(`${op}: counter= must be a whole number, zero or more (got ${params.counter})`);
  }
  return {
    secret: base32ToBytes(base32From(value, op)),
    mode: normalizeType(params.mode),
    algorithm: normalizeAlgorithm(params.algorithm),
    digits: normalizeDigits(params.digits),
    period: normalizePeriod(params.period),
    counter,
    fromUri: false,
    label: "",
  };
}

/** `otp.uri` — a Base32 secret (or raw bytes) → the `otpauth://` enrolment URI. */
export async function execOtpUri(value, params = {}) {
  const uri = buildOtpauthUri({
    type: normalizeType(params.mode),
    secret: base32From(value, "otp.uri"),
    issuer: String(params.issuer ?? ""),
    account: String(params.account ?? ""),
    algorithm: params.algorithm,
    digits: params.digits,
    period: params.period,
    counter: Number(params.counter ?? 0),
  });
  return {
    type: "text",
    data: uri,
    // The URI *is* the shared secret. Same flag, same reason, as an
    // unencrypted private key block.
    meta: { kind: "otpauth-uri", sensitive: true },
  };
}

/** `otp.parse` — read one field out of an `otpauth://` URI. */
export async function execOtpParse(value, params = {}) {
  if (value?.type !== "text") {
    throw new Error("otp.parse expects text (an otpauth:// URI)");
  }
  const rec = parseOtpauthUri(String(value.data));
  const field = String(params.field || "secret");
  /** @type {Record<string, string>} */
  const fields = {
    secret: rec.secret,
    issuer: rec.issuer,
    account: rec.account,
    algorithm: rec.algorithm,
    digits: String(rec.digits),
    period: String(rec.period),
    counter: String(rec.counter),
    mode: rec.type,
  };
  if (!(field in fields)) {
    throw new Error(`otp.parse: no field "${field}" in a Key URI`);
  }
  if (field === "issuer" && !rec.issuer) {
    throw new Error("otp.parse: this URI's label carries no issuer");
  }
  return {
    type: "text",
    data: fields[field],
    // Only the secret is a credential. The issuer and the digit count are
    // metadata, and masking them would teach that everything here is secret.
    meta:
      field === "secret"
        ? { kind: "otp-secret", sensitive: true }
        : { sensitive: false },
  };
}

/** `otp.code` — the code for right now (or for `at=`). */
export async function execOtpCode(value, params = {}) {
  const s = otpSettings(value, params, "otp.code");
  const seconds = secondsFrom(params);
  const code =
    s.mode === "hotp"
      ? await hotp(s.secret, s.counter, s)
      : await totp(s.secret, { ...s, seconds });
  return {
    type: "text",
    data: code,
    // Not sensitive: see the file header. A masked code is a useless code.
    meta: {
      kind: "otp-code",
      sensitive: false,
      otpMode: s.mode,
      otpDigits: s.digits,
      ...(s.mode === "hotp"
        ? { otpCounter: s.counter }
        : {
            otpPeriod: s.period,
            otpExpiresIn: secondsRemaining({ period: s.period, seconds }),
            otpStep: String(timeCounter(seconds, s.period, 0)),
          }),
      ...(s.label ? { otpLabel: s.label } : {}),
    },
  };
}

/** Resolve a slot ref to its raw pipeline value (the `ssh.*` pattern). */
function slotValue(bindings, ref, what) {
  const r = String(ref || "").trim();
  if (!r) throw new Error(`otp.verify: ${what} is required`);
  const resolve = bindings?.resolveSlot;
  if (typeof resolve !== "function") throw new Error(`Slot ${r}: runtime slot resolver missing`);
  return resolve(r);
}

/**
 * `otp.verify` — check the code on the stem against the secret in a slot,
 * allowing ±`window` steps of drift. Fail-loud; `-q` emits a bool instead.
 */
export async function execOtpVerify(value, params = {}, bindings = {}) {
  if (value?.type !== "text" && value?.type !== "int") {
    throw new Error("otp.verify expects the submitted code as text");
  }
  const code = String(value.data);
  const secretVal = slotValue(bindings, params.secret, "secret= (Base32 secret or otpauth:// URI)");
  const s = otpSettings(secretVal, params, "otp.verify");
  const window = normalizeWindow(params.window);
  const seconds = secondsFrom(params);
  let verdict;
  try {
    verdict =
      s.mode === "hotp"
        ? await verifyHotp(code, s.secret, s.counter, { ...s, window })
        : await verifyTotp(code, s.secret, { ...s, window, seconds });
  } catch (err) {
    // A malformed code is a failed check, not a crash — but only in soft
    // mode, so a typo in a recipe still surfaces loudly.
    if (params.soft) return { type: "bool", data: false, meta: { sensitive: false } };
    throw err;
  }
  if (!verdict.ok) {
    if (params.soft) return { type: "bool", data: false, meta: { sensitive: false } };
    throw new Error(
      s.mode === "hotp"
        ? `otp.verify: no counter in [${s.counter}, ${s.counter + window}] produces that code — ` +
          "the client may have run further ahead than window= allows"
        : `otp.verify: that code does not match any step within ±${window} of now — ` +
          "either it is wrong, or the two clocks are further apart than window= allows"
    );
  }
  return {
    type: "bool",
    data: true,
    meta: { sensitive: false, otpDelta: verdict.delta },
  };
}
