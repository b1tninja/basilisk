/**
 * Human-readable inspection of toolkit pipeline values
 * (openssl … -text / hexdump style).
 *
 * Snapshots let the UI switch formats on an inspect/tee tile without
 * re-running the recipe (CryptoKeys are exported once into the snapshot).
 * @module lib/toolkit/inspect
 */

import { bytesToHex } from "./encode.js";
import { buildPacketMapFromArmoredSync } from "../packet-hex-view.js";

/**
 * SHA-256 hex of a public JWK's identifying fields (handy fingerprint; not full RFC 7638 for all kty).
 * @param {JsonWebKey|Record<string, *>|null|undefined} jwk
 * @returns {Promise<string>}
 */
async function publicJwkThumbprintHex(jwk) {
  if (!jwk || typeof jwk !== "object") return "";
  /** @type {Record<string, string>} */
  const canon = { kty: String(jwk.kty || "") };
  if (jwk.crv) canon.crv = String(jwk.crv);
  if (jwk.x) canon.x = String(jwk.x);
  if (jwk.y) canon.y = String(jwk.y);
  if (jwk.n) canon.n = String(jwk.n);
  if (jwk.e) canon.e = String(jwk.e);
  // Sorted keys for stable digest.
  const keys = Object.keys(canon).sort();
  const body = `{${keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(canon[k])}`).join(",")}}`;
  try {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(body)
    );
    return bytesToHex(new Uint8Array(digest));
  } catch {
    return "";
  }
}

/** @typedef {"auto"|"text"|"hex"|"hexdump"|"packets"|"jwk"|"meta"} InspectFormat */

/** Formats offered by the inspect / tee result tile. */
export const INSPECT_FORMATS = /** @type {InspectFormat[]} */ ([
  "auto",
  "text",
  "hex",
  "hexdump",
  "packets",
  "jwk",
  "meta",
]);

/**
 * @param {string} text
 * @returns {boolean}
 */
export function textLooksLikeOpenPgpArmor(text) {
  return /-----BEGIN PGP (MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----/i.test(
    String(text || "")
  );
}

/**
 * @typedef {object} InspectSnapshot
 * @property {string} type
 * @property {Record<string, *>} meta  JSON-cloneable subset
 * @property {Uint8Array} [bytes]
 * @property {string} [text]
 * @property {{
 *   mnemonics: string[],
 *   threshold?: number,
 *   enveloped?: boolean,
 *   envelopeBytes?: number,
 * }} [shares]
 * @property {{
 *   privateJwk?: JsonWebKey,
 *   publicJwk?: JsonWebKey,
 *   raw?: Uint8Array,
 *   hasPrivate?: boolean,
 *   hasPublic?: boolean,
 * }} [keypair]
 */

/**
 * @param {number} n
 * @param {number} width
 */
function hexPad(n, width) {
  return n.toString(16).padStart(width, "0");
}

/**
 * Classic hexdump (offset + hex + ASCII).
 * @param {Uint8Array} bytes
 * @param {{ width?: number, limit?: number }} [opts]
 * @returns {string}
 */
export function formatHexdump(bytes, opts = {}) {
  const width = opts.width || 16;
  const limit = opts.limit && opts.limit > 0 ? opts.limit : bytes.length;
  const slice = bytes.subarray(0, Math.min(bytes.length, limit));
  const lines = [];
  for (let i = 0; i < slice.length; i += width) {
    const chunk = slice.subarray(i, i + width);
    const hex = [...chunk]
      .map((b) => hexPad(b, 2))
      .join(" ")
      .padEnd(width * 3 - 1, " ");
    const ascii = [...chunk]
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${hexPad(i, 8)}  ${hex}  |${ascii}|`);
  }
  if (limit < bytes.length) {
    lines.push(`… truncated (${limit} of ${bytes.length} bytes)`);
  }
  return lines.join("\n");
}

/**
 * @param {string} text
 * @returns {boolean}
 */
function isMostlyPrintable(text) {
  if (!text) return true;
  let bad = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13) continue;
    if (c < 0x20 || c === 0x7f) bad++;
  }
  return bad / text.length < 0.05;
}

/**
 * Colon-separated hex groups (openssl -text style).
 * @param {string} hex
 * @param {number} [group]
 * @returns {string}
 */
function colonHex(hex, group = 2) {
  const h = String(hex || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  if (!h) return "";
  const parts = [];
  for (let i = 0; i < h.length; i += group) {
    parts.push(h.slice(i, i + group));
  }
  return parts.join(":");
}

/**
 * Decode base64url JWK field to lowercase hex (no padding).
 * @param {string|undefined} b64u
 * @returns {string}
 */
function jwkFieldToHex(b64u) {
  if (!b64u) return "";
  try {
    const pad = "=".repeat((4 - (b64u.length % 4)) % 4);
    const b64 = String(b64u).replace(/-/g, "+").replace(/_/g, "/") + pad;
    const bin = atob(b64);
    let hex = "";
    for (let i = 0; i < bin.length; i++) {
      hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return hex;
  } catch {
    return "";
  }
}

/**
 * openssl pkey -text–style summary from JWK snapshot fields.
 * @param {InspectSnapshot} snap
 * @param {{ redactPrivate?: boolean }} [opts]
 * @returns {string[]}
 */
export function formatOpenSslTextLines(snap, opts = {}) {
  const meta = snap.meta || {};
  const kp = snap.keypair || {};
  const jwk = kp.privateJwk || kp.publicJwk || {};
  const redact = opts.redactPrivate !== false && !!meta.sensitive;
  /** @type {string[]} */
  const lines = [];

  const kty = String(jwk.kty || "");
  const crv = String(jwk.crv || meta.curve || "");
  const alg = String(meta.alg || meta.algorithm || "");

  if (kty === "EC" || /^ec\//i.test(alg) || crv.startsWith("P-")) {
    const bits =
      crv === "P-256" || alg.includes("p256")
        ? 256
        : crv === "P-384" || alg.includes("p384")
          ? 384
          : crv === "P-521" || alg.includes("p521")
            ? 521
            : null;
    const curveName =
      crv === "P-256"
        ? "prime256v1"
        : crv === "P-384"
          ? "secp384r1"
          : crv === "P-521"
            ? "secp521r1"
            : crv || "?";
    const label = kp.hasPrivate ? "Private-Key" : "Public-Key";
    lines.push(
      bits != null
        ? `${label}: (${bits} bit, ${crv || curveName})`
        : `${label}: (${crv || alg || "EC"})`
    );
    if (kp.hasPrivate && jwk.d) {
      lines.push("priv:");
      if (redact) {
        lines.push("    [redacted]");
      } else {
        const hx = jwkFieldToHex(jwk.d);
        lines.push(`    ${colonHex(hx) || "[unavailable]"}`);
      }
    }
    const x = jwkFieldToHex(jwk.x);
    const y = jwkFieldToHex(jwk.y);
    if (x && y) {
      lines.push("pub:");
      lines.push(`    ${colonHex(`04${x}${y}`)}`);
    }
    lines.push(`ASN1 OID: ${curveName}`);
    if (crv) lines.push(`NIST CURVE: ${crv}`);
  } else if (kty === "OKP" || /ed25519|x25519/i.test(alg + crv)) {
    const curve = crv || (alg.includes("x25519") ? "X25519" : "Ed25519");
    const label = kp.hasPrivate ? "Private-Key" : "Public-Key";
    lines.push(`${label}: (${curve})`);
    if (kp.hasPrivate && jwk.d) {
      lines.push("priv:");
      lines.push(redact ? "    [redacted]" : `    ${colonHex(jwkFieldToHex(jwk.d))}`);
    }
    if (jwk.x) {
      lines.push("pub:");
      lines.push(`    ${colonHex(jwkFieldToHex(jwk.x))}`);
    }
  } else if (kty === "RSA" || /^rsa\//i.test(alg)) {
    const nHex = jwkFieldToHex(jwk.n);
    const bits = nHex ? nHex.length * 4 : null;
    const label = kp.hasPrivate ? "Private-Key" : "Public-Key";
    lines.push(bits != null ? `${label}: (${bits} bit)` : `${label}: (RSA)`);
    if (jwk.n) {
      lines.push("modulus:");
      lines.push(`    ${colonHex(nHex)}`);
    }
    if (jwk.e) {
      lines.push(`publicExponent: ${colonHex(jwkFieldToHex(jwk.e))} (0x${jwkFieldToHex(jwk.e)})`);
    }
    if (kp.hasPrivate && jwk.d) {
      lines.push("privateExponent:");
      lines.push(redact ? "    [redacted]" : `    ${colonHex(jwkFieldToHex(jwk.d))}`);
    }
  } else if (kty === "oct" || meta.symmetric || /^aes\//i.test(alg) || /^hmac\//i.test(alg)) {
    lines.push(`Secret-Key: (${alg || "oct"})`);
    if (jwk.k) {
      lines.push("k:");
      lines.push(redact ? "    [redacted]" : `    ${colonHex(jwkFieldToHex(jwk.k))}`);
    }
  } else {
    lines.push(`Key: (${alg || kty || meta.algorithm || "unknown"})`);
  }

  if (meta.alg) lines.push(`basilisk.alg: ${meta.alg}`);
  if (kp.thumbprint) lines.push(`jwk.thumbprint.sha256: ${kp.thumbprint}`);
  if (Array.isArray(jwk.key_ops) && jwk.key_ops.length) {
    lines.push(`usages: ${jwk.key_ops.join(", ")}`);
  }
  return lines;
}

/**
 * Drop non-cloneable / non-JSON fields from pipeline meta for snapshots.
 * @param {Record<string, *>|undefined|null} meta
 * @returns {Record<string, *>}
 */
function cloneableMeta(meta) {
  if (!meta || typeof meta !== "object") return {};
  /** @type {Record<string, *>} */
  const out = {};
  for (const [k, v] of Object.entries(meta)) {
    if (k === "inspectSnapshot" || k === "inspectFormat") continue;
    if (v instanceof Uint8Array) {
      out[k] = `<${v.length} bytes>`;
      continue;
    }
    if (typeof v === "function") continue;
    if (typeof CryptoKey !== "undefined" && v instanceof CryptoKey) continue;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      try {
        out[k] = JSON.parse(JSON.stringify(v));
      } catch {
        /* skip */
      }
      continue;
    }
    if (
      v === null ||
      typeof v === "string" ||
      typeof v === "number" ||
      typeof v === "boolean" ||
      Array.isArray(v)
    ) {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Build a structured-clone-safe snapshot for live format switching in the UI.
 * @param {import("./engine.js").PipelineValue|null|undefined} value
 * @returns {Promise<InspectSnapshot|null>}
 */
/**
 * Primary key, user IDs, and subkeys of an armored OpenPGP key (§32b).
 *
 * An OpenPGP key is a *tree* — a primary key with user IDs and subkeys bound
 * to it by self-signatures — and reporting only "openpgp-key, N chars"
 * throws away the only part anyone inspects it for. Never returns private
 * material: fingerprints and algorithms identify a key without exposing it.
 *
 * @param {string} armored
 * @returns {Promise<object>} structure fields, or `{}` when unparseable
 */
async function readOpenpgpStructure(armored) {
  if (!armored.includes("BEGIN PGP")) return {};
  try {
    const { readKey } = await import("openpgp");
    const key = await readKey({ armoredKey: armored });
    const algOf = (k) => {
      const a = k.getAlgorithmInfo?.() || {};
      return [a.algorithm, a.curve || (a.bits ? `${a.bits}` : "")]
        .filter(Boolean)
        .join("/");
    };
    const expiry = await key.getExpirationTime?.().catch(() => null);
    return {
      primary: {
        alg: algOf(key),
        fingerprint: key.getFingerprint?.() || "",
        created: key.getCreationTime?.()?.toISOString?.() || "",
        // openpgp.js returns Infinity for "never expires".
        expires: expiry && expiry !== Infinity ? new Date(expiry).toISOString() : "",
      },
      userIds: (key.getUserIDs?.() || []).map((id) => ({ id, selfSigned: true })),
      subkeys: (key.getSubkeys?.() || []).map((sk) => ({
        alg: algOf(sk),
        fingerprint: sk.getFingerprint?.() || "",
        bound: true,
      })),
    };
  } catch {
    return {};
  }
}

export async function buildInspectSnapshot(value) {
  if (!value) return null;
  const meta = cloneableMeta(value.meta);

  if (value.type === "bytes") {
    const bytes =
      value.data instanceof Uint8Array
        ? new Uint8Array(value.data)
        : new Uint8Array(0);
    return { type: "bytes", meta, bytes };
  }

  if (value.type === "text") {
    return { type: "text", meta, text: String(value.data ?? "") };
  }

  if (value.type === "int") {
    const n = Number(value.data);
    return {
      type: "int",
      meta,
      text: String(Number.isFinite(n) ? Math.trunc(n) : 0),
    };
  }

  if (value.type === "bool") {
    return {
      type: "bool",
      meta,
      text: value.data ? "true" : "false",
    };
  }

  if (value.type === "shares") {
    const d = value.data || {};
    const env = d.envelope || value.meta?.envelope;
    return {
      type: "shares",
      meta,
      shares: {
        mnemonics: (d.mnemonics || []).map((m) => String(m)),
        threshold: d.threshold ? Number(d.threshold) : undefined,
        enveloped: d.enveloped != null ? !!d.enveloped : undefined,
        envelopeBytes: env instanceof Uint8Array ? env.length : undefined,
      },
    };
  }

  if (value.type === "keypair" || value.type === "key") {
    // Full keypair bags are `{ privateKey, publicKey }`. Projected `:public` /
    // `:private` tips are a bare CryptoKey on `data` with `meta.which`.
    const bag = value.data;
    const isCryptoKey =
      typeof CryptoKey !== "undefined" && bag instanceof CryptoKey;
    const tipWhich =
      value.meta?.which === "public" ||
      value.meta?.which === "private" ||
      value.meta?.which === "secret"
        ? value.meta.which
        : null;
    let priv = !isCryptoKey ? bag?.privateKey : null;
    let pub = !isCryptoKey ? bag?.publicKey : null;
    let secret = !isCryptoKey ? bag?.secretKey : null;
    if (isCryptoKey) {
      if (tipWhich === "public") pub = bag;
      else if (tipWhich === "private") priv = bag;
      else if (tipWhich === "secret" || bag.type === "secret") secret = bag;
      else if (bag.type === "public") pub = bag;
      else priv = bag;
    }
    /** @type {InspectSnapshot["keypair"]} */
    const keypair = {
      hasPrivate: !!priv,
      hasPublic: !!pub,
    };
    if (priv) {
      try {
        keypair.privateJwk = await crypto.subtle.exportKey("jwk", priv);
      } catch {
        /* keep hasPrivate */
      }
    }
    if (secret) {
      try {
        keypair.privateJwk = await crypto.subtle.exportKey("jwk", secret);
        keypair.hasPrivate = true;
      } catch {
        /* keep */
      }
    }
    if (pub) {
      try {
        keypair.publicJwk = await crypto.subtle.exportKey("jwk", pub);
      } catch {
        /* keep hasPublic */
      }
    }
    try {
      const key = priv || secret || pub;
      if (key) {
        keypair.raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
      }
    } catch {
      /* raw not extractable for many algs */
    }
    const pubForThumb = keypair.publicJwk || (() => {
      const j = keypair.privateJwk;
      if (!j) return null;
      // Strip private fields for thumbprint of asymmetric keys.
      if (j.kty === "oct") return null;
      const { d, p, q, dp, dq, qi, oth, k, ...rest } = j;
      void d;
      void p;
      void q;
      void dp;
      void dq;
      void qi;
      void oth;
      void k;
      return rest;
    })();
    if (pubForThumb) {
      const tp = await publicJwkThumbprintHex(pubForThumb);
      if (tp) keypair.thumbprint = tp;
    }
    return { type: value.type, meta, keypair };
  }

  if (value.type === "openpgp-key") {
    const armored = String(value.data || "");
    return {
      type: "openpgp-key",
      meta,
      text: armored,
      openpgpKey: {
        which: value.meta?.which || "private",
        fingerprint: value.meta?.fingerprint || "",
        length: armored.length,
        // Structure for the tree body (§32b). Best-effort: a key that will not
        // parse still gets the flat fields above, so the inspector degrades to
        // what it always showed rather than failing.
        ...(await readOpenpgpStructure(armored)),
      },
    };
  }

  if (value.type === "recipients") {
    const rows = Array.isArray(value.data) ? value.data : [];
    return {
      type: "recipients",
      meta,
      recipients: rows.map((r) => ({
        fingerprint: r.fingerprint,
        label: r.label || "",
        email: r.email || "",
        approvalState: r.approvalState || "",
        // `null` where nothing has asked the certificate — see the recipients
        // branch of `materializeOutArtifacts`. An inspector that reported `true`
        // for an unread key would be the most misleading place of all to do it.
        encryptCapable: r.encryptCapable == null ? null : !!r.encryptCapable,
        hasArmor: String(r.armoredPublic || "").includes("BEGIN PGP"),
      })),
    };
  }

  return { type: value.type || "other", meta };
}

/**
 * Render a dump from an inspect snapshot (no CryptoKey / no re-run).
 * @param {InspectSnapshot|null|undefined} snap
 * @param {string} [format]
 * @returns {string}
 */
export function inspectFromSnapshot(snap, format = "auto") {
  if (!snap) return "(empty)\n";
  const fmt = String(format || "auto").toLowerCase();
  const meta = snap.meta || {};
  const lines = [
    `type: ${snap.type}`,
    `sensitive: ${meta.sensitive ? "yes" : "no"}`,
  ];

  if (snap.type === "bytes") {
    const bytes = snap.bytes instanceof Uint8Array ? snap.bytes : new Uint8Array(0);
    lines.push(`length: ${bytes.length} bytes`);
    if (meta.format) lines.push(`format: ${meta.format}`);
    if (meta.which) lines.push(`which: ${meta.which}`);
    lines.push("");
    if (fmt === "hex") {
      lines.push(bytesToHex(bytes));
    } else if (fmt === "meta") {
      lines.push(JSON.stringify(meta, null, 2));
    } else {
      const dumpLimit = 4096;
      lines.push(formatHexdump(bytes, { limit: dumpLimit }));
      if (fmt === "auto" || fmt === "text") {
        try {
          const asText = new TextDecoder("utf-8", { fatal: false }).decode(
            bytes.subarray(0, Math.min(bytes.length, 2048))
          );
          if (isMostlyPrintable(asText)) {
            lines.push("");
            lines.push("--- utf-8 preview ---");
            lines.push(asText);
            if (bytes.length > 2048) lines.push("…");
          }
        } catch (_) {
          /* ignore */
        }
      }
    }
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "text") {
    const text = String(snap.text ?? "");
    lines.push(`length: ${text.length} chars`);
    lines.push("");
    if (fmt === "packets") {
      if (!textLooksLikeOpenPgpArmor(text)) {
        lines.push("packets: (not OpenPGP armor)");
      } else {
        try {
          const built = buildPacketMapFromArmoredSync(text);
          lines.push(built.summary.trimEnd());
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          lines.push(`packets: (unavailable — ${msg})`);
        }
      }
    } else if (fmt === "hex" || fmt === "hexdump") {
      const bytes = new TextEncoder().encode(text);
      lines.push(
        fmt === "hex" ? bytesToHex(bytes) : formatHexdump(bytes, { limit: 4096 })
      );
    } else if (fmt === "meta") {
      lines.push(JSON.stringify(meta, null, 2));
    } else {
      lines.push(text);
    }
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "int" || snap.type === "bool") {
    lines.push(`value: ${snap.text ?? ""}`);
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "shares") {
    const d = snap.shares || { mnemonics: [] };
    const mnemonics = d.mnemonics || [];
    lines.push(`shares: ${mnemonics.length}`);
    if (d.threshold) lines.push(`threshold: ${d.threshold}`);
    if (d.enveloped != null) lines.push(`enveloped: ${d.enveloped}`);
    if (d.envelopeBytes != null) {
      lines.push(`envelope: ${d.envelopeBytes} bytes`);
    }
    lines.push("");
    mnemonics.forEach((m, i) => {
      lines.push(`--- share ${i + 1} ---`);
      if (fmt === "meta") {
        const words = String(m).trim().split(/\s+/);
        lines.push(`words: ${words.length}`);
        lines.push(`preview: ${words.slice(0, 3).join(" ")} …`);
      } else {
        lines.push(String(m).trim());
      }
      lines.push("");
    });
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "keypair" || snap.type === "key") {
    const kp = snap.keypair || {};
    lines.push(`alg: ${meta.alg || "?"}`);
    lines.push(`algorithm: ${meta.algorithm || "?"}`);
    if (meta.curve) lines.push(`curve: ${meta.curve}`);
    if (meta.which) lines.push(`which: ${meta.which}`);
    if (meta.symmetric) lines.push(`symmetric: yes`);
    lines.push(`private: ${kp.hasPrivate || kp.privateJwk ? "yes" : "no"}`);
    lines.push(`public: ${kp.hasPublic || kp.publicJwk ? "yes" : "no"}`);
    lines.push("");

    if (fmt === "meta") {
      lines.push(JSON.stringify(meta, null, 2));
      return `${lines.join("\n")}\n`;
    }

    if (fmt === "auto" || fmt === "text") {
      lines.push("--- openssl -text ---");
      lines.push(...formatOpenSslTextLines(snap));
      lines.push("");
    }

    if (kp.privateJwk && (fmt === "auto" || fmt === "jwk" || fmt === "text")) {
      if (fmt === "jwk" || fmt === "text") {
        lines.push("--- private JWK ---");
        lines.push(JSON.stringify(kp.privateJwk, null, 2));
        lines.push("");
      } else if (fmt === "auto") {
        lines.push("--- private JWK (summary) ---");
        lines.push(
          JSON.stringify(
            {
              kty: kp.privateJwk.kty,
              crv: kp.privateJwk.crv,
              alg: kp.privateJwk.alg,
              key_ops: kp.privateJwk.key_ops,
              ext: kp.privateJwk.ext,
              has_d: !!kp.privateJwk.d,
              has_x: !!kp.privateJwk.x,
              has_n: !!kp.privateJwk.n,
            },
            null,
            2
          )
        );
        lines.push("(use format=jwk for full JWK)");
        lines.push("");
      }
    } else if (kp.hasPrivate && (fmt === "auto" || fmt === "jwk" || fmt === "text")) {
      lines.push("private JWK: export failed");
    }

    if (kp.publicJwk && (fmt === "auto" || fmt === "jwk" || fmt === "text")) {
      lines.push("--- public JWK ---");
      lines.push(JSON.stringify(kp.publicJwk, null, 2));
      lines.push("");
    } else if (kp.hasPublic && (fmt === "auto" || fmt === "jwk" || fmt === "text")) {
      lines.push("public JWK: export failed");
    }

    if (fmt === "hex" || fmt === "hexdump") {
      if (kp.raw instanceof Uint8Array) {
        lines.push("--- raw ---");
        lines.push(fmt === "hex" ? bytesToHex(kp.raw) : formatHexdump(kp.raw));
      } else {
        lines.push("raw export: not available in snapshot");
      }
    }
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "openpgp-key") {
    const info = snap.openpgpKey || {};
    const text = String(snap.text || "");
    lines.push(`which: ${info.which || meta.which || "?"}`);
    if (info.fingerprint || meta.fingerprint) {
      lines.push(`fingerprint: ${info.fingerprint || meta.fingerprint}`);
    }
    lines.push(`length: ${info.length ?? text.length} chars`);
    lines.push("");
    if (fmt === "meta") {
      lines.push(JSON.stringify(meta, null, 2));
    } else if (fmt === "packets") {
      try {
        const built = buildPacketMapFromArmoredSync(text);
        lines.push(built.summary.trimEnd());
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        lines.push(`packets: (unavailable — ${msg})`);
      }
    } else {
      lines.push(text);
    }
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "recipients") {
    const rows = snap.recipients || [];
    lines.push(`count: ${rows.length}`);
    lines.push("");
    if (fmt === "meta") {
      lines.push(JSON.stringify(rows, null, 2));
    } else {
      for (const r of rows) {
        lines.push(
          `${r.fingerprint || "?"}  ${r.label || r.email || ""}  ${r.approvalState || ""}  armor=${r.hasArmor ? "yes" : "no"}`
        );
      }
    }
    return `${lines.join("\n")}\n`;
  }

  if (snap.type === "artifact" || snap.type === "bundle") {
    lines.push("(sink / bundle — no further dump)");
    return `${lines.join("\n")}\n`;
  }

  lines.push(JSON.stringify(meta, null, 2));
  return `${lines.join("\n")}\n`;
}

/**
 * @param {import("./engine.js").PipelineValue} value
 * @param {string} [format] auto | text | hex | hexdump | jwk | meta
 * @returns {Promise<string>}
 */
export async function inspectValue(value, format = "auto") {
  const snap = await buildInspectSnapshot(value);
  return inspectFromSnapshot(snap, format);
}
