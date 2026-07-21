/**
 * Human-readable inspection of toolkit pipeline values
 * (openssl … -text / hexdump style).
 * @module lib/toolkit/inspect
 */

import { bytesToHex } from "./encode.js";

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
 * @param {import("./engine.js").PipelineValue} value
 * @param {string} [format] auto | text | hex | hexdump | jwk | meta
 * @returns {Promise<string>}
 */
export async function inspectValue(value, format = "auto") {
  if (!value) return "(empty)\n";
  const fmt = String(format || "auto").toLowerCase();
  const lines = [
    `type: ${value.type}`,
    `sensitive: ${value.meta?.sensitive ? "yes" : "no"}`,
  ];

  if (value.type === "bytes") {
    const bytes = value.data;
    lines.push(`length: ${bytes.length} bytes`);
    if (value.meta?.format) lines.push(`format: ${value.meta.format}`);
    if (value.meta?.which) lines.push(`which: ${value.meta.which}`);
    lines.push("");
    if (fmt === "hex") {
      lines.push(bytesToHex(bytes));
    } else if (fmt === "meta") {
      lines.push(JSON.stringify(value.meta || {}, null, 2));
    } else {
      // auto / text / hexdump
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

  if (value.type === "text") {
    const text = String(value.data);
    lines.push(`length: ${text.length} chars`);
    lines.push("");
    if (fmt === "hex" || fmt === "hexdump") {
      const bytes = new TextEncoder().encode(text);
      lines.push(
        fmt === "hex"
          ? bytesToHex(bytes)
          : formatHexdump(bytes, { limit: 4096 })
      );
    } else if (fmt === "meta") {
      lines.push(JSON.stringify(value.meta || {}, null, 2));
    } else {
      lines.push(text);
    }
    return `${lines.join("\n")}\n`;
  }

  if (value.type === "shares") {
    const d = value.data || {};
    const mnemonics = d.mnemonics || [];
    lines.push(`shares: ${mnemonics.length}`);
    if (d.threshold) lines.push(`threshold: ${d.threshold}`);
    if (d.enveloped != null) lines.push(`enveloped: ${d.enveloped}`);
    if (d.envelope || value.meta?.envelope) {
      const env = d.envelope || value.meta.envelope;
      lines.push(
        `envelope: ${env instanceof Uint8Array ? `${env.length} bytes` : "present"}`
      );
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

  if (value.type === "keypair") {
    const meta = value.meta || {};
    lines.push(`alg: ${meta.alg || "?"}`);
    lines.push(`algorithm: ${meta.algorithm || "?"}`);
    if (meta.curve) lines.push(`curve: ${meta.curve}`);
    if (meta.symmetric) lines.push(`symmetric: yes`);
    const priv = value.data?.privateKey;
    const pub = value.data?.publicKey;
    lines.push(`private: ${priv ? "yes" : "no"}`);
    lines.push(`public: ${pub ? "yes" : "no"}`);
    lines.push("");

    if (fmt === "meta") {
      lines.push(JSON.stringify(meta, null, 2));
      return `${lines.join("\n")}\n`;
    }

    // openssl-ish JWK dump (WebCrypto's portable "text" form)
    if (priv && (fmt === "auto" || fmt === "jwk" || fmt === "text")) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", priv);
        lines.push("--- private JWK ---");
        lines.push(JSON.stringify(jwk, null, 2));
        lines.push("");
      } catch (err) {
        lines.push(`private JWK: export failed (${err?.message || err})`);
      }
    }
    if (pub && (fmt === "auto" || fmt === "jwk" || fmt === "text")) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", pub);
        lines.push("--- public JWK ---");
        lines.push(JSON.stringify(jwk, null, 2));
        lines.push("");
      } catch (err) {
        lines.push(`public JWK: export failed (${err?.message || err})`);
      }
    }

    if (fmt === "hex" || fmt === "hexdump") {
      try {
        const key = priv || pub;
        if (key) {
          const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
          lines.push("--- raw ---");
          lines.push(
            fmt === "hex" ? bytesToHex(raw) : formatHexdump(raw)
          );
        }
      } catch (err) {
        lines.push(`raw export: ${err?.message || err}`);
      }
    }
    return `${lines.join("\n")}\n`;
  }

  if (value.type === "artifact" || value.type === "bundle") {
    lines.push("(sink / bundle — no further dump)");
    return `${lines.join("\n")}\n`;
  }

  lines.push(JSON.stringify(value.meta || {}, null, 2));
  return `${lines.join("\n")}\n`;
}
