/**
 * RSA private JWK from openssh-key-v1 wire material.
 *
 * OpenSSH stores n, e, d, iqmp, p, q; JWK wants dp and dq as well, which
 * are derivable (d mod p-1, d mod q-1). Split out of agent-server.js because
 * the same arithmetic is wanted anywhere an SSH RSA key meets SubtleCrypto.
 */

const b64u = (bytes) =>
  Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const toBig = (b) => {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
};

const fromBig = (v) => {
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

/** @param {{ n: Uint8Array, e: Uint8Array, d: Uint8Array, p: Uint8Array, q: Uint8Array, iqmp: Uint8Array }} m */
export function rsaPrivateJwkFromSsh(m) {
  const d = toBig(m.d);
  const p = toBig(m.p);
  const q = toBig(m.q);
  return {
    kty: "RSA",
    n: b64u(m.n),
    e: b64u(m.e),
    d: b64u(m.d),
    p: b64u(m.p),
    q: b64u(m.q),
    dp: b64u(fromBig(d % (p - 1n))),
    dq: b64u(fromBig(d % (q - 1n))),
    qi: b64u(m.iqmp),
  };
}
