/**
 * GF(256) arithmetic and Shamir secret sharing (SLIP-39 field).
 * Polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d), same as AES / SLIP-39.
 */

const EXP = new Uint8Array(255);
const LOG = new Uint8Array(256);

(function init() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x = x << 1;
    if (x & 0x100) x ^= 0x11d;
  }
})();

/** @param {number} a @param {number} b */
export function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a] + LOG[b]) % 255];
}

/** @param {number} a @param {number} b */
export function gfDiv(a, b) {
  if (b === 0) throw new Error("GF division by zero");
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

/**
 * Evaluate polynomial coeffs[0] + coeffs[1]*x + … at x (Horner).
 * @param {Uint8Array|number[]} coeffs
 * @param {number} x
 */
export function polyEval(coeffs, x) {
  let y = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    y = gfMul(y, x) ^ coeffs[i];
  }
  return y;
}

/**
 * Interpolate y at x=0 from points [{x,y}, …] (Lagrange).
 * @param {{ x: number, y: number }[]} points
 */
export function interpolate(points) {
  let result = 0;
  for (let i = 0; i < points.length; i++) {
    const xi = points[i].x;
    const yi = points[i].y;
    let num = 1;
    let den = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      const xj = points[j].x;
      num = gfMul(num, xj); // (0 - xj) == xj in characteristic 2? Wait: 0^xj = xj
      den = gfMul(den, xi ^ xj);
    }
    // In GF(2^8), 0 - xj = xj (since + and - are XOR)
    result ^= gfMul(yi, gfDiv(num, den));
  }
  return result;
}

/**
 * Split a secret into n shares with threshold t.
 * Share indices are 1..n (x-coordinates).
 * @param {Uint8Array} secret
 * @param {number} threshold
 * @param {number} shares
 * @returns {{ index: number, data: Uint8Array }[]}
 */
export function splitSecret(secret, threshold, shares) {
  if (threshold < 1 || shares < threshold || shares > 255) {
    throw new Error("Invalid threshold/shares");
  }
  if (threshold === 1) {
    // All shares are copies of the secret
    return Array.from({ length: shares }, (_, i) => ({
      index: i + 1,
      data: new Uint8Array(secret),
    }));
  }
  const out = [];
  for (let i = 0; i < shares; i++) {
    out.push({ index: i + 1, data: new Uint8Array(secret.length) });
  }
  for (let b = 0; b < secret.length; b++) {
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[b];
    crypto.getRandomValues(coeffs.subarray(1));
    // Ensure random coeffs are non-zero for highest degree when possible
    for (let i = 1; i < threshold; i++) {
      if (coeffs[i] === 0) coeffs[i] = 1;
    }
    for (let i = 0; i < shares; i++) {
      out[i].data[b] = polyEval(coeffs, i + 1);
    }
  }
  return out;
}

/**
 * Combine shares to recover the secret.
 * @param {{ index: number, data: Uint8Array }[]} shareList
 * @returns {Uint8Array}
 */
export function combineSecret(shareList) {
  if (!shareList.length) throw new Error("No shares");
  const len = shareList[0].data.length;
  const secret = new Uint8Array(len);
  for (let b = 0; b < len; b++) {
    const points = shareList.map((s) => ({ x: s.index, y: s.data[b] }));
    secret[b] = interpolate(points);
  }
  return secret;
}
