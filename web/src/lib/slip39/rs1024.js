/**
 * RS1024 checksum used by SLIP-39 (Bech32-style polymod over 10-bit symbols).
 * Spec: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
 */

const GEN = [
  0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24,
  0x3090fc48, 0x21b1f890, 0x3f3f120b,
];

/**
 * @param {number[]} values  10-bit symbols
 * @returns {number}
 */
export function rs1024Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 20;
    chk = ((chk & 0xfffff) << 10) ^ v;
    for (let i = 0; i < 10; i++) {
      if ((b >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

/**
 * Customize checksum with a tag (SLIP-39 uses "shamir" customization).
 * @param {string} tag
 * @param {number[]} data
 * @returns {number[]}
 */
export function rs1024CreateChecksum(tag, data) {
  const values = [...tagToValues(tag), ...data, 0, 0, 0];
  const polymod = rs1024Polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 3; i++) {
    checksum.push((polymod >> (10 * (2 - i))) & 1023);
  }
  return checksum;
}

/**
 * @param {string} tag
 * @param {number[]} dataWithChecksum
 * @returns {boolean}
 */
export function rs1024VerifyChecksum(tag, dataWithChecksum) {
  return rs1024Polymod([...tagToValues(tag), ...dataWithChecksum]) === 1;
}

/**
 * @param {string} tag
 * @returns {number[]}
 */
function tagToValues(tag) {
  return Array.from(String(tag || ""), (c) => c.charCodeAt(0));
}
