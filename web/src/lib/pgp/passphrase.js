/**
 * Dependency-free passphrase strength estimate for SKESK UX.
 * Soft guidance only — never blocks encryption.
 */

/** Common weak passwords / patterns (lowercase). */
const COMMON = new Set([
  "password",
  "password1",
  "passphrase",
  "secret",
  "hunter2",
  "123456",
  "12345678",
  "qwerty",
  "letmein",
  "admin",
  "welcome",
  "monkey",
  "dragon",
  "master",
  "login",
  "abc123",
  "iloveyou",
  "openpgp",
  "basilisk",
]);

/**
 * @param {string} pw
 * @returns {{ bits: number, label: "empty"|"weak"|"fair"|"strong", hint: string }}
 */
export function estimatePassphraseStrength(pw) {
  const s = String(pw || "");
  if (!s.length) {
    return { bits: 0, label: "empty", hint: "" };
  }

  let charset = 0;
  if (/[a-z]/.test(s)) charset += 26;
  if (/[A-Z]/.test(s)) charset += 26;
  if (/[0-9]/.test(s)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(s)) charset += 33;
  if (!charset) charset = 1;

  // Shannon-style upper bound: log2(|charset|^len)
  let bits = s.length * Math.log2(charset);

  // Penalties
  if (/^(.)\1+$/.test(s)) bits *= 0.15; // all same char
  else if (/(.)\1{2,}/.test(s)) bits *= 0.85; // runs

  // Sequential runs (abc, 123, cba)
  let seq = 0;
  for (let i = 2; i < s.length; i++) {
    const a = s.charCodeAt(i - 2);
    const b = s.charCodeAt(i - 1);
    const c = s.charCodeAt(i);
    if (b - a === 1 && c - b === 1) seq += 1;
    if (a - b === 1 && b - c === 1) seq += 1;
  }
  if (seq) bits *= Math.max(0.4, 1 - seq * 0.12);

  const lower = s.toLowerCase();
  if (COMMON.has(lower) || [...COMMON].some((w) => lower.includes(w) && w.length >= 5)) {
    bits = Math.min(bits, 18);
  }

  bits = Math.max(0, Math.round(bits));

  /** @type {"weak"|"fair"|"strong"} */
  let label = "weak";
  let hint = "Weak — prefer a longer random passphrase.";
  if (bits >= 50) {
    label = "strong";
    hint = "Strong passphrase.";
  } else if (bits >= 35) {
    label = "fair";
    hint = "Fair — a few more characters would help.";
  }

  return { bits, label, hint };
}
