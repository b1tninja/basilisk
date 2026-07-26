/**
 * Canonical toolkit step names + accepted alternate spellings (OpenSSL-sized, JCE).
 * Basilisk-legacy tokens (aesgcm, wa-*, recover, …) are NOT accepted at parse time —
 * use migrateRecipe() to rewrite old recipes.
 *
 * Bare `encrypt` / `decrypt` are parse sugar for WebCrypto ciphers (not OpenPGP).
 * Old OpenPGP `encrypt gpg` / `decrypt gpg` still migrate via compound rules.
 */

/**
 * @typedef {{ canonical: string, expectedKeyBits?: number, oaepHash?: string }} StepResolve
 */

/** Concrete cipher ops that `encrypt` / `decrypt` may dispatch to. */
export const CIPHER_DISPATCH_TARGETS = new Set([
  "aes-gcm",
  "aes-cbc",
  "aes-ctr",
  "rsa-oaep",
  "rsa-pkcs1",
]);

/** OpenSSL-sized and JCE forms → canonical (lowercase keys). */
const ALTERNATE_FORMS = new Map(
  /** @type {[string, StepResolve][]} */ ([
    ["aes-128-gcm", { canonical: "aes-gcm", expectedKeyBits: 128 }],
    ["aes-256-gcm", { canonical: "aes-gcm", expectedKeyBits: 256 }],
    ["aes-128-cbc", { canonical: "aes-cbc", expectedKeyBits: 128 }],
    ["aes-256-cbc", { canonical: "aes-cbc", expectedKeyBits: 256 }],
    ["aes-128-ctr", { canonical: "aes-ctr", expectedKeyBits: 128 }],
    ["aes-256-ctr", { canonical: "aes-ctr", expectedKeyBits: 256 }],
    ["aes/gcm/nopadding", { canonical: "aes-gcm" }],
    ["aes/cbc/nopadding", { canonical: "aes-cbc" }],
    ["aes/cbc/pkcs5padding", { canonical: "aes-cbc" }],
    ["aes/cbc/pkcs7padding", { canonical: "aes-cbc" }],
    ["aes/ctr/nopadding", { canonical: "aes-ctr" }],
    ["rsa/ecb/oaepwithsha-1andmgf1padding", { canonical: "rsa-oaep", oaepHash: "sha-1" }],
    ["rsa/ecb/oaepwithsha-256andmgf1padding", { canonical: "rsa-oaep", oaepHash: "sha-256" }],
    ["rsa/ecb/pkcs1padding", { canonical: "rsa-pkcs1" }],
  ])
);

/**
 * Old Basilisk tokens → canonical (migrator only; not used by the parser).
 * Bare `encrypt` / `decrypt` are intentionally omitted — they are WebCrypto sugar.
 * @type {Record<string, string>}
 */
export const LEGACY_STEP_MIGRATE = {
  gpg: "gpg.encrypt",
  symencrypt: "gpg.symencrypt",
  symdecrypt: "gpg.symdecrypt",
  aesgcm: "aes-gcm",
  aescbc: "aes-cbc",
  aesctr: "aes-ctr",
  rsaoaep: "rsa-oaep",
  rsapkcs1: "rsa-pkcs1",
  sss: "sss.split",
  recover: "sss.combine",
  "wa-caps": "webauthn.caps",
  "wa-create": "webauthn.create",
  "wa-get": "webauthn.get",
  "wa-prf": "webauthn.prf",
  "wa-attest": "webauthn.attest",
  "wa-mds": "webauthn.mds",
};

/**
 * @param {string} raw
 * @returns {string}
 */
export function normalizeStepToken(raw) {
  return String(raw || "").trim().toLowerCase();
}

/**
 * Resolve an alternate spelling (OpenSSL-sized / JCE) to a canonical name.
 * Does not resolve registry aliases or legacy Basilisk names.
 * @param {string} raw
 * @returns {StepResolve|null}
 */
export function resolveAlternateForm(raw) {
  const key = normalizeStepToken(raw);
  return ALTERNATE_FORMS.get(key) || null;
}

/**
 * Resolve a cipher transform for `encrypt` / `decrypt` sugar (hyphen, sized, or JCE).
 * @param {string} raw
 * @returns {StepResolve|null}
 */
export function resolveCipherTransform(raw) {
  const alt = resolveAlternateForm(raw);
  if (alt && CIPHER_DISPATCH_TARGETS.has(alt.canonical)) return alt;
  const key = normalizeStepToken(raw);
  if (CIPHER_DISPATCH_TARGETS.has(key)) return { canonical: key };
  return null;
}

/**
 * Hint when the user typed a removed Basilisk-legacy token.
 * @param {string} raw
 * @returns {string|null}
 */
export function legacyRemovalHint(raw) {
  const key = normalizeStepToken(raw);
  const to = LEGACY_STEP_MIGRATE[key];
  if (!to) return null;
  return `"${raw}" was removed — use ${to} (or Upgrade recipe to migrate)`;
}

/**
 * Rewrite a recipe string from Basilisk-legacy step tokens to canonical names.
 * Token-boundary aware for dotted/hyphen targets; does not rewrite inside strings.
 * @param {string} text
 * @returns {{ recipe: string, changes: { from: string, to: string, count: number }[] }}
 */
export function migrateRecipe(text) {
  let recipe = String(text ?? "");
  /** @type {Map<string, number>} */
  const counts = new Map();

  /**
   * @param {string} from
   * @param {string} to
   * @param {RegExp} re
   */
  function apply(from, to, re) {
    let n = 0;
    recipe = recipe.replace(re, (m, pre) => {
      n += 1;
      return `${pre}${to}`;
    });
    if (n) counts.set(from, (counts.get(from) || 0) + n);
  }

  // Compound `encrypt gpg` / `decrypt gpg` (old positional with=gpg) before bare tokens.
  apply(
    "encrypt gpg",
    "gpg.encrypt",
    /(^|[\s|;{]|-(?:\s+))encrypt\s+gpg(?=[\s|;}\-]|$)/gi
  );
  apply(
    "decrypt gpg",
    "gpg.decrypt",
    /(^|[\s|;{]|-(?:\s+))decrypt\s+gpg(?=[\s|;}\-]|$)/gi
  );

  // Longer keys first so wa-create beats nothing overlapping; sort by length desc.
  const keys = Object.keys(LEGACY_STEP_MIGRATE).sort((a, b) => b.length - a.length);
  for (const from of keys) {
    const to = LEGACY_STEP_MIGRATE[from];
    // Step token at start or after | / newline / list dash; not mid-ident.
    const re = new RegExp(
      `(^|[\\s|;{]|-(?:\\s+))(${escapeRegExp(from)})(?=[\\s|;}\\-]|$)`,
      "gi"
    );
    apply(from, to, re);
  }

  const changes = [...counts.entries()].map(([from, count]) => ({
    from,
    to:
      from === "encrypt gpg"
        ? "gpg.encrypt"
        : from === "decrypt gpg"
          ? "gpg.decrypt"
          : LEGACY_STEP_MIGRATE[from],
    count,
  }));
  return { recipe, changes };
}

/**
 * @param {string} s
 */
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
