/**
 * Canonical toolkit step names + accepted alternate spellings (OpenSSL-sized, JCE).
 * Basilisk-legacy tokens (aesgcm, wa-*, recover, …) are NOT accepted at parse time —
 * use migrateRecipe() to rewrite old recipes.
 *
 * Bare `encrypt` / `decrypt` are migrator-only sugar for WebCrypto ciphers (not OpenPGP).
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
 * Bare `encrypt` / `decrypt` + transform are rewritten separately in migrateRecipe.
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
  "gpg.vault": "agent.unlock",
  "gpg.vault.pub": "agent.pub",
  paste: "input",
  cat: "input",
  print: "text",
  echo: "text",
  dump: "inspect",
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
 * Resolve a cipher transform for migrator `encrypt` / `decrypt` sugar
 * (hyphen, sized, or JCE).
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
 * Encodings accepted by `to` / `from` (positional). First pass: hex only.
 * @type {Set<string>}
 */
export const TO_FROM_ENCODINGS = new Set(["hex"]);

/**
 * Whether a token is a known `to` / `from` encoding name.
 * @param {string} raw
 * @returns {boolean}
 */
export function isToFromEncoding(raw) {
  return TO_FROM_ENCODINGS.has(normalizeStepToken(raw));
}

/**
 * Encoding (and other non-cipher) decodeTwin verbs: `base64.encode` / `base64.decode`.
 * Canonical AST stays `{ name, params: { decode } }`; `-d` remains accepted.
 * Note: `pem` ↔ `der` and `to` ↔ `from` are conjugate pairs (not decodeTwin).
 * @param {string} raw
 * @param {(name: string) => { decodeTwin?: boolean, toolbox?: string } | null | undefined} getStep
 * @returns {{ canonical: string, decode: boolean } | null}
 */
export function resolveDecodeTwinVerb(raw, getStep) {
  const key = normalizeStepToken(raw);
  const m = /^(.*)\.(encode|decode)$/.exec(key);
  if (!m) return null;
  const base = m[1];
  const mode = m[2];
  const alt = resolveAlternateForm(base);
  const canonical = alt?.canonical || base;
  // Conjugate pairs — not decodeTwin.
  if (
    canonical === "pem" ||
    canonical === "der" ||
    canonical === "to" ||
    canonical === "from" ||
    canonical === "hex" ||
    canonical === "unhex"
  ) {
    return null;
  }
  const spec = getStep?.(canonical);
  if (!spec?.decodeTwin) return null;
  // Cipher ops keep encrypt/decrypt + `-d`; dotted verbs are for encodings etc.
  if (CIPHER_DISPATCH_TARGETS.has(canonical)) return null;
  return { canonical, decode: mode === "decode" };
}

/**
 * Recipe / UI token for a decodeTwin step direction.
 * Encoding twins prefer `base64.encode` / `base64.decode`; ciphers stay `aes-gcm` / `aes-gcm -d`.
 * pem/der and to/from serialize as bare conjugate verbs (not `.encode`/`.decode`).
 * @param {{ name: string, decodeTwin?: boolean, toolbox?: string } | null | undefined} spec
 * @param {boolean} decode
 * @returns {string}
 */
export function decodeTwinToken(spec, decode) {
  if (!spec?.name) return decode ? "-d" : "";
  if (spec.decodeTwin && !CIPHER_DISPATCH_TARGETS.has(spec.name)) {
    return `${spec.name}.${decode ? "decode" : "encode"}`;
  }
  return decode ? `${spec.name} -d` : spec.name;
}

/**
 * Hint when the user typed a removed Basilisk-legacy token.
 * @param {string} raw
 * @returns {string|null}
 */
export function legacyRemovalHint(raw) {
  const key = normalizeStepToken(raw);
  if (key === "encrypt" || key === "decrypt") {
    return `"${raw}" was removed from live parse — use a concrete cipher (aes-gcm, …) or Upgrade recipe to migrate`;
  }
  if (key === "hex") {
    return `"hex" was removed — use to hex (or Upgrade recipe to migrate)`;
  }
  if (key === "unhex") {
    return `"unhex" was removed — use from hex (or Upgrade recipe to migrate)`;
  }
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

  // Bare slot labels → @ (live parse requires @).
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))out\s+name=([A-Za-z][A-Za-z0-9_-]*)(?=[\s|;}\-]|$)/gi,
      (m, pre, lab) => {
        n += 1;
        return `${pre}out @${lab}`;
      }
    );
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))out\s+(?!@)([A-Za-z][A-Za-z0-9_-]*)(?=[\s|;}\-]|$)/gi,
      (m, pre, lab) => {
        n += 1;
        return `${pre}out @${lab}`;
      }
    );
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))in\s+(?!@)([A-Za-z][A-Za-z0-9_-]*)(?=[\s|;}\-]|$)/gi,
      (m, pre, lab) => {
        n += 1;
        return `${pre}in @${lab}`;
      }
    );
    // Known slot-typed kwargs (not to= emails / fingerprints).
    recipe = recipe.replace(
      /\b(key|peer|private|target|with)=(?!@)([A-Za-z][A-Za-z0-9_-]*)\b/gi,
      (m, k, lab) => {
        n += 1;
        return `${k}=@${lab}`;
      }
    );
    if (n) counts.set("bare-slot-@", (counts.get("bare-slot-@") || 0) + n);
  }

  // WebCrypto sugar: encrypt|decrypt [-d] TRANSFORM → concrete cipher (migrator-only).
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))(encrypt|decrypt)(?:\s+-d)?\s+([A-Za-z][A-Za-z0-9./_-]*)(?=[\s|;}\-]|$)/gi,
      (m, pre, verb, transform) => {
        const resolved = resolveCipherTransform(transform);
        if (!resolved) return m;
        n += 1;
        const hadDashD = /\s+-d\s/i.test(m);
        const decode =
          String(verb).toLowerCase() === "decrypt" || hadDashD;
        // Keep OpenSSL-sized forms (still live-parse); map JCE / bare to canonical.
        const key = normalizeStepToken(transform);
        const keepSized = /^(aes)-\d{3}-(gcm|cbc|ctr)$/.test(key);
        const outToken = keepSized ? key : resolved.canonical;
        return `${pre}${outToken}${decode ? " -d" : ""}`;
      }
    );
    if (n) counts.set("encrypt/decrypt", (counts.get("encrypt/decrypt") || 0) + n);
  }

  // Hex conjugate → CyberChef to/from (do not double-rewrite `to hex` / `from hex`).
  apply(
    "unhex",
    "from hex",
    /(^|[\s|;{]|-(?:\s+))unhex(?=[\s|;}\-]|$)/gi
  );
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))hex(?=[\s|;}\-]|$)/gi,
      (m, pre, offset, full) => {
        const head = full.slice(0, offset + pre.length);
        if (/\bto\s*$/i.test(head) || /\bfrom\s*$/i.test(head)) return m;
        n += 1;
        return `${pre}to hex`;
      }
    );
    if (n) counts.set("hex", (counts.get("hex") || 0) + n);
  }

  // Slot-load alias `from` → `in` when not already `from <encoding>`.
  // Keep `from hex` (and future encodings); rewrite `from @x` / `from 1` / `from label`.
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))from(?=\s+(?:@|\d|(?!hex\b)[A-Za-z][\w-]*))/gi,
      (m, pre) => {
        n += 1;
        return `${pre}in`;
      }
    );
    if (n) counts.set("from (slot)", (counts.get("from (slot)") || 0) + n);
  }

  // Member selectors `.public` → `:public` (not dotted ops like gpg.vault.pub).
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-\s+)\.(public|private|pub|priv|secret|items|values|keys|key|value)\b/gi,
      (m, pre, name) => {
        n += 1;
        return `${pre}:${String(name).toLowerCase()}`;
      }
    );
    if (n) counts.set(".selector", (counts.get(".selector") || 0) + n);
  }

  // Selector shorts → canonical :public / :private.
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-\s+):(pub|priv|secret)\b/gi,
      (m, pre, name) => {
        n += 1;
        const canon =
          String(name).toLowerCase() === "pub" ? "public" : "private";
        return `${pre}:${canon}`;
      }
    );
    if (n) counts.set(":selector-short", (counts.get(":selector-short") || 0) + n);
  }

  // `hexdump` as a step → `inspect format=hexdump`.
  apply(
    "hexdump",
    "inspect format=hexdump",
    /(^|[\s|;{]|-(?:\s+))hexdump(?=[\s|;}\-]|$)/gi
  );

  // `export d` / `import d` → scalar.
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))(export|import)\s+d(?=[\s|;}\-]|$)/gi,
      (m, pre, verb) => {
        n += 1;
        return `${pre}${verb} scalar`;
      }
    );
    if (n) counts.set("export/import d", (counts.get("export/import d") || 0) + n);
  }

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

  /** @type {Record<string, string>} */
  const EXTRA_MIGRATE_TO = {
    hex: "to hex",
    unhex: "from hex",
    "from (slot)": "in",
    "encrypt gpg": "gpg.encrypt",
    "decrypt gpg": "gpg.decrypt",
    "encrypt/decrypt": "aes-gcm / …",
    ".selector": ":selector",
    ":selector-short": ":public/:private",
    hexdump: "inspect format=hexdump",
    "export/import d": "export/import scalar",
  };
  const changes = [...counts.entries()].map(([from, count]) => ({
    from,
    to: EXTRA_MIGRATE_TO[from] || LEGACY_STEP_MIGRATE[from],
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
