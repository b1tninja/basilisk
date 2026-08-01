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
  // Channel traffic moved from the session manager to the transport. `quorum.*`
  // now covers only the exchange itself — room, roster, lifecycle — while
  // `rtc.*` owns the connection primitives, which is where reading and writing
  // a data channel always belonged (`rtc.stats` was already there).
  // The practical payoff: `rtc.send`/`rtc.recv` work on any data channel rather
  // than being married to a quorum room.
  "quorum.send": "rtc.send",
  "quorum.recv": "rtc.recv",
  // Recipe-language audit (design turn 48a): every real namespaced op is
  // `namespace.singlelowercaseword`; the WebRTC toolbox shipped seven that
  // camelCased instead. Keys are lowercase because hint lookup normalizes the
  // typed token first; the rewrite regex matches case-insensitively.
  "rtc.gathercandidates": "rtc.gather",
  "rtc.checkconnectivity": "rtc.check",
  "rtc.connectionstate": "rtc.state",
  "rtc.datachannelstats": "rtc.stats",
  "rtc.createoffer": "rtc.offer",
  "rtc.createanswer": "rtc.answer",
  "rtc.statsreport": "rtc.quality",
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
 * Base alphabets `encode` / `decode` accept, in menu order.
 *
 * Lives in this module because it has no imports of its own, so the registry,
 * the type checker, and the legacy text migration can all share one list
 * without an import cycle. Adding an alphabet here is the only edit needed for
 * all three to agree — this list was previously duplicated in each of them,
 * and the copies had already drifted (two said hex-only).
 * @type {string[]}
 */
export const BASE_ENCODINGS = ["hex", "base64", "base64url", "base32"];

/** @type {Set<string>} */
const BASE_ENCODING_SET = new Set(BASE_ENCODINGS);

/**
 * Whether a token names a base alphabet.
 * @param {string} raw
 * @returns {boolean}
 */
export function isBaseEncoding(raw) {
  return BASE_ENCODING_SET.has(normalizeStepToken(raw));
}

/**
 * Encoding (and other non-cipher) decodeTwin verbs: `base64.encode` / `base64.decode`.
 * Canonical AST stays `{ name, params: { decode } }`; `-d` remains accepted.
 * Note: `pem` ↔ `der` and `encode` ↔ `decode` are conjugate pairs (not decodeTwin).
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
  // Conjugate pairs — not decodeTwin, so they never take a dotted verb.
  if (
    canonical === "pem" ||
    canonical === "der" ||
    canonical === "encode" ||
    canonical === "decode" ||
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
 * pem/der and encode/decode serialize as bare conjugate verbs (not `.encode`/`.decode`).
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
    return `"hex" was removed — use encode hex (or Upgrade recipe to migrate)`;
  }
  if (key === "unhex") {
    return `"unhex" was removed — use decode hex (or Upgrade recipe to migrate)`;
  }
  // Hinted here rather than via LEGACY_STEP_MIGRATE: that map also drives the
  // final token rewrite in migrateRecipe, and `to`/`from` need the narrower
  // rules there (only when followed by an alphabet) so a slot-load `from @x`
  // is not turned into a decode.
  if (key === "to") {
    return `"to" was renamed — use encode <alphabet> (or Upgrade recipe to migrate)`;
  }
  if (key === "from") {
    return `"from" was renamed — use decode <alphabet>, or in @slot to load a slot (or Upgrade recipe to migrate)`;
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

  // Bare `hex` → `encode hex` (but not when it is already the argument of an
  // encode/decode verb, in any of their spellings).
  apply(
    "unhex",
    "decode hex",
    /(^|[\s|;{]|-(?:\s+))unhex(?=[\s|;}\-]|$)/gi
  );
  {
    let n = 0;
    recipe = recipe.replace(
      /(^|[\s|;{]|-(?:\s+))hex(?=[\s|;}\-]|$)/gi,
      (m, pre, offset, full) => {
        const head = full.slice(0, offset + pre.length);
        if (/\b(to|from|encode|decode)\s*$/i.test(head)) return m;
        n += 1;
        return `${pre}encode hex`;
      }
    );
    if (n) counts.set("hex", (counts.get("hex") || 0) + n);
  }

  // `from` was overloaded: the slot-load verb *and* the decode verb. Split it
  // by what follows — an alphabet means decode, anything else meant a slot.
  //
  // The alphabet list has to be spelled out here because this is a text
  // rewrite that runs before parsing. It previously hardcoded `hex` alone, so
  // the moment `to`/`from` learned base64 every `from base64` was rewritten to
  // `in base64` and then rejected as a slot label missing its `@`. Renaming
  // the verb to `decode` is what retires this ambiguity for good; this rule
  // only has to carry legacy text.
  {
    let n = 0;
    recipe = recipe.replace(
      new RegExp(
        `(^|[\\s|;{]|-(?:\\s+))from(?=\\s+(?:@|\\d|(?!(?:${BASE_ENCODINGS.join("|")})\\b)[A-Za-z][\\w-]*))`,
        "gi"
      ),
      (m, pre) => {
        n += 1;
        return `${pre}in`;
      }
    );
    if (n) counts.set("from (slot)", (counts.get("from (slot)") || 0) + n);
  }

  // The surviving `to`/`from` are the encode/decode verbs — rename them.
  apply("to", "encode", /(^|[\s|;{]|-(?:\s+))to(?=\s+[A-Za-z])/gi);
  apply("from", "decode", /(^|[\s|;{]|-(?:\s+))from(?=\s+[A-Za-z])/gi);

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

  // `file.read as=auto` → `as=bytes`. A retired *param value*, which is new
  // here — everything above retires a step token — and it is retired for the
  // reason the others were kept: `auto` sniffed the chosen file's MIME and
  // extension to pick `text` or `bytes`, while the compiler, holding no file,
  // declared `bytes`. `bytes` is what the declaration always said, so this
  // rewrite changes the recipe's text without changing its type.
  //
  // Scoped to the step: `as=` is `file.read`'s alone, but `auto` is a live
  // value on `out encoding=`, `jwt.verify alg=`, `pem label=` and more, and a
  // bare `as=auto` rewrite would be one step away from touching those.
  {
    let n = 0;
    recipe = recipe.replace(
      /(\bfile\.read\b)([^|;\n]*)/gi,
      (m, verb, args) => {
        const next = args.replace(/\bas=auto\b/gi, () => {
          n += 1;
          return "as=bytes";
        });
        return `${verb}${next}`;
      }
    );
    if (n) counts.set("file.read as=auto", (counts.get("file.read as=auto") || 0) + n);
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
    hex: "encode hex",
    unhex: "decode hex",
    "from (slot)": "in",
    "encrypt gpg": "gpg.encrypt",
    "decrypt gpg": "gpg.decrypt",
    "encrypt/decrypt": "aes-gcm / …",
    ".selector": ":selector",
    ":selector-short": ":public/:private",
    hexdump: "inspect format=hexdump",
    "export/import d": "export/import scalar",
    "file.read as=auto": "file.read as=bytes",
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
