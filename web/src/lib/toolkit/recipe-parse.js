/**
 * Recursive-descent recipe parser (PEG-style ordered choice).
 * Normative grammar: docs/RECIPE.md
 *
 * Supports multi-chain recipes (blank-line separated), `$slot` refs on `out`/`in`,
 * tee/foreach bodies, member selectors (`:public`, `[n]`), and bare `$slot` sources.
 *
 * AST steps match recipe.js RecipeStep, with:
 *   - chains[] + steps (= chains[0].steps)
 *   - tee.branches[].selector  e.g. ":private"
 *   - tee.branches[].member    canonical "private"|"public"
 *   - foreach.foreachSelector  e.g. ":items" (optional)
 *   - select steps for bare selectors: { name: "select", params: { selector } }
 *   - bare `$label` → { name: "in", params: { ref: "$label" } }
 *
 * Sigils. `$` marks a slot; `@` is reserved for the chain-header position (peer
 * assignment) and is *not* a slot marker there. Recipes written before the swap
 * spelled slots with `@`, so `@label` is still read as a slot in the two
 * positions where nothing else can appear — after `out`/`in`, and after
 * `param=` — and normalized to `$label` in the AST, so the very next serialize
 * writes the new spelling. Both sigils are start-anchored: they mark a slot only
 * as the first character of a reference token, which is what keeps
 * `to=alice@example.com` and `passphrase=my$ecret` literal.
 */

import { canonicalName, getStep } from "./registry.js";
import {
  legacyRemovalHint,
  resolveAlternateForm,
  resolveDecodeTwinVerb,
} from "./step-names.js";

/**
 * @typedef {import("./recipe.js").RecipeStep} RecipeStep
 * @typedef {import("./recipe.js").RecipeError} RecipeError
 * @typedef {import("./recipe.js").TeeBranch} TeeBranch
 */

/** @typedef {{ type: string, value: string, start: number, end: number }} Tok */

const SELECTOR_MEMBERS = new Set([
  "private",
  "public",
  "keys",
  "values",
  "items",
  "key",
  "value",
]);

/**
 * @param {string} raw
 * @returns {string}
 */
export function canonicalSelectorMember(raw) {
  const m = String(raw || "")
    .replace(/^[.:]/, "")
    .toLowerCase();
  // Legacy shorts accepted only via Upgrade recipe / migrator — not live parse.
  if (m === "private") return "private";
  if (m === "public") return "public";
  return m;
}

/** Slot sigil in the current grammar. */
export const SLOT_SIGIL = "$";

/** Pre-swap slot sigil, still read (and rewritten) for old share links. */
export const LEGACY_SLOT_SIGIL = "@";

/** Slot a bare `out` writes to. */
export const DEFAULT_OUT_SLOT = "$output";

/**
 * `$` or the legacy `@`, at the *start* of a reference token only.
 * @param {string} ch
 * @returns {boolean}
 */
export function isSlotSigil(ch) {
  return ch === SLOT_SIGIL || ch === LEGACY_SLOT_SIGIL;
}

/**
 * A slot label, no sigil. Shared by the parser and by every caller that has to
 * build a pattern out of a label — `$` is the regex end-anchor, so a label must
 * never reach `new RegExp` unescaped.
 */
const SLOT_LABEL_RE = /^[A-Za-z][A-Za-z0-9_-]*$/;

/** A whole param value that is a pre-swap slot ref, sigil and all. */
const LEGACY_SLOT_TOKEN_RE = /^@[A-Za-z][A-Za-z0-9_-]*$/;

/**
 * Escape a slot ref for interpolation into a regular expression.
 * `$` is the end-anchor and `$&`-style replacement syntax; a bare `$kp` spliced
 * into a pattern matches an empty string at end of input instead of the ref.
 * @param {string} ref
 * @returns {string}
 */
export function escapeSlotRefForRegExp(ref) {
  return String(ref ?? "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Path-shaped refs reserved for future file I/O.
 * @param {string} raw
 * @returns {boolean}
 */
export function isPathLikeRef(raw) {
  const s = String(raw || "").trim();
  if (!s) return false;
  if (/^file:/i.test(s)) return true;
  if (s.startsWith("./") || s.startsWith("../") || s.startsWith("/")) return true;
  if (s.includes("\\") || s.includes("/") && !isSlotSigil(s[0])) return true;
  if (/\.(pem|der|bin|txt|asc|key|spki|pkcs8)$/i.test(s)) return true;
  return false;
}

/**
 * Canonical slot ref for out/in: `$label` or decimal index string.
 * Labels must include `$` (bare `kp` / `key=cek` rejected — use migrateRecipe / Upgrade).
 * A legacy `@label` normalizes to `$label` and reports `legacy: true`, so the
 * caller can warn once and the AST carries only the new spelling.
 * @param {string} raw
 * @param {{ allowIndex?: boolean }} [opts]
 * @returns {{ ok: true, ref: string, legacy?: boolean } | { ok: false, error: string }}
 */
export function normalizeSlotRef(raw, opts = {}) {
  const allowIndex = opts.allowIndex !== false;
  const s = String(raw ?? "").trim();
  if (!s) return { ok: false, error: "Empty slot reference" };
  if (isPathLikeRef(s)) {
    return {
      ok: false,
      error:
        "File paths are not supported yet — use $label (e.g. out $kp / in $kp)",
    };
  }
  if (/^\d+$/.test(s)) {
    if (!allowIndex) {
      return { ok: false, error: `Slot index "${s}" is only valid on in` };
    }
    const n = Number(s);
    if (n < 1) return { ok: false, error: "Slot index must be ≥ 1" };
    return { ok: true, ref: String(n) };
  }
  if (!isSlotSigil(s[0])) {
    if (!SLOT_LABEL_RE.test(s)) {
      return { ok: false, error: `Invalid slot label "${s}"` };
    }
    return {
      ok: false,
      error: `Slot labels require $ (use $${s}, not ${s})`,
    };
  }
  const legacy = s[0] === LEGACY_SLOT_SIGIL;
  const bare = s.slice(1);
  if (!SLOT_LABEL_RE.test(bare)) {
    return { ok: false, error: `Invalid slot label "${s}"` };
  }
  return legacy
    ? { ok: true, ref: `${SLOT_SIGIL}${bare}`, legacy: true }
    : { ok: true, ref: `${SLOT_SIGIL}${bare}` };
}

/**
 * Label key without its sigil (for registry maps). Null if index ref.
 * @param {string} ref
 * @returns {string|null}
 */
export function slotLabelKey(ref) {
  const s = String(ref || "");
  if (/^\d+$/.test(s)) return null;
  return isSlotSigil(s[0]) ? s.slice(1) : s;
}

/**
 * The message every legacy-sigil warning carries.
 * @param {string} ref  canonical (`$label`) ref
 * @returns {string}
 */
export function legacySlotSigilWarning(ref) {
  const bare = slotLabelKey(ref) || "";
  return `Slots are written \`$${bare}\` now — \`@${bare}\` still loads and was rewritten. \`@\` is reserved for naming a peer.`;
}

/**
 * @param {string} source
 * @returns {{ ast: { chains: { steps: RecipeStep[] }[], steps: RecipeStep[], source: string }|null, errors: RecipeError[], warnings: RecipeError[] }}
 */
export function parseRecipeSource(source) {
  const raw = String(source || "");
  const text = raw.trim();
  if (!text) {
    return {
      ast: { chains: [], steps: [], source: text },
      errors: [
        {
          message:
            "Empty recipe — start with a source step like genkey, random, or input.",
        },
      ],
      warnings: [],
    };
  }

  if (raw.includes("\t")) {
    const idx = raw.indexOf("\t");
    return {
      ast: null,
      errors: [
        {
          message: "Tabs are not allowed — use 2 spaces per indent level",
          start: idx,
          end: idx + 1,
        },
      ],
      warnings: [],
    };
  }

  // Pass 1 reads `@` as a slot only where nothing else can appear (after
  // `out`/`in`, after `param=`) and leaves the chain-header `@` reserved.
  const first = runParse(raw, text, false);
  // A chain-header `@kp` is only a slot in a recipe that is *provably* pre-swap:
  // one that spelled a slot `@` somewhere unambiguous. That is not a guess — a
  // bare `@kp` source can only resolve against an `out @kp` in the same source,
  // so every valid legacy recipe carries the evidence. Without it, `@` at the
  // head of a chain stays free for peer assignment.
  if (first.replayAsLegacy) return runParse(raw, text, true);
  return first;
}

/**
 * @param {string} raw
 * @param {string} text
 * @param {boolean} legacyChainHeader
 */
function runParse(raw, text, legacyChainHeader) {
  /** @type {RecipeError[]} */
  const errors = [];
  const p = new Parser(raw, errors);
  p.legacyChainHeader = legacyChainHeader;
  try {
    const chains = p.parseRecipe();
    const replayAsLegacy =
      !legacyChainHeader && p.sawReservedChainHeader && p.sawLegacySlotSigil;
    if (errors.length) {
      return { ast: null, errors, warnings: p.warnings, replayAsLegacy };
    }
    const steps = chains[0]?.steps || [];
    return {
      ast: { chains, steps, source: text },
      errors: [],
      warnings: p.warnings,
      replayAsLegacy,
    };
  } catch (err) {
    if (!errors.length) {
      errors.push({
        message: err?.message || String(err),
        start: p.pos,
        end: p.pos,
      });
    }
    return {
      ast: null,
      errors,
      warnings: p.warnings,
      replayAsLegacy:
        !legacyChainHeader && p.sawReservedChainHeader && p.sawLegacySlotSigil,
    };
  }
}

class Parser {
  /**
   * @param {string} src
   * @param {RecipeError[]} errors
   */
  constructor(src, errors) {
    this.src = src;
    this.errors = errors;
    /** @type {RecipeError[]} */
    this.warnings = [];
    this.pos = 0;
    /** Read a chain-header `@label` as a slot (legacy replay only). */
    this.legacyChainHeader = false;
    /** A `$label` was read as a slot where the position allows only a slot. */
    this.sawLegacySlotSigil = false;
    /** A chain began with `$label`, which this grammar reserves. */
    this.sawReservedChainHeader = false;
    /** Next stage starts a chain — the position `@` is reserved for. */
    this.atChainHeader = false;
    this.lineStarts = [0];
    for (let i = 0; i < src.length; i++) {
      if (src[i] === "\n") this.lineStarts.push(i + 1);
    }
  }

  /**
   * Record a legacy `@label` read, once per distinct ref.
   * @param {string} ref  canonical `$label`
   * @param {number} start
   * @param {number} end
   */
  noteLegacySlotSigil(ref, start, end) {
    this.sawLegacySlotSigil = true;
    const message = legacySlotSigilWarning(ref);
    if (this.warnings.some((w) => w.message === message)) return;
    this.warnings.push({ message, start, end });
  }

  eof() {
    return this.pos >= this.src.length;
  }

  peek() {
    return this.eof() ? "" : this.src[this.pos];
  }

  /**
   * Indent (spaces) at the start of the current line containing pos.
   * @returns {number}
   */
  lineIndentAt(pos) {
    let i = pos;
    while (i > 0 && this.src[i - 1] !== "\n") i--;
    let n = 0;
    while (i + n < this.src.length && this.src[i + n] === " ") n++;
    return n;
  }

  skipSpaces() {
    while (this.peek() === " ") this.pos++;
  }

  skipSpacesAndCommentsOnLine() {
    this.skipSpaces();
    if (this.peek() === "#") {
      while (!this.eof() && this.peek() !== "\n") this.pos++;
    }
  }

  /**
   * @returns {{ steps: RecipeStep[] }[]}
   */
  parseRecipe() {
    /** @type {{ steps: RecipeStep[] }[]} */
    const chains = [];
    /** @type {RecipeStep[]} */
    let current = [];

    const flush = () => {
      if (current.length) {
        chains.push({ steps: current });
        current = [];
      }
    };

    while (!this.eof()) {
      const lineStart = this.pos;
      this.skipSpaces();

      // Blank line → chain separator (once we have content).
      if (this.peek() === "\n" || this.eof()) {
        if (this.peek() === "\n") this.pos++;
        if (current.length) flush();
        continue;
      }

      // Full-line comment — stays inside the current chain.
      if (this.peek() === "#") {
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }

      // Orphan list marker at stem level.
      if (this.peek() === "-") {
        this.errors.push({
          message:
            "Unexpected indent — use `- step` under tee/foreach (or `{ … }` bodies)",
          start: this.pos,
          end: this.pos + 1,
        });
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }

      // A leading `|` continues the stem of the chain above it, so the stage
      // after it is not a chain header.
      let header = current.length === 0;
      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
        header = false;
      }

      void lineStart;
      this.atChainHeader = header;
      const pipeSteps = this.parsePipeline(0);
      current.push(...pipeSteps);

      this.skipSpacesAndCommentsOnLine();
      if (this.peek() === "\n") {
        // Indent bodies may leave pos on a blank line (chain separator). That
        // newline is not stem EOL — flush before the next chain.
        const blankLine = this.isBlankLineEndingAt(this.pos);
        this.pos++;
        if (blankLine) flush();
      } else if (!this.eof()) {
        this.errors.push({
          message: `Unexpected "${this.peek()}"`,
          start: this.pos,
          end: this.pos + 1,
        });
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
      }
    }
    flush();
    return chains.length ? chains : [{ steps: [] }];
  }

  /**
   * @param {number} parentIndent
   * @returns {RecipeStep[]}
   */
  parsePipeline(parentIndent) {
    /** @type {RecipeStep[]} */
    const stages = [];
    stages.push(this.parseStage(parentIndent));
    for (;;) {
      this.skipSpaces();
      if (this.peek() !== "|") break;
      // Don't consume `|` that starts a new stem line after indent body —
      // those are handled by the caller at indent 0.
      this.pos++;
      this.skipSpaces();
      if (this.peek() === "\n" || this.eof()) {
        this.errors.push({
          message: "Dangling `|` — expected a step after the pipe",
          start: this.pos,
          end: this.pos,
        });
        break;
      }
      stages.push(this.parseStage(parentIndent));
    }
    // `$kp | out` → out inherits $kp (same as `in $kp | out $kp`).
    for (let i = 1; i < stages.length; i++) {
      const prev = stages[i - 1];
      const cur = stages[i];
      if (cur.name !== "out") continue;
      const name = cur.params?.name;
      const isDefault =
        name === undefined || name === "" || name === DEFAULT_OUT_SLOT;
      if (!isDefault) continue;
      if (
        prev.name === "in" &&
        String(prev.params?.ref || "").startsWith(SLOT_SIGIL)
      ) {
        cur.params = { ...cur.params, name: String(prev.params.ref) };
      }
    }
    return stages;
  }

  /**
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseStage(parentIndent) {
    const header = this.atChainHeader;
    this.atChainHeader = false;
    this.skipSpaces();
    if (this.peek() === ":") {
      return this.parseSelectorStage();
    }
    if (this.peek() === ".") {
      const start = this.pos;
      this.pos++;
      const id = this.readIdent();
      this.errors.push({
        message: id
          ? `Member selectors use :${id.toLowerCase()} (dot is for namespaced ops like gpg.encrypt)`
          : "Member selectors use :public / :private (dot is for namespaced ops like gpg.encrypt)",
        start,
        end: this.pos,
      });
      return {
        name: "select",
        params: { selector: id ? `:${id}` : ":" },
        start,
        end: this.pos,
      };
    }
    if (this.peek() === "[") {
      return this.parseIndexSelectorStage();
    }
    if (this.peek() === SLOT_SIGIL) {
      return this.parseBareSlotStage();
    }
    if (this.peek() === LEGACY_SLOT_SIGIL) {
      // Reserved: `@alice | …` is how a chain will name the peer it runs for.
      // Mid-pipeline there is no such reading, so the legacy slot read is safe.
      if (header && !this.legacyChainHeader) {
        this.sawReservedChainHeader = true;
        this.errors.push({
          message:
            "`@` at the start of a chain is reserved — write a slot as `$label` (e.g. `$kp | :public`)",
          start: this.pos,
          end: this.pos + 1,
        });
        // Parsed, not counted: this `@` must never be its own evidence that the
        // recipe is legacy, or the reservation would unmake itself.
        return this.parseBareSlotStage(false);
      }
      return this.parseBareSlotStage();
    }

    // Stem literals: "…" / '…' / 0xff / decimal int / true|false.
    if (this.peek() === '"' || this.peek() === "'") {
      return this.parseLiteralStage();
    }
    if (/[0-9]/.test(this.peek())) {
      return this.parseLiteralStage();
    }
    if (/^(true|false)(?![A-Za-z0-9_.+/-])/i.test(this.src.slice(this.pos))) {
      return this.parseLiteralStage();
    }

    const nameStart = this.pos;
    const name = this.readStepName();
    if (!name) {
      this.errors.push({
        message: "Expected a step name",
        start: this.pos,
        end: this.pos,
      });
      return {
        name: "inspect",
        params: {},
        start: nameStart,
        end: this.pos,
      };
    }

    const lower = name.toLowerCase();
    if (lower === "merge" || lower === "collect") {
      this.errors.push({
        message:
          `"${name}" is not used — foreach bodies close by dedent or \`}\` (see docs/RECIPE.md)`,
        start: nameStart,
        end: this.pos,
      });
      return {
        name: lower,
        params: {},
        start: nameStart,
        end: this.pos,
      };
    }

    // HMAC sugar → SubtleCrypto sign/verify (serialize as sign/verify).
    if (lower === "hmac") {
      return this.parseApply("sign", name, nameStart);
    }
    if (lower === "hmac.verify") {
      return this.parseApply("verify", name, nameStart);
    }

    // CyberChef encoding: `to` / `from` are normal registry steps (positional encoding).
    // Bare encrypt|decrypt sugar is migrator-only — hard-error in live parse.
    if (lower === "encrypt" || lower === "decrypt") {
      this.errors.push({
        message:
          `"${name}" was removed from live parse — use a concrete cipher (aes-gcm, …) or Upgrade recipe to migrate`,
        start: nameStart,
        end: this.pos,
      });
      return {
        name: "aes-gcm",
        params: { decode: lower === "decrypt" },
        start: nameStart,
        end: this.pos,
      };
    }

    // Encoding twins: base64.encode / base64.decode → base64 / base64 -d.
    const twinVerb = resolveDecodeTwinVerb(name, getStep);
    if (twinVerb) {
      const step = this.parseApply(twinVerb.canonical, name, nameStart);
      step.params = { ...step.params, decode: twinVerb.decode };
      return step;
    }

    const alt = resolveAlternateForm(name);
    const lookup = alt?.canonical || name;
    const canon = canonicalName(lookup);
    if (!canon) {
      const legacy = legacyRemovalHint(name);
      const jceHint =
        name.includes("/") && !legacy
          ? `Unknown JCE transform "${name}"; try aes-gcm (or AES/GCM/NoPadding)`
          : null;
      this.errors.push({
        message:
          legacy ||
          jceHint ||
          `Unknown step "${name}". See the Reference panel for available steps.`,
        start: nameStart,
        end: this.pos,
      });
      return {
        name: name.toLowerCase(),
        params: {},
        start: nameStart,
        end: this.pos,
      };
    }

    if (canon === "tee") {
      return this.parseTeeBlock(nameStart, parentIndent);
    }
    if (canon === "foreach") {
      return this.parseForeachBlock(nameStart, parentIndent);
    }

    const step = this.parseApply(canon, name, nameStart);
    if (alt?.expectedKeyBits) {
      step.params = { ...step.params, keyBits: alt.expectedKeyBits };
    }
    if (alt?.oaepHash) {
      step.params = { ...step.params, hash: alt.oaepHash };
    }
    return step;
  }

  /**
   * Stem literal stage → internal `lit` (serialize writes the literal form).
   * @returns {RecipeStep}
   */
  parseLiteralStage() {
    const start = this.pos;
    if (this.peek() === '"' || this.peek() === "'") {
      const value = this.readString();
      return {
        name: "lit",
        params: { kind: "text", value },
        start,
        end: this.pos,
      };
    }
    // Bool: true / false (case-insensitive; must be a whole token).
    if (/^(true|false)(?![A-Za-z0-9_.+/-])/i.test(this.src.slice(this.pos))) {
      const word = this.src.slice(this.pos).match(/^(true|false)/i)?.[0] || "";
      this.pos += word.length;
      return {
        name: "lit",
        params: { kind: "bool", value: word.toLowerCase() === "true" },
        start,
        end: this.pos,
      };
    }
    // Hex int 0x… or decimal.
    if (
      this.peek() === "0" &&
      (this.src[this.pos + 1] === "x" || this.src[this.pos + 1] === "X")
    ) {
      this.pos += 2;
      const hexStart = this.pos;
      while (/[0-9A-Fa-f]/.test(this.peek())) this.pos++;
      if (this.pos === hexStart) {
        this.errors.push({
          message: "Expected hex digits after `0x`",
          start,
          end: this.pos,
        });
        return {
          name: "lit",
          params: { kind: "int", value: 0 },
          start,
          end: this.pos,
        };
      }
      const hex = this.src.slice(hexStart, this.pos);
      const n = Number.parseInt(hex, 16);
      return {
        name: "lit",
        params: { kind: "int", value: Number.isFinite(n) ? n : 0 },
        start,
        end: this.pos,
      };
    }
    const n = this.readNumber();
    if (n == null) {
      this.errors.push({
        message: "Expected a number literal",
        start,
        end: this.pos,
      });
      return {
        name: "lit",
        params: { kind: "int", value: 0 },
        start,
        end: this.pos,
      };
    }
    return {
      name: "lit",
      params: { kind: "int", value: n },
      start,
      end: this.pos,
    };
  }

  /**
   * Bare `$label` source — same as `in $label`.
   * @returns {RecipeStep}
   */
  parseBareSlotStage(noteLegacy = true) {
    const start = this.pos;
    const sigil = this.peek();
    this.pos++; // $ or legacy @
    const id = this.readIdent();
    if (!id) {
      this.errors.push({
        message: `Expected slot label after \`${sigil}\``,
        start,
        end: this.pos,
      });
      return {
        name: "in",
        params: { ref: sigil },
        start,
        end: this.pos,
      };
    }
    const ref = `${SLOT_SIGIL}${id}`;
    if (sigil === LEGACY_SLOT_SIGIL && noteLegacy) {
      this.noteLegacySlotSigil(ref, start, this.pos);
    }
    return {
      name: "in",
      params: { ref },
      start,
      end: this.pos,
    };
  }

  /**
   * @returns {RecipeStep}
   */
  parseSelectorStage() {
    const start = this.pos;
    this.pos++; // :
    const id = this.readIdent();
    if (!id) {
      this.errors.push({
        message: "Expected selector name after `:`",
        start,
        end: this.pos,
      });
      return { name: "select", params: { selector: ":" }, start, end: this.pos };
    }
    const sel = `:${id.toLowerCase()}`;
    const member = canonicalSelectorMember(id);
    if (!SELECTOR_MEMBERS.has(id.toLowerCase()) && !SELECTOR_MEMBERS.has(member)) {
      this.errors.push({
        message: `Unknown selector "${sel}"`,
        start,
        end: this.pos,
      });
    }
    return {
      name: "select",
      params: { selector: sel },
      start,
      end: this.pos,
    };
  }

  /**
   * @returns {RecipeStep}
   */
  parseIndexSelectorStage() {
    const start = this.pos;
    this.pos++; // [
    this.skipSpaces();
    const a = this.readNumber();
    if (a == null) {
      this.errors.push({
        message: "Expected number inside `[…]`",
        start,
        end: this.pos,
      });
      return { name: "at", params: { selector: "1" }, start, end: this.pos };
    }
    let selector = String(a);
    this.skipSpaces();
    if (this.peek() === ":") {
      this.pos++;
      this.skipSpaces();
      const b = this.readNumber();
      if (b == null) {
        this.errors.push({
          message: "Expected number after `:` in `[n:m]`",
          start: this.pos,
          end: this.pos,
        });
      } else {
        selector = `${a}:${b}`;
      }
    }
    this.skipSpaces();
    if (this.peek() === "]") this.pos++;
    else {
      this.errors.push({
        message: "Expected `]`",
        start: this.pos,
        end: this.pos,
      });
    }
    return {
      name: "at",
      params: { selector },
      start,
      end: this.pos,
    };
  }

  /**
   * @param {number} start
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseTeeBlock(start, parentIndent) {
    this.skipSpaces();
    const body = this.parseBody(parentIndent);
    if (!body.listBody.length && !body.branches.length) {
      this.errors.push({
        message:
          "tee requires a body — use `{ - :public | … }` or indented `-` lines (use `peek` for a side inspect)",
        start,
        end: this.pos,
      });
    }
    /** @type {RecipeStep} */
    const step = {
      name: "tee",
      params: {},
      start,
      end: this.pos,
    };
    if (body.listBody.length) step.body = body.listBody;
    if (body.branches.length) step.branches = body.branches;
    if (body.brace) step.bodyForm = "brace";
    return step;
  }

  /**
   * @param {number} start
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseForeachBlock(start, parentIndent) {
    this.skipSpaces();
    /** @type {string|undefined} */
    let foreachSelector;
    if (this.peek() === ":") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      if (!id) {
        this.errors.push({
          message: "Expected selector after `foreach :`",
          start: selStart,
          end: this.pos,
        });
      } else {
        foreachSelector = `:${id.toLowerCase()}`;
        const m = id.toLowerCase();
        if (m !== "items" && m !== "values" && m !== "keys") {
          this.errors.push({
            message: `foreach selector must be :items, :values, or :keys (got ${foreachSelector})`,
            start: selStart,
            end: this.pos,
          });
        }
      }
      this.skipSpaces();
    } else if (this.peek() === ".") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      this.errors.push({
        message: id
          ? `foreach selectors use :${id.toLowerCase()} (not .${id})`
          : "foreach selectors use :items / :values / :keys",
        start: selStart,
        end: this.pos,
      });
      this.skipSpaces();
    }

    const body = this.parseBody(parentIndent);
    if (!body.listBody.length && !body.branches.length) {
      // branches shouldn't appear under foreach with selectors as member —
      // allow list body only; if someone used - :key under foreach :items it's a list body with selector prefix...
      // Actually foreach body branches with selectors mean per-item projection via tee inside,
      // OR we allow - :value | out as a branch-style list item.
      // parseBody puts selector-prefix items into branches for tee; for foreach we need them as body with selector.
    }
    if (!body.listBody.length && !body.branches.length) {
      this.errors.push({
        message:
          "foreach requires a body — use indented `- out $share` or `foreach { - out $share }`",
        start,
        end: this.pos,
      });
    }

    // Under foreach, selector-prefixed branches are still list items that project the item.
    /** @type {RecipeStep[]} */
    const listBody = [...body.listBody];
    for (const br of body.branches) {
      // Represent as a synthetic tee? Better: store as steps with .selector on a wrapper.
      // Flatten: foreach body item with selector becomes a mini-pipeline starting with select.
      const selStep = {
        name: "select",
        params: { selector: br.selector || `:${br.member}` },
        start: br.start || start,
        end: br.end || this.pos,
      };
      listBody.push(selStep, ...br.body);
    }

    /** @type {RecipeStep} */
    const step = {
      name: "foreach",
      params: {},
      start,
      end: this.pos,
      body: listBody,
    };
    if (foreachSelector) step.foreachSelector = foreachSelector;
    if (body.brace) step.bodyForm = "brace";
    return step;
  }

  /**
   * @param {number} parentIndent
   * @returns {{ listBody: RecipeStep[], branches: TeeBranch[], brace: boolean }}
   */
  parseBody(parentIndent) {
    this.skipSpaces();
    if (this.peek() === "{") {
      return this.parseBraceBody();
    }
    // Indent body requires a newline next (after optional trailing spaces/comment)
    this.skipSpacesAndCommentsOnLine();
    if (this.peek() !== "\n") {
      return { listBody: [], branches: [], brace: false };
    }
    return this.parseIndentBody(parentIndent);
  }

  /**
   * @returns {{ listBody: RecipeStep[], branches: TeeBranch[], brace: boolean }}
   */
  parseBraceBody() {
    this.pos++; // {
    /** @type {RecipeStep[]} */
    const listBody = [];
    /** @type {TeeBranch[]} */
    const branches = [];
    for (;;) {
      this.skipSpaces();
      if (this.peek() === "\n") {
        this.pos++;
        continue;
      }
      if (this.peek() === "#") {
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        continue;
      }
      if (this.peek() === "}") {
        this.pos++;
        break;
      }
      if (this.eof()) {
        this.errors.push({
          message: "Unclosed `{` in tee/foreach body",
          start: this.pos,
          end: this.pos,
        });
        break;
      }
      // optional indent then -
      this.skipSpaces();
      if (this.peek() === "-") {
        this.parseBranchLineInto(listBody, branches, /*brace*/ true);
        this.skipSpacesAndCommentsOnLine();
        if (this.peek() === "\n") this.pos++;
        continue;
      }
      this.errors.push({
        message: "Expected `- branch` or `}` inside block body",
        start: this.pos,
        end: this.pos + 1,
      });
      while (!this.eof() && this.peek() !== "\n" && this.peek() !== "}") {
        this.pos++;
      }
    }
    return { listBody, branches, brace: true };
  }

  /**
   * @param {number} parentIndent
   * @returns {{ listBody: RecipeStep[], branches: TeeBranch[], brace: boolean }}
   */
  /**
   * True when `newlinePos` points at `\n` that ends an empty/whitespace-only line
   * (or a full-line comment). Used to detect chain separators left by indent bodies.
   * @param {number} newlinePos
   * @returns {boolean}
   */
  isBlankLineEndingAt(newlinePos) {
    if (this.src[newlinePos] !== "\n") return false;
    let i = newlinePos - 1;
    while (i >= 0 && this.src[i] !== "\n") i--;
    const lineStart = i + 1;
    let p = lineStart;
    while (p < newlinePos && this.src[p] === " ") p++;
    if (p >= newlinePos) return true;
    if (this.src[p] === "#") return true;
    return false;
  }

  /**
   * Indent of the next non-blank, non-comment line at or after `from`, or -1 at EOF.
   * @param {number} from
   * @returns {number}
   */
  peekNextContentIndent(from) {
    let p = from;
    while (p < this.src.length) {
      let i = 0;
      while (this.src[p + i] === " ") i++;
      const j = p + i;
      if (j >= this.src.length) return -1;
      if (this.src[j] === "\n") {
        p = j + 1;
        continue;
      }
      if (this.src[j] === "#") {
        while (p < this.src.length && this.src[p] !== "\n") p++;
        if (this.src[p] === "\n") p++;
        continue;
      }
      return i;
    }
    return -1;
  }

  parseIndentBody(parentIndent) {
    /** @type {RecipeStep[]} */
    const listBody = [];
    /** @type {TeeBranch[]} */
    const branches = [];
    // consume the newline that starts the body
    if (this.peek() === "\n") this.pos++;

    let bodyIndent = 0;
    while (!this.eof()) {
      const lineStart = this.pos;
      // peek indent
      let i = 0;
      while (this.src[lineStart + i] === " ") i++;
      const indent = i;

      // blank / comment
      let j = lineStart + i;
      if (j >= this.src.length || this.src[j] === "\n") {
        // Blank line after body items ends the body when the next content is
        // dedented (chain separator or stem continuation). Leave the blank so
        // parseRecipe can flush chains. Blanks between list items still skip.
        if (bodyIndent) {
          const nextIndent = this.peekNextContentIndent(
            j < this.src.length ? j + 1 : j
          );
          if (nextIndent < 0 || nextIndent <= parentIndent) {
            this.pos = lineStart;
            break;
          }
        }
        this.pos = j < this.src.length ? j + 1 : j;
        continue;
      }
      if (this.src[j] === "#") {
        this.pos = j;
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }

      if (indent <= parentIndent) {
        // stem continuation (e.g. `| export`) — do not consume
        this.pos = lineStart;
        break;
      }

      if (!bodyIndent) {
        if (indent % 2 !== 0) {
          this.errors.push({
            message: "Use 2-space indent levels for nested list bodies",
            start: lineStart,
            end: lineStart + indent,
          });
        }
        bodyIndent = indent;
      }

      if (indent > bodyIndent) {
        this.errors.push({
          message: "Nested lists inside tee/foreach bodies are not supported in v1",
          start: lineStart,
          end: lineStart + indent,
        });
        this.pos = lineStart + indent;
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }
      if (indent < bodyIndent) {
        this.pos = lineStart;
        break;
      }

      this.pos = lineStart + indent;
      if (this.peek() !== "-") {
        this.errors.push({
          message: "Body lines under tee/foreach must be list items (`- step`)",
          start: this.pos,
          end: this.pos + 1,
        });
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }
      this.parseBranchLineInto(listBody, branches, false);
      this.skipSpacesAndCommentsOnLine();
      if (this.peek() === "\n") this.pos++;
    }
    return { listBody, branches, brace: false };
  }

  /**
   * Parse `- [selector |] pipeline` at current pos (on `-`).
   * @param {RecipeStep[]} listBody
   * @param {TeeBranch[]} branches
   * @param {boolean} _brace
   */
  parseBranchLineInto(listBody, branches, _brace) {
    const start = this.pos;
    this.pos++; // -
    if (this.peek() !== " " && this.peek() !== "\t") {
      // allow `-:public` without space; require space otherwise
      if (this.peek() !== ":" && this.peek() !== "[") {
        this.errors.push({
          message: "Expected space after `-` in list body",
          start: this.pos,
          end: this.pos,
        });
      }
    }
    this.skipSpaces();

    /** @type {string|null} */
    let selector = null;
    if (this.peek() === ":") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      if (!id) {
        this.errors.push({
          message: "Expected selector name after `:`",
          start: selStart,
          end: this.pos,
        });
      } else {
        selector = `:${id.toLowerCase()}`;
        const member = canonicalSelectorMember(id);
        if (
          !SELECTOR_MEMBERS.has(id.toLowerCase()) &&
          !SELECTOR_MEMBERS.has(member)
        ) {
          this.errors.push({
            message: `Unknown selector "${selector}"`,
            start: selStart,
            end: this.pos,
          });
        }
        this.skipSpaces();
        if (this.peek() === "|") {
          this.pos++;
          this.skipSpaces();
        } else {
          this.errors.push({
            message: `Expected \`|\` after selector ${selector} (e.g. \`- :private | inspect\`)`,
            start: this.pos,
            end: this.pos,
          });
        }
      }
    } else if (this.peek() === ".") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      this.errors.push({
        message: id
          ? `Member selectors use :${id.toLowerCase()} (e.g. \`- :public | …\`)`
          : "Member selectors use :public / :private",
        start: selStart,
        end: this.pos,
      });
      this.skipSpaces();
      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
      }
    } else if (this.peek() === "[") {
      const idx = this.parseIndexSelectorStage();
      selector = `[${idx.params.selector}]`;
      this.skipSpaces();
      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
      }
    }

    const pipe = this.parsePipeline(this.lineIndentAt(start));
    // Stop pipeline if we hit end of line — parsePipeline may consume too much?
    // parsePipeline stops at non-pipe; good. But it could parse across newlines inside?
    // Our parseStage for blocks could nest — rejected for foreach/tee inside body via validate.

    if (selector) {
      const member = canonicalSelectorMember(selector);
      branches.push({
        member: canonicalSelectorMember(selector),
        selector,
        body: pipe,
        start,
        end: this.pos,
      });
    } else {
      listBody.push(...pipe);
    }

    // Reject nested block openers inside branch pipelines at parse time
    for (const s of pipe) {
      if (s.name === "foreach" || s.name === "tee") {
        this.errors.push({
          message: `Nested ${s.name} is not supported inside a list body in v1`,
          start: s.start,
          end: s.end,
        });
      }
    }
  }

  /**
   * @param {string} canon
   * @param {string} rawName
   * @param {number} start
   * @returns {RecipeStep}
   */
  parseApply(canon, rawName, start) {
    const spec = getStep(canon);
    /** @type {Record<string, string|number|boolean>} */
    const params = {};
    let positionalUsed = false;

    // Bracket form already handled; here handle at with positional etc.
    while (!this.eof()) {
      this.skipSpaces();
      const ch = this.peek();
      if (
        !ch ||
        ch === "\n" ||
        ch === "|" ||
        ch === "}" ||
        ch === "#"
      ) {
        break;
      }
      // Stop before indent-body list on same... won't happen same line

      if (ch === '"' || ch === "'") {
        const v = this.readString();
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (!pos) {
            this.errors.push({
              message: `Unexpected string (no positional parameter for ${canon})`,
              start: this.pos,
              end: this.pos,
            });
          } else {
            params[pos.name] = coerceParam(spec, pos.name, v);
            positionalUsed = true;
          }
        } else {
          this.errors.push({
            message: `Unexpected token "${v}"`,
            start: this.pos,
            end: this.pos,
          });
        }
        continue;
      }

      if (ch === "-" && /[A-Za-z]/.test(this.src[this.pos + 1] || "")) {
        const flagStart = this.pos;
        this.pos++;
        const flagName = this.readIdent();
        const flag = `-${flagName}`;
        const flagParam = (spec?.params || []).find((p) => p.flag === flag);
        if (!flagParam) {
          this.errors.push({
            message: `Unknown flag "${flag}" for ${canon}`,
            start: flagStart,
            end: this.pos,
          });
        } else {
          params[flagParam.name] = true;
        }
        continue;
      }

      // Path-like tokens reserved for future file I/O (out/in only).
      const tokStart = this.pos;
      if (
        (canon === "out" || canon === "in") &&
        (ch === "." || ch === "/" || ch === '"' || ch === "'")
      ) {
        let raw;
        if (ch === '"' || ch === "'") {
          raw = this.readString();
        } else {
          while (
            !this.eof() &&
            !/\s/.test(this.peek()) &&
            this.peek() !== "|" &&
            this.peek() !== "}" &&
            this.peek() !== "#"
          ) {
            this.pos++;
          }
          raw = this.src.slice(tokStart, this.pos);
        }
        this.errors.push({
          message:
            "File paths are not supported yet — use $label (e.g. out $kp / in $kp)",
          start: tokStart,
          end: this.pos,
        });
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (pos) {
            params[pos.name] = raw;
            positionalUsed = true;
          }
        }
        continue;
      }

      // $label slot sugar (legacy `@label` still read here — a positional
      // argument is one of the two positions where only a slot can appear).
      if (isSlotSigil(ch)) {
        this.pos++;
        const id = this.readIdent();
        const raw = id ? `${ch}${id}` : ch;
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (!pos) {
            this.errors.push({
              message: `Unexpected token "${raw}" (no positional parameter for ${canon})`,
              start: tokStart,
              end: this.pos,
            });
          } else {
            params[pos.name] = coerceParam(spec, pos.name, raw);
            positionalUsed = true;
          }
        } else {
          this.errors.push({
            message: `Unexpected token "${raw}"`,
            start: tokStart,
            end: this.pos,
          });
        }
        continue;
      }

      // ident or ident=value or number
      if (/[0-9]/.test(ch)) {
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (!pos) {
            const num = this.readNumber();
            this.errors.push({
              message: `Unexpected token "${num}" (no positional parameter for ${canon})`,
              start: tokStart,
              end: this.pos,
            });
          } else if (pos.type === "string") {
            // Fingerprints / opaque hex often start with a digit — don't stop at
            // the first non-digit (e.g. `8F…` must not become `8` + junk).
            const raw = this.readNamedArgValue();
            params[pos.name] = coerceParam(spec, pos.name, raw);
            positionalUsed = true;
          } else {
            const num = this.readNumber();
            const raw = String(num);
            params[pos.name] = coerceParam(spec, pos.name, raw);
            positionalUsed = true;
          }
        } else {
          const num = this.readNumber();
          this.errors.push({
            message: `Unexpected token "${num}"`,
            start: tokStart,
            end: this.pos,
          });
        }
        continue;
      }

      if (/[A-Za-z]/.test(ch)) {
        // Peek whether this is `name=value` or a bare value (may contain `/`).
        const word = this.readIdent();
        this.skipSpaces();
        if (this.peek() === "=") {
          this.pos++;
          this.skipSpaces();
          // Named values may be base64url (can start with a digit) — don't use
          // readArgValue's number shortcut.
          const rawVal = this.readNamedArgValue();
          const known = (spec?.params || []).some((p) => p.name === word);
          if (!known) {
            this.errors.push({
              message: `Unknown parameter "${word}" for ${canon}`,
              start: tokStart,
              end: this.pos,
            });
          } else {
            params[word] = coerceParam(spec, word, rawVal);
          }
        } else {
          // Positional: allow alg ids (ec/p256) and emails (alice@example.org).
          let raw = word;
          if (/[/:@+$]/.test(this.peek())) {
            this.pos = tokStart;
            raw = this.readArgValue();
          }
          if (!positionalUsed) {
            const pos = (spec?.params || []).find((p) => p.positional);
            if (!pos) {
              this.errors.push({
                message: `Unexpected token "${raw}" (no positional parameter for ${canon})`,
                start: tokStart,
                end: this.pos,
              });
            } else {
              params[pos.name] = coerceParam(spec, pos.name, raw);
              positionalUsed = true;
            }
          } else {
            this.errors.push({
              message: `Unexpected token "${raw}"`,
              start: tokStart,
              end: this.pos,
            });
          }
        }
        continue;
      }

      this.errors.push({
        message: `Unexpected "${ch}"`,
        start: this.pos,
        end: this.pos + 1,
      });
      this.pos++;
      break;
    }

    for (const p of spec?.params || []) {
      if (params[p.name] === undefined && p.default !== undefined) {
        params[p.name] = p.default;
      }
    }
    if (String(rawName || "").toLowerCase() === "hexdump") {
      params.format = "hexdump";
    }

    // Legacy sigil, one sweep. Not every slot-bearing param is declared
    // `type: "slot"` — `passphrase=`, `aad=`, `salt=`, `info=`, `signature=`
    // and `gpg.encrypt to=` are strings that the validator reads as a slot
    // when, and only when, the value starts with the sigil. That leading-sigil
    // rule is the whole of the old grammar, so replaying it here rewrites all
    // of them at once and the AST leaves parse holding only `$`.
    for (const key of Object.keys(params)) {
      const v = params[key];
      if (typeof v !== "string") continue;
      if (!LEGACY_SLOT_TOKEN_RE.test(v)) continue;
      const ref = `${SLOT_SIGIL}${v.slice(1)}`;
      params[key] = ref;
      this.noteLegacySlotSigil(ref, start, this.pos);
    }

    // Normalize out/in slot refs to canonical $label or index.
    if (canon === "out" || canon === "in") {
      const key = canon === "out" ? "name" : "ref";
      const rawSlot = params[key];
      if (rawSlot != null && rawSlot !== "") {
        const norm = normalizeSlotRef(String(rawSlot), {
          allowIndex: canon === "in",
        });
        if (!norm.ok) {
          this.errors.push({
            message: norm.error,
            start,
            end: this.pos,
          });
        } else {
          params[key] = norm.ref;
          if (norm.legacy) this.noteLegacySlotSigil(norm.ref, start, this.pos);
        }
      } else if (canon === "out") {
        params.name = DEFAULT_OUT_SLOT;
      }
    }

    // Normalize typed slot params (key=$cek, peer=$pub, …).
    for (const p of spec?.params || []) {
      if (p.type !== "slot") continue;
      const rawSlot = params[p.name];
      if (rawSlot == null || rawSlot === "") continue;
      const norm = normalizeSlotRef(String(rawSlot), {
        allowIndex: !!p.allowIndex,
      });
      if (!norm.ok) {
        this.errors.push({
          message: `${canon} ${p.name}=: ${norm.error}`,
          start,
          end: this.pos,
        });
      } else {
        params[p.name] = norm.ref;
        if (norm.legacy) this.noteLegacySlotSigil(norm.ref, start, this.pos);
      }
    }

    // verify signature=$slot (bare base64url strings stay as-is).
    if (canon === "verify") {
      const sig = params.signature;
      if (sig != null && isSlotSigil(String(sig).trim()[0])) {
        const norm = normalizeSlotRef(String(sig), { allowIndex: false });
        if (!norm.ok) {
          this.errors.push({
            message: `verify signature=: ${norm.error}`,
            start,
            end: this.pos,
          });
        } else {
          params.signature = norm.ref;
          if (norm.legacy) this.noteLegacySlotSigil(norm.ref, start, this.pos);
        }
      }
    }

    return {
      name: canon,
      params,
      start,
      end: this.pos,
    };
  }

  /**
   * Unquoted argument value: ident extended with `/` (e.g. ec/p256), or a string/number.
   * @returns {string}
   */
  readArgValue() {
    if (this.peek() === '"' || this.peek() === "'") return this.readString();
    if (isSlotSigil(this.peek())) {
      const start = this.pos;
      const sigil = this.peek();
      this.pos++;
      const id = this.readIdent();
      return id ? `${sigil}${id}` : this.src.slice(start, this.pos);
    }
    if (/[0-9]/.test(this.peek())) return String(this.readNumber());
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    // Mid-token `@` / `$` / `:` so positional emails (`hkp.search
    // alice@example.org`) parse as one value. A sigil marks a slot only at the
    // start of the token — that is what keeps `my$ecret` a literal.
    while (/[A-Za-z0-9_+./:@$-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  /**
   * Value after `name=` — allows base64url (may start with a digit).
   * @returns {string}
   */
  readNamedArgValue() {
    if (this.peek() === '"' || this.peek() === "'") return this.readString();
    if (isSlotSigil(this.peek())) {
      const start = this.pos;
      const sigil = this.peek();
      this.pos++;
      const id = this.readIdent();
      return id ? `${sigil}${id}` : this.src.slice(start, this.pos);
    }
    // Unquoted values: allow `@` / `$` / `:` so `to=alice@example.org`,
    // `passphrase=my$ecret` and `to=email:…` / `to=fpr:…` parse as one token.
    // Only a *leading* sigil (handled above) means a slot.
    if (!/[A-Za-z0-9_+./-]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_+./:@$-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  readIdent() {
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  /**
   * Step head: dotted namespaces (`gpg.encrypt`), hyphen ciphers (`aes-gcm`),
   * or JCE transforms (`AES/GCM/NoPadding`). Not used for param names.
   * @returns {string}
   */
  readStepName() {
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_.+/-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  readNumber() {
    if (!/[0-9]/.test(this.peek())) return null;
    const start = this.pos;
    while (/[0-9]/.test(this.peek())) this.pos++;
    return Number(this.src.slice(start, this.pos));
  }

  readString() {
    const q = this.peek();
    this.pos++;
    const start = this.pos;
    while (!this.eof() && this.peek() !== q) this.pos++;
    const v = this.src.slice(start, this.pos);
    if (this.peek() === q) this.pos++;
    return v;
  }
}

/**
 * @param {import("./registry.js").StepSpec|null|undefined} spec
 * @param {string} key
 * @param {string} raw
 * @returns {string|number|boolean}
 */
function coerceParam(spec, key, raw) {
  const p = (spec?.params || []).find((x) => x.name === key);
  if (!p) return raw;
  if (
    (spec?.name === "export" || spec?.name === "import") &&
    key === "format" &&
    String(raw).toLowerCase() === "d"
  ) {
    return "scalar";
  }
  if (p.type === "int") {
    const n = Number(raw);
    return Number.isFinite(n) ? Math.floor(n) : raw;
  }
  if (p.type === "bool") {
    return raw === "true" || raw === "1" || raw === "yes";
  }
  if (p.type === "enum" && Array.isArray(p.enum)) {
    const lower = String(raw).toLowerCase();
    const hit = p.enum.find((e) => String(e).toLowerCase() === lower);
    if (hit != null) return hit;
  }
  return raw;
}
