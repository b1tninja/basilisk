/**
 * Recursive-descent recipe parser (PEG-style ordered choice).
 * Normative grammar: docs/RECIPE.md
 *
 * Supports multi-chain recipes (blank-line separated), `@slot` refs on `out`/`in`,
 * tee/foreach bodies, and bare selectors (`.public`, `[n]`).
 *
 * AST steps match recipe.js RecipeStep, with:
 *   - chains[] + steps (= chains[0].steps)
 *   - tee.branches[].selector  e.g. ".private"
 *   - tee.branches[].member    canonical "private"|"public"
 *   - foreach.foreachSelector  e.g. ".items" (optional)
 *   - select steps for bare selectors: { name: "select", params: { selector } }
 */

import { canonicalName, getStep } from "./registry.js";

/**
 * @typedef {import("./recipe.js").RecipeStep} RecipeStep
 * @typedef {import("./recipe.js").RecipeError} RecipeError
 * @typedef {import("./recipe.js").TeeBranch} TeeBranch
 */

/** @typedef {{ type: string, value: string, start: number, end: number }} Tok */

const SELECTOR_MEMBERS = new Set([
  "private",
  "priv",
  "secret",
  "public",
  "pub",
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
    .replace(/^\./, "")
    .toLowerCase();
  if (m === "private" || m === "priv" || m === "secret") return "private";
  if (m === "public" || m === "pub") return "public";
  return m;
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
  if (s.includes("\\") || s.includes("/") && !s.startsWith("@")) return true;
  if (/\.(pem|der|bin|txt|asc|key|spki|pkcs8)$/i.test(s)) return true;
  return false;
}

/**
 * Canonical slot ref for out/in: `@label` or decimal index string.
 * Bare ident → `@ident`. Rejects path-like forms.
 * @param {string} raw
 * @param {{ allowIndex?: boolean }} [opts]
 * @returns {{ ok: true, ref: string } | { ok: false, error: string }}
 */
export function normalizeSlotRef(raw, opts = {}) {
  const allowIndex = opts.allowIndex !== false;
  const s = String(raw ?? "").trim();
  if (!s) return { ok: false, error: "Empty slot reference" };
  if (isPathLikeRef(s)) {
    return {
      ok: false,
      error:
        "File paths are not supported yet — use @label (e.g. out @kp / in @kp)",
    };
  }
  if (/^\d+$/.test(s)) {
    if (!allowIndex) {
      return { ok: false, error: `Slot index "${s}" is only valid on in/from` };
    }
    const n = Number(s);
    if (n < 1) return { ok: false, error: "Slot index must be ≥ 1" };
    return { ok: true, ref: String(n) };
  }
  const bare = s.startsWith("@") ? s.slice(1) : s;
  if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(bare)) {
    return { ok: false, error: `Invalid slot label "${s}"` };
  }
  return { ok: true, ref: `@${bare}` };
}

/**
 * Label key without `@` (for registry maps). Null if index ref.
 * @param {string} ref
 * @returns {string|null}
 */
export function slotLabelKey(ref) {
  const s = String(ref || "");
  if (/^\d+$/.test(s)) return null;
  return s.startsWith("@") ? s.slice(1) : s;
}

/**
 * @param {string} source
 * @returns {{ ast: { chains: { steps: RecipeStep[] }[], steps: RecipeStep[], source: string }|null, errors: RecipeError[] }}
 */
export function parseRecipeSource(source) {
  const raw = String(source || "");
  const text = raw.trim();
  /** @type {RecipeError[]} */
  const errors = [];
  if (!text) {
    return {
      ast: { chains: [], steps: [], source: text },
      errors: [
        {
          message:
            "Empty recipe — start with a source step like genkey, random, or input.",
        },
      ],
    };
  }

  if (raw.includes("\t")) {
    const idx = raw.indexOf("\t");
    errors.push({
      message: "Tabs are not allowed — use 2 spaces per indent level",
      start: idx,
      end: idx + 1,
    });
    return { ast: null, errors };
  }

  const p = new Parser(raw, errors);
  try {
    const chains = p.parseRecipe();
    if (errors.length) return { ast: null, errors };
    const steps = chains[0]?.steps || [];
    return { ast: { chains, steps, source: text }, errors: [] };
  } catch (err) {
    if (!errors.length) {
      errors.push({
        message: err?.message || String(err),
        start: p.pos,
        end: p.pos,
      });
    }
    return { ast: null, errors };
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
    this.pos = 0;
    this.lineStarts = [0];
    for (let i = 0; i < src.length; i++) {
      if (src[i] === "\n") this.lineStarts.push(i + 1);
    }
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

      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
      }

      void lineStart;
      const pipeSteps = this.parsePipeline(0);
      current.push(...pipeSteps);

      this.skipSpacesAndCommentsOnLine();
      if (this.peek() === "\n") this.pos++;
      else if (!this.eof()) {
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
    return stages;
  }

  /**
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseStage(parentIndent) {
    this.skipSpaces();
    if (this.peek() === ".") {
      return this.parseSelectorStage();
    }
    if (this.peek() === "[") {
      return this.parseIndexSelectorStage();
    }

    const nameStart = this.pos;
    const name = this.readIdent();
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

    const canon = canonicalName(name);
    if (!canon) {
      this.errors.push({
        message: `Unknown step "${name}". See the Reference panel for available steps.`,
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

    return this.parseApply(canon, name, nameStart);
  }

  /**
   * @returns {RecipeStep}
   */
  parseSelectorStage() {
    const start = this.pos;
    this.pos++; // .
    const id = this.readIdent();
    if (!id) {
      this.errors.push({
        message: "Expected selector name after `.`",
        start,
        end: this.pos,
      });
      return { name: "select", params: { selector: "." }, start, end: this.pos };
    }
    const sel = `.${id}`;
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
          "tee requires a body — use `{ - .public | … }` or indented `-` lines (use `peek` for a side inspect)",
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
    if (this.peek() === ".") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      if (!id) {
        this.errors.push({
          message: "Expected selector after `foreach .`",
          start: selStart,
          end: this.pos,
        });
      } else {
        foreachSelector = `.${id}`;
        const m = id.toLowerCase();
        if (m !== "items" && m !== "values" && m !== "keys") {
          this.errors.push({
            message: `foreach selector must be .items, .values, or .keys (got ${foreachSelector})`,
            start: selStart,
            end: this.pos,
          });
        }
      }
      this.skipSpaces();
    }

    const body = this.parseBody(parentIndent);
    if (!body.listBody.length && !body.branches.length) {
      // branches shouldn't appear under foreach with selectors as member —
      // allow list body only; if someone used - .key under foreach .items it's a list body with selector prefix...
      // Actually foreach body branches with selectors mean per-item projection via tee inside,
      // OR we allow - .value | out as a branch-style list item.
      // parseBody puts selector-prefix items into branches for tee; for foreach we need them as body with selector.
    }
    if (!body.listBody.length && !body.branches.length) {
      this.errors.push({
        message:
          "foreach requires a body — use indented `- out @share` or `foreach { - out @share }`",
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
        params: { selector: br.selector || `.${br.member}` },
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
      // allow `-step`? grammar requires space; be lenient if next is .
      if (this.peek() !== ".") {
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
    if (this.peek() === ".") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      if (!id) {
        this.errors.push({
          message: "Expected selector name after `.`",
          start: selStart,
          end: this.pos,
        });
      } else {
        selector = `.${id}`;
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
            message: `Expected \`|\` after selector ${selector} (e.g. \`- .private | inspect\`)`,
            start: this.pos,
            end: this.pos,
          });
        }
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
        member: member === selector.replace(/^\./, "") ? member : member,
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
            "File paths are not supported yet — use @label (e.g. out @kp / in @kp)",
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

      // @label slot sugar
      if (ch === "@") {
        this.pos++;
        const id = this.readIdent();
        const raw = id ? `@${id}` : "@";
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
        const num = this.readNumber();
        const raw = String(num);
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

      if (/[A-Za-z]/.test(ch)) {
        // Peek whether this is `name=value` or a bare value (may contain `/`).
        const word = this.readIdent();
        this.skipSpaces();
        if (this.peek() === "=") {
          this.pos++;
          this.skipSpaces();
          const rawVal = this.readArgValue();
          params[word] = coerceParam(spec, word, rawVal);
        } else {
          // Positional: allow alg ids like ec/p256 (slash beyond bare ident).
          let raw = word;
          if (this.peek() === "/") {
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

    // Normalize out/in slot refs to canonical @label or index.
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
        }
      } else if (canon === "out") {
        params.name = "@output";
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
    if (this.peek() === "@") {
      const start = this.pos;
      this.pos++;
      const id = this.readIdent();
      return id ? `@${id}` : this.src.slice(start, this.pos);
    }
    if (/[0-9]/.test(this.peek())) return String(this.readNumber());
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_./-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  readIdent() {
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_-]/.test(this.peek())) this.pos++;
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
