/**
 * Toolkit recipe language: pipe-separated steps with key=value params.
 *
 *   genkey ec/p256 | export pkcs8 | pem | slip39 threshold=2 shares=3 | foreach | encrypt gpg
 *   recombine | combine | utf8 | pem -d | import pkcs8 alg=ec/p256 | export pkcs8 | pem
 *   (aliases: input / read / paste for recombine)
 *
 * Flow control (CyberChef Fork/Merge):
 *   foreach (aliases: map, each, fork) opens a per-item scope
 *   merge   (aliases: collect) closes it (implicit at end of pipeline)
 *
 * Decode flags (shell-style):
 *   base64 -d | hex -d | pem -d   → params.decode = true
 */

import {
  canonicalName,
  effectiveIo,
  getStep,
  ioCompatible,
  listSteps,
} from "./registry.js";

/**
 * @typedef {object} RecipeStep
 * @property {string} name  canonical name
 * @property {Record<string, string|number|boolean>} params
 * @property {number} start  char offset in source
 * @property {number} end
 */

/**
 * @typedef {object} RecipeAst
 * @property {RecipeStep[]} steps
 * @property {string} source
 */

/**
 * @typedef {object} RecipeError
 * @property {string} message
 * @property {number} [start]
 * @property {number} [end]
 * @property {number} [stepIndex]
 */

/**
 * @typedef {object} ValidationResult
 * @property {boolean} ok
 * @property {RecipeError[]} errors
 * @property {string[]} warnings
 * @property {number} [recipientSlots]  how many GPG recipient slots Run needs
 * @property {boolean} [foreachGpg]  encrypt gpg is inside foreach
 * @property {("shares"|"gpg"|"text")[]} [inputNeeds]  runtime input panels required
 */

/**
 * Parse a recipe string into an AST.
 * @param {string} source
 * @returns {{ ast: RecipeAst|null, errors: RecipeError[] }}
 */
export function parseRecipe(source) {
  const text = String(source || "").trim();
  /** @type {RecipeError[]} */
  const errors = [];
  if (!text) {
    return {
      ast: { steps: [], source: text },
      errors: [{ message: "Empty recipe — start with a source step like genkey, random, or input." }],
    };
  }

  const segments = splitPipes(text);
  /** @type {RecipeStep[]} */
  const steps = [];

  for (const seg of segments) {
    const parsed = parseSegment(seg.text, seg.start);
    if (parsed.error) {
      errors.push(parsed.error);
      continue;
    }
    steps.push(parsed.step);
  }

  if (errors.length) return { ast: null, errors };
  return { ast: { steps, source: text }, errors: [] };
}

/**
 * Split on `|` that are not inside quotes or brackets.
 * @param {string} text
 * @returns {{ text: string, start: number, end: number }[]}
 */
function splitPipes(text) {
  /** @type {{ text: string, start: number, end: number }[]} */
  const out = [];
  let start = 0;
  let depth = 0;
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (c === "[" || c === "(") {
      depth++;
      continue;
    }
    if (c === "]" || c === ")") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (c === "|" && depth === 0) {
      const slice = text.slice(start, i);
      out.push({ text: slice, start, end: i });
      start = i + 1;
    }
  }
  out.push({ text: text.slice(start), start, end: text.length });
  return out
    .map((s) => {
      const trimmed = s.text.trim();
      const lead = s.text.length - s.text.trimStart().length;
      return {
        text: trimmed,
        start: s.start + lead,
        end: s.start + lead + trimmed.length,
      };
    })
    .filter((s) => s.text.length > 0);
}

/**
 * @param {string} segment
 * @param {number} offset
 * @returns {{ step: RecipeStep, error?: undefined } | { step?: undefined, error: RecipeError }}
 */
function parseSegment(segment, offset) {
  const tokens = tokenize(segment);
  if (!tokens.length) {
    return {
      error: { message: "Empty step", start: offset, end: offset },
    };
  }
  const nameTok = tokens[0];
  const canon = canonicalName(nameTok.value);
  if (!canon) {
    return {
      error: {
        message: `Unknown step "${nameTok.value}". See the Reference panel for available steps.`,
        start: offset + nameTok.start,
        end: offset + nameTok.end,
      },
    };
  }
  const spec = getStep(canon);
  /** @type {Record<string, string|number|boolean>} */
  const params = {};
  let positionalUsed = false;

  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    // Bare CLI flags (e.g. -d)
    if (t.value.startsWith("-") && !t.value.includes("=")) {
      const flagParam = (spec?.params || []).find((p) => p.flag === t.value);
      if (!flagParam) {
        return {
          error: {
            message: `Unknown flag "${t.value}" for ${canon}`,
            start: offset + t.start,
            end: offset + t.end,
          },
        };
      }
      params[flagParam.name] = true;
      continue;
    }
    if (t.value.includes("=")) {
      const eq = t.value.indexOf("=");
      const key = t.value.slice(0, eq).trim();
      const raw = t.value.slice(eq + 1).trim();
      if (!key) {
        return {
          error: {
            message: "Empty parameter name",
            start: offset + t.start,
            end: offset + t.end,
          },
        };
      }
      params[key] = coerceParam(spec, key, unquote(raw));
    } else if (!positionalUsed) {
      const pos = (spec?.params || []).find((p) => p.positional);
      if (!pos) {
        return {
          error: {
            message: `Unexpected token "${t.value}" (no positional parameter for ${canon})`,
            start: offset + t.start,
            end: offset + t.end,
          },
        };
      }
      params[pos.name] = coerceParam(spec, pos.name, unquote(t.value));
      positionalUsed = true;
    } else {
      return {
        error: {
          message: `Unexpected token "${t.value}"`,
          start: offset + t.start,
          end: offset + t.end,
        },
      };
    }
  }

  // Apply defaults
  for (const p of spec?.params || []) {
    if (params[p.name] === undefined && p.default !== undefined) {
      params[p.name] = p.default;
    }
  }

  // Alias `hexdump` forces classic dump layout (canonical step is still inspect).
  if (String(nameTok.value || "").toLowerCase() === "hexdump") {
    params.format = "hexdump";
  }

  return {
    step: {
      name: canon,
      params,
      start: offset,
      end: offset + segment.length,
    },
  };
}

/**
 * @param {string} s
 * @returns {{ value: string, start: number, end: number }[]}
 */
function tokenize(s) {
  /** @type {{ value: string, start: number, end: number }[]} */
  const out = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    const start = i;
    if (s[i] === '"' || s[i] === "'") {
      const q = s[i];
      i++;
      while (i < s.length && s[i] !== q) i++;
      i++;
      out.push({ value: s.slice(start, i), start, end: i });
      continue;
    }
    while (i < s.length && !/\s/.test(s[i])) i++;
    out.push({ value: s.slice(start, i), start, end: i });
  }
  return out;
}

function unquote(s) {
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * @param {import("./registry.js").StepSpec|null} spec
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
  return raw;
}

/**
 * Serialize an AST back to recipe text (canonical names, no aliases).
 * Recipients are never included. Decode flags emit as `-d`.
 * @param {RecipeAst|RecipeStep[]} astOrSteps
 * @returns {string}
 */
export function serializeRecipe(astOrSteps) {
  const steps = Array.isArray(astOrSteps) ? astOrSteps : astOrSteps?.steps || [];
  return steps
    .map((step) => {
      const spec = getStep(step.name);
      const parts = [step.name];
      for (const p of spec?.params || []) {
        const v = step.params?.[p.name];
        if (v === undefined || v === "") continue;
        // CLI flags: emit -d instead of decode=true
        if (p.flag && p.type === "bool") {
          if (v === true) parts.push(p.flag);
          continue;
        }
        // Always emit positional params (even when equal to default) so
        // recipes stay explicit and round-trip cleanly.
        if (p.positional && parts.length === 1) {
          parts.push(String(v));
          continue;
        }
        if (v === p.default) continue;
        const needsQuote = /[\s|=]/.test(String(v));
        parts.push(
          `${p.name}=${needsQuote ? JSON.stringify(String(v)) : String(v)}`
        );
      }
      return parts.join(" ");
    })
    .join(" | ");
}

/**
 * Validate a parsed AST against the registry (types, scopes, params).
 * @param {RecipeAst} ast
 * @returns {ValidationResult}
 */
export function validateRecipe(ast) {
  /** @type {RecipeError[]} */
  const errors = [];
  /** @type {string[]} */
  const warnings = [];
  const steps = ast?.steps || [];
  if (!steps.length) {
    return {
      ok: false,
      errors: [{ message: "Empty recipe" }],
      warnings,
      inputNeeds: [],
    };
  }

  /** @type {import("./registry.js").IoType} */
  let current = "none";
  let foreachDepth = 0;
  let sharesCount = 0;
  let gpgSlots = 0;
  let foreachGpg = false;
  /** @type {("shares"|"gpg"|"text")[]} */
  const inputNeeds = [];
  let sawInputShares = false;
  let sawInputText = false;
  let sawDecryptGpg = false;

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const spec = getStep(step.name);
    if (!spec) {
      errors.push({
        message: `Unknown step "${step.name}"`,
        start: step.start,
        end: step.end,
        stepIndex: i,
      });
      continue;
    }

    const io = effectiveIo(spec, step.params);

    // Param checks
    for (const p of spec.params || []) {
      const v = step.params[p.name];
      if (v === undefined) continue;
      if (p.type === "enum" && p.enum && !p.enum.includes(String(v))) {
        errors.push({
          message: `${step.name}: invalid ${p.name}="${v}" (allowed: ${p.enum.join(", ")})`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      if (p.type === "int") {
        const n = Number(v);
        if (!Number.isFinite(n)) {
          errors.push({
            message: `${step.name}: ${p.name} must be an integer`,
            start: step.start,
            end: step.end,
            stepIndex: i,
          });
        } else {
          if (p.min != null && n < p.min) {
            errors.push({
              message: `${step.name}: ${p.name} must be ≥ ${p.min}`,
              start: step.start,
              end: step.end,
              stepIndex: i,
            });
          }
          if (p.max != null && n > p.max) {
            errors.push({
              message: `${step.name}: ${p.name} must be ≤ ${p.max}`,
              start: step.start,
              end: step.end,
              stepIndex: i,
            });
          }
        }
      }
    }

    if (step.name === "slip39") {
      const t = Number(step.params.threshold);
      const n = Number(step.params.shares);
      if (t > n) {
        errors.push({
          message: `slip39: threshold (${t}) cannot exceed shares (${n})`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      sharesCount = n;
    }

    if (step.name === "recombine") {
      if (sawInputShares) {
        errors.push({
          message: "Only one recombine step is supported per pipeline",
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      sawInputShares = true;
      if (spec.unresolvedInputs === "shares" || String(step.params.kind || "shares") === "shares") {
        if (!inputNeeds.includes("shares")) inputNeeds.push("shares");
      }
    }

    if (step.name === "input") {
      if (sawInputText) {
        errors.push({
          message: "Only one input step is supported per pipeline",
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      sawInputText = true;
      if (!inputNeeds.includes("text")) inputNeeds.push("text");
    }

    if (step.name === "decrypt") {
      if (sawDecryptGpg) {
        errors.push({
          message: "Only one decrypt step is supported per recipe",
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      sawDecryptGpg = true;
      if (!inputNeeds.includes("gpg")) inputNeeds.push("gpg");
      // Share rows for mnemonics already decrypted outside the browser
      // (Kleopatra/gpg/YubiKey — OpenPGP cards are not reachable from JS).
      if (!inputNeeds.includes("shares")) inputNeeds.push("shares");
    }

    if (step.name === "foreach") {
      if (foreachDepth > 0) {
        errors.push({
          message: "Nested foreach is not supported in v1",
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      if (current !== "shares") {
        errors.push({
          message: `foreach requires a collection (shares) — got ${current}. Add slip39 or recombine before foreach.`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      foreachDepth++;
      current = "text";
      continue;
    }

    if (step.name === "merge") {
      if (foreachDepth === 0) {
        errors.push({
          message: "merge without an open foreach",
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      } else {
        foreachDepth--;
      }
      current = "bundle";
      continue;
    }

    // tee: side-channel inspect, value type unchanged
    if (step.name === "tee") {
      if (current === "none") {
        errors.push({
          message: `"tee" needs a pipeline value — start with genkey, random, input, or decrypt.`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      continue;
    }

    // out: named output tile; value type unchanged so it can pipe to encrypt/gpg/…
    if (step.name === "out") {
      if (current === "none") {
        errors.push({
          message: `"out" needs a pipeline value to emit.`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      }
      continue;
    }

    // inspect / print / hexdump: any value → text dump
    if (step.name === "inspect") {
      if (current === "none") {
        errors.push({
          message: `"inspect" needs a pipeline value to dump.`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      } else {
        current = "text";
      }
      continue;
    }

    // Type flow
    if (spec.kind === "source") {
      if (i > 0 && current !== "none" && foreachDepth === 0) {
        warnings.push(
          `Source step "${step.name}" at position ${i + 1} discards prior pipeline value`
        );
      }
      current = io.output;
    } else {
      // Collection into non-foreach / non-combine / non-inspect
      if (
        current === "shares" &&
        step.name !== "foreach" &&
        step.name !== "combine" &&
        step.name !== "tee" &&
        step.name !== "inspect" &&
        step.name !== "out"
      ) {
        errors.push({
          message: `Cannot pipe shares into "${step.name}" — add foreach to unpack, or combine to recover.`,
          start: step.start,
          end: step.end,
          stepIndex: i,
        });
      } else if (
        !ioCompatible(current, io.input, step.name) &&
        !(foreachDepth > 0 && io.input === "text" && current === "text")
      ) {
        if (
          step.name === "slip39" &&
          (current === "text" || current === "bytes")
        ) {
          current = io.output;
        } else if (current === "keypair" && io.input === "bytes") {
          errors.push({
            message: `"${step.name}" expects DER bytes — add export pkcs8 (or spki) first.`,
            start: step.start,
            end: step.end,
            stepIndex: i,
          });
        } else if (current === "bytes" && io.input === "text") {
          errors.push({
            message: `"${step.name}" expects text — encode with pem, base64, base64url, hex, or utf8 first.`,
            start: step.start,
            end: step.end,
            stepIndex: i,
          });
        } else if (current === "text" && io.input === "bytes") {
          errors.push({
            message: `"${step.name}" expects bytes — decode with pem -d, base64 -d, or hex -d first.`,
            start: step.start,
            end: step.end,
            stepIndex: i,
          });
        } else if (current === "none") {
          errors.push({
            message: `"${step.name}" needs an input — start with genkey, random, passphrase, input, or decrypt.`,
            start: step.start,
            end: step.end,
            stepIndex: i,
          });
        } else {
          errors.push({
            message: `Type mismatch: "${step.name}" expects ${io.input}, got ${current}.`,
            start: step.start,
            end: step.end,
            stepIndex: i,
          });
        }
      } else {
        // utf8 is bidirectional: text in → bytes out (encode), bytes in → text out.
        current =
          step.name === "utf8" && current === "text" ? "bytes" : io.output;
        if (foreachDepth > 0 && spec.kind === "sink") {
          current = "text";
        }
      }
    }

    if (step.name === "encrypt") {
      if (foreachDepth > 0) {
        foreachGpg = true;
        gpgSlots = Math.max(gpgSlots, sharesCount || 1);
      } else {
        gpgSlots = Math.max(gpgSlots, 1);
      }
    }
  }

  if (foreachDepth > 0) {
    warnings.push("foreach scope closed implicitly at end of pipeline");
  }

  const first = getStep(steps[0].name);
  if (first && first.kind !== "source" && first.kind !== "flow") {
    errors.push({
      message: `Pipeline should start with a source (genkey, random, passphrase, input, decrypt), not "${steps[0].name}".`,
      start: steps[0].start,
      end: steps[0].end,
      stepIndex: 0,
    });
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    recipientSlots: gpgSlots,
    foreachGpg,
    inputNeeds,
  };
}

/**
 * Parse + validate convenience.
 * @param {string} source
 * @returns {{ ast: RecipeAst|null, validation: ValidationResult }}
 */
export function compileRecipe(source) {
  const { ast, errors } = parseRecipe(source);
  if (!ast || errors.length) {
    return {
      ast: null,
      validation: { ok: false, errors, warnings: [], inputNeeds: [] },
    };
  }
  return { ast, validation: validateRecipe(ast) };
}

/**
 * Detect unresolved GPG recipient requirements without running.
 * @param {RecipeAst} ast
 * @returns {{ slots: number, foreach: boolean }}
 */
export function unresolvedRecipients(ast) {
  const v = validateRecipe(ast);
  return { slots: v.recipientSlots || 0, foreach: !!v.foreachGpg };
}

/**
 * Detect runtime input panels required.
 * @param {RecipeAst} ast
 * @returns {("shares"|"gpg")[]}
 */
export function unresolvedInputs(ast) {
  return validateRecipe(ast).inputNeeds || [];
}

/**
 * Registry completeness check for tests.
 * @returns {string[]}
 */
export function registryIssues() {
  /** @type {string[]} */
  const issues = [];
  for (const s of listSteps()) {
    if (!s.name) issues.push("step missing name");
    if (!s.kind) issues.push(`${s.name}: missing kind`);
    if (!s.doc) issues.push(`${s.name}: missing doc`);
    if (!s.input) issues.push(`${s.name}: missing input`);
    if (!s.output) issues.push(`${s.name}: missing output`);
    for (const p of s.params || []) {
      if (!p.name) issues.push(`${s.name}: param missing name`);
      if (!p.type) issues.push(`${s.name}.${p.name}: missing type`);
    }
  }
  return issues;
}

/**
 * Preset recipes for the gallery.
 *
 * `group` clusters presets under a heading. Presets sharing a `pair` value are
 * companion pipelines (forward ⇄ inverse, e.g. split/recover or encrypt/decrypt)
 * and render side by side; the one listed first appears on the left.
 */
export const PRESETS = [
  {
    id: "p256-pem",
    group: "Generate keys",
    title: "P-256 private key (PEM)",
    blurb: "secp256r1 PKCS#8 PEM — drop-in for TLS / JWT / WebCrypto import.",
    recipe: "genkey ec/p256 | export pkcs8 | pem",
  },
  {
    id: "p256-tee-inspect",
    group: "Generate keys",
    title: "P-256 with mid-pipeline tee",
    blurb: "Generate a key, tee an openssl-style dump, then export PEM (keypair still flows through).",
    recipe: "genkey ec/p256 | tee name=keypair | export pkcs8 | pem",
  },
  {
    id: "ed25519-jwk",
    group: "Generate keys",
    title: "Ed25519 key (JWK)",
    blurb: "Signing key as JSON Web Key.",
    recipe: "genkey ed25519 | export jwk",
  },
  {
    id: "secret-b64url",
    group: "Secrets & passphrases",
    title: "256-bit secret (base64url)",
    blurb: "Websafe random secret — no +/ or padding.",
    recipe: "random 32 | base64url",
  },
  {
    id: "diceware",
    group: "Secrets & passphrases",
    title: "Diceware passphrase",
    blurb: "EFF Large Wordlist, 6 words (~77 bits).",
    recipe: "passphrase 6",
  },
  {
    id: "slip39-split",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "SLIP-39 split a secret",
    blurb: "Generate 32 random bytes and split 2-of-3 mnemonic shares.",
    recipe: "random 32 | slip39 threshold=2 shares=3 | foreach | out name=share",
  },
  {
    id: "recover-shares",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "Recover secret from SLIP-39 shares",
    blurb: "Paste K-of-N mnemonics (+ envelope if prompted) and reconstruct the secret as Base64.",
    recipe: "recombine | combine | base64",
  },
  {
    id: "out-mid-pipeline",
    group: "Split & recover",
    pair: "slip39-pem",
    title: "Split P-256 key into shares",
    blurb: "Save a PEM tile (copy/download), then keep piping into SLIP-39 — same pattern as out | encrypt gpg.",
    recipe:
      "genkey ec/p256 | export pkcs8 | pem | out name=private-key ext=pem label=PKCS8 | slip39 threshold=2 shares=3 | foreach | out name=share",
  },
  {
    id: "rebuild-p256",
    group: "Split & recover",
    pair: "slip39-pem",
    title: "Rebuild P-256 key from shares",
    blurb: "Combine SLIP-39 shares of a PEM private key and re-import as WebCrypto P-256.",
    recipe:
      "recombine | combine | utf8 | pem -d | import pkcs8 alg=ec/p256 | export pkcs8 | pem",
  },
  {
    id: "quorum-gpg",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Key + quorum-share to GPG",
    blurb: "P-256 key → SLIP-39 2-of-3 → encrypt each share to a different recipient (chosen at run time).",
    recipe: "genkey ec/p256 | export pkcs8 | pem | slip39 threshold=2 shares=3 | foreach | encrypt gpg",
  },
  {
    id: "decrypt-rebuild-p256",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Decrypt GPG shares → rebuild key",
    blurb:
      "Decrypt OpenPGP-wrapped shares in-browser and/or paste mnemonics already decrypted externally (e.g. Kleopatra/gpg + YubiKey), then combine and rebuild the P-256 PEM.",
    recipe:
      "decrypt gpg | combine | utf8 | pem -d | import pkcs8 alg=ec/p256 | export pkcs8 | pem",
  },
];
