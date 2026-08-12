/**
 * A control that can be refused cannot render without saying why.
 *
 * Four bug reports in one week were the same defect: a control that declined
 * and said nothing. "Nothing happens when I click Start shared session" was a
 * `disabled` attribute; a paste that matched nothing and an empty key chooser
 * were the same shape elsewhere. The count at the time was **37 disabled
 * controls in the toolkit and 4 sitting near any explanation at all** — so 33
 * could go dead in front of a reader with nothing to read.
 *
 * Fixing 33 call sites does not fix this; the 34th is written next week. So the
 * refusal and the reason became the same value — `disabledReason` on `Button`
 * and `DropdownMenuItem`, `useRefusal` for the controls that cannot be either —
 * and `disabled` is typed `never` on all of them. This file is the half the
 * compiler cannot do: raw `<button disabled>`, an `aria-disabled` with nothing
 * described, a reason that is technically a string.
 *
 * The sweep is a **ratchet with an empty baseline**, in the shape
 * `no-inline-styles.test.js` established — every entry would be a live defect,
 * so there are none, and the way to add one is to not need it.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *
 * **What this cannot check, said plainly rather than implied.**
 *
 * It cannot tell whether a reason names the state the reader is actually in.
 * `disabledReason="No private key in this browser."` on a button that is really
 * refusing because the audience has one member passes every assertion here and
 * is exactly the class of bug that caused five reports this week. A sweep can
 * see that a sentence exists, that it is a sentence, and that it reaches the
 * screen and the accessibility tree; the correspondence between the sentence
 * and the condition beside it is a matter of reading the diff. What the API
 * does buy is narrower and real: the reason is written in the same expression
 * that decides the refusal, so the two cannot drift apart afterwards, and a
 * condition with no sentence has no spelling.
 *
 * The contentless-word list below is the one thing it can do beyond "non-empty":
 * "Unavailable" restates `aria-disabled`, makes the audit pass, and leaves the
 * reader where they were.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CONTENTLESS_REASONS } from "../components/ui/refusal.tsx";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");
/** The primitives, which are the one place the DOM attributes may be written. */
const UI_ROOT = join(SRC_ROOT, "components", "ui");

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const rel = (path) => relative(WEB_ROOT, path).replace(/\\/g, "/");

/** Comments stripped — prose explaining an absence satisfies a naive grep. */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

function walk(dir, pred, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "node_modules" || name === "dist" || name === "test") continue;
      walk(path, pred, out);
    } else if (pred(path)) {
      out.push(path);
    }
  }
  return out;
}

/** Every product `.tsx` — the primitives excluded, since they define the rule. */
const PRODUCT = walk(SRC_ROOT, (p) => p.endsWith(".tsx") && !p.startsWith(UI_ROOT));
/** The primitives themselves, swept separately and by different rules. */
const PRIMITIVES = walk(UI_ROOT, (p) => p.endsWith(".tsx"));

/**
 * Every JSX opening tag in a source, as `{ tag, attrs, line }`.
 *
 * A regex over lines cannot do this: `disabled` and the `aria-describedby` that
 * has to accompany it are routinely twelve lines apart on the same element, and
 * an attribute value is an arbitrary expression containing `>`, quotes and
 * nested JSX. So this walks the text, tracking string and brace depth, and
 * stops at the `>` that actually closes the tag.
 */
function jsxTags(source) {
  const tags = [];
  const text = stripComments(source);
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "<") continue;
    const m = /^<([A-Za-z][\w.]*)/.exec(text.slice(i, i + 60));
    if (!m) continue;
    let j = i + m[0].length;
    let depth = 0;
    let quote = "";
    for (; j < text.length; j++) {
      const c = text[j];
      if (quote) {
        if (c === "\\") j++;
        else if (c === quote) quote = "";
        continue;
      }
      if (c === '"' || c === "'" || c === "`") quote = c;
      else if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (c === ">" && depth === 0) break;
    }
    tags.push({
      tag: m[1],
      attrs: text.slice(i + m[0].length, j),
      line: text.slice(0, i).split("\n").length,
    });
    i = j;
  }
  return tags;
}

/** `disabled=`, never `aria-disabled=` and never Tailwind's `disabled:`. */
const RAW_DISABLED = /(?<![\w-])disabled\s*=/;
const ARIA_DISABLED = /aria-disabled\s*=/;
const DESCRIBED_BY = /aria-describedby\s*=/;

describe("the primitives make an unexplained refusal unrepresentable", () => {
  const BUTTON = read("../components/ui/button.tsx");
  const MENU = read("../components/ui/dropdown-menu.tsx");
  const REFUSAL = read("../components/ui/refusal.tsx");
  const INPUT = read("../components/ui/input.tsx");
  const TEXTAREA = read("../components/ui/textarea.tsx");

  it("types `disabled` as never, so a boolean has no spelling", () => {
    // The whole mechanism in one line per primitive: there is no way to turn
    // one of these off that does not also produce the sentence. `Omit` alone
    // would let `disabled` through via the spread; `never` is what makes
    // writing it a compile error at the call site.
    for (const [name, src] of [
      ["button.tsx", BUTTON],
      ["dropdown-menu.tsx", MENU],
      ["input.tsx", INPUT],
      ["textarea.tsx", TEXTAREA],
    ]) {
      expect(stripComments(src), name).toMatch(/disabled\?:\s*never;/);
      expect(stripComments(src), name).toMatch(/Omit<[\s\S]{0,200}?"disabled">/);
    }
  });

  it("derives the refusal from the reason, so the two cannot drift apart", () => {
    // Not two independent props. "Off, with no reason" is the state the rule
    // forbids, so it is the state that has no representation.
    expect(stripComments(REFUSAL)).toMatch(/const refused = !!reason;/);
    expect(stripComments(BUTTON)).toMatch(/useRefusal\(disabledReason,/);
    expect(stripComments(MENU)).toMatch(/useRefusal\(disabledReason\)/);
  });

  it("keeps the refused control focusable, because the reason is the feature", () => {
    // `disabled` removes a button from the tab order, which puts
    // `aria-describedby` out of reach of exactly the people it was written
    // for. So the refusal is `aria-disabled` — and because that leaves the
    // button clickable, the guard has to stop the event rather than omit a
    // handler. An omitted handler is not a refusal: the click still bubbles.
    const code = stripComments(REFUSAL);
    expect(code).toMatch(/"aria-disabled": refused \|\| undefined/);
    expect(code).toMatch(/event\.preventDefault\(\)/);
    expect(code).toMatch(/event\.stopPropagation\(\)/);
    expect(code).not.toMatch(RAW_DISABLED);
  });

  it("puts the sentence on screen, not only in the accessibility tree", () => {
    // The reports came from someone looking straight at the control, so a
    // description nobody can see is half a fix. `REASON_CLASS` is ordinary
    // rendered text; `sr-only` here would be the regression.
    const code = stripComments(REFUSAL);
    expect(code).toMatch(/data-disabled-reason/);
    expect(code).not.toMatch(/sr-only/);
    expect(code).toMatch(/"aria-describedby": describedBy/);
    // …and the Button actually renders what the hook produced. A note the
    // component computes and drops is the dead-mechanism defect: a finished
    // feature with no consumer.
    expect(stripComments(BUTTON)).toMatch(/<RefusalLayout note=\{refusal\.note\}>/);
    expect(stripComments(MENU)).toMatch(/\{refusal\.note\}/);
  });

  it("treats in-flight as busy rather than refused", () => {
    // A disabled control loses its accessible name in some screen-reader
    // pairings at exactly the moment its user most wants it — and a control
    // that is running has not declined anything, so it owes no explanation.
    const code = stripComments(REFUSAL);
    expect(code).toMatch(/"aria-busy": busy \|\| undefined/);
    expect(code).toMatch(/const inert = refused \|\| busy;/);
    expect(code).not.toMatch(/aria-disabled.*busy/);
  });
});

describe("no control in the app can go dead with nothing to read", () => {
  /**
   * Sites still to convert, per file.
   *
   * Empty, and it should stay that way: every one of the 37 has been given a
   * reason, and an entry here would be a control a reader can press today and
   * learn nothing from. The two ways to satisfy the rule are the two ways a
   * reason can exist — the primitive's `disabledReason`, or `useRefusal` for a
   * control the primitives do not cover.
   */
  const BASELINE = {};

  /** `{file: [{line, tag, why}]}` for everything that refuses without saying so. */
  function offenders() {
    const byFile = new Map();
    for (const path of PRODUCT) {
      const hits = [];
      for (const t of jsxTags(readFileSync(path, "utf8"))) {
        const raw = RAW_DISABLED.test(t.attrs);
        const aria = ARIA_DISABLED.test(t.attrs);
        if (!raw && !aria) continue;
        if (DESCRIBED_BY.test(t.attrs)) continue;
        hits.push({
          line: t.line,
          tag: t.tag,
          why: raw
            ? "`disabled` with no aria-describedby"
            : "`aria-disabled` with no aria-describedby",
        });
      }
      if (hits.length) byFile.set(rel(path), hits);
    }
    return byFile;
  }

  const byFile = offenders();

  it("adds no refusal without a description in files that had none", () => {
    const added = [...byFile.keys()].filter((f) => !(f in BASELINE));
    expect(
      added,
      `A control refuses here without describing why:\n${added
        .map((f) => byFile.get(f).map((h) => `${f}:${h.line} <${h.tag}> — ${h.why}`).join("\n"))
        .join("\n")}\n` +
        `Use <Button disabledReason={…}> or useRefusal(reason) — both wire ` +
        `aria-describedby to a visible sentence. A control that declines and ` +
        `says nothing is the defect this file exists to stop.`
    ).toEqual([]);
  });

  it("keeps the baseline empty, which is the whole point of it", () => {
    // A ratchet with entries would be a list of controls we have agreed can
    // stay dead. There is no such list.
    expect(Object.keys(BASELINE)).toEqual([]);
  });

  /**
   * Controls turned off by assignment rather than by markup.
   *
   * `btn.disabled = true` is the same dead control with no type system in
   * front of it — `verify.tsx` did exactly this after marking a key trusted,
   * and it is fixed. What is left is the pre-React surface: four imperative
   * `*-mount.js` files that build their markup as strings, where the shared
   * control this change is built around does not exist.
   *
   * They are counted rather than converted because they are not one job with
   * the toolkit's 37, and because they are mostly a different thing: sixteen
   * of the nineteen are in-flight guards — `disabled = true`, label to
   * "Saving…", `disabled = false` when the promise settles — which this
   * mechanism answers with `aria-busy` and which owe no explanation. The three
   * in `quorum-mount.js` are the real ones: `leave`, `chat-input` and
   * `chat-send-btn` go dead together whenever no session is open, and the page
   * says so only in a status span they are not associated with.
   *
   * A number here may go down. It may not go up, and no file may join.
   */
  const IMPERATIVE_BASELINE = {
    "src/lib/key-mount.js": 2,
    "src/lib/keys.js": 2,
    "src/lib/my-keys-mount.js": 12,
    "src/lib/quorum-mount.js": 3,
  };

  function imperativeCounts() {
    const counts = {};
    for (const path of walk(SRC_ROOT, (p) => /\.(tsx|ts|js)$/.test(p))) {
      const code = stripComments(readFileSync(path, "utf8"));
      const n = (code.match(/\.disabled\s*=\s*(?:true|false|!)/g) || []).length;
      if (n) counts[rel(path)] = n;
    }
    return counts;
  }

  const imperative = imperativeCounts();

  it("adds no new imperative disable, and none at all in React code", () => {
    const added = Object.keys(imperative).filter((f) => !(f in IMPERATIVE_BASELINE));
    expect(
      added,
      `${added.join(", ")} turn a control off by assignment. Set aria-disabled ` +
        `and aria-describedby and leave it reachable — or, if the control is ` +
        `merely running, aria-busy.`
    ).toEqual([]);
    expect(added.filter((f) => f.endsWith(".tsx"))).toEqual([]);
  });

  it("does not grow the legacy count, and does not leave a stale entry", () => {
    const drift = [];
    for (const [file, max] of Object.entries(IMPERATIVE_BASELINE)) {
      const n = imperative[file] ?? 0;
      if (n > max) drift.push(`${file}: ${n} > ${max}`);
      if (n < max) drift.push(`${file}: now ${n}, baseline still ${max} — lower it`);
    }
    expect(drift, drift.join("\n")).toEqual([]);
  });
});

describe("the sentence a control describes itself with is one you can see", () => {
  /** Everything marked as a refusal's visible half, across the whole app. */
  function reasonTargets() {
    const found = [];
    for (const path of [...PRODUCT, ...PRIMITIVES]) {
      for (const t of jsxTags(readFileSync(path, "utf8"))) {
        if (/data-disabled-reason/.test(t.attrs)) {
          found.push({ file: rel(path), line: t.line, attrs: t.attrs, tag: t.tag });
        }
      }
    }
    return found;
  }

  const targets = reasonTargets();

  it("marks the elements that carry a refusal's words", () => {
    // The attribute is what makes the visibility rule below checkable at all,
    // so its absence everywhere would be a green suite over an unenforced rule.
    expect(targets.length).toBeGreaterThan(5);
  });

  it("never hides one", () => {
    const hidden = targets.filter(
      (t) => /\bsr-only\b/.test(t.attrs) || /(?<![\w-])hidden(?![\w-])/.test(t.attrs)
    );
    expect(
      hidden.map((t) => `${t.file}:${t.line} <${t.tag}>`),
      `A refusal's sentence is hidden. The reports this rule comes from were ` +
        `from someone looking straight at the control — a reason only a screen ` +
        `reader reaches is half a fix, and one behind a hover is none.`
    ).toEqual([]);
  });

  it("names ArtifactAction as the one refusal that is still only announced", () => {
    /**
     * The known gap, counted so it cannot spread.
     *
     * `ArtifactAction` puts its own reason in an `sr-only` span, and where
     * every action in a tile's row refuses for the same reason `ArtifactTile`
     * prints it once, visibly, as `.artifact-row-gate`. The mixed case — two
     * of five refused — still reaches sighted readers only through `title`.
     * It predates this mechanism and is a design question about a row of six
     * 22-pixel pills inside a list of tiles, not an oversight; what is not
     * negotiable is that it stays the only one.
     */
    const srOnlyReasons = [];
    for (const path of [...PRODUCT, ...PRIMITIVES]) {
      const src = stripComments(readFileSync(path, "utf8"));
      if (/className="sr-only"[\s\S]{0,80}\{reason\}/.test(src)) srOnlyReasons.push(rel(path));
    }
    expect(srOnlyReasons).toEqual(["src/toolkit/widgets/ArtifactAction.tsx"]);
  });
});

describe("a reason is a sentence, not a word that ends an audit", () => {
  /**
   * Every string literal that can reach a refusal, one hop deep.
   *
   * One hop because the honest sites hold their sentence in a module constant
   * — `NO_SESSION`, `NO_PROOF_YET` — precisely so the panel's copy of it and
   * the button's cannot drift, and a sweep that only read the attribute would
   * check the shortest reasons and skip the most-shared ones.
   */
  function reasonLiterals() {
    const out = [];
    for (const path of [...PRODUCT, ...PRIMITIVES]) {
      const src = stripComments(readFileSync(path, "utf8"));
      const exprs = [];
      // The opening delimiter is part of the match, so `balanced` starts at
      // depth 1 already — without it the scan runs off the end of the file and
      // sweeps in every class string between here and the closing brace.
      for (const pattern of [/disabledReason\s*=\s*\{/g, /useRefusal\s*\(/g]) {
        let m;
        while ((m = pattern.exec(src))) exprs.push(balanced(src, m.index + m[0].length));
      }
      // `disabledReason: "…"` in an object literal — a menu item's row.
      for (const m of src.matchAll(/disabledReason\s*[:=]\s*(?![{\s])(.*)/g)) exprs.push(m[1]);
      const seen = new Set();
      for (const expr of exprs) {
        for (const lit of literalsIn(expr)) out.push({ file: rel(path), text: lit });
        /**
         * …then one hop, but only for an identifier that could *be* the whole
         * reason. Identifiers are read after the literals are stripped out, so
         * a name interpolated into a sentence (`` `${step} ${needs} — …` ``)
         * is not followed: `needs` holds "needs bytes", a fragment that is
         * correct inside that sentence and would be a bad reason on its own.
         * What is followed is `live ? undefined : NO_SESSION`, where the
         * identifier is the sentence.
         */
        for (const id of stripLiterals(expr).match(/\b[A-Za-z_$][\w$]*\b/g) || []) {
          if (seen.has(id)) continue;
          seen.add(id);
          const body = constInitializer(src, id);
          if (body) for (const lit of literalsIn(body)) out.push({ file: rel(path), text: lit });
        }
      }
    }
    return out;
  }

  /** Every string and template literal blanked out, so identifiers can be read. */
  const stripLiterals = (text) =>
    text.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');

  /**
   * A same-file `const <id> = …;` initializer, when it is a plain expression.
   *
   * JSX and arrow bodies are skipped: a component or a callback bound to a
   * name that also appears in a reason expression would drag every class
   * string in its body into the sweep, and a class string is not a sentence.
   */
  function constInitializer(src, id) {
    const decl = new RegExp(`\\bconst ${id}(?::[^=\\n]*)?\\s=\\s`).exec(src);
    if (!decl) return null;
    const start = decl.index + decl[0].length;
    const end = src.indexOf(";", start);
    if (end < 0 || end - start > 1500) return null;
    const body = src.slice(start, end);
    if (/=>|<[A-Za-z]/.test(body)) return null;
    return body;
  }

  /** Text of a JSX expression / call argument, from just after its opener. */
  function balanced(src, start) {
    let depth = 1;
    let quote = "";
    for (let i = start; i < src.length; i++) {
      const c = src[i];
      if (quote) {
        if (c === "\\") i++;
        else if (c === quote) quote = "";
        continue;
      }
      if (c === '"' || c === "'" || c === "`") quote = c;
      else if (c === "{" || c === "(") depth++;
      else if (c === "}" || c === ")") {
        depth--;
        if (!depth) return src.slice(start, i);
      }
    }
    return src.slice(start, start + 600);
  }

  /**
   * String and template literals, with `${…}` collapsed to a word.
   *
   * Collapsed rather than dropped: half these sentences interpolate the thing
   * they are about ("`${step} needs bytes`"), and removing the hole would make
   * a real sentence look like a fragment to the length check below.
   */
  function literalsIn(text) {
    const out = [];
    for (const m of text.matchAll(/"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`/g)) {
      const raw = m[1] ?? m[2] ?? m[3] ?? "";
      const collapsed = raw.replace(/\$\{[^}]*\}/g, "it").trim();
      // Class names, ids and data attributes reach these expressions too.
      if (!collapsed || !/\s/.test(collapsed)) continue;
      if (/^[\w-]+(\s+[\w-]+)*$/.test(collapsed) && !/[.!?]$/.test(collapsed)) continue;
      out.push(collapsed);
    }
    return out;
  }

  const literals = reasonLiterals();

  it("finds the reasons at all, so a green run means something", () => {
    expect(literals.length).toBeGreaterThan(10);
  });

  it("writes each one as a sentence, with a remedy where there is one", () => {
    // Same bar as ACTION_REASONS, which earned it: length, and a full stop.
    // A fragment is a label; a sentence is what a reader can act on.
    const bad = literals.filter((l) => l.text.length <= 30 || !/[.!?]$/.test(l.text));
    expect(
      bad.map((l) => `${l.file}: ${JSON.stringify(l.text)}`),
      "A refusal must be a sentence naming the state the reader is in."
    ).toEqual([]);
  });

  it("refuses the words that make an audit pass and a reader no wiser", () => {
    const contentless = literals.filter((l) => {
      const bare = l.text.toLowerCase().replace(/[.!?…]+$/, "").trim();
      return CONTENTLESS_REASONS.includes(bare);
    });
    expect(
      contentless.map((l) => `${l.file}: ${JSON.stringify(l.text)}`),
      `"Unavailable" restates aria-disabled. A reason that says nothing is ` +
        `worse than none, because it retires the question while leaving the ` +
        `reader exactly where they were.`
    ).toEqual([]);
  });

  it("keeps the placeholder list where the component can see it", () => {
    // Exported from `refusal.tsx` rather than written here, so the rule and
    // the mechanism it governs live together — the `artifact-reasons.js`
    // argument, one layer up.
    expect(CONTENTLESS_REASONS).toContain("unavailable");
    expect(CONTENTLESS_REASONS).toContain("not available");
    expect(Object.isFrozen(CONTENTLESS_REASONS)).toBe(true);
  });
});

describe("borrowing a sentence still requires having written one", () => {
  it("never passes reasonId without disabledReason", () => {
    /**
     * `reasonId` says "the panel already prints this" — it is not a way to
     * skip the reason, and a control that passed only the id would have an
     * `aria-describedby` and no words behind it if the id ever went stale.
     * Whether a given id resolves to a real element is the thing this sweep
     * cannot see across a component boundary; that it is never the *only*
     * thing passed, it can.
     */
    const bad = [];
    for (const path of PRODUCT) {
      for (const t of jsxTags(readFileSync(path, "utf8"))) {
        if (!/(?<![\w-])reasonId\s*=/.test(t.attrs)) continue;
        if (/(?<![\w-])disabledReason\s*=/.test(t.attrs)) continue;
        bad.push(`${rel(path)}:${t.line} <${t.tag}>`);
      }
    }
    expect(bad, bad.join("\n")).toEqual([]);
  });
});
