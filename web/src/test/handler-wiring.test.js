/**
 * Every `on*` a toolkit component declares is passed by its callers, or is on
 * this list with a reason.
 *
 * `ShareSheet` declared an optional `onExportProof`, destructured it, and hung
 * it on a `<Button>`. No caller passed it, so the button rendered enabled and
 * clicking it did nothing. That was the **second** instance of exactly this:
 * `session-flow.test.js` records the first — `onStartSession`, same component,
 * same shape — and it asserts against that one prop *by name*. Which is why the
 * second one went unnoticed for as long as it did. A test that names the bug it
 * was written for catches that bug and no other.
 *
 * So this names none of them. It asks the general question — *does anybody hand
 * this component the handler it declares* — of every component under
 * `src/toolkit`, and the answer is a list that may only shrink. A new unwired
 * handler fails here rather than quietly joining a crowd, which is the shape
 * `glyph-shadowing.test.js` and `fips-engine-entrypoints.test.js` established.
 *
 * ## What counts as a caller
 *
 * `src/toolkit/**` — the shell and the widgets it renders, including widgets
 * rendered only by other widgets, since the shell renders those too, one layer
 * down. **`src/pages/toolkit-widgets.tsx` is deliberately not a caller**: it is
 * the widget catalogue, it mounts components with sample data to be looked at,
 * and it hands `() => {}` where it hands anything at all. Counting it would let
 * the catalogue answer a question only the product can answer, and every
 * handler in the toolkit would read as wired.
 *
 * ## Source-scanning, and comments stripped before the scan
 *
 * The question is *does this call site pass the prop*, which is a fact about the
 * code rather than about a run — a behavioural test would only prove the paths
 * it happened to drive, and the defect is precisely a path nothing drives.
 *
 * `codeOf` runs first, for `fips-engine-entrypoints.test.js`'s reason stated one
 * layer over: a JSX comment inside an opening tag sits *inside the attribute
 * list*, in the exact position an attribute would occupy, so prose naming a
 * handler satisfies a naive scan of that tag. A sweep a comment can satisfy is
 * a sweep documentation can silence. Unlike that file, this one has no honest
 * gap to declare — `ToolkitShell.tsx` carries paragraphs of prose between its
 * attributes, and the last check below proves the stripping matters.
 *
 * ## What this cannot see, said plainly
 *
 * It cannot tell a handler that is passed from a handler that *works*. A caller
 * that passes `onFoo={() => {}}` is wired as far as this file is concerned, and
 * that is a real hole — but it is a different hole from the one that shipped
 * twice, which was a prop no expression anywhere mentioned.
 *
 * It also cannot see a handler declared under a name that does not begin `on`.
 * `OpsShelf`'s inner rows take an `action` callback; it is out of scope here and
 * says so rather than being silently in the 62.
 */
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../", import.meta.url));

/**
 * Handlers no caller passes, each with the callers that omit it.
 *
 * **May only shrink.** Every entry is a claim that the control still works —
 * because the component renders it only when the handler arrives, or because it
 * falls back to a default that does the job. The claim has to survive being
 * read, and the assertion is a deep equality rather than a "contains", so a new
 * caller that starts omitting an already-listed prop fails too.
 */
const OPTIONAL = {
  // The panel was designed ahead of the op layer, which is why it draws a
  // session somebody hand-cranks. What shipped instead is `dkg.run` — one op
  // that deals every round and finalizes itself — so the shell mounts the panel
  // as a progress view and all three buttons are `onX ? … : null`. The start
  // button is the cell's own Run. DkgPanel's own header carries the argument,
  // including what must never be added (an "Exclude them" button).
  "DkgPanel.onStart": ["toolkit/ToolkitShell.tsx"],
  "DkgPanel.onFinalize": ["toolkit/ToolkitShell.tsx"],
  "DkgPanel.onRestart": ["toolkit/ToolkitShell.tsx"],

  // Opt-in on purpose. `GateBanner` was extracted *from* `ApprovalBanner`, and
  // the extraction's contract was that the approval banner's behaviour does not
  // change — a keystroke that used to do nothing must not start denying a
  // signing request as a side effect of a refactor. `ConsequenceBanner` opts
  // in; the signing gate declines to.
  "GateBanner.onEscape": ["toolkit/widgets/ApprovalBanner.tsx"],

  // The armed-branch caret. It is already the pending insert position and the
  // branch it would insert into does not exist yet, so a click has nowhere to
  // move the caret to; the gap takes a *drop*, which carries the step name that
  // creates the branch (`onAddBranchStep`). The other four gaps spread
  // `bindGap`/`stemGap`, which pass all four handlers.
  //
  // This entry was once a judgement and is now a fact. `InsertGap` used to
  // render a `<button>` either way, so the omission left a focusable,
  // button-announced marker that answered Enter with nothing; the component now
  // keys the element on the handler, and a `pending` gap with no `onClick` is a
  // named, unfocusable `<span>` (`gap-marker.test.js` holds both halves of that
  // split). So the absence here is the input to that rule rather than a gap in
  // the wiring — which is also why this entry must not be "fixed" by inventing
  // an `onClick`: a click has nowhere to move a caret that is already where it
  // is, and doing so would silently turn the marker back into a control.
  "InsertGap.onClick": ["toolkit/widgets/RecipeChipFlow.tsx"],

  // An override with a working default, not a wire. Absent, the Types tab's
  // literal constructor appends through `onAppend(step.name, { params })` — the
  // same route a format or cipher pick takes — so a literal lands at the caret
  // with ordinary insert semantics.
  "OpsShelf.onInsertLiteral": ["toolkit/ToolkitShell.tsx"],

  // Falls back to `window.print()`, which is what printing share cards means:
  // the layout is CSS-only with its own `@media print` block. The prop exists
  // for a host that needs to print something other than the page.
  "ShareCards.onPrint": ["toolkit/widgets/CeremonySheet.tsx"],

  // `clickable` is `!!onClick`, so a chip with no handler is a label. The one
  // that omits it is the armed-branch selector, which is a name plus a cancel
  // ×; there is nothing for a click on it to select.
  "SuggestChip.onClick": ["toolkit/widgets/RecipeChipFlow.tsx"],
  // Only the placed-step chip sets `draggable`; selector and ghost chips do
  // not, so no drag ever starts on the sites that omit these.
  "SuggestChip.onDragStart": ["toolkit/widgets/RecipeChipFlow.tsx"],
  "SuggestChip.onDragEnd": ["toolkit/widgets/RecipeChipFlow.tsx"],
  // The trailing × renders only when this arrives. The chips that omit it —
  // the loop-body label, "+ branch", "peek instead" — are things to press, not
  // things that exist to be removed.
  "SuggestChip.onRemove": ["toolkit/widgets/RecipeChipFlow.tsx"],

  // Both sites are hover tooltips, and the card's close button is
  // `onClose ? … : null`. A tooltip is dismissed by moving the pointer; a
  // close button inside one would be a second, worse way to do that.
  "ToolCard.onClose": ["toolkit/widgets/OpsTile.tsx", "toolkit/widgets/RecipeChipFlow.tsx"],
};

/**
 * The file with its comments removed, strings left alone.
 *
 * A regex pair would do most of this, but not the `//` inside a `"https://…"`,
 * and these files carry URLs. Scanning character by character costs nothing at
 * this size and removes the class of mistake entirely. Block comments keep
 * their newlines so reported line numbers are the ones in the editor.
 */
export function codeOf(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n) {
        if (text[i] === "\\") {
          out += text[i] + (text[i + 1] || "");
          i += 2;
          continue;
        }
        out += text[i];
        i++;
        if (text[i - 1] === quote) break;
      }
      continue;
    }
    if (c === "/" && text[i + 1] === "/") {
      while (i < n && text[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      const from = i;
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i = Math.min(i + 2, n);
      out += " " + text.slice(from, i).replace(/[^\n]/g, "");
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** Every `.tsx` under `src/toolkit`, comments stripped. */
function toolkitSources(dir = "toolkit", out = new Map()) {
  for (const entry of readdirSync(SRC + dir, { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) toolkitSources(rel, out);
    else if (entry.name.endsWith(".tsx")) out.set(rel, codeOf(readFileSync(SRC + rel, "utf8")));
  }
  return out;
}

const SOURCES = toolkitSources();

/** The balanced `{…}` starting at or after `from`. */
function braced(text, from) {
  const start = text.indexOf("{", from);
  if (start < 0) return null;
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return text.slice(start + 1, i);
  }
  return null;
}

/** Top-level `name:` / `name?:` keys of a type body. */
function topKeys(body) {
  const keys = [];
  let depth = 0;
  let line = "";
  const take = () => {
    // `<` and `>` are left out of the depth count on purpose: `() => void` would
    // otherwise close a level it never opened. A generic's comma can then split
    // a member early, which costs nothing — the half that carries the name is
    // the half that matches.
    const m = /^\s*(\w+)(\??)\s*:/.exec(line);
    if (m) keys.push({ name: m[1], optional: m[2] === "?" });
    line = "";
  };
  for (const c of body) {
    if (c === "{" || c === "(" || c === "[") depth++;
    if (c === "}" || c === ")" || c === "]") depth--;
    if (depth === 0 && (c === ";" || c === "," || c === "\n")) take();
    else line += c;
  }
  take();
  return keys;
}

/**
 * Every component under `src/toolkit` that declares at least one `on*` prop.
 *
 * Components here are all `function Name(…)` declarations annotated with either
 * a named type in the same file or an inline object type; there are no arrow
 * components and no `forwardRef` in this tree, and the count assertion below is
 * what notices if that changes.
 *
 * @returns {Map<string, {file: string, handlers: {name: string, optional: boolean}[]}>}
 */
function componentsWithHandlers() {
  const found = new Map();
  for (const [rel, code] of SOURCES) {
    const fnRe = /(?:^|\n)(?:export\s+)?function\s+([A-Z]\w*)\s*\(/g;
    let m;
    while ((m = fnRe.exec(code))) {
      const open = code.indexOf("(", m.index + m[0].length - 1);
      let depth = 0;
      let close = -1;
      for (let i = open; i < code.length; i++) {
        if (code[i] === "(") depth++;
        else if (code[i] === ")" && --depth === 0) {
          close = i;
          break;
        }
      }
      if (close < 0) continue;
      const params = code.slice(open + 1, close);
      let d = 0;
      let colon = -1;
      for (let i = 0; i < params.length; i++) {
        const c = params[i];
        if (c === "{" || c === "(" || c === "[") d++;
        else if (c === "}" || c === ")" || c === "]") d--;
        else if (c === ":" && d === 0) colon = i;
      }
      if (colon < 0) continue;
      let ann = params.slice(colon + 1);
      // A trailing default (`= {}`) is not part of the annotation. `=>` is.
      let dd = 0;
      for (let i = 0; i < ann.length; i++) {
        const c = ann[i];
        if (c === "{" || c === "(" || c === "[") dd++;
        else if (c === "}" || c === ")" || c === "]") dd--;
        else if (c === "=" && dd === 0 && ann[i + 1] !== ">" && !"=!<>".includes(ann[i - 1])) {
          ann = ann.slice(0, i);
          break;
        }
      }
      ann = ann.trim();
      let props = null;
      if (ann.startsWith("{")) {
        props = topKeys(braced(ann, 0) ?? "");
      } else {
        const name = ann.replace(/<[\s\S]*$/, "").trim();
        const decl = new RegExp(`(?:^|\\n)(?:export\\s+)?type\\s+${name}\\s*=`).exec(code);
        if (decl) props = topKeys(braced(code, decl.index + decl[0].length) ?? "");
      }
      if (!props) continue;
      const handlers = props.filter((p) => /^on[A-Z]/.test(p.name));
      if (handlers.length) found.set(m[1], { file: rel, handlers });
    }
  }
  return found;
}

const COMPONENTS = componentsWithHandlers();

/** Which top-level component encloses this offset — who would forward a prop. */
function enclosing(code, at) {
  let name = "";
  const re = /(?:^|\n)(?:export\s+)?function\s+([A-Z]\w*)\s*\(/g;
  let m;
  while ((m = re.exec(code)) && m.index < at) name = m[1];
  return name;
}

/** Every `onX` written as an attribute or an object key in a chunk of code. */
function handlerNamesIn(text) {
  const names = new Set();
  const re = /(?:^|[\s{,(])(on[A-Z]\w*)\s*[=:]/g;
  let m;
  while ((m = re.exec(text))) names.add(m[1]);
  return names;
}

/** The body of a local `const <name> = …` in this file, or null. */
function localBinding(code, name) {
  const m = new RegExp(`(?:^|\\n)\\s*const\\s+${name}\\s*=`).exec(code);
  return m ? braced(code, m.index + m[0].length) : null;
}

/** Spreads the scan could not follow. Empty, or the sweep is not measuring. */
const unfollowed = [];

/** Every place a component is rendered, with the opening tag's own text. */
function renderSites(name) {
  const out = [];
  for (const [rel, code] of SOURCES) {
    const re = new RegExp(`<${name}(?=[\\s/>])`, "g");
    let m;
    while ((m = re.exec(code))) {
      let depth = 0;
      let attrs = "";
      const spreads = [];
      for (let i = m.index + m[0].length; i < code.length; i++) {
        const c = code[i];
        if (c === "{") {
          if (depth === 0 && /^\{\s*\.\.\./.test(code.slice(i, i + 8))) {
            spreads.push((braced(code, i) ?? "").replace(/^\s*\.\.\./, "").trim());
          }
          depth++;
        } else if (c === "}") depth--;
        else if (c === '"' || c === "'" || c === "`") {
          const quote = c;
          i++;
          while (i < code.length && code[i] !== quote) i += code[i] === "\\" ? 2 : 1;
          continue;
        } else if (c === ">" && depth === 0) break;
        attrs += c;
      }
      out.push({
        file: rel,
        line: code.slice(0, m.index).split("\n").length,
        attrs,
        spreads,
        host: enclosing(code, m.index),
      });
    }
  }
  return out;
}

const SITES = new Map();
function sitesOf(name) {
  if (!SITES.has(name)) SITES.set(name, renderSites(name));
  return SITES.get(name);
}

/**
 * What a site actually hands the component, following JSX spreads.
 *
 * A spread is where a naive scan goes quiet and stays quiet, so it is followed
 * rather than skipped, in the two shapes this tree uses:
 *
 * - `{...bindGap(0)}` / `{...someObject}` — built here. Read the local binding.
 * - `{...live}` — a prop of the component doing the rendering, so the object was
 *   built by *its* caller. Follow it up to whoever renders the host. That is how
 *   `SessionSheet` hands `SessionStart` and `SessionLive` their whole prop
 *   objects, which `ToolkitShell` writes out in full.
 *
 * The second is deliberately loose: it accepts the handler being named anywhere
 * in the host's opening tag, not specifically inside the object being forwarded.
 * It can therefore call a handler wired when the shell wrote that name into a
 * *different* prop of the same tag. That is a false negative in the one
 * direction and never a false positive — this file's job is finding handlers
 * nothing anywhere mentions, and it does not need to be a type checker to do it.
 *
 * Anything neither shape matches goes on `unfollowed` and fails a test of its
 * own. Silence from a spread the scan could not read is worth nothing.
 */
function passedAt(site, seen = new Set()) {
  const passed = handlerNamesIn(site.attrs);
  for (const expr of site.spreads) {
    const code = SOURCES.get(site.file);
    const call = /^(\w+)\s*\(/.exec(expr);
    const ident = /^(\w+)$/.exec(expr);
    const local = call || ident ? localBinding(code, (call || ident)[1]) : null;
    if (local) {
      for (const h of handlerNamesIn(local)) passed.add(h);
      continue;
    }
    if (ident && site.host && !seen.has(site.host)) {
      seen.add(site.host);
      for (const up of sitesOf(site.host)) for (const h of passedAt(up, seen)) passed.add(h);
      continue;
    }
    unfollowed.push(`${site.file}:${site.line} {...${expr}}`);
  }
  return passed;
}

/** `Component.onProp` -> the callers that omit it, for every handler in the tree. */
function unwiredHandlers() {
  /** @type {Record<string, string[]>} */
  const out = {};
  for (const [name, info] of COMPONENTS) {
    const sites = sitesOf(name);
    if (!sites.length) continue;
    for (const handler of info.handlers) {
      const omitting = sites.filter((s) => !passedAt(s).has(handler.name));
      if (!omitting.length) continue;
      out[`${name}.${handler.name}`] = [...new Set(omitting.map((s) => s.file))].sort();
    }
  }
  return out;
}

describe("a control the shell renders has a handler behind it", () => {
  it("finds the components it is measuring", () => {
    // An empty sweep passes every assertion below it.
    expect(COMPONENTS.size, "no components with handlers found — the scan is broken").toBeGreaterThan(
      40
    );
    expect([...COMPONENTS.keys()], "the shell itself is gone from the sweep").toContain("ShareSheet");
    expect(
      sitesOf("ShareSheet").map((s) => s.file),
      "ShareSheet is no longer rendered where this file thinks it is"
    ).toEqual(["toolkit/ToolkitShell.tsx"]);
  });

  it("reads the two props this file exists for as wired", () => {
    // Named rather than swept, because the sweep below is also satisfied by
    // deleting the props — which would close the test and lose the controls.
    const passed = passedAt(sitesOf("ShareSheet")[0]);
    for (const name of ["onExportProof", "onStartSession"]) {
      expect(
        COMPONENTS.get("ShareSheet").handlers.map((h) => h.name),
        `ShareSheet no longer declares ${name}`
      ).toContain(name);
      expect(passed.has(name), `${name} is unwired again`).toBe(true);
    }
  });

  it("follows every spread it meets", () => {
    unwiredHandlers();
    expect(
      [...new Set(unfollowed)],
      `a spread hides these call sites from the scan, so its silence about them means nothing: ${[
        ...new Set(unfollowed),
      ].join(", ")}`
    ).toEqual([]);
  });

  it("passes every handler that is not written down as optional", () => {
    expect(
      unwiredHandlers(),
      "a handler no caller passes, and no reason recorded for it — wire it, or add it to OPTIONAL with the argument"
    ).toEqual(OPTIONAL);
  });

  it("keeps the exemption list honest — every entry is really optional", () => {
    // A *required* prop that nothing passes is not an exemption anybody can
    // argue; it is a type error the compiler should already be refusing, and if
    // it is not, the props type and the call site have stopped describing the
    // same component.
    const required = [];
    for (const key of Object.keys(OPTIONAL)) {
      const [component, prop] = key.split(".");
      const declared = COMPONENTS.get(component)?.handlers.find((h) => h.name === prop);
      expect(declared, `${key} is not declared any more, so its exemption is stale`).toBeTruthy();
      if (!declared.optional) required.push(key);
    }
    expect(
      required,
      `these are declared as required props and nothing passes them: ${required.join(", ")}`
    ).toEqual([]);
  });

  it("does not let a comment stand in for an attribute", () => {
    // A JSX comment inside an opening tag sits exactly where an attribute would.
    // Without the strip, prose describing a handler — and `ToolkitShell.tsx` has
    // paragraphs of it between its attributes — reads as the handler.
    const tag = ['<ShareSheet', '  {/* onExportProof={exportProof} */}', '/>'].join("\n");
    expect(handlerNamesIn(tag).has("onExportProof")).toBe(true);
    expect(handlerNamesIn(codeOf(tag)).has("onExportProof")).toBe(false);
    // And the strip leaves a real attribute, and a URL inside a string, alone.
    const real = '<A href="https://x/y" onExportProof={f} /> // onStartSession={g}';
    expect(codeOf(real)).toContain('href="https://x/y"');
    expect(handlerNamesIn(codeOf(real))).toEqual(new Set(["onExportProof"]));
  });
});
