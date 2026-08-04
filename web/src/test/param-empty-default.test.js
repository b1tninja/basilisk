/**
 * A default that changes behaviour is visible where the choice is made.
 *
 * `rtc.ice stun=` is the case that made this a rule. Blank meant *contact
 * Cloudflare and Google* — a STUN binding request that hands a third party
 * this machine's public address — and the only place it was written down was
 * a doc string, reachable as a `title` tooltip. The field itself was an empty
 * box, which is what a field that does nothing when empty also looks like. A
 * user could not see the default, so they could not knowingly accept it, and
 * (until `stun=none`) could not decline it either.
 *
 * The general form is `ParamSpec.emptyMeans`: the effective default, written
 * once in the registry and rendered where the choosing happens. It is not a
 * synonym for `doc`. `doc` says what the parameter is *for*; `emptyMeans` says
 * what happens if you walk past it.
 *
 * Two gates, and the second is the one that matters in a year:
 *
 *  1. Everything declared is drawn. Five fields this session were declared and
 *     rendered by nothing, which is worse than absent — it reads as done.
 *  2. Everything that *needs* declaring is declared. A param whose doc explains
 *     what empty does has, by its own admission, a consequential empty default;
 *     burying that in prose is how `stun=` got where it was.
 *
 * Source-level for the widgets, because the failure is presentational and the
 * suite runs in node. Line endings are normalised — CI is LF, Windows CRLF.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { STEPS } from "../lib/toolkit/registry.js";

const source = (rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8").replace(/\r\n/g, "\n");

/** Comments are not code — both files explain the old behaviour in prose. */
const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

const FIELD = source("../toolkit/widgets/ParamField.tsx");
const CARD = source("../toolkit/widgets/ToolCard.tsx");
const CSS = source("../css/toolkit.css");

/** Every `[step, param]` pair in the registry. */
const PARAMS = STEPS.flatMap((s) => (s.params || []).map((p) => [s.name, p]));

describe("the effective default is declared", () => {
  it("is declared wherever a doc string admits the empty case matters", () => {
    // The gate that generalises this beyond ICE. `empty = zero-length salt`,
    // `empty = Run binder`, `Empty = This site only` — each is a behaviour
    // change described in a place the person choosing does not look.
    const buried = PARAMS.filter(
      ([, p]) => p.default === "" && !p.emptyMeans && /\bempty\b/i.test(String(p.doc || ""))
    ).map(([step, p]) => `${step} ${p.name}=`);
    expect(
      buried,
      `${buried.join(", ")} explains what empty does in prose. Declare it as ` +
        `emptyMeans so the field, the hint and the tool card can show it, and ` +
        `leave doc to say what the parameter is for.`
    ).toEqual([]);
  });

  it("is declared only where empty is actually the default", () => {
    // A phrase about the empty case on a param that defaults to something
    // else would never render, and would read as true in the registry.
    for (const [step, p] of PARAMS) {
      if (!p.emptyMeans) continue;
      expect(p.default, `${step} ${p.name}= declares emptyMeans`).toBe("");
    }
  });

  it("says what happens, not what the parameter is", () => {
    for (const [step, p] of PARAMS) {
      if (!p.emptyMeans) continue;
      const where = `${step} ${p.name}=`;
      // Short enough to sit in a placeholder without being truncated to
      // nonsense; the long version is what `doc` is for.
      expect(p.emptyMeans.length, `${where} phrase is too long for a field`).toBeLessThan(70);
      // Not a restatement of the doc — two spellings of one fact are a defect
      // already, and the two are rendered inches apart.
      expect(String(p.doc || "").toLowerCase(), `${where} repeats itself`).not.toContain(
        p.emptyMeans.toLowerCase()
      );
      // The word "empty" belongs to the label the view draws around it.
      expect(p.emptyMeans, `${where} restates its own condition`).not.toMatch(/^empty\b/i);
    }
  });

  it("says the ICE default out loud, and how to refuse it", () => {
    // The instruction this came from: make the defaults obvious, and keep
    // "no third party" available to someone who really wants it.
    const stun = PARAMS.find(([s, p]) => s === "rtc.ice" && p.name === "stun")[1];
    expect(stun.emptyMeans).toMatch(/cloudflare/i);
    expect(stun.emptyMeans).toMatch(/google/i);
    expect(`${stun.emptyMeans} ${stun.doc}`).toMatch(/\bnone\b/);
  });
});

describe("the effective default is drawn", () => {
  it("fills the empty field's ghost text with it", () => {
    expect(strip(FIELD)).toMatch(/placeholder=\{param\.emptyMeans/);
  });

  it("keeps a hint under the field, where a placeholder would be truncated", () => {
    const code = strip(FIELD);
    expect(code).toMatch(/function EmptyMeans/);
    expect(code).toMatch(/param-empty-means/);
  });

  it("shows it exactly while it is in effect", () => {
    // Not after the field has a value: the default no longer applies then, and
    // a line describing something that is not happening is worse than none.
    expect(strip(FIELD)).toMatch(/String\(value \?\? ""\)\.trim\(\) !== ""/);
  });

  it("reaches the secret fields too, where unbound is the empty case", () => {
    // `ssh.encode passphrase=` left unbound writes the private block in the
    // clear. That is the same invisible default as `stun=`, on a control that
    // renders no text input at all.
    const secretBranch = strip(FIELD).slice(0, strip(FIELD).indexOf("if (control)"));
    expect(secretBranch).toMatch(/<EmptyMeans/);
  });

  it("replaces the tool card's `default ` with nothing after it", () => {
    const code = strip(CARD);
    expect(code).toMatch(/p\.default === "" && p\.emptyMeans/);
    // The old branch printed `default ` for an empty string. It must not be
    // reachable for one any more, declared or not.
    expect(code).toMatch(/p\.default !== "" *\)/);
  });

  it("styles the placeholder rather than leaving it to the browser", () => {
    // A measured contrast claim needs a colour we set. Firefox also dims
    // placeholders by default, which would have faded the sentence.
    const rule = CSS.slice(CSS.indexOf(".param-field input::placeholder"));
    expect(rule).toMatch(/color: var\(--text-muted\)/);
    expect(rule).toMatch(/opacity: 1/);
  });

  it("sets the hint apart by shape, never by fading it", () => {
    // `opacity: 0.8` on the marker measured 4.35:1 dark and 3.85:1 on the
    // light raised surface, under the 4.5:1 floor small text sets — the same
    // mistake as the candidate badges' `opacity-45`.
    const rule = CSS.slice(CSS.indexOf(".param-empty-means-key"));
    expect(rule.slice(0, rule.indexOf("}"))).not.toMatch(/opacity/);
  });
});
