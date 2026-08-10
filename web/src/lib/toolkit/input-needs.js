/**
 * What a recipe still needs from the person running it — *derived* from the
 * param and step declarations, never detected from step names.
 *
 * There used to be two independent answers to "what does this recipe need".
 * `stepNeedsKeyPanel(step)` was a hand-written `switch` over nine op names, and
 * the slot-binding errors were computed separately by comparing `out`
 * registrations against references. The two shared no source, so an op could
 * grow a key param and get no panel, and *nothing failed* — the recipe simply
 * could not be run and said nothing about why. `stream.seal` and `stream.open`
 * were exactly that: `key` declared `slot: "required"`, the engine falling back
 * to the key panel, and the `switch` never updated.
 *
 * `d532a4c` gave every param a real signature — `type` (the value kind),
 * `slot` (whether a `$ref` may supply it) and `slotOf` (what the ref must
 * resolve to). This module is the consumer that signature was missing:
 *
 * - a param declaring `unresolvedInput` and left unbound *is* an input need;
 * - the panel that need renders as is a view of `slotOf`, not a parallel
 *   vocabulary — a slot set that can hold an `openpgp-key` is the OpenPGP
 *   panel's business, anything else is the WebCrypto key panel's;
 * - a step declaring `unresolvedInputs` needs a panel for its *pipeline value*,
 *   which no param describes because it arrives through the pipe.
 *
 * The six-value union (`shares | gpg | text | envelope | key | keypair`, plus
 * `gpgPass`) survives at the UI boundary, because it names *panels* — one for
 * each tray the shell can open — and a panel is not a type. It is derived here
 * rather than pushed by whoever noticed first.
 */

import { getStep } from "./registry.js";

/**
 * Runtime input trays the shell can open. A panel is a place a value is typed,
 * pasted or unlocked — not a type. `key` and `gpg` are two panels over the same
 * question ("which key?") because they open different drawers.
 * @typedef {"text"|"shares"|"keypair"|"envelope"|"gpg"|"gpgPass"|"key"} InputPanel
 */

/** @type {readonly InputPanel[]} */
export const INPUT_PANELS = Object.freeze([
  "text",
  "shares",
  "keypair",
  "envelope",
  "gpg",
  "gpgPass",
  "key",
]);

/**
 * The panel that renders a declared slot type.
 *
 * This is the "rendering, not vocabulary" rule: `slotOf` is the compile-time
 * contract for what a ref must resolve to, and the panel is a view of it. An
 * `openpgp-key` in the accepted set means the value can be an OpenPGP key, and
 * OpenPGP keys come from the vault / paste panel; everything else is a
 * WebCrypto handle and comes from the keys tray.
 * @param {import("./registry.js").IoType|import("./registry.js").IoType[]|undefined} slotOf
 * @returns {InputPanel}
 */
export function panelForSlotOf(slotOf) {
  const of = Array.isArray(slotOf) ? slotOf : slotOf ? [slotOf] : [];
  return of.includes("openpgp-key") ? "gpg" : "key";
}

/**
 * What is still missing once a slot *has* supplied the value.
 *
 * The OpenPGP panel hands over two things: the private key and the passphrase
 * that unwraps it. A slot carries only the first, so binding `key=$slot` leaves
 * the S2K passphrase behind — which is why `gpgPass` exists and why it is the
 * residue of `gpg` rather than an independent entry. The keys tray hands over
 * an already-unlocked `CryptoKey`, so binding it leaves nothing.
 * @param {InputPanel} panel
 * @returns {InputPanel|null}
 */
function panelResidue(panel) {
  return panel === "gpg" ? "gpgPass" : null;
}

/**
 * A param holds a value when the recipe wrote one. Registry defaults are `""`
 * for every slot param, so "declared" and "bound" are not the same question.
 * @param {{ params?: Record<string, *> }} step
 * @param {string} name
 */
function isBound(step, name) {
  const v = step?.params?.[name];
  return v != null && String(v).trim() !== "";
}

/**
 * Does a `when:` guard hold for this step? Each key names a sibling param and
 * each value the setting (or settings) that arm the need.
 * @param {Record<string, string|string[]>|undefined} when
 * @param {{ params?: Record<string, *> }} step
 */
function whenHolds(when, step) {
  if (!when) return true;
  return Object.entries(when).every(([name, want]) => {
    const got = String(step?.params?.[name] ?? "");
    return Array.isArray(want) ? want.includes(got) : got === want;
  });
}

/**
 * `unresolvedInputs` accepts a bare panel name, a guarded entry, or a list of
 * either. Normalizing here keeps every reader from re-deciding.
 * @param {import("./registry.js").StepSpec["unresolvedInputs"]} decl
 * @returns {{ panel: InputPanel, when?: Record<string, string|string[]> }[]}
 */
export function stepInputDeclarations(decl) {
  if (!decl) return [];
  const list = Array.isArray(decl) ? decl : [decl];
  return list.map((e) => (typeof e === "string" ? { panel: e } : e));
}

/**
 * @typedef {object} InputRequirement
 * @property {string} step  op name
 * @property {string|null} param  the param that requires a value, or null when
 *   the need is the step's pipeline value
 * @property {import("./registry.js").IoType[]} of  what a ref would have to
 *   resolve to (`slotOf`); empty for a pipeline-value need
 * @property {boolean} bound  whether the recipe already supplies it
 * @property {InputPanel|null} panel  the tray that answers it, or null when the
 *   requirement is satisfied
 */

/**
 * Every declared requirement of one step, bound or not. The single walk both
 * the compiler and the gate read: nothing here consults a step name.
 *
 * `spec` is a parameter so the gate can hand in a step the registry has never
 * heard of and watch the panel appear anyway. That is the whole property being
 * bought — a new key param needs no list to be edited — and a test that can
 * only ask about ops that already exist cannot demonstrate it.
 * @param {{ name: string, params?: Record<string, *> }} step
 * @param {import("./registry.js").StepSpec} [spec]
 * @returns {InputRequirement[]}
 */
export function stepInputRequirements(step, spec = getStep(step?.name)) {
  if (!spec) return [];
  /** @type {InputRequirement[]} */
  const out = [];

  for (const decl of stepInputDeclarations(spec.unresolvedInputs)) {
    if (!whenHolds(decl.when, step)) continue;
    out.push({ step: spec.name, param: null, of: [], bound: false, panel: decl.panel });
  }

  for (const p of spec.params || []) {
    if (!p.unresolvedInput) continue;
    if (p.requiredWith && !step?.params?.[p.requiredWith]) continue;
    const of = Array.isArray(p.slotOf) ? p.slotOf : p.slotOf ? [p.slotOf] : [];
    const panel = panelForSlotOf(p.slotOf);
    const bound = isBound(step, p.name);
    out.push({
      step: spec.name,
      param: p.name,
      of,
      bound,
      panel: bound ? panelResidue(panel) : panel,
    });
  }
  return out;
}

/**
 * The panels one step still needs, in declaration order.
 * @param {{ name: string, params?: Record<string, *> }} step
 * @param {import("./registry.js").StepSpec} [spec]
 * @returns {InputPanel[]}
 */
export function stepInputNeeds(step, spec) {
  /** @type {InputPanel[]} */
  const needs = [];
  for (const r of stepInputRequirements(step, spec ?? getStep(step?.name))) {
    if (r.panel && !needs.includes(r.panel)) needs.push(r.panel);
  }
  return needs;
}

/**
 * The panels a *bare* instance of an op needs — nothing bound, every guarded
 * entry at its default. What the tool card advertises before the op is placed.
 * @param {import("./registry.js").StepSpec} spec
 * @returns {InputPanel[]}
 */
export function specInputNeeds(spec) {
  if (!spec?.name) return [];
  /** @type {Record<string, *>} */
  const params = {};
  for (const p of spec.params || []) {
    if (p.default !== undefined) params[p.name] = p.default;
  }
  return stepInputNeeds({ name: spec.name, params }, spec);
}
