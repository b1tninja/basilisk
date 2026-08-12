/**
 * The Activity log (§36, design_handoff_artifact_actions).
 *
 * Moving dispositions out of the recipe and onto buttons buys portability —
 * a shared recipe stops being a script of side effects on whoever runs it —
 * but it costs the recipe its status as a complete record of what happened.
 * A key lands in the vault with nothing in the recipe to say so.
 *
 * Three answers were considered. Folding clicks into **run receipts** was
 * rejected because a receipt's whole value is that a re-run reproduces it,
 * and a click cannot be re-run — every such receipt would be permanently
 * unverifiable. **Promote-to-recipe** was rejected more firmly: its one-click
 * effect is to put the disposition back into the recipe, undoing the premise.
 * So the split is accepted deliberately: recipes record derivations, this
 * records dispositions, and neither pretends to be the other.
 *
 * Design consequences that are not negotiable:
 *
 * - **Every action of every tier is logged, including inert ones.** Copy and
 *   Download are how a secret leaves the notebook. A log that records only
 *   the dramatic actions answers the wrong question at 2am.
 * - **Digests, never values** — the same `digestText` receipts use, so the
 *   two records can be cross-read against each other.
 * - **Session-scoped, never persisted.** It names key ids and directory URLs,
 *   and localStorage is XSS-readable; `workspace-store.js` already states
 *   that rule and this follows it.
 * - **Exportable by copy, as text.** Deliberately not a signed downloadable
 *   object: signing it would imply a verifiability it does not have, because
 *   nobody can re-run a click.
 */

import { digestText } from "./receipt.js";

/**
 * @typedef {object} ActivityEntry
 * @property {number} at            Wall clock, for display only
 * @property {string} action        Action id ("copy", "key.copyPublicLine")
 * @property {string} label         Human label as the button showed it
 * @property {string} artifact      The artifact's label
 * @property {"inert"|"local"|"outward"} tier
 * @property {string} digest        sha256 of the artifact content at the time
 * @property {string} [detail]      Where it landed — a vault id, a directory URL
 * @property {string} [receipt]     The action's own one-line result
 */

/** @type {ActivityEntry[]} */
let entries = [];
/** @type {Set<() => void>} */
const listeners = new Set();

function notify() {
  for (const fn of [...listeners]) {
    try {
      fn();
    } catch (_) {
      /* a broken subscriber must not stop the log */
    }
  }
}

/** Subscribe to changes; returns an unsubscribe. */
export function onActivityChange(fn) {
  listeners.add(fn);
  // Braces on purpose: an unsubscriber returns nothing. Set.delete's boolean
  // would otherwise leak out as the value, and React's cleanup slot is typed
  // void — which is how this surfaced.
  return () => {
    listeners.delete(fn);
  };
}

/** Newest first — the order a reader wants when something just happened. */
export function listActivity() {
  return [...entries].reverse();
}

export function activityCount() {
  return entries.length;
}

/**
 * Record one action. Called by the tile's action runner in exactly one place,
 * so a newly declared action cannot forget to log — the same structural move
 * as routing every action's outcome through `ActionResult`.
 *
 * Never throws: a logging failure must not turn a completed action into an
 * apparent error. The action already happened; refusing to record it does not
 * un-happen it, and surfacing that as a failure would be a lie in the other
 * direction.
 *
 * @param {{ action: string, label: string, artifact: string,
 *           tier: string, content?: string, detail?: string, receipt?: string }} evt
 */
export async function recordActivity(evt) {
  try {
    entries.push({
      at: Date.now(),
      action: String(evt.action || ""),
      label: String(evt.label || ""),
      artifact: String(evt.artifact || ""),
      tier: /** @type {*} */ (evt.tier || "inert"),
      digest: evt.content ? (await digestText(String(evt.content))).slice(0, 16) : "",
      ...(evt.detail ? { detail: String(evt.detail) } : {}),
      ...(evt.receipt ? { receipt: String(evt.receipt) } : {}),
    });
    notify();
  } catch (_) {
    /* see above */
  }
}

/**
 * Clear the log. Wired to Clear session / Clear sensitive data alongside
 * `cellOutputs`, because the log names key ids and destinations even though
 * it holds no values.
 */
export function clearActivity() {
  entries = [];
  notify();
}

const two = (n) => String(n).padStart(2, "0");

/** `14:07:22` — wall clock, local, seconds included because order matters. */
export function formatActivityTime(at) {
  const d = new Date(at);
  return `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
}

/**
 * The log as plain text, for pasting into a ceremony's minutes.
 *
 * Oldest first here, deliberately, though the UI shows newest first: a
 * transcript someone reads start to finish wants chronological order, while a
 * panel someone glances at wants the most recent thing at the top.
 */
export function activityAsText() {
  if (!entries.length) return "";
  return entries
    .map((e) => {
      const head = `${formatActivityTime(e.at)}  ${e.label}  ${e.artifact}${
        e.digest ? `  sha256 ${e.digest}…` : ""
      }`;
      return e.detail ? `${head}\n          → ${e.detail}` : head;
    })
    .join("\n");
}
