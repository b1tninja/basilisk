/**
 * Detect subresources that never loaded, and say so where you cannot miss it.
 *
 * The failure this exists for: a chunk, stylesheet, or module is blocked — by
 * CSP, an SRI mismatch, a 404, or an offline network — and the page keeps
 * running with that piece absent. What you then see is not "X failed to load"
 * but whatever the *next* code does without it: a widget that renders nothing,
 * a handler that never fires, a `TypeError` deep inside something unrelated.
 * You debug the symptom for an hour. The cause scrolled past in the console
 * before you opened it.
 *
 * Three things make these easy to miss, and each needs handling:
 *
 *  1. **Resource `error` events do not bubble.** A failed `<script>`/`<link>`
 *     fires `error` on the element only; it reaches `window` in the *capture*
 *     phase or not at all. `window.onerror` never sees it.
 *  2. **CSP blocks are not errors.** A refused subresource or inline style
 *     fires `securitypolicyviolation`, which nothing listens to by default.
 *  3. **Dynamic `import()` failures are rejections**, not error events — this
 *     app code-splits openpgp and the WebRTC ops, so a bad chunk shows up as
 *     an unhandled promise rejection far from the import.
 *
 * Install this before anything else on the page. It is dependency-free and
 * does no work until something actually fails.
 *
 * @module lib/boot-diagnostics
 */

/**
 * @typedef {object} BootFailure
 * @property {"resource"|"csp"|"import"} kind
 * @property {string} url        the thing that failed, as best we can name it
 * @property {string} detail     one line a human can act on
 * @property {number} at         ms since page start
 * @property {boolean} [predicted]  report-only CSP: fine now, breaks when built
 */

/** @type {BootFailure[]} */
const failures = [];

/** Everything recorded so far. Read this from the console when debugging. */
export function getBootFailures() {
  return failures.slice();
}

/**
 * Which element failed, and what it was for.
 *
 * Exported for tests: this is the part that can be wrong, and getting it wrong
 * means reporting "something failed" without saying what — barely better than
 * silence.
 *
 * @param {Event} event  a captured `error` event
 * @returns {{ url: string, detail: string }|null} null when it is a script
 *   *error* (a real exception) rather than a *load* failure
 */
export function classifyResourceError(event) {
  const el = /** @type {HTMLElement & { src?: string, href?: string }} */ (
    event?.target
  );
  // A thrown exception has `event.error` and targets `window`; a failed load
  // targets the element and has none. Only the latter is our business.
  if (!el || el === /** @type {*} */ (globalThis) || !el.tagName) return null;
  if (/** @type {ErrorEvent} */ (event).error) return null;

  const tag = el.tagName.toLowerCase();
  const url = String(el.getAttribute?.("src") || el.getAttribute?.("href") || "");
  if (!url) return null;

  const what =
    tag === "script"
      ? el.getAttribute("integrity")
        ? "script blocked or integrity mismatch"
        : "script failed to load"
      : tag === "link"
        ? "stylesheet or preload failed"
        : `<${tag}> failed to load`;
  return { url, detail: what };
}

/**
 * Render a banner naming what failed.
 *
 * Deliberately a DOM element rather than a console message: the whole point is
 * that console output is missed, and a partially-loaded page looks like a
 * feature bug rather than a load failure. Styling lives in site.css — the app
 * runs under `style-src 'self'`, so a style attribute here would itself be
 * blocked, which would be a poor joke in a load-failure reporter.
 */
function render() {
  const doc = globalThis.document;
  if (!doc?.body) return;
  let el = doc.getElementById("boot-diagnostics");
  if (!el) {
    el = doc.createElement("div");
    el.id = "boot-diagnostics";
    el.setAttribute("role", "alert");
    doc.body.appendChild(el);
  }
  el.textContent = "";
  const h = doc.createElement("strong");
  // A report-only CSP hit is a *prediction* — nothing is broken here, it will
  // be once built. Announcing "running incomplete" for one would be the same
  // species of misleading message this whole module exists to eliminate.
  const broken = failures.filter((f) => !f.predicted).length;
  const predicted = failures.length - broken;
  const parts = [];
  if (broken) {
    parts.push(
      `${broken} subresource${broken === 1 ? "" : "s"} failed to load — this page is running incomplete.`
    );
  }
  if (predicted) {
    parts.push(
      `${predicted} issue${predicted === 1 ? "" : "s"} would break the production build.`
    );
  }
  h.textContent = parts.join(" ");
  el.appendChild(h);
  const list = doc.createElement("ul");
  for (const f of failures.slice(0, 8)) {
    const li = doc.createElement("li");
    li.textContent = `${f.kind}: ${f.detail} — ${f.url}`;
    list.appendChild(li);
  }
  el.appendChild(list);
}

/**
 * @param {BootFailure["kind"]} kind
 * @param {string} url
 * @param {string} detail
 */
function record(kind, url, detail, predicted = false) {
  // Same resource failing twice is one problem, not two.
  if (failures.some((f) => f.kind === kind && f.url === url)) return;
  failures.push({ kind, url, detail, predicted, at: Math.round(performance.now()) });
  // Still log — the banner is for the person who did not open the console, the
  // log is for the one who did.
  console.error(`[boot] ${kind}: ${detail} — ${url}`);
  render();
}

let installed = false;

/**
 * Start watching. Idempotent.
 * @param {{ onFailure?: (f: BootFailure) => void }} [opts]
 */
export function installBootDiagnostics(opts = {}) {
  if (installed || typeof window === "undefined") return;
  installed = true;

  const emit = (/** @type {BootFailure["kind"]} */ kind, url, detail, predicted) => {
    const before = failures.length;
    record(kind, url, detail, predicted);
    if (failures.length > before) opts.onFailure?.(failures[failures.length - 1]);
  };

  // Capture phase is mandatory: resource errors do not bubble, so a listener
  // without `true` here silently receives nothing at all.
  window.addEventListener(
    "error",
    (event) => {
      const hit = classifyResourceError(event);
      if (hit) emit("resource", hit.url, hit.detail);
    },
    true
  );

  window.addEventListener("securitypolicyviolation", (event) => {
    const e = /** @type {SecurityPolicyViolationEvent} */ (event);
    // Vite's own injected client and HMR hooks trip the report-only policy on
    // every reload. They are a dev-server artefact, not something that ships,
    // and leaving them in would bury the real findings.
    const src = String(e.sourceFile || "");
    if (/\/@vite\/|\/@react-refresh|\/node_modules\/\.vite\//.test(src)) return;

    // `blockedURI` is "inline" for inline script/style; the source file and
    // line are what actually locate it.
    const where = e.sourceFile
      ? `${e.sourceFile}:${e.lineNumber || 0}`
      : e.blockedURI || "unknown";
    // In dev the production policy rides along as report-only, so a violation
    // there is a *prediction* — this works now and breaks once built. Saying
    // "blocked" would be false, and the difference is the whole reason the
    // report-only copy exists.
    const predicted = e.disposition === "report";
    emit(
      "csp",
      where,
      `${predicted ? "would be blocked in production by" : "blocked by"} ${
        e.effectiveDirective || e.violatedDirective
      }${e.blockedURI === "inline" ? " (inline)" : ""}`,
      predicted
    );
  });

  window.addEventListener("unhandledrejection", (event) => {
    const reason = /** @type {PromiseRejectionEvent} */ (event).reason;
    const msg = String(reason?.message || reason || "");
    // Only claim the ones that are recognisably module-loading failures;
    // ordinary rejected promises are the app's business, not ours.
    if (!/dynamically imported module|Importing a module script failed|Failed to fetch/i.test(msg)) {
      return;
    }
    const url = String(msg.match(/https?:\/\/\S+|\/[\w./-]+\.m?js/)?.[0] || "dynamic import");
    emit("import", url, "dynamic import failed — a code-split chunk is missing");
  });
}
