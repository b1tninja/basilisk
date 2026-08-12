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
 *     A refused *connection* fires the same event and is a different kind of
 *     accident — see `isConnection`, which is why the two are counted apart.
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
 * @property {"resource"|"csp"|"connection"|"import"} kind
 * @property {string} url        the thing that failed, as best we can name it
 * @property {string} detail     one line a human can act on
 * @property {number} at         ms since page start
 * @property {boolean} [predicted]  report-only CSP: fine now, breaks when built
 */

/**
 * A refused *connection* is not a subresource that failed to load.
 *
 * `connect-src` governs fetch, XHR and WebSockets — things the page reaches out
 * to, not things it is assembled from. Counting one as a failed subresource
 * produced the report this split exists for: a blocked signalling socket was
 * announced as "1 subresource failed to load — this page is running
 * incomplete", above a line naming `/assets/session-*.js`. Both halves were
 * wrong. Nothing failed to load, and the chunk named was the *caller* — the
 * origin it could not reach was never mentioned, so the one fact needed to
 * diagnose it was the one fact absent.
 *
 * @param {string} directive
 */
export function isConnection(directive) {
  return String(directive || "").startsWith("connect-src");
}

/**
 * Which origin a violation was about, preferring the blocked one.
 *
 * For a subresource the source file locates the problem. For a refused
 * connection the *destination* is the problem, and the source file is merely
 * whoever called. `blockedURI` carries the destination; it is only useless for
 * inline script/style, which is never a connection.
 *
 * @param {SecurityPolicyViolationEvent} e
 */
export function violationTarget(e) {
  const blocked = String(e.blockedURI || "");
  if (isConnection(e.effectiveDirective || e.violatedDirective) && blocked && blocked !== "inline") {
    return blocked;
  }
  return e.sourceFile ? `${e.sourceFile}:${e.lineNumber || 0}` : blocked || "unknown";
}

/**
 * What a refused connection costs, in the reader's terms.
 *
 * The only WebSocket this app opens is the signalling relay, so a blocked
 * `ws:`/`wss:` origin has exactly one consequence and it is worth saying rather
 * than leaving to be inferred from a hostname. The deployment that prompted
 * this had a correct Front Door header and a stale `<meta>` policy in the
 * uploaded pages; the browser enforces the intersection, so the socket was
 * refused and every shared session failed with nothing on screen that named
 * signalling.
 *
 * @param {string} origin
 */
export function connectionConsequence(origin) {
  return /^wss?:/i.test(origin)
    ? "this page cannot reach it, so shared sessions are unavailable on this deployment"
    : "this page cannot reach it";
}

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
  const live = failures.filter((f) => !f.predicted);
  const predicted = failures.length - live.length;
  // Two different accidents, counted apart. A missing chunk leaves the page
  // assembled wrong; a refused connection leaves it whole and unable to reach
  // something. Saying "subresource failed to load" for the second was wrong
  // twice over and sent the reader looking at the chunk that was named.
  const refused = live.filter((f) => f.kind === "connection").length;
  const broken = live.length - refused;
  const parts = [];
  if (broken) {
    parts.push(
      `${broken} subresource${broken === 1 ? "" : "s"} failed to load — this page is running incomplete.`
    );
  }
  if (refused) {
    parts.push(
      `${refused} connection${refused === 1 ? "" : "s"} refused by this page's security policy.`
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

    const directive = e.effectiveDirective || e.violatedDirective;
    // For a connection the destination is the subject; for anything else the
    // source file locates it. `blockedURI` is "inline" for inline script/style.
    const where = violationTarget(e);
    // In dev the production policy rides along as report-only, so a violation
    // there is a *prediction* — this works now and breaks once built. Saying
    // "blocked" would be false, and the difference is the whole reason the
    // report-only copy exists.
    const predicted = e.disposition === "report";
    if (isConnection(directive) && where !== "unknown" && e.blockedURI !== "inline") {
      emit(
        "connection",
        where,
        predicted
          ? `would be refused in production by ${directive} — ${connectionConsequence(where)} once built`
          : `refused by ${directive} — ${connectionConsequence(where)}`,
        predicted
      );
      return;
    }
    emit(
      "csp",
      where,
      `${predicted ? "would be blocked in production by" : "blocked by"} ${directive}${
        e.blockedURI === "inline" ? " (inline)" : ""
      }`,
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
