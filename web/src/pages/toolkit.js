/**
 * Crypto Toolkit page — presets-first pipeline builder + recipe language.
 * Separate from /encrypt novice UX.
 */

import { Auth } from "../lib/auth.js";
import {
  CryptoModuleError,
  SELF_TEST_LABELS,
  assertCryptoReady,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { mountRecipientBinder } from "../lib/recipient-picker.js";
import {
  PRESETS,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import { getStep, listSteps, stepsAccepting } from "../lib/toolkit/registry.js";
import {
  copyTextTransient,
  escapeHtml,
  formatFingerprint,
  showError,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/toolkit");

const errorEl = document.getElementById("error");
const app = document.getElementById("toolkit-app");

let cryptoReady = false;
/** @type {import("../lib/toolkit/recipe.js").RecipeStep[]} */
let steps = [];
let customizeOpen = false;
let referenceOpen = false;
/** @type {import("../lib/toolkit/engine.js").ToolkitArtifact[]} */
let artifacts = [];
/** @type {import("../lib/recipient-picker.js").Recipient[]} */
let boundRecipients = [];
/** @type {ReturnType<typeof mountRecipientBinder>|null} */
let binder = null;

const IDLE_CLEAR_MS = 5 * 60 * 1000;
let idleTimer = null;

app.innerHTML = `
  <div id="crypto-status" class="status-row" role="status">Verifying crypto module…</div>

  <div class="card toolkit-banner">
    <p class="m-0 fs-md">
      <strong>Advanced tool.</strong> This page generates extractable key material and shareable backups.
      Prefer hardware tokens for long-lived identity keys. Everyday messaging belongs on
      <a class="text-link" href="/encrypt">Encrypt</a>.
    </p>
  </div>

  <div id="preset-gallery" class="card">
    <p class="card-title">Templates</p>
    <p class="muted m-0-b-lg fs-md">One-click recipes. Customize afterward if you need a different pipeline.</p>
    <div class="preset-grid" id="preset-grid"></div>
  </div>

  <div class="btn-row my-lg">
    <button type="button" class="btn btn-ghost" id="toggle-customize">Customize pipeline</button>
    <button type="button" class="btn btn-ghost" id="toggle-reference">Reference</button>
  </div>

  <div id="customize-panel" class="hidden">
    <div class="card">
      <p class="card-title">Pipeline builder</p>
      <div id="builder-steps" class="builder-steps"></div>
      <div class="btn-row mt-md wrap">
        <select id="add-step-select" class="text-input maxw-220"></select>
        <button type="button" class="btn btn-compact" id="add-step-btn">Add step</button>
      </div>
    </div>

    <div class="card mt-lg">
      <p class="card-title">Recipe</p>
      <p class="muted m-0-b-sm fs-sm">
        Pipe-separated steps. Flow control: <code>foreach</code> / <code>merge</code>
        (aliases: map, each, fork / collect). Recipients are chosen at run time — never written into the recipe.
      </p>
      <textarea id="recipe-text" class="compose-message" rows="3" spellcheck="false"
        placeholder="genkey ec/p256 | export pkcs8 | pem"></textarea>
      <p id="recipe-errors" class="status-row err hidden mt-sm"></p>
      <p id="recipe-warnings" class="muted mt-xs fs-sm"></p>
      <div id="autocomplete" class="recipient-dropdown hidden"></div>
    </div>
  </div>

  <div id="reference-panel" class="card hidden mt-lg">
    <p class="card-title">Step reference</p>
    <div id="reference-body"></div>
  </div>

  <div class="card mt-lg">
    <p class="card-title">Run</p>
    <div id="recipient-bind-host"></div>
    <div class="btn-row mt-md">
      <button type="button" class="btn" id="run-btn" disabled>Run recipe</button>
    </div>
    <p id="run-status" class="status-row hidden mt-sm"></p>
  </div>

  <div id="results-panel" class="hidden mt-lg"></div>
`;

function touchActivity() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    artifacts = [];
    renderResults();
    const rt = document.getElementById("recipe-text");
    // don't clear recipe — only sensitive outputs
  }, IDLE_CLEAR_MS);
}

function setRecipeFromSteps() {
  const ta = document.getElementById("recipe-text");
  if (ta instanceof HTMLTextAreaElement) {
    ta.value = serializeRecipe(steps);
  }
  validateAndBind();
  renderBuilder();
}

function loadRecipeText(text) {
  const { ast, errors } = parseRecipe(text);
  const errEl = document.getElementById("recipe-errors");
  if (errors.length || !ast) {
    if (errEl) {
      errEl.textContent = errors.map((e) => e.message).join(" · ");
      errEl.classList.remove("hidden");
    }
    return;
  }
  steps = ast.steps.map((s) => ({
    name: s.name,
    params: { ...s.params },
    start: s.start,
    end: s.end,
  }));
  if (errEl) errEl.classList.add("hidden");
  validateAndBind();
  renderBuilder();
}

function validateAndBind() {
  const { ast, validation } = compileRecipe(serializeRecipe(steps));
  const errEl = document.getElementById("recipe-errors");
  const warnEl = document.getElementById("recipe-warnings");
  const runBtn = document.getElementById("run-btn");

  if (!validation.ok) {
    if (errEl) {
      errEl.textContent = validation.errors.map((e) => e.message).join(" · ");
      errEl.classList.remove("hidden");
    }
    if (runBtn) runBtn.disabled = true;
  } else {
    if (errEl) errEl.classList.add("hidden");
    if (runBtn) runBtn.disabled = !cryptoReady;
  }
  if (warnEl) {
    warnEl.textContent = (validation.warnings || []).join(" · ");
  }

  // Recipient binder
  const host = document.getElementById("recipient-bind-host");
  if (!host) return;
  const slots = validation.recipientSlots || 0;
  if (binder) {
    binder.destroy();
    binder = null;
  }
  boundRecipients = [];
  if (slots > 0 && ast) {
    const info = unresolvedRecipients(ast);
    binder = mountRecipientBinder(host, {
      slots: info.slots || slots,
      foreach: info.foreach,
      onChange: (recs) => {
        boundRecipients = recs;
      },
    });
  } else {
    host.innerHTML = "";
  }
}

function renderPresets() {
  const grid = document.getElementById("preset-grid");
  if (!grid) return;
  grid.innerHTML = PRESETS.map(
    (p) => `
    <button type="button" class="preset-card" data-preset="${escapeHtml(p.id)}">
      <strong>${escapeHtml(p.title)}</strong>
      <span class="muted">${escapeHtml(p.blurb)}</span>
      <code class="preset-recipe">${escapeHtml(p.recipe)}</code>
    </button>`
  ).join("");
  grid.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-preset");
      const preset = PRESETS.find((p) => p.id === id);
      if (!preset) return;
      loadRecipeText(preset.recipe);
      customizeOpen = true;
      document.getElementById("customize-panel")?.classList.remove("hidden");
      document.getElementById("toggle-customize").textContent = "Hide pipeline";
    });
  });
}

function renderBuilder() {
  const host = document.getElementById("builder-steps");
  const addSelect = document.getElementById("add-step-select");
  if (!host) return;

  let foreachOpen = false;
  host.innerHTML = steps
    .map((step, i) => {
      const spec = getStep(step.name);
      if (step.name === "foreach") foreachOpen = true;
      const inForeach =
        foreachOpen && step.name !== "foreach" && step.name !== "merge";
      if (step.name === "merge") foreachOpen = false;

      const paramFields = (spec?.params || [])
        .map((p) => {
          const val = step.params[p.name] ?? p.default ?? "";
          if (p.type === "enum") {
            return `<label class="builder-param">${escapeHtml(p.name)}
              <select data-step="${i}" data-param="${escapeHtml(p.name)}" class="text-input">
                ${(p.enum || [])
                  .map(
                    (e) =>
                      `<option value="${escapeHtml(e)}" ${String(val) === e ? "selected" : ""}>${escapeHtml(e)}</option>`
                  )
                  .join("")}
              </select></label>`;
          }
          return `<label class="builder-param">${escapeHtml(p.name)}
            <input class="text-input" data-step="${i}" data-param="${escapeHtml(p.name)}"
                   value="${escapeHtml(String(val))}" ${p.type === "int" ? 'type="number"' : 'type="text"'}></label>`;
        })
        .join("");

      return `
        <div class="builder-card ${inForeach ? "builder-foreach-child" : ""} ${step.name === "foreach" ? "builder-foreach" : ""}"
             draggable="true" data-index="${i}">
          <div class="builder-card-head">
            <span class="builder-drag" title="Drag to reorder">⠿</span>
            <strong>${escapeHtml(step.name)}</strong>
            <span class="muted fs-xs">${escapeHtml(spec?.kind || "")}</span>
            <button type="button" class="btn btn-ghost btn-compact text-error" data-remove="${i}">Remove</button>
          </div>
          <p class="muted mt-xs mb-sm fs-xs">${escapeHtml(spec?.doc || "")}</p>
          <div class="builder-params">${paramFields}</div>
        </div>`;
    })
    .join("");

  // Param change handlers
  host.querySelectorAll("[data-param]").forEach((el) => {
    el.addEventListener("change", () => {
      const i = Number(el.getAttribute("data-step"));
      const name = el.getAttribute("data-param");
      if (!name || !steps[i]) return;
      const v =
        el instanceof HTMLInputElement || el instanceof HTMLSelectElement
          ? el.value
          : "";
      const spec = getStep(steps[i].name);
      const p = (spec?.params || []).find((x) => x.name === name);
      steps[i].params[name] = p?.type === "int" ? Number(v) : v;
      setRecipeFromSteps();
    });
  });

  host.querySelectorAll("[data-remove]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-remove"));
      steps.splice(i, 1);
      setRecipeFromSteps();
    });
  });

  // Drag reorder
  let dragFrom = -1;
  host.querySelectorAll(".builder-card").forEach((card) => {
    card.addEventListener("dragstart", () => {
      dragFrom = Number(card.getAttribute("data-index"));
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
    card.addEventListener("dragover", (e) => e.preventDefault());
    card.addEventListener("drop", (e) => {
      e.preventDefault();
      const to = Number(card.getAttribute("data-index"));
      if (dragFrom < 0 || to < 0 || dragFrom === to) return;
      const [moved] = steps.splice(dragFrom, 1);
      steps.splice(to, 0, moved);
      setRecipeFromSteps();
    });
  });

  // Add-step select: suggest based on last output
  if (addSelect instanceof HTMLSelectElement) {
    const last = steps[steps.length - 1];
    const from = last ? getStep(last.name)?.output || "none" : "none";
    const candidates = stepsAccepting(from);
    const all = listSteps().filter((s) => s.kind !== "flow" || s.name === "foreach" || s.name === "merge");
    const list = candidates.length ? candidates : all;
    addSelect.innerHTML = list
      .map((s) => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} — ${escapeHtml(s.kind)}</option>`)
      .join("");
  }
}

function renderReference() {
  const body = document.getElementById("reference-body");
  if (!body) return;
  body.innerHTML = listSteps()
    .map((s) => {
      const params = (s.params || [])
        .map(
          (p) =>
            `<li><code>${escapeHtml(p.name)}</code> (${escapeHtml(p.type)}${
              p.enum ? `: ${p.enum.join("|")}` : ""
            }) — ${escapeHtml(p.doc || "")}</li>`
        )
        .join("");
      const aliases = (s.aliases || []).length
        ? `<p class="muted fs-xs">Aliases: ${(s.aliases || []).map(escapeHtml).join(", ")}</p>`
        : "";
      return `<details class="ref-step">
        <summary><code>${escapeHtml(s.name)}</code> <span class="muted">${escapeHtml(s.kind)}</span>
          · ${escapeHtml(s.input)} → ${escapeHtml(s.output)}</summary>
        <p class="fs-md">${escapeHtml(s.doc)}</p>
        ${aliases}
        ${params ? `<ul class="fs-sm">${params}</ul>` : "<p class='muted'>No parameters.</p>"}
      </details>`;
    })
    .join("");
}

function renderResults() {
  const panel = document.getElementById("results-panel");
  if (!panel) return;
  if (!artifacts.length) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }
  panel.classList.remove("hidden");
  panel.innerHTML = `
    <h2>Results</h2>
    <p class="muted mb-md">Sensitive outputs are masked until revealed. Cleared after ${IDLE_CLEAR_MS / 60000} minutes of inactivity.</p>
    ${artifacts
      .map((a, i) => {
        const masked = a.sensitive;
        const preview = masked
          ? "•••••••• (click Reveal)"
          : a.content.length > 400
            ? escapeHtml(a.content.slice(0, 400)) + "…"
            : escapeHtml(a.content);
        const isSvg = a.mime === "image/svg+xml";
        return `
        <div class="card artifact-card" data-art="${i}">
          <p class="card-title m-0-b-xs">${escapeHtml(a.label)}
            ${a.shareIndex ? `<span class="badge pending">share ${a.shareIndex}</span>` : ""}
            ${a.recipientFingerprint ? `<span class="muted fs-xs">→ ${escapeHtml(formatFingerprint(a.recipientFingerprint))}</span>` : ""}
          </p>
          ${
            isSvg && !masked
              ? `<div class="qr-preview">${a.content}</div>`
              : `<pre class="output-pre artifact-body" data-art="${i}">${preview}</pre>`
          }
          <div class="btn-row mt-sm wrap">
            ${masked ? `<button type="button" class="btn btn-ghost btn-compact" data-reveal="${i}">Reveal</button>` : ""}
            <button type="button" class="btn btn-ghost btn-compact" data-copy="${i}">Copy</button>
            <button type="button" class="btn btn-ghost btn-compact" data-download="${i}">Download</button>
          </div>
        </div>`;
      })
      .join("")}`;

  panel.querySelectorAll("[data-reveal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-reveal"));
      const pre = panel.querySelector(`.artifact-body[data-art="${i}"]`);
      if (pre) pre.textContent = artifacts[i].content;
      btn.remove();
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const i = Number(btn.getAttribute("data-copy"));
      await copyTextTransient(artifacts[i].content);
      btn.textContent = "Copied";
      setTimeout(() => {
        btn.textContent = "Copy";
      }, 1200);
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-download]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-download"));
      const a = artifacts[i];
      const blob = new Blob([a.content], {
        type: a.mime || "text/plain",
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = a.filename || "artifact.txt";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      touchActivity();
    });
  });
}

async function runViaWorker(ast) {
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("../lib/crypto-worker.js", import.meta.url), {
        type: "module",
      });
    } catch (err) {
      reject(err);
      return;
    }
    const id = `tk-${Date.now()}`;
    const timer = setTimeout(() => {
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(new Error("Toolkit worker timed out"));
    }, 120_000);
    worker.onmessage = (ev) => {
      if (ev.data?.id !== id) return;
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      if (ev.data.ok) resolve(ev.data.artifacts || []);
      else reject(new Error(ev.data.error || "Toolkit run failed"));
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(err?.message ? new Error(err.message) : new Error("Worker error"));
    };
    worker.postMessage({
      id,
      type: "toolkit-run",
      ast,
      recipientKeysArmored: boundRecipients.map((r) => r.armoredKey),
      recipientFingerprints: boundRecipients.map((r) => r.fingerprint),
    });
  });
}

document.getElementById("toggle-customize")?.addEventListener("click", () => {
  customizeOpen = !customizeOpen;
  document.getElementById("customize-panel")?.classList.toggle("hidden", !customizeOpen);
  document.getElementById("toggle-customize").textContent = customizeOpen
    ? "Hide pipeline"
    : "Customize pipeline";
});

document.getElementById("toggle-reference")?.addEventListener("click", () => {
  referenceOpen = !referenceOpen;
  document.getElementById("reference-panel")?.classList.toggle("hidden", !referenceOpen);
  if (referenceOpen) renderReference();
});

document.getElementById("add-step-btn")?.addEventListener("click", () => {
  const sel = document.getElementById("add-step-select");
  const name = sel instanceof HTMLSelectElement ? sel.value : "";
  const spec = getStep(name);
  if (!spec) return;
  /** @type {Record<string, string|number|boolean>} */
  const params = {};
  for (const p of spec.params || []) {
    if (p.default !== undefined) params[p.name] = p.default;
  }
  steps.push({ name: spec.name, params, start: 0, end: 0 });
  setRecipeFromSteps();
});

let recipeTimer = 0;
document.getElementById("recipe-text")?.addEventListener("input", () => {
  clearTimeout(recipeTimer);
  recipeTimer = window.setTimeout(() => {
    const ta = document.getElementById("recipe-text");
    if (ta instanceof HTMLTextAreaElement) loadRecipeText(ta.value);
  }, 300);
});

document.getElementById("run-btn")?.addEventListener("click", async () => {
  if (!cryptoReady) {
    showError(errorEl, "Crypto self-test has not passed.");
    return;
  }
  try {
    await assertCryptoReady();
  } catch (err) {
    showError(
      errorEl,
      err instanceof CryptoModuleError
        ? `Refusing to run — crypto self-test failed: ${err.message}`
        : String(err)
    );
    return;
  }

  const source = serializeRecipe(steps);
  const { ast, validation } = compileRecipe(source);
  if (!ast || !validation.ok) {
    showError(errorEl, validation.errors.map((e) => e.message).join(" · "));
    return;
  }
  const need = unresolvedRecipients(ast);
  if (need.slots > 0) {
    if (boundRecipients.length < need.slots) {
      showError(
        errorEl,
        `Select ${need.slots} recipient${need.slots === 1 ? "" : "s"} and confirm fingerprints before running.`
      );
      return;
    }
  }

  const status = document.getElementById("run-status");
  const btn = document.getElementById("run-btn");
  if (status) {
    status.className = "status-row";
    status.textContent = "Running…";
    status.classList.remove("hidden");
  }
  if (btn) btn.disabled = true;
  errorEl.classList.add("hidden");

  try {
    artifacts = await runViaWorker(ast);
    renderResults();
    touchActivity();
    if (status) {
      status.className = "status-row ok";
      status.textContent = `Done — ${artifacts.length} artifact${artifacts.length === 1 ? "" : "s"}.`;
    }
  } catch (err) {
    if (status) {
      status.className = "status-row err";
      status.textContent = err?.message || "Run failed";
    }
    showError(errorEl, err?.message || "Run failed");
  } finally {
    if (btn) btn.disabled = false;
  }
});

async function startPage() {
  const status = document.getElementById("crypto-status");
  try {
    const result = await runCryptoSelfTests();
    if (!result.passed) {
      throw new CryptoModuleError(result.error || "POST failed");
    }
    cryptoReady = true;
    if (status) {
      status.className = "status-row ok";
      status.textContent = "Crypto module verified.";
    }
    const runBtn = document.getElementById("run-btn");
    if (runBtn) runBtn.disabled = false;
  } catch (err) {
    cryptoReady = false;
    if (status) {
      status.className = "status-row err";
      status.innerHTML =
        `<strong>Crypto self-test FAILED</strong> — toolkit disabled. ` +
        escapeHtml(err?.message || String(err));
    }
  }
}

renderPresets();
loadRecipeText(PRESETS[0].recipe);
startPage();
