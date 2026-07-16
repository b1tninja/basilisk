import { Auth } from "../lib/auth.js";
import { fetchJson, queryParam, showError } from "../lib/utils.js";
import { renderKeysTable } from "../lib/keys.js";
import {
  renderSearchHelpSnippets,
  wireSnippetCopy,
} from "../lib/snippets.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"));

const form = document.getElementById("search-form");
const input = document.getElementById("q");
const results = document.getElementById("results");
const error = document.getElementById("error");
const help = document.getElementById("cli-help");

if (help) {
  help.innerHTML = renderSearchHelpSnippets();
  wireSnippetCopy(help);
}

async function runSearch(query) {
  error.classList.add("hidden");
  results.innerHTML = "";
  if (!query.trim()) return;
  try {
    const payload = await fetchJson(`/api/v1/search?q=${encodeURIComponent(query.trim())}`);
    if (!payload.results || !payload.results.length) {
      results.innerHTML = "<p class='muted'>No matching approved keys found.</p>";
      return;
    }
    results.innerHTML = renderKeysTable(payload.results);
  } catch (err) {
    showError(error, err.message);
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const q = input.value.trim();
  history.replaceState(null, "", q ? `/?q=${encodeURIComponent(q)}` : "/");
  runSearch(q);
});

const initial = queryParam("q");
if (initial) {
  input.value = initial;
  runSearch(initial);
}
