/**
 * docs/THREAT-MODEL.md, checked against the code it describes.
 *
 * A threat model that can drift from its implementation is marketing. The
 * claims pinned here are the load-bearing ones — the policy that stops
 * exfiltration, where keys actually live, and the properties the mesh
 * genuinely provides. If someone weakens one and forgets the page, this
 * fails.
 *
 * Deliberately not pinned: prose, structure, wording. This guards facts.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8").replace(
    /\r\n/g,
    "\n"
  );

const DOC = read("../../../docs/THREAT-MODEL.md");
const TOOLKIT_HTML = read("../../toolkit.html");
const VAULT = read("../lib/vault.js");

/** The `content` of the CSP meta tag, normalized to single spaces. */
function livePolicy() {
  // The attribute value itself contains single quotes (`'none'`, `'self'`), so
  // the delimiter has to be captured and matched, not excluded by class — a
  // `[^"']+` here silently truncates the policy at `default-src `.
  const m = TOOLKIT_HTML.match(
    /<meta[^>]*http-equiv=(["'])Content-Security-Policy\1[^>]*content=(["'])([\s\S]*?)\2/i
  );
  return m ? m[3].replace(/\s+/g, " ").trim() : "";
}

describe("the quoted CSP is the CSP that ships", () => {
  const policy = livePolicy();

  it("finds a policy on the page at all", () => {
    expect(policy, "no CSP meta tag in toolkit.html").toBeTruthy();
  });

  it("quotes every directive verbatim", () => {
    // The doc prints the policy in a fenced block, wrapped over lines.
    const quoted = (DOC.match(/```\n(default-src[\s\S]*?)```/) || ["", ""])[1]
      .replace(/\s+/g, " ")
      .trim();
    expect(quoted, "policy block missing from THREAT-MODEL.md").toBeTruthy();
    expect(quoted).toBe(policy);
  });

  it("still has the properties the page claims of it", () => {
    // Each of these is load-bearing prose in the doc; if the policy loosens,
    // the claim becomes false and this test is where it surfaces.
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("style-src 'self'"); // no inline styles
    expect(policy).toContain("img-src 'self' data:"); // no remote pixels
    expect(policy).not.toMatch(/style-src[^;]*unsafe-inline/);
    expect(policy).not.toMatch(/script-src[^;]*unsafe-inline/);
    // `'wasm-unsafe-eval'` is a far narrower grant than `'unsafe-eval'` — it
    // permits WebAssembly compilation, not eval of strings — so the check has
    // to distinguish them rather than pattern-match the shared suffix.
    expect(policy).not.toMatch(/script-src[^;]*(?<!wasm-)'unsafe-eval'/);
  });

  it("keeps connect-src an allow-list, and the doc names the same hosts", () => {
    const connect = (policy.match(/connect-src ([^;]+)/) || ["", ""])[1].trim();
    expect(connect).toBeTruthy();
    const hosts = connect.split(/\s+/).filter((h) => h.startsWith("https://"));
    // The claim "cannot phone anywhere else" is only true while this is a
    // finite list without a wildcard.
    expect(connect).not.toContain("*");
    for (const h of hosts) {
      expect(DOC, `${h} not named in the doc`).toContain(h);
    }
  });
});

describe("key-storage claims match lib/vault.js", () => {
  it("keys are in IndexedDB, not localStorage", () => {
    expect(VAULT).toContain("indexedDB.open");
    expect(DOC).toContain("IndexedDB");
    // The doc says localStorage is deliberately unused for secrets; the vault
    // must not quietly start using it.
    expect(VAULT).not.toMatch(/localStorage\.setItem/);
  });

  it("the wrapping key is non-extractable and device-bound", () => {
    expect(VAULT).toMatch(/non-extractable/i);
    expect(DOC).toMatch(/non-extractable/i);
  });

  it("names the same protection modes the vault implements", () => {
    const modes = (VAULT.match(/@typedef \{("[a-z]+"\|?)+\} VaultProtection/) || [
      "",
    ])[0];
    for (const mode of ["passphrase", "passkey", "device"]) {
      expect(modes, `${mode} missing from VaultProtection`).toContain(mode);
    }
    expect(DOC).toContain("passphrase");
    expect(DOC).toContain("passkey");
  });
});

describe("the honest parts stay in", () => {
  it("still leads with the served-code problem", () => {
    // The single most important caveat for any in-browser crypto tool. If a
    // future edit quietly drops it, that is a material change to what this
    // page promises.
    expect(DOC).toMatch(/served code|serving.*JavaScript|hands you the JavaScript/i);
    expect(DOC).toMatch(/reproducible-build|transparency log/i);
  });

  it("keeps the dev-server caveat, which is a real trap", () => {
    // Matched on substance rather than a phrase: this fired once on a
    // rewording that *improved* the same warning, which is a guard testing
    // prose instead of fact.
    expect(DOC).toMatch(/report-only/i);
    expect(DOC).toMatch(/dev server/i);
    expect(DOC).toMatch(/relax|loose|widen/i);
  });

  it("does not claim erasure guarantees JavaScript cannot make", () => {
    // The wipe is real but bounded — immutable strings, engine copies. The
    // doc must keep saying so; "guaranteed erasure" may appear only in the
    // sentence disclaiming it.
    expect(DOC).toMatch(/best-effort/i);
    for (const m of DOC.matchAll(/guaranteed erasure/gi)) {
      const before = DOC.slice(Math.max(0, m.index - 40), m.index);
      expect(before, "erasure claimed rather than disclaimed").toMatch(/not as|never/i);
    }
  });

  it("keeps the out-of-scope list from quietly shrinking", () => {
    for (const item of [
      "extension",
      "traffic analysis",
      "constant-time",
      "post-quantum",
    ]) {
      expect(DOC.toLowerCase(), `${item} dropped from out-of-scope`).toContain(item);
    }
  });
});
