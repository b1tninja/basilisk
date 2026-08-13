/**
 * The policy a browser actually computes, for every page that ships.
 *
 * A document carries a `<meta http-equiv="Content-Security-Policy">` and the
 * response arrives with a `Content-Security-Policy` header, and the browser
 * enforces the **intersection**. So a source named in one and not the other is
 * a source that does not exist — and neither file looks wrong on its own. That
 * is not a hypothetical: `keys.b1tninja.com` shipped with Front Door's header
 * naming the signalling socket and the uploaded pages' meta not naming it, and
 * shared sessions could not open a socket on the deployed site. Every
 * configuration file involved was correct.
 *
 * `browser-peers.js` serves the deployed response header alongside the built
 * bytes, so this is the only place in the suite where both halves of the policy
 * exist at once. The assertion is the one whose absence let that ship: **every
 * source the header allows must also be allowed by the page's own policy.**
 *
 * ## The direction that is checked, and the direction that is not
 *
 * Header ⊄ meta is always a bug: the header is the deployment's intent, and a
 * page that refuses part of it silently drops a capability. The reverse — a
 * meta naming something the header does not — is *also* a dead source, but it
 * is a page asking for more than the deployment grants, which `quorum.html`
 * did deliberately with its `stun:` entries until it was retired. So only the
 * first direction fails here; the second is reported so it cannot accumulate
 * unnoticed, which is how those `stun:` entries stayed visible long enough to
 * be shown, in `stun-discovery.e2e.js`, to have bought nothing.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readdirSync } from "node:fs";
import {
  DIST_ROOT,
  HEADER_CSP,
  chromiumAvailability,
  openPeers,
} from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the CSP suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[csp-policy.e2e] skipping — chromium not installed (${availability.reason})`);
}

/**
 * The sources a policy's `connect-src` lists.
 *
 * Mirrors `connect_src_sources` in `basilisk/security/csp.py`. Deliberately
 * small and duplicated rather than shared: this side has to read the policy out
 * of a served response in a JS test process, and the alternative is shelling
 * out to Python from a browser suite. An empty result means the directive is
 * *absent*, which is not an empty allowlist — `connect-src` falls back to
 * `default-src`, and every page here sets that to `'none'`.
 */
function connectSrc(policy) {
  const m = /connect-src ([^;"]+)/.exec(String(policy || ""));
  return m ? m[1].trim().split(/\s+/) : [];
}

/** The page's own policy, out of its `<meta http-equiv>`. */
function metaPolicy(html) {
  const m = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/i.exec(html);
  return m ? m[1] : "";
}

/** Every page the build produces — not a list, so a new page is covered on day one. */
const PAGES = readdirSync(DIST_ROOT)
  .filter((n) => n.endsWith(".html"))
  .sort();

describe.runIf(availability.ok)("meta and header describe the same policy", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 1 });
  });

  afterAll(async () => {
    await fx?.close();
  });

  it("finds the pages to check, so the sweep cannot pass by being empty", () => {
    expect(PAGES.length).toBeGreaterThan(5);
  });

  it("serves both halves, or there is nothing to compare", async () => {
    const [peer] = fx.peers;
    const res = await peer.page.request.get(`${fx.origin}/toolkit`);
    expect(res.headers()["content-security-policy"], "no policy header").toBeTruthy();
    expect(metaPolicy(await res.text()), "no policy meta").toBeTruthy();
  });

  it("allows, in every page, every source its response header allows", async () => {
    const [peer] = fx.peers;
    /** @type {string[]} */
    const broken = [];
    /** @type {string[]} */
    const metaOnly = [];

    for (const page of PAGES) {
      const res = await peer.page.request.get(`${fx.origin}/${page}`);
      expect(res.status(), page).toBe(200);
      const meta = connectSrc(metaPolicy(await res.text()));
      const header = connectSrc(res.headers()["content-security-policy"] || "");
      if (!meta.length) continue;

      for (const source of header) {
        if (!meta.includes(source)) broken.push(`${page}: header allows ${source}, meta does not`);
      }
      for (const source of meta) {
        if (!header.includes(source)) metaOnly.push(`${page}: ${source}`);
      }
    }

    // Reported, not failed — see the note at the top on the two directions.
    if (metaOnly.length) {
      console.info(`[csp-policy.e2e] sources no header grants:\n  ${metaOnly.join("\n  ")}`);
    }
    expect(broken).toEqual([]);
  });

  it("states which header it is comparing against, and what it leaves out", () => {
    // The harness's header mirrors `Settings.csp_connect_src()` with no
    // signalling origin — the shape of a deployment with no Web PubSub, and the
    // only shape the built artifact is valid for on its own. A deployment that
    // *has* one adds it to the header, and `scripts/package-static.sh` merges
    // the same value into every page before upload so this comparison still
    // holds on the bytes that are served. `tests/unit/test_csp_signaling.py`
    // owns that half, against the artifact.
    expect(HEADER_CSP).toMatch(/connect-src/);
    expect(HEADER_CSP).not.toMatch(/wss:|ws:/);
  });
});
