/**
 * What the toolkit's status pill claims, read off the shipped bundle.
 *
 * The pill is the most prominent safety statement the page makes, and it said
 * **"4 suites ready"** in a browser that had self-tested three things. The
 * fourth was WebAuthn, whose whole test was `typeof PublicKeyCredential`,
 * reported in the self-test's own word (`"verified"`), listed in the popover
 * beside three real results, and stamped with a ✓ under a heading reading
 * "Crypto self-test (POST)". Measured on `dist/` before the fix:
 *
 *     pill:    "4 suites ready"
 *     popover: WebCrypto verified · OpenPGP verified · SSS verified · WebAuthn browser
 *     Params:  ✓ WebCrypto  ✓ OpenPGP  ✓ SSS  ✓ WebAuthn
 *
 * and with `PublicKeyCredential` deleted before load, on a notebook with no
 * WebAuthn step in it and FIPS mode on:
 *
 *     pill:    "3 suites ready · 1 issue"
 *     Params:  "Blocks adding or running ops on an unverified suite (WebAuthn, above)."
 *     banner:  "FIPS mode: blocked — webauthn unverified"
 *
 * Every line of that is false. `toolboxToSuite("webauthn")` returns `null`,
 * so no recipe can ever be blocked for WebAuthn; the run the banner called
 * blocked would have proceeded.
 *
 * ## Why this is measured in a browser
 *
 * The count is React state rendered into a string. Both halves of the defect
 * — a probe answering in the wrong vocabulary, and a render site adding two
 * kinds of claim together — are invisible to any test that imports a module,
 * and the pre-fix code would pass a unit test of every function it contains.
 * `suite-badge-claims.test.js` holds the cheap tripwires; this file reads the
 * sentences a person actually sees.
 *
 * ## The three browsers
 *
 * **API present** is the ordinary case, and the one that read "4 suites
 * ready". **API absent** deletes `PublicKeyCredential` before any script
 * runs, which is the only way to reach the degraded copy — it is a real
 * browser state (a non-secure context, an old build, a hardened profile) and
 * the fix must not report it as a suite failure. **Self-test failing**
 * corrupts `SubtleCrypto.digest` by one byte so no known answer matches; it
 * is the control that keeps the count honest in the other direction. If the
 * count were hardcoded to three, the first two cases would pass — this one
 * demands the number track the vectors, and that WebAuthn's row stay
 * "present" while every suite around it fails.
 *
 * Serves `dist/` like every spec here, so `npm run build` must have run.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DIST_ROOT, chromiumAvailability, serveDist } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the pill is measured in", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[suite-badge-claims.e2e] skipping — chromium not installed (${availability.reason})`);
}

/**
 * Runs in the page: the pill and, if it is open, its popover rows.
 *
 * Separate from `readTray` because the popover closes on any mousedown
 * outside it, and reaching the Params tab takes two clicks. Serialised into
 * the browser, so it stands alone. Reads text the way a person reads it — the
 * rendered string — rather than any attribute or class a refactor could keep
 * while changing the sentence.
 */
function readPill() {
  const norm = (n) => (n?.textContent || "").replace(/\s+/g, " ").trim();
  const pill = document.querySelector(".suite-pill");
  const popover = pill?.parentElement?.querySelector("div.absolute");
  return {
    pill: norm(pill).replace(/▾$/, "").trim(),
    tone: pill?.getAttribute("data-suite-tone") || null,
    rows: popover ? [...popover.children].map(norm) : null,
  };
}

/** Runs in the page: the Params tab's self-test, capability and FIPS blocks. */
function readTray() {
  const norm = (n) => (n?.textContent || "").replace(/\s+/g, " ").trim();
  const all = [...document.querySelectorAll("p,span,div,label")].map(norm);
  return {
    selfTestHeading: all.find((t) => /^Crypto self-test/.test(t)) || null,
    selfTestBadges: all.filter((t) => /^[✓⚠] (WebCrypto|OpenPGP|SSS|WebAuthn)$/.test(t)),
    capabilityHeading: all.find((t) => /^Browser capability$/.test(t)) || null,
    capabilityBadge: all.find((t) => /^WebAuthn API /.test(t)) || null,
    capabilityProse: all.find((t) => /^This browser exposes/.test(t)) || null,
    // Every wording this paragraph has had, kept together on purpose: a
    // scraper that only knows the current one silently returns `null` when the
    // copy changes, and `null` satisfies a `not.toMatch` — so the assertion
    // that FIPS never names WebAuthn would have gone on passing while matching
    // nothing at all. `Refuses` is the wording since the switch started
    // refusing rather than only flagging.
    fipsBlurb:
      all.find((t) =>
        /^Refuses any run|^Flags any recipe|^Blocks adding|^Verified suites only/.test(t)
      ) || null,
    banner: all.find((t) => /^FIPS mode:/.test(t)) || null,
  };
}

describe.skipIf(!availability.ok)("the suite pill counts self-tests only", () => {
  /** @type {Awaited<ReturnType<typeof serveDist>>} */
  let server;
  /** @type {import("playwright").Browser} */
  let browser;

  beforeAll(async () => {
    const { chromium } = await import("playwright");
    server = await serveDist(DIST_ROOT);
    browser = await chromium.launch();
  });

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  /**
   * @param {(() => void)|null} sabotage  runs before any page script
   */
  async function claims(sabotage) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    try {
      // FIPS on for every case: the arm that lied loudest ("blocked") only
      // drew with the switch on, and it drew on recipes it had no business
      // refusing.
      await context.addInitScript(() => {
        window.localStorage.setItem("basilisk.fipsMode", "1");
      });
      if (sabotage) await context.addInitScript(sabotage);
      const page = await context.newPage();
      await page.goto(`${server.origin}/toolkit`, { waitUntil: "load" });
      await page.waitForSelector(".suite-pill", { timeout: 30000 });
      // The self-test is async and started at boot; until it settles the pill
      // holds the pre-test default, which is every suite `unverified` and so
      // amber. Waiting for the tone to leave amber waits for the real result
      // in all three browsers here — green when the vectors pass, red when
      // they fail — where a fixed sleep would let a slow machine score the
      // default instead.
      await page
        .waitForFunction(
          () =>
            document.querySelector(".suite-pill")?.getAttribute("data-suite-tone") !== "warn",
          { timeout: 30000 }
        )
        .catch(() => {});
      await page.click(".suite-pill");
      const pill = await page.evaluate(readPill);
      await page.click(".suite-pill");
      const rail = await page.$('button[title="Expand session tray"]');
      if (rail) await rail.click();
      const params = await page.$('button[role="tab"][aria-label="Params"]');
      if (params) await params.click();
      await page.waitForTimeout(300);
      return { ...pill, ...(await page.evaluate(readTray)) };
    } finally {
      await context.close();
    }
  }

  it("says three, not four, when the browser has WebAuthn", async () => {
    const seen = await claims(null);
    expect(seen.pill).toBe("3 suites verified");
    expect(seen.tone).toBe("ok");
    // The row is still there — a person wants to know the API exists — but it
    // does not say "verified" and it is not one of the three.
    expect(seen.rows).toEqual([
      "WebCryptoverified",
      "OpenPGPverified",
      "SSSverified",
      "WebAuthn APIpresent",
    ]);
    expect(seen.selfTestHeading).toBe("Crypto self-test (POST)");
    expect(seen.selfTestBadges).toEqual(["✓ WebCrypto", "✓ OpenPGP", "✓ SSS"]);
    expect(seen.capabilityHeading).toBe("Browser capability");
    expect(seen.capabilityBadge).toBe("WebAuthn API present");
    expect(seen.capabilityProse).toMatch(/not a self-test result/);
    expect(seen.capabilityProse).toMatch(/no webauthn op is blocked by it/);
  });

  it("reports a missing WebAuthn API as absent, not as a failed suite", async () => {
    const seen = await claims(() => {
      delete window.PublicKeyCredential;
    });
    // The number and the colour are the self-tests', and the self-tests all
    // passed in this browser. The old build read "3 suites ready · 1 issue"
    // in amber here.
    expect(seen.pill).toBe("3 suites verified");
    expect(seen.tone).toBe("ok");
    expect(seen.rows?.at(-1)).toBe("WebAuthn APIabsent");
    expect(seen.selfTestBadges).toEqual(["✓ WebCrypto", "✓ OpenPGP", "✓ SSS"]);
    expect(seen.capabilityBadge).toBe("WebAuthn API absent");
    expect(seen.capabilityProse).toMatch(/webauthn ops cannot run here/);
    expect(seen.capabilityProse).toMatch(/not a self-test failure/);
    // FIPS mode is on and the notebook is empty: nothing is blocked, so
    // nothing may say it is. This is the sentence the old build drew here.
    expect(seen.banner).toBeNull();
    expect(seen.fipsBlurb).toBe("Verified suites only (POST/CAST). Not a FIPS 140 certificate.");
  });

  it("counts down when a suite fails, and leaves the capability row alone", async () => {
    const seen = await claims(() => {
      const real = crypto.subtle.digest.bind(crypto.subtle);
      crypto.subtle.digest = async (alg, data) => {
        const out = new Uint8Array(await real(alg, data));
        out[0] ^= 0xff; // one flipped byte misses every known answer
        return out.buffer;
      };
    });
    expect(seen.pill).toBe("0 of 3 suites verified");
    expect(seen.tone).toBe("error");
    expect(seen.rows?.at(-1)).toBe("WebAuthn APIpresent");
    // "Refuses", not "Flags": the switch used to have no effect on the run
    // path, and this sentence used to say so. It names the suites and then the
    // way out, and the run path throws the same shape.
    expect(seen.fipsBlurb, "the tray paragraph was not found at all").not.toBeNull();
    expect(seen.fipsBlurb).toMatch(/^Refuses any run that reaches an unverified suite \(/);
    // Named suites, and only suites. WebAuthn is not gated by FIPS and must
    // never appear in this list, however the self-test went.
    expect(seen.fipsBlurb).not.toMatch(/WebAuthn/);
  });
});
