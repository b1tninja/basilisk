/**
 * "No third party" has to be sayable, and then it has to be kept.
 *
 * `DEFAULT_ICE_SERVERS` is Cloudflare and Google STUN, and a STUN binding
 * request hands whoever answers it this machine's public address. Declining
 * that is a privacy decision a user of a browser-only crypto notebook is
 * entitled to make. It used to be inexpressible: four sites answered "what ICE
 * servers does this connection start from" and three of them answered it with
 * `list?.length ? list : DEFAULT_ICE_SERVERS`, which cannot tell *nobody said*
 * from *somebody said none*. A user could write the choice in a recipe and the
 * session layer would overrule it one call later, silently, on the far side of
 * a pipeline.
 *
 * Two claims are pinned here, and they are different claims:
 *
 *  1. **The rule holds.** `iceServersOrDefault` substitutes for `null` and
 *     never for `[]`, and the ops and the session both go through it — asserted
 *     by behaviour, end to end, from `rtc.ice stun=none` to what the session
 *     hands its transport.
 *  2. **The rule stays the only one.** A module that imports
 *     `DEFAULT_ICE_SERVERS` can re-implement the substitution in a line, and
 *     nothing else would complain. So the importers are enumerated: `ice.js`
 *     owns the rule and the standalone quorum page *renders* the list as text.
 *     Any other importer is a fourth answer to a settled question and fails
 *     here with the reason written out.
 *
 * Comments are stripped before the import assertions look at a file — the
 * docstrings in these modules discuss the symbol at length, which is what they
 * are for — and line endings normalised so a Windows checkout and CI agree.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_ICE_SERVERS,
  NO_ICE_SERVERS,
  iceServerCensus,
  iceServersOrDefault,
} from "../lib/webrtc/ice.js";

/* ─────────────────────────────── the rule ─────────────────────────────── */

describe("iceServersOrDefault tells 'nobody said' from 'somebody said none'", () => {
  it("fills only the absent case", () => {
    expect(iceServersOrDefault(null)).toBe(DEFAULT_ICE_SERVERS);
    expect(iceServersOrDefault(undefined)).toBe(DEFAULT_ICE_SERVERS);
  });

  it("hands an empty list back untouched, because it is an answer", () => {
    // The whole point of the module. `[]` is a user declining every third
    // party; substituting the defaults here is the app overruling them.
    expect(iceServersOrDefault([])).toEqual([]);
    expect(iceServersOrDefault(NO_ICE_SERVERS)).toEqual([]);
  });

  it("hands a stated list back as stated", () => {
    const mine = [{ urls: "stun:mine.example:3478" }];
    expect(iceServersOrDefault(mine)).toBe(mine);
  });

  it("refuses a shape that is neither", () => {
    // A string or an object here means a caller has confused the slot value
    // with the parsed list, and taking it would build a peer connection with
    // a config the browser silently ignores.
    expect(() => iceServersOrDefault("stun:x")).toThrow(/RTCIceServer/);
    expect(() => iceServersOrDefault({ urls: "stun:x" })).toThrow(/RTCIceServer/);
  });

  it("cannot be grown by a consumer, since the empty answer is shared", () => {
    expect(Object.isFrozen(NO_ICE_SERVERS)).toBe(true);
  });

  it("ships STUN only — a relay would carry the traffic", () => {
    for (const s of DEFAULT_ICE_SERVERS) {
      const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
      for (const u of urls) expect(u).toMatch(/^stuns?:/);
    }
  });
});

describe("iceServerCensus counts third parties by role", () => {
  it("separates the one that learns an address from the one that carries traffic", () => {
    expect(iceServerCensus(DEFAULT_ICE_SERVERS)).toEqual({
      stun: 2,
      turn: 0,
      total: 2,
    });
    expect(
      iceServerCensus([
        { urls: "stun:a.example:3478" },
        { urls: "turn:r.example:3478", username: "u", credential: "c" },
      ])
    ).toEqual({ stun: 1, turn: 1, total: 2 });
  });

  it("counts every URL of a multi-URL server, not every server", () => {
    expect(iceServerCensus([{ urls: ["stun:a:3478", "stuns:a:5349"] }]).stun).toBe(2);
  });

  it("reads an empty or absent list as no third party at all", () => {
    for (const empty of [[], null, undefined]) {
      expect(iceServerCensus(empty)).toEqual({ stun: 0, turn: 0, total: 0 });
    }
  });
});

/* ──────────────────── the rule stays the only one ──────────────────── */

/** Source with comments stripped and line endings normalised. */
const sourceOf = (rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8")
    .replace(/\r\n/g, "\n")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");

/** Every `.js`/`.ts`/`.tsx` under `src/`, as `{ name, code }`. */
function walk(rel, out = []) {
  const base = fileURLToPath(new URL(rel, import.meta.url));
  for (const entry of readdirSync(base, { withFileTypes: true })) {
    const next = `${rel}${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === "test" || entry.name === "node_modules") continue;
      walk(`${next}/`, out);
    } else if (/\.(js|ts|tsx)$/.test(entry.name)) {
      out.push({ name: next.replace("../", ""), code: sourceOf(next) });
    }
  }
  return out;
}

const MODULES = walk("../");

/**
 * Who may name the default list, and why.
 *
 * Not an allowlist for its own sake: each entry is a *different* use. `ice.js`
 * declares it and owns the one substitution. `quorum-mount.js` prefills a
 * textarea with the URLs so a user of the standalone page can read them and
 * delete them — rendering the list, never deciding with it.
 */
const MAY_IMPORT_DEFAULTS = ["lib/webrtc/ice.js", "lib/quorum-mount.js"];

describe("the substitution has one home", () => {
  it("is imported only where the list is owned or drawn", () => {
    const importers = MODULES.filter(
      (m) => /\bDEFAULT_ICE_SERVERS\b/.test(m.code) && m.name !== "lib/webrtc/ice.js"
    ).map((m) => m.name);
    const unexpected = importers.filter((n) => !MAY_IMPORT_DEFAULTS.includes(n));
    expect(
      unexpected,
      `${unexpected.join(", ")} reaches for DEFAULT_ICE_SERVERS. If it is deciding ` +
        `what a connection starts from, that decision belongs to ` +
        `iceServersOrDefault — an empty list there is a user who declined every ` +
        `third party, and a second copy of "?.length ? list : DEFAULT" takes ` +
        `their choice back.`
    ).toEqual([]);
  });

  it("is the rule each substitution site actually calls", () => {
    for (const name of [
      "lib/notebook/session.js",
      "lib/toolkit/rtc-ops.js",
      "lib/toolkit/quorum-ops.js",
    ]) {
      const mod = MODULES.find((m) => m.name === name);
      expect(mod, `${name} not found`).toBeTruthy();
      expect(mod.code, `${name} must resolve through the shared rule`).toMatch(
        /\biceServersOrDefault\b/
      );
    }
  });

  it("has no site left testing a server list for truthiness", () => {
    // The exact shape of the defect: `opts.iceServers?.length ? … : DEFAULT`,
    // which reads "you asked for none" as "you did not ask".
    for (const m of MODULES) {
      expect(m.code, `${m.name} length-tests an ICE list`).not.toMatch(
        /iceServers\s*(\?\.|\.)\s*length\s*\?/
      );
    }
  });
});
