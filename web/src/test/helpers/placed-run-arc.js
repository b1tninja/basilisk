/**
 * What two browsers need in order to run a cell on each other's behalf.
 *
 * `placed-run-arc.e2e.js` is the suite; this is the plumbing it stands on, kept
 * here because every piece of it is a decision about *what is allowed to be
 * fake*, and those decisions are easier to audit in one place than scattered
 * through a spec.
 *
 * Three of them, in the order they matter.
 *
 * ## 1. The page is the real server's page, not `dist/` re-served
 *
 * `browser-peers.js` serves `dist/` straight off the filesystem, and its header
 * says why: the toolkit page ships its policy in a `<meta http-equiv>` tag, so
 * unmodified bytes are what make the production CSP the one under test. For
 * notebook signalling that is no longer the whole policy. `connect-src` in the
 * built HTML is `'self'` plus two keyservers, and the signalling socket is on
 * neither — the service's origin comes out of a connection string that differs
 * per deployment, so `basilisk/portal/static.py` merges it into the page's own
 * `connect-src` on the way out. A test serving the raw file would be driving a
 * policy no deployment ever emits, and the WebSocket would be blocked.
 *
 * So `proxyToBasilisk` forwards **every** path to the Flask server this repo
 * ships, and the browser gets the document that server produced, CSP merge and
 * all. The proxy adds and removes nothing.
 *
 * ## 2. The signalling service is the product's own, spawned by the product
 *
 * `basilisk.serve` starts `webpubsub_local.py` alongside itself whenever the
 * connection string points at loopback — that is a shipped behaviour, not a
 * test path, and it is how `npm run dev` gets working signalling. Naming a free
 * port in the connection string is therefore the whole of the arrangement: the
 * server mints the grants (real tokens, real room/lobby scoping, real proof and
 * rate-limit gates), the double verifies them with the same code that minted
 * them, and the browser's own `webpubsub.js` runs unmodified above it. Nothing
 * here speaks the subprotocol.
 *
 * ## 3. The arc's modules are bundled from source, and that is a finding
 *
 * `quorum-key-confirmation.e2e.js` reaches `NotebookSession` inside the chunks
 * the page loaded, and this suite does the same for the session half of the arc.
 * The other half is not there to reach. `planRun`, `buildOfferFor`,
 * `acceptHandoffOffer`, `buildResultFor` and `acceptCellResult` have no caller
 * in the application — no page, no op, no mount — so Rollup drops every one of
 * them, and `engine.js`'s `placement` option is never passed by anything that
 * ships. The suite asserts that absence rather than working around it quietly;
 * see *"the shipped bundle cannot do this"* there.
 *
 * `buildArcBundle` therefore compiles the **real source modules** for the
 * browser with esbuild, unminified and unmodified, and serves them same-origin.
 * `openpgp` is left external and pointed at the chunk the page already loaded,
 * so the signing key material and the shipped verifier meet in one OpenPGP
 * instance rather than two copies of the library.
 *
 * @module test/helpers/placed-run-arc
 */

import { request as httpRequest } from "node:http";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** `web/`, which is where the source the arc bundle is built from lives. */
const WEB_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

/** Where the built arc is served. Same origin, so `script-src 'self'` covers it. */
export const ARC_PATH = "/e2e/placed-run-arc.js";

/**
 * The environment that turns notebook signalling on for a spawned server.
 *
 * `AZURE_WEBPUBSUB_CONNECTION_STRING` is read by `basilisk/config.py` and does
 * three things at once: it makes `/api/v1/notebook/negotiate` answer instead of
 * returning 503, it puts the double's ws origin into the page's `connect-src`,
 * and — because the endpoint is loopback — it makes `basilisk.serve` start the
 * local double. One string, no flags.
 *
 * **It names no port, deliberately.** This used to reserve one and write it in,
 * which meant the number was chosen while nothing held it and claimed a moment
 * later by a process that might by then have lost it. The double now binds
 * first and `serve.py` publishes the result back into its own settings, so the
 * port arrives from the server — `startBasilisk`'s `signalingOrigin` — instead
 * of being predicted for it.
 *
 * @param {string} [accessKey]
 * @returns {Record<string, string>}
 */
export function signalingEnv(accessKey = "placed-run-arc-e2e-key") {
  return {
    AZURE_WEBPUBSUB_CONNECTION_STRING: `Endpoint=http://127.0.0.1;AccessKey=${accessKey};Version=1.0;`,
    BASILISK_WEBPUBSUB_HUB: "notebook",
  };
}

/**
 * Compile the placed-run modules for the browser, from source.
 *
 * Unminified, no `define`, no transform beyond module resolution: what runs in
 * the page is the text in `src/lib/`. `openpgp` resolves to the chunk the
 * toolkit page already fetched, which keeps one copy of the library in the
 * realm and means a key read by the page's own session and a key used to sign
 * a result are the same kind of object.
 *
 * @param {string} distRoot  absolute path to `dist/`
 * @returns {Promise<{ code: string, openpgpChunk: string }>}
 */
export async function buildArcBundle(distRoot) {
  const { build } = await import("esbuild");
  const assets = readdirSync(new URL("assets/", new URL(`file:///${distRoot.replace(/\\/g, "/")}`)));
  const openpgp = assets.find((n) => /^openpgp[^/]*\.js$/.test(n));
  if (!openpgp) throw new Error("placed-run-arc: dist/assets has no openpgp chunk to point at");
  const openpgpChunk = `/assets/${openpgp}`;

  const result = await build({
    stdin: {
      contents: ARC_ENTRY,
      resolveDir: WEB_ROOT,
      sourcefile: "placed-run-arc-entry.js",
    },
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
    // Readable in a stack trace, and it is the point of this bundle that the
    // bytes are the source rather than a build artifact.
    minify: false,
    plugins: [
      {
        name: "openpgp-is-the-page's",
        setup(b) {
          b.onResolve({ filter: /^openpgp$/ }, () => ({ path: openpgpChunk, external: true }));
        },
      },
    ],
  });
  if (result.errors.length) {
    throw new Error(`placed-run-arc: bundling the arc failed — ${JSON.stringify(result.errors)}`);
  }
  return { code: result.outputFiles[0].text, openpgpChunk };
}

/**
 * Every export the arc needs, and nothing that would let the suite cheat.
 *
 * There is no `accept` helper and no `registerBindings` here: acceptance is
 * `acceptHandoffOffer` plus a caller putting the bindings into a registry, and
 * the suite writes that second line itself so that a reader can see the human
 * act it stands for. `approval-gate.js` states the rule; this entry is shaped
 * so the suite cannot quietly break it.
 *
 * `roomRoster` is here for the opposite reason to the rest: it is not part of
 * the arc, it is the thing the suite used to *substitute for*. The peer labels
 * and `me` were the test's own literals, so the arc passed for a year while the
 * shell's own resolution of `me` could not return anything but `""`. Exporting
 * it means the suite asks the product who this browser is instead of telling it.
 */
const ARC_ENTRY = `
export { compileRecipe, migrateRecipe, serializeRecipe } from "./src/lib/toolkit/recipe.js";
export {
  labelForFingerprint,
  planChains,
  planRun,
  summarizePlan,
} from "./src/lib/toolkit/plan.js";
export { placementGate, withheldSlotMessage } from "./src/lib/toolkit/placement.js";
export { runRecipe } from "./src/lib/toolkit/engine.js";
export { buildRunManifest, manifestDigest, parseManifest } from "./src/lib/toolkit/manifest.js";
export { attestationToJson, buildAttestation } from "./src/lib/toolkit/attest.js";
export { createSlotRegistry } from "./src/lib/toolkit/slot-registry.js";
export { canonicalAudience, deriveRoomId } from "./src/lib/notebook/room.js";
export { roomRoster } from "./src/lib/notebook/roster.js";
export { signOpenPgp } from "./src/lib/pgp/sign.js";
export {
  acceptCellResult,
  acceptHandoffOffer,
  buildOfferFor,
  buildResultFor,
  offerAwaiting,
  offerToJson,
  parseCellResult,
  parseHandoffOffer,
  resultToJson,
  summarizeHandoff,
} from "./src/lib/toolkit/handoff.js";
`;

/**
 * `serveDist`'s hook, wired to answer the arc bundle and forward the rest.
 *
 * Order matters and is the only rule here: the bundle is served from this
 * process because Flask has no route for it, and **everything else** — the
 * page, its chunks, the keyserver, the negotiate endpoint — is forwarded
 * untouched to the server that would serve it in production. Nothing is
 * rewritten on the way through; a page that reached this proxy and a page
 * fetched from Flask directly are the same bytes.
 *
 * @param {{ origin: string }} server  a `startBasilisk` result
 * @param {string} arcCode
 * @param {{ onRequest?: (method: string, path: string) => void }} [opts]
 * @returns {(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => boolean}
 */
export function proxyToBasilisk(server, arcCode, opts = {}) {
  const upstream = new URL(server.origin);
  return (req, res) => {
    const raw = req.url || "/";
    const path = raw.split("?")[0];
    opts.onRequest?.(String(req.method || "GET").toUpperCase(), path);

    if (path === ARC_PATH) {
      const body = Buffer.from(arcCode, "utf8");
      res.writeHead(200, {
        "content-type": "text/javascript; charset=utf-8",
        "content-length": String(body.byteLength),
        "cache-control": "no-store",
      });
      res.end(body);
      return true;
    }

    const headers = { ...req.headers };
    delete headers.connection;
    const forward = httpRequest(
      {
        host: upstream.hostname,
        port: Number(upstream.port),
        method: req.method,
        path: raw,
        headers: { ...headers, host: upstream.host },
      },
      (up) => {
        res.writeHead(up.statusCode || 502, up.headers);
        up.pipe(res);
      }
    );
    forward.on("error", (err) => {
      // Answered as a gateway failure rather than a 404: a proxy that
      // translated "the server is not there" into "the page does not exist"
      // would send the suite looking for a routing bug.
      res.writeHead(502, { "content-type": "text/plain" });
      res.end(`basilisk proxy failed: ${err.message}`);
    });
    req.pipe(forward);
    return true;
  };
}

/**
 * Two OpenPGP identities, and the directory rows that make them fetchable.
 *
 * Real keys, generated here rather than taken from `key-corpus.js`, because
 * both halves are needed: the public half goes into the directory through the
 * server's own ingest path and the private half has to reach a browser, and no
 * fixture in this repo ships a private key for a directory-approved identity.
 *
 * @param {string[]} emails
 * @returns {Promise<{ fpr: string, email: string, armoredPublic: string,
 *   armoredPrivate: string, corpus: object }[]>}
 */
export async function makeIdentities(emails) {
  const { generateKey } = await import("openpgp");
  const out = [];
  for (const email of emails) {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: email.split("@")[0], email }],
      format: "object",
    });
    const fpr = publicKey.getFingerprint().toUpperCase();
    out.push({
      fpr,
      email,
      armoredPublic: publicKey.armor(),
      armoredPrivate: privateKey.armor(),
      corpus: {
        id: email,
        fingerprint: fpr,
        armoredPublic: publicKey.armor(),
        uids: [`${email.split("@")[0]} <${email}>`],
        approvalState: "approved",
      },
    });
  }
  return out;
}
